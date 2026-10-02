package com.fusionplay.miplay.discovery

import android.content.Context
import android.net.wifi.WifiManager
import android.util.Log
import java.io.IOException
import java.net.DatagramPacket
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.MulticastSocket
import java.net.NetworkInterface
import java.util.Collections
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Callbacks for a MiPlay discovery scan.
 *
 * All callbacks are delivered on the discovery thread unless documented
 * otherwise; consumers that touch UI state should marshal to the main thread.
 */
interface MiPlayDiscoveryListener {

    fun onStarted()

    /**
     * Fired whenever the aggregated device set changes.
     *
     * The list carries **everything** currently known, including devices whose
     * name could not be resolved (those are reported as-is rather than
     * filtered).
     */
    fun onDevicesChanged(devices: List<MiPlayDevice>)

    /**
     * A DNS-SD service instance answered.
     *
     * @param serviceType the browsed service (`_mi-connect._udp.local.` or
     *   `_lyra-mdns._udp.local.`).
     * @param serviceName the full instance name, e.g.
     *   `小爱音箱-2284._mi-connect._udp.local.`.
     */
    fun onServiceFound(serviceType: String, serviceName: String, sourceIp: String, port: Int)

    /** Every raw datagram, in both directions. */
    fun onPacket(packet: MiPlayPacket) {}

    /** Non-fatal problem worth surfacing in the debug UI. */
    fun onLog(message: String) {}

    fun onStopped() {}
}

/**
 * MiPlay (小米妙播) **sender-side** device discovery.
 *
 * ## Protocol summary
 *
 * MiPlay discovery is plain mDNS / DNS-SD on `224.0.0.251:5353`. A sender
 * browses two Xiaomi service types:
 *
 * * `_mi-connect._udp.local.` — the IDM / route-picker identity record, which
 *   carries `name`, `dev`, `idHash`, `sec`, `appsData` and (often) `mac`;
 * * `_lyra-mdns._udp.local.` — the Lyra NetBus record, which carries `AppData`,
 *   `MediumType` and `DebugInfo`.
 *
 * The browse question is sent with `qclass = 0x8001` (IN + QU), i.e. "answer me
 * by unicast". Receivers therefore reply from their own port 5353 directly to
 * the sender's **ephemeral** source port. This is what makes the protocol
 * usable from Android without ever binding port 5353 — which is why
 * [QUERY_FROM_EPHEMERAL_PORT] exists and why the multicast listener is only a
 * best-effort secondary path.
 *
 * ## Threading
 *
 * One scheduler thread owns every socket. [startDiscovery] and
 * [stopDiscovery] are safe to call from the main thread.
 */
class MiPlayDiscovery(
    private val context: Context?,
    private val listener: MiPlayDiscoveryListener? = null,
    private val queryIntervalMillis: Long = DEFAULT_QUERY_INTERVAL_MILLIS,
    private val startupQueryCount: Int = DEFAULT_STARTUP_QUERY_COUNT
) {

    companion object {
        const val TAG = "MiPlayDiscovery"

        /** Re-query cadence while a scan is running. */
        const val DEFAULT_QUERY_INTERVAL_MILLIS = 3_000L

        /** Number of closely spaced queries sent at the start of a scan. */
        const val DEFAULT_STARTUP_QUERY_COUNT = 3

        /**
         * Bind the query socket to an ephemeral port rather than 5353.
         *
         * Verified on a live LAN: Xiaomi speakers honour the QU bit and send the
         * complete PTR/SRV/TXT/A(+AAAA) answer back to the ephemeral source
         * port, so no privileged port is required.
         */
        const val QUERY_FROM_EPHEMERAL_PORT = true

        /** TTL for locally cached records, guarded against lost goodbyes. */
        private const val CACHE_TTL_MILLIS = 150_000L
    }

    private val running = AtomicBoolean(false)

    @Volatile
    private var scheduler: ScheduledExecutorService? = null

    @Volatile
    private var querySocket: MulticastSocket? = null

    @Volatile
    private var multicastSocket: MulticastSocket? = null

    @Volatile
    private var multicastLock: WifiManager.MulticastLock? = null

    private val registry = DeviceRegistry()

    /** Raw datagram log, retained for the debug UI and for report generation. */
    val packetLog = MiPlayPacketLog()

    private val activeServices = Collections.synchronizedSet(mutableSetOf<String>())

    @Volatile
    private var queryCounter = 0

    // ------------------------------------------------------------------ public

    val isRunning: Boolean get() = running.get()

    /** Snapshot of everything discovered so far. */
    fun discoveredDevices(): List<MiPlayDevice> = registry.snapshot()

    /**
     * Starts browsing. Idempotent: calling it while a scan runs only forces an
     * immediate re-query.
     */
    fun startDiscovery() {
        if (!running.compareAndSet(false, true)) {
            sendQueries("manual-refresh")
            return
        }

        val executor = Executors.newSingleThreadScheduledExecutor { runnable ->
            Thread(runnable, "miplay-discovery").apply { isDaemon = true }
        }
        scheduler = executor

        acquireMulticastLock()

        executor.execute {
            try {
                openSockets()
            } catch (error: Exception) {
                log("failed to open sockets: ${error.message}")
                stopDiscovery()
                return@execute
            }
            log("discovery started; browsing ${MiPlayMdns.BROWSE_SERVICES.joinToString(", ")}")
            listener?.onStarted()
            sendQueries("startup")
        }

        executor.scheduleWithFixedDelay(
            {
                if (running.get()) sendQueries("cache-refresh")
            },
            queryIntervalMillis,
            queryIntervalMillis,
            TimeUnit.MILLISECONDS
        )

        executor.scheduleWithFixedDelay(
            {
                if (!running.get()) return@scheduleWithFixedDelay
                pruneAndPublish()
            },
            1_000L,
            1_000L,
            TimeUnit.MILLISECONDS
        )
    }

    /** Stops browsing and releases every socket and the multicast lock. */
    fun stopDiscovery() {
        if (!running.compareAndSet(true, false)) return
        scheduler?.shutdownNow()
        scheduler = null
        closeQuietly(querySocket)
        querySocket = null
        closeQuietly(multicastSocket)
        multicastSocket = null
        releaseMulticastLock()
        synchronized(activeServices) { activeServices.clear() }
        log("discovery stopped")
        listener?.onStopped()
    }

    // ----------------------------------------------------------------- sockets

    private fun openSockets() {
        val query = MulticastSocket(null)
        query.reuseAddress = true
        query.bind(InetSocketAddress(0))
        query.timeToLive = 255
        query.networkInterface = preferredInterface(query)
        querySocket = query
        log("query socket bound to ${query.localSocketAddress} (ephemeral port ${query.localPort})")

        // Secondary path: also listen on the real mDNS port for responders that
        // answer to the group address instead of honouring the QU bit. This
        // bind is allowed for normal apps via SO_REUSEADDR; if it fails, the
        // unicast path still works and the failure is only logged.
        try {
            val multicast = MulticastSocket(null)
            multicast.reuseAddress = true
            multicast.bind(InetSocketAddress(MiPlayMdns.MDNS_PORT))
            multicast.timeToLive = 255
            multicastSocket = multicast
            joinMulticastGroups(multicast)
            log("multicast listener bound to ${multicast.localSocketAddress}")
        } catch (error: Exception) {
            log("multicast listener unavailable on port ${MiPlayMdns.MDNS_PORT}: ${error.message}")
        }
    }

    private fun preferredInterface(socket: MulticastSocket): NetworkInterface? {
        val candidates = Collections.list(NetworkInterface.getNetworkInterfaces())
            .filter { it.isUp && !it.isLoopback && it.supportsMulticast() }
        // Prefer an interface that carries a routable IPv4 address; Wi-Fi and
        // Ethernet both qualify, VPN/tunnel interfaces usually do not.
        return candidates.firstOrNull { nic ->
            Collections.list(nic.inetAddresses).any {
                it is Inet4Address && !it.isLoopbackAddress && !it.isLinkLocalAddress
            }
        } ?: candidates.firstOrNull()
    }

    private fun joinMulticastGroups(socket: MulticastSocket) {
        val group = InetAddress.getByName(MiPlayMdns.MDNS_GROUP_V4)
        val interfaces = Collections.list(NetworkInterface.getNetworkInterfaces())
            .filter { it.isUp && !it.isLoopback && it.supportsMulticast() }
        for (nic in interfaces) {
            for (address in Collections.list(nic.inetAddresses)) {
                if (address !is Inet4Address || address.isLoopbackAddress) continue
                try {
                    socket.joinGroup(InetSocketAddress(group, MiPlayMdns.MDNS_PORT), nic)
                    log("joined ${MiPlayMdns.MDNS_GROUP_V4} on ${nic.name}/${address.hostAddress}")
                } catch (error: Exception) {
                    log("join failed on ${nic.name}: ${error.message}")
                }
            }
        }

        // Receive loop for the multicast socket.
        val thread = Thread({ receiveLoop(socket, "multicast") }, "miplay-multicast-rx")
        thread.isDaemon = true
        thread.start()

        // Receive loop for the ephemeral query socket (unicast QU replies).
        val query = querySocket ?: return
        val unicastThread = Thread({ receiveLoop(query, "unicast") }, "miplay-unicast-rx")
        unicastThread.isDaemon = true
        unicastThread.start()
    }

    private fun receiveLoop(socket: MulticastSocket, channel: String) {
        val buffer = ByteArray(9000)
        while (running.get()) {
            try {
                val packet = DatagramPacket(buffer, buffer.size)
                socket.receive(packet)
                handleDatagram(
                    channel = channel,
                    data = buffer.copyOfRange(packet.offset, packet.offset + packet.length),
                    source = packet.socketAddress as? InetSocketAddress,
                    localSocket = socket.localSocketAddress as? InetSocketAddress
                )
            } catch (error: IOException) {
                if (running.get()) log("$channel receive error: ${error.message}")
                if (socket.isClosed) return
            } catch (error: Exception) {
                log("$channel processing error: ${error.message}")
            }
        }
    }

    // ----------------------------------------------------------------- queries

    private fun sendQueries(reason: String) {
        val socket = querySocket ?: return
        val destination = MiPlayMdns.resolve(MiPlayMdns.MDNS_GROUP_V4, MiPlayMdns.MDNS_PORT)
        queryCounter += 1
        val transactionId = queryCounter and 0xFFFF

        for (service in MiPlayMdns.BROWSE_SERVICES) {
            val query = MiPlayMdns.buildBrowseQuery(
                service = service,
                unicastResponse = QUERY_FROM_EPHEMERAL_PORT,
                id = transactionId
            )
            try {
                socket.send(DatagramPacket(query, query.size, destination))
                record(
                    MiPlayPacket(
                        direction = MiPlayPacketDirection.SEND,
                        address = "${MiPlayMdns.MDNS_GROUP_V4}:${MiPlayMdns.MDNS_PORT}",
                        localAddress = socket.localSocketAddress.toString().removePrefix("/"),
                        byteCount = query.size,
                        hex = query.toHex(),
                        ascii = query.toAscii(),
                        hexDump = query.toHexDump(),
                        service = service,
                        decoded = MiPlayDnsParser.parseAndDescribe(query),
                        note = "$reason (id=$transactionId, qclass=0x8001 unicast-response-requested)"
                    )
                )
            } catch (error: Exception) {
                log("query send failed for $service: ${error.message}")
            }
        }
    }

    // --------------------------------------------------------------- ingestion

    private fun handleDatagram(
        channel: String,
        data: ByteArray,
        source: InetSocketAddress?,
        localSocket: InetSocketAddress?
    ) {
        val message = MiPlayDnsParser.parse(data)
        val sourceIp = source?.address?.let { MiPlayMdns.formatAddress(it) } ?: "unknown"
        val serviceHint = message?.allRecords
            ?.firstOrNull { it.type == MiPlayMdns.TYPE_PTR && MiPlayMdns.isMiPlayService(it.name) }
            ?.name
            ?: MiPlayMdns.BROWSE_SERVICES.firstOrNull { service ->
                data.containsSubsequence(service.toByteArray(Charsets.UTF_8))
            }

        record(
            MiPlayPacket(
                direction = MiPlayPacketDirection.RECV,
                address = source?.let { "${MiPlayMdns.formatAddress(it.address)}:${it.port}" } ?: "unknown",
                localAddress = localSocket?.toString()?.removePrefix("/") ?: "-",
                byteCount = data.size,
                hex = data.toHex(),
                ascii = data.toAscii(),
                hexDump = data.toHexDump(),
                service = serviceHint,
                decoded = message?.describe(),
                note = "channel=$channel"
            )
        )

        if (message == null) {
            log("unparseable datagram (${data.size} bytes) from $sourceIp; raw hex retained")
            return
        }
        if (!message.isResponse) {
            log("ignoring query (not a response) from $sourceIp")
            return
        }

        val changed = registry.ingest(message, sourceIp)
        for (record in message.allRecords) {
            if (record.type == MiPlayMdns.TYPE_PTR && MiPlayMdns.isMiPlayService(record.name)) {
                val instance = record.domainName ?: continue
                activeServices.add("${record.name}|$instance")
                listener?.onServiceFound(
                    record.name,
                    instance,
                    sourceIp,
                    registry.portFor(instance) ?: 0
                )
            }
        }
        if (changed) publish()
    }

    private fun pruneAndPublish() {
        if (registry.prune(CACHE_TTL_MILLIS)) publish()
    }

    private fun publish() {
        val devices = registry.snapshot()
        listener?.onDevicesChanged(devices)
    }

    // ------------------------------------------------------------------ helpers

    private fun record(packet: MiPlayPacket) {
        packetLog.onPacket(packet)
        listener?.onPacket(packet)
        Log.d(TAG, packet.format())
    }

    private fun log(message: String) {
        Log.i(TAG, message)
        listener?.onLog(message)
    }

    private fun acquireMulticastLock() {
        val wifi = context?.applicationContext
            ?.getSystemService(Context.WIFI_SERVICE) as? WifiManager ?: return
        try {
            val lock = wifi.createMulticastLock("miplay-discovery")
            lock.setReferenceCounted(true)
            lock.acquire()
            multicastLock = lock
            log("Wi-Fi MulticastLock acquired")
        } catch (error: Exception) {
            log("MulticastLock unavailable: ${error.message}")
        }
    }

    private fun releaseMulticastLock() {
        try {
            multicastLock?.takeIf { it.isHeld }?.release()
        } catch (error: Exception) {
            Log.w(TAG, "MulticastLock release failed", error)
        }
        multicastLock = null
    }

    private fun closeQuietly(socket: MulticastSocket?) {
        try {
            socket?.close()
        } catch (error: Exception) {
            Log.w(TAG, "socket close failed", error)
        }
    }

    private fun ByteArray.containsSubsequence(needle: ByteArray): Boolean {
        if (needle.isEmpty() || size < needle.size) return false
        outer@ for (index in 0..size - needle.size) {
            for (offset in needle.indices) {
                if (this[index + offset] != needle[offset]) continue@outer
            }
            return true
        }
        return false
    }
}
