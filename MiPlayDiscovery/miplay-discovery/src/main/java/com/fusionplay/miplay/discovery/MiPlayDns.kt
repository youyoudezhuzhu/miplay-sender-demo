package com.fusionplay.miplay.discovery

import java.io.ByteArrayOutputStream
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.UnknownHostException

/**
 * Raw DNS / mDNS wire constants, names and query construction.
 *
 * Everything here is derived from observed MiPlay (小米妙播) traffic on a live
 * LAN and from the FusionPlay-Android MiPlaySDK implementation. No field is
 * invented: see MIPlay_DISCOVERY_RE.md for the packet captures behind each
 * constant.
 */
object MiPlayMdns {

    /** Standard IPv4 mDNS group. */
    const val MDNS_GROUP_V4 = "224.0.0.251"

    /** Standard IPv4 mDNS port. */
    const val MDNS_PORT = 5353

    /**
     * Xiaomi "Mi Connect" / IDM (Interconnect Device Management) DNS-SD service.
     * This is the service that carries the route-picker device identity
     * (`name`, `dev`, `idHash`, `appsData`, optional `mac`). Every Xiaomi
     * speaker observed on the test LAN answered a browse for this type.
     */
    const val SERVICE_MI_CONNECT = "_mi-connect._udp.local."

    /**
     * Xiaomi "Lyra" NetBus DNS-SD service. Advertised by MiPCAudio/MAFSvr style
     * receivers and by newer speaker firmware; carries the `AppData` blob, the
     * media `MediumType` and the human readable `DebugInfo`.
     */
    const val SERVICE_LYRA = "_lyra-mdns._udp.local."

    /** Service types browsed by [MiPlayDiscovery.startDiscovery]. */
    val BROWSE_SERVICES = listOf(SERVICE_MI_CONNECT, SERVICE_LYRA)

    /** DNS record types used by MiPlay. */
    const val TYPE_A = 1
    const val TYPE_PTR = 12
    const val TYPE_TXT = 16
    const val TYPE_AAAA = 28
    const val TYPE_SRV = 33

    /** DNS classes. */
    const val CLASS_IN = 0x0001

    /**
     * IN class with the mDNS "unicast response requested" (QU) bit set.
     *
     * This is the single most important detail for a sender: Xiaomi's own
     * MAFSvr and the reference probe send the PTR browse as
     * `qclass = 0x8001`, which asks every responder to answer by **unicast to
     * the sender's source port**. That lets an Android sender receive replies
     * on an ephemeral UDP port instead of having to win a bind on port 5353.
     */
    const val CLASS_IN_UNICAST_REQUESTED = 0x8001

    /**
     * Builds a minimal DNS-SD PTR browse question.
     *
     * Wire shape (verified against real Xiaomi senders, 39/40 bytes):
     * ```
     * 00 00  00 00  00 01  00 00  00 00  00 00   <- ID 0, flags 0, QDCOUNT 1
     * 0b 5f 6d 69 2d 63 6f 6e 6e 65 63 74 04 5f 75 64 70 05 6c 6f 63 61 6c 00
     * 00 0c  80 01                              <- QTYPE PTR, QCLASS IN|QU
     * ```
     */
    fun buildBrowseQuery(service: String, unicastResponse: Boolean = true, id: Int = 0): ByteArray {
        val out = ByteArrayOutputStream(48)
        writeU16(out, id)          // transaction id (responders echo it)
        writeU16(out, 0)           // flags: standard query
        writeU16(out, 1)           // QDCOUNT
        writeU16(out, 0)           // ANCOUNT
        writeU16(out, 0)           // NSCOUNT
        writeU16(out, 0)           // ARCOUNT
        writeName(out, service)
        writeU16(out, TYPE_PTR)
        writeU16(out, if (unicastResponse) CLASS_IN_UNICAST_REQUESTED else CLASS_IN)
        return out.toByteArray()
    }

    // ---------------------------------------------------------------- writers

    fun writeU16(out: ByteArrayOutputStream, value: Int) {
        out.write((value ushr 8) and 0xFF)
        out.write(value and 0xFF)
    }

    fun writeU32(out: ByteArrayOutputStream, value: Long) {
        out.write(((value ushr 24) and 0xFF).toInt())
        out.write(((value ushr 16) and 0xFF).toInt())
        out.write(((value ushr 8) and 0xFF).toInt())
        out.write((value and 0xFF).toInt())
    }

    /** Writes a DNS name as a sequence of length-prefixed labels. */
    fun writeName(out: ByteArrayOutputStream, name: String) {
        for (label in name.trimEnd('.').split('.')) {
            val bytes = label.toByteArray(Charsets.UTF_8)
            out.write(bytes.size and 0xFF)
            out.write(bytes, 0, bytes.size)
        }
        out.write(0)
    }

    // ---------------------------------------------------------------- helpers

    /** Lower-cases and guarantees a single trailing dot, for cache keying. */
    fun canonicalName(name: String): String {
        val trimmed = name.trim().trimEnd('.')
        return if (trimmed.isEmpty()) "." else "${trimmed.lowercase()}."
    }

    /** `true` when the service type looks like a MiPlay Xiaomi interconnect service. */
    fun isMiPlayService(name: String): Boolean {
        val canonical = canonicalName(name)
        return canonical == SERVICE_MI_CONNECT || canonical == SERVICE_LYRA
    }

    fun formatAddress(address: InetAddress): String =
        address.hostAddress?.substringBefore('%') ?: address.toString()

    fun resolve(host: String, port: Int): InetSocketAddress = try {
        InetSocketAddress(InetAddress.getByName(host), port)
    } catch (error: UnknownHostException) {
        InetSocketAddress.createUnresolved(host, port)
    }
}
