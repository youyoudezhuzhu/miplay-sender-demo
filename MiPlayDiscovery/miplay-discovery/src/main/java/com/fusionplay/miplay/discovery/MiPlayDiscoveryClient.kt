package com.fusionplay.miplay.discovery

import android.content.Context
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Minimal façade required by the task specification:
 * [startDiscovery], [stopDiscovery], [discoveredDevices], [DiscoveryListener].
 *
 * ```kotlin
 * val discovery = MiPlayDiscoveryClient(context)
 * discovery.addListener(object : MiPlayDiscoveryClient.DiscoveryListener {
 *     override fun onDevicesChanged(devices: List<MiPlayDevice>) { /* render */ }
 * })
 * discovery.startDiscovery()
 * ```
 */
class MiPlayDiscoveryClient(
    context: Context,
    private val queryIntervalMillis: Long = MiPlayDiscovery.DEFAULT_QUERY_INTERVAL_MILLIS
) {

    /** Listener surface; every method has a default so implementers pick what they need. */
    interface DiscoveryListener {
        fun onDevicesChanged(devices: List<MiPlayDevice>)
        fun onServiceFound(
            serviceType: String,
            serviceName: String,
            sourceIp: String,
            port: Int
        ) {}

        fun onPacket(packet: MiPlayPacket) {}
        fun onLog(message: String) {}
        fun onStarted() {}
        fun onStopped() {}
    }

    private val listeners = CopyOnWriteArrayList<DiscoveryListener>()

    /** Aggregated raw datagram log, for the debug view and for bug reports. */
    val packetLog = MiPlayPacketLog()

    private val engine = MiPlayDiscovery(
        context = context.applicationContext,
        listener = object : MiPlayDiscoveryListener {
            override fun onStarted() {
                listeners.forEach { it.onStarted() }
            }

            override fun onDevicesChanged(devices: List<MiPlayDevice>) {
                listeners.forEach { it.onDevicesChanged(devices) }
            }

            override fun onServiceFound(
                serviceType: String,
                serviceName: String,
                sourceIp: String,
                port: Int
            ) {
                listeners.forEach { it.onServiceFound(serviceType, serviceName, sourceIp, port) }
            }

            override fun onPacket(packet: MiPlayPacket) {
                packetLog.onPacket(packet)
                listeners.forEach { it.onPacket(packet) }
            }

            override fun onLog(message: String) {
                listeners.forEach { it.onLog(message) }
            }

            override fun onStopped() {
                listeners.forEach { it.onStopped() }
            }
        },
        queryIntervalMillis = queryIntervalMillis
    )

    val isRunning: Boolean get() = engine.isRunning

    /** Devices discovered so far. */
    val discoveredDevices: List<MiPlayDevice> get() = engine.discoveredDevices()

    fun addListener(listener: DiscoveryListener) {
        listeners.addIfAbsent(listener)
    }

    fun removeListener(listener: DiscoveryListener) {
        listeners.remove(listener)
    }

    /** Begins browsing; a no-op scan refresh when already running. */
    fun startDiscovery() = engine.startDiscovery()

    /** Stops browsing and releases sockets plus the Wi-Fi multicast lock. */
    fun stopDiscovery() = engine.stopDiscovery()
}
