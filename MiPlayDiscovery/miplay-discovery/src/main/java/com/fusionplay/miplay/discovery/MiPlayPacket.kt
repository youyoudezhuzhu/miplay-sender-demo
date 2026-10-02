package com.fusionplay.miplay.discovery

/** Direction of a captured datagram, for the raw protocol log. */
enum class MiPlayPacketDirection { SEND, RECV }

/**
 * One captured datagram, verbatim.
 *
 * The module's contract is that the *raw* protocol is always available: the UI
 * may render a friendly device card, but the debug log carries the complete hex
 * and ASCII of every datagram in both directions.
 */
data class MiPlayPacket(
    val direction: MiPlayPacketDirection,
    /** `host:port` of the sender for [MiPlayPacketDirection.SEND], responder for RECV. */
    val address: String,
    /** Local socket address that sent / received this datagram. */
    val localAddress: String,
    val byteCount: Int,
    /** Compact single-line hex. */
    val hex: String,
    /** Printable-ASCII rendering with `.` for non-printable bytes. */
    val ascii: String,
    /** 16-bytes-per-line dump with ASCII gutter. */
    val hexDump: String,
    /** mDNS service this datagram belongs to, when known. */
    val service: String?,
    /** Decoded DNS view, when the datagram was a DNS/mDNS message. */
    val decoded: String?,
    /** Why the datagram was sent. */
    val note: String?,
    val timestampMillis: Long = System.currentTimeMillis()
) {
    /** Renders the log block described in the task specification. */
    fun format(): String = buildString {
        appendLine("[MiPlayDiscovery]")
        appendLine(direction.name)
        appendLine("destination=$address")
        appendLine("local=$localAddress")
        appendLine("service=${service ?: "-"}")
        appendLine("length=$byteCount")
        if (note != null) appendLine("note=$note")
        appendLine()
        appendLine("HEX:")
        appendLine(hexDump)
        appendLine()
        appendLine("ASCII:")
        appendLine(ascii)
        if (decoded != null) {
            appendLine()
            appendLine("DECODED:")
            appendLine(decoded)
        }
    }.trimEnd()
}

/**
 * Recorder handed to [MiPlayDiscovery] for raw protocol capture.
 *
 * Implementations must be cheap and must not throw: the discovery loop calls
 * this on its own thread.
 */
interface MiPlayPacketRecorder {
    fun onPacket(packet: MiPlayPacket)
}

/** Simple in-memory ring buffer of raw datagrams, suitable for a debug screen. */
class MiPlayPacketLog(private val capacity: Int = 400) : MiPlayPacketRecorder {

    private val entries = ArrayDeque<MiPlayPacket>(capacity)
    private val lock = Any()

    override fun onPacket(packet: MiPlayPacket) {
        synchronized(lock) {
            if (entries.size >= capacity) entries.removeFirst()
            entries.addLast(packet)
        }
    }

    fun snapshot(): List<MiPlayPacket> = synchronized(lock) { entries.toList() }

    fun clear() = synchronized(lock) { entries.clear() }

    fun dump(): String = snapshot().joinToString("\n\n") { it.format() }
}
