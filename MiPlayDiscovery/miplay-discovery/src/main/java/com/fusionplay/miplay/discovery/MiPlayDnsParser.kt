package com.fusionplay.miplay.discovery

import java.net.InetAddress
import java.net.UnknownHostException

/**
 * Decoder for the DNS / mDNS packets MiPlay receivers actually send.
 *
 * The decoder is deliberately total: anything it cannot interpret is preserved
 * as raw bytes instead of being dropped, so unknown record types survive into
 * the debug log (real Xiaomi speakers emit type 47 records that no public
 * specification documents).
 */
object MiPlayDnsParser {

    private const val HEADER_LENGTH = 12
    private const val MAX_POINTER_JUMPS = 24

    /**
     * A single resource record with its RDATA already resolved where the type
     * is understood.
     */
    data class Record(
        val name: String,
        val type: Int,
        val dnsClass: Int,
        val ttl: Long,
        val rdLength: Int,
        /** Raw RDATA bytes, exactly as received. */
        val rawData: ByteArray,
        /** PTR / CNAME / NS target. */
        val domainName: String? = null,
        /** TXT strings. */
        val txt: List<String> = emptyList(),
        /** A record address literal. */
        val address: String? = null,
        /** SRV fields. */
        val srvPriority: Int? = null,
        val srvWeight: Int? = null,
        val srvPort: Int? = null,
        val srvTarget: String? = null
    ) {
        val typeName: String
            get() = when (type) {
                MiPlayMdns.TYPE_A -> "A"
                MiPlayMdns.TYPE_PTR -> "PTR"
                MiPlayMdns.TYPE_TXT -> "TXT"
                MiPlayMdns.TYPE_AAAA -> "AAAA"
                MiPlayMdns.TYPE_SRV -> "SRV"
                else -> "TYPE$type"
            }

        val isUnicastResponseRequested: Boolean
            get() = dnsClass and 0x8000 != 0

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Record) return false
            return name == other.name && type == other.type && dnsClass == other.dnsClass &&
                ttl == other.ttl && rawData.contentEquals(other.rawData)
        }

        override fun hashCode(): Int {
            var result = name.hashCode()
            result = 31 * result + type
            result = 31 * result + dnsClass
            result = 31 * result + ttl.hashCode()
            result = 31 * result + rawData.contentHashCode()
            return result
        }
    }

    data class Question(val name: String, val type: Int, val dnsClass: Int)

    data class Message(
        val id: Int,
        val flags: Int,
        val questions: List<Question>,
        val answers: List<Record>,
        val authorities: List<Record>,
        val additionals: List<Record>
    ) {
        val isResponse: Boolean get() = flags and 0x8000 != 0
        val isAuthoritative: Boolean get() = flags and 0x0400 != 0

        val allRecords: List<Record> get() = answers + authorities + additionals

        /**
         * Human readable dump for the debug log. Never abbreviated away — the
         * whole point of the module is to keep the raw protocol visible.
         */
        fun describe(): String = buildString {
            append("flags=0x").append(Integer.toHexString(flags))
            append(" qd=").append(questions.size)
            append(" an=").append(answers.size)
            append(" ns=").append(authorities.size)
            append(" ar=").append(additionals.size)
            append(" response=").append(isResponse)
            for (question in questions) {
                append("\n  Q    ").append(question.name)
                append(" type=").append(question.type)
                append(" class=0x").append(Integer.toHexString(question.dnsClass))
            }
            for (record in allRecords) {
                append("\n  ").append(record.typeName.padEnd(5))
                append(record.name)
                append(" ttl=").append(record.ttl)
                append(" class=0x").append(Integer.toHexString(record.dnsClass))
                when {
                    record.type == MiPlayMdns.TYPE_PTR -> append(" -> ").append(record.domainName)
                    record.type == MiPlayMdns.TYPE_SRV ->
                        append(" port=").append(record.srvPort).append(" target=").append(record.srvTarget)
                    record.type == MiPlayMdns.TYPE_TXT -> {
                        for (value in record.txt) {
                            append("\n       TXT: ").append(value)
                        }
                    }
                    record.type == MiPlayMdns.TYPE_A || record.type == MiPlayMdns.TYPE_AAAA ->
                        append(" = ").append(record.address)
                    else -> append(" raw=").append(record.rawData.toHex())
                }
            }
        }
    }

    /**
     * Parses a packet. Returns `null` when the buffer is too short or
     * structurally impossible; callers keep the hex dump regardless.
     */
    fun parse(packet: ByteArray): Message? {
        if (packet.size < HEADER_LENGTH) return null
        val reader = Reader(packet)
        return try {
            val id = reader.u16()
            val flags = reader.u16()
            val qdCount = reader.u16()
            val anCount = reader.u16()
            val nsCount = reader.u16()
            val arCount = reader.u16()

            val questions = ArrayList<Question>(qdCount)
            repeat(qdCount) {
                val name = reader.name() ?: return null
                val type = reader.u16()
                val dnsClass = reader.u16()
                questions += Question(name, type, dnsClass)
            }

            fun readRecords(count: Int): List<Record> {
                val out = ArrayList<Record>(count)
                repeat(count) {
                    // Local functions cannot non-locally return from parse();
                    // raise instead and let the single catch below handle it.
                    out += reader.record() ?: throw MalformedPacketException()
                }
                return out
            }

            val answers = readRecords(anCount)
            val authorities = readRecords(nsCount)
            val additionals = readRecords(arCount)
            Message(id, flags, questions, answers, authorities, additionals)
        } catch (error: Exception) {
            null
        }
    }

    /** Internal signal that a record could not be read; never escapes [parse]. */
    private class MalformedPacketException : RuntimeException("malformed DNS packet")

    /** Convenience: parse and immediately render for logging. */
    fun parseAndDescribe(packet: ByteArray): String = parse(packet)?.describe() ?: "<unparseable DNS message>"

    // ------------------------------------------------------------------ reader

    private class Reader(private val packet: ByteArray) {
        private var cursor = 0

        fun u8(): Int {
            require(cursor < packet.size) { "truncated" }
            return packet[cursor++].toInt() and 0xFF
        }

        fun u16(): Int = (u8() shl 8) or u8()

        fun u32(): Long = (u16().toLong() shl 16) or u16().toLong()

        /** Reads a (possibly compressed) DNS name and advances past it. */
        fun name(): String? {
            val start = cursor
            val labels = StringBuilder()
            var jumps = 0
            var consumed = -1

            while (true) {
                val length = u8()
                when {
                    length == 0 -> {
                        if (consumed < 0) consumed = cursor
                        break
                    }
                    length and 0xC0 == 0xC0 -> {
                        val low = u8()
                        val pointer = ((length and 0x3F) shl 8) or low
                        if (consumed < 0) consumed = cursor
                        if (++jumps > MAX_POINTER_JUMPS) return null
                        if (pointer >= packet.size) return null
                        cursor = pointer
                    }
                    else -> {
                        if (cursor + length > packet.size) return null
                        if (labels.isNotEmpty()) labels.append('.')
                        labels.append(String(packet, cursor, length, Charsets.UTF_8))
                        cursor += length
                    }
                }
            }
            cursor = if (consumed >= 0) consumed else cursor
            if (cursor < start) cursor = start
            // Absolute (fully qualified) form, matching how DNS treats names in
            // a packet's answer sections. DeviceRegistry normalises through
            // MiPlayMdns.canonicalName() before using a name as a cache key.
            return labels.toString() + "."
        }

        fun record(): Record? {
            val name = name() ?: return null
            val type = u16()
            val dnsClass = u16()
            val ttl = u32()
            val rdLength = u16()
            if (cursor + rdLength > packet.size) return null
            val rdataOffset = cursor
            val rdata = packet.copyOfRange(rdataOffset, rdataOffset + rdLength)
            cursor += rdLength

            return when (type) {
                MiPlayMdns.TYPE_PTR -> Record(
                    name, type, dnsClass, ttl, rdLength, rdata,
                    domainName = nameAt(rdataOffset)
                )
                MiPlayMdns.TYPE_SRV -> {
                    if (rdLength < 6) return Record(name, type, dnsClass, ttl, rdLength, rdata)
                    val priority = ((rdata[0].toInt() and 0xFF) shl 8) or (rdata[1].toInt() and 0xFF)
                    val weight = ((rdata[2].toInt() and 0xFF) shl 8) or (rdata[3].toInt() and 0xFF)
                    val port = ((rdata[4].toInt() and 0xFF) shl 8) or (rdata[5].toInt() and 0xFF)
                    Record(
                        name, type, dnsClass, ttl, rdLength, rdata,
                        srvPriority = priority, srvWeight = weight, srvPort = port,
                        srvTarget = nameAt(rdataOffset + 6)
                    )
                }
                MiPlayMdns.TYPE_TXT -> Record(
                    name, type, dnsClass, ttl, rdLength, rdata,
                    txt = readTxtStrings(rdata)
                )
                MiPlayMdns.TYPE_A -> {
                    val literal = if (rdLength == 4) {
                        "${rdata[0].toInt() and 0xFF}.${rdata[1].toInt() and 0xFF}." +
                            "${rdata[2].toInt() and 0xFF}.${rdata[3].toInt() and 0xFF}"
                    } else null
                    Record(name, type, dnsClass, ttl, rdLength, rdata, address = literal)
                }
                MiPlayMdns.TYPE_AAAA -> {
                    val literal = if (rdLength == 16) {
                        try {
                            InetAddress.getByAddress(rdata).hostAddress?.substringBefore('%')
                        } catch (error: UnknownHostException) {
                            null
                        }
                    } else null
                    Record(name, type, dnsClass, ttl, rdLength, rdata, address = literal)
                }
                else -> Record(name, type, dnsClass, ttl, rdLength, rdata)
            }
        }

        private fun nameAt(offset: Int): String? {
            val saved = cursor
            return try {
                cursor = offset
                name()
            } catch (error: Exception) {
                null
            } finally {
                cursor = saved
            }
        }

        private fun readTxtStrings(data: ByteArray): List<String> {
            val out = ArrayList<String>()
            var i = 0
            while (i < data.size) {
                val length = data[i].toInt() and 0xFF
                i += 1
                if (i + length > data.size) break
                out += String(data, i, length, Charsets.UTF_8)
                i += length
            }
            return out
        }
    }
}

/** Lower-case hex, the canonical form used by every log line in this module. */
fun ByteArray.toHex(): String {
    if (isEmpty()) return ""
    val digits = "0123456789abcdef"
    val builder = StringBuilder(size * 2)
    for (byte in this) {
        val value = byte.toInt() and 0xFF
        builder.append(digits[value ushr 4]).append(digits[value and 0x0F])
    }
    return builder.toString()
}

/** Printable ASCII rendering with `.` for non-printable bytes, for the debug log. */
fun ByteArray.toAscii(): String {
    val builder = StringBuilder(size)
    for (byte in this) {
        val value = byte.toInt() and 0xFF
        builder.append(if (value in 0x20..0x7E) value.toChar() else '.')
    }
    return builder.toString()
}

/** Hex dump with 16 bytes per line and a trailing ASCII column. */
fun ByteArray.toHexDump(): String {
    if (isEmpty()) return "(empty)"
    val builder = StringBuilder()
    var offset = 0
    while (offset < size) {
        val end = minOf(offset + 16, size)
        builder.append(String.format("%04x  ", offset))
        for (i in offset until end) {
            builder.append(String.format("%02x ", this[i].toInt() and 0xFF))
        }
        for (i in end until offset + 16) builder.append("   ")
        builder.append(" |")
        for (i in offset until end) {
            val value = this[i].toInt() and 0xFF
            builder.append(if (value in 0x20..0x7E) value.toChar() else '.')
        }
        builder.append('|')
        if (end < size) builder.append('\n')
        offset = end
    }
    return builder.toString()
}
