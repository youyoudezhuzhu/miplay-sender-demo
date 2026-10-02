package com.fusionplay.miplay.sender.media

/**
 * Minimal MPEG-TS muxer for the MiPlay audio push path.
 *
 * Structure reproduced from a real capture (see
 * `reports/MIPLAY_AUDIO_PUSH_PROTOCOL.md` §4.3):
 *
 * | PID      | contents                        |
 * |----------|---------------------------------|
 * | `0x0000` | PAT                             |
 * | `0x0100` | PMT                             |
 * | `0x1000` | PCR clock reference             |
 * | `0x1100` | audio PES (stream_id `0xC0`)    |
 *
 * Every TS packet is exactly [PACKET_SIZE] bytes and starts with `0x47`.
 * The muxer is deliberately encoder-agnostic: it accepts already-encoded audio
 * access units (AAC-LATM / ADTS) and packetises them.
 *
 * This class is **not** thread-safe.
 */
class TsMuxer(
    private val programNumber: Int = 1,
    private val pmtPid: Int = 0x0100,
    private val pcrPid: Int = 0x1000,
    private val audioPid: Int = 0x1100,
    /** MPEG-TS stream_type for the audio elementary stream. */
    private val audioStreamType: Int = STREAM_TYPE_AAC_LATM
) {

    companion object {
        const val PACKET_SIZE = 188
        const val SYNC_BYTE = 0x47

        const val STREAM_TYPE_AAC_ADTS = 0x0F
        const val STREAM_TYPE_AAC_LATM = 0x11
        const val STREAM_TYPE_MP3 = 0x03

        private const val PID_PAT = 0x0000
        private const val TABLE_ID_PAT = 0x00
        private const val TABLE_ID_PMT = 0x02
    }

    /** Continuity counters, one per PID. */
    private val continuity = HashMap<Int, Int>()

    /** 27 MHz PCR base; advanced by the caller via [advancePcr]. */
    private var pcrBase: Long = 0

    private var patVersion = 0
    private var pmtVersion = 0

    private fun nextCc(pid: Int): Int {
        val c = (continuity[pid] ?: 0) and 0x0F
        continuity[pid] = (c + 1) and 0x0F
        return c
    }

    /** Advance the PCR clock by [micros] microseconds. */
    fun advancePcr(micros: Long) {
        // 27 MHz: 1 microsecond = 27 ticks.
        pcrBase = (pcrBase + micros * 27) and 0x1_FFFFFFFFL
    }

    fun setPcrMicros(value: Long) {
        pcrBase = (value * 27) and 0x1_FFFFFFFFL
    }

    // ------------------------------------------------------------------ PSI
    /** Build a complete PAT section (one TS packet). */
    fun buildPat(): ByteArray {
        val section = ByteArray(0)
        val body = ArrayList<Byte>()
        // program_number (16) + reserved(3) + PID (13)
        body.add(((programNumber ushr 8) and 0xFF).toByte())
        body.add((programNumber and 0xFF).toByte())
        body.add((0xE0 or ((pmtPid ushr 8) and 0x1F)).toByte())
        body.add((pmtPid and 0xFF).toByte())
        return psiPacket(PID_PAT, TABLE_ID_PAT, body.toByteArray(), patVersion)
    }

    /** Build a complete PMT section (one TS packet). */
    fun buildPmt(): ByteArray {
        val body = ArrayList<Byte>()
        // PCR_PID
        body.add((0xE0 or ((pcrPid ushr 8) and 0x1F)).toByte())
        body.add((pcrPid and 0xFF).toByte())
        // program_info_length = 0
        body.add(0xF0.toByte())
        body.add(0x00.toByte())
        // one elementary stream: stream_type, elementary_PID, ES_info_length=0
        body.add(audioStreamType.toByte())
        body.add((0xE0 or ((audioPid ushr 8) and 0x1F)).toByte())
        body.add((audioPid and 0xFF).toByte())
        body.add(0xF0.toByte())
        body.add(0x00.toByte())
        return psiPacket(pmtPid, TABLE_ID_PMT, body.toByteArray(), pmtVersion)
    }

    /** Wrap a PSI [body] into a single 188-byte TS packet. */
    private fun psiPacket(pid: Int, tableId: Int, body: ByteArray, version: Int): ByteArray {
        // section_length counts everything after its own 2 bytes:
        //   5 bytes of table header (table_id_ext, version, section numbers) + body + CRC
        val sectionLength = 5 + body.size + 4
        // full section = 3 (table_id + section_length) + sectionLength
        val section = ByteArray(3 + sectionLength)
        section[0] = tableId.toByte()
        section[1] = (0xB0 or ((sectionLength ushr 8) and 0x0F)).toByte()   // section_syntax=1
        section[2] = (sectionLength and 0xFF).toByte()
        section[3] = ((programNumber ushr 8) and 0xFF).toByte()
        section[4] = (programNumber and 0xFF).toByte()
        section[5] = (0xC1 or ((version and 0x1F) shl 1)).toByte()          // reserved + current_next=1
        section[6] = 0                                                       // section_number
        section[7] = 0                                                       // last_section_number
        System.arraycopy(body, 0, section, 8, body.size)
        // CRC32/MPEG-2 over the whole section
        val crc = mpegCrc32(section)
        val withCrc = section + byteArrayOf(
            (crc ushr 24).toByte(), (crc ushr 16).toByte(),
            (crc ushr 8).toByte(), crc.toByte()
        )

        val pkt = ByteArray(PACKET_SIZE) { 0xFF.toByte() }
        pkt[0] = SYNC_BYTE.toByte()
        pkt[1] = (0x40 or ((pid ushr 8) and 0x1F)).toByte()   // payload_unit_start=1
        pkt[2] = (pid and 0xFF).toByte()
        pkt[3] = (0x10 or nextCc(pid)).toByte()               // payload only
        System.arraycopy(withCrc, 0, pkt, 4, withCrc.size)
        return pkt
    }

    // ------------------------------------------------------------------ PCR
    /** A PCR-bearing packet on [pcrPid] (adaptation field only). */
    fun buildPcrPacket(): ByteArray {
        val pkt = ByteArray(PACKET_SIZE) { 0xFF.toByte() }
        pkt[0] = SYNC_BYTE.toByte()
        pkt[1] = ((pcrPid ushr 8) and 0x1F).toByte()
        pkt[2] = (pcrPid and 0xFF).toByte()
        // adaptation_field_control = 10 (adaptation only), adaptation length = 7
        pkt[3] = (0x20 or nextCc(pcrPid)).toByte()
        pkt[4] = 7
        pkt[5] = 0x10.toByte()                                // PCR_flag
        val base = pcrBase
        pkt[6] = (base ushr 25).toByte()
        pkt[7] = (base ushr 17).toByte()
        pkt[8] = (base ushr 9).toByte()
        pkt[9] = (base ushr 1).toByte()
        pkt[10] = (((base and 1L) shl 7) or 0x7E).toByte()    // reserved bits + ext high
        pkt[11] = 0                                           // PCR extension
        return pkt
    }

    // ------------------------------------------------------------------ PES
    /**
     * Packetise one audio access unit into TS packets.
     *
     * @param data encoded audio (LATM/ADTS/…) for exactly one access unit.
     * @param ptsMicros presentation timestamp, microseconds.
     */
    fun muxAccessUnit(data: ByteArray, ptsMicros: Long): ByteArray {
        val pes = buildPes(data, ptsMicros)
        return packetisePes(pes)
    }

    /** Build the PES packet (header + payload) for one access unit. */
    fun buildPes(data: ByteArray, ptsMicros: Long): ByteArray {
        // PES_packet_length covers the 3 flag/len bytes + header data + payload.
        val headerDataLen = 5                                   // PTS only
        val pesLen = 3 + headerDataLen + data.size
        val out = ByteArray(6 + 3 + headerDataLen + data.size)
        out[0] = 0x00; out[1] = 0x00; out[2] = 0x01
        out[3] = 0xC0.toByte()                                  // stream_id: audio
        out[4] = ((pesLen ushr 8) and 0xFF).toByte()
        out[5] = (pesLen and 0xFF).toByte()
        out[6] = 0x84.toByte()                                  // '10' + data_alignment + PTS
        out[7] = 0x80.toByte()                                  // PTS only
        out[8] = headerDataLen.toByte()
        writePts(out, 9, ptsMicros, 0x02)                       // '0010' = PTS only
        System.arraycopy(data, 0, out, 14, data.size)
        return out
    }

    /**
     * Split a PES packet across TS packets on [audioPid].
     * A 2-byte adaptation field is used to keep the payload 184-aligned bytes.
     */
    private fun packetisePes(pes: ByteArray): ByteArray {
        val out = ArrayList<Byte>()
        var offset = 0
        var first = true
        val payloadSize = PACKET_SIZE - 4

        while (offset < pes.size) {
            val remaining = pes.size - offset
            val pkt = ByteArray(PACKET_SIZE) { 0xFF.toByte() }
            pkt[0] = SYNC_BYTE.toByte()
            // payload_unit_start only on the first packet of the PES
            val pusi = if (first) 0x40 else 0x00
            pkt[1] = (pusi or ((audioPid ushr 8) and 0x1F)).toByte()
            pkt[2] = (audioPid and 0xFF).toByte()

            if (remaining >= payloadSize) {
                pkt[3] = (0x10 or nextCc(audioPid)).toByte()
                System.arraycopy(pes, offset, pkt, 4, payloadSize)
                offset += payloadSize
            } else {
                // Last packet: pad with an adaptation field so the packet is full.
                val stuffing = payloadSize - remaining
                if (stuffing == 1) {
                    // adaptation_field_length = 0 means 1 stuffing byte
                    pkt[3] = (0x30 or nextCc(audioPid)).toByte()
                    pkt[4] = 0
                    System.arraycopy(pes, offset, pkt, 5, remaining)
                } else {
                    pkt[3] = (0x30 or nextCc(audioPid)).toByte()
                    pkt[4] = (stuffing - 1).toByte()
                    if (stuffing > 1) pkt[5] = 0x00.toByte()
                    System.arraycopy(pes, offset, pkt, 4 + stuffing, remaining)
                }
                offset = pes.size
            }
            out.addAll(pkt.toList())
            first = false
        }
        return out.toByteArray()
    }

    // ------------------------------------------------------------------ PTS
    /** Write a 33-bit PTS using the 5-byte MPEG encoding. */
    private fun writePts(buf: ByteArray, at: Int, micros: Long, marker: Int) {
        val pts = (micros * 90) and 0x1_FFFFFFFFL      // 90 kHz
        buf[at] = ((marker shl 4) or (((pts ushr 30) and 0x07).toInt()) shl 1 or 1).toByte()
        buf[at + 1] = ((pts ushr 22) and 0xFF).toByte()
        buf[at + 2] = ((((pts ushr 15) and 0x7F).toInt() shl 1) or 1).toByte()
        buf[at + 3] = ((pts ushr 7) and 0xFF).toByte()
        buf[at + 4] = ((((pts and 0x7F).toInt()) shl 1) or 1).toByte()
    }

    /** CRC-32/MPEG-2 as required for PSI sections. */
    private fun mpegCrc32(data: ByteArray): Long {
        var crc = 0xFFFFFFFFL
        for (b in data) {
            crc = crc xor ((b.toLong() and 0xFF) shl 24)
            repeat(8) {
                crc = if (crc and 0x8000_0000L != 0L) {
                    ((crc shl 1) xor 0x04C11DB7L) and 0xFFFFFFFFL
                } else {
                    (crc shl 1) and 0xFFFFFFFFL
                }
            }
        }
        return crc and 0xFFFFFFFFL
    }
}
