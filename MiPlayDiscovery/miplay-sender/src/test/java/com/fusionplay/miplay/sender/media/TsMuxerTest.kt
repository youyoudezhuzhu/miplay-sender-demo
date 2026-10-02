package com.fusionplay.miplay.sender.media

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Structural tests for the MPEG-TS muxer.
 *
 * The expectations mirror the layout observed in a real MiPlay capture
 * (`reports/MIPLAY_AUDIO_PUSH_PROTOCOL.md` §4.3): PAT on 0x0000, PMT on 0x0100,
 * PCR on 0x1000 and audio PES on 0x1100 with stream_id 0xC0.
 */
class TsMuxerTest {

    private fun pidOf(pkt: ByteArray): Int =
        ((pkt[1].toInt() and 0x1F) shl 8) or (pkt[2].toInt() and 0xFF)

    private fun pusi(pkt: ByteArray): Boolean = (pkt[1].toInt() and 0x40) != 0

    @Test
    fun `every packet is 188 bytes and starts with the sync byte`() {
        val m = TsMuxer()
        val packets = listOf(
            m.buildPat(), m.buildPmt(), m.buildPcrPacket(),
            m.muxAccessUnit(ByteArray(100) { 0x5A }, 0).copyOfRange(0, 188),
            m.muxAccessUnit(ByteArray(400) { 0x5A }, 1000).copyOfRange(0, 188)
        )
        for (p in packets) {
            assertEquals(188, p.size)
            assertEquals(TsMuxer.SYNC_BYTE.toByte(), p[0])
        }
    }

    @Test
    fun `pat declares program 1 mapped to the pmt pid`() {
        val pkt = TsMuxer().buildPat()
        assertEquals(0x0000, pidOf(pkt))
        assertTrue("payload_unit_start must be set on PSI", pusi(pkt))
        // TS header is 4 bytes, so the PSI section starts at pkt[4].
        assertEquals(0x00, pkt[4].toInt() and 0xFF)          // table_id = PAT
        // section_length
        val sectionLen = ((pkt[5].toInt() and 0x0F) shl 8) or (pkt[6].toInt() and 0xFF)
        assertEquals(13, sectionLen)                          // 5 header + 4 entry + 4 crc
        // program_number = 1  (section offset 3..4 -> packet 7..8)
        assertEquals(0, pkt[7].toInt() and 0xFF)
        assertEquals(1, pkt[8].toInt() and 0xFF)
        // PMT pid = 0x0100  (section offset 5..6 -> packet 9..10)
        val pmtPid = ((pkt[9].toInt() and 0x1F) shl 8) or (pkt[10].toInt() and 0xFF)
        assertEquals(0x0100, pmtPid)
    }

    @Test
    fun `pmt declares the audio pid with the configured stream type`() {
        val pkt = TsMuxer().buildPmt()
        assertEquals(0x0100, pidOf(pkt))
        assertEquals(0x02, pkt[4].toInt() and 0xFF)          // table_id = PMT
        // section: 3 skip + prog_num(2) + ver(1) + sec(2) = body starts at section offset 8
        // -> packet offset 4 + 8 = 12 for PCR_PID
        val pcrPid = ((pkt[12].toInt() and 0x1F) shl 8) or (pkt[13].toInt() and 0xFF)
        assertEquals(0x1000, pcrPid)
        // program_info_length(2) then the elementary stream entry
        assertEquals(TsMuxer.STREAM_TYPE_AAC_LATM, pkt[16].toInt() and 0xFF)
        val esPid = ((pkt[17].toInt() and 0x1F) shl 8) or (pkt[18].toInt() and 0xFF)
        assertEquals(0x1100, esPid)
    }

    @Test
    fun `pmt honours a different audio stream type`() {
        val pkt = TsMuxer(audioStreamType = TsMuxer.STREAM_TYPE_AAC_ADTS).buildPmt()
        assertEquals(TsMuxer.STREAM_TYPE_AAC_ADTS, pkt[16].toInt() and 0xFF)
    }

    @Test
    fun `pcr packet carries an adaptation field on the pcr pid`() {
        val m = TsMuxer()
        m.setPcrMicros(1000)
        val pkt = m.buildPcrPacket()
        assertEquals(0x1000, pidOf(pkt))
        // adaptation_field_control = 10 -> 0x20
        assertEquals(0x20, pkt[3].toInt() and 0x30)
        assertEquals(7, pkt[4].toInt() and 0xFF)             // adaptation_field_length
        assertTrue("PCR flag must be set", pkt[5].toInt() and 0x10 != 0)
    }

    @Test
    fun `pes header uses stream id 0xC0 with a PTS`() {
        val pes = TsMuxer().buildPes(ByteArray(10) { 1 }, 1_000_000)
        assertEquals(0x00, pes[0].toInt() and 0xFF)
        assertEquals(0x00, pes[1].toInt() and 0xFF)
        assertEquals(0x01, pes[2].toInt() and 0xFF)
        assertEquals(0xC0, pes[3].toInt() and 0xFF)          // audio stream id, as captured
        // PTS_DTS_flags = '10' (PTS only)
        assertEquals(0x80, pes[7].toInt() and 0xC0)
        // marker bits in the PTS must be 1
        assertTrue(pes[9].toInt() and 1 != 0)
        assertTrue(pes[11].toInt() and 1 != 0)
        assertTrue(pes[13].toInt() and 1 != 0)
    }

    @Test
    fun `pes packet length covers flags header and payload`() {
        val data = ByteArray(50)
        val pes = TsMuxer().buildPes(data, 0)
        val declared = ((pes[4].toInt() and 0xFF) shl 8) or (pes[5].toInt() and 0xFF)
        assertEquals(3 + 5 + data.size, declared)
        assertEquals(6 + 3 + 5 + data.size, pes.size)
    }

    @Test
    fun `a large access unit spans multiple ts packets with pusi only on the first`() {
        val m = TsMuxer()
        val ts = m.muxAccessUnit(ByteArray(500) { 0x33 }, 0)
        assertEquals(0, ts.size % 188)
        val count = ts.size / 188
        assertTrue("500-byte AU must span more than one packet", count >= 3)

        val first = ts.copyOfRange(0, 188)
        assertTrue("first packet sets payload_unit_start", pusi(first))
        for (i in 1 until count) {
            val p = ts.copyOfRange(i * 188, (i + 1) * 188)
            assertTrue("only the first packet may set payload_unit_start", !pusi(p))
            assertEquals(0x1100, pidOf(p))
        }
    }

    @Test
    fun `continuity counter increments per pid and wraps at 16`() {
        val m = TsMuxer()
        val ccs = (0 until 20).map { m.buildPcrPacket()[3].toInt() and 0x0F }
        for (i in 1 until ccs.size) {
            assertEquals((ccs[i - 1] + 1) and 0x0F, ccs[i])
        }
        assertEquals(0, ccs[16])                              // wrapped
    }

    @Test
    fun `pcr advances at 27 MHz`() {
        val m = TsMuxer()
        m.setPcrMicros(0)
        val before = m.buildPcrPacket()
        m.advancePcr(1_000_000)                               // one second
        val after = m.buildPcrPacket()
        // 1 s = 27_000_000 ticks; byte 6 holds bits 32..25
        val b6 = after[6].toInt() and 0xFF
        assertEquals((27_000_000L ushr 25).toInt() and 0xFF, b6)
        assertTrue(before[6] != after[6] || before[7] != after[7])
    }
}
