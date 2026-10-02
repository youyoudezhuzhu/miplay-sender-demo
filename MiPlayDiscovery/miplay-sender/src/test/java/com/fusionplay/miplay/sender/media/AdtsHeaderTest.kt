package com.fusionplay.miplay.sender.media

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * ADTS framing used when the TS carries ADTS rather than bare LATM AUs.
 *
 * The header is 7 bytes (no CRC). Layout:
 * ```
 * FF F1 | profile+sfIndex+priv | chanCfg+lenHi | lenMid | lenLo+fullness | numFrames
 * ```
 * Verified here structurally; whether a real speaker wants ADTS or bare LATM
 * still needs on-device confirmation.
 */
class AdtsHeaderTest {

    /** Mirror of AacLatmEncoder.withAdts so the layout can be tested off-device. */
    private fun adts(auLen: Int, sampleRate: Int = 48_000, channels: Int = 2): ByteArray {
        val freqIndex = intArrayOf(
            96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050,
            16000, 12000, 11025, 8000, 7350
        ).indexOf(sampleRate).let { if (it < 0) 3 else it }
        val frameLen = auLen + 7
        val h = ByteArray(7)
        h[0] = 0xFF.toByte()
        h[1] = 0xF1.toByte()
        h[2] = (((2 - 1) shl 6) or (freqIndex shl 2) or ((channels shr 2) and 1)).toByte()
        h[3] = (((channels and 3) shl 6) or ((frameLen shr 11) and 0x03)).toByte()
        h[4] = ((frameLen shr 3) and 0xFF).toByte()
        h[5] = (((frameLen and 7) shl 5) or 0x1F).toByte()
        h[6] = 0xFC.toByte()
        return h
    }

    @Test
    fun `syncword is FFF and MPEG-4 with no CRC`() {
        val h = adts(100)
        assertEquals(0xFF, h[0].toInt() and 0xFF)
        assertEquals(0xF1, h[1].toInt() and 0xFF)   // FFF + MPEG-4 + layer 0 + protection_absent
    }

    @Test
    fun `48kHz stereo AAC-LC encodes the right profile and frequency index`() {
        val h = adts(100)
        // profile = AAC-LC-1 = 1 in the 2-bit field; sfIndex(48000) = 3
        assertEquals(1, (h[2].toInt() shr 6) and 0x03)
        assertEquals(3, (h[2].toInt() shr 2) and 0x0F)
        // channel config low bit is 0 for stereo(2)
        assertEquals(0, h[2].toInt() and 0x01)
        assertEquals(2, (h[3].toInt() shr 6) and 0x03)
    }

    @Test
    fun `frame length field round trips`() {
        for (auLen in intArrayOf(1, 100, 255, 1024, 4000)) {
            val h = adts(auLen)
            val total = ((h[3].toInt() and 0x03) shl 11) or
                    ((h[4].toInt() and 0xFF) shl 3) or
                    ((h[5].toInt() and 0xE0) shr 5)
            assertEquals("auLen=$auLen", auLen + 7, total)
        }
    }

    @Test
    fun `unknown sample rate falls back to index 3`() {
        val h = adts(50, sampleRate = 12345)
        assertEquals(3, (h[2].toInt() shr 2) and 0x0F)
    }

    @Test
    fun `44100 maps to index 4`() {
        val h = adts(50, sampleRate = 44_100)
        assertEquals(4, (h[2].toInt() shr 2) and 0x0F)
    }
}
