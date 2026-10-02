package com.fusionplay.miplay.sender.media

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pins the RTSP interleaved framing used by the MiPlay audio channel.
 *
 * Verified against a real capture: parsing 3,095,052 bytes as
 * `'$' | channel:u8 | length:u16be` consumes **100.00%** with **0 resync
 * events**, and the channel byte is always 0. See
 * `reports/MIPLAY_AUDIO_PUSH_PROTOCOL.md` §4.1.
 *
 * This is the reading that corrects V2's `'$' | length:u16be`.
 */
class InterleavedFrameTest {

    /** Build a frame the way the server must emit it. */
    private fun frame(channel: Int, payload: ByteArray): ByteArray =
        byteArrayOf(
            0x24,
            channel.toByte(),
            ((payload.size ushr 8) and 0xFF).toByte(),
            (payload.size and 0xFF).toByte()
        ) + payload

    @Test
    fun `header is marker channel and big-endian length`() {
        val f = frame(0, ByteArray(764))
        assertEquals(0x24, f[0].toInt() and 0xFF)
        assertEquals(0, f[1].toInt() and 0xFF)                       // channel 0, as captured
        assertEquals(0x02, f[2].toInt() and 0xFF)                    // 764 = 0x02FC
        assertEquals(0xFC, f[3].toInt() and 0xFF)
        assertEquals(764 + 4, f.size)
    }

    @Test
    fun `the captured 764-byte frame header round trips`() {
        // Real frame from the capture: 24 00 02 fc ...
        val header = byteArrayOf(0x24, 0x00, 0x02, 0xFC.toByte())
        val len = ((header[2].toInt() and 0xFF) shl 8) or (header[3].toInt() and 0xFF)
        assertEquals(764, len)
        // The V2 misreading would have yielded 2 and desynced immediately.
        assertEquals(2, ((header[1].toInt() and 0xFF) shl 8) or (header[2].toInt() and 0xFF))
    }

    @Test
    fun `parsing a concatenated stream consumes every byte with no resync`() {
        val payloads = listOf(ByteArray(764) { 0x11 }, ByteArray(1328) { 0x22 }, ByteArray(200) { 0x33 })
        val stream = payloads.map { frame(0, it) }.reduce { a, b -> a + b }

        var i = 0; var frames = 0; var consumed = 0
        while (i + 4 <= stream.size) {
            assertEquals(0x24, stream[i].toInt() and 0xFF)           // no resync needed
            val ch = stream[i + 1].toInt() and 0xFF
            val len = ((stream[i + 2].toInt() and 0xFF) shl 8) or (stream[i + 3].toInt() and 0xFF)
            assertEquals(0, ch)
            if (i + 4 + len > stream.size) break
            i += 4 + len; frames++; consumed = i
        }
        assertEquals(3, frames)
        assertEquals(stream.size, consumed)
        assertTrue("must consume 100% without resyncing", consumed == stream.size)
    }

    @Test
    fun `a payload containing 0x24 does not break framing`() {
        // Audio payloads contain 0x24 by chance; only the length may drive the cursor.
        val payload = ByteArray(64) { if (it % 7 == 0) 0x24 else 0x41 }
        val f = frame(0, payload)
        val len = ((f[2].toInt() and 0xFF) shl 8) or (f[3].toInt() and 0xFF)
        assertEquals(payload.size, len)
        assertEquals(f.size, 4 + len)
    }
}
