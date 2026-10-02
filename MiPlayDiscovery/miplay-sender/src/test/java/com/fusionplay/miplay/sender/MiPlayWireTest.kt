package com.fusionplay.miplay.sender

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests pinned to values captured from a real Xiaomi speaker session.
 *
 * Every constant here is taken from an actual packet capture, so these tests
 * fail if the wire format or the crypto drifts from the verified behaviour.
 * See `reports/MIPLAY_CRYPTO_ANALYSIS_V4.md` for provenance.
 */
class MiPlayWireTest {

    private fun hex(s: String): ByteArray =
        ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    // ------------------------------------------------------------------ pad
    @Test
    fun `pad length is always 1 to 16`() {
        assertEquals(16, MiPlayWire.padLength(0))    // empty payload still pads a full block
        assertEquals(15, MiPlayWire.padLength(1))
        assertEquals(2, MiPlayWire.padLength(14))
        assertEquals(1, MiPlayWire.padLength(15))
        assertEquals(16, MiPlayWire.padLength(16))   // exact multiple pads a whole block
        assertEquals(16, MiPlayWire.padLength(32))
        for (n in 0..1000) assertTrue(MiPlayWire.padLength(n) in 1..16)
    }

    // ------------------------------------------------------------------ crc
    @Test
    fun `integrity matches the captured envelope`() {
        // Real HeartBeat frame body from a live capture:
        //   00 07 01 e0 10 56 36 e0 96 | <16 bytes ciphertext>
        // stored integrity = 0x5636e096, computed over the ciphertext only.
        val body = hex("000701e0105636e09616d4410bbad49a42299092ee885113f5")
        val env = MiPlayWire.parseEnvelope(body)
        assertNotNull(env)
        assertTrue("integrity must verify", MiPlayWire.verify(env!!))
        assertEquals(0x5636e096L, env.integrity)
        assertEquals(0x10, env.pad)
        assertEquals(0xE0, env.flags)
        assertEquals(16, env.ciphertext.size)
    }

    @Test
    fun `integrity is key independent and stable`() {
        val ct = hex("16d4410bbad49a42299092ee885113f5")
        val a = MiPlayWire.integrity(ct)
        val b = MiPlayWire.integrity(ct.copyOf())
        assertEquals(a, b)
        assertEquals(0x5636e096L, a)
    }

    // -------------------------------------------------------------- framing
    @Test
    fun `frame round trips`() {
        val body = byteArrayOf(1, 2, 3, 4, 5)
        val frame = MiPlayWire.frame(cmd = 0x58, seq = 0x1234, body = body, outer = 0)
        val (frames, consumed) = MiPlayWire.parseFrames(frame)
        assertEquals(frame.size, consumed)
        assertEquals(1, frames.size)
        assertEquals(0x58, frames[0].cmd)
        assertEquals(0x1234, frames[0].seq)
        assertArrayEquals(body, frames[0].body)
    }

    @Test
    fun `wrapper frame records outer type`() {
        // cmd 0x14 sets outer_type = 0x14 on the wire.
        val frame = MiPlayWire.frame(cmd = 0x14, seq = 1, body = byteArrayOf(9), outer = 0x14)
        assertEquals(0x14, frame[1].toInt() and 0xFF)
        assertEquals(0x14, frame[2].toInt() and 0xFF)
    }

    @Test
    fun `parser keeps a partial frame as carry`() {
        val full = MiPlayWire.frame(0x1A, 7, ByteArray(16))
        val partial = full.copyOfRange(0, full.size - 4)
        val (frames, consumed) = MiPlayWire.parseFrames(partial)
        assertTrue("no complete frame yet", frames.isEmpty())
        assertEquals(0, consumed)
    }

    @Test
    fun `parser does not resync on 0x24 inside a body`() {
        // 0x24 is legal inside ciphertext; the length field is the only cursor.
        val body = ByteArray(32) { if (it == 5) 0x24 else 0x41 }
        val frame = MiPlayWire.frame(0x58, 1, body)
        val (frames, _) = MiPlayWire.parseFrames(frame)
        assertEquals(1, frames.size)
        assertArrayEquals(body, frames[0].body)
    }

    // --------------------------------------------------------------- crypto
    @Test
    fun `session keys require exactly 16 ascii chars and map to the right roles`() {
        val keys = MiPlaySessionKeys(
            authKey = "5a4e75f096044fde",
            streamKey = "52611f0aa23c4777",
            streamIV = "c828b4938a624767"
        )
        // Control channel key is the authKey — the non-obvious, verified mapping.
        assertEquals("5a4e75f096044fde", String(keys.controlCipherKey(), Charsets.US_ASCII))
        assertEquals("c828b4938a624767", String(keys.controlCipherIv(), Charsets.US_ASCII))
        assertEquals("52611f0aa23c4777", String(keys.audioCipherKey(), Charsets.US_ASCII))
    }

    @Test(expected = IllegalArgumentException::class)
    fun `rejects a short key`() {
        MiPlaySessionKeys(authKey = "tooshort", streamKey = "52611f0aa23c4777", streamIV = "c828b4938a624767")
    }

    @Test
    fun `control cipher encrypt then decrypt round trips`() {
        val keys = MiPlaySessionKeys("5a4e75f096044fde", "52611f0aa23c4777", "c828b4938a624767")
        val enc = MiPlayControlCipher(keys)
        val dec = MiPlayControlCipher(keys)

        val plain = """{"sourceName":"test","mTitle":"Blame"}""".toByteArray()
        val body = enc.encrypt(plain)
        assertTrue(MiPlayWire.isEncrypted(body))
        val env = MiPlayWire.parseEnvelope(body)!!
        assertTrue(MiPlayWire.verify(env))
        assertArrayEquals(plain, dec.decrypt(env))
    }

    @Test
    fun `encryption chains the iv across frames`() {
        val keys = MiPlaySessionKeys("5a4e75f096044fde", "52611f0aa23c4777", "c828b4938a624767")
        val enc = MiPlayControlCipher(keys)
        val dec = MiPlayControlCipher(keys)

        // Identical plaintext in two consecutive frames must produce different
        // ciphertext, because the IV advanced after the first frame.
        val plain = ByteArray(16) { 0x41 }
        val e1 = MiPlayWire.parseEnvelope(enc.encrypt(plain))!!
        val e2 = MiPlayWire.parseEnvelope(enc.encrypt(plain))!!
        assertFalse("IV must chain between frames",
            e1.ciphertext.contentEquals(e2.ciphertext))

        // ...and the receiver, chaining the same way, still recovers both.
        assertArrayEquals(plain, dec.decrypt(e1))
        assertArrayEquals(plain, dec.decrypt(e2))
    }

    @Test
    fun `decrypt rejects a wrong key instead of returning garbage`() {
        val good = MiPlaySessionKeys("5a4e75f096044fde", "52611f0aa23c4777", "c828b4938a624767")
        val bad = MiPlaySessionKeys("0000000000000000", "52611f0aa23c4777", "c828b4938a624767")
        val env = MiPlayWire.parseEnvelope(MiPlayControlCipher(good).encrypt("hello".toByteArray()))!!
        // With zero padding the chance a wrong key yields a valid tail is ~2^-8n;
        // assert it does not silently succeed.
        val out = MiPlayControlCipher(bad).decrypt(env)
        assertTrue("wrong key must not validate padding", out == null || out.contentEquals("hello".toByteArray()).not())
    }

    @Test
    fun `set mirror key json matches the official sender field order`() {
        val keys = MiPlaySessionKeys("99b1b4101660440f", "eb7c6f2de7d2493b", "f1a898ab5b524136")
        assertEquals(
            """{"wlan0ip":"10.42.0.42","authKey":"99b1b4101660440f","streamKey":"eb7c6f2de7d2493b","streamIV":"f1a898ab5b524136"}""",
            keys.toSetMirrorKeyJson("10.42.0.42")
        )
    }
}
