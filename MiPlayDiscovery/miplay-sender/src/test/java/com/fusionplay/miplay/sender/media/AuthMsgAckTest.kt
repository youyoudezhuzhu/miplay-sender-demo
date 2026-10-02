package com.fusionplay.miplay.sender.media

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Pins `authMsgAck` to **real captured values**.
 *
 * Four pairs were captured from live hardware across two sessions and both
 * directions; all four are reproduced by a plain standard
 * `HMAC-SHA256(key = authKey, msg = authMsg)` with both operands as ASCII.
 *
 * The session keys are `uuid[:16]` as printed by the SDK, delivered to the
 * sender in `SET_MIRROR_KEY`.
 */
class AuthMsgAckTest {

    // Session A: keys generated 15:32:32, RTSP auth exchange at 15:32:32.4-.6
    private val authA = "2feb068001324c98"
    // Session B: keys generated 15:31:47, RTSP auth exchange at 15:31:48-.49
    private val authB = "769a326df0ac49f0"

    @Test
    fun `session A challenge 1`() {
        assertEquals(
            "889f8b7adb2e8c03dd8259a9b5e822bda053400210d67cafc3dcebebe7dc5d58",
            WfdRtspServer.authMsgAck("25e1d5733eff0008f56e81eb04eb87a8", authA)
        )
    }

    @Test
    fun `session A challenge 2`() {
        assertEquals(
            "1ff0c8da8c3a346438bfd86794959ae366a4ee5c204d8dd5fc383f532958ed19",
            WfdRtspServer.authMsgAck("7f490a69948c805f992d461bb4f2faee", authA)
        )
    }

    @Test
    fun `session B challenge 1`() {
        assertEquals(
            "611bfd79439f357502f31fe0077c66d6dbe05d5a340198341359d154b0f87af8",
            WfdRtspServer.authMsgAck("794a11ae931cbcd1dc9068624a642a39", authB)
        )
    }

    @Test
    fun `session B challenge 2`() {
        assertEquals(
            "9c1e29b0147c2be4d9c5f796796fef9aa6c533823046283302a02aa34f3833be",
            WfdRtspServer.authMsgAck("47fe880cf6852fe762c5d5e894172029", authB)
        )
    }

    /** The challenge is per-session random; a different key must not match. */
    @Test
    fun `wrong key does not produce the captured ack`() {
        val wrong = WfdRtspServer.authMsgAck("25e1d5733eff0008f56e81eb04eb87a8", authB)
        assertEquals(64, wrong.length)
        assertEquals(
            false,
            wrong == "889f8b7adb2e8c03dd8259a9b5e822bda053400210d67cafc3dcebebe7dc5d58"
        )
    }

    /** Output is lowercase hex, 64 chars for SHA-256. */
    @Test
    fun `output shape is 64 lowercase hex chars`() {
        val v = WfdRtspServer.authMsgAck("00", authA)
        assertEquals(64, v.length)
        assertEquals(true, v.all { it in "0123456789abcdef" })
    }
}
