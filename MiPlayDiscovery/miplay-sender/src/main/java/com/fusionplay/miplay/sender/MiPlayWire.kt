package com.fusionplay.miplay.sender

/**
 * MiPlay (小米妙播) control-channel wire format and integrity check.
 *
 * Frame layout on TCP 8899:
 * ```
 * '$'(0x24) | outer:u8 | cmd:u8 | seq:u16be | bodyLen:u32be | body
 * ```
 *
 * Encrypted body layout (produced by `SafetyDataDeal::encryptData`):
 * ```
 * 00 07 01 e0 | flags:u8 | pad:u8 | crc32be(ct) | ciphertext
 * ```
 * * `flags` bit7 = encrypted, bit6 = padded, bit5 = integrity present
 * * `pad = 16 - (len % 16)`, always 1..16 (a half-open multiple still pads 16)
 * * the CRC covers the **ciphertext only**, so it is key-independent
 *
 * All of the above is verified against real captures; see
 * `reports/MIPLAY_CRYPTO_ANALYSIS_V4.md`.
 */
object MiPlayWire {

    const val FRAME_MARKER = 0x24
    val ENVELOPE_MAGIC = byteArrayOf(0x00, 0x07, 0x01, 0xE0.toByte())

    const val FLAG_ENCRYPTED = 0x80
    const val FLAG_PADDED = 0x40
    const val FLAG_INTEGRITY = 0x20

    const val DEFAULT_FLAGS = FLAG_ENCRYPTED or FLAG_PADDED or FLAG_INTEGRITY

    /** Pad length for a plaintext of [len] bytes; 1..16, never 0. */
    fun padLength(len: Int): Int = 16 - (len % 16)

    // ------------------------------------------------------------------ CRC
    private val CRC_TABLE = IntArray(256) { i ->
        var v = i shl 24
        repeat(8) {
            v = if (v and 0x80000000.toInt() != 0) (v shl 1) xor POLY else v shl 1
        }
        // MiPlay byte-swaps the 32-bit result (matches the reference implementation).
        Integer.reverseBytes(v)
    }

    private const val POLY = 0x04C11DB7

    /**
     * Byte-swapped CRC-32 over [data], as used for the `integrity` field.
     * Returns an unsigned 32-bit value in a Long so it can be compared safely.
     */
    fun integrity(data: ByteArray, offset: Int = 0, length: Int = data.size): Long {
        var v = 0xFFFFFFFFL
        for (i in offset until offset + length) {
            val idx = ((v and 0xFF).toInt()) xor (data[i].toInt() and 0xFF)
            v = (CRC_TABLE[idx].toLong() and 0xFFFFFFFFL) xor (v ushr 8)
        }
        return v and 0xFFFFFFFFL
    }

    // -------------------------------------------------------------- envelope
    /**
     * Wrap an already-encrypted payload in the MiPlay envelope.
     *
     * @param ciphertext AES output; its length must be a multiple of 16.
     */
    fun envelope(ciphertext: ByteArray, pad: Int): ByteArray {
        val out = ByteArray(9 + ciphertext.size)
        System.arraycopy(ENVELOPE_MAGIC, 0, out, 0, 4)
        out[4] = pad.toByte()
        val crc = integrity(ciphertext)
        out[5] = (crc ushr 24).toByte()
        out[6] = (crc ushr 16).toByte()
        out[7] = (crc ushr 8).toByte()
        out[8] = crc.toByte()
        System.arraycopy(ciphertext, 0, out, 9, ciphertext.size)
        return out
    }

    /** True when [body] starts with the encrypted-envelope magic. */
    fun isEncrypted(body: ByteArray): Boolean =
        body.size >= 9 && body[0] == 0x00.toByte() && body[1] == 0x07.toByte() &&
                body[2] == 0x01.toByte() && body[3] == 0xE0.toByte()

    /** Parsed encrypted envelope. */
    data class Envelope(val flags: Int, val pad: Int, val integrity: Long, val ciphertext: ByteArray) {
        override fun equals(other: Any?): Boolean = this === other
        override fun hashCode(): Int = ciphertext.contentHashCode()
    }

    /** Parse an encrypted body, or null when it is not an envelope. */
    fun parseEnvelope(body: ByteArray): Envelope? {
        if (!isEncrypted(body)) return null
        val flags = body[3].toInt() and 0xFF
        val pad = if (flags and FLAG_PADDED != 0) body[4].toInt() and 0xFF else 0
        val integ = ((body[5].toLong() and 0xFF) shl 24) or
                ((body[6].toLong() and 0xFF) shl 16) or
                ((body[7].toLong() and 0xFF) shl 8) or
                (body[8].toLong() and 0xFF)
        return Envelope(flags, pad, integ, body.copyOfRange(9, body.size))
    }

    /** Verify the key-independent integrity field of an envelope. */
    fun verify(env: Envelope): Boolean = integrity(env.ciphertext) == env.integrity

    // ------------------------------------------------------------- full frame
    /** Build a complete `'$'` frame around [body]. */
    fun frame(cmd: Int, seq: Int, body: ByteArray, outer: Int = 0): ByteArray {
        val out = ByteArray(9 + body.size)
        out[0] = FRAME_MARKER.toByte()
        out[1] = outer.toByte()
        out[2] = cmd.toByte()
        out[3] = (seq ushr 8).toByte()
        out[4] = seq.toByte()
        val n = body.size
        out[5] = (n ushr 24).toByte()
        out[6] = (n ushr 16).toByte()
        out[7] = (n ushr 8).toByte()
        out[8] = n.toByte()
        System.arraycopy(body, 0, out, 9, n)
        return out
    }

    /** A decoded control frame. */
    data class Frame(val cmd: Int, val seq: Int, val body: ByteArray) {
        override fun equals(other: Any?): Boolean = this === other
        override fun hashCode(): Int = body.contentHashCode()
    }

    /**
     * Split a byte buffer into frames. Returns the parsed frames plus the number
     * of bytes consumed; callers keep the remainder for the next read.
     */
    fun parseFrames(buf: ByteArray, offset: Int = 0, length: Int = buf.size): Pair<List<Frame>, Int> {
        val frames = ArrayList<Frame>()
        var i = offset
        val end = offset + length
        while (i + 9 <= end) {
            if (buf[i].toInt() and 0xFF != FRAME_MARKER) {
                i++
                continue
            }
            val cmd = buf[i + 2].toInt() and 0xFF
            val seq = ((buf[i + 3].toInt() and 0xFF) shl 8) or (buf[i + 4].toInt() and 0xFF)
            val n = ((buf[i + 5].toInt() and 0xFF) shl 24) or
                    ((buf[i + 6].toInt() and 0xFF) shl 16) or
                    ((buf[i + 7].toInt() and 0xFF) shl 8) or
                    (buf[i + 8].toInt() and 0xFF)
            if (n < 0 || i + 9 + n > end) break
            frames.add(Frame(cmd, seq, buf.copyOfRange(i + 9, i + 9 + n)))
            i += 9 + n
        }
        return frames to (i - offset)
    }
}
