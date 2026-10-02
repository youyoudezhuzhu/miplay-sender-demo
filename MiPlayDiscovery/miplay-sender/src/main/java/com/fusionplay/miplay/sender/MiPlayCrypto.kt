package com.fusionplay.miplay.sender

import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Session keys as delivered by the sender's own key generator and pushed to the
 * receiver inside `SET_MIRROR_KEY` (cmd 0x6c).
 *
 * Each value is **16 ASCII characters** taken from the first 16 characters of a
 * `java.util.UUID.randomUUID()` string — not a hex-decoded 8-byte value. This is
 * why the receiver insists on "exactly 16 ASCII bytes".
 *
 * Role mapping (verified end-to-end against live traffic):
 * * **control channel** — AES key = [authKey], IV = [streamIV]
 * * **audio channel**   — AES key = [streamKey], IV = [streamIV]
 *
 * The control-channel mapping is the surprising one: `genAesKey(type=4)` reads
 * `SafetyKeyDeal+0x58`, which `onSessionConnect` fills from the `authKey` JSON
 * field. See `reports/MIPLAY_CRYPTO_ANALYSIS_V4.md` §1.
 */
data class MiPlaySessionKeys(
    val authKey: String,
    val streamKey: String,
    val streamIV: String
) {
    init {
        require(authKey.length == 16) { "authKey must be 16 ASCII chars, got ${authKey.length}" }
        require(streamKey.length == 16) { "streamKey must be 16 ASCII chars" }
        require(streamIV.length == 16) { "streamIV must be 16 ASCII chars" }
    }

    fun controlCipherKey(): ByteArray = authKey.toByteArray(Charsets.US_ASCII)
    fun controlCipherIv(): ByteArray = streamIV.toByteArray(Charsets.US_ASCII)
    fun audioCipherKey(): ByteArray = streamKey.toByteArray(Charsets.US_ASCII)
    fun audioCipherIv(): ByteArray = streamIV.toByteArray(Charsets.US_ASCII)

    /** JSON body used by `SET_MIRROR_KEY`; field order matches the official sender. */
    fun toSetMirrorKeyJson(wlan0Ip: String): String =
        """{"wlan0ip":"$wlan0Ip","authKey":"$authKey","streamKey":"$streamKey","streamIV":"$streamIV"}"""
}

/**
 * AES-128-CBC codec for the MiPlay control channel.
 *
 * Two properties matter and both were confirmed on real captures:
 *  1. **zero padding**, `pad = 16 - (len % 16)`, 1..16 (never a "no padding" case);
 *  2. **free-running IV chaining** — the IV for the next block is the last 16
 *     bytes of the previous ciphertext, *across frames*, not reset per frame.
 *
 * This class is not thread-safe; the control client serialises access.
 */
class MiPlayControlCipher(keys: MiPlaySessionKeys) {

    private val keySpec = SecretKeySpec(keys.controlCipherKey(), "AES")
    private val initialIv = keys.controlCipherIv()

    /** Current chaining IV; advances as ciphertext flows. */
    private var iv: ByteArray = initialIv.copyOf()

    /** Reset the chain back to the negotiated IV. */
    fun reset() {
        iv = initialIv.copyOf()
    }

    /**
     * Encrypt [plaintext] and return the envelope body ready for framing.
     * Advances the chaining IV.
     */
    fun encrypt(plaintext: ByteArray): ByteArray {
        val pad = MiPlayWire.padLength(plaintext.size)
        val padded = ByteArray(plaintext.size + pad)
        System.arraycopy(plaintext, 0, padded, 0, plaintext.size)

        val cipher = Cipher.getInstance("AES/CBC/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, IvParameterSpec(iv))
        val ct = cipher.doFinal(padded)
        iv = ct.copyOfRange(ct.size - 16, ct.size)
        return MiPlayWire.envelope(ct, pad)
    }

    /**
     * Decrypt an envelope body, returning the plaintext with zero padding
     * stripped, or null when the padding does not validate (wrong key / desync).
     * Advances the chaining IV on success.
     */
    fun decrypt(env: MiPlayWire.Envelope): ByteArray? {
        if (env.ciphertext.isEmpty() || env.ciphertext.size % 16 != 0) return null
        val cipher = Cipher.getInstance("AES/CBC/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, keySpec, IvParameterSpec(iv))
        val pt = try {
            cipher.doFinal(env.ciphertext)
        } catch (t: Throwable) {
            return null
        }
        iv = env.ciphertext.copyOfRange(env.ciphertext.size - 16, env.ciphertext.size)

        val pad = env.pad
        if (pad !in 1..16 || pt.size < pad) return null
        for (i in pt.size - pad until pt.size) {
            if (pt[i] != 0.toByte()) return null
        }
        return pt.copyOfRange(0, pt.size - pad)
    }
}
