package com.fusionplay.miplay.discovery

/**
 * Minimal standard-alphabet Base64 decoder.
 *
 * MiPlay TXT values (`appsData=`, `AppData=`, `mac=`) are base64. A private
 * implementation is used instead of `android.util.Base64` so that the whole
 * protocol layer stays pure Kotlin: it can then be unit-tested on the JVM
 * against captured packets, and reused outside Android without a shim.
 *
 * Standard alphabet (`A–Z a–z 0–9 + /`) with `=` padding. Whitespace and line
 * breaks are ignored, because TXT values are sometimes wrapped. URL-safe
 * characters are accepted as well, since they cost nothing to support.
 */
internal object Base64Codec {

    private val DECODE_TABLE = IntArray(128) { -1 }.apply {
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        alphabet.forEachIndexed { index, character -> this[character.code] = index }
        // URL-safe aliases.
        this['-'.code] = 62
        this['_'.code] = 63
    }

    /**
     * @return decoded bytes, or `null` when [value] is not valid base64.
     */
    fun decode(value: String): ByteArray? {
        val output = java.io.ByteArrayOutputStream(value.length * 3 / 4 + 3)
        var buffer = 0
        var bits = 0
        var padding = 0

        for (character in value) {
            if (character == '=') {
                padding++
                continue
            }
            if (character.isWhitespace()) continue
            val code = character.code
            if (code >= DECODE_TABLE.size) return null
            val decoded = DECODE_TABLE[code]
            if (decoded < 0) return null

            // Any data after padding means the value is malformed.
            if (padding > 0) return null

            buffer = (buffer shl 6) or decoded
            bits += 6
            if (bits >= 8) {
                bits -= 8
                output.write((buffer ushr bits) and 0xFF)
            }
        }

        // A single leftover character can never be a valid final group.
        if (bits >= 6) return null
        return output.toByteArray()
    }
}
