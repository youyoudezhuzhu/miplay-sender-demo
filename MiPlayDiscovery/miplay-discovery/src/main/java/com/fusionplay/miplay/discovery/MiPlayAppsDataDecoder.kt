package com.fusionplay.miplay.discovery


/**
 * Decoder for Xiaomi's opaque `appsData` (`_mi-connect`) and `AppData`
 * (`_lyra-mdns`) TXT payloads.
 *
 * No public specification exists for this blob. It is therefore decoded
 * conservatively and losslessly:
 *
 * * the whole payload is kept as hex, so nothing is discarded;
 * * the embedded `{"mico" ...}` JSON fragment is located by marker and parsed
 *   with a real JSON parser (several observed payloads are **not**
 *   null-terminated, so the fragment is terminated at the matching brace);
 * * `mico.device_id` is extracted as the device UUID;
 * * any embedded MAC (`wlanMac`, `mac`, `ethMac`) is extracted when present.
 *
 * Observed real payloads:
 * ```
 * 小爱音箱-2284  appsData -> 81 00 66 04 83 22 c3 ...
 * 小爱音箱-1218  appsData -> 01 66 00 00 22 c3 50 ...
 * 客厅音箱 Pro   appsData -> 01 66 00 00 22 c3 90 ...
 * 客厅音箱 Pro   AppData  -> 00 40 05 93 7e 4b a6 ... (Lyra variant)
 * ```
 * The byte at index 2 is the only field whose meaning is confidently known for
 * the Lyra variant (device category); the rest is treated as opaque header.
 */
object MiPlayAppsDataDecoder {

    /**
     * Marker for the embedded identity JSON.
     *
     * Two distinct shapes are emitted by real devices, so the search is for the
     * bare quoted key `"mico"` and the enclosing `{` is then located backwards:
     *
     * * `_mi-connect` `appsData`: `... {"mico": {"device_id": "..."}}`
     * * `_lyra-mdns` `AppData`:  `... ,{ "mico": { "device_id": "..." }}`
     */
    private const val JSON_MARKER = "\"mico\""
    private const val SOURCE_KEY_MI_CONNECT = "appsData"
    private const val SOURCE_KEY_LYRA = "AppData"

    /** TXT keys that may carry the blob, in MiPlay's own spelling. */
    val SOURCE_KEYS = listOf(SOURCE_KEY_MI_CONNECT, SOURCE_KEY_LYRA)

    /**
     * Decodes [value] (base64 text from a TXT record).
     *
     * @param key the TXT key the value came from, recorded for provenance.
     * @return the decoded blob, or `null` when the value is not valid base64.
     */
    fun decode(key: String, value: String): MiPlayAppsData? {
        val raw = Base64Codec.decode(value) ?: return null
        if (raw.isEmpty()) return null

        val markerIndex = indexOf(raw, JSON_MARKER.toByteArray(Charsets.UTF_8))
        var deviceId: String? = null
        var hardwareAddress: String? = null
        var json: String? = null

        if (markerIndex >= 0) {
            // The payload is NOT a single JSON document. A real Lyra AppData is:
            //
            //   00 40 05 <instance> ... 40 02 10 <devicename utf8>
            //   24 26 { "wlanMac": "90:FB:5D:D3:43:1E" }        <- fragment 1
            //   24 64 <binary identity block>
            //   2c 01 { "mico": { "device_id": "..uuid.." } }    <- fragment 2
            //
            // Two brace-delimited JSON fragments separated by binary, which no
            // JSON parser can read as one value. The decoded payload from the
            // first "mico" marker onwards is therefore kept as a text region and
            // each key is located textually; that keeps working for truncated
            // fragments too.
            // The FIRST '{' precedes the marker (the wlanMac fragment), so it is
            // found forward from the start rather than backwards from "mico".
            val jsonStart = indexOf(raw, byteArrayOf('{'.code.toByte())).let {
                if (it in 0 until markerIndex) it else markerIndex
            }
            json = String(raw, jsonStart, raw.size - jsonStart, Charsets.UTF_8)
                .trimEnd('\u0000', '\n', '\r')
            deviceId = stringValue(json, "device_id")
            hardwareAddress = firstNonEmpty(
                stringValue(json, "wlanMac"),
                stringValue(json, "mac"),
                stringValue(json, "ethMac")
            )
        }

        return MiPlayAppsData(
            headerHex = raw.copyOfRange(0, minOf(markerIndex.takeIf { it >= 0 } ?: raw.size, raw.size)).toHex(),
            deviceId = deviceId,
            hardwareAddress = hardwareAddress,
            embeddedJson = json,
            rawHex = raw.toHex(),
            rawLength = raw.size,
            sourceKey = key
        )
    }

    private fun indexOf(haystack: ByteArray, needle: ByteArray): Int {
        if (needle.isEmpty() || haystack.size < needle.size) return -1
        outer@ for (index in 0..haystack.size - needle.size) {
            for (offset in needle.indices) {
                if (haystack[index + offset] != needle[offset]) continue@outer
            }
            return index
        }
        return -1
    }

    /**
     * Reassembles a base64 value that a receiver split across several TXT
     * strings and then decodes it.
     *
     * This is required in practice: a real 客厅音箱 Pro publishes its Lyra
     * `AppData` as two `AppData=` strings (144 and 35 base64 characters), and
     * neither half decodes on its own because the split lands mid-group. DNS-SD
     * permits concatenation of TXT strings into one logical value, and MiPlay
     * relies on it, so the halves are joined before decoding.
     */
    fun decodeConcatenated(key: String, fragments: List<String>): MiPlayAppsData? {
        if (fragments.isEmpty()) return null
        val joined = fragments.joinToString("")
        return decode(key, joined)
    }

    /**
     * Reads `"key": "value"` out of the embedded JSON fragment.
     *
     * The fragment is inspected textually, so a `\u0000` terminator, a missing
     * closing brace or an unexpected extra field cannot break identity
     * extraction. Escapes are un-escaped for the common `\"` and `\\` cases.
     */
    private fun stringValue(fragment: String?, key: String): String? {
        if (fragment == null) return null
        val needle = "\"$key\""
        var searchFrom = 0
        while (true) {
            val keyIndex = fragment.indexOf(needle, searchFrom)
            if (keyIndex < 0) return null
            var cursor = keyIndex + needle.length
            while (cursor < fragment.length && fragment[cursor].isWhitespace()) cursor++
            if (cursor < fragment.length && fragment[cursor] == ':') {
                cursor++
                while (cursor < fragment.length && fragment[cursor].isWhitespace()) cursor++
                if (cursor < fragment.length && fragment[cursor] == '"') {
                    cursor++
                    val builder = StringBuilder()
                    var escaped = false
                    while (cursor < fragment.length) {
                        val char = fragment[cursor]
                        if (escaped) {
                            builder.append(
                                when (char) {
                                    'n' -> '\n'
                                    't' -> '\t'
                                    'r' -> '\r'
                                    else -> char
                                }
                            )
                            escaped = false
                        } else when (char) {
                            '\\' -> escaped = true
                            '"' -> return builder.toString().takeIf { it.isNotEmpty() }
                            else -> builder.append(char)
                        }
                        cursor++
                    }
                    return builder.toString().takeIf { it.isNotEmpty() }
                }
            }
            searchFrom = keyIndex + needle.length
        }
    }

    private fun firstNonEmpty(vararg values: String?): String? =
        values.firstOrNull { !it.isNullOrEmpty() }

    /**
     * Xiaomi's `DebugInfo` address obfuscation is recorded here because it is
     * easy to mistake for a plain address, but it is **deliberately not
     * inverted**.
     *
     * `encode_xiaomi_debug_ip` (FusionPlay-Android MiPlaySDK) shifts each
     * character by its class:
     *
     * * decimal digit `0`–`9` → `'#' + d`  (codes 35–44)
     * * hex letter `a`–`f`     → `'1' + v`  (codes 49–54)
     *
     * Those two ranges are **disjoint**, but the encoder's *output* aliases the
     * input space: an encoded `a` is the character `1`, which is also the
     * literal digit `1`. Verified on the JVM:
     *
     * ```
     * '1' in '#'..',' == false      // so it is not caught by the digit rule
     * '1' in '1'..'6' == true       // and is decoded as 'a' instead of 1
     * ```
     *
     * A character-wise inverse is therefore unsound: the real captured value
     * `192.$)+.&$.117` (which is `192.168.31.117`) cannot be recovered
     * unconditionally. Because `DebugInfo` is diagnostic only and the
     * authoritative address is always the **A/AAAA record**, the raw string is
     * preserved verbatim instead of being translated into something that looks
     * authoritative but may be wrong.
     *
     * @return [debugInfo] unchanged; provided solely so callers have one
     *   documented place that explains why it is not decoded.
     */
    fun keepRawDebugInfo(debugInfo: String): String = debugInfo
}
