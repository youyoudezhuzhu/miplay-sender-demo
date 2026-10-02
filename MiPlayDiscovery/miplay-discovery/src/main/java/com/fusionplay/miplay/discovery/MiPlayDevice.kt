package com.fusionplay.miplay.discovery

/**
 * A MiPlay (小米妙播) receiver discovered on the local network.
 *
 * Every field except [serviceTypes] / [serviceNames] / [ip] is **nullable on
 * purpose**: the protocol does not guarantee that a responder publishes a
 * given TXT key, and a partially understood device must still be surfaced
 * rather than filtered out.
 */
data class MiPlayDevice(
    /** Human readable name from the `name=` TXT key of the `_mi-connect` record. */
    val name: String?,
    /** IPv4 (or IPv6) literal of the responder that answered the browse. */
    val ip: String,
    /** Port advertised by the SRV record; `56666` for `_mi-connect`, `5353` for Lyra. */
    val port: Int?,
    /** UUID parsed out of the base64 `appsData` / `AppData` blob (`mico.device_id`). */
    val deviceId: String?,
    /** Hardware model, taken from the SRV target hostname (e.g. `LX06`, `OH2-1218`). */
    val model: String?,
    /** Manufacturer — always `Xiaomi` for a MiPlay responder; kept explicit for the model. */
    val manufacturer: String?,
    /** Primary DNS-SD service type that produced this device. */
    val serviceType: String?,
    /** Capabilities expressed as the raw TXT key/value pairs MiPlay actually sends. */
    val capabilities: List<String>?,
    /** All DNS-SD service types this endpoint advertised during the scan. */
    val serviceTypes: List<String> = emptyList(),
    /** Service instance names (e.g. `小爱音箱-2284._mi-connect._udp.local.`). */
    val serviceNames: List<String> = emptyList(),
    /** SRV target host, e.g. `LX06.local.`. */
    val host: String? = null,
    /** Raw TXT map, exactly as received, for downstream protocol work. */
    val txt: Map<String, String> = emptyMap(),
    /** `dev=` route-picker presentation category. */
    val deviceCategory: Int? = null,
    /** `sec=` security/authorisation mode advertised by the receiver. */
    val securityMode: Int? = null,
    /** `idHash=` account/IDM short hash. */
    val idHash: String? = null,
    /** `version=` MiPlay protocol version (decimal). */
    val version: Int? = null,
    /** `flags=` capability bitset, base64 encoded on the wire. */
    val flags: String? = null,
    /** `apps=[..]` advertised applications. */
    val apps: String? = null,
    /** `MediumType=` media capability mask (Lyra records). */
    val mediumType: Int? = null,
    /** `mac=` raw bytes as base64, from the TXT record. */
    val mac: String? = null,
    /** Fully decoded `appsData` / `AppData` blob, if present. */
    val appsData: MiPlayAppsData? = null,
    /** Last time this device answered, epoch millis. */
    val lastSeenMillis: Long = System.currentTimeMillis(),
    /** Addresses seen for this device in addition to [ip]. */
    val addresses: List<String> = emptyList()
) {
    /** Feature-rich one-line summary, used by the debug log. */
    fun describe(): String = buildString {
        append("MiPlayDevice(name=").append(name ?: "<unknown>")
        append(", ip=").append(ip)
        append(", port=").append(port ?: "<none>")
        append(", deviceId=").append(deviceId ?: "<unknown>")
        append(", model=").append(model ?: "<unknown>")
        append(", services=").append(serviceTypes.joinToString("+"))
        append(", dev=").append(deviceCategory ?: "<none>")
        append(", sec=").append(securityMode ?: "<none>")
        append(")")
    }
}

/**
 * The decoded Xiaomi `appsData` (`_mi-connect`) / `AppData` (`_lyra-mdns`)
 * base64 payload.
 *
 * Observed layout for a real 小爱音箱 (LX06):
 * ```
 * 81 00 66 04 83 22 c3        magic / version / record kind / instance
 * 4c c6 4c d6 17 db 00 00     opaque
 * 00 00 00 00 00 00 00 00 01 a0 e0 d9 8f 2c 00
 * 7b 0a 09 22 6d 69 63 6f 22 ...  {"mico": {"device_id": "<uuid>"}}
 * ```
 * The trailing JSON is not length-prefixed by a reliable field, so it is
 * located by its `{"mico"` marker — the same way a receiver's own tooling
 * correlates identity.
 */
data class MiPlayAppsData(
    /** Leading bytes, verbatim. */
    val headerHex: String,
    /** Decoded `mico.device_id`, when the JSON blob was present and parseable. */
    val deviceId: String?,
    /** `mac` / `wlanMac` when the blob embedded one (`aa:bb:..` or raw). */
    val hardwareAddress: String?,
    /** The embedded JSON fragment, verbatim, for further reverse engineering. */
    val embeddedJson: String?,
    /** Whole payload in hex, so nothing is lost. */
    val rawHex: String,
    val rawLength: Int,
    /** Which TXT key it came from: `appsData` or `AppData`. */
    val sourceKey: String
)
