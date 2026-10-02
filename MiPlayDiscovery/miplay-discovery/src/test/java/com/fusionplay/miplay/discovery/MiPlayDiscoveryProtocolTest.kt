package com.fusionplay.miplay.discovery

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Regression tests built from **real captured traffic** on a live LAN
 * (see `evidence/miplay_capture.jsonl`).
 *
 * Every hex string below is a verbatim datagram received from a physical Xiaomi
 * speaker while browsing `_mi-connect._udp.local.` / `_lyra-mdns._udp.local.`
 * with a unicast-response (QU) mDNS query. If a future refactor breaks parsing,
 * these fail.
 */
class MiPlayDiscoveryProtocolTest {

    private fun bytes(hex: String) = ByteArray(hex.length / 2) { index ->
        hex.substring(index * 2, index * 2 + 2).toInt(16).toByte()
    }

    /** TXT strings are `key=value`; this mirrors what DeviceRegistry does. */
    private fun List<String>.toTxtMap(): Map<String, String> = buildMap {
        for (entry in this@toTxtMap) {
            val separator = entry.indexOf('=')
            if (separator <= 0) put(entry, "") else put(entry.take(separator), entry.substring(separator + 1))
        }
    }

    // ------------------------------------------------ query construction

    @Test
    fun `browse query matches the observed Xiaomi wire format`() {
        val query = MiPlayMdns.buildBrowseQuery(MiPlayMdns.SERVICE_MI_CONNECT)
        // 6 x u16 header, 11+4+5+1 name bytes, then QTYPE/QCLASS.
        assertEquals(40, query.size)
        assertEquals(
            "0000000000010000000000000b5f6d692d636f6e6e656374045f756470056c6f63616c00000c8001",
            query.toHex()
        )
    }

    @Test
    fun `lyra browse query is 39 bytes`() {
        val query = MiPlayMdns.buildBrowseQuery(MiPlayMdns.SERVICE_LYRA)
        assertEquals(39, query.size)
        assertEquals(
            "0000000000010000000000000a5f6c7972612d6d646e73045f756470056c6f63616c00000c8001",
            query.toHex()
        )
    }

    // ------------------------------------------------ response parsing

    /** `小爱音箱-1218` (OH2-1218) at 192.168.31.89, `_mi-connect`, TTL 120. */
    private val miConnectOh2 =
        "0000840000000001000000030b5f6d692d636f6e6e656374045f756470056c6f63616c00000c000100000078001411e5b08fe788b1e99fb3e7aeb12d31323138c00cc02e0021800100000078001100000000dd5a084f48322d31323138c01dc02e001080010000007800f40d76657273696f6e3d363535343508617070733d5b355d0a666c6167733d41673d3d166e616d653de5b08fe788b1e99fb3e7aeb12d313231380b6964486173683d4d54466b056465763d34057365633d329561707073446174613d4157594141434c44555034354d527a4a41414141414141414141414141414767344e6d504c41423743676b6962576c6a627949364948734b43516b695a47563261574e6c58326c6b496a6f67496d55344d574d794f574a6c4c574d7a5a6d59744e4749784d7930354d324d794c57593459324d344d544a6c4e6d51335979496743676c394941703949416f3d0c6d61633d555034354d527a4ac05400018001000000780004c0a81f59"

    /** `客厅音箱 Pro` at 192.168.31.117, `_mi-connect`, TTL 120 (announcement). */
    private val miConnectPro =
        "0000840000000001000000040b5f6d692d636f6e6e656374045f756470056c6f63616c00000c000100000078000b083933374534424136c00cc02e0021800100000078001100000000dd5a083933374534424136c01dc02e001080010000007801650b6964486173683d617a4d31056465763d34156e616d653de5aea2e58e85e99fb3e7aeb12050726f057365633d300c6d61633d6b50746430304d650a666c6167733d41413d3d0e76657273696f6e3d31393636303808617070733d5b355d9561707073446174613d4157594141434c446b50746430304d6541414141414141414141414141414767344e6d504c41463743676b6962576c6a627949364948734b43516b695a47563261574e6c58326c6b496a6f67496d5a6c593255334d5451334c5441324f5449744e4451354d5331685a5463304c5451334e6a457a4f575a6c4e6d49305a43496743676c394941703949416f3d0e4d656469756d547970653d323536614465627567496e666f3d7b6d73673a7265706c792c2069666e616d653a776c616e302c2076343a3139322e24292b2e26242e3131372c2076363a323430383a2b25263d3a272524243a3b3d233a3b2b2c2a3a24293c2c3a24253c243a666163627dc04b00018001000000780004c0a81f75c04b001c80010000007800102408823c42110ac0a89716b912b1facb"

    /** `937E4BA6` at 192.168.31.117, `_lyra-mdns`, TTL 120, AAAA included. */
    private val lyraPro =
        "0000840000000001000000040a5f6c7972612d6d646e73045f756470056c6f63616c00000c000100000078000b083933374534424136c00cc02d002180010000007800110000000014e9083933374534424136c01cc02d00108001000000780173c8417070446174613d414541466b33354c706741434151514b4177487067674542514149513561366935593646365a2b7a35363678494642796279516d65776f4a496e64735957354e59574d694f6941694f544136526b49364e55513652444d364e444d364d5555694941703949416f6b5a434c446b50746430304d6541414141414141414141414141414767344e6d504c41463743676b6962576c6a627949364948734b43516b695a47563261574e6c58326c6b496a6f67496d5a6c593255334d5451334c54413238417070446174613d4f5449744e4451354d5331685a5463304c5451334e6a457a4f575a6c4e6d49305a43496743676c394941703949416f3d0e4d656469756d547970653d323536614465627567496e666f3d7b6d73673a7265706c792c2069666e616d653a776c616e302c2076343a3139322e24292b2e26242e3131372c2076363a323430383a2b25263d3a272524243a3b3d233a3b2b2c2a3a24293c2c3a24253c243a666163627dc04a00018001000000780004c0a81f75c04a001c80010000007800102408823c42110ac0a89716b912b1facb"

    /** `小爱音箱-2284` (LX06) at 192.168.31.115 — the QU reply echoed our question. */
    private val miConnectLx06QuReply =
        "0000840000010001000000030b5f6d692d636f6e6e656374045f756470056c6f63616c00000c8001c00c000c00010000000a001411e5b08fe788b1e99fb3e7aeb12d32323834c00cc034002100010000000a000d00000000dd5a044c583036c01dc034001000010000000a00e70d76657273696f6e3d363535343508617070733d5b355d0a666c6167733d41673d3d166e616d653de5b08fe788b1e99fb3e7aeb12d323238340b6964486173683d5a445930056465763d34057365633d329561707073446174613d6751426d42494d6977307a47544e5958327741414141414141414141414141426f4f445a6a79774165776f4a496d3170593238694f69423743676b4a496d526c646d6c6a5a5639705a434936494349324e4759794d6a45315a53316b597a526d4c5451324f4441744f5749795a43316c4f4459354f575930597a517a5957516949416f4a6653414b6653414bc05a000100010000000a0004c0a81f73"

    @Test
    fun `parses oh2 mi-connect response`() {
        val message = MiPlayDnsParser.parse(bytes(miConnectOh2))
        assertNotNull(message)
        requireNotNull(message)
        assertTrue(message.isResponse)

        val ptr = message.answers.single { it.type == MiPlayMdns.TYPE_PTR }
        assertEquals(MiPlayMdns.SERVICE_MI_CONNECT, ptr.name)
        assertEquals("小爱音箱-1218._mi-connect._udp.local.", ptr.domainName)

        val srv = message.additionals.single { it.type == MiPlayMdns.TYPE_SRV }
        assertEquals(56666, srv.srvPort)
        assertEquals("OH2-1218.local.", srv.srvTarget)

        val txt = message.additionals.single { it.type == MiPlayMdns.TYPE_TXT }.txt.toTxtMap()
        assertEquals("小爱音箱-1218", txt["name"])
        assertEquals("65545", txt["version"])
        assertEquals("4", txt["dev"])
        assertEquals("2", txt["sec"])
        assertEquals("[5]", txt["apps"])

        val address = message.additionals.single { it.type == MiPlayMdns.TYPE_A }
        assertEquals("192.168.31.89", address.address)
    }

    @Test
    fun `extracts device id from appsData blob`() {
        val message = requireNotNull(MiPlayDnsParser.parse(bytes(miConnectOh2)))
        val txt = message.additionals.single { it.type == MiPlayMdns.TYPE_TXT }.txt.toTxtMap()
        val blob = MiPlayAppsDataDecoder.decode("appsData", txt.getValue("appsData"))
        assertNotNull(blob)
        requireNotNull(blob)
        assertEquals("e81c29be-c3ff-4b13-93c2-f8cc812e6d7c", blob.deviceId)
        assertEquals(104, blob.rawLength)
        // The opaque header must survive verbatim for further reverse engineering.
        assertTrue(blob.rawHex.startsWith("0166000022c350fe39311cc9"))
        // The "mico" key is located textually; the surrounding braces differ
        // between the _mi-connect and Lyra payload shapes.
        assertTrue(blob.embeddedJson!!.contains("\"mico\""))
        assertTrue(blob.embeddedJson!!.contains("device_id"))
    }

    @Test
    fun `decodes base64 mac txt into a hardware address`() {
        val message = requireNotNull(MiPlayDnsParser.parse(bytes(miConnectOh2)))
        val txt = message.additionals.single { it.type == MiPlayMdns.TYPE_TXT }.txt.toTxtMap()
        // "UP45MRzJ" is base64 of 50:fe:39:31:1c:c9, matching the device id blob.
        assertEquals("50:fe:39:31:1c:c9", formatMacForTest(txt.getValue("mac")))
    }

    @Test
    fun `parses pro mi-connect response including ipv6 and debuginfo`() {
        val message = requireNotNull(MiPlayDnsParser.parse(bytes(miConnectPro)))
        assertEquals(4, message.additionals.size)

        val srv = message.additionals.single { it.type == MiPlayMdns.TYPE_SRV }
        assertEquals(56666, srv.srvPort)
        assertEquals("937E4BA6.local.", srv.srvTarget)

        val txt = message.additionals.single { it.type == MiPlayMdns.TYPE_TXT }.txt.toTxtMap()
        assertEquals("客厅音箱 Pro", txt["name"])
        assertEquals("256", txt["MediumType"])
        assertEquals("0", txt["sec"])

        val aaaa = message.additionals.single { it.type == MiPlayMdns.TYPE_AAAA }
        assertEquals("2408:823c:4211:ac0:a897:16b9:12b1:facb", aaaa.address)

        // DebugInfo carries an obfuscated address that is NOT inverted (the
        // encoder's output aliases its input space). The raw string must be
        // preserved verbatim, and the authoritative address must come from the
        // A/AAAA record above.
        val debug = txt.getValue("DebugInfo")
        assertTrue(debug.startsWith("{msg:reply, ifname:wlan0, v4:192."))
        assertTrue(debug.contains("v6:2408:"))
        assertEquals(debug, MiPlayAppsDataDecoder.keepRawDebugInfo(debug))
    }

    @Test
    fun `lyra service uses port 5353 and carries AppData`() {
        val message = requireNotNull(MiPlayDnsParser.parse(bytes(lyraPro)))
        val ptr = message.answers.single { it.type == MiPlayMdns.TYPE_PTR }
        assertEquals(MiPlayMdns.SERVICE_LYRA, ptr.name)
        assertEquals("937E4BA6._lyra-mdns._udp.local.", ptr.domainName)

        val srv = message.additionals.single { it.type == MiPlayMdns.TYPE_SRV }
        assertEquals(MiPlayMdns.MDNS_PORT, srv.srvPort)

        val txtStrings = message.additionals.single { it.type == MiPlayMdns.TYPE_TXT }.txt
        // The blob really is split across two AppData strings on the wire.
        val appData = txtStrings.filter { it.startsWith("AppData=") }
        assertEquals(2, appData.size)

        // The split lands mid-payload: each half is separately valid base64 but
        // only the concatenation carries the identity, which is why the
        // registry must reassemble repeated TXT keys.
        val fragments = appData.map { it.substringAfter('=') }
        val firstHalfAlone = MiPlayAppsDataDecoder.decode("AppData", fragments[0])
        // The first half carries the blob header but its JSON fragment is cut
        // mid-value, so the identity it yields is incomplete. This is exactly
        // the failure mode that TXT reassembly fixes.
        val firstHalfId = firstHalfAlone?.deviceId
        assertTrue(
            "first half alone must not yield the complete device id, was $firstHalfId",
            firstHalfId != "fece7147-0692-4491-ae74-476139fe6b4d"
        )
        val joined = MiPlayAppsDataDecoder.decodeConcatenated("AppData", fragments)
        assertNotNull(joined)
        assertEquals("fece7147-0692-4491-ae74-476139fe6b4d", joined!!.deviceId)
        assertEquals(179, joined.rawLength)
        // As embedded by the device; DeviceRegistry lower-cases it for display.
        assertEquals("90:FB:5D:D3:43:1E", joined.hardwareAddress)
    }

    @Test
    fun `parses the QU reply that echoes our question`() {
        val message = requireNotNull(MiPlayDnsParser.parse(bytes(miConnectLx06QuReply)))
        // A QU reply may repeat the question; the answer is still authoritative.
        assertEquals(1, message.questions.size)
        assertEquals("_mi-connect._udp.local.", message.questions[0].name)
        assertEquals(0x8001, message.questions[0].dnsClass)

        val ptr = message.answers.single { it.type == MiPlayMdns.TYPE_PTR }
        assertEquals("小爱音箱-2284._mi-connect._udp.local.", ptr.domainName)
        // On-demand/queries answer with the short 10s TTL.
        assertEquals(10L, ptr.ttl)

        val srv = message.additionals.single { it.type == MiPlayMdns.TYPE_SRV }
        assertEquals(56666, srv.srvPort)
        assertEquals("LX06.local.", srv.srvTarget)
        assertEquals(10L, srv.ttl)
    }

    @Test
    fun `raw rdata is preserved for every record`() {
        val message = requireNotNull(MiPlayDnsParser.parse(bytes(miConnectPro)))
        assertTrue(message.allRecords.all { it.rawData.isNotEmpty() })
        // The pointer-compressed PTR/SRV/TXT records must still resolve.
        val ptr = message.answers.single { it.type == MiPlayMdns.TYPE_PTR }
        assertEquals("937E4BA6._mi-connect._udp.local.", ptr.domainName)
    }

    @Test
    fun `short packets do not crash the parser`() {
        assertEquals(null, MiPlayDnsParser.parse(ByteArray(0)))
        assertEquals(null, MiPlayDnsParser.parse(ByteArray(11)))
    }

    /** Mirrors DeviceRegistry's MAC formatting without exposing test-only API. */
    private fun formatMacForTest(value: String): String {
        val raw = java.util.Base64.getDecoder().decode(value)
        // DeviceRegistry renders hardware addresses in lower case, matching the
        // spelling Xiaomi itself uses for wlanMac in the appsData blob.
        return raw.joinToString(":") { String.format("%02x", it.toInt() and 0xFF) }
    }
}
