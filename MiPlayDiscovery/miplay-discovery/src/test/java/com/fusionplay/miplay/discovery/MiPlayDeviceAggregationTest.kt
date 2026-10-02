package com.fusionplay.miplay.discovery

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * End-to-end test of DNS-SD record aggregation using verbatim captured
 * datagrams: PTR + SRV + TXT + A records are fed in the order a real scan
 * receives them, and the resulting [MiPlayDevice] must be fully populated.
 */
class MiPlayDeviceAggregationTest {

    private fun bytes(hex: String) = ByteArray(hex.length / 2) { i ->
        hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
    }

    /** `小爱音箱-2284` (LX06, 192.168.31.115) answering a QU browse. */
    private val lx06QuReply =
        "0000840000010001000000030b5f6d692d636f6e6e656374045f756470056c6f63616c00000c8001c00c000c00010000000a001411e5b08fe788b1e99fb3e7aeb12d32323834c00cc034002100010000000a000d00000000dd5a044c583036c01dc034001000010000000a00e70d76657273696f6e3d363535343508617070733d5b355d0a666c6167733d41673d3d166e616d653de5b08fe788b1e99fb3e7aeb12d323238340b6964486173683d5a445930056465763d34057365633d329561707073446174613d6751426d42494d6977307a47544e5958327741414141414141414141414141426f4f445a6a79774165776f4a496d3170593238694f69423743676b4a496d526c646d6c6a5a5639705a434936494349324e4759794d6a45315a53316b597a526d4c5451324f4441744f5749795a43316c4f4459354f575930597a517a5957516949416f4a6653414b6653414bc05a000100010000000a0004c0a81f73"

    /** `小爱音箱-1218` (OH2-1218, 192.168.31.89), TTL 120 announcement. */
    private val oh2Announcement =
        "0000840000000001000000030b5f6d692d636f6e6e656374045f756470056c6f63616c00000c000100000078001411e5b08fe788b1e99fb3e7aeb12d31323138c00cc02e0021800100000078001100000000dd5a084f48322d31323138c01dc02e001080010000007800f40d76657273696f6e3d363535343508617070733d5b355d0a666c6167733d41673d3d166e616d653de5b08fe788b1e99fb3e7aeb12d313231380b6964486173683d4d54466b056465763d34057365633d329561707073446174613d4157594141434c44555034354d527a4a41414141414141414141414141414767344e6d504c41423743676b6962576c6a627949364948734b43516b695a47563261574e6c58326c6b496a6f67496d55344d574d794f574a6c4c574d7a5a6d59744e4749784d7930354d324d794c57593459324d344d544a6c4e6d51335979496743676c394941703949416f3d0c6d61633d555034354d527a4ac05400018001000000780004c0a81f59"

    /** `客厅音箱 Pro` (937E4BA6, 192.168.31.117) `_mi-connect` record. */
    private val proMiConnect =
        "0000840000000001000000040b5f6d692d636f6e6e656374045f756470056c6f63616c00000c000100000078000b083933374534424136c00cc02e0021800100000078001100000000dd5a083933374534424136c01dc02e001080010000007801650b6964486173683d617a4d31056465763d34156e616d653de5aea2e58e85e99fb3e7aeb12050726f057365633d300c6d61633d6b50746430304d650a666c6167733d41413d3d0e76657273696f6e3d31393636303808617070733d5b355d9561707073446174613d4157594141434c446b50746430304d6541414141414141414141414141414767344e6d504c41463743676b6962576c6a627949364948734b43516b695a47563261574e6c58326c6b496a6f67496d5a6c593255334d5451334c5441324f5449744e4451354d5331685a5463304c5451334e6a457a4f575a6c4e6d49305a43496743676c394941703949416f3d0e4d656469756d547970653d323536614465627567496e666f3d7b6d73673a7265706c792c2069666e616d653a776c616e302c2076343a3139322e24292b2e26242e3131372c2076363a323430383a2b25263d3a272524243a3b3d233a3b2b2c2a3a24293c2c3a24253c243a666163627dc04b00018001000000780004c0a81f75c04b001c80010000007800102408823c42110ac0a89716b912b1facb"

    /** Same physical device as [proMiConnect], advertising `_lyra-mdns`. */
    private val proLyra =
        "0000840000000001000000040a5f6c7972612d6d646e73045f756470056c6f63616c00000c000100000078000b083933374534424136c00cc02d002180010000007800110000000014e9083933374534424136c01cc02d00108001000000780173c8417070446174613d414541466b33354c706741434151514b4177487067674542514149513561366935593646365a2b7a35363678494642796279516d65776f4a496e64735957354e59574d694f6941694f544136526b49364e55513652444d364e444d364d5555694941703949416f6b5a434c446b50746430304d6541414141414141414141414141414767344e6d504c41463743676b6962576c6a627949364948734b43516b695a47563261574e6c58326c6b496a6f67496d5a6c593255334d5451334c54413238417070446174613d4f5449744e4451354d5331685a5463304c5451334e6a457a4f575a6c4e6d49305a43496743676c394941703949416f3d0e4d656469756d547970653d323536614465627567496e666f3d7b6d73673a7265706c792c2069666e616d653a776c616e302c2076343a3139322e24292b2e26242e3131372c2076363a323430383a2b25263d3a272524243a3b3d233a3b2b2c2a3a24293c2c3a24253c243a666163627dc04a00018001000000780004c0a81f75c04a001c80010000007800102408823c42110ac0a89716b912b1facb"

    @Test
    fun `aggregates a single speaker into one fully populated device`() {
        val registry = DeviceRegistry()
        val message = requireNotNull(MiPlayDnsParser.parse(bytes(oh2Announcement)))
        assertTrue(registry.ingest(message, "192.168.31.89"))

        val devices = registry.snapshot()
        assertEquals(1, devices.size)
        val device = devices.single()

        assertEquals("小爱音箱-1218", device.name)
        assertEquals("192.168.31.89", device.ip)
        assertEquals(56666, device.port)
        assertEquals("e81c29be-c3ff-4b13-93c2-f8cc812e6d7c", device.deviceId)
        assertEquals("OH2-1218", device.model)
        assertEquals("Xiaomi", device.manufacturer)
        assertEquals("_mi-connect._udp.local", device.serviceType)
        assertEquals(4, device.deviceCategory)
        assertEquals(2, device.securityMode)
        assertEquals(65545, device.version)
        // mac= in the TXT record is base64 of the six raw bytes.
        assertEquals("50:fe:39:31:1c:c9", device.mac)
        assertTrue(device.capabilities!!.contains("sec=2"))
        assertTrue(device.capabilities!!.contains("version=65545"))
        assertNotNull(device.appsData)
    }

    @Test
    fun `merges the mi-connect and lyra views of one physical device`() {
        val registry = DeviceRegistry()
        registry.ingest(requireNotNull(MiPlayDnsParser.parse(bytes(proMiConnect))), "192.168.31.117")
        registry.ingest(requireNotNull(MiPlayDnsParser.parse(bytes(proLyra))), "192.168.31.117")

        val devices = registry.snapshot()
        // The two service records carry the same appsData device_id, so they
        // must collapse into a single logical receiver rather than two.
        assertEquals(1, devices.size)
        val device = devices.single()

        assertEquals("客厅音箱 Pro", device.name)
        assertEquals("192.168.31.117", device.ip)
        assertEquals("fece7147-0692-4491-ae74-476139fe6b4d", device.deviceId)
        assertEquals(2, device.serviceTypes.size)
        assertTrue(device.serviceTypes.contains("_mi-connect._udp.local"))
        assertTrue(device.serviceTypes.contains("_lyra-mdns._udp.local"))
        // The AAAA record is retained alongside the IPv4 address.
        assertTrue(device.addresses.contains("2408:823c:4211:ac0:a897:16b9:12b1:facb"))
        assertEquals(256, device.mediumType)
    }

    @Test
    fun `discovers a speaker that answers only the QU unicast query`() {
        val registry = DeviceRegistry()
        registry.ingest(requireNotNull(MiPlayDnsParser.parse(bytes(lx06QuReply))), "192.168.31.115")

        val device = registry.snapshot().single()
        assertEquals("小爱音箱-2284", device.name)
        assertEquals("192.168.31.115", device.ip)
        assertEquals(56666, device.port)
        assertEquals("LX06", device.model)
        assertEquals("64f2215e-dc4f-4680-9b2d-e8699f4c43ad", device.deviceId)
        // The QU reply questions `_mi-connect` and is matched on that service.
        assertEquals("_mi-connect._udp.local", device.serviceType)
    }

    @Test
    fun `a responder with no TXT record keeps its endpoint but no identity`() {
        // Real captured SRV/A records, but a *different* instance name whose TXT
        // was never published. This is the "Unknown MiPlay Device" case: the
        // endpoint must still be listed with name == null rather than filtered.
        val registry = DeviceRegistry()
        // Strip the TXT record from the genuine 小爱音箱-1218 announcement,
        // keeping the PTR, SRV and A records exactly as received.
        val announcement = requireNotNull(MiPlayDnsParser.parse(bytes(oh2Announcement)))
        val withoutTxt = announcement.copy(
            additionals = announcement.additionals.filterNot { it.type == MiPlayMdns.TYPE_TXT }
        )
        assertTrue(registry.ingest(withoutTxt, "192.168.31.89"))

        val device = registry.snapshot().single()
        assertEquals(null, device.name)
        assertEquals("192.168.31.89", device.ip)
        assertEquals(56666, device.port)
        assertEquals(null, device.deviceId)
        assertEquals("OH2-1218", device.model)
        // The SRV target hostname is still exposed for follow-up protocol work.
        assertEquals("OH2-1218.local.", device.host)
    }

    @Test
    fun `expired records disappear from the snapshot`() {
        val registry = DeviceRegistry()
        registry.ingest(requireNotNull(MiPlayDnsParser.parse(bytes(oh2Announcement))), "192.168.31.89")
        assertEquals(1, registry.snapshot().size)

        // Simulate the TTL (120s) having elapsed with no refresh.
        Thread.sleep(5)
        val changed = registry.prune(1L)
        assertTrue("prune should report a change", changed)
        assertEquals(0, registry.snapshot().size)
    }
}
