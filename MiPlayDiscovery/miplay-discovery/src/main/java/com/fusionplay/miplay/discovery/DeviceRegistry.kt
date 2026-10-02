package com.fusionplay.miplay.discovery


/**
 * Aggregates mDNS resource records into [MiPlayDevice]s.
 *
 * DNS-SD splits one logical device across four record types (PTR → SRV → TXT,
 * plus A/AAAA for the SRV target). This class re-assembles them, applies TTLs,
 * merges the `_mi-connect` and `_lyra-mdns` views of the same physical device,
 * and never discards an endpoint just because its name is unknown.
 */
internal class DeviceRegistry {

    /** One DNS-SD service instance, e.g. `小爱音箱-2284._mi-connect._udp.local.`. */
    private class Instance(
        val name: String,
        val serviceType: String
    ) {
        var srvExpiry: Long = 0L
        var srvTarget: String? = null
        var srvPort: Int? = null

        var txtExpiry: Long = 0L
        val txt: MutableMap<String, String> = LinkedHashMap()

        /**
         * Base64 blob fragments keyed by TXT key.
         *
         * MiPlay may split one logical `AppData=` value across several TXT
         * strings, so fragments are accumulated in order and only joined when
         * the whole record has been received.
         */
        val blobFragments: MutableMap<String, MutableList<String>> = LinkedHashMap()

        /** Advertised identity, when the payload carried one. */
        var advertisedDeviceId: String? = null
        var appsData: MiPlayAppsData? = null

        /** Source IPs that answered for this instance. */
        val sourceIps: MutableSet<String> = LinkedHashSet()

        /** Resolved addresses of [srvTarget]. */
        val resolvedIps: MutableSet<String> = LinkedHashSet()

        var lastSeen: Long = 0L

        /** Best address: a resolved A record wins over the datagram source. */
        val addresses: List<String>
            get() {
                val merged = LinkedHashSet<String>()
                merged.addAll(resolvedIps)
                merged.addAll(sourceIps)
                return merged.toList()
            }

        /** Hard expiry derived from the SRV/TXT TTLs, or 0 when not yet known. */
        val expiresAt: Long
            get() = maxOf(srvExpiry, txtExpiry)

        /** Relative liveness used by prune()/snapshot(); keeps the private type local. */
        fun isStillAlive(now: Long, staleMillis: Long): Boolean {
            val deadline = expiresAt
            if (deadline != 0L && deadline <= now) return false
            return now - lastSeen <= staleMillis
        }
    }

    private data class HostRecord(val address: String, val expiry: Long)

    private val instances = LinkedHashMap<String, Instance>()
    private val hosts = HashMap<String, MutableList<HostRecord>>()
    private val lock = Any()

    /** @return `true` when the aggregated device set changed. */
    fun ingest(message: MiPlayDnsParser.Message, sourceIp: String): Boolean {
        val now = System.currentTimeMillis()
        var changed = false
        synchronized(lock) {
            for (record in message.allRecords) {
                when (record.type) {
                    MiPlayMdns.TYPE_A, MiPlayMdns.TYPE_AAAA -> {
                        val address = record.address ?: continue
                        val key = MiPlayMdns.canonicalName(record.name)
                        val expiry = now + ttlMillis(record.ttl)
                        val list = hosts.getOrPut(key) { ArrayList(2) }
                        val existing = list.indexOfFirst { it.address == address }
                        if (existing >= 0) {
                            if (list[existing].expiry < expiry) list[existing] = HostRecord(address, expiry)
                        } else {
                            list += HostRecord(address, expiry)
                            changed = true
                        }
                    }

                    MiPlayMdns.TYPE_PTR -> {
                        if (!MiPlayMdns.isMiPlayService(record.name)) continue
                        val instanceName = record.domainName ?: continue
                        val instance = obtain(instanceName, record.name)
                        instance.sourceIps.add(sourceIp)
                        instance.lastSeen = now
                        // PTR liveness is represented by lastSeen; TTL is applied in prune().
                        changed = true
                    }

                    MiPlayMdns.TYPE_SRV -> {
                        val instance = instances[MiPlayMdns.canonicalName(record.name)] ?: continue
                        instance.srvTarget = record.srvTarget
                        instance.srvPort = record.srvPort
                        instance.srvExpiry = now + ttlMillis(record.ttl)
                        instance.sourceIps.add(sourceIp)
                        instance.lastSeen = now
                        resolveTarget(instance)
                        changed = true
                    }

                    MiPlayMdns.TYPE_TXT -> {
                        val instance = instances[MiPlayMdns.canonicalName(record.name)] ?: continue
                        instance.txtExpiry = now + ttlMillis(record.ttl)
                        instance.sourceIps.add(sourceIp)
                        instance.lastSeen = now
                        applyTxt(instance, record.txt)
                        changed = true
                    }
                }
            }

            // A/AAAA records are usually emitted *after* the SRV record that
            // names their target, but a responder is free to order them either
            // way (and a cache-flush announcement often puts the address first).
            // Resolving after the whole message avoids silently dropping an
            // endpoint's address purely because of record ordering. This was a
            // real bug: the IPv6 address of a dual-stack speaker never reached
            // the device model.
            val targets = instances.values.mapNotNull { it.srvTarget }.toSet()
            if (targets.isNotEmpty()) {
                for (instance in instances.values) {
                    resolveTarget(instance)
                }
            }
        }
        return changed
    }

    /** Copies every cached address of this instance's SRV target onto it. */
    private fun resolveTarget(instance: Instance) {
        val target = instance.srvTarget?.let { MiPlayMdns.canonicalName(it) } ?: return
        val cached = hosts[target] ?: return
        for (host in cached) instance.resolvedIps.add(host.address)
    }

    /**
     * Records the TXT key/values of one record and re-decodes the identity blob.
     *
     * A repeated key is treated as a continuation of the previous value (DNS-SD
     * concatenation), which is how a real speaker publishes `AppData`.
     */
    private fun applyTxt(instance: Instance, values: List<String>) {
        for (value in values) {
            val separator = value.indexOf('=')
            if (separator <= 0) {
                instance.txt[value] = ""
                continue
            }
            val key = value.substring(0, separator)
            val content = value.substring(separator + 1)
            if (MiPlayAppsDataDecoder.SOURCE_KEYS.contains(key)) {
                // Blobs are base64 and may be split; keep fragments, never
                // overwrite an earlier half with a later one.
                instance.blobFragments.getOrPut(key) { ArrayList(2) }.add(content)
                instance.txt[key] = (instance.txt[key] ?: "") + content
            } else {
                instance.txt[key] = content
            }
        }
        for ((key, fragments) in instance.blobFragments) {
            val decoded = MiPlayAppsDataDecoder.decodeConcatenated(key, fragments) ?: continue
            instance.appsData = decoded
            decoded.deviceId?.let { instance.advertisedDeviceId = it }
        }
    }

    fun portFor(instanceName: String): Int? = synchronized(lock) {
        instances[MiPlayMdns.canonicalName(instanceName)]?.srvPort
    }

    /** @return `true` when something expired and the device set changed. */
    fun prune(ttlMillis: Long): Boolean {
        val now = System.currentTimeMillis()
        var changed = false
        synchronized(lock) {
            hosts.values.forEach { list ->
                if (list.removeAll { it.expiry <= now }) changed = true
            }
            hosts.entries.removeAll { it.value.isEmpty() }

            val iterator = instances.iterator()
            while (iterator.hasNext()) {
                // LinkedHashMap iteration yields entries, not values.
                val instance: Instance = iterator.next().value
                if (!instance.isStillAlive(now, ttlMillis)) {
                    iterator.remove()
                    changed = true
                }
            }
        }
        return changed
    }

    fun snapshot(): List<MiPlayDevice> {
        val now = System.currentTimeMillis()
        return synchronized(lock) {
            val live: List<Instance> = instances.values.filter { candidate ->
                candidate.isStillAlive(now, 300_000L)
            }
            val groups = LinkedHashMap<String, MutableList<Instance>>()
            for (instance in live) {
                val address = instance.addresses.firstOrNull() ?: instance.sourceIps.firstOrNull() ?: "unknown"
                val identity = instance.advertisedDeviceId ?: "ip:$address"
                groups.getOrPut(identity) { ArrayList(2) }.add(instance)
            }
            groups.map { (_, members) -> buildDevice(members) }
                .sortedWith(compareBy({ it.name ?: "\uFFFF" }, { it.ip }))
        }
    }

    // ------------------------------------------------------------------ private

    private fun obtain(instanceName: String, serviceType: String): Instance {
        val key = MiPlayMdns.canonicalName(instanceName)
        return instances.getOrPut(key) { Instance(key, MiPlayMdns.canonicalName(serviceType)) }
    }

    private fun ttlMillis(ttl: Long): Long = (ttl.coerceAtLeast(1L) * 1000L).coerceAtMost(600_000L)

    private fun buildDevice(members: List<Instance>): MiPlayDevice {
        val primary = members.firstOrNull { it.serviceType == MiPlayMdns.SERVICE_MI_CONNECT }
            ?: members.first()

        val addresses = LinkedHashSet<String>()
        for (member in members) addresses.addAll(member.addresses)
        val hostNames = members.mapNotNull { it.srvTarget }.map { it.trimEnd('.') }.distinct()
        val serviceTypes = members.map { it.serviceType.trimEnd('.') }.distinct()
        val serviceNames = members.map { it.name.trimEnd('.') }.distinct()
        val ports = members.mapNotNull { it.srvPort }.distinct()
        val txt = LinkedHashMap<String, String>()
        for (member in members) txt.putAll(member.txt)

        val appsData = members.firstNotNullOfOrNull { it.appsData }

        // TXT values are read from any member, because a device may publish
        // `dev`/`sec` only on one of its two service records.
        val name = firstNonEmpty(
            primary.txt["name"],
            members.firstNotNullOfOrNull { it.txt["name"] }
        )

        // The SRV target is the receiver's mDNS host name, which for Xiaomi
        // speakers is the hardware model: `LX06.local.`, `OH2-1218.local.`,
        // `937E4BA6.local.`. The `.local` suffix is stripped for display, and
        // the untouched name remains available in MiPlayDevice.host.
        val model = hostNames.firstOrNull { it.isNotEmpty() }
            ?.removeSuffix(".local")
            ?: primary.srvTarget?.trimEnd('.')?.removeSuffix(".local")

        val port = primary.srvPort
            ?: ports.firstOrNull()

        val category = members.firstNotNullOfOrNull { it.txt["dev"]?.toIntOrNull() }
        val security = members.firstNotNullOfOrNull { it.txt["sec"]?.toIntOrNull() }
        val version = members.firstNotNullOfOrNull { it.txt["version"]?.toIntOrNull() }
        val mediumType = members.firstNotNullOfOrNull { it.txt["MediumType"]?.toIntOrNull() }
        val flags = members.firstNotNullOfOrNull { it.txt["flags"] }
        val apps = members.firstNotNullOfOrNull { it.txt["apps"] }
        val idHash = members.firstNotNullOfOrNull { it.txt["idHash"] }
        val mac = members.firstNotNullOfOrNull { it.txt["mac"] }
        val deviceId = members.firstNotNullOfOrNull { it.advertisedDeviceId }

        // Capabilities: MiPlay expresses them as flags/apps/dev/MediumType.
        // They are surfaced both as decoded key=value strings and raw.
        val capabilities = buildList {
            flags?.let { add("flags=$it") }
            apps?.let { add("apps=$it") }
            txt["MediumType"]?.let { add("MediumType=$it") }
            txt["sec"]?.let { add("sec=$it") }
            txt["version"]?.let { add("version=$it") }
        }.ifEmpty { null }

        val lastSeen = members.maxOf { it.lastSeen }

        return MiPlayDevice(
            name = name,
            ip = addresses.firstOrNull() ?: "unknown",
            port = port,
            deviceId = deviceId,
            model = model,
            manufacturer = "Xiaomi",
            serviceType = primary.serviceType.trimEnd('.'),
            capabilities = capabilities,
            serviceTypes = serviceTypes,
            serviceNames = serviceNames,
            // Fully qualified: the SRV target with its trailing dot preserved.
            host = hostNames.firstOrNull()?.let { "$it." },
            txt = txt,
            deviceCategory = category,
            securityMode = security,
            idHash = idHash,
            version = version,
            flags = flags,
            apps = apps,
            mediumType = mediumType,
            mac = mac?.let { formatMac(it) },
            appsData = appsData,
            lastSeenMillis = lastSeen,
            addresses = addresses.toList()
        )
    }

    /**
     * `mac=` is base64 of the six raw hardware bytes (FusionPlay-Android
     * documents and real speakers confirm this). Anything that does not decode
     * to exactly six bytes is returned unchanged rather than mangled.
     */
    private fun formatMac(value: String): String {
        val raw = Base64Codec.decode(value) ?: return value
        if (raw.size != 6) return value
        return raw.joinToString(":") { String.format("%02x", it.toInt() and 0xFF) }
    }

    private fun firstNonEmpty(vararg values: String?): String? =
        values.firstOrNull { !it.isNullOrBlank() }
}
