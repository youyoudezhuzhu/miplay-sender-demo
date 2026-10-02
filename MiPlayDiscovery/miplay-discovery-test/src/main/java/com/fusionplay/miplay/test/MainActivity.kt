package com.fusionplay.miplay.test

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.fusionplay.miplay.discovery.MiPlayDevice
import com.fusionplay.miplay.discovery.MiPlayDiscoveryClient
import com.fusionplay.miplay.discovery.MiPlayPacket
import com.fusionplay.miplay.sender.MiPlayControlClient
import com.google.android.material.button.MaterialButton
import com.google.android.material.checkbox.MaterialCheckBox

/**
 * MiPlay 妙播 sender demo.
 *
 * Stage 1 (this app):
 *  * mDNS discovery of every 小爱音箱 / 小米 device on the LAN,
 *  * multi-select,
 *  * the TCP 8899 **control channel**: connect, run the plaintext handshake
 *    (GET_VERSION / DEVICE_ID / AUTH_20 / capability negotiation), and report
 *    every frame the speaker sends back.
 *
 * Encryption: the channel turns encrypted at `SAFETY_AUTH`. Decrypting it needs
 * the session keys, which are generated on the sender and delivered out of band
 * (the official sender logs them; see `reports/MIPLAY_CRYPTO_ANALYSIS_V4.md`).
 * [MiPlayControlClient.installSessionKeys] arms the AES-128-CBC codec
 * (key = authKey, IV = streamIV, free-running chaining) once keys are known.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var discovery: MiPlayDiscoveryClient
    private lateinit var adapter: DeviceAdapter

    private lateinit var scanButton: MaterialButton
    private lateinit var selectAllButton: MaterialButton
    private lateinit var connectButton: MaterialButton
    private lateinit var disconnectButton: MaterialButton
    private lateinit var logToggleButton: MaterialButton
    private lateinit var clearLogButton: MaterialButton
    private lateinit var subtitleText: TextView
    private lateinit var selectionText: TextView
    private lateinit var emptyHint: TextView
    private lateinit var logPanel: View
    private lateinit var logText: TextView
    private lateinit var logScroll: androidx.core.widget.NestedScrollView

    /** Full raw capture transcript; the TextView only ever shows its tail. */
    private val transcript = StringBuilder()
    private var servicesSeen = 0

    /** device key (ip) -> selected */
    private val selected = linkedSetOf<String>()

    /** device key -> status line */
    private val statuses = mutableMapOf<String, String>()

    /** device key -> live control-channel client */
    private val clients = mutableMapOf<String, MiPlayControlClient>()

    private var devices: List<MiPlayDevice> = emptyList()

    private fun keyOf(d: MiPlayDevice): String = d.ip

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        scanButton = findViewById(R.id.scanButton)
        selectAllButton = findViewById(R.id.selectAllButton)
        connectButton = findViewById(R.id.connectButton)
        disconnectButton = findViewById(R.id.disconnectButton)
        logToggleButton = findViewById(R.id.logToggleButton)
        clearLogButton = findViewById(R.id.clearLogButton)
        subtitleText = findViewById(R.id.subtitleText)
        selectionText = findViewById(R.id.selectionText)
        emptyHint = findViewById(R.id.emptyHint)
        logPanel = findViewById(R.id.logPanel)
        logText = findViewById(R.id.logText)
        logScroll = findViewById(R.id.logScroll)

        adapter = DeviceAdapter(
            isSelected = { selected.contains(it) },
            statusOf = { statuses[it] },
            onToggle = { d, checked ->
                if (checked) selected.add(keyOf(d)) else selected.remove(keyOf(d))
                refreshSelectionUi()
                adapter.notifyDataSetChanged()
            }
        )
        findViewById<RecyclerView>(R.id.deviceList).apply {
            layoutManager = LinearLayoutManager(this@MainActivity)
            adapter = this@MainActivity.adapter
        }

        discovery = MiPlayDiscoveryClient(applicationContext)

        scanButton.setOnClickListener {
            if (discovery.isRunning) discovery.stopDiscovery() else discovery.startDiscovery()
        }

        selectAllButton.setOnClickListener {
            if (selected.size == devices.size) selected.clear()
            else devices.forEach { selected.add(keyOf(it)) }
            refreshSelectionUi()
            adapter.notifyDataSetChanged()
        }

        connectButton.setOnClickListener { connectSelected() }
        disconnectButton.setOnClickListener { disconnectAll() }

        logToggleButton.setOnClickListener {
            val show = logPanel.visibility != View.VISIBLE
            logPanel.visibility = if (show) View.VISIBLE else View.GONE
            logToggleButton.text =
                getString(if (show) R.string.hide_log else R.string.show_log)
        }

        clearLogButton.setOnClickListener {
            transcript.setLength(0)
            logText.text = ""
            discovery.packetLog.clear()
        }

        discovery.addListener(object : MiPlayDiscoveryClient.DiscoveryListener {
            override fun onDevicesChanged(devices: List<MiPlayDevice>) {
                runOnUiThread {
                    this@MainActivity.devices = devices
                    // Drop selections for devices that disappeared.
                    val live = devices.map { keyOf(it) }.toSet()
                    selected.retainAll(live)
                    adapter.submit(devices, statuses)
                    emptyHint.visibility = if (devices.isEmpty()) View.VISIBLE else View.GONE
                    subtitleText.text =
                        "已发现 ${devices.size} 台设备 · 服务响应 $servicesSeen 次"
                    refreshSelectionUi()
                }
            }

            override fun onServiceFound(
                serviceType: String,
                serviceName: String,
                sourceIp: String,
                port: Int
            ) {
                servicesSeen += 1
                appendLog("[discovery] SERVICE $sourceIp:$port $serviceType\n  instance=$serviceName\n")
            }

            override fun onPacket(packet: MiPlayPacket) {
                appendLog(packet.format() + "\n")
            }

            override fun onLog(message: String) {
                appendLog("[discovery] $message\n")
            }

            override fun onStarted() {
                runOnUiThread { scanButton.text = getString(R.string.stop_scan) }
                appendLog("[discovery] SCAN STARTED\n")
            }

            override fun onStopped() {
                runOnUiThread { scanButton.text = getString(R.string.start_scan) }
                appendLog("[discovery] SCAN STOPPED\n")
            }
        })

        refreshSelectionUi()
    }

    // ------------------------------------------------------------ selection
    private fun refreshSelectionUi() {
        selectionText.text = "已选 ${selected.size} 台音箱"
        connectButton.isEnabled = selected.isNotEmpty()
    }

    // ------------------------------------------------------- control channel
    private fun connectSelected() {
        val targets = devices.filter { selected.contains(keyOf(it)) }
        if (targets.isEmpty()) return
        val localIp = localIpv4() ?: run {
            appendLog("[control] no local IPv4 address; cannot start a session\n")
            return
        }
        for (d in targets) {
            val k = keyOf(d)
            if (clients.containsKey(k)) continue
            setStatus(k, getString(R.string.status_connecting))
            appendLog("[control] connecting to ${d.name ?: d.ip} (${d.ip}:8899)\n")
            val client = MiPlayControlClient(
                host = d.ip,
                localIp = localIp,
                listener = object : MiPlayControlClient.Listener {
                    override fun onStage(stage: String) {
                        appendLog("[control ${d.ip}] $stage\n")
                        runOnUiThread {
                            if (stage.contains("keys installed")) {
                                setStatus(k, getString(R.string.status_encrypted))
                            } else {
                                setStatus(k, getString(R.string.status_connected))
                            }
                        }
                    }

                    override fun onFrame(cmd: Int, seq: Int, plaintext: ByteArray?) {
                        val body = plaintext?.let { renderBody(it) } ?: "<encrypted>"
                        appendLog("[control ${d.ip}] rx cmd=0x%02x seq=%d %s\n".format(cmd, seq, body))
                    }

                    override fun onLog(message: String) {
                        appendLog("[control ${d.ip}] $message\n")
                    }

                    override fun onError(error: Throwable) {
                        appendLog("[control ${d.ip}] ERROR ${error.message}\n")
                        runOnUiThread { setStatus(k, getString(R.string.status_failed, error.message ?: "?")) }
                    }
                }
            )
            clients[k] = client
            Thread({
                try {
                    client.connectAndHandshake()
                } catch (t: Throwable) {
                    appendLog("[control ${d.ip}] connect failed: ${t.message}\n")
                    runOnUiThread { setStatus(k, getString(R.string.status_failed, t.message ?: "?")) }
                }
            }, "miplay-connect-${d.ip}").start()
        }
    }

    private fun disconnectAll() {
        clients.values.forEach { it.close() }
        clients.clear()
        selected.forEach { setStatus(it, getString(R.string.status_closed)) }
        adapter.notifyDataSetChanged()
    }

    private fun setStatus(key: String, status: String) {
        statuses[key] = status
        runOnUiThread { adapter.notifyDataSetChanged() }
    }

    /** Human-readable rendering of a frame body (UTF-8 when printable, else hex). */
    private fun renderBody(body: ByteArray): String {
        val printable = body.count { it.toInt() in 32..126 || it.toInt() == 10 || it.toInt() == 9 }
        return if (body.isNotEmpty() && printable * 100 / body.size > 80) {
            String(body, Charsets.UTF_8).replace("\n", " ").take(200)
        } else {
            "[" + body.take(48).joinToString("") { "%02x".format(it) } +
                    if (body.size > 48) "…]" else "]"
        }
    }

    private fun localIpv4(): String? {
        return try {
            java.net.NetworkInterface.getNetworkInterfaces().toList()
                .filter { it.isUp && !it.isLoopback }
                .flatMap { it.inetAddresses.toList() }
                .filterIsInstance<java.net.Inet4Address>()
                .firstOrNull()?.hostAddress
        } catch (t: Throwable) {
            null
        }
    }

    override fun onDestroy() {
        disconnectAll()
        discovery.stopDiscovery()
        super.onDestroy()
    }

    private fun appendLog(text: String) {
        runOnUiThread {
            transcript.append(text)
            if (transcript.length > MAX_TRANSCRIPT_CHARS) {
                transcript.delete(0, transcript.length - MAX_TRANSCRIPT_CHARS)
            }
            logText.text = transcript
            if (logPanel.visibility == View.VISIBLE) {
                logScroll.post { logScroll.fullScroll(View.FOCUS_DOWN) }
            }
        }
    }

    private companion object {
        const val MAX_TRANSCRIPT_CHARS = 400_000
    }
}

/** Renders one [MiPlayDevice] card with a selectable checkbox and a status line. */
private class DeviceAdapter(
    private val isSelected: (String) -> Boolean,
    private val statusOf: (String) -> String?,
    private val onToggle: (MiPlayDevice, Boolean) -> Unit
) : RecyclerView.Adapter<DeviceAdapter.Holder>() {

    private val items = mutableListOf<MiPlayDevice>()
    private var statuses: Map<String, String> = emptyMap()

    fun submit(devices: List<MiPlayDevice>, statuses: Map<String, String>) {
        items.clear()
        items.addAll(devices)
        this.statuses = statuses
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_miplay_device, parent, false)
        return Holder(view)
    }

    override fun onBindViewHolder(holder: Holder, position: Int) = holder.bind(items[position])

    override fun getItemCount(): Int = items.size

    inner class Holder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        private val check: MaterialCheckBox = itemView.findViewById(R.id.deviceCheck)
        private val name: TextView = itemView.findViewById(R.id.deviceName)
        private val status: TextView = itemView.findViewById(R.id.deviceStatus)
        private val detail: TextView = itemView.findViewById(R.id.deviceDetail)
        private val raw: TextView = itemView.findViewById(R.id.deviceRaw)

        fun bind(device: MiPlayDevice) {
            name.text = device.name ?: "Unknown MiPlay Device"

            val st = statuses[device.ip]
            status.text = st ?: ""
            status.visibility = if (st.isNullOrEmpty()) View.GONE else View.VISIBLE

            // Rebind-safe: clear the listener before setting state.
            check.setOnCheckedChangeListener(null)
            check.isChecked = isSelected(device.ip)
            check.setOnCheckedChangeListener { _, checked -> onToggle(device, checked) }

            detail.text = buildString {
                appendLine("IP:        ${device.ip}")
                appendLine("Port:      ${device.port ?: "-"}")
                appendLine("Model:     ${device.model ?: "-"}")
                appendLine("Device ID: ${device.deviceId ?: "-"}")
                appendLine("Service:   ${device.serviceTypes.joinToString(", ").ifEmpty { "-" }}")
                append("Category:  dev=${device.deviceCategory ?: "-"} sec=${device.securityMode ?: "-"}")
            }

            raw.text = buildString {
                if (device.txt.isNotEmpty()) {
                    appendLine("TXT:")
                    device.txt.forEach { (key, value) ->
                        val shown = if (value.length > 120) value.take(120) + "…" else value
                        appendLine("  $key=$shown")
                    }
                }
                device.mac?.let { appendLine("MAC: $it") }
                device.appsData?.let { appData ->
                    appendLine("appsData[${appData.sourceKey}] len=${appData.rawLength}")
                    appData.embeddedJson?.let { append("  json: $it") }
                }
                if (device.serviceNames.isNotEmpty()) {
                    appendLine()
                    append("Instances: ${device.serviceNames.joinToString(" | ")}")
                }
            }.trimEnd()
        }
    }
}
