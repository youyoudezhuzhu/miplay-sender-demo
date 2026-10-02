package com.fusionplay.miplay.sender

import android.util.Log
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicInteger

/**
 * MiPlay control-channel client (TCP 8899) — sender side.
 *
 * Implements the session as observed on real captures:
 *
 * ```
 *  ->  0x36 GET_VERSION      "2.1.4111518\0"
 *  <-  0x28 DEVICE_ID        "81222965823935"
 *  <-  0x37 GET_VERSION_ACK  "2.2.4112519\0"
 *  <-  0x22 NOTIFY           mode / mediaInfoEx / state (TLV)
 *  ->  0x29 AUTH_20          40 ASCII hex chars = 20 bytes, per-session
 *  ->  0x14/0x00 wrapper key="cmd"  {"aesIvTypes":"7", ...}
 *  <-  0x14/0x01 wrapper key="ack"  {"aesIvType":"4","aesKeyType":"4", ...}
 *  ->  0x02 SAFETY_AUTH      (first ENCRYPTED frame)
 *  <-  0x03 SAFETY_INFO      (carries the chosen types; encrypted)
 *  ->  0x6c SET_MIRROR_KEY   {"wlan0ip":..,"authKey":..,"streamKey":..,"streamIV":..}
 * ```
 *
 * Encryption turns on at `SAFETY_AUTH`. Before that point the handshake is
 * plaintext, which is why the version strings and the AUTH_20 value are
 * recoverable from a capture without any key.
 *
 * The class is deliberately low-level: it performs the handshake, exposes the
 * decrypted frames it sees, and lets the caller push commands. It does **not**
 * implement the media (RTSP/WFD/MPEG-TS) path.
 */
class MiPlayControlClient(
    private val host: String,
    private val port: Int = DEFAULT_PORT,
    private val localIp: String,
    private val listener: Listener
) {

    interface Listener {
        /** Handshake progressed to [stage]; free-form for the debug UI. */
        fun onStage(stage: String)

        /** A frame arrived. [plaintext] is null when the frame was encrypted and could not be opened. */
        fun onFrame(cmd: Int, seq: Int, plaintext: ByteArray?)

        /** Non-fatal diagnostics. */
        fun onLog(message: String)

        /** Terminal failure. */
        fun onError(error: Throwable)
    }

    companion object {
        private const val TAG = "MiPlayControl"
        const val DEFAULT_PORT = 8899

        // Command codes used by the handshake.
        const val CMD_SET_MIRROR_KEY = 0x6C
        const val CMD_GET_VERSION = 0x36
        const val CMD_DEVICE_ID = 0x28
        const val CMD_GET_VERSION_ACK = 0x37
        const val CMD_NOTIFY = 0x22
        const val CMD_AUTH_20 = 0x29
        const val CMD_WRAPPER = 0x14
        const val CMD_SAFETY_AUTH = 0x02
        const val CMD_SAFETY_INFO = 0x03
        const val CMD_HEARTBEAT = 0x1A
        const val CMD_HEARTBEAT_ACK = 0x1B

        const val SENDER_VERSION = "2.1.4111518"

        /** cmd 0x14 also sets outer_type = 0x14 on the wire. */
        private const val WRAPPER_OUTER = 0x14

        /** Capability bitmask offered by the official sender during negotiation. */
        private const val OFFERED_TYPES = "7"
        private const val OFFERED_AUTH_KEY_TYPES = "3"
        private const val OFFERED_INTEGRITY_TYPES = "1"
    }

    private var socket: Socket? = null
    private var input: InputStream? = null
    private var output: OutputStream? = null
    private var worker: Thread? = null
    private val seq = AtomicInteger(1)
    private var cipher: MiPlayControlCipher? = null

    /** Session keys once the caller installs them (from our key recovery / SET_MIRROR_KEY). */
    @Volatile
    var sessionKeys: MiPlaySessionKeys? = null
        private set

    /** The 20-byte AUTH value we generated for this session, hex-encoded. */
    @Volatile
    var auth20Hex: String? = null
        private set

    /** The receiver's negotiated capability JSON, once returned. */
    @Volatile
    var negotiated: String? = null
        private set

    @Volatile
    private var running = false

    /**
     * Install session keys and switch the channel into encrypted mode.
     * Called after the type negotiation with keys recovered out-of-band.
     */
    fun installSessionKeys(keys: MiPlaySessionKeys) {
        sessionKeys = keys
        cipher = MiPlayControlCipher(keys)
        listener.onStage("keys installed (control cipher armed)")
    }

    /** Open the socket, run the plaintext handshake, then serve frames. */
    fun connectAndHandshake(timeoutMs: Int = 8000) {
        val s = Socket()
        s.tcpNoDelay = true
        s.soTimeout = timeoutMs
        s.connect(InetSocketAddress(host, port), timeoutMs)
        socket = s
        input = s.getInputStream()
        output = s.getOutputStream()
        running = true
        listener.onStage("connected to $host:$port")

        // ---- plaintext handshake -------------------------------------------
        sendPlain(CMD_GET_VERSION, (SENDER_VERSION + "\u0000").toByteArray(Charsets.US_ASCII))
        listener.onStage("sent GET_VERSION $SENDER_VERSION")

        val auth = ByteArray(20)
        SecureRandom().nextBytes(auth)
        auth20Hex = auth.joinToString("") { "%02x".format(it) }
        sendPlain(CMD_AUTH_20, auth20Hex!!.toByteArray(Charsets.US_ASCII))
        listener.onStage("sent AUTH_20 ${auth20Hex!!.length} hex chars")

        val offer = buildString {
            append("{\n")
            append("\t\"aesIvTypes\": \"$OFFERED_TYPES\",\n")
            append("\t\"aesKeyTypes\": \"$OFFERED_TYPES\",\n")
            append("\t\"authAlgorithmTypes\": \"$OFFERED_TYPES\",\n")
            append("\t\"authKeyTypes\": \"$OFFERED_AUTH_KEY_TYPES\",\n")
            append("\t\"integrityTypes\": \"$OFFERED_INTEGRITY_TYPES\" \n")
            append("} \n")
        }
        sendWrapper("cmd", offer)
        listener.onStage("sent capability offer")

        worker = Thread({ pumpLoop() }, "miplay-rx").also { it.isDaemon = true; it.start() }
    }

    /** Wrap a payload in the `key`/`len` TLV used by cmd 0x14. */
    private fun sendWrapper(key: String, payload: String) {
        val keyBytes = key.toByteArray(Charsets.US_ASCII)
        val payloadBytes = payload.toByteArray(Charsets.UTF_8)
        val body = ByteArray(1 + keyBytes.size + 4 + payloadBytes.size)
        body[0] = keyBytes.size.toByte()
        System.arraycopy(keyBytes, 0, body, 1, keyBytes.size)
        var o = 1 + keyBytes.size
        val n = payloadBytes.size
        body[o++] = (n ushr 24).toByte()
        body[o++] = (n ushr 16).toByte()
        body[o++] = (n ushr 8).toByte()
        body[o++] = n.toByte()
        System.arraycopy(payloadBytes, 0, body, o, payloadBytes.size)
        // cmd 0x14 carries outer_type = 0x14 on the wire (confirmed in captures).
        sendPlain(CMD_WRAPPER, body, outer = WRAPPER_OUTER)
    }

    /** Send a plaintext (pre-encryption) frame. */
    private fun sendPlain(cmd: Int, body: ByteArray, outer: Int = 0) {
        val s = output ?: return
        val frame = MiPlayWire.frame(cmd, seq.getAndIncrement(), body, outer)
        synchronized(this) { s.write(frame); s.flush() }
        listener.onLog("tx plain cmd=0x%02x outer=%d len=%d".format(cmd, outer, body.size))
    }

    /** Send a frame through the control cipher, once armed. */
    fun sendEncrypted(cmd: Int, plaintext: ByteArray): Boolean {
        val c = cipher ?: run {
            listener.onLog("cannot send encrypted cmd=0x%02x: no session keys".format(cmd))
            return false
        }
        val s = output ?: return false
        val body = c.encrypt(plaintext)
        val frame = MiPlayWire.frame(cmd, seq.getAndIncrement(), body)
        synchronized(this) { s.write(frame); s.flush() }
        listener.onLog("tx enc cmd=0x%02x len=%d".format(cmd, plaintext.size))
        return true
    }

    /** Push the media keys to the receiver (cmd 0x6c). */
    fun sendSetMirrorKey(keys: MiPlaySessionKeys): Boolean {
        val json = keys.toSetMirrorKeyJson(localIp)
        return sendEncrypted(CMD_SET_MIRROR_KEY, json.toByteArray(Charsets.UTF_8))
    }

    private fun pumpLoop() {
        val buf = ByteArray(64 * 1024)
        var carry = ByteArray(0)
        try {
            while (running) {
                val n = input?.read(buf) ?: break
                if (n <= 0) break
                val merged = ByteArray(carry.size + n)
                System.arraycopy(carry, 0, merged, 0, carry.size)
                System.arraycopy(buf, 0, merged, carry.size, n)

                val (frames, consumed) = MiPlayWire.parseFrames(merged)
                carry = if (consumed < merged.size) merged.copyOfRange(consumed, merged.size) else ByteArray(0)
                for (f in frames) handleFrame(f)
            }
            if (running) listener.onError(java.io.EOFException("control channel closed by peer"))
        } catch (t: Throwable) {
            if (running) listener.onError(t)
        }
    }

    private fun handleFrame(f: MiPlayWire.Frame) {
        var plain: ByteArray? = null
        if (MiPlayWire.isEncrypted(f.body)) {
            val env = MiPlayWire.parseEnvelope(f.body)
            if (env != null) {
                if (!MiPlayWire.verify(env)) listener.onLog("integrity mismatch on cmd=0x%02x".format(f.cmd))
                plain = cipher?.decrypt(env)
                if (plain == null && cipher != null) {
                    // A failed open means the chain desynced; re-sync from the next frame.
                    listener.onLog("decrypt failed cmd=0x%02x (chain resync)".format(f.cmd))
                    cipher?.reset()
                }
            }
        } else {
            plain = f.body
        }
        if (f.cmd == CMD_WRAPPER && plain != null) maybeParseAck(plain)
        listener.onFrame(f.cmd, f.seq, plain)
    }

    /** Extract the negotiation result from the 0x14 wrapper `ack` payload. */
    private fun maybeParseAck(plain: ByteArray) {
        val text = String(plain, Charsets.UTF_8)
        if (!text.contains("\"ack\"") && !text.contains("aesKeyType")) return
        negotiated = text
        listener.onStage("peer negotiation: ${text.replace('\n', ' ').trim()}")
    }

    fun close() {
        running = false
        try { worker?.interrupt() } catch (_: Throwable) {}
        try { socket?.close() } catch (_: Throwable) {}
        socket = null; input = null; output = null
    }
}
