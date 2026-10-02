package com.fusionplay.miplay.sender.media

import android.util.Log
import java.io.BufferedInputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.SecureRandom
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * Minimal WFD / `org.wfa.wfd1.0` RTSP server for the MiPlay audio push path.
 *
 * The speaker dials **into** the sender, so the sender must host this. The
 * dialogue reproduced here comes from a real capture; see
 * `reports/MIPLAY_AUDIO_PUSH_PROTOCOL.md` §2 for every field.
 *
 * Sequence (sender = server, speaker = client):
 * ```
 *  <- OPTIONS *                (speaker probes; carries authMsg)
 *  -> 200 OK + Public + authMsgAck
 *  <- GET_PARAMETER            (speaker asks for capabilities)
 *  -> 200 OK + wfd_audio_codecs_v2 / wfd_client_rtp_ports ...
 *  <- SET_PARAMETER            (speaker selects codec + presentation URL)
 *  -> 200 OK
 *  <- SETUP  / PLAY            (stream starts)
 *  -> interleaved MPEG-TS on the same TCP connection
 * ```
 *
 * ## Not implemented / risk
 * The `authMsg` -> `authMsgAck` algorithm is still unknown (see §5 of the
 * report). [authMsgAck] computes a best-effort HMAC-SHA256 answer; if the
 * speaker rejects it, the session will not start. This is the single biggest
 * unknown in the push path.
 */
class WfdRtspServer(
    private val port: Int = 0,
    private val localIp: String,
    private val listener: Listener,
    /** Audio capabilities advertised to the receiver. */
    private val audioCodecsV2: String = "63 3 3",
    /** `authKey` from the MiPlay session, when known. */
    private val authKey: String? = null
) {

    interface Listener {
        fun onLog(message: String)
        /** The speaker connected; the server is ready to receive RTSP requests. */
        fun onClientConnected(remote: String)
        /** `SETUP`/`PLAY` completed: audio now flows on this session. */
        fun onPlay(sessionId: Int)
        fun onError(error: Throwable)
    }

    companion object {
        private const val TAG = "WfdRtsp"
        private const val RTSP_VERSION = "RTSP/1.0"
        private const val WFD_VERSION = "org.wfa.wfd1.0"

        /** Server banner, matching the reference sender. */
        const val LIB_VERSION = "audio-display-release2.1 2.1.4111518"

        /**
         * Best-effort `authMsgAck`: HMAC-SHA256(authMsg) keyed with the session
         * authKey. The real algorithm is still unknown.
         */
        fun authMsgAck(authMsgHex: String, authKey: String): String {
            return try {
                val mac = javax.crypto.Mac.getInstance("HmacSHA256")
                mac.init(javax.crypto.spec.SecretKeySpec(authKey.toByteArray(Charsets.US_ASCII), "HmacSHA256"))
                val msg = authMsgHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                mac.doFinal(msg).joinToString("") { "%02x".format(it) }
            } catch (t: Throwable) {
                ""
            }
        }
    }

    private var serverSocket: ServerSocket? = null
    private val running = AtomicBoolean(false)
    private var acceptThread: Thread? = null
    private val sessions = CopyOnWriteArrayList<RtspSession>()
    private val sessionCounter = AtomicInteger(1)

    /** Bound port (valid after [start]; useful when [port] was 0). */
    @Volatile
    var boundPort: Int = -1
        private set

    /** `wfd://<ip>:<port>?mirrorMode=1`, to be handed to the speaker over 8899. */
    fun presentationUri(): String = "wfd://$localIp:$boundPort?mirrorMode=1"

    fun start() {
        if (!running.compareAndSet(false, true)) return
        val ss = ServerSocket(port)
        serverSocket = ss
        boundPort = ss.localPort
        listener.onLog("RTSP listening on :$boundPort (WFD $WFD_VERSION)")
        acceptThread = Thread({ acceptLoop(ss) }, "wfd-rtsp-accept").also {
            it.isDaemon = true
            it.start()
        }
    }

    private fun acceptLoop(ss: ServerSocket) {
        while (running.get()) {
            try {
                val sock = ss.accept()
                sock.tcpNoDelay = true
                listener.onClientConnected(sock.inetAddress.hostAddress ?: "?")
                val session = RtspSession(sock)
                sessions.add(session)
                Thread({ session.run() }, "wfd-rtsp-${sock.port}").also {
                    it.isDaemon = true
                    it.start()
                }
            } catch (t: Throwable) {
                if (running.get()) listener.onError(t)
            }
        }
    }

    fun stop() {
        running.set(false)
        sessions.forEach { it.close() }
        sessions.clear()
        try { serverSocket?.close() } catch (_: Throwable) {}
        serverSocket = null
    }

    // ================================================================== session
    /**
     * One RTSP connection. Requests and interleaved responses share the socket,
     * exactly as the capture shows.
     */
    inner class RtspSession(private val sock: Socket) {
        private val input: InputStream = BufferedInputStream(sock.getInputStream())
        private val output: OutputStream = sock.getOutputStream()
        private var sessionId: Int = 0
        private val cseq = AtomicInteger(0)
        private var playing = false

        /** Synthetic RTP-Info / session info echoed to the client. */
        private val random = SecureRandom()

        fun run() {
            try {
                while (running.get() && !sock.isClosed) {
                    val request = readRequest() ?: break
                    handle(request)
                }
            } catch (t: Throwable) {
                if (running.get()) listener.onLog("session ended: ${t.message}")
            } finally {
                close()
            }
        }

        /** Read one RTSP request: headers plus any body. */
        private fun readRequest(): RtspRequest? {
            val headerBytes = readUntilBlankLine() ?: return null
            val text = String(headerBytes, Charsets.UTF_8)
            val lines = text.split("\r\n").filter { it.isNotEmpty() }
            if (lines.isEmpty()) return null
            val startLine = lines[0]
            val headers = HashMap<String, String>()
            for (i in 1 until lines.size) {
                val idx = lines[i].indexOf(':')
                if (idx > 0) {
                    headers[lines[i].substring(0, idx).trim().lowercase()] =
                        lines[i].substring(idx + 1).trim()
                }
            }
            val contentLength = headers["content-length"]?.toIntOrNull() ?: 0
            val body = if (contentLength > 0) readExactly(contentLength) else ByteArray(0)
            return RtspRequest(startLine, headers, body)
        }

        private fun readUntilBlankLine(): ByteArray? {
            val buf = java.io.ByteArrayOutputStream()
            var state = 0
            while (true) {
                val b = input.read()
                if (b < 0) return if (buf.size() == 0) null else buf.toByteArray()
                buf.write(b)
                state = when {
                    state == 0 && b == '\r'.code -> 1
                    state == 1 && b == '\n'.code -> 2
                    state == 2 && b == '\r'.code -> 3
                    state == 3 && b == '\n'.code -> return buf.toByteArray()
                    b == '\r'.code -> 1
                    else -> 0
                }
            }
        }

        private fun readExactly(n: Int): ByteArray {
            val out = ByteArray(n)
            var read = 0
            while (read < n) {
                val r = input.read(out, read, n - read)
                if (r < 0) break
                read += r
            }
            return if (read == n) out else out.copyOf(read)
        }

        private fun handle(req: RtspRequest) {
            val method = req.startLine.substringBefore(' ').uppercase()
            listener.onLog("<- $method ${req.headers["cseq"] ?: "-"}")
            when (method) {
                "OPTIONS" -> onOptions(req)
                "GET_PARAMETER" -> onGetParameter(req)
                "SET_PARAMETER" -> onSetParameter(req)
                "SETUP" -> onSetup(req)
                "PLAY" -> onPlay(req)
                "TEARDOWN" -> {
                    sendResponse(req, 200, "OK")
                    close()
                }
                "PAUSE" -> sendResponse(req, 200, "OK")
                else -> sendResponse(req, 200, "OK")
            }
        }

        private fun onOptions(req: RtspRequest) {
            val authMsg = req.headers["authmsg"]
            val extra = StringBuilder()
            if (authMsg != null && authKey != null) {
                extra.append("authMsgAck:${authMsgAck(authMsg, authKey)}\r\n")
            }
            sendResponse(
                req, 200, "OK",
                extraHeaders = extra.toString(),
                publicHeader = "$WFD_VERSION, SETUP, TEARDOWN, PLAY, PAUSE, GET_PARAMETER, SET_PARAMETER"
            )
        }

        /** Reply with the sender's capabilities — this is what the speaker asks for. */
        private fun onGetParameter(req: RtspRequest) {
            val body = buildString {
                append("wfd_audio_codecs_v2: $audioCodecsV2\r\n")
                append("wfd_video_formats: none\r\n")
                append("wfd_video_enctype: none\r\n")
                append("wfd_video_gamuttype: none\r\n")
                append("wfd_video_bitrate: none\r\n")
                append("wfd_current_video_info: none\r\n")
                append("wfd_client_rtp_ports: RTP/AVP/TCP;interleaved mode=play\r\n")
                append("miplay_support_image: none\r\n")
                append("wfd_standby_resume_capability: supported\r\n")
                append("wfd_content_SP_protection: 4 1 256 2 1 1 0 0\r\n")
                append("wfd_support_secure_win:enable\r\n")
                append("device_info: -1 -1 -1 -1 -1 -1 -1\r\n")
            }
            sendResponse(req, 200, "OK", body = body, contentType = "text/parameters")
        }

        private fun onSetParameter(req: RtspRequest) {
            val body = String(req.body, Charsets.UTF_8)
            listener.onLog("   SET_PARAMETER body: ${body.replace("\r\n", " | ").take(200)}")
            sendResponse(req, 200, "OK", contentType = "text/parameters")
        }

        private fun onSetup(req: RtspRequest) {
            if (sessionId == 0) sessionId = sessionCounter.getAndIncrement()
            sendResponse(
                req, 200, "OK",
                sessionHeader = "$sessionId;timeout=20",
                transport = req.headers["transport"]
                    ?: "RTP/AVP/TCP;unicast;interleaved=0-1"
            )
        }

        private fun onPlay(req: RtspRequest) {
            if (sessionId == 0) sessionId = sessionCounter.getAndIncrement()
            playing = true
            val rtpInfo = "url=${req.startLine.split(' ').getOrNull(1) ?: "*"};seq=0;rtptime=0"
            sendResponse(
                req, 200, "OK",
                sessionHeader = "$sessionId;timeout=20",
                rtpInfo = rtpInfo
            )
            listener.onPlay(sessionId)
        }

        // ---------------------------------------------------------- responses
        private fun sendResponse(
            req: RtspRequest,
            code: Int,
            reason: String,
            body: String = "",
            contentType: String? = null,
            sessionHeader: String? = null,
            transport: String? = null,
            rtpInfo: String? = null,
            publicHeader: String? = null,
            extraHeaders: String = ""
        ) {
            val c = req.headers["cseq"] ?: cseq.incrementAndGet().toString()
            val sb = StringBuilder()
            sb.append("$RTSP_VERSION $code $reason\r\n")
            sb.append("CSeq: $c\r\n")
            if (publicHeader != null) sb.append("Public: $publicHeader\r\n")
            if (sessionHeader != null) sb.append("Session: $sessionHeader\r\n")
            if (transport != null) sb.append("Transport: $transport\r\n")
            if (rtpInfo != null) sb.append("RTP-Info: $rtpInfo\r\n")
            if (extraHeaders.isNotEmpty()) sb.append(extraHeaders)
            if (body.isNotEmpty()) {
                sb.append("Content-Type: ${contentType ?: "text/parameters"}\r\n")
                sb.append("Content-Length: ${body.toByteArray(Charsets.UTF_8).size}\r\n")
            } else {
                sb.append("Content-Length: 0\r\n")
            }
            sb.append("\r\n")
            if (body.isNotEmpty()) sb.append(body)
            synchronized(output) {
                output.write(sb.toString().toByteArray(Charsets.UTF_8))
                output.flush()
            }
            listener.onLog("-> $code $reason (cseq $c)")
        }

        // ------------------------------------------------- interleaved output
        /**
         * Write one interleaved frame: `'$' | channel:u8 | length:u16be | payload`.
         * The captured stream uses channel 0 for audio (report §4.1).
         */
        fun writeInterleaved(channel: Int, payload: ByteArray) {
            if (!playing) return
            val header = byteArrayOf(
                0x24,
                channel.toByte(),
                ((payload.size ushr 8) and 0xFF).toByte(),
                (payload.size and 0xFF).toByte()
            )
            synchronized(output) {
                output.write(header)
                output.write(payload)
                output.flush()
            }
        }

        fun isPlaying(): Boolean = playing

        fun close() {
            try { sock.close() } catch (_: Throwable) {}
        }
    }

    /** Push an already-muxed TS chunk to every playing session. */
    fun broadcastTs(ts: ByteArray, channel: Int = 0) {
        for (s in sessions) if (s.isPlaying()) s.writeInterleaved(channel, ts)
    }

    data class RtspRequest(
        val startLine: String,
        val headers: Map<String, String>,
        val body: ByteArray
    ) {
        override fun equals(other: Any?): Boolean = this === other
        override fun hashCode(): Int = startLine.hashCode()
    }
}
