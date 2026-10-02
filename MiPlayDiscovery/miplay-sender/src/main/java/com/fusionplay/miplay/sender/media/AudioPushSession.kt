package com.fusionplay.miplay.sender.media

import android.util.Log
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean

/**
 * End-to-end audio push session: encodes a local file and streams it to the
 * speaker as MPEG-TS over the WFD RTSP connection.
 *
 * Flow (reproduced from a real capture, see
 * `reports/MIPLAY_AUDIO_PUSH_PROTOCOL.md` §7):
 *
 * ```
 *  1. start the RTSP server, learn our bound port
 *  2. hand wfd://<ip>:<port>?mirrorMode=1 to the speaker over the 8899 control channel
 *  3. the speaker dials in; answer OPTIONS (with authMsgAck) -> GET/SET_PARAMETER -> SETUP -> PLAY
 *  4. on PLAY, start encoding and muxing; push interleaved TS on the audio connection
 * ```
 *
 * Step 2 is the caller's responsibility (it needs the 8899 client), and step 4
 * writes to whichever RTSP session reported PLAY.
 */
class AudioPushSession(
    private val localIp: String,
    private val rtspPort: Int = 0,
    private val authKey: String?,
    private val listener: Listener
) {

    interface Listener {
        fun onLog(message: String)
        /** Give this URI to the speaker via the control channel (cmd 0x6c path). */
        fun onPresentationUriReady(uri: String)
        fun onError(error: Throwable)
    }

    companion object {
        private const val TAG = "AudioPushSession"

        /** PES stream_id for the audio elementary stream (matches captures). */
        private const val AUDIO_PID = 0x1100
    }

    private val running = AtomicBoolean(false)
    private var server: WfdRtspServer? = null
    private val muxer = TsMuxer(audioPid = AUDIO_PID)
    private var encoderThread: Thread? = null

    /** Presentation URI to advertise; valid once [start] has bound the socket. */
    @Volatile
    var presentationUri: String = ""
        private set

    /** The RTSP session that reached PLAY, if any. */
    @Volatile
    private var playingSession: WfdRtspServer.RtspSession? = null

    fun start() {
        if (!running.compareAndSet(false, true)) return
        val srv = WfdRtspServer(
            port = rtspPort,
            localIp = localIp,
            authKey = authKey,
            listener = object : WfdRtspServer.Listener {
                override fun onLog(message: String) = listener.onLog("rtsp: $message")

                override fun onClientConnected(remote: String) =
                    listener.onLog("speaker connected from $remote")

                override fun onPlay(sessionId: Int) {
                    listener.onLog("PLAY received (session $sessionId) -> starting audio")
                    // The audio is written by broadcastTs() on the next tick.
                }

                override fun onError(error: Throwable) {
                    Log.w(TAG, "rtsp error", error)
                    listener.onError(error)
                }
            }
        )
        server = srv
        srv.start()
        presentationUri = srv.presentationUri()
        listener.onLog("presentation URI: $presentationUri")
        listener.onPresentationUriReady(presentationUri)
    }

    /**
     * Encode [file] and stream it. Blocking; call on a worker thread.
     * Sends PAT/PMT/PCR up front, then one PES per access unit.
     */
    fun streamFile(file: File, encoder: AacLatmEncoder = AacLatmEncoder(file)) {
        val srv = server ?: return
        // PSI first so a receiver can lock on immediately.
        srv.broadcastTs(muxer.buildPat())
        srv.broadcastTs(muxer.buildPmt())
        srv.broadcastTs(muxer.buildPcrPacket())

        encoder.encode(object : AacLatmEncoder.Listener {
            private var lastPcrMicros = 0L

            override fun onAccessUnit(data: ByteArray, ptsMicros: Long) {
                // Refresh PCR roughly every 40 ms.
                if (ptsMicros - lastPcrMicros > 40_000) {
                    muxer.setPcrMicros(ptsMicros)
                    srv.broadcastTs(muxer.buildPcrPacket())
                    lastPcrMicros = ptsMicros
                }
                srv.broadcastTs(muxer.muxAccessUnit(data, ptsMicros))
            }

            override fun onLog(message: String) = listener.onLog("encoder: $message")
            override fun onComplete() = listener.onLog("stream finished")
            override fun onError(error: Throwable) = listener.onError(error)
        })
    }

    fun stop() {
        running.set(false)
        try { encoderThread?.interrupt() } catch (_: Throwable) {}
        server?.stop()
        server = null
    }
}
