package com.fusionplay.miplay.sender.media

import android.media.MediaCodec
import android.media.MediaCodecInfo
import android.media.MediaExtractor
import android.media.MediaFormat
import android.util.Log
import java.io.File
import java.nio.ByteBuffer

/**
 * Encodes a local audio file to raw **AAC-LATM** access units, ready for
 * [TsMuxer] and [WfdRtspServer].
 *
 * Pipeline: `MediaExtractor` (MP3) -> `MediaCodec` AAC encoder -> raw AUs.
 *
 * The MiPlay sender advertises `wfd_audio_codecs_v2: 63 3 3` and negotiates
 * `audio/mp4a-latm`, so the encoder output is requested as
 * `MediaFormat.MIMETYPE_AUDIO_AAC` with an AAC **LATM/LOAS** profile where the
 * device supports it. Output from `MediaCodec` for AAC is normally ADTS-framed
 * when `aac-profile` is ADTS; for LATM the codec emits raw AUs and the stream
 * must carry the AudioSpecificConfig in the TS PMT descriptor, or be wrapped in
 * LOAS framing. [prependAdts] controls which of the two shapes is produced.
 *
 * ## Verification status
 * The full TS/PES layout this feeds *is* verified against captures
 * (`TsMuxerTest`). The **encoder-side framing still needs on-device validation**
 * against a real speaker, because the captured elementary stream could not be
 * positively identified offline as ADTS or LOAS.
 */
class AacLatmEncoder(
    private val inputFile: File,
    /** Emit ADTS headers (0xFFF1…) instead of bare LATM access units. */
    private val prependAdts: Boolean = true,
    private val bitRate: Int = 128_000,
    private val sampleRate: Int = 48_000,
    private val channelCount: Int = 2
) {

    interface Listener {
        fun onAccessUnit(data: ByteArray, ptsMicros: Long)
        fun onLog(message: String)
        fun onComplete()
        fun onError(error: Throwable)
    }

    companion object {
        private const val TAG = "AacLatmEncoder"
        private const val TIMEOUT_US = 10_000L

        /** AAC-LATM object type as used by WFD (`audio/mp4a-latm`). */
        const val AOT_AAC_LC = 2

        /** ADTS sampling frequency index table. */
        val ADTS_FREQ = intArrayOf(
            96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050,
            16000, 12000, 11025, 8000, 7350
        )
    }

    /** Optional codec-specific config (AudioSpecificConfig) for the PMT descriptor. */
    @Volatile
    var audioSpecificConfig: ByteArray? = null
        private set

    /**
     * Decode + encode the whole file synchronously, invoking [listener] per AU.
     * Blocking; run this on a worker thread.
     */
    fun encode(listener: Listener) {
        var extractor: MediaExtractor? = null
        var codec: MediaCodec? = null
        try {
            extractor = MediaExtractor().apply { setDataSource(inputFile.absolutePath) }

            // ---- locate the first audio track ----------------------------------
            var trackIndex = -1
            var inFormat: MediaFormat? = null
            for (i in 0 until extractor.trackCount) {
                val f = extractor.getTrackFormat(i)
                if (f.getString(MediaFormat.KEY_MIME)?.startsWith("audio/") == true) {
                    trackIndex = i; inFormat = f; break
                }
            }
            if (trackIndex < 0 || inFormat == null) {
                listener.onError(IllegalArgumentException("no audio track in ${inputFile.name}"))
                return
            }
            extractor.selectTrack(trackIndex)
            val srcRate = inFormat.getInteger(MediaFormat.KEY_SAMPLE_RATE)
            val srcCh = inFormat.getInteger(MediaFormat.KEY_CHANNEL_COUNT)
            listener.onLog("input: ${inFormat.getString(MediaFormat.KEY_MIME)} ${srcRate}Hz ${srcCh}ch")

            // ---- configure the AAC encoder -------------------------------------
            val outFormat = MediaFormat.createAudioFormat(
                MediaFormat.MIMETYPE_AUDIO_AAC, sampleRate, channelCount
            ).apply {
                setInteger(MediaFormat.KEY_AAC_PROFILE,
                    MediaCodecInfo.CodecProfileLevel.AACObjectLC)
                setInteger(MediaFormat.KEY_BIT_RATE, bitRate)
                setInteger(MediaFormat.KEY_MAX_INPUT_SIZE, 64 * 1024)
            }
            codec = MediaCodec.createEncoderByType(MediaFormat.MIMETYPE_AUDIO_AAC)
            codec.configure(outFormat, null, null, MediaCodec.CONFIGURE_FLAG_ENCODE)
            codec.start()
            listener.onLog("encoder: ${codec.name} -> ${sampleRate}Hz ${channelCount}ch ${bitRate}bps")

            val bufferInfo = MediaCodec.BufferInfo()
            var sawInputEos = false
            var sawOutputEos = false
            var outPtsUs = 0L
            var auCount = 0

            while (!sawOutputEos) {
                // ---- feed input ------------------------------------------------
                if (!sawInputEos) {
                    val inIdx = codec.dequeueInputBuffer(TIMEOUT_US)
                    if (inIdx >= 0) {
                        val inBuf: ByteBuffer = codec.getInputBuffer(inIdx)!!
                        val size = extractor.readSampleData(inBuf, 0)
                        if (size < 0) {
                            codec.queueInputBuffer(inIdx, 0, 0, 0, MediaCodec.BUFFER_FLAG_END_OF_STREAM)
                            sawInputEos = true
                        } else {
                            codec.queueInputBuffer(inIdx, 0, size, extractor.sampleTime, 0)
                            extractor.advance()
                        }
                    }
                }

                // ---- drain output ---------------------------------------------
                val outIdx = codec.dequeueOutputBuffer(bufferInfo, TIMEOUT_US)
                when {
                    outIdx == MediaCodec.INFO_OUTPUT_FORMAT_CHANGED -> {
                        val f = codec.outputFormat
                        if (f.containsKey("csd-0")) {
                            audioSpecificConfig = f.getByteBuffer("csd-0")?.let { bb ->
                                ByteArray(bb.remaining()).also { bb.get(it) }
                            }
                            listener.onLog("AudioSpecificConfig: " +
                                (audioSpecificConfig?.joinToString("") { "%02x".format(it) } ?: "-"))
                        }
                    }
                    outIdx >= 0 -> {
                        val outBuf = codec.getOutputBuffer(outIdx)!!
                        if (bufferInfo.size > 0) {
                            val au = ByteArray(bufferInfo.size)
                            outBuf.position(bufferInfo.offset)
                            outBuf.limit(bufferInfo.offset + bufferInfo.size)
                            outBuf.get(au)
                            val framed = if (prependAdts) withAdts(au) else au
                            listener.onAccessUnit(framed, outPtsUs)
                            outPtsUs += (1024L * 1_000_000L) / sampleRate   // 1024 samples/AU
                            auCount++
                        }
                        codec.releaseOutputBuffer(outIdx, false)
                        if (bufferInfo.flags and MediaCodec.BUFFER_FLAG_END_OF_STREAM != 0) {
                            sawOutputEos = true
                        }
                    }
                }
            }
            listener.onLog("encoded $auCount access units")
            listener.onComplete()
        } catch (t: Throwable) {
            Log.w(TAG, "encode failed", t)
            listener.onError(t)
        } finally {
            try { codec?.stop() } catch (_: Throwable) {}
            try { codec?.release() } catch (_: Throwable) {}
            try { extractor?.release() } catch (_: Throwable) {}
        }
    }

    /**
     * Wrap one AAC AU in an ADTS header.
     *
     * ADTS layout (7 bytes, no CRC):
     * ```
     * FF F1                  syncword + MPEG-4 + layer 0 + no CRC
     * 5x                     profile(2) + sampling_frequency_index(4) + private(1)
     * 8x                     channel_config(3) + ...
     * xx                     ...
     * FF                     buffer fullness
     * FC                     number of AAC frames - 1
     * ```
     */
    private fun withAdts(au: ByteArray): ByteArray {
        val freqIndex = ADTS_FREQ.indexOf(sampleRate).let { if (it < 0) 3 else it }
        val chanCfg = channelCount
        val frameLen = au.size + 7
        val hdr = ByteArray(7)
        hdr[0] = 0xFF.toByte()
        hdr[1] = 0xF1.toByte()                                    // MPEG-4, no CRC
        hdr[2] = (((AOT_AAC_LC - 1) shl 6) or (freqIndex shl 2) or ((chanCfg shr 2) and 1)).toByte()
        hdr[3] = (((chanCfg and 3) shl 6) or ((frameLen shr 11) and 0x03)).toByte()
        hdr[4] = ((frameLen shr 3) and 0xFF).toByte()
        hdr[5] = (((frameLen and 7) shl 5) or 0x1F).toByte()
        hdr[6] = 0xFC.toByte()
        return hdr + au
    }
}
