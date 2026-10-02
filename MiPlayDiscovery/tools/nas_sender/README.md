# NAS MiPlay sender

A third-party MiPlay sender that runs on the NAS itself and pushes audio to a
Xiaomi speaker over the hotspot. This exists to answer one question:

> **Can a third-party sender reproduce a MiPlay session from scratch?**

It does not use the tablet at all.

## Status (honest)

| Step | State |
| --- | --- |
| generate our own authKey / streamKey / streamIV | ✅ works |
| connect to the speaker's 8899 port | ✅ works |
| plaintext handshake (DEVICE_ID / version) | ✅ works — the speaker replies |
| send GET_VERSION / AUTH_20 | ✅ accepted |
| capability offer (byte-exact copy of the official sender) | ⚠️ speaker drops the connection right after |
| encrypted SAFETY_AUTH exchange | ❌ never reached |
| setMirrorKey + `wfd://` hand-off | ❌ never reached |
| RTSP server + audio stream | implemented, never exercised |

**So: not working yet.** The speaker accepts a third-party connection and the
first two handshake messages, then closes once the capability offer goes out.

## What is already proven

The 8899 control channel cipher is fully cracked and cross-verified — see
`../../../reports/MIPLAY_CMD_KEY_LIFECYCLE_V6.md`:

```
key      = authKey   (uuid[:16], ASCII)
IV(1st)  = authKey
IV(next) = last 16 bytes of previous ciphertext
AES-128-CBC, zero padding, per-direction chain
```

`tests/test_wire.py` and `tests/test_tsmux.py` pin this and the MPEG-TS layout.

## Files

| File | Purpose |
| --- | --- |
| `wire.py` | frame format, AES control cipher, `authMsgAck`, capability blob |
| `tsmux.py` | MPEG-TS muxer producing the captured 12-byte private header + PES |
| `rtsp.py` | WFD RTSP server the speaker dials into |
| `sender.py` | orchestrates the whole session |

## Run

```bash
python3 -m tests.test_wire
python3 -m tests.test_tsmux

# encode the sample and push it
ffmpeg -i ../../../sample-55s.mp3 -c:a aac -b:a 128k -f adts /tmp/a.aac
python3 sender.py --speaker <speaker-ip> --bind <our-ip> --rtsp-port 33071 --aac /tmp/a.aac
```

## Next step to close it

The speaker drops the connection right after the capability offer. Diagnose by
capturing the bytes it sends before closing (`tcpdump` on the 8899 flow during a
run) and comparing byte-for-byte with the official exchange, which is fully
decoded in `MIPLAY_CMD_KEY_LIFECYCLE_V6.md`. Also free the speaker first — the
tablet keeps a half-open 8899 session that appears to make the speaker reject
new senders.
