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
| capability offer (byte-exact copy of the official sender) | ✅ verified byte-identical to the official frame |
| encrypted SAFETY_AUTH exchange | ⚠️ the speaker DOES send its challenge; our reply path is untested end to end |
| setMirrorKey + `wfd://` hand-off | ❌ never reached (connection times out first) |
| RTSP server + audio stream | implemented, never exercised |

**So: still not working, but the earlier diagnosis was wrong.**

## Correction: the speaker is not rejecting us

An earlier revision of this file claimed the speaker "drops the connection right
after the capability offer". **That was wrong, and it was my bug.** In one run
the speaker plainly sent a successful negotiation ack:

```
24 14 01 0001 0000008c  03 'ack' 1e 00000083
{"aesIvType":"4","aesKeyType":"4","authAlgorithmType":"4",
 "authKeyType":"2","integrityType":"1","result":"0"}
```

`result: "0"` means success. The cause was `parse_frames`, which returned frames
**without consuming them**, so every already-decoded frame was re-parsed on the
next `recv()` and the ack never reached the handler. Fixed: the parser now
consumes what it parses.

## The real blocker now: a 3-second idle timeout

Measured directly: connect, stay completely silent, and the speaker closes the
socket after **3.0 s**. So this is a keepalive/pacing requirement, not a
protocol rejection. The official sender interleaves messages quickly enough to
stay inside that window; this sender currently does not.

Measured sequence-number behaviour (the speaker's `0x28` carries a high seq such
as 1464, and its replies use seq 0):

```
<- 0x28 DEVICE_ID      seq=1464
-> 0x36 GET_VERSION    seq=0        <- speaker then replies 0x37
<- 0x37 version        seq=0
   [EOF ~3s]
```

Next step: drive the handshake without idle gaps inside the 3s window (and/or
send heartbeats), then observe the `0x01` ack and the encrypted `0x02`
challenge. The challenge reply path is already implemented
(`_on_challenge` -> `HMAC-SHA256(authKey, authMsg)`).

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
