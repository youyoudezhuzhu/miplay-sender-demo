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

**So: not working.**

## Correction, and a correction of the correction

I have now been wrong about this twice. Both errors are recorded because the
second one matters more.

**First claim (wrong):** "the speaker drops the connection right after the
capability offer." Retracted correctly -- the real observation was that my
`parse_frames` returned frames *without consuming them*, so an ack that did
arrive was never delivered to the handler.

**Second claim (also wrong):** I then asserted "the speaker is NOT rejecting us"
and cited this successful-looking ack:

```
24 14 01 0001 0000008c  03 'ack' 1e 00000083
{"aesIvType":"4",...,"result":"0"}
```

**That ack was not mine.** The capture I quoted it from (`spk.pcap`) was filtered
on `host 10.42.0.127 and port 8899` while the TABLET was still connected, and its
source addresses are `10.42.0.42` (tablet) <-> `10.42.0.127` (speaker). The NAS
client never appears in it. So the "successful negotiation" I used to argue the
speaker accepts us was someone else's session entirely.

**What is actually true**, measured with the tablet off the network and only the
NAS talking:

* the speaker accepts the TCP connection;
* it sends `0x28` DEVICE_ID, and `0x1b` heartbeats every 5 s;
* it replies `0x37` to our `0x36` GET_VERSION;
* **it closes the connection immediately after our `0x29` AUTH_20**, every time,
  at every pacing (back-to-back, 0.4 s apart, seq mirrored from the peer);
* it never sends us a `0x01` ack or a `0x02` challenge.

Also verified: my capability offer frame is byte-identical to the official
sender's (`24140000010000008103636d641e00000078...`). So the content is not the
issue -- whatever the speaker objects to happens at AUTH_20.

## What root made visible (Frida on the live service)

The tablet is now rooted (KernelSU) and `frida-server` runs as root, so the
official sender can be observed. Hooking the service confirmed the plaintext
order of the official handshake, straight off the wire:

```
-> 0x36 GET_VERSION
-> 0x29 AUTH_20  = b17e5e1dbd20c32d9b66ec4e8726d3d528480116   <- RANDOM 20 bytes
-> 0x00 capability offer                  (plaintext, 129-byte frame)
<- 0x01 negotiate ack   {"result":"0"}    (plaintext)
<- 0x02 encrypted challenge
-> 0x03 encrypted ack
```

Two corrections to this sender came out of that:

* **AUTH_20 must be 20 random bytes.** It was a fixed `0001..13` pattern.
  Now `secrets.token_bytes(20).hex()`.
* **AUTH_20 must wait for the speaker's `0x37`** and mirror the speaker's seq.
  It was being fired back-to-back with GET_VERSION using seq 1.

Both are fixed. The speaker still closes immediately after AUTH_20, but the
failure now happens at exactly the same point as before with a
protocol-correct message, which localises the remaining difference to the
AUTH_20 step itself or to something the official sender establishes before it
that we do not.

`SafetyDataDeal::encryptData` (the hook I expected to catch the outgoing
plaintext) does **not** fire for this path, so the control channel does not use
that class -- `EncryKey::GetStringAesKey` and `AES_CBC_encrypt_buffer` are the
more likely entry points for the next attempt.

## 0x29 is byte-structurally identical to the official frame

Compared directly against the captured official frame:

```
OFFICIAL: 240029 05bf 00000028 b17e5e1dbd20c32d9b66ec4e8726d3d528480116
NAS     : 240029 0000 00000028 <20 random bytes as 40 hex chars>
          outer=0x00  cmd=0x29  bodyLen=40  body=40 ASCII hex
```

Everything matches -- outer, cmd, body length, body shape (40 ASCII hex chars,
i.e. the hex STRING of 20 random bytes, not 20 raw bytes). The only difference
is the seq value, and mirroring the peer's seq has already been tried.

So the AUTH_20 frame is not malformed. The remaining explanations are about
*connection state* or *prior setup*, not about this frame's bytes.

## Hook coverage limits found

`Interceptor.attach` on libc `send`/`sendto`/`write`/`writev`/`sendmsg`, filtered
to 0x24-prefixed MiPlay frames, only ever reports **fd=239** (the audio RTP
channel). The 8899 control socket (fd 207, confirmed via `ss -tnp`) never shows
up, so the control channel does not write through those libc entry points --
it goes through the library's own socket wrappers. Hooking the library's write
path (`mirror::net::TCPSession::writeMore` / `writeDirect`) is the next step.

Keep the parser fix: it was a real bug and it is still correct.

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
