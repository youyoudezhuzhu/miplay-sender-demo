#!/usr/bin/env python3
"""MiPlay NAS sender, part 4: end-to-end audio push.

Purpose: answer the real question - can a THIRD-PARTY sender reproduce a MiPlay
session from scratch? This runs entirely on the NAS and drives a real speaker.

Sequence (every step taken from a decoded live session; see
reports/MIPLAY_CMD_KEY_LIFECYCLE_V6.md and MIPLAY_AUDIO_PUSH_PROTOCOL.md §7):

  1. generate our own authKey / streamKey / streamIV  (uuid4 hex, first 16 chars)
  2. start the RTSP server, learn its port
  3. connect to the speaker's 8899 control port
  4. plaintext handshake: DEVICE_ID / GET_VERSION / AUTH_20 / capability offer
  5. encrypted SAFETY_AUTH exchange (challenge-response)
  6. cmd 0x6c  setMirrorKey   {wlan0ip, authKey, streamKey, streamIV}
  7. cmd 0x00  wfd://<our-ip>:<rtsp-port>?mirrorMode=1
  8. the speaker dials our RTSP port; answer OPTIONS with authMsgAck
  9. on PLAY, stream the sample audio as interleaved MPEG-TS
"""
import argparse
import json
import secrets
import socket
import struct
import sys
import threading
import time

sys.path.insert(0, __file__.rsplit('/', 1)[0])

from wire import (ControlCipher, frame, parse_frames, tlv, gen_key,
                  CMD_AUTH20, CMD_GET_VERSION, CMD_SAFETY_AUTH,
                  CMD_SAFETY_AUTH_ACK, CMD_OPEN, CMD_WRAPPER,
                  CMD_SET_MIRROR_KEY, CMD_MEDIA_INFO)
from rtsp import RtspServer
from tsmux import TsMuxer, interleave

SENDER_VERSION = '2.1.4111518'
CTRL_PORT = 8899


class NasSender:
    def __init__(self, speaker_ip, bind_ip, rtsp_port=0, log=print):
        self.speaker_ip = speaker_ip
        self.bind_ip = bind_ip
        self.log = log
        self.auth_key = gen_key()
        self.stream_key = gen_key()
        self.stream_iv = gen_key()
        self.cipher = ControlCipher(self.auth_key)
        self.sock = None
        self.seq = 0
        self.rx = bytearray()
        self.device_id = None
        self.auth_msg = None
        self.rtsp = RtspServer(bind_ip, rtsp_port, self.auth_key, log=log)
        self.muxer = TsMuxer()
        self._lock = threading.Lock()
        self.negotiated = None
        self.mode_seen = False
        self.peer_seq = 0
        self.speaker_version = None

    # ------------------------------------------------------------------ send
    def send(self, cmd, body, outer=0, plain=False, seq=None):
        with self._lock:
            if seq is None:
                self.seq = (self.seq + 1) & 0xFFFF
                seq = self.seq
            payload = body if plain else self.cipher.encrypt(body)
            pkt = frame(cmd, seq, payload, outer=outer)
            self.sock.sendall(pkt)
            self.log('[ctrl] -> cmd=0x%02x seq=%d %slen=%d %r'
                     % (cmd, seq, 'PLAIN ' if plain else 'ENC ', len(body),
                        body[:70]))

    def send_wrapper(self, key, payload):
        self.send(CMD_WRAPPER, tlv(key, payload), outer=CMD_WRAPPER)

    # ---------------------------------------------------------------- receive
    def pump(self, stop: threading.Event):
        self.sock.settimeout(1.0)
        while not stop.is_set():
            try:
                data = self.sock.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                break
            if not data:
                break
            self.rx += data
            for outer, cmd, seq, body in parse_frames(self.rx):
                self.handle(outer, cmd, seq, body)

    def handle(self, outer, cmd, seq, body):
        if body[:4] == b'\x00\x07\x01\xe0':
            pt = self.cipher.decrypt(body)
            tag = 'ENC '
        else:
            pt = body
            tag = 'PLAIN'
        if cmd == 0x28:
            self.device_id = pt.decode('ascii', 'replace').rstrip('\x00')
            self.peer_seq = seq
            self.log('[ctrl] <- 0x28 DEVICE_ID %s (peer seq=%d)' % (self.device_id, seq))
        elif cmd == 0x37:
            self.speaker_version = pt
            self.log('[ctrl] <- 0x37 speaker version %r' % pt[:24])
        elif cmd == 0x22:
            self.mode_seen = True
            self.log('[ctrl] <- 0x22 %r' % pt[:40])
        elif cmd == CMD_SAFETY_AUTH:
            self._on_challenge(pt)
        elif cmd == 0x01:
            self.negotiated = pt
            self.log('[ctrl] <- 0x01 negotiate ack %r' % pt[:160])
        else:
            self.log('[ctrl] <- cmd=0x%02x %s %r' % (cmd, tag, pt[:90]))

    def _on_challenge(self, pt):
        try:
            obj = json.loads(pt[pt.find(b'{'):].decode('utf-8', 'replace'))
            msg = obj.get('authMsg')
        except Exception:
            msg = None
        if not msg:
            return
        self.auth_msg = msg
        from wire import auth_msg_ack
        ack = auth_msg_ack(self.auth_key, msg)
        self.log('[ctrl]    challenge authMsg=%s' % msg)
        self.log('[ctrl]    computed authMsgAck=%s' % ack)
        self.send(CMD_SAFETY_AUTH_ACK,
                  tlv('ack', json.dumps({'authMsgAck': ack, 'result': '0'},
                                        separators=(',', ':'))),
                  outer=CMD_WRAPPER)

    # ------------------------------------------------------------- handshake
    def run(self, audio_path, loop=False):
        # 1. RTSP server (the speaker will dial us)
        self.rtsp.start()

        # 2. connect
        self.sock = socket.socket()
        self.sock.settimeout(15)
        self.sock.connect((self.speaker_ip, CTRL_PORT))
        self.log('[ctrl] connected to %s:%d' % (self.speaker_ip, CTRL_PORT))

        stop = threading.Event()
        threading.Thread(target=self.pump, args=(stop,), daemon=True).start()
        time.sleep(1.0)

        # 3. plaintext handshake, in the official order (verified from capture):
        #      -> GET_VERSION (seq 0), then WAIT for speaker 0x37
        #      -> AUTH_20 (20 RANDOM bytes as 40 hex), then WAIT for speaker 0x22
        #      -> capability offer (PLAINTEXT)
        # The official sender's AUTH_20 is random per session, e.g.
        #   b17e5e1dbd20c32d9b66ec4e8726d3d528480116
        self.send(CMD_GET_VERSION, (SENDER_VERSION + '\x00').encode(),
                  plain=True, seq=0)
        for _ in range(30):
            if self.speaker_version is not None:
                break
            time.sleep(0.1)
        self.log('[ctrl] speaker version seen=%s' % (self.speaker_version is not None))

        # Mirror the speaker's sequence number, as the real sender does.
        auth20 = secrets.token_bytes(20).hex().encode()
        self.send(CMD_AUTH20, auth20, plain=True, seq=self.peer_seq)
        # the speaker answers AUTH_20 with its 0x22 pair (mode/mediaInfoEx/state)
        for _ in range(30):
            if self.mode_seen:
                break
            time.sleep(0.1)
        self.log('[ctrl] speaker mode seen=%s' % self.mode_seen)

        offer = ('{\n'
                 '\t"aesIvTypes": "7",\n'
                 '\t"aesKeyTypes": "7",\n'
                 '\t"authAlgorithmTypes": "7",\n'
                 '\t"authKeyTypes": "3",\n'
                 '\t"integrityTypes": "1" \n'
                 '} \n')
        # The official sender emits this offer in the CLEAR.
        self.send(CMD_OPEN, tlv('cmd', offer), outer=CMD_WRAPPER, plain=True)

        # 4. tell the speaker where to dial, and with which keys
        self.send(CMD_SET_MIRROR_KEY, json.dumps({
            'wlan0ip': self.bind_ip, 'authKey': self.auth_key,
            'streamKey': self.stream_key,
            'streamIV': self.stream_iv}).encode('utf-8'))
        time.sleep(0.3)
        uri = 'wfd://%s:%d?mirrorMode=1' % (self.bind_ip, self.rtsp.port)
        self.send(CMD_OPEN, uri.encode())
        self.log('[ctrl] advertised %s' % uri)

        # 5. wait for the speaker to dial in and PLAY
        self.log('[main] waiting for the speaker to dial %s:%d ...'
                 % (self.bind_ip, self.rtsp.port))
        deadline = time.time() + 45
        while time.time() < deadline and not self.rtsp.playing.is_set():
            time.sleep(0.3)

        if not self.rtsp.playing.is_set():
            self.log('[main] NO PLAY within 45s - speaker did not start a stream')
            stop.set()
            return False

        self.log('[main] PLAY received - streaming audio')
        self.stream_audio(audio_path, loop=loop)
        stop.set()
        return True

    # ------------------------------------------------------------ audio push
    def stream_audio(self, path, loop=False):
        frames = load_adts(path)
        self.log('[main] %d AAC access units, %.1fs'
                 % (len(frames), len(frames) * 1024 / 44100.0))
        # PSI first
        for pkt in (self.muxer.build_pat(), self.muxer.build_pmt()):
            self.rtsp.send_interleaved(pkt)
        pts = 0
        last_pcr = -1
        n = 0
        while True:
            for au in frames:
                if not self.rtsp.playing.is_set() and n > 0:
                    return
                if pts - last_pcr > 40_000:
                    self.muxer.set_pcr_micros(pts)
                    self.rtsp.send_interleaved(self.muxer.build_pcr_packet())
                    last_pcr = pts
                self.rtsp.send_interleaved(self.muxer.mux_access_unit(au, pts))
                pts += (1024 * 1_000_000) // 44100
                n += 1
                if n % 50 == 0:
                    self.log('[main] sent %d AUs (%.1fs)'
                             % (n, n * 1024 / 44100.0))
                    time.sleep(0.0)
                # pace to real time
                target = n * 1024 / 44100.0
                now = time.time() - self._t0 if hasattr(self, '_t0') else 0
                if not hasattr(self, '_t0'):
                    self._t0 = time.time()
                drift = target - (time.time() - self._t0)
                if drift > 0.02:
                    time.sleep(min(drift, 0.05))
            if not loop:
                break
        self.log('[main] finished streaming %d AUs' % n)


def load_adts(path):
    """Split an ADTS AAC file into bare access units (strip 7-byte headers)."""
    data = open(path, 'rb').read()
    aus = []
    i = 0
    while i + 7 <= len(data):
        if data[i] != 0xFF or (data[i + 1] & 0xF0) != 0xF0:
            i += 1
            continue
        protection_absent = data[i + 1] & 1
        frame_len = ((data[i + 3] & 0x03) << 11) | (data[i + 4] << 3) | \
                    ((data[i + 5] >> 5) & 0x07)
        header = 7 if protection_absent else 9
        if frame_len < header or i + frame_len > len(data):
            i += 1
            continue
        aus.append(data[i + header:i + frame_len])
        i += frame_len
    return aus


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--speaker', required=True, help='speaker IP')
    ap.add_argument('--bind', required=True, help='our IP on the hotspot')
    ap.add_argument('--rtsp-port', type=int, default=33071)
    ap.add_argument('--aac', required=True, help='ADTS AAC file to stream')
    ap.add_argument('--loop', action='store_true')
    args = ap.parse_args()

    s = NasSender(args.speaker, args.bind, args.rtsp_port)
    print('authKey   =', s.auth_key)
    print('streamKey =', s.stream_key)
    print('streamIV  =', s.stream_iv)
    ok = s.run(args.aac, loop=args.loop)
    print('RESULT:', 'PLAYED' if ok else 'NO PLAY')
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
