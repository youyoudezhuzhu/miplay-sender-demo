#!/usr/bin/env python3
# RETRACTED ORACLE: the zero-padding 'padok' test below is NOT a valid
# key oracle and previously yielded a false KEY OK. Key/IV for the 8899
# control channel remain UNCONFIRMED. See MIPLAY_VERIFIED_FINDINGS_V7.md.
"""mp_full_decrypt.py -- end-to-end MiPlay 8899 control-channel decryption.

Given the sender's *authKey* (the first 16 characters of the UUID the SDK logs
in `Cir_Miplay_UUIDGenerator: uuid:<32hex>`), this decrypts the whole control
channel and prints every plaintext frame, extracting the media keys that the
sender pushes in SET_MIRROR_KEY (0x6c).

Cipher (verified end-to-end against live traffic):
    AES-128-CBC, key = authKey, IV = streamIV
    free-running chain: IV for the next block = last 16 bytes of previous ct
    zero padding: pad = 16 - (len % 16), 1..16
Wire:
    '$' | outer:u8 | cmd:u8 | seq:u16be | body_len:u32be | body
    body = 00 07 01 e0 | flags:u8 | pad:u8 | crc32be(ct) | ct

Usage:
    mp_full_decrypt.py <pcap> <tcp-stream-index> <authKey16> [--json]
    mp_full_decrypt.py live  <iface>  <authKey16>          # capture then decode
"""
import json
import re
import struct
import subprocess
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from miplay_keys import crc32_be, MAGIC

SET_MIRROR_KEY = 0x6C


# ------------------------------------------------------------------ capture
def follow_stream(pcap, stream):
    """Reassemble both directions of a TCP stream via tshark."""
    out = subprocess.run(['tshark', '-r', pcap, '-q', '-z',
                          'follow,tcp,raw,%d' % stream], capture_output=True, text=True)
    dirs = {0: bytearray(), 1: bytearray()}
    cur = None
    for line in out.stdout.splitlines():
        if line.startswith('Node') or line.startswith('=') or \
           line.startswith('Follow') or line.startswith('Filter') or not line.strip():
            continue
        if line.startswith('\t'):
            cur, h = 1, line.strip()
        else:
            cur, h = 0, line.strip()
        try:
            dirs[cur] += bytes.fromhex(h)
        except ValueError:
            pass
    return dirs


def split_frames(buf):
    out, i = [], 0
    while i + 9 <= len(buf):
        if buf[i] != 0x24:
            i += 1
            continue
        cmd = buf[i + 2]
        seq = struct.unpack('>H', buf[i + 3:i + 5])[0]
        blen = struct.unpack('>I', buf[i + 5:i + 9])[0]
        if i + 9 + blen > len(buf) or blen > (1 << 22):
            i += 1
            continue
        out.append((cmd, seq, bytes(buf[i + 9:i + 9 + blen])))
        i += 9 + blen
    return out


# ------------------------------------------------------------------ decrypt
def decrypt_direction(buf, key, verbose=True):
    """Decrypt one direction.

    Returns (frames, padok, checked) where frames is a list of
    (cmd, seq, plaintext, crc_ok, pad_ok).  pad_ok is the self-check: the
    decrypted tail must be `pad` zero bytes.  A wrong key yields ~0 padok.
    """
    res = []
    iv = None
    padok = checked = 0
    for cmd, seq, body in split_frames(buf):
        if len(body) < 9 or body[:4] != MAGIC:
            if verbose and body:
                res.append((cmd, seq, body, True, True))   # plaintext frame
            continue
        flags = body[3]
        pad = body[4] if flags & 0x40 else 0
        stored = struct.unpack('>I', body[5:9])[0]
        ct = body[9:]
        crc_ok = (crc32_be(ct) == stored)
        if iv is not None and ct and len(ct) % 16 == 0:
            pt = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor().update(ct)
            plain = pt[:len(pt) - pad] if pad else pt
            ok = bool(pad) and pt.endswith(b'\x00' * pad)
            checked += 1
            padok += ok
            res.append((cmd, seq, plain, crc_ok, ok))
        if ct:
            iv = ct[-16:]
    return res, padok, checked


def extract_media_keys(frames):
    """Pull the SET_MIRROR_KEY JSON payloads out of decrypted frames."""
    found = []
    for cmd, seq, plain, _, _ok in frames:
        if cmd == SET_MIRROR_KEY and plain.startswith(b'{'):
            try:
                found.append((seq, json.loads(plain.decode('utf-8', 'replace'))))
            except Exception:
                pass
    return found


def printable(b):
    return ''.join(chr(c) if 32 <= c < 127 else '.' for c in b)


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        return 1
    if sys.argv[1] == 'live':
        iface, key = sys.argv[2], sys.argv[3].encode()
        pcap = '/tmp/mp_live_decrypt.pcap'
        print('# capturing on %s (Ctrl-C to stop)...' % iface)
        subprocess.run(['tcpdump', '-i', iface, '-s', '0', '-U', '-w', pcap,
                        'tcp port 8899'])
        stream = 0
    else:
        pcap, stream, key = sys.argv[1], int(sys.argv[2]), sys.argv[3].encode()
    assert len(key) == 16, 'authKey must be 16 ASCII bytes'
    as_json = '--json' in sys.argv
    dirs = follow_stream(pcap, stream)
    allkeys = []
    for k in (0, 1):
        frames, padok, checked = decrypt_direction(dirs[k], key)
        # WARNING: this padok oracle is UNSOUND as a key test and produced a
        # false 'KEY OK' historically. It assumes a specific framing/chaining
        # model that does not hold. Do NOT treat a high padok rate as proof.
        verdict = 'ORACLE-UNSOUND (see reports/MIPLAY_VERIFIED_FINDINGS_V7.md)'
        print('\n========== direction %d (%d frames) ==========' % (k, len(frames)))
        print('  self-check: %d/%d frames had a valid zero-pad tail  -> %s'
              % (padok, checked, verdict))
        for cmd, seq, plain, crc_ok, ok in frames:
            if not plain or not ok:
                continue
            tag = '' if crc_ok else ' [CRC?]'
            print('  seq=%-5d cmd=0x%02x%s  %s' % (seq, cmd, tag, printable(plain)[:150]))
        allkeys += extract_media_keys(frames)
    if allkeys:
        print('\n########## MEDIA KEYS (from SET_MIRROR_KEY 0x6c) ##########')
        for seq, d in allkeys:
            print('  seq=%-5d %s' % (seq, json.dumps(d, ensure_ascii=False)))
        last = allkeys[-1][1]
        if as_json:
            print(json.dumps(last))
        else:
            print('\n# audio channel: AES-128-CBC key=%s iv=%s'
                  % (last.get('streamKey'), last.get('streamIV')))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
