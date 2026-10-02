#!/usr/bin/env python3
# RETRACTED ORACLE: the zero-padding 'padok' test below is NOT a valid
# key oracle and previously yielded a false KEY OK. Key/IV for the 8899
# control channel remain UNCONFIRMED. See MIPLAY_VERIFIED_FINDINGS_V7.md.
"""verify_live.py -- validate the MiPlay control-channel crypto against a LIVE session.

Reads the session keys from a logcat dump (as the official SDK prints them) and a
pcap of the tablet<->speaker 8899 conversation, then proves the decryption by the
zero-padding oracle. A wrong key gives ~0 valid frames.

Usage: verify_live.py <logcat.txt> <capture.pcap>
"""
import struct, subprocess, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from miplay_keys import parse_encrypted, keys_from_logcat

def main():
    log, pcap = sys.argv[1], sys.argv[2]
    keys, notes = keys_from_logcat(open(log, errors='replace').read())
    for n in notes: print('# ' + n)
    if not keys.get('authKey') or not keys.get('streamIV'):
        print('!! need authKey + streamIV in the log'); return 2
    K, IV = keys['authKey'], keys['streamIV']
    print('# control key (authKey) = %r' % K)
    print('# control IV  (streamIV)= %r' % IV)

    out = subprocess.run(['tshark', '-r', pcap, '-T', 'fields',
                          '-e', 'tcp.srcport', '-e', 'tcp.payload'],
                         capture_output=True, text=True)
    st = {}
    for line in out.stdout.splitlines():
        p = line.split('\t')
        if len(p) < 2 or not p[1].strip(): continue
        try: raw = bytes.fromhex(p[1].replace(':', ''))
        except ValueError: continue
        st.setdefault(p[0], bytearray()).extend(raw)

    total_ok = total = 0
    for sp, buf in sorted(st.items()):
        frames = []; i = 0
        while i + 9 <= len(buf):
            if buf[i] != 0x24: i += 1; continue
            blen = struct.unpack('>I', buf[i + 5:i + 9])[0]
            if i + 9 + blen > len(buf) or blen > (1 << 22): i += 1; continue
            b = bytes(buf[i + 9:i + 9 + blen])
            p = parse_encrypted(b)
            if p: frames.append((buf[i + 2], struct.unpack('>H', buf[i + 3:i + 5])[0], p))
            i += 9 + blen
        iv = None; ok = tot = 0
        for cmd, seq, p in frames:
            if iv and p[3] and len(p[3]) % 16 == 0:
                pt = Cipher(algorithms.AES(K), modes.CBC(iv)).decryptor().update(p[3])
                tot += 1
                if pt.endswith(b'\x00' * p[1]):
                    ok += 1
                    body = pt[:len(pt) - p[1]]
                    if body:
                        print('   dir %s seq=%-4d cmd=0x%02x %r' % (sp, seq, cmd, body[:100]))
            if p[3]: iv = p[3][-16:]
        print('dir %s: padok %d/%d' % (sp, ok, tot))
        total_ok += ok; total += tot
    # WARNING: this padok oracle is UNSOUND as a key test and produced a
        # false 'KEY OK' historically. It assumes a specific framing/chaining
        # model that does not hold. Do NOT treat a high padok rate as proof.
        verdict = 'ORACLE-UNSOUND (see reports/MIPLAY_VERIFIED_FINDINGS_V7.md)'
    print('\nTOTAL %d/%d  -> %s' % (total_ok, total, verdict))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
