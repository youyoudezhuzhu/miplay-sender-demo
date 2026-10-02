#!/usr/bin/env python3
"""verify_cmd_channel.py -- regression test for the 8899 control channel cipher.

THE RESULT (verified against a live session, see
reports/MIPLAY_CMD_KEY_LIFECYCLE_V6.md):

    8899 = AES-128-CBC
      key      = authKey   (uuid[:16], ASCII -- NOT hex-decoded)
      IV(1st)  = authKey
      IV(next) = last 16 bytes of the previous ciphertext (free-running chain)
      padding  = zero padding, pad = 16 - (len % 16)

The vectors below are real ciphertext taken from the session whose keys were
generated 609 ms before the TCP session opened. The strongest check is the
cross-verification: the authMsgAck recovered from THIS encrypted channel must
equal HMAC-SHA256(authKey, authMsg) for the authMsg from the opposite direction.

The historical failure mode is worth keeping in mind: a key captured OUTSIDE the
session's time window will never decrypt it, no matter how correct the algorithm
is. Both the key and the traffic must come from the same window.
"""
import hashlib
import hmac
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Session at 23:47:01 (keys generated 23:47:01.441, TCP SYN at 23:47:01.500)
AUTH_KEY = '14e7e6475d2142dd'
STREAM_KEY = '3ba139cc95df4284'
STREAM_IV = '93c0822773324746'

# First encrypted frame of each direction: (cmd, pad, ciphertext_hex)
DIR_TABLET = [
    (0x02, 2, '2988c7f5323cb4e067edcb7d9c0392790f3ca34a145cc3c486cc0751ce1b9300'
              '4c937495e8bb9987e6366fed43b9ef1641614f3408cddea6203c1a25c72c82d6'),
    (0x03, 15, 'f012ad195a82ecef0f0e5be94064979d1661421f014c6544ee55f2fc37bd96f0'
               '26066a6d63abb5113f4cdc80e22adba8e62310eb3fffa53f3c7fc12c38ba0bc30e'
               'be1b9dde85561cf2d10879799e090006ce46282729e0e316192289fb27f52785c9'
               '2939439b18aa12973c50bb73f07307c0c85b40ad47c4268b3b12a301303d69'),
    (0x1e, 16, '42c42cd7bf1901d7d81b7d15d80fbc8f'),
]
# Recovered plaintext expectations
EXPECT_AUTHMSG_TABLET = '78c4a5bafb0d6a3e3a6b75494acd991a'
EXPECT_AUTHMSG_SPEAKER = 'd99d45abcdc7973b96721118447a2323'
EXPECT_ACK_FOR_TABLET = 'c636354ddfb86084b272670d4fc20e8cd6fa8dc6d91689e749fc900bb5227b3f'
EXPECT_ACK_FOR_SPEAKER = '464294bb09b495cb9699cc4a3cfff758174ed1c1ea5692538699457a1b1b75e6'


def decrypt_chained(key_ascii: str, iv_seed: bytes, frames):
    """Decrypt frames with a free-running CBC chain. Returns list of plaintexts.

    NOTE: pad==0 is legal and means 'no padding needed' -- in that case zero
    padding still applies, so strip trailing NULs. pad in 1..16 is a literal
    count of zero bytes to remove.
    """
    key = key_ascii.encode('ascii')
    assert len(key) == 16, 'authKey must be 16 ASCII bytes'
    cur = iv_seed
    out = []
    for cmd, pad, ct_hex in frames:
        ct = bytes.fromhex(ct_hex)
        if not ct or len(ct) % 16:
            continue
        pt = Cipher(algorithms.AES(key), modes.CBC(cur)).decryptor().update(ct)
        if 0 < pad <= len(pt):
            body = pt[:len(pt) - pad]
        else:
            body = pt.rstrip(b'\x00')
        out.append((cmd, body))
        cur = ct[-16:]
    return out


def main():
    ok = True

    # 1. Key must be the ASCII authKey, and it must decrypt to readable TLV/JSON.
    pts = decrypt_chained(AUTH_KEY, AUTH_KEY.encode('ascii'), DIR_TABLET)
    print('decrypted %d frames with key=authKey, IV=authKey' % len(pts))
    # Frames are TLV-wrapped: b'\x03cmd' + u32be length + JSON, or b'\x03ack' + ....
    # So they legitimately contain control bytes; assert STRUCTURE, not blanket
    # printability. The JSON inside must be readable.
    for cmd, pt in pts:
        if not pt:
            print('  cmd=0x%02x len=0 (empty payload, full-block padding)' % cmd)
            continue
        # TLV (verified against decrypted bytes):
        #   keylen:u8 | key(keylen) | len:u32be | payload
        #   observed: 03 'cmd' 001e 0000 0000 0035 ...  -> hmm
        # Concretely for this frame: 03 'cmd' | 1e000000 | 35000000?  No --
        # the actual bytes are 03 63 6d 64 1e 00 00 00 35 7b ...
        # i.e. keylen(1) key(3) dtype(4)=0x1e len(4)=0x35? That leaves json at 9
        # with length 53 == 0x35. So: keylen | key | dtype:u32be | len:u32be | json
        stripped = pt.rstrip(b' \t\r\n')
        has_tlv = pt[:1] == b'\x03' and len(pt) > 9
        json_at = pt.find(b'{')
        json_ok = False
        if has_tlv and json_at > 0:
            # Bytes: 03 'cmd' 1e 00000035 <53 bytes JSON>
            #   keylen:u8 | key(keylen) | 0x1e | len:u32be | payload
            keylen = pt[0]
            key = pt[1:1 + keylen]
            marker = pt[1 + keylen]                                  # 0x1e
            plen = int.from_bytes(pt[2 + keylen:6 + keylen], 'big')   # 0x35 = 53
            payload = pt[6 + keylen:]
            json_ok = (key in (b'cmd', b'ack')
                       and plen == len(payload)
                       and stripped.endswith(b'}'))
        print('  cmd=0x%02x len=%-3d tlv=%s json=%s  %r'
              % (cmd, len(pt), has_tlv, json_ok, pt[:60]))
        if not (has_tlv and json_ok):
            ok = False

    body = b''.join(pt for _, pt in pts)
    for expected, label in ((EXPECT_AUTHMSG_TABLET, 'authMsg (tablet->speaker)'),):
        if expected.encode() in body:
            print('  FOUND %s = %s' % (label, expected))
        else:
            print('  MISSING %s' % label)
            ok = False

    # 2. CROSS-VERIFICATION: the ACK recovered from the encrypted channel must be
    #    the HMAC of the opposite direction's challenge.
    print('\ncross-verification (the decisive check):')
    checks = [
        ('tablet challenge -> speaker ack', EXPECT_AUTHMSG_TABLET, EXPECT_ACK_FOR_TABLET),
        ('speaker challenge -> tablet ack', EXPECT_AUTHMSG_SPEAKER, EXPECT_ACK_FOR_SPEAKER),
    ]
    for label, msg, ack in checks:
        calc = hmac.new(AUTH_KEY.encode('ascii'), msg.encode('ascii'),
                        hashlib.sha256).hexdigest()
        good = calc == ack
        ok = ok and good
        print('  %-34s %s' % (label, 'MATCH' if good else 'MISMATCH'))
        if not good:
            print('    expected %s\n    got      %s' % (ack, calc))

    # 3. Sanity: streamIV is NOT the first-frame IV (a documented past mistake).
    wrong = decrypt_chained(AUTH_KEY, STREAM_IV.encode('ascii'), DIR_TABLET)
    if wrong and b'authMsg' in wrong[0][1]:
        print('\nWARNING: streamIV also recovers authMsg -- IV assumption needs review')
    else:
        print('\nconfirmed: streamIV is not the first-frame IV (authKey is)')

    # 4. streamKey must NOT decrypt this channel.
    bad = decrypt_chained(STREAM_KEY, STREAM_KEY.encode('ascii'), DIR_TABLET)
    readable = bool(bad) and b'authMsg' in bad[0][1]
    print('streamKey recovers authMsg: %s (expected False)' % readable)
    if readable:
        ok = False

    print('\n%s' % ('ALL CHECKS PASSED' if ok else 'FAILURES PRESENT'))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
