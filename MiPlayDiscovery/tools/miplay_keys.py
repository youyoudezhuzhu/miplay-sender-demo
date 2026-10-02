#!/usr/bin/env python3
"""miplay_keys.py -- MiPlay control-channel key recovery and decryption harness.

WHY THIS EXISTS
---------------
Round 7 of the analysis established that the 8899 control channel is encrypted
with the *media* secrets and proved the sender's key derivation from
decompiled source.  This round closed the remaining gap: the keys are
generated with java.util.UUID.randomUUID() and therefore CANNOT be derived
from a packet capture.  They are, however, logged in cleartext by the
MiPlay SDK, and this script turns those log lines into working keys.

KEY CHAIN (all verified against decompiled source)
--------------------------------------------------
    ProtocolSession.getKey(which)                     [Java]
        b = new byte[16]
        System.arraycopy(UUIDGenerator.getUUID().getBytes(UTF_8), 0, b, 0, 16)
        return new String(b)          -> 16 ASCII chars, not hex-decoded
                |
                v
    MiplaySessionCtrProxy.setMirrorKey(json)  ->  CmdSessionControl.setMirrorKey  [JNI]
                |
                v
    mirror::CmdSource::setLyraInfo(json)       [libmirror-jni.so]
        "authKey"   -> CmdSource+0x360
        "streamKey" -> CmdSource+0x378
        "streamIV"  -> CmdSource+0x390
                |
                v
    mirror::CmdSource::onSessionConnect()      [libmirror-jni.so]
        SafetyKeyDeal+0x58 = CmdSource+0x360   (authKey)
        SafetyKeyDeal+0x70 = CmdSource+0x378   (streamKey)
        SafetyKeyDeal+0x88 = CmdSource+0x390   (streamIV)
                |
                v
    mirror::CmdSource::dealSafetyInfoAck()     [libmirror-jni.so]
        ack JSON gives aesKeyType / aesIvType   (observed: 4 / 4)
        genAesKey(str, 4) -> copy of SafetyKeyDeal+0x58  = authKey    <-- NOT streamKey!
        genAesIv (str, 4) -> copy of SafetyKeyDeal+0x88  = streamIV
        new SafetyDataDeal(1, integrityType, aesKey, aesIv)

    !! CORRECTED MAPPING (verified end-to-end on live traffic) !!
    SafetyKeyDeal+0x58 <- CmdSource+0x360 = "authKey"
    SafetyKeyDeal+0x70 <- CmdSource+0x378 = "streamKey"
    SafetyKeyDeal+0x88 <- CmdSource+0x390 = "streamIV"
    genAesKey(type 4) reads +0x58 => the CONTROL CHANNEL CIPHER KEY IS authKey.
    The streamKey/streamIV pair is what the sender pushes to the receiver in
    SET_MIRROR_KEY (0x6c) and is used for the AUDIO channel, not the control one.
                |
                v
    SafetyDataDeal::encryptData/decryptData    AES-128-CBC, zero padding
        wire body = 00 07 01 e0 | flags:u8 | pad:u8 | crc32be(ct) | ct

RECOVERY
--------
    adb logcat | grep -E 'UUIDGenerator|generatorMirrorKey'
      I/Cir_Miplay_ProtocolSession: generatorMirrorKey:
      I/Cir_Miplay_UUIDGenerator: uuid:<32hex>     <- authKey   (1st)
      I/Cir_Miplay_UUIDGenerator: uuid:<32hex>     <- streamKey (2nd)
      I/Cir_Miplay_UUIDGenerator: uuid:<32hex>     <- streamIV  (3rd)
      I/Cir_Miplay_ProtocolSession: toJson:authKey:XXXX ,streamKey:YYYY ,streamIV:ZZZZ

    The toJson line masks all but the last 4 characters; they MUST equal the
    last 4 characters of uuid[:16] for each key - use that to bind the three
    UUID lines to their roles (verified: 4bf9 / 4e7a / 45a5).
    Independent confirmation: the native layer logs its own masked copy of the
    JSON it sends, e.g.
      D/MiPlay CmdControl: setMirrorKey {"wlan0ip":"...","authKey":"****4bf9",...
"""
import re
import struct
import sys

# ------------------------------------------------------------------ integrity
def _table_entry(i):
    v = (i << 24) & 0xFFFFFFFF
    for _ in range(8):
        v = ((v << 1) ^ 0x04C1_1DB7) & 0xFFFFFFFF if v & 0x8000_0000 else (v << 1) & 0xFFFFFFFF
    return int.from_bytes(v.to_bytes(4, 'big'), 'little')


_TABLE = [_table_entry(i) for i in range(256)]


def crc32_be(data):
    """Byte-swapped CRC-32 (poly 0x04C11DB7), as logged/transmitted by MiPlay."""
    v = 0xFFFFFFFF
    for b in data:
        v = (_TABLE[(v & 0xFF) ^ b] ^ (v >> 8)) & 0xFFFFFFFF
    return v


# ------------------------------------------------------------------ key parse
KEY_LINE = re.compile(r'uuid:([0-9a-fA-F]{32})')
TOJSON = re.compile(r'toJson:authKey:(\w+)\s*,streamKey:(\w+)\s*,streamIV:(\w+)')
MIRROR_JSON = re.compile(r'setMirrorKey\s+(\{.*)$')


def keys_from_logcat(text):
    """Parse a logcat dump into {authKey, streamKey, streamIV} 16-byte ASCII keys.

    Returns (keys, notes).  keys values are the 16-byte ASCII key material
    exactly as the SDK uses it (NOT hex-decoded).
    """
    notes = []
    uuids = KEY_LINE.findall(text)
    tail = TOJSON.search(text)
    masked = None
    if tail:
        masked = {'authKey': tail.group(1)[-4:], 'streamKey': tail.group(2)[-4:],
                  'streamIV': tail.group(3)[-4:]}
        notes.append('toJson masked tails: %s' % masked)
    # also accept the native masked JSON as a fallback
    if not masked:
        m = re.search(r'authKey":"\*+(\w{4})', text)
        if m:
            masked = {'authKey': m.group(1)}
            notes.append('native masked authKey tail: %s' % m.group(1))
    out = {}
    pools = list(uuids)
    for role, want in (masked or {}).items():
        for u in pools:
            if u[:16].endswith(want):
                out[role] = u[:16].encode()
                notes.append('bound %s -> uuid %s (tail %s)' % (role, u, want))
                pools.remove(u)
                break
    # fill any remaining roles positionally if exactly 3 uuids and 3 roles
    if len(out) < 3 and not masked and len(uuids) == 3:
        out = {'authKey': uuids[0][:16].encode(),
               'streamKey': uuids[1][:16].encode(),
               'streamIV': uuids[2][:16].encode()}
        notes.append('positional binding (authKey, streamKey, streamIV)')
    return out, notes


# ------------------------------------------------------------------ framing
MAGIC = b'\x00\x07\x01\xe0'


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
        out.append(dict(off=i, cmd=cmd, seq=seq, body=bytes(buf[i + 9:i + 9 + blen])))
        i += 9 + blen
    return out


def parse_encrypted(body):
    """Return (flags, pad, crc, ct) for an encrypted body, or None."""
    if len(body) < 9 or body[:4] != MAGIC:
        return None
    flags = body[3]
    pad = body[4] if flags & 0x40 else 0
    crc = struct.unpack('>I', body[5:9])[0]
    ct = body[9:]
    return flags, pad, crc, ct


def crc_ok(body):
    p = parse_encrypted(body)
    return bool(p) and crc32_be(p[3]) == p[2]


# ------------------------------------------------------------------ main
def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    text = open(sys.argv[1], errors='replace').read() if sys.argv[1] != '-' else sys.stdin.read()
    keys, notes = keys_from_logcat(text)
    for n in notes:
        print('# ' + n)
    if not keys:
        print('!! no UUID keys found in log')
        return 2
    for r in ('authKey', 'streamKey', 'streamIV'):
        if r in keys:
            print('%-10s = %-20r  (uuid[:16])' % (r, keys[r].decode('latin1')))
    if 'authKey' in keys and 'streamIV' in keys:
        print('\n# CONTROL channel : AES-128-CBC key = authKey   IV = streamIV')
        print('#   key = %s' % keys['authKey'].hex())
        print('#   iv  = %s' % keys['streamIV'].hex())
        print('# AUDIO   channel : AES-128-CBC key = streamKey IV = streamIV')
        if 'streamKey' in keys:
            print('#   key = %s' % keys['streamKey'].hex())
        print('# chaining: free-running, IV := last16(prev ciphertext block)')
        print('# padding : zero, pad = 16-(len%%16) in 1..16')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
