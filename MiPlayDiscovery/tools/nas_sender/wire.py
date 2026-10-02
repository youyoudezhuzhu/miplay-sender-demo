#!/usr/bin/env python3
"""MiPlay NAS sender, part 1: wire format + crypto.

Reversed from live captures; see reports/MIPLAY_CMD_KEY_LIFECYCLE_V6.md.

Control channel (TCP 8899)  = AES-128-CBC
    key      = authKey  (uuid[:16], ASCII)
    IV(1st)  = authKey
    IV(next) = last 16 bytes of previous ciphertext  (free-running, per direction)
    padding  = zero padding, pad = 16 - (len % 16)
Frame        = '$' | outer:u8 | cmd:u8 | seq:u16be | bodyLen:u32be | body
Encrypted body = 00 07 01 e0 | pad:u8 | flags:u8(0xe0) | crc32be(ct) | ct
"""
import struct
import uuid


# --------------------------------------------------------------------- CRC32
def crc32_be(data: bytes) -> int:
    """CRC-32/MPEG-2 (poly 0x04C11DB7, init 0xFFFFFFFF, no reflection, no xorout).

    NOT zlib.crc32 -- that is the reflected variant and produces different
    values. Verified against live frames: this matches the 4 bytes stored in the
    frame body for 8/8 sampled frames.
    """
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b << 24
        for _ in range(8):
            crc = ((crc << 1) ^ 0x04C11DB7) & 0xFFFFFFFF if crc & 0x80000000 \
                else (crc << 1) & 0xFFFFFFFF
    return crc


def crc32_swap(data: bytes) -> int:
    """Same CRC with the 4 result bytes reversed (the device stores it LE-ish)."""
    c = crc32_be(data)
    return int.from_bytes(c.to_bytes(4, 'big'), 'little')


# ------------------------------------------------------------------ key gen
def gen_key() -> str:
    """The sender generates its own keys: uuid4 hex, first 16 chars (ASCII)."""
    return str(uuid.uuid4()).replace('-', '')[:16]


# --------------------------------------------------------------- frame codec
MAGIC = b'\x00\x07\x01\xe0'
FLAGS = 0xE0
CMD_AUTH20 = 0x29
CMD_GET_VERSION = 0x36
CMD_SAFETY_AUTH = 0x02
CMD_SAFETY_AUTH_ACK = 0x03
CMD_OPEN = 0x00
CMD_WRAPPER = 0x14
CMD_SET_MIRROR_KEY = 0x6C
CMD_MEDIA_INFO = 0x12


class ControlCipher:
    """Free-running AES-128-CBC with zero padding, matching the device."""

    def __init__(self, auth_key: str):
        self.key = auth_key.encode('ascii')
        assert len(self.key) == 16, 'authKey must be 16 ASCII bytes'
        self.iv = self.key          # first IV is authKey, NOT streamIV
        self.encrypt = self._enc
        self.decrypt = self._dec

    # Envelope layout, read off real bytes:
    #   magic:4 | pad:u8 | crc32:u32be | ciphertext
    # Example body: 00 07 01 e0 | 02 | 32 6e 7f 86 | 29 88 c7 ...
    #   cmd=0x02, body_len=73, ct=64, pad=2 -> plaintext 62 bytes
    # The pad byte always equals the number of trailing zero bytes, confirmed
    # across every frame (0x02->2, 0x0f->15, 0x10->16, 0x0a->10, 0x08->8).
    # Header is 9 bytes; ciphertext starts at offset 9. (The earlier "flags
    # 0xe0" reading was wrong: 0xe0 never appears in this field.)
    HDR = 9

    @staticmethod
    def _raw(key: bytes, iv: bytes, data: bytes, encrypt: bool) -> bytes:
        """Single-shot raw AES-CBC with NO padding added or removed.

        `CipherContext.update()` applies its own PKCS#7 padding when a full
        message is pushed through it, which would append a spurious block on top
        of the zero padding the device uses. `update()` on an already
        block-aligned input is safe, so it is used directly here.
        """
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        c = Cipher(algorithms.AES(key), modes.CBC(iv))
        ctx = c.encryptor() if encrypt else c.decryptor()
        return ctx.update(data)

    def _enc(self, pt: bytes) -> bytes:
        pad = 16 - (len(pt) % 16)
        ct = self._raw(self.key, self.iv, pt + b'\x00' * pad, True)
        if len(ct) % 16:
            raise ValueError('ciphertext not block aligned: %d' % len(ct))
        self.iv = ct[-16:]
        # The device stores the CRC with its 4 bytes reversed.
        return MAGIC + bytes([pad]) + \
            struct.pack('>I', crc32_swap(ct)) + ct

    def _dec(self, body: bytes) -> bytes | None:
        if len(body) < self.HDR or body[:4] != MAGIC:
            return None
        pad = body[4]
        ct = body[self.HDR:]
        if not ct or len(ct) % 16:
            return None
        pt = self._raw(self.key, self.iv, ct, False)
        self.iv = ct[-16:]
        if 0 < pad <= len(pt):
            return pt[:len(pt) - pad]
        return pt.rstrip(b'\x00')


def frame(cmd: int, seq: int, body: bytes, outer: int = 0) -> bytes:
    out = bytearray(9 + len(body))
    out[0] = 0x24
    out[1] = outer
    out[2] = cmd
    struct.pack_into('>H', out, 3, seq & 0xFFFF)
    struct.pack_into('>I', out, 5, len(body))
    out[9:] = body
    return bytes(out)


def parse_frames(buf: bytearray):
    """Yield (outer, cmd, seq, body) without resyncing on 0x24 inside payloads."""
    out = []
    i = 0
    while i + 9 <= len(buf):
        if buf[i] != 0x24:
            i += 1
            continue
        n = struct.unpack('>I', buf[i + 5:i + 9])[0]
        if i + 9 + n > len(buf) or n > (1 << 22):
            i += 1
            continue
        out.append((buf[i + 1], buf[i + 2], struct.unpack('>H', buf[i + 3:i + 5])[0],
                    bytes(buf[i + 9:i + 9 + n])))
        i += 9 + n
    return out


def tlv(key: str, payload: str) -> bytes:
    """keylen:u8 | key | 0x1e | len:u32be | payload  (layout verified from capture)."""
    kb = key.encode('ascii')
    pb = payload.encode('utf-8')
    return bytes([len(kb)]) + kb + b'\x1e' + struct.pack('>I', len(pb)) + pb


# --------------------------------------------------------------------- RTSP
def auth_msg_ack(auth_key: str, auth_msg: str) -> str:
    """WFD challenge response. Verified 7/7 on live hardware."""
    import hashlib
    import hmac
    return hmac.new(auth_key.encode('ascii'), auth_msg.encode('ascii'),
                    hashlib.sha256).hexdigest()


def capabilities() -> str:
    return (
        'wfd_audio_codecs_v2: 63 3 3\r\n'
        'wfd_video_formats: none\r\n'
        'wfd_video_enctype: none\r\n'
        'wfd_video_gamuttype: none\r\n'
        'wfd_video_bitrate: none\r\n'
        'wfd_current_video_info: none\r\n'
        'wfd_client_rtp_ports: RTP/AVP/TCP;interleaved mode=play\r\n'
        'miplay_support_image: none\r\n'
        'wfd_standby_resume_capability: supported\r\n'
        'wfd_content_SP_protection: 4 1 256 2 1 1 0 0\r\n'
        'wfd_support_secure_win:enable\r\n'
        'device_info: -1 -1 -1 -1 -1 -1 -1\r\n'
    )
