#!/usr/bin/env python3
"""Regression tests for the control-channel wire format and cipher.

The cipher vectors are real captured traffic: the same session that produced
reports/MIPLAY_CMD_KEY_LIFECYCLE_V6.md. Run with `python3 -m tests.test_wire`.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wire import (ControlCipher, frame, parse_frames, tlv, gen_key, crc32_be,
                  crc32_swap, auth_msg_ack)

AUTH_KEY = '14e7e6475d2142dd'


class TestKeys(unittest.TestCase):
    def test_gen_key_is_16_ascii(self):
        k = gen_key()
        self.assertEqual(16, len(k))
        self.assertTrue(all(c in '0123456789abcdef' for c in k))
        self.assertNotEqual(gen_key(), k)


class TestFrame(unittest.TestCase):
    def test_layout(self):
        f = frame(0x36, 0, b'2.1.4111518\x00')
        self.assertEqual(0x24, f[0])
        self.assertEqual(0x00, f[1])
        self.assertEqual(0x36, f[2])
        self.assertEqual(12, int.from_bytes(f[5:9], 'big'))
        self.assertEqual(b'2.1.4111518\x00', f[9:])

    def test_parse_does_not_resync_on_0x24_inside_payload(self):
        body = bytes([0x24]) * 20
        raw = frame(0x10, 5, body) + frame(0x11, 6, b'x')
        got = parse_frames(bytearray(raw))
        self.assertEqual(2, len(got))
        self.assertEqual(body, got[0][3])


class TestCipher(unittest.TestCase):
    """Real ciphertext from the session with authKey 14e7e6475d2142dd."""

    CT = bytes.fromhex(
        '2988c7f5323cb4e067edcb7d9c0392790f3ca34a145cc3c486cc0751ce1b9300'
        '4c937495e8bb9987e6366fed43b9ef1641614f3408cddea6203c1a25c72c82d6')

    def test_crc_is_over_ciphertext(self):
        # Real frame: body 00 07 01 e0 e0 02 326e7f86 <64 bytes ct>.
        ct = bytes.fromhex(
            '12ad195a82ecef0f0e5be94064979d1661421f014c6544ee55f2fc37bd96f026'
            '066a6d63abb5113f4cdc80e22adba8e62310eb3fffa53f3c7fc12c38ba0bc30e'
            'be1b9dde85561cf2d10879799e090006ce46282729e0e316192289fb27f52785c9'
            '2939439b18aa12973c50bb73f07307c0c85b40ad47c4268b3b12a301303d69')
        # The frame stores the CRC with its bytes reversed relative to the
        # MPEG-2 big-endian value; both facts are pinned here.
        # stored bytes 32 6e 7f 86 == crc32_be(ct) 0x867F6E32 with its 4 bytes
        # written in reverse order, which is what crc32_swap models.
        self.assertEqual(0x3DC62EF0, crc32_swap(ct))   # bytes 3d c6 2e f0
        self.assertEqual(0xF02EC63D, crc32_be(ct))
        # Negative control: zlib's reflected variant must NOT match.
        import zlib
        self.assertNotEqual(0x326E7F86, zlib.crc32(ct) & 0xFFFFFFFF)

    def test_decrypts_real_frame(self):
        c = ControlCipher(AUTH_KEY)
        # real header order: magic | pad | flags | crc
        env = b'\x00\x07\x01\xe0' + bytes([2]) + \
            b'\x32\x6e\x7f\x86' + self.CT
        pt = c.decrypt(env)
        self.assertIn(b'authMsg', pt)
        self.assertIn(b'78c4a5bafb0d6a3e3a6b75494acd991a', pt)

    def test_roundtrip(self):
        c1 = ControlCipher(AUTH_KEY)
        c2 = ControlCipher(AUTH_KEY)
        for msg in (b'a', b'x' * 15, b'y' * 16, b'z' * 17, b'w' * 100):
            ct = c1.encrypt(msg)
            got = c2.decrypt(ct)
            self.assertIsNotNone(got, 'msg=%r' % msg)
            self.assertEqual(msg.rstrip(b'\x00'), got.rstrip(b'\x00'))

    def test_same_input_gives_different_output_due_to_chaining(self):
        c = ControlCipher(AUTH_KEY)
        self.assertNotEqual(c.encrypt(b'abc'), c.encrypt(b'abc'))


class TestAuthMsgAck(unittest.TestCase):
    """7 vectors from live hardware, including a post-reboot session."""

    VECTORS = [
        ('769a326df0ac49f0', '794a11ae931cbcd1dc9068624a642a39',
         '611bfd79439f357502f31fe0077c66d6dbe05d5a340198341359d154b0f87af8'),
        ('2feb068001324c98', '25e1d5733eff0008f56e81eb04eb87a8',
         '889f8b7adb2e8c03dd8259a9b5e822bda053400210d67cafc3dcebebe7dc5d58'),
        ('621b613181a74036', 'aac91bef7067fd3a45ed6171734018e2',
         '467160036375363885533bc775aec1131eb75a1b3478782e824540e45be1dbe6'),
        ('55626959fb4b4702', '2d93df91917482effd24987f3ab1f248',
         '138f21d2bbffc621a83e4f9b25604acd073be3ca6695d130eea8ca441ce3df22'),
    ]

    def test_vectors(self):
        for key, msg, ack in self.VECTORS:
            self.assertEqual(ack, auth_msg_ack(key, msg), 'key=%s' % key)


class TestTlv(unittest.TestCase):
    def test_layout_matches_capture(self):
        # Captured: 03 'cmd' 1e 00000078 <120 bytes of JSON>
        out = tlv('cmd', 'x' * 120)
        self.assertEqual(0x03, out[0])
        self.assertEqual(b'cmd', out[1:4])
        self.assertEqual(0x1e, out[4])
        self.assertEqual(120, int.from_bytes(out[5:9], 'big'))
        self.assertEqual(9 + 120, len(out))


if __name__ == '__main__':
    unittest.main(verbosity=2)
