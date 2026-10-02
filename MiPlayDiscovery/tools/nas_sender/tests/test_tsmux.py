#!/usr/bin/env python3
"""Regression tests for the MPEG-TS muxer (mirrors the verified Kotlin layout)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tsmux import TsMuxer, interleave, crc32_mpeg, TS_PACKET_SIZE


def pid_of(p):
    return ((p[1] & 0x1F) << 8) | p[2]


class TestPsi(unittest.TestCase):
    def test_crc32_mpeg_check_value(self):
        self.assertEqual(0x0376E6E7, crc32_mpeg(b'123456789'))

    def test_pat(self):
        p = TsMuxer().build_pat()
        self.assertEqual(TS_PACKET_SIZE, len(p))
        self.assertEqual(0x47, p[0])
        self.assertEqual(0x0000, pid_of(p))
        self.assertTrue(p[1] & 0x40)                       # payload_unit_start
        self.assertEqual(0x00, p[4])                       # table_id
        self.assertEqual(13, ((p[5] & 0x0F) << 8) | p[6])  # section_length
        self.assertEqual(1, (p[7] << 8) | p[8])            # program_number
        self.assertEqual(0x0100, ((p[9] & 0x1F) << 8) | p[10])

    def test_pmt(self):
        p = TsMuxer().build_pmt()
        self.assertEqual(TS_PACKET_SIZE, len(p))
        self.assertEqual(0x0100, pid_of(p))
        self.assertEqual(0x02, p[4])
        self.assertEqual(0x1000, ((p[12] & 0x1F) << 8) | p[13])   # PCR pid
        self.assertEqual(0x11, p[16])                             # AAC LATM
        self.assertEqual(0x1100, ((p[17] & 0x1F) << 8) | p[18])   # ES pid


class TestPes(unittest.TestCase):
    def test_header(self):
        pes = TsMuxer().build_pes(bytes(10), 1_000_000)
        self.assertEqual(b'\x00\x00\x01', pes[:3])
        self.assertEqual(0xC0, pes[3])                     # audio stream_id
        self.assertEqual(3 + 5 + 10, (pes[4] << 8) | pes[5])
        self.assertEqual(0x80, pes[7] & 0xC0)              # PTS only


class TestAccessUnit(unittest.TestCase):
    def test_every_packet_is_188_bytes_with_private_header(self):
        for size in (1, 10, 100, 182, 184, 500, 1000):
            m = TsMuxer()
            ts = m.mux_access_unit(bytes(size), 0)
            self.assertEqual(0, len(ts) % TS_PACKET_SIZE, 'size=%d' % size)
            for k in range(0, len(ts), TS_PACKET_SIZE):
                pkt = ts[k:k + TS_PACKET_SIZE]
                self.assertEqual(188, len(pkt))
                self.assertEqual(0x47, pkt[0])
                self.assertEqual(0x1100, pid_of(pkt))
            first = ts[:TS_PACKET_SIZE]
            afc = (first[3] & 0x30) >> 4
            start = 5 + first[4] if afc == 3 else 4
            # private header: 80 a1 | seq:u16 | 0000 | deadbeef | subtype:u16
            self.assertEqual(b'\x80\xa1', first[start:start + 2])
            self.assertEqual(b'\xde\xad\xbe\xef', first[start + 6:start + 10])

    def test_only_first_packet_sets_payload_unit_start(self):
        ts = TsMuxer().mux_access_unit(bytes(500), 0)
        n = len(ts) // TS_PACKET_SIZE
        self.assertGreater(n, 1)
        self.assertTrue(ts[1] & 0x40)
        for i in range(1, n):
            self.assertFalse(ts[i * TS_PACKET_SIZE + 1] & 0x40)

    def test_continuity_counter_increments(self):
        m = TsMuxer()
        ccs = [m.build_pcr_packet()[3] & 0x0F for _ in range(20)]
        for i in range(1, len(ccs)):
            self.assertEqual((ccs[i - 1] + 1) & 0x0F, ccs[i])


class TestInterleave(unittest.TestCase):
    def test_layout(self):
        f = interleave(0, bytes(764))
        self.assertEqual(0x24, f[0])
        self.assertEqual(0, f[1])
        self.assertEqual(764, (f[2] << 8) | f[3])
        self.assertEqual(4 + 764, len(f))


if __name__ == '__main__':
    unittest.main(verbosity=2)
