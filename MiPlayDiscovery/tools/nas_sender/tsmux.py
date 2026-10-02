#!/usr/bin/env python3
"""MiPlay NAS sender, part 2: MPEG-TS muxer for the audio channel.

Matches the captured audio carriage (reports/MIPLAY_AUDIO_PUSH_PROTOCOL.md):

    RTSP interleaved : '$' | channel:u8 | length:u16be | payload
    payload          : 12-byte private header + MPEG-TS
    private header   : 80 a1 | seq:u16be | 0000 | de ad be ef | subtype:u16be
    MPEG-TS          : PAT 0x0000 / PMT 0x0100 / PCR 0x1000 / audio PES 0x1100
                       PES stream_id = 0xC0, carries a PTS

The muxer is structurally identical to the verified Kotlin TsMuxer, so the
layout here is the same one that passes those unit tests.
"""
import struct
from typing import List, Optional

TS_PACKET_SIZE = 188
SYNC = 0x47

PID_PAT = 0x0000
PID_PMT = 0x0100
PID_PCR = 0x1000
PID_AUDIO = 0x1100

STREAM_TYPE_AAC_LATM = 0x11
STREAM_TYPE_AAC_ADTS = 0x0F

PRIVATE_MAGIC = b'\x80\xa1'
PRIVATE_MARKER = b'\xde\xad\xbe\xef'


def crc32_mpeg(data: bytes) -> int:
    """MPEG-2 CRC-32 (poly 0x04C11DB7, init 0xFFFFFFFF, no final xor)."""
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b << 24
        for _ in range(8):
            crc = ((crc << 1) ^ 0x04C11DB7) & 0xFFFFFFFF if crc & 0x80000000 \
                else (crc << 1) & 0xFFFFFFFF
    return crc


class TsMuxer:
    def __init__(self, pmt_pid: int = PID_PMT, audio_pid: int = PID_AUDIO,
                 pcr_pid: int = PID_PCR,
                 audio_stream_type: int = STREAM_TYPE_AAC_LATM,
                 program_number: int = 1):
        self.pmt_pid = pmt_pid
        self.audio_pid = audio_pid
        self.pcr_pid = pcr_pid
        self.audio_stream_type = audio_stream_type
        self.program_number = program_number
        self._cc = {}
        self.pcr = 0
        self.priv_seq = 0

    # ------------------------------------------------------------- internals
    def _next_cc(self, pid: int) -> int:
        v = self._cc.get(pid, 0)
        self._cc[pid] = (v + 1) & 0x0F
        return v

    def _ts(self, pid: int, payload: bytes, pusi: bool,
            adaptation: Optional[bytes] = None) -> bytes:
        hdr = bytearray(4)
        hdr[0] = SYNC
        hdr[1] = ((pid >> 8) & 0x1F) | (0x40 if pusi else 0x00)
        hdr[2] = pid & 0xFF
        afc = 0x30 if adaptation is not None else 0x10   # payload + adaptation
        hdr[3] = (afc) | self._next_cc(pid)
        out = bytes(hdr)
        if adaptation is not None:
            out += bytes([len(adaptation)]) + adaptation
        out += payload
        assert len(out) == TS_PACKET_SIZE, 'packet must be exactly 188 bytes'
        return out

    def _psi(self, pid: int, table_id: int, body: bytes, version: int = 0) -> bytes:
        # section_length counts everything after its own two bytes:
        #   5 header + body + 4 CRC
        section_length = 5 + len(body) + 4
        section = bytearray(3 + section_length)
        section[0] = table_id
        section[1] = 0xB0 | ((section_length >> 8) & 0x0F)
        section[2] = section_length & 0xFF
        struct.pack_into('>H', section, 3, self.program_number)
        section[5] = 0xC1 | ((version & 0x1F) << 1)     # reserved + current_next
        section[6] = 0
        section[7] = 0
        section[8:8 + len(body)] = body
        crc = crc32_mpeg(bytes(section[:8 + len(body)]))
        struct.pack_into('>I', section, 8 + len(body), crc)
        # A PSI section must fill the whole packet; pad the remainder with 0xFF.
        payload = bytes(section)
        if len(payload) > TS_PACKET_SIZE - 4:
            raise ValueError('PSI section too large for one packet')
        payload += b'\xFF' * (TS_PACKET_SIZE - 4 - len(payload))
        return self._ts(pid, payload, pusi=True)

    # ------------------------------------------------------------------ PSI
    def build_pat(self) -> bytes:
        body = struct.pack('>H', self.program_number) + \
               struct.pack('>H', 0xE000 | self.pmt_pid)
        return self._psi(PID_PAT, 0x00, body)

    def build_pmt(self) -> bytes:
        body = bytearray()
        body += struct.pack('>H', 0xE000 | self.pcr_pid)
        body += struct.pack('>H', 0xF000)                    # program_info_length = 0
        body += bytes([self.audio_stream_type])
        body += struct.pack('>H', 0xE000 | self.audio_pid)
        body += struct.pack('>H', 0xF000)                    # ES_info_length = 0
        return self._psi(self.pmt_pid, 0x02, bytes(body))

    # ------------------------------------------------------------------ PCR
    def set_pcr_micros(self, micros: int) -> None:
        # 27 MHz clock; PCR_base = 90 kHz, PCR_ext = 27 MHz remainder
        base = (micros * 27) // 1000
        self.pcr = base

    def build_pcr_packet(self) -> bytes:
        pcr_base = self.pcr
        adaptation = bytearray()
        adaptation.append(0x10)                              # PCR_flag
        p = pcr_base & 0x1FFFFFFFF
        adaptation += bytes([
            (p >> 25) & 0xFF, (p >> 17) & 0xFF, (p >> 9) & 0xFF,
            (p >> 1) & 0xFF, ((p & 1) << 7) | 0x7E, 0x00,
        ])
        # pad adaptation to fill the packet
        pad = TS_PACKET_SIZE - 4 - 1 - len(adaptation)
        adaptation += b'\xFF' * pad
        return self._ts(self.pcr_pid, b'', pusi=False, adaptation=bytes(adaptation))

    # ------------------------------------------------------------------ PES
    @staticmethod
    def _pts_bytes(pts: int) -> bytes:
        pts &= 0x1FFFFFFFF
        return bytes([
            0x21 | (((pts >> 30) & 0x07) << 1),
            (pts >> 22) & 0xFF,
            0x01 | (((pts >> 15) & 0x7F) << 1),
            (pts >> 7) & 0xFF,
            0x01 | ((pts & 0x7F) << 1),
        ])

    def build_pes(self, data: bytes, pts_micros: int) -> bytes:
        pts = (pts_micros * 90) // 1000                        # 90 kHz
        header = bytearray()
        header += b'\x00\x00\x01' + bytes([0xC0])              # stream_id 0xC0
        pes_len = 3 + 5 + len(data)
        header += struct.pack('>H', pes_len)
        header += bytes([0x80, 0x80, 0x05])                    # marker, PTS only
        header += self._pts_bytes(pts)
        return bytes(header) + data

    # ------------------------------------------------------- private header
    def private_header(self, subtype: int = 0x4751) -> bytes:
        h = PRIVATE_MAGIC + struct.pack('>H', self.priv_seq & 0xFFFF) + b'\x00\x00' + \
            PRIVATE_MARKER + struct.pack('>H', subtype)
        self.priv_seq = (self.priv_seq + 1) & 0xFFFF
        return h

    # ------------------------------------------------------------ public API
    def mux_access_unit(self, data: bytes, pts_micros: int,
                        private: bool = True) -> bytes:
        """One AAC access unit -> private header + PES -> TS packets.

        Every emitted packet is exactly 188 bytes. The 12-byte private header
        MUST be the first thing in the payload area of the first packet, so the
        payload is placed first and only the leftover room is stuffed.
        """
        payload = self.build_pes(data, pts_micros)
        if private:
            payload = self.private_header() + payload
        out = bytearray()
        first = True
        while payload:
            chunk, payload = payload[:184], payload[184:]
            out += self._ts_filled(self.audio_pid, chunk, pusi=first)
            first = False
        return bytes(out)

    def _ts_filled(self, pid: int, payload: bytes, pusi: bool) -> bytes:
        """Build a packet; pad with an adaptation field only if needed."""
        room = TS_PACKET_SIZE - 4
        if len(payload) == room:
            return self._ts(pid, payload, pusi=pusi)
        stuffing = room - len(payload)
        # adaptation_field_length counts the flags byte plus the stuffing bytes
        af_len = stuffing - 1
        if af_len == 0:
            adaptation = b''                      # length 0 means 'no AF data'
        else:
            adaptation = bytes([0x00]) + b'\xFF' * (af_len - 1)
        return self._ts(pid, payload, pusi=pusi, adaptation=adaptation)

    def write_pts(self, pts_micros: int) -> bytes:
        return self._pts_bytes((pts_micros * 90) // 1000)

    def mpeg_crc32(self, data: bytes) -> int:
        return crc32_mpeg(data)


def interleave(channel: int, payload: bytes) -> bytes:
    """RTSP interleaved framing: '$' | channel | length:u16be | payload."""
    assert len(payload) <= 0xFFFF, 'frame too large for u16 length'
    return bytes([0x24, channel & 0xFF]) + struct.pack('>H', len(payload)) + payload
