#!/usr/bin/env python3
"""MiPlay NAS sender, part 3: WFD RTSP server.

The SPEAKER dials the sender, so the sender hosts this server. Sequence
reproduced from a live capture (reports/MIPLAY_AUDIO_PUSH_PROTOCOL.md §7):

    speaker -> OPTIONS *          (carries authMsg, authKeyType, authAlgorithmTypes)
    sender  -> 200 OK             (authMsgAck = HMAC-SHA256(authKey, authMsg))
    speaker -> GET_PARAMETER      (asks for capabilities)
    sender  -> 200 OK             (wfd_audio_codecs_v2, wfd_video_formats: none, ...)
    speaker -> SET_PARAMETER      (codec choice + presentation URL)
    speaker -> SET_PARAMETER      wfd_trigger_method: SETUP
    speaker -> SETUP              Transport: ...; MultiPort: multi_port=<port>
    sender  -> 200 OK             Session: <id>;timeout=20  + echo Transport
    speaker -> PLAY               Session: <id>
    sender  -> 200 OK             Session + Range: npt=now-
    <audio flows as interleaved MPEG-TS on this TCP connection>

The server binds a fixed port; that port goes into the `wfd://<ip>:<port>` URI
handed to the speaker over the 8899 control channel.
"""
import socket
import threading
import time
from typing import Optional

from wire import auth_msg_ack, capabilities


def _read_headers(sock: socket.socket) -> Optional[tuple]:
    """Read one RTSP request. Returns (start_line, headers, content_length)."""
    buf = bytearray()
    while b'\r\n\r\n' not in buf:
        try:
            chunk = sock.recv(4096)
        except (socket.timeout, OSError):
            return None
        if not chunk:
            return None
        buf += chunk
        if len(buf) > 1 << 20:
            return None
    head, _, rest = buf.partition(b'\r\n\r\n')
    lines = head.decode('utf-8', 'replace').split('\r\n')
    start = lines[0]
    headers = {}
    for ln in lines[1:]:
        if ':' in ln:
            k, v = ln.split(':', 1)
            headers[k.strip().lower()] = v.strip()
    clen = int(headers.get('content-length', '0') or '0')
    return start, headers, clen, bytes(rest)


class RtspServer:
    def __init__(self, bind_ip: str, port: int, auth_key: str, log=print):
        self.bind_ip = bind_ip
        self.port = port
        self.auth_key = auth_key
        self.log = log
        self.srv: Optional[socket.socket] = None
        self.playing = threading.Event()
        self.audio_conn: Optional[socket.socket] = None
        self.session_id = 0
        self.audio_return_port = 0
        self._stop = threading.Event()
        self.on_play = None

    # ------------------------------------------------------------------ serve
    def start(self) -> None:
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.bind_ip, self.port))
        s.listen(8)
        self.srv = s
        self.port = s.getsockname()[1]
        self.log('[rtsp] listening on %s:%d' % (self.bind_ip, self.port))
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                c, a = self.srv.accept()
            except OSError:
                break
            c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.log('[rtsp] connection from %s:%d' % a)
            threading.Thread(target=self._serve, args=(c, a), daemon=True).start()

    def _serve(self, c: socket.socket, addr) -> None:
        c.settimeout(120)
        while not self._stop.is_set():
            req = _read_headers(c)
            if req is None:
                break
            start, headers, clen, rest = req
            body = rest
            while len(body) < clen:
                more = c.recv(clen - len(body))
                if not more:
                    break
                body += more
            body = body[:clen]
            method = start.split(' ')[0].upper()
            self.log('[rtsp] <- %s' % start)
            try:
                if method == 'OPTIONS':
                    self._on_options(c, headers)
                elif method == 'GET_PARAMETER':
                    self._on_get_parameter(c, headers)
                elif method == 'SET_PARAMETER':
                    self.log('[rtsp]    body: %r' % body[:200])
                    self._reply(c, headers, 200, 'OK')
                elif method == 'SETUP':
                    self._on_setup(c, headers)
                elif method == 'PLAY':
                    self._on_play(c, headers)
                    # audio flows on this same connection
                    self.audio_conn = c
                    self.playing.set()
                    if self.on_play:
                        threading.Thread(target=self.on_play, daemon=True).start()
                    return
                elif method == 'TEARDOWN':
                    self._reply(c, headers, 200, 'OK')
                    break
                else:
                    self._reply(c, headers, 200, 'OK')
            except OSError as e:
                self.log('[rtsp] write failed: %s' % e)
                break
        try:
            c.close()
        except OSError:
            pass

    # -------------------------------------------------------------- handlers
    def _on_options(self, c, headers):
        auth = headers.get('authmsg')
        extra = ''
        if auth:
            ack = auth_msg_ack(self.auth_key, auth)
            extra += 'authMsgAck:%s\r\n' % ack
            self.log('[rtsp]    authMsg=%s' % auth)
            self.log('[rtsp]    authMsgAck=%s' % ack)
        self._reply(c, headers, 200, 'OK', extra=extra,
                    public='org.wfa.wfd1.0, SETUP, TEARDOWN, PLAY, PAUSE, '
                           'GET_PARAMETER, SET_PARAMETER')

    def _on_get_parameter(self, c, headers):
        self._reply(c, headers, 200, 'OK', body=capabilities(),
                    ctype='text/parameters')

    def _on_setup(self, c, headers):
        import re
        mp = headers.get('multiport', '')
        m = re.search(r'multi_port\s*=\s*(\d+)', mp)
        if m:
            self.audio_return_port = int(m.group(1))
            self.log('[rtsp]    MultiPort audio_return_port=%d' % self.audio_return_port)
        if not self.session_id:
            import random
            self.session_id = random.randint(1, 2 ** 31 - 1)
        transport = headers.get('transport', 'RTP/AVP/TCP;interleaved=0-1') + ';'
        self._reply(c, headers, 200, 'OK',
                    session='%d;timeout=20' % self.session_id, transport=transport)

    def _on_play(self, c, headers):
        if not self.session_id:
            import random
            self.session_id = random.randint(1, 2 ** 31 - 1)
        self._reply(c, headers, 200, 'OK',
                    session='%d;timeout=20' % self.session_id,
                    extra='Range: npt=now-\r\n')

    # --------------------------------------------------------------- replies
    def _reply(self, c, headers, code, reason, body='', ctype='text/parameters',
               session=None, transport=None, public=None, extra=''):
        cseq = headers.get('cseq', '0')
        lines = ['RTSP/1.0 %d %s' % (code, reason), 'CSeq: %s' % cseq]
        if public:
            lines.append('Public: %s' % public)
        if session:
            lines.append('Session: %s' % session)
        if transport:
            lines.append('Transport: %s' % transport)
        if extra:
            lines.append(extra.rstrip('\r\n'))
        b = body.encode('utf-8') if isinstance(body, str) else body
        if b:
            lines.append('Content-Type: %s' % ctype)
        lines.append('Content-Length: %d' % len(b))
        msg = '\r\n'.join(lines) + '\r\n\r\n'
        c.sendall(msg.encode('utf-8') + b)

    # ------------------------------------------------------------ audio send
    def send_interleaved(self, payload: bytes, channel: int = 0) -> bool:
        conn = self.audio_conn
        if conn is None:
            return False
        try:
            conn.sendall(bytes([0x24, channel]) +
                         len(payload).to_bytes(2, 'big') + payload)
            return True
        except OSError:
            self.audio_conn = None
            return False

    def stop(self):
        self._stop.set()
        try:
            self.srv.close()
        except OSError:
            pass
