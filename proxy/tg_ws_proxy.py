#!/usr/bin/env python3
"""
Telegram SOCKS5 -> Cloudflare WebSocket Bridge Proxy
- Entry: SOCKS5
- Relay: Cloudflare WS
- Fallback: Direct TCP passthrough (last resort)
- Browser/WS/TLS detection & routing
- Subnet-based DC resolver
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import ipaddress
import logging
import os
import socket as _socket
import ssl
import struct
import sys
import time
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ======================== CONSTANTS ========================
DEFAULT_PORT = 1080
_TCP_NODELAY = True
_RECV_BUF = 256 * 1024
_SEND_BUF = 256 * 1024

_TELEGRAM_IP_RANGES = [
    (struct.unpack('!I', _socket.inet_aton('185.76.151.0'))[0],
     struct.unpack('!I', _socket.inet_aton('185.76.151.255'))[0]),
    (struct.unpack('!I', _socket.inet_aton('149.154.160.0'))[0],
     struct.unpack('!I', _socket.inet_aton('149.154.175.255'))[0]),
    (struct.unpack('!I', _socket.inet_aton('91.105.192.0'))[0],
     struct.unpack('!I', _socket.inet_aton('91.105.193.255'))[0]),
    (struct.unpack('!I', _socket.inet_aton('91.108.0.0'))[0],
     struct.unpack('!I', _socket.inet_aton('91.108.255.255'))[0]),
]

_PROTO_ABRIDGED = 0xEFEFEFEF
_PROTO_INTERMEDIATE = 0xEEEEEEEE
_PROTO_PADDED_INTERMEDIATE = 0xDDDDDDDD
_VALID_PROTOS = frozenset((_PROTO_ABRIDGED, _PROTO_INTERMEDIATE, _PROTO_PADDED_INTERMEDIATE))
_ZERO_64 = b'\x00' * 64

_st_BB = struct.Struct('>BB')
_st_BBH = struct.Struct('>BBH')
_st_BBQ = struct.Struct('>BBQ')
_st_BB4s = struct.Struct('>BB4s')
_st_BBH4s = struct.Struct('>BBH4s')
_st_BBQ4s = struct.Struct('>BBQ4s')
_st_H = struct.Struct('>H')
_st_Q = struct.Struct('>Q')
_st_I_net = struct.Struct('!I')
_st_Ih = struct.Struct('<Ih')
_st_I_le = struct.Struct('<I')

_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode = ssl.CERT_NONE

log = logging.getLogger('tg-ws-cf-proxy')

# ======================== ROBUST DC RESOLVER ========================
_DC_SUBNETS = [
    (ipaddress.ip_network('185.76.151.0/24'), 1, False),
    (ipaddress.ip_network('149.154.172.0/22'), 1, False),
    (ipaddress.ip_network('5.28.195.0/24'), 2, False),
    (ipaddress.ip_network('95.161.64.0/20'), 2, False),
    (ipaddress.ip_network('149.154.160.0/20'), 2, False),
    (ipaddress.ip_network('149.154.164.0/22'), 4, False),
    (ipaddress.ip_network('91.108.4.0/22'), 5, False),
    (ipaddress.ip_network('91.108.8.0/22'), 5, False),
    (ipaddress.ip_network('91.108.12.0/22'), 5, False),
    (ipaddress.ip_network('91.108.16.0/22'), 5, False),
    (ipaddress.ip_network('91.108.20.0/22'), 5, False),
    (ipaddress.ip_network('91.108.56.0/22'), 5, False),
    (ipaddress.ip_network('91.105.192.0/23'), 203, False),
]

def _resolve_dc_from_ip(ip: str) -> Tuple[int, bool]:
    try: addr = ipaddress.ip_address(ip)
    except ValueError: return 2, False
    for net, dc, is_media in _DC_SUBNETS:
        if addr in net: return dc, is_media
    return 2, False

# ======================== HELPERS ========================
def _set_sock_opts(transport):
    sock = transport.get_extra_info('socket')
    if sock is None: return
    if _TCP_NODELAY:
        try: sock.setsockopt(_socket.IPPROTO_TCP, _socket.TCP_NODELAY, 1)
        except (OSError, AttributeError): pass
    try:
        sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_RCVBUF, _RECV_BUF)
        sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_SNDBUF, _SEND_BUF)
    except OSError: pass

def _human_bytes(n: int) -> str:
    for unit in ('B', 'KB', 'MB', 'GB'):
        if abs(n) < 1024: return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"

def _is_telegram_ip(ip: str) -> bool:
    try:
        n = _st_I_net.unpack(_socket.inet_aton(ip))[0]
        return any(lo <= n <= hi for lo, hi in _TELEGRAM_IP_RANGES)
    except OSError: return False

def _is_http_transport(data: bytes) -> bool:
    return data[:5] in (b'POST ', b'GET  ', b'HEAD ') or data[:8] == b'OPTIONS '

def _is_browser_ws_init(data: bytes) -> bool:
    if len(data) < 16: return False
    if data[:3] in (b'GET', b'POS', b'HEA', b'OPT'): return True
    try:
        text = data[:128].decode('ascii', errors='ignore').lower()
        if 'sec-websocket-key:' in text and 'origin:' in text:
            return 'telegram.org' in text
    except Exception: pass
    return False

# ======================== RAW WEBSOCKET ========================
class WsHandshakeError(Exception):
    def __init__(self, status_code: int, status_line: str, headers: dict = None, location: str = None):
        self.status_code = status_code
        self.status_line = status_line
        self.headers = headers or {}
        self.location = location
        super().__init__(f"HTTP {status_code}: {status_line}")
    @property
    def is_redirect(self) -> bool:
        return self.status_code in (301, 302, 303, 307, 308)

def _xor_mask(data: bytes, mask: bytes) -> bytes:
    if not data: return data
    n = len(data)
    mask_rep = (mask * (n // 4 + 1))[:n]
    return (int.from_bytes(data, 'big') ^ int.from_bytes(mask_rep, 'big')).to_bytes(n, 'big')

class RawWebSocket:
    __slots__ = ('reader', 'writer', '_closed')
    OP_BINARY = 0x2; OP_CLOSE = 0x8; OP_PING = 0x9; OP_PONG = 0xA

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader; self.writer = writer; self._closed = False

    @staticmethod
    async def connect(host: str, domain: str, path: str = '/apiws', timeout: float = 10.0) -> 'RawWebSocket':
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, 443, ssl=_ssl_ctx, server_hostname=domain),
            timeout=min(timeout, 10)
        )
        _set_sock_opts(writer.transport)
        ws_key = base64.b64encode(os.urandom(16)).decode()
        req = (f'GET {path} HTTP/1.1\r\nHost: {domain}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
               f'Sec-WebSocket-Key: {ws_key}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: binary\r\n'
               f'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\n\r\n')
        writer.write(req.encode()); await writer.drain()
        response_lines = []
        try:
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=timeout)
                if line in (b'\r\n', b'\n', b''): break
                response_lines.append(line.decode('utf-8', errors='replace').strip())
        except asyncio.TimeoutError: writer.close(); raise
        if not response_lines: writer.close(); raise WsHandshakeError(0, 'empty response')
        first_line = response_lines[0]; parts = first_line.split(' ', 2)
        try: status_code = int(parts[1]) if len(parts) >= 2 else 0
        except ValueError: status_code = 0
        if status_code == 101: return RawWebSocket(reader, writer)
        headers = {}
        for hl in response_lines[1:]:
            if ':' in hl: k, v = hl.split(':', 1); headers[k.strip().lower()] = v.strip()
        writer.close(); raise WsHandshakeError(status_code, first_line, headers, location=headers.get('location'))

    async def send(self, data: bytes):
        if self._closed: raise ConnectionError("WebSocket closed")
        self.writer.write(self._build_frame(self.OP_BINARY, data, mask=True)); await self.writer.drain()

    async def send_batch(self, parts: List[bytes]):
        if self._closed: raise ConnectionError("WebSocket closed")
        for part in parts: self.writer.write(self._build_frame(self.OP_BINARY, part, mask=True))
        await self.writer.drain()

    async def recv(self) -> Optional[bytes]:
        while not self._closed:
            opcode, payload = await self._read_frame()
            if opcode == self.OP_CLOSE:
                self._closed = True
                try: self.writer.write(self._build_frame(self.OP_CLOSE, payload[:2] if payload else b'', mask=True)); await self.writer.drain()
                except Exception: pass
                return None
            if opcode == self.OP_PING:
                try: self.writer.write(self._build_frame(self.OP_PONG, payload, mask=True)); await self.writer.drain()
                except Exception: pass
                continue
            if opcode == self.OP_PONG: continue
            if opcode in (0x1, self.OP_BINARY): return payload
        return None

    async def close(self):
        if self._closed: return
        self._closed = True
        try: self.writer.write(self._build_frame(self.OP_CLOSE, b'', mask=True)); await self.writer.drain()
        except Exception: pass
        try: self.writer.close(); await self.writer.wait_closed()
        except Exception: pass

    @staticmethod
    def _build_frame(opcode: int, data: bytes, mask: bool = False) -> bytes:
        length = len(data); fb = 0x80 | opcode
        if not mask:
            if length < 126: return _st_BB.pack(fb, length) + data
            if length < 65536: return _st_BBH.pack(fb, 126, length) + data
            return _st_BBQ.pack(fb, 127, length) + data
        mask_key = os.urandom(4); masked = _xor_mask(data, mask_key)
        if length < 126: return _st_BB4s.pack(fb, 0x80 | length, mask_key) + masked
        if length < 65536: return _st_BBH4s.pack(fb, 0x80 | 126, length, mask_key) + masked
        return _st_BBQ4s.pack(fb, 0x80 | 127, length, mask_key) + masked

    async def _read_frame(self) -> Tuple[int, bytes]:
        hdr = await self.reader.readexactly(2)
        opcode = hdr[0] & 0x0F; length = hdr[1] & 0x7F
        if length == 126: length = _st_H.unpack(await self.reader.readexactly(2))[0]
        elif length == 127: length = _st_Q.unpack(await self.reader.readexactly(8))[0]
        if hdr[1] & 0x80:
            mask_key = await self.reader.readexactly(4)
            payload = await self.reader.readexactly(length)
            return opcode, _xor_mask(payload, mask_key)
        payload = await self.reader.readexactly(length)
        return opcode, payload

# ======================== MSG SPLITTER ========================
class MsgSplitter:
    __slots__ = ('_dec', '_proto', '_cipher_buf', '_plain_buf', '_disabled')
    def __init__(self, init_data: bytes, proto: int):
        cipher = Cipher(algorithms.AES(init_data[8:40]), modes.CTR(init_data[40:56]))
        self._dec = cipher.encryptor(); self._dec.update(_ZERO_64); self._proto = proto
        self._cipher_buf = bytearray(); self._plain_buf = bytearray(); self._disabled = False

    def split(self, chunk: bytes) -> List[bytes]:
        if not chunk or self._disabled: return [chunk]
        self._cipher_buf.extend(chunk); self._plain_buf.extend(self._dec.update(chunk))
        parts = []
        while self._cipher_buf:
            packet_len = self._next_packet_len()
            if packet_len is None: break
            if packet_len <= 0:
                parts.append(bytes(self._cipher_buf)); self._cipher_buf.clear(); self._plain_buf.clear(); self._disabled = True; break
            parts.append(bytes(self._cipher_buf[:packet_len])); del self._cipher_buf[:packet_len]; del self._plain_buf[:packet_len]
        return parts
    def flush(self) -> List[bytes]:
        if not self._cipher_buf: return []
        tail = bytes(self._cipher_buf); self._cipher_buf.clear(); self._plain_buf.clear(); return [tail]
    def _next_packet_len(self) -> Optional[int]:
        if not self._plain_buf: return None
        if self._proto == _PROTO_ABRIDGED: return self._next_abridged_len()
        if self._proto in (_PROTO_INTERMEDIATE, _PROTO_PADDED_INTERMEDIATE): return self._next_intermediate_len()
        return 0
    def _next_abridged_len(self) -> Optional[int]:
        first = self._plain_buf[0]
        if first in (0x7F, 0xFF):
            if len(self._plain_buf) < 4: return None
            payload_len = int.from_bytes(self._plain_buf[1:4], 'little') * 4; header_len = 4
        else: payload_len = (first & 0x7F) * 4; header_len = 1
        if payload_len <= 0: return 0
        packet_len = header_len + payload_len
        return packet_len if len(self._plain_buf) >= packet_len else None
    def _next_intermediate_len(self) -> Optional[int]:
        if len(self._plain_buf) < 4: return None
        payload_len = _st_I_le.unpack_from(self._plain_buf, 0)[0] & 0x7FFFFFFF
        if payload_len <= 0: return 0
        packet_len = 4 + payload_len
        return packet_len if len(self._plain_buf) >= packet_len else None

# ======================== DC EXTRACTION & PATCH ========================
def _dc_from_init(data: bytes):
    try:
        cipher = Cipher(algorithms.AES(data[8:40]), modes.CTR(data[40:56]))
        encryptor = cipher.encryptor(); keystream = encryptor.update(_ZERO_64)
        plain = (int.from_bytes(data[56:64], 'big') ^ int.from_bytes(keystream[56:64], 'big')).to_bytes(8, 'big')
        proto, dc_raw = _st_Ih.unpack(plain[:6])
        if proto in _VALID_PROTOS:
            dc = abs(dc_raw)
            if 1 <= dc <= 5 or dc == 203: return dc, (dc_raw < 0), proto
            return None, False, proto
    except Exception as exc: log.debug("DC extraction failed: %s", exc)
    return None, False, None

def _patch_init_dc(data: bytes, dc: int) -> bytes:
    if len(data) < 64: return data
    new_dc = struct.pack('<h', dc)
    try:
        cipher = Cipher(algorithms.AES(data[8:40]), modes.CTR(data[40:56]))
        enc = cipher.encryptor(); ks = enc.update(_ZERO_64)
        patched = bytearray(data[:64]); patched[60] = ks[60] ^ new_dc[0]; patched[61] = ks[61] ^ new_dc[1]
        return bytes(patched) + data[64:] if len(data) > 64 else bytes(patched)
    except Exception: return data

# ======================== TCP PASSTHROUGH / FALLBACK ========================
async def _pipe_passthrough(reader, writer, dst, port, label, init_data: Optional[bytes] = None):
    log.info("[%s] [Passthrough] -> %s:%d", label, dst, port)
    try:
        rr, rw = await asyncio.wait_for(asyncio.open_connection(dst, port), timeout=10)
        _set_sock_opts(rw.transport)
    except Exception as exc:
        log.warning("[%s] Passthrough connect failed to %s:%d: %s", label, dst, port, exc)
        return
    if init_data:
        rw.write(init_data); await rw.drain()
    async def forward(src, dst_w, direction: str):
        try:
            while True:
                data = await src.read(65536)
                if not data:
                    log.debug("[%s] %s EOF", label, direction); break
                dst_w.write(data); await dst_w.drain()
        except (asyncio.CancelledError, ConnectionError, OSError, BrokenPipeError): pass
    t1 = asyncio.create_task(forward(reader, rw, "client->remote"))
    t2 = asyncio.create_task(forward(rr, writer, "remote->client"))
    try: await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in (t1, t2):
            if not t.done(): t.cancel()
        try: await t1; await t2
        except BaseException: pass
        for w in (writer, rw):
            try:
                if not w.is_closing(): w.close(); await w.wait_closed()
            except BaseException: pass
        log.info("[%s] Passthrough session closed", label)

async def _tcp_last_resort(reader, writer, dst, port, init, label):
    log.info("[%s] Last resort -> direct TCP to %s:%d", label, dst, port)
    await _pipe_passthrough(reader, writer, dst, port, label, init_data=init)

# ======================== BRIDGE LOGIC ========================
async def _bridge_cf_ws(client_reader, client_writer, ws: RawWebSocket, label: str,
                        dc: int, is_media: bool, splitter: Optional[MsgSplitter] = None):
    dc_tag = f"DC{dc}{'m' if is_media else ''}"
    up_bytes = down_bytes = up_packets = down_packets = 0
    start_time = asyncio.get_event_loop().time()
    async def tcp_to_ws():
        nonlocal up_bytes, up_packets
        try:
            while True:
                chunk = await client_reader.read(65536)
                if not chunk:
                    if splitter:
                        tail = splitter.flush()
                        if tail: await ws.send(tail[0])
                    break
                n = len(chunk); up_bytes += n; up_packets += 1
                if splitter:
                    parts = splitter.split(chunk)
                    if not parts: continue
                    await ws.send_batch(parts) if len(parts) > 1 else await ws.send(parts[0])
                else: await ws.send(chunk)
        except (asyncio.CancelledError, ConnectionError, OSError): pass
    async def ws_to_tcp():
        nonlocal down_bytes, down_packets
        try:
            while True:
                data = await ws.recv()
                if data is None: break
                n = len(data); down_bytes += n; down_packets += 1
                client_writer.write(data); await client_writer.drain()
        except (asyncio.CancelledError, ConnectionError, OSError): pass
    tasks = [asyncio.create_task(tcp_to_ws()), asyncio.create_task(ws_to_tcp())]
    try: await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in tasks: t.cancel()
        for t in tasks:
            try: await t
            except BaseException: pass
        elapsed = asyncio.get_event_loop().time() - start_time
        log.info("[%s] %s CF-WS session closed: ^%s (%d pkts) v%s (%d pkts) in %.1fs",
                 label, dc_tag, _human_bytes(up_bytes), up_packets, _human_bytes(down_bytes), down_packets, elapsed)
        try: await ws.close()
        except BaseException: pass
        try: client_writer.close(); await client_writer.wait_closed()
        except BaseException: pass

# ======================== SOCKS5 HANDLER ========================
_SOCKS5_REPLIES = {s: bytes([0x05, s, 0x00, 0x01, 0, 0, 0, 0, 0, 0]) for s in (0x00, 0x05, 0x07, 0x08)}
def _socks5_reply(status): return _SOCKS5_REPLIES[status]

async def _handle_client(reader, writer, cf_domain: str):
    peer = writer.get_extra_info('peername')
    label = f"{peer[0]}:{peer[1]}" if peer else "?"
    _set_sock_opts(writer.transport)
    try:
        # 1. SOCKS5 Greeting
        hdr = await asyncio.wait_for(reader.readexactly(2), timeout=10)
        if hdr[0] != 5:
            log.debug("[%s] not SOCKS5", label); writer.close(); return
        await reader.readexactly(hdr[1]); writer.write(b'\x05\x00'); await writer.drain()
        # 2. CONNECT Request
        req = await asyncio.wait_for(reader.readexactly(4), timeout=10)
        _ver, cmd, _rsv, atyp = req
        if cmd != 1:
            writer.write(_socks5_reply(0x07)); await writer.drain(); writer.close(); return
        if atyp == 1: dst = _socket.inet_ntoa(await reader.readexactly(4))
        elif atyp == 3:
            dlen = (await reader.readexactly(1))[0]; dst = (await reader.readexactly(dlen)).decode()
        elif atyp == 4:
            await reader.readexactly(16); writer.write(_socks5_reply(0x08)); await writer.drain(); writer.close(); return
        else:
            writer.write(_socks5_reply(0x08)); await writer.drain(); writer.close(); return
        port = _st_H.unpack(await reader.readexactly(2))[0]
        writer.write(_socks5_reply(0x00)); await writer.drain()

        # 🆕 [Unknown TG IP] Check
        if not _is_telegram_ip(dst):
            log.info("[%s] [Unknown TG IP] %s:%d -> direct TCP passthrough", label, dst, port)
            await _pipe_passthrough(reader, writer, dst, port, label)
            return

        # 3. Smart init read: peek first byte to route Browser/TLS vs MTProto
        first = await asyncio.wait_for(reader.read(1), timeout=10)
        if not first:
            log.debug("[%s] no data after SOCKS5", label); writer.close(); return
        fb = first[0]
        # TLS (0x16), HTTP GET (0x47), POST (0x50) -> Browser/WS
        if fb == 0x16 or fb == 0x47 or fb == 0x50:
            log.info("[%s] [Browser/TLS/HTTP] %s:%d -> passthrough", label, dst, port)
            await _pipe_passthrough(reader, writer, dst, port, label, init_data=first)
            return

        # Native MTProto client
        rest = await asyncio.wait_for(reader.readexactly(63), timeout=10)
        init = first + rest
        if _is_http_transport(init):
            log.debug("[%s] HTTP transport rejected", label); writer.close(); return

        # 4. Extract DC
        dc, is_media, proto = _dc_from_init(init)
        init_patched = False
        if dc is None:
            dc, is_media = _resolve_dc_from_ip(dst)
            init = _patch_init_dc(init, -dc if is_media else dc)
            init_patched = True
            log.debug("[%s] DC resolved from IP %s -> DC%d%s", label, dst, dc, ' media' if is_media else '')

        if dc not in (1, 2, 3, 4, 5, 203):
            log.warning("[%s] unknown DC for %s:%d -> TCP last resort", label, dst, port)
            await _tcp_last_resort(reader, writer, dst, port, init, label)
            return
        if dc == 203: dc = 2

        # 5. Попытка CF-WS
        domains = [f'kws{dc}.{cf_domain}']
        ws = None
        for domain in domains:
            log.info("[%s] DC%d%s (%s:%d) -> CF-WS %s", label, dc, ' media' if is_media else '', dst, port, domain)
            try:
                ws = await RawWebSocket.connect(domain, domain, timeout=10.0)
                break
            except WsHandshakeError as exc:
                log.warning("[%s] CF-WS handshake failed: %d %s", label, exc.status_code, exc.status_line)
            except Exception as exc:
                log.warning("[%s] CF-WS connect failed: %s", label, exc)

        if ws is None:
            log.error("[%s] All CF-WS endpoints failed for DC%d -> TCP last resort", label, dc)
            await _tcp_last_resort(reader, writer, dst, port, init, label)
            return

        # 6. Splitter & Bridge
        splitter = None
        if proto is not None and (init_patched or is_media or proto != _PROTO_INTERMEDIATE):
            try:
                splitter = MsgSplitter(init, proto)
                log.debug("[%s] MsgSplitter activated for proto 0x%08X", label, proto)
            except Exception: pass
        await ws.send(init)
        await _bridge_cf_ws(reader, writer, ws, label, dc, is_media, splitter)
    except asyncio.TimeoutError: log.warning("[%s] timeout during SOCKS5 handshake", label)
    except asyncio.IncompleteReadError: log.debug("[%s] client disconnected", label)
    except Exception as exc: log.error("[%s] unexpected: %s", label, exc, exc_info=True)
    finally:
        try:
            if not writer.is_closing(): writer.close(); await writer.wait_closed()
        except BaseException: pass

# ======================== MAIN ========================
async def _run(host: str, port: int, cf_domain: str):
    server = await asyncio.start_server(lambda r, w: _handle_client(r, w, cf_domain), host, port)
    for sock in server.sockets:
        try: sock.setsockopt(_socket.IPPROTO_TCP, _socket.TCP_NODELAY, 1)
        except: pass
    log.info("="*60)
    log.info("  Telegram SOCKS5 -> Cloudflare WS Bridge Proxy")
    log.info("  Listening on   %s:%d", host, port)
    log.info("  CF Domain:     %s", cf_domain)
    log.info("  Fallback:      Direct TCP (last resort)")
    log.info("  Browser supp:  TLS/HTTP passthrough")
    log.info("  DC Resolver:   Subnet-based (auto)")
    log.info("="*60)
    try: await server.serve_forever()
    except asyncio.CancelledError: pass

def main():
    ap = argparse.ArgumentParser(description='Telegram SOCKS5 -> CF WebSocket Proxy')
    ap.add_argument('--port', type=int, default=DEFAULT_PORT, help=f'Listen port (default {DEFAULT_PORT})')
    ap.add_argument('--host', type=str, default='0.0.0.0', help='Listen host')
    ap.add_argument('--cf-domain', type=str, required=True, help='Cloudflare proxy domain (e.g. example.com)')
    ap.add_argument('-v', '--verbose', action='store_true', help='Debug logging')
    args = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format='%(asctime)s %(levelname)-5s %(message)s', datefmt='%H:%M:%S')
    logging.getLogger('asyncio').setLevel(logging.WARNING)
    try: asyncio.run(_run(args.host, args.port, args.cf_domain.strip().rstrip('/')))
    except KeyboardInterrupt: log.info("Shutting down.")

if __name__ == '__main__':
    main()
