from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, Optional
import hashlib

from .models import Endpoint, FlowContext, NetworkPacket, TCPChunk


KNOWN_SERVICE_PORTS = {
    20, 21, 22, 23, 25, 53, 80, 81, 110, 119, 135, 139, 143, 389, 443,
    445, 465, 554, 587, 636, 993, 995, 1080, 1433, 1521, 1883, 3306,
    3389, 5432, 5672, 5900, 5985, 6379, 8000, 8008, 8080, 8081, 8443,
    8883, 8888, 9200, 11211, 27017,
}
PORT_HINTS = {
    21: 'ftp', 23: 'telnet', 25: 'smtp', 80: 'http', 81: 'http', 110: 'pop3',
    119: 'nntp', 143: 'imap', 389: 'ldap', 443: 'tls', 445: 'smb', 465: 'tls',
    554: 'rtsp', 587: 'smtp', 636: 'tls', 993: 'tls', 995: 'tls', 1080: 'socks5',
    1433: 'mssql', 1883: 'mqtt', 3306: 'mysql', 5432: 'postgresql', 5672: 'amqp',
    5900: 'vnc', 5985: 'http', 6379: 'redis', 8000: 'http', 8008: 'http',
    8080: 'http', 8081: 'http', 8443: 'tls', 8883: 'tls', 8888: 'http',
    9200: 'http', 11211: 'memcached', 27017: 'mongodb',
}


def _endpoint_key(ep: Endpoint) -> tuple[str, int]:
    return ep.host, ep.port


def _flow_id(a: Endpoint, b: Endpoint) -> str:
    ordered = sorted([str(a), str(b)])
    return hashlib.sha1('|'.join(ordered).encode()).hexdigest()[:16]


@dataclass
class DirectionAssembler:
    next_seq: Optional[int] = None
    pending: Dict[int, bytes] = field(default_factory=dict)
    max_pending_bytes: int = 4 * 1024 * 1024

    def seed(self, seq: int) -> None:
        if self.next_seq is None:
            self.next_seq = seq & 0xFFFFFFFF

    def add(self, seq: int, data: bytes) -> bytes:
        if not data:
            return b''
        seq &= 0xFFFFFFFF
        if self.next_seq is None:
            self.next_seq = seq

        # This implementation assumes captures do not span a full 2^32 sequence wrap.
        end = seq + len(data)
        if end <= self.next_seq:
            return b''
        if seq < self.next_seq:
            data = data[self.next_seq - seq:]
            seq = self.next_seq
        if not data:
            return b''

        existing = self.pending.get(seq)
        if existing is None or len(data) > len(existing):
            self.pending[seq] = data

        if sum(len(v) for v in self.pending.values()) > self.max_pending_bytes:
            # Preserve the closest segments and discard distant gaps.
            self.pending = dict(sorted(self.pending.items(), key=lambda kv: abs(kv[0] - (self.next_seq or 0)))[:256])

        output = bytearray()
        while True:
            candidates = [(s, d) for s, d in self.pending.items() if s <= self.next_seq < s + len(d)]
            if not candidates:
                break
            s, d = max(candidates, key=lambda item: item[0] + len(item[1]))
            del self.pending[s]
            offset = self.next_seq - s
            piece = d[offset:]
            if not piece:
                continue
            output.extend(piece)
            self.next_seq += len(piece)

            # Remove retransmissions now fully covered.
            for old_s in list(self.pending):
                if old_s + len(self.pending[old_s]) <= self.next_seq:
                    del self.pending[old_s]
        return bytes(output)


@dataclass
class TCPConnection:
    context: FlowContext
    orig_stream: DirectionAssembler = field(default_factory=DirectionAssembler)
    resp_stream: DirectionAssembler = field(default_factory=DirectionAssembler)


class TCPReassembler:
    def __init__(self, max_pending_bytes: int = 4 * 1024 * 1024):
        self.connections: dict[tuple[tuple[str, int], tuple[str, int]], TCPConnection] = {}
        self.max_pending_bytes = max_pending_bytes

    @staticmethod
    def _canonical(src: Endpoint, dst: Endpoint) -> tuple[tuple[str, int], tuple[str, int]]:
        a, b = _endpoint_key(src), _endpoint_key(dst)
        return (a, b) if a <= b else (b, a)

    def _choose_roles(self, packet: NetworkPacket, src: Endpoint, dst: Endpoint) -> tuple[Endpoint, Endpoint]:
        syn = bool(packet.tcp_flags & 0x02)
        ack = bool(packet.tcp_flags & 0x10)
        if syn and not ack:
            return src, dst
        if dst.port in KNOWN_SERVICE_PORTS and src.port not in KNOWN_SERVICE_PORTS:
            return src, dst
        if src.port in KNOWN_SERVICE_PORTS and dst.port not in KNOWN_SERVICE_PORTS:
            return dst, src
        # Ephemeral ports are normally higher than service ports.
        if src.port > dst.port:
            return src, dst
        return dst, src

    def process(self, packet: NetworkPacket) -> list[TCPChunk]:
        if packet.protocol != 6:
            return []
        src = Endpoint(packet.src_ip, packet.src_port)
        dst = Endpoint(packet.dst_ip, packet.dst_port)
        key = self._canonical(src, dst)
        conn = self.connections.get(key)
        if conn is None:
            origin, responder = self._choose_roles(packet, src, dst)
            service_port = responder.port
            context = FlowContext(
                flow_id=_flow_id(origin, responder),
                origin=origin,
                responder=responder,
                service_port=service_port,
                protocol_hint=PORT_HINTS.get(service_port, ''),
                first_seen=packet.timestamp,
                last_seen=packet.timestamp,
            )
            conn = TCPConnection(
                context=context,
                orig_stream=DirectionAssembler(max_pending_bytes=self.max_pending_bytes),
                resp_stream=DirectionAssembler(max_pending_bytes=self.max_pending_bytes),
            )
            self.connections[key] = conn

        conn.context.last_seen = packet.timestamp
        direction = 'orig' if src == conn.context.origin else 'resp'
        stream = conn.orig_stream if direction == 'orig' else conn.resp_stream

        if packet.tcp_flags & 0x02:  # SYN consumes one sequence number.
            stream.seed(packet.tcp_seq + 1)
        assembled = stream.add(packet.tcp_seq, packet.payload)
        if not assembled:
            return []
        return [TCPChunk(packet.timestamp, conn.context, direction, src, dst, assembled,
                         packet.interface_id, packet.interface_name)]

    def expire(self, now: float, idle_seconds: float = 300.0) -> None:
        for key in list(self.connections):
            if now - self.connections[key].context.last_seen > idle_seconds:
                del self.connections[key]
