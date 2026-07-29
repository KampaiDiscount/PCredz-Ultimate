from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Optional
import hashlib


@dataclass(frozen=True, order=True)
class Endpoint:
    host: str
    port: int

    def __str__(self) -> str:
        if ':' in self.host and not self.host.startswith('['):
            return f'[{self.host}]:{self.port}'
        return f'{self.host}:{self.port}'


@dataclass
class CapturePacket:
    timestamp: float
    data: bytes
    linktype: int
    interface_id: int = 0
    interface_name: str = ''
    original_length: int = 0


@dataclass
class NetworkPacket:
    timestamp: float
    src_ip: str
    dst_ip: str
    protocol: int
    payload: bytes
    src_port: int = 0
    dst_port: int = 0
    tcp_seq: int = 0
    tcp_ack: int = 0
    tcp_flags: int = 0
    src_mac: str = ''
    dst_mac: str = ''
    interface_id: int = 0
    interface_name: str = ''
    ip_version: int = 0
    fragmented: bool = False
    l2_ethertype: int = 0
    raw_l2_payload: bytes = b''


@dataclass
class FlowContext:
    flow_id: str
    origin: Endpoint
    responder: Endpoint
    service_port: int
    protocol_hint: str = ''
    first_seen: float = 0.0
    last_seen: float = 0.0


@dataclass
class TCPChunk:
    timestamp: float
    flow: FlowContext
    direction: str  # "orig" or "resp"
    src: Endpoint
    dst: Endpoint
    data: bytes
    interface_id: int = 0
    interface_name: str = ''


@dataclass
class UDPDatagram:
    timestamp: float
    src: Endpoint
    dst: Endpoint
    data: bytes
    src_ip: str
    dst_ip: str
    interface_id: int = 0
    interface_name: str = ''


@dataclass
class Finding:
    timestamp: float
    protocol: str
    category: str
    severity: str
    title: str
    src: Endpoint
    dst: Endpoint
    flow_id: str = ''
    username: str = ''
    secret: str = ''
    secret_type: str = ''
    evidence: str = ''
    metadata: dict[str, Any] = field(default_factory=dict)
    finding_id: str = ''

    def secret_fingerprint(self) -> str:
        if not self.secret:
            return ''
        return hashlib.sha256(self.secret.encode('utf-8', errors='surrogatepass')).hexdigest()

    def stable_key(self) -> str:
        material = '\x1f'.join([
            self.protocol.lower(),
            self.category.lower(),
            str(self.src),
            str(self.dst),
            self.username,
            self.secret_fingerprint(),
            self.title,
        ])
        return hashlib.sha256(material.encode('utf-8', errors='ignore')).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result['src'] = str(self.src)
        result['dst'] = str(self.dst)
        result['secret_fingerprint'] = self.secret_fingerprint()
        return result
