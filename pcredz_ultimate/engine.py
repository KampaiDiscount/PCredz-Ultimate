from __future__ import annotations

import ipaddress
import traceback
from collections import Counter
from pathlib import Path
from typing import Iterable, Iterator

from .capture import live_capture, read_capture
from .detectors.base import Detector
from .detectors.databases import DatabaseDetector
from .detectors.directory import DirectoryDetector
from .detectors.http import HTTPDetector
from .detectors.kerberos import KerberosDetector
from .detectors.line_auth import LineAuthDetector
from .detectors.messaging import MessagingDetector
from .detectors.metadata import MetadataDetector
from .detectors.ntlm import NTLMDetector
from .inventory import Inventory
from .models import CapturePacket, Endpoint, Finding, UDPDatagram
from .output import AuditWriter
from .packet import parse_packet
from .reassembly import TCPReassembler


class HostExclusions:
    """Exact-IP and CIDR exclusions for captures containing unrelated systems."""

    def __init__(self, values: Iterable[str] = ()):
        self.addresses: set[ipaddress._BaseAddress] = set()
        self.networks: list[ipaddress._BaseNetwork] = []
        self.names: set[str] = set()
        for raw in values:
            value = raw.strip()
            if not value:
                continue
            try:
                if '/' in value:
                    self.networks.append(ipaddress.ip_network(value, strict=False))
                else:
                    self.addresses.add(ipaddress.ip_address(value))
            except ValueError:
                self.names.add(value.lower())

    def matches(self, host: str) -> bool:
        if not host:
            return False
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            return host.lower() in self.names
        return addr in self.addresses or any(addr.version == net.version and addr in net for net in self.networks)


class AuditEngine:
    """Passive credential and authentication-material audit engine.

    The engine never transmits packets. Live capture is an input source only and
    is explicitly gated by the CLI.
    """

    def __init__(
        self,
        output_dir: str,
        *,
        reveal_secrets: bool = False,
        export_hashes: bool = False,
        write_html: bool = True,
        verbose: bool = False,
        disabled: Iterable[str] = (),
        excluded_hosts: Iterable[str] = (),
        max_stream_bytes: int = 4 * 1024 * 1024,
    ):
        self.inventory = Inventory()
        self.writer = AuditWriter(
            output_dir,
            reveal_secrets=reveal_secrets,
            export_hashes=export_hashes,
            write_html=write_html,
            verbose=verbose,
        )
        self.reassembler = TCPReassembler(max_pending_bytes=max_stream_bytes)
        self.disabled = {item.strip().lower() for item in disabled if item.strip()}
        self.exclusions = HostExclusions(excluded_hosts)
        self.verbose = verbose
        self.stats = Counter()
        self.stats.update({
            'capture_files': 0,
            'packets_seen': 0,
            'packets_decoded': 0,
            'packets_excluded': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'l2_packets': 0,
            'fragmented_packets': 0,
            'detector_errors': 0,
            'findings_written': 0,
        })
        self.current_capture = ''
        self.detectors: list[Detector] = [
            HTTPDetector(self.inventory, max_buffer=max_stream_bytes),
            LineAuthDetector(),
            NTLMDetector(max_buffer=min(max_stream_bytes, 2 * 1024 * 1024)),
            DirectoryDetector(max_buffer=min(max_stream_bytes, 2 * 1024 * 1024)),
            DatabaseDetector(),
            MessagingDetector(),
            KerberosDetector(),
            MetadataDetector(self.inventory),
        ]

    def _detector_enabled(self, detector: Detector) -> bool:
        return detector.name.lower() not in self.disabled

    def _finding_enabled(self, finding: Finding) -> bool:
        protocol = finding.protocol.lower()
        category = finding.category.lower()
        return protocol not in self.disabled and category not in self.disabled

    def _emit(self, findings: Iterable[Finding]) -> None:
        for finding in findings:
            if not finding or not self._finding_enabled(finding):
                continue
            if self.current_capture:
                finding.metadata.setdefault('capture_file', self.current_capture)
            if self.writer.add(finding):
                self.stats['findings_written'] += 1
                self.inventory.protocols[finding.protocol] += 1

    def _safe_detector_call(self, detector: Detector, method_name: str, value) -> None:
        if not self._detector_enabled(detector):
            return
        try:
            method = getattr(detector, method_name)
            findings = list(method(value))
            interface_name = getattr(value, 'interface_name', '')
            interface_id = getattr(value, 'interface_id', 0)
            for finding in findings:
                if interface_name:
                    finding.metadata.setdefault('interface_name', interface_name)
                if interface_id:
                    finding.metadata.setdefault('interface_id', interface_id)
            self._emit(findings)
        except Exception as exc:  # A malformed packet must not abort a long audit.
            self.stats['detector_errors'] += 1
            if self.verbose:
                print(f'[warning] detector={detector.name} method={method_name}: {exc}')
                traceback.print_exc()

    def process_packet(self, capture_packet: CapturePacket) -> None:
        self.stats['packets_seen'] += 1
        try:
            packet = parse_packet(capture_packet)
        except Exception as exc:
            self.stats['packet_decode_errors'] += 1
            if self.verbose:
                print(f'[warning] packet decode error: {exc}')
            return
        if packet is None:
            self.stats['unsupported_packets'] += 1
            return
        self.stats['packets_decoded'] += 1
        self.inventory.observe_packet(packet)

        if self.exclusions.matches(packet.src_ip) or self.exclusions.matches(packet.dst_ip):
            self.stats['packets_excluded'] += 1
            return
        if packet.fragmented:
            self.stats['fragmented_packets'] += 1

        if packet.l2_ethertype:
            self.stats['l2_packets'] += 1
            for detector in self.detectors:
                self._safe_detector_call(detector, 'on_l2', packet)

        if packet.protocol == 6:
            self.stats['tcp_packets'] += 1
            for chunk in self.reassembler.process(packet):
                self.stats['tcp_reassembled_bytes'] += len(chunk.data)
                for detector in self.detectors:
                    self._safe_detector_call(detector, 'on_tcp', chunk)
            if packet.timestamp:
                self.reassembler.expire(packet.timestamp)
            return

        if packet.protocol == 17:
            self.stats['udp_packets'] += 1
            datagram = UDPDatagram(
                timestamp=packet.timestamp,
                src=Endpoint(packet.src_ip, packet.src_port),
                dst=Endpoint(packet.dst_ip, packet.dst_port),
                data=packet.payload,
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                interface_id=packet.interface_id,
                interface_name=packet.interface_name,
            )
            for detector in self.detectors:
                self._safe_detector_call(detector, 'on_udp', datagram)

    def process_capture(self, path: str) -> None:
        self.current_capture = str(Path(path).resolve())
        self.stats['capture_files'] += 1
        for packet in read_capture(path):
            self.process_packet(packet)

    def process_capture_packets(self, packets: Iterable[CapturePacket], label: str = '<live>') -> None:
        self.current_capture = label
        for packet in packets:
            self.process_packet(packet)

    def finalize(self) -> None:
        for detector in self.detectors:
            if self._detector_enabled(detector):
                try:
                    self._emit(detector.finalize())
                except Exception as exc:
                    self.stats['detector_errors'] += 1
                    if self.verbose:
                        print(f'[warning] detector finalize={detector.name}: {exc}')
        self.writer.finalize(self.inventory.as_dict(), dict(self.stats))


def capture_files_in_directory(directory: str) -> list[str]:
    root = Path(directory)
    if not root.is_dir():
        raise NotADirectoryError(directory)
    extensions = {'.pcap', '.pcapng', '.cap', '.dump'}
    return [str(path) for path in sorted(root.rglob('*')) if path.is_file() and path.suffix.lower() in extensions]
