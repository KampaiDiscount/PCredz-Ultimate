from __future__ import annotations

from collections import defaultdict
from typing import Any

from .models import NetworkPacket


class Inventory:
    def __init__(self):
        self.hosts: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
        self.dns_queries: set[str] = set()
        self.tls_sni: set[str] = set()
        self.http_hosts: set[str] = set()
        self.user_agents: set[str] = set()
        self.protocols: dict[str, int] = defaultdict(int)
        self.interfaces: set[str] = set()

    def observe_packet(self, packet: NetworkPacket) -> None:
        if packet.interface_name:
            self.interfaces.add(packet.interface_name)
        for ip, mac in ((packet.src_ip, packet.src_mac), (packet.dst_ip, packet.dst_mac)):
            if ip and ip != 'l2':
                self.hosts[ip]['ips'].add(ip)
                if mac:
                    self.hosts[ip]['macs'].add(mac)

    def add_hostname(self, ip: str, hostname: str) -> None:
        if ip and hostname:
            self.hosts[ip]['hostnames'].add(hostname.rstrip('.'))

    def add_http_host(self, host: str) -> None:
        if host:
            self.http_hosts.add(host)

    def add_user_agent(self, ua: str) -> None:
        if ua:
            self.user_agents.add(ua)

    def add_sni(self, name: str) -> None:
        if name:
            self.tls_sni.add(name)

    def add_dns_query(self, name: str) -> None:
        if name:
            self.dns_queries.add(name.rstrip('.'))

    def as_dict(self) -> dict[str, Any]:
        return {
            'hosts': {
                ip: {k: sorted(v) for k, v in details.items()}
                for ip, details in sorted(self.hosts.items())
            },
            'dns_queries': sorted(self.dns_queries),
            'tls_sni': sorted(self.tls_sni),
            'http_hosts': sorted(self.http_hosts),
            'user_agents': sorted(self.user_agents),
            'interfaces': sorted(self.interfaces),
            'protocol_counts': dict(sorted(self.protocols.items())),
        }
