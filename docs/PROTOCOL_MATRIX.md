# Protocol coverage matrix

| Family | Protocol / mechanism | Material detected | Parsing model |
|---|---|---|---|
| Web/API | HTTP/1.x, WebDAV, WinRM-over-HTTP | Basic, Digest response, Bearer/API tokens, session cookies, URL-encoded/JSON/multipart/XML credential fields | TCP reassembly + HTTP framing, chunked transfer and gzip/deflate bodies |
| Real-time media | SIP, RTSP | Basic/Digest/Bearer and structured fields | HTTP-like message parser |
| Microsoft authentication | NTLMSSP over SMB, HTTP, LDAP, MSSQL, RPC and other carriers | Type 2 challenge, Type 3 NetNTLMv1/v2 material | Raw and Base64-wrapped NTLMSSP scan over reassembled streams |
| Kerberos | AS-REQ PA-ENC-TIMESTAMP | Etype 23 pre-authentication material; other etypes as metadata | ASN.1/DER parser over UDP and length-framed TCP |
| Mail/news | SMTP, IMAP, POP3, NNTP | AUTH PLAIN/LOGIN, USER/PASS, APOP, CRAM-MD5, OAuth bearer tokens | Stateful line protocol parser with STARTTLS transition tracking |
| Legacy/admin | FTP, Telnet, IRC | USER/PASS, prompt-response password, IRC PASS | Stateful line parser and Telnet IAC stripping |
| Directory/management | LDAP, SNMPv1/v2c | Simple Bind password, community strings | BER parser |
| Databases/cache | MSSQL, PostgreSQL, MySQL, Redis | LOGIN7 password, PostgreSQL cleartext/MD5/SCRAM metadata, MySQL cleartext/challenge response, Redis AUTH | Native binary/line protocol parsers |
| IoT/proxy/AAA | MQTT, AMQP 0-9-1, Memcached SASL, SOCKS5, RADIUS | CONNECT/SASL username-password, RFC 1929 credentials, PAP ciphertext, CHAP response, EAP identity | Native binary protocol parsers |
| Wireless/identity | EAPOL/EAP | EAP identities and EAPOL-Key handshake presence | Ethernet/802.11 L2 parser |
| Inventory | TLS, DNS, DHCP | SNI, ALPN, supported TLS versions, JA3-style fingerprint, DNS queries, DHCP hostnames | Metadata-only parsers |

## Deliberate non-features

The tool does not crack hashes, replay credentials, validate credentials against services, force protocol downgrade, or decrypt protected traffic. HTTP/2 and HTTP/3 application data remain encrypted in normal captures; only visible TLS metadata is inventoried. IP fragment reassembly is not currently implemented, so heavily fragmented application traffic can be incomplete.
