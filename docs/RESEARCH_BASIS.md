# Research basis

PCredz Ultimate is designed around protocol-aware parsing rather than packet-local keyword matching. The implementation was reviewed against primary specifications and official analyzer documentation.

## Transport and analyzer architecture

- Wireshark packet reassembly: https://www.wireshark.org/docs/wsug_html_chunked/ChAdvReassemblySection.html
- Wireshark protocol stream following: https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html
- Wireshark URL-encoded form fields: https://www.wireshark.org/docs/dfref/u/urlencoded-form.html
- Zeek protocol-analyzer reference: https://docs.zeek.org/en/lts/script-reference/proto-analyzers.html
- Zeek TCP reassembly events: https://docs.zeek.org/en/master/scripts/base/bif/plugins/Zeek_TCP.events.bif.zeek.html

These sources support the central design rule: transport data must be reassembled and then handed to a stateful application parser. A TCP packet can contain part of one message, multiple messages, a retransmission, or out-of-order data; a packet-local regular expression is therefore neither complete nor precise.

## Web and API authentication

- HTTP/1.1 message framing, RFC 9112: https://www.rfc-editor.org/rfc/rfc9112.html
- HTTP Basic, RFC 7617: https://www.rfc-editor.org/rfc/rfc7617.html
- HTTP Digest, RFC 7616: https://www.rfc-editor.org/rfc/rfc7616.html

The HTTP detector implements request/response framing, Content-Length, chunked transfer coding, gzip/deflate decoding, structured URL-encoded/JSON/multipart/XML fields, Basic/Digest/Bearer headers, cookies and common API-token headers. It searches binary bodies only after a protocol parser establishes that the content is plausibly structured text.

## Microsoft authentication

- Microsoft NTLM overview and message flow, MS-NLMP: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/c50a85f0-5940-42d8-9e82-ed206902e919
- NTLM connection-oriented call flow: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/1fbf5c3b-04c1-4591-a4be-9dc232c4744b
- NTLMv2 authentication: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/5e550938-91d4-459f-b67d-75d70009e3f3

The NTLM detector correlates Type 2 server challenges with Type 3 authentication messages over a reconstructed connection and supports raw NTLMSSP as well as Base64-wrapped HTTP Negotiate/NTLM carriers.

## Mail, directory, proxy and Kerberos authentication

- SASL PLAIN, RFC 4616: https://www.rfc-editor.org/rfc/rfc4616.html
- SMTP AUTH, RFC 4954: https://www.rfc-editor.org/rfc/rfc4954.html
- LDAP, RFC 4511: https://www.rfc-editor.org/rfc/rfc4511.html
- SOCKS5 username/password, RFC 1929: https://www.rfc-editor.org/rfc/rfc1929.html
- Kerberos, RFC 4120: https://www.rfc-editor.org/rfc/rfc4120.html
- Kerberos RC4-HMAC, RFC 4757: https://www.rfc-editor.org/rfc/rfc4757.html

State transitions such as STARTTLS, STLS and database SSL negotiation are tracked so encrypted application bytes are not later misclassified as plaintext credentials.

## Design implications applied in the code

1. Reassemble TCP by sequence number and suppress retransmissions/overlaps before application analysis.
2. Frame application messages according to the protocol instead of scanning arbitrary packet payloads.
3. Track originator/responder direction and encryption upgrades.
4. Correlate multi-message authentication exchanges, preserving challenge, salt, nonce, username and response relationships.
5. Use structured key classification for web forms, including dynamic numeric suffixes and context-aware identity resolution.
6. Preserve evidence provenance and emit deterministic JSONL, CSV, SQLite, protocol logs and HTML reports.
7. Redact secrets by default and require explicit operator switches for full secret or challenge-response export.
8. Never crack, replay, validate, inject, downgrade or actively solicit credentials.
