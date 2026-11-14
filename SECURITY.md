# Security policy

CipherSight processes untrusted image and archive data. Use it in a controlled environment and keep Python and Pillow updated.

## Safe handling
- CipherSight should not execute extracted files or recovered payloads.
- Treat generated reports and candidate exports as sensitive; they can contain EXIF GPS, strings, and challenge secrets.
- Do not expose the local web interface to an untrusted network.
- Use conservative resource limits when scanning unknown files.

## Reporting a vulnerability
Do not publish exploit details or malicious sample files in a public issue before maintainers have had a chance to assess the issue. Provide a minimal reproduction, affected version, environment, and impact through a private maintainer contact if one is available.
