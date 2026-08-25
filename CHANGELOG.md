# Changelog

All notable changes to this project are documented in this file.

## [1.0.0] - 2026-08-24

### Added
- Initial release.
- Redaction of IPv4/IPv6 addresses, MAC addresses, emails, generic
  hostnames/FQDNs, and common credential patterns (AWS keys, GitHub/Slack
  tokens, JWTs, Bearer tokens, PEM private keys, password/api_key/secret
  assignments).
- `--domain` flag for client-specific domains not covered by the generic
  hostname pattern.
- `--stdout` and `--suffix` options.
- IPv6 detection with timestamp false-positive filtering.
- Full unit test suite (24 tests).
- Snap packaging (strict confinement, core22, amd64/arm64).
