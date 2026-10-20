# nsconv 0.1.0-rc1

First test build, for lab testing before the field validation with real Huawei switches and FlowLink (F17).
- Receives Huawei NetStream NetFlow v5, v9 and IPFIX (UDP, default port 9996) from an allow-list of switches.
- Re-exports clean IPFIX (default), NetFlow v9 or v5 to a collector such as Illumio FlowLink, from the switch's
  own address (`source_address = "exporter"`, default) or from this host (`local`).
- Restamps skewed export clocks, forwards the sampling rate (override, reported, or default 1000 with a warning),
  sends octets as IE 1 and IE 85.
- Exact flow accounting: every datagram and flow is either forwarded or counted under a named reason.
- `nsconvctl`: `run`, `status`, `tui`, `logs`, `reload`, `config`, `decode`, `replay`, `debug-capture`,
  `dismiss`/`undismiss`, `install`/`uninstall`; warnings for sequence loss, collector down and missing sampling.
- RPM for EL8/EL9 (x86_64, aarch64) with a sandboxed systemd unit whose only capability is CAP_NET_RAW.
- Tested on Rocky Linux 8.10: RPM install, replayed Huawei captures reach a test collector unchanged, reload,
  restart, uninstall; fuzzed and load-tested. Not yet tested with real Huawei hardware or a real FlowLink.

## Supported systems
- RHEL, Rocky Linux and AlmaLinux 8 (x86_64 first) and 9; any Linux with kernel ≥ 4.18 for the static binary.
- `nsconvctl-0.1.0-rc1-aarch64-macos` (when present) runs `decode`, `replay` and `tui --demo` only.

## Verify
```
sha256sum -c SHA256SUMS
```
The artifacts are not signed; the checksums prove the download is intact, not who built it.

## Install
RPM (EL8/EL9): `sudo dnf install ./nsconv-0.1.0~rc1-1.x86_64.rpm`, then edit `/etc/nsconv/nsconv.toml` and
`sudo systemctl enable --now nsconv`.

Binary: `chmod +x nsconvctl-0.1.0-rc1-x86_64-linux && sudo ./nsconvctl-0.1.0-rc1-x86_64-linux install --enable`.

SBOM: `nsconv-0.1.0-rc1.cdx.json` (CycloneDX). The binaries embed their dependency list: `cargo audit bin <file>`.
