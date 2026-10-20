#!/usr/bin/env python3
# nsconv test kit: write a pcap of Huawei-style NetStream datagrams (NetFlow v5, v9 or IPFIX) for tcpreplay or
# `nsconvctl replay`. No external modules; runs with RHEL 8 /usr/libexec/platform-python (3.6) and newer.
#
# Record layouts are modelled on published Huawei captures (v9 template 1315 / 1507 field order, IPFIX
# template 2599 with relative times + IE 160 in every record and PEN 2011 enterprise fields, UDP source port
# 40000, templates in their own datagrams before the data, periodic template refresh). All values are synthetic.
#
# Examples:
#   nsconv-sample-pcap.py --version 9 --out sample-v9.pcap
#   nsconv-sample-pcap.py --version ipfix --ipv6 --switch 198.51.100.21,198.51.100.22 --flows 500 --out v6.pcap
#   nsconv-sample-pcap.py --version 5 --dst 192.0.2.10 --dst-mac 52:54:00:12:34:56 --out v5.pcap
#   nsconv-sample-pcap.py --version 9 --out s.pcap --check            # decode it with nsconvctl and compare
from __future__ import print_function

import argparse
import ipaddress
import json
import random
import socket
import struct
import subprocess
import sys
import time

PEN_HUAWEI = 2011


def mac(s):
    b = bytes(int(x, 16) for x in s.split(":"))
    if len(b) != 6:
        raise argparse.ArgumentTypeError("MAC must look like 02:00:00:00:00:01")
    return b


def addrs(spec, limit):
    """'10.1.0.0/24,10.9.9.9' -> list of address strings (hosts of each CIDR, at most `limit` in total)."""
    out = []
    for part in spec.split(","):
        net = ipaddress.ip_network(part.strip(), strict=False)
        hosts = [net.network_address] if net.num_addresses == 1 else net.hosts()
        for h in hosts:
            out.append(str(h))
            if len(out) >= limit:
                return out
    return out


def csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def frame(a, src_ip, payload, ident):
    """Ethernet + IPv4 + UDP around one NetStream payload (exporter transport is IPv4)."""
    s = socket.inet_aton(src_ip)
    d = socket.inet_aton(a.dst)
    ulen = 8 + len(payload)
    pseudo = s + d + struct.pack("!BBH", 0, 17, ulen)
    udp = struct.pack("!HHHH", a.sport, a.dport, ulen, 0) + payload
    uc = csum(pseudo + udp) or 0xFFFF
    udp = udp[:6] + struct.pack("!H", uc) + udp[8:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + ulen, ident & 0xFFFF, 0x4000, 64, 17, 0, s, d)
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    return a.dst_mac + a.src_mac + b"\x08\x00" + ip + udp


# ---- flows ----------------------------------------------------------------------------------------------

def make_flows(a, now_ms):
    rnd = random.Random(a.seed)
    srcs = addrs(a.src, 4096)
    dsts = addrs(a.dst_hosts, 4096)
    if not srcs or not dsts:
        sys.exit("--src and --dst-hosts must contain at least one address")
    if any((":" in x) != a.ipv6 for x in srcs + dsts):
        sys.exit("--src/--dst-hosts must all be IPv4, or all IPv6 together with --ipv6")
    ports = [int(p) for p in a.dst_ports.split(",")]
    flows = []
    for i in range(a.flows):
        dp = ports[i % len(ports)]
        pk = rnd.randint(1, 20)
        end = now_ms - rnd.randint(1000, 30000)
        flows.append({
            "src": srcs[i % len(srcs)],
            "dst": dsts[(i // len(srcs)) % len(dsts)],
            "src_port": 32768 + (i % 28000),
            "dst_port": dp,
            "proto": 17 if dp in (53, 123, 161, 514) else 6,
            "packets": pk,
            "bytes": pk * rnd.randint(60, 1500),
            "start_ms": end - rnd.randint(0, 60000),
            "end_ms": end,
            "tcp_flags": 0x1B,
            "in_if": 1 + i % 48,
            "out_if": 49,
        })
    return flows


def ipb(s):
    return ipaddress.ip_address(s).packed


# ---- NetFlow v5 (48-byte records, sampling_interval left 0 as Huawei does) -------------------------------

def v5_datagrams(a, ex, flows):
    for k in range(0, len(flows), 30):
        chunk = flows[k:k + 30]
        secs = ex.now_ms // 1000
        up = secs * 1000 - ex.boot_ms
        body = b""
        for f in chunk:
            body += struct.pack(
                "!4s4s4sHHIIIIHHBBBBHHBBH",
                ipb(f["src"]), ipb(f["dst"]), b"\0\0\0\0", f["in_if"], f["out_if"], f["packets"], f["bytes"],
                f["start_ms"] - ex.boot_ms, f["end_ms"] - ex.boot_ms, f["src_port"], f["dst_port"], 0,
                f["tcp_flags"], f["proto"], 0, 0, 0, 24, 24, 0)
        hdr = struct.pack("!HHIIIIBBH", 5, len(chunk), up, secs, 0, ex.seq, 0, ex.domain & 0xFF, 0)
        ex.seq += len(chunk)
        yield hdr + body


# ---- v9 / IPFIX templates --------------------------------------------------------------------------------
# (ie, length, value-key) ; enterprise fields as (ie, length, None, pen). 'pad' = paddingOctets.

V9_V4 = [(8, 4, "src"), (12, 4, "dst"), (15, 4, "zero"), (2, 4, "packets"), (1, 4, "bytes"),
         (22, 4, "first"), (21, 4, "last"), (18, 4, "zero"), (10, 2, "in_if"), (14, 2, "out_if"),
         (7, 2, "src_port"), (11, 2, "dst_port"), (16, 2, "zero"), (17, 2, "zero"), (58, 2, "zero"),
         (59, 2, "zero"), (232, 2, "zero"), (6, 1, "tcp_flags"), (4, 1, "proto"), (5, 1, "zero"),
         (9, 1, "mask"), (13, 1, "mask"), (61, 1, "zero"), (89, 1, "fwd"), (210, 3, "zero")]
# Template 1507 order: 32-bit ifIndex and SAMPLING_INTERVAL / SAMPLING_ALGORITHM in every record.
V9_V4_SAMPLED = [(8, 4, "src"), (12, 4, "dst"), (15, 4, "zero"), (2, 4, "packets"), (1, 4, "bytes"),
                 (22, 4, "first"), (21, 4, "last"), (18, 4, "zero"), (10, 4, "in_if"), (14, 4, "out_if"),
                 (7, 2, "src_port"), (11, 2, "dst_port"), (16, 2, "zero"), (17, 2, "zero"), (58, 2, "zero"),
                 (59, 2, "zero"), (6, 1, "tcp_flags"), (4, 1, "proto"), (5, 1, "zero"), (61, 1, "zero"),
                 (34, 4, "rate"), (35, 1, "algo"), (9, 1, "mask"), (13, 1, "mask")]
V9_V6 = [(27, 16, "src"), (28, 16, "dst"), (62, 16, "zero"), (2, 4, "packets"), (1, 4, "bytes"),
         (22, 4, "first"), (21, 4, "last"), (63, 16, "zero"), (10, 4, "in_if"), (14, 4, "out_if"),
         (7, 2, "src_port"), (11, 2, "dst_port"), (16, 2, "zero"), (17, 2, "zero"), (58, 2, "zero"),
         (59, 2, "zero"), (232, 2, "zero"), (6, 1, "tcp_flags"), (4, 1, "proto"), (5, 1, "zero"),
         (29, 1, "mask6"), (30, 1, "mask6"), (61, 1, "zero"), (89, 1, "fwd"), (31, 3, "zero")]
SAMPLED_V6_TAIL = [(34, 4, "rate"), (35, 1, "algo"), (210, 3, "zero")]
# IPFIX (template 2599 skeleton): relative times 22/21 plus systemInitTimeMilliseconds 160 in every record,
# Huawei enterprise IEs (PEN 2011) 232 and 701-704 that collectors must skip.
IPFIX_HEAD_V4 = [(8, 4, "src"), (12, 4, "dst"), (15, 4, "zero")]
IPFIX_HEAD_V6 = [(27, 16, "src"), (28, 16, "dst"), (62, 16, "zero")]
IPFIX_BODY = [(2, 4, "packets"), (1, 4, "bytes"), (22, 4, "first"), (21, 4, "last"), (160, 8, "init"),
              (10, 4, "in_if"), (14, 4, "out_if"), (16, 2, "zero"), (17, 2, "zero"), (7, 2, "src_port"),
              (11, 2, "dst_port"), (58, 2, "zero"), (59, 2, "zero"), (232, 2, "one", PEN_HUAWEI),
              (6, 1, "tcp_flags"), (4, 1, "proto"), (5, 1, "zero"), (61, 1, "zero"), (89, 1, "fwd"),
              (136, 1, "reason"), (48, 4, "in_if"), (302, 8, "zero"), (701, 4, "zero", PEN_HUAWEI),
              (702, 4, "zero", PEN_HUAWEI), (703, 4, "zero", PEN_HUAWEI), (704, 8, "zero", PEN_HUAWEI),
              (210, 3, "zero")]


def template(a):
    if a.version == 10:
        t = (IPFIX_HEAD_V6 if a.ipv6 else IPFIX_HEAD_V4) + IPFIX_BODY
        if a.sampling:
            t = t[:-1] + [(34, 4, "rate"), (35, 1, "algo"), (210, 2, "zero")]
        return (2599 if a.ipv6 else 2598), t
    if a.ipv6:
        return 1316, (V9_V6 + SAMPLED_V6_TAIL if a.sampling else V9_V6)
    return (1507, V9_V4_SAMPLED) if a.sampling else (1315, V9_V4)


def value(key, f, ex, a):
    if key in ("src", "dst"):
        return ipb(f[key])
    v = {
        "zero": 0, "one": 1, "fwd": 0x40, "reason": 2, "algo": 2, "rate": a.sampling, "init": ex.boot_ms,
        "mask": 24, "mask6": 64, "first": f["start_ms"] - ex.boot_ms, "last": f["end_ms"] - ex.boot_ms,
    }.get(key)
    return f[key] if v is None else v


def record(fields, f, ex, a):
    out = b""
    for fl in fields:
        ie, ln, key = fl[0], fl[1], fl[2]
        v = value(key, f, ex, a)
        out += v if isinstance(v, bytes) else (v & ((1 << (8 * ln)) - 1)).to_bytes(ln, "big")
    return out


def tmpl_set(a, tid, fields):
    spec = b""
    for fl in fields:
        if len(fl) == 4 and a.version == 10:
            spec += struct.pack("!HHI", 0x8000 | fl[0], fl[1], fl[3])
        else:  # Huawei sends its private 232 without a PEN in v9
            spec += struct.pack("!HH", fl[0], fl[1])
    rec = struct.pack("!HH", tid, len(fields)) + spec
    return struct.pack("!HH", 2 if a.version == 10 else 0, 4 + len(rec)) + rec


def message(a, ex, sets, nrec):
    body = b"".join(sets)
    secs = ex.now_ms // 1000
    if a.version == 10:  # Huawei counts IPFIX messages, not records, in the sequence number
        hdr = struct.pack("!HHIII", 10, 16 + len(body), secs, ex.seq, ex.domain)
        ex.seq += 1
    else:
        hdr = struct.pack("!HHIIII", 9, nrec, secs * 1000 - ex.boot_ms, secs, ex.seq, ex.domain)
        ex.seq += 1
    return hdr + body


def v9_datagrams(a, ex, flows):
    tid, fields = template(a)
    tset = tmpl_set(a, tid, fields)
    rec_len = sum(fl[1] for fl in fields)
    # v9 header 20 B, IPFIX 16 B, data set header 4 B, up to 3 pad bytes; datagrams stay <= --max-datagram
    per = max(1, (a.max_datagram - 20 - 4 - 3) // rec_len)
    sent = 0
    for k in range(0, len(flows), per):
        if sent % a.template_every == 0 and not a.data_only:
            yield message(a, ex, [tset], 1)  # templates in their own datagram, before the data
        chunk = flows[k:k + per]
        data = b"".join(record(fields, f, ex, a) for f in chunk)
        if a.version == 9:
            data += b"\0" * (-(4 + len(data)) % 4)  # Huawei pads v9 data FlowSets to 4 bytes
        yield message(a, ex, [struct.pack("!HH", tid, 4 + len(data)) + data], len(chunk))
        sent += 1


class Exporter(object):
    def __init__(self, ip, domain, now_ms):
        self.ip = ip
        self.domain = domain
        self.now_ms = now_ms
        self.boot_ms = now_ms - 9 * 86400 * 1000  # the switch booted 9 days ago (sysUptime < 2^32 ms)
        self.seq = 1


def write_pcap(a, frames):
    with open(a.out, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, fr in frames:
            fh.write(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(fr), len(fr)) + fr)


def check(a, flows):
    """Decode the written pcap with nsconvctl and compare every flow with what was generated."""
    cmd = [a.nsconvctl, "--json", "decode", a.out]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()
    if p.returncode != 0:
        sys.exit("check: {} failed ({}): {}".format(" ".join(cmd), p.returncode, err.decode(errors="replace")))
    keys = ("exporter", "src", "dst", "src_port", "dst_port", "proto", "packets", "bytes", "start_ms", "end_ms")
    got = sorted(tuple(d[k] for k in keys) for d in map(json.loads, out.decode().splitlines())
                 if d.get("type") == "flow")
    want = sorted(tuple(f[k] for k in keys) for f in flows)
    bad = [] if got == want else [x for x in set(want) ^ set(got)][:5]
    samp = set(d.get("sampling") for d in map(json.loads, out.decode().splitlines()) if d.get("type") == "flow")
    if a.sampling and a.version != 5 and samp != {a.sampling}:
        bad.append("sampling decoded as {} instead of {}".format(sorted(samp), a.sampling))
    if bad or len(got) != len(want):
        sys.exit("check FAILED: generated {} flows, decoded {}; first differences: {}".format(
            len(want), len(got), bad))
    print("check OK: {} decoded {} of {} flows with identical addresses, ports, protocol, packets, bytes "
          "and times".format(a.nsconvctl, len(got), len(want)))


def main():
    p = argparse.ArgumentParser(description="Write a pcap of Huawei-style NetStream datagrams (synthetic data).")
    p.add_argument("--version", default="9", choices=["5", "9", "10", "ipfix"], help="export version (default 9)")
    p.add_argument("--out", required=True, help="output .pcap file")
    p.add_argument("--switch", default="198.51.100.21",
                   help="exporter (switch) IPv4 source address(es), comma separated (default 198.51.100.21)")
    p.add_argument("--sport", type=int, default=40000, help="exporter UDP source port (Huawei default 40000)")
    p.add_argument("--dst", default="192.0.2.10", help="nsconv host IPv4 address (default 192.0.2.10)")
    p.add_argument("--dport", type=int, default=9996, help="nsconv input UDP port (default 9996)")
    p.add_argument("--src-mac", type=mac, default=mac("02:00:00:00:00:01"), help="source MAC of the frames")
    p.add_argument("--dst-mac", type=mac, default=mac("02:00:00:00:00:02"),
                   help="destination MAC: the nsconv host NIC (needed for tcpreplay)")
    p.add_argument("--src", default=None, help="workload source IPs or CIDRs, comma separated")
    p.add_argument("--dst-hosts", default=None, help="workload destination IPs or CIDRs, comma separated")
    p.add_argument("--dst-ports", default="443,22,3306,8080,53", help="destination ports used in turn")
    p.add_argument("--flows", type=int, default=200, help="flows per switch (default 200)")
    p.add_argument("--ipv6", action="store_true", help="IPv6 workload flows (v9 and IPFIX only)")
    p.add_argument("--sampling", type=int, default=0,
                   help="1-in-N rate written as IE 34 in every v9/IPFIX record (0 = not reported, default)")
    p.add_argument("--domain", type=int, default=0, help="v9 Source ID / IPFIX ODID / v5 engine id (default 0)")
    p.add_argument("--template-every", type=int, default=10, help="repeat the template every N data datagrams")
    p.add_argument("--data-only", action="store_true",
                   help="no template datagrams (tests templates restored after an nsconv restart)")
    p.add_argument("--max-datagram", type=int, default=1400, help="largest NetStream payload in bytes")
    p.add_argument("--pps", type=float, default=100, help="datagram rate written into the pcap timestamps")
    p.add_argument("--seed", type=int, default=1, help="random seed for counters and times")
    p.add_argument("--expect", help="also write the generated flows as JSON lines to this file")
    p.add_argument("--check", action="store_true", help="decode the pcap with nsconvctl and compare")
    p.add_argument("--nsconvctl", default="nsconvctl", help="nsconvctl binary for --check")
    a = p.parse_args()
    a.version = 10 if a.version == "ipfix" else int(a.version)
    if a.ipv6 and a.version == 5:
        sys.exit("NetFlow v5 carries IPv4 only: use --version 9 or ipfix with --ipv6")
    if a.flows < 1 or a.template_every < 1 or a.pps <= 0 or not 0 <= a.sampling < 2 ** 32:
        sys.exit("--flows, --template-every and --pps must be positive, --sampling 0..2^32-1")
    a.src = a.src or ("2001:db8:a::/112" if a.ipv6 else "10.1.1.0/24")
    a.dst_hosts = a.dst_hosts or ("2001:db8:b::/112" if a.ipv6 else "10.2.2.0/24")

    now_ms = int(time.time()) * 1000
    frames, all_flows, ident, ts = [], [], 1, now_ms / 1000.0
    gens = []
    for n, ip in enumerate(x.strip() for x in a.switch.split(",")):
        ex = Exporter(ip, a.domain, now_ms)
        flows = make_flows(a, now_ms)
        # each switch gets its own workload flows: shift the seed so counters differ too
        a.seed += 1
        for f in flows:
            f["exporter"] = "{}:{}".format(ip, a.sport)
        all_flows += flows
        gens.append((ip, (v5_datagrams if a.version == 5 else v9_datagrams)(a, ex, flows)))
    while gens:  # interleave the switches datagram by datagram
        for g in list(gens):
            pl = next(g[1], None)
            if pl is None:
                gens.remove(g)
                continue
            frames.append((ts, frame(a, g[0], pl, ident)))
            ident += 1
            ts += 1.0 / a.pps
    write_pcap(a, frames)
    print("wrote {}: {} datagrams, {} flows, NetFlow v{} {} from {} (UDP {}) to {}:{}{}".format(
        a.out, len(frames), len(all_flows), a.version, "IPv6" if a.ipv6 else "IPv4", a.switch, a.sport, a.dst,
        a.dport, ", sampling 1:{}".format(a.sampling) if a.sampling else ""))
    if a.expect:
        with open(a.expect, "w") as fh:
            for f in all_flows:
                fh.write(json.dumps(f, sort_keys=True) + "\n")
    if a.check:
        if a.data_only:
            sys.exit("--check needs the templates in the file: drop --data-only")
        check(a, all_flows)


if __name__ == "__main__":
    main()
