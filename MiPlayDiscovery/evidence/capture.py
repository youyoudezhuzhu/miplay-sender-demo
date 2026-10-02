#!/usr/bin/env python3
"""MiPlay (Xiaomi 妙播) mDNS discovery capture/verification probe.

Sender side only. Sends a standard DNS-SD PTR browse for each MiPlay service
type using the QU (unicast-response) bit from an EPHEMERAL source port, then
records every reply verbatim (hex) plus a decoded view.

Usage: python3 capture.py [interface_ip] [seconds] [outfile]
"""
from __future__ import annotations
import base64, datetime as dt, json, socket, struct, sys, time

MDNS_ADDR = "224.0.0.251"
MDNS_PORT = 5353
SERVICES = ["_mi-connect._udp.local.", "_lyra-mdns._udp.local."]
# QU bit => "unicast response requested"; mirrors Xiaomi's own MAFSvr sender.
QU_CLASS = 0x8001


def encode_name(name: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode() for p in name.rstrip(".").split(".")) + b"\0"


def build_query(name: str) -> bytes:
    hdr = struct.pack("!6H", 0, 0, 1, 0, 0, 0)
    return hdr + encode_name(name) + struct.pack("!HH", 12, QU_CLASS)


def read_name(pkt: bytes, off: int, depth: int = 0):
    labels, cursor, end = [], off, None
    if depth > 8:
        raise ValueError("pointer recursion")
    while True:
        if cursor >= len(pkt):
            raise ValueError("truncated name")
        n = pkt[cursor]
        if n & 0xC0 == 0xC0:
            ptr = ((n & 0x3F) << 8) | pkt[cursor + 1]
            if end is None:
                end = cursor + 2
            nested, _ = read_name(pkt, ptr, depth + 1)
            labels.extend(nested.rstrip(".").split("."))
            cursor = end
            break
        cursor += 1
        if n == 0:
            break
        labels.append(pkt[cursor:cursor + n].decode("utf-8", "replace"))
        cursor += n
    return ".".join(labels) + ".", (end if end is not None else cursor)


def read_txt(data: bytes):
    out, i = [], 0
    while i < len(data):
        n = data[i]
        i += 1
        out.append(data[i:i + n].decode("utf-8", "replace"))
        i += n
    return out


def decode_packet(pkt: bytes) -> dict:
    if len(pkt) < 12:
        return {"error": "short packet"}
    tid, flags, qd, an, ns, ar = struct.unpack_from("!6H", pkt)
    rec = {"id": tid, "flags": f"0x{flags:04x}", "qd": qd, "an": an, "ns": ns, "ar": ar,
           "questions": [], "records": []}
    c = 12
    for _ in range(qd):
        name, c = read_name(pkt, c)
        qt, qc = struct.unpack_from("!HH", pkt, c)
        c += 4
        rec["questions"].append({"name": name, "type": qt, "class": f"0x{qc:04x}"})
    for section, count in (("answer", an), ("authority", ns), ("additional", ar)):
        for _ in range(count):
            name, c = read_name(pkt, c)
            rtype, rclass, ttl, ln = struct.unpack_from("!HHIH", pkt, c)
            c += 10
            rdata_off = c
            data = pkt[c:c + ln]
            c += ln
            entry = {"section": section, "name": name, "type": rtype,
                     "class": f"0x{rclass:04x}", "ttl": ttl, "rdlength": ln}
            if rtype in (12, 5, 2):
                entry["value"] = read_name(pkt, rdata_off)[0]
            elif rtype == 16:
                entry["txt"] = read_txt(data)
            elif rtype == 1 and ln == 4:
                entry["value"] = socket.inet_ntoa(data)
            elif rtype == 28 and ln == 16:
                entry["value"] = socket.inet_ntop(socket.AF_INET6, data)
            elif rtype == 33 and ln >= 6:
                pr, w, port = struct.unpack_from("!HHH", data)
                entry["value"] = {"priority": pr, "weight": w, "port": port,
                                  "target": read_name(pkt, rdata_off + 6)[0]}
            else:
                entry["value"] = data.hex()
            rec["records"].append(entry)
    return rec


def extract_apps_data(decoded: dict):
    """Pull device_id out of the base64 `appsData` TXT blob."""
    for r in decoded.get("records", []):
        for kv in r.get("txt", []):
            if kv.startswith("appsData="):
                raw = base64.b64decode(kv[len("appsData="):])
                i = raw.find(b'{"mico"')
                info = {"raw_hex": raw.hex(), "raw_len": len(raw)}
                if i >= 0:
                    frag = raw[i:].decode("utf-8", "replace")
                    info["json"] = frag
                    j = frag.find('"device_id"')
                    if j >= 0:
                        val = frag[j:].split('"', 3)
                        if len(val) >= 4:
                            info["device_id"] = val[3]
                return info
    return None


def main() -> int:
    iface = sys.argv[1] if len(sys.argv) > 1 else None
    seconds = float(sys.argv[2]) if len(sys.argv) > 2 else 12.0
    out = sys.argv[3] if len(sys.argv) > 3 else "capture.jsonl"

    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Ephemeral source port: a QU reply is unicast straight back here.
    tx.bind(("", 0))
    if iface:
        tx.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(iface))
    tx.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    tx.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
    tx.settimeout(0.4)
    print(f"[capture] source port {tx.getsockname()[1]}, iface {iface or 'default'}")

    rows, seen = [], set()
    deadline = time.time() + seconds
    nxt = 0.0
    round_no = 0
    while time.time() < deadline:
        now = time.time()
        if now >= nxt:
            round_no += 1
            for svc in SERVICES:
                q = build_query(svc)
                tx.sendto(q, (MDNS_ADDR, MDNS_PORT))
                print(f"[capture] SEND round={round_no} destination={MDNS_ADDR}:{MDNS_PORT} "
                      f"len={len(q)} qname={svc}")
                print(f"          HEX: {q.hex()}")
            nxt = now + 3
        try:
            pkt, src = tx.recvfrom(65535)
        except TimeoutError:
            continue
        key = (src[0], pkt.hex())
        if key in seen:
            continue
        seen.add(key)
        decoded = decode_packet(pkt)
        row = {"timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
               "source_ip": src[0], "source_port": src[1], "length": len(pkt),
               "wire_hex": pkt.hex(),
               "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in pkt),
               "decoded": decoded}
        ad = extract_apps_data(decoded)
        if ad:
            row["apps_data"] = ad
        rows.append(row)
        print(f"[capture] RECV source={src[0]}:{src[1]} length={len(pkt)}")
        print(f"          HEX: {pkt.hex()}")
        for r in decoded.get("records", []):
            if r["type"] == 12:
                print(f"          PTR  {r['name']} -> {r['value']}")
            elif r["type"] == 33:
                v = r["value"]
                print(f"          SRV  {r['name']} port={v['port']} target={v['target']}")
            elif r["type"] == 16:
                print(f"          TXT  {r['name']}")
                for kv in r.get("txt", []):
                    print(f"               {kv}")
            elif r["type"] == 1:
                print(f"          A    {r['name']} = {r['value']}")
            elif r["type"] == 28:
                print(f"          AAAA {r['name']} = {r['value']}")
            else:
                print(f"          T{r['type']}  {r['name']} = {r['value']}")

    with open(out, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"[capture] {len(rows)} unique responses -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
