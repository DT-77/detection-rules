#!/usr/bin/env python3
"""
Deterministic, OFFLINE synthetic PCAP generator for detection-rules-lab self-tests.

Runs inside the drl/pcapgen:local container with NO network access:
    docker run --rm --network none \
        -v <repo>/tests/generators:/gen:ro -v <repo>/tests/pcaps:/out \
        --entrypoint python drl/pcapgen:local /gen/gen_pcaps.py

Scapy synthesizes packets in memory; nothing is sniffed from a NIC.

Two complete TCP sessions are produced, both with full 3-way handshakes so
stream reassembly engages:

  1. HTTP GET on :80  — exercises app-layer rules (http.uri / http_uri).
  2. Plain TCP "beacon" on :4444 — carries the marker as RAW payload on a
     NON-HTTP flow. This matters because Snort 3 routes an HTTP request line
     into HTTP buffers (so generic `content`/pkt_data sees only the body),
     whereas Suricata's generic `content` inspects the raw stream. A non-HTTP
     flow makes the raw-content match fire IDENTICALLY on both engines.
"""
import os
from scapy.all import IP, TCP, Raw, wrpcap

OUT_DIR = "/out"
MARKER = "drl-functional-test"


def _handshake(src, dst, sport, dport, cseq, sseq):
    syn     = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S",  seq=cseq)
    synack  = IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="SA", seq=sseq, ack=cseq + 1)
    handack = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A",  seq=cseq + 1, ack=sseq + 1)
    return [syn, synack, handack]


def http_get_session(uri, host, ua, src="10.10.10.10", dst="93.184.216.34",
                     sport=44001, dport=80, cseq=1000, sseq=500000):
    pkts = _handshake(src, dst, sport, dport, cseq, sseq)
    cseq += 1
    request = (
        "GET {uri} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\n"
        "Accept: */*\r\nConnection: close\r\n\r\n"
    ).format(uri=uri, host=host, ua=ua).encode()
    pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA", seq=cseq, ack=sseq + 1) / Raw(load=request))
    pkts.append(IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="A",  seq=sseq + 1, ack=cseq + len(request)))
    return pkts


def tcp_beacon_session(payload, src="10.10.10.10", dst="203.0.113.55",
                       sport=44002, dport=4444, cseq=2000, sseq=900000):
    pkts = _handshake(src, dst, sport, dport, cseq, sseq)
    cseq += 1
    data = payload.encode()
    pkts.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA", seq=cseq, ack=sseq + 1) / Raw(load=data))
    pkts.append(IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="A",  seq=sseq + 1, ack=cseq + len(data)))
    return pkts


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    pkts  = http_get_session(uri="/{}?id=1".format(MARKER), host="example.com", ua="DRL-TEST-UA")
    pkts += tcp_beacon_session(payload="BEACON {} id=1\n".format(MARKER))
    out_path = os.path.join(OUT_DIR, "http_test.pcap")
    wrpcap(out_path, pkts)
    print("[+] wrote {} packet(s) -> {}".format(len(pkts), out_path))


if __name__ == "__main__":
    main()
