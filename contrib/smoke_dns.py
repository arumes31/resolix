#!/usr/bin/env python3
"""Minimal dependency-free DNS smoke client for UDP, TCP, DoH, and DoT."""

import argparse
import http.client
import socket
import ssl
import struct


def query(name: str) -> bytes:
    labels = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.rstrip(".").split("."))
    return struct.pack("!HHHHHH", 0x4D21, 0x0100, 1, 0, 0, 0) + labels + b"\0" + struct.pack("!HH", 1, 1)


def exact(sock: socket.socket, length: int) -> bytes:
    chunks = []
    remaining = length
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise RuntimeError("unexpected EOF")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def exchange(args: argparse.Namespace, wire: bytes) -> bytes:
    if args.protocol == "udp":
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(5)
            sock.sendto(wire, (args.host, args.port))
            return sock.recv(65535)
    if args.protocol == "doh":
        conn = http.client.HTTPConnection(args.host, args.port, timeout=5)
        conn.request("POST", "/dns-query", wire, {"Content-Type": "application/dns-message", "Accept": "application/dns-message"})
        response = conn.getresponse()
        body = response.read()
        conn.close()
        if response.status != 200:
            raise RuntimeError(f"DoH returned HTTP {response.status}: {body!r}")
        return body

    if args.protocol == "dot" and not args.ca_file:
        raise RuntimeError("DoT requires --ca-file")
    raw = socket.create_connection((args.host, args.port), timeout=5)
    if args.protocol == "dot":
        context = ssl.create_default_context(cafile=args.ca_file)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        raw = context.wrap_socket(raw, server_hostname="localhost")
    with raw:
        raw.sendall(struct.pack("!H", len(wire)) + wire)
        length = struct.unpack("!H", exact(raw, 2))[0]
        return exact(raw, length)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("protocol", choices=("udp", "tcp", "doh", "dot"))
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument("domain")
    parser.add_argument("expected_rcode", type=int)
    parser.add_argument("--ca-file")
    args = parser.parse_args()
    response = exchange(args, query(args.domain))
    if len(response) < 12:
        raise RuntimeError("short DNS response")
    _, flags, _, answer_count, _, _ = struct.unpack("!HHHHHH", response[:12])
    rcode = flags & 0xF
    if rcode != args.expected_rcode:
        raise RuntimeError(f"rcode {rcode}, expected {args.expected_rcode}")
    if args.expected_rcode == 0 and answer_count == 0:
        raise RuntimeError("successful DNS response contained no answers")


if __name__ == "__main__":
    main()
