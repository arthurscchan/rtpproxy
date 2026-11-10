#!/usr/bin/env python3
"""Generate the seed corpus for fuzz_rtp_record.

Each seed mirrors one fuzz_rtp_record input: a single op_flags byte
(bit 0 = reseed) followed by chunk-framed records; every chunk is a
struct sockaddr_in (16 bytes) followed by a raw RTP packet, exactly the
shape proc_foreach() in scripts/fuzz/fuzz_rtp_record.c consumes.
Chunk framing is implemented by rfz_get_chunk() in rfz_chunk.c: one length
byte holds the payload size (255 = continue into the next byte), followed
by the payload.

Run from anywhere:  python3 scripts/fuzz/gen_rtp_record_seeds.py
Seeds are (re)written into scripts/fuzz/rtp_record_seeds/.
"""

import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
OUTDIR = os.path.join(HERE, "rtp_record_seeds")


def rtp(pt, seq, ts, ssrc, payload=b"", marker=False, pad=False,
        ext=False, csrcs=(), ext_data=b""):
    vpxcc = 0x80 | (0x20 if pad else 0) | (0x10 if ext else 0) | len(csrcs)
    pkt = struct.pack("!BBHII", vpxcc, (0x80 if marker else 0) | (pt & 0x7f),
                      seq & 0xffff, ts & 0xffffffff, ssrc)
    for csrc in csrcs:
        pkt += struct.pack("!I", csrc)
    if ext:
        assert len(ext_data) % 4 == 0
        pkt += struct.pack("!HH", 1, len(ext_data) // 4) + ext_data
    return pkt + payload


def sockaddr(addr, port):
    return struct.pack("!HH4s8s", 2, port,
                       bytes(int(x) for x in addr.split(".")), b"")


def seed(packets):
    """One fuzz input: op_flags byte + chunk-framed sockaddr+RTP records."""
    out = bytearray([0x00])
    for sa, pkt in packets:
        payload = sa + pkt
        assert 0 < len(payload) < 255
        out += bytes([len(payload)]) + payload
    return bytes(out)


SEEDS = {
    # Minimal valid PCMU talkspurt, remote peer 1.2.3.4:1234
    "seed_ping.bin": seed([
        (sockaddr("1.2.3.4", 1234),
         rtp(0, 1, 160, 0xdeadbeef, b"\xd5" * 16)),
    ]),
    # Marker bit + CSRC list + header extension
    "seed_ext_csrc.bin": seed([
        (sockaddr("1.2.3.4", 1234),
         rtp(8, 2, 320, 0xdeadbeef, b"\xff" * 8, marker=True, ext=True,
             csrcs=(0x11111111, 0x22222222),
             ext_data=b"\x00\x01\x00\x02\x00\x03\x00\x04")),
    ]),
    # Zero-length payload
    "seed_empty_payload.bin": seed([
        (sockaddr("5.6.7.8", 5678), rtp(0, 3, 480, 0xcafebabe)),
    ]),
    # Padding-bit packet (padded octet count in last byte)
    "seed_padded.bin": seed([
        (sockaddr("5.6.7.8", 5678),
         rtp(0, 4, 640, 0xcafebabe, b"\x01" * 100 + b"\x04", pad=True)),
    ]),
    # Two packets with a timestamp jump (resizer reorder/repacketization)
    "seed_ts_jump.bin": seed([
        (sockaddr("1.2.3.4", 1234),
         rtp(0, 5, 800, 0xdeadbeef, b"\xd5" * 160)),
        (sockaddr("1.2.3.4", 1234),
         rtp(0, 6, 0xfff00000, 0xdeadbeef, b"\xd5" * 160)),
    ]),
    # Maximum sequence numbers and near-overflow timestamp
    "seed_seq_wrap.bin": seed([
        (sockaddr("9.9.9.9", 65535),
         rtp(0, 0xffff, 0xffffffa0, 0x12345678, b"\xd5" * 32)),
        (sockaddr("9.9.9.9", 65535),
         rtp(0, 0, 0xffffffe0, 0x12345678, b"\xd5" * 32)),
    ]),
}


def main():
    os.makedirs(OUTDIR, exist_ok=True)
    for name, data in SEEDS.items():
        with open(os.path.join(OUTDIR, name), "wb") as fp:
            fp.write(data)
    print("wrote %d seeds to %s" % (len(SEEDS), OUTDIR))


if __name__ == "__main__":
    main()
