#!/usr/bin/env python3
"""
impair.py — a userspace `netem`, because this kernel has no `sch_netem`.

The bench needs delay, jitter, loss and reordering on the client<->broker path.
`tc qdisc … netem` is the normal way to get them; the Firecracker kernel this
runs on compiles in only `htb` and `pfifo`, so that door is shut.

What this does instead: it carries the client's traffic over a pair of TUN
devices and impairs the IP PACKETS in flight between them.

    [netns]  app -> tun-c -- impair.py --UDP--> impair.py -- tun-h -> app  [host]

That distinction matters. A userspace TCP proxy (the easy alternative) would
terminate the client's connection and open its own, so the client's TCP would
see a fast local path and a stall in the middle: congestion control, RTO and
fast retransmit would all be measuring the wrong network. Here the packets are
real IP packets and TCP is end-to-end, so a dropped packet is a real drop that
the real TCP stack really retransmits after a real RTO. That is the whole point
of the experiment: at 5% loss, the thing under test is how many round trips a
handshake needs, and a fake TCP would hide exactly that.

Impairment is applied ONE WAY, on the packets this process reads from its own
TUN. Both ends run it, so a profile's `delay` is one-way and the RTT an
application sees is about twice it. Always quote the measured RTT.

Usage:
    impair.py --tun tun-h --addr 10.88.0.1/24 --carrier-bind 10.77.0.1:9999 \
              --carrier-peer 10.77.0.2:9999 --profile lte [--mtu 1400]
"""
import argparse, fcntl, os, random, select, socket, struct, sys, threading, time, heapq

TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

# name -> (one-way delay s, jitter s, loss frac, reorder frac, rate bit/s or None)
#
# The numbers are meant to be recognisable rather than authoritative: `lte` is a
# decent 4G link, `lte-congested` a busy cell, `edge-hostile` a train/basement,
# `awful` the network you actually write retry logic for. `clean` measures the
# floor this harness itself imposes.
#
# `pure-25` and `pure-50` carry delay and NOTHING else. They exist to settle a
# question the messy profiles cannot: the WebSocket arms showed a warm-path
# message penalty (+10ms at `lte`, +26ms at `lte-congested`) that per-frame bytes
# cannot account for, and with jitter and loss in play there is no telling a real
# effect from variance. With pure delay, any systematic difference is systematic.
PROFILES = {
    "clean":         dict(delay=0.0,   jitter=0.0,   loss=0.0,  reorder=0.0,  rate=None),
    "pure-25":       dict(delay=0.025, jitter=0.0,   loss=0.0,  reorder=0.0,  rate=None),
    "pure-50":       dict(delay=0.050, jitter=0.0,   loss=0.0,  reorder=0.0,  rate=None),
    "wifi":          dict(delay=0.008, jitter=0.003, loss=0.001, reorder=0.0,  rate=None),
    "lte":           dict(delay=0.025, jitter=0.010, loss=0.005, reorder=0.0,  rate=None),
    "lte-congested": dict(delay=0.045, jitter=0.025, loss=0.02,  reorder=0.01, rate=8_000_000),
    "edge-hostile":  dict(delay=0.090, jitter=0.040, loss=0.05,  reorder=0.02, rate=2_000_000),
    "awful":         dict(delay=0.150, jitter=0.070, loss=0.10,  reorder=0.03, rate=1_000_000),
}


def open_tun(name: str, mtu: int) -> int:
    fd = os.open("/dev/net/tun", os.O_RDWR)
    fcntl.ioctl(fd, TUNSETIFF, struct.pack("16sH", name.encode(), IFF_TUN | IFF_NO_PI))
    return fd


class Link:
    """One direction of impairment: read from `src`, deliver to `dst` later.

    Delayed packets live in a heap keyed by due time, which is what makes
    reordering expressible: a packet given a smaller delay than its predecessor
    overtakes it, exactly as netem's `reorder` does. A single timer thread
    drains the heap.
    """

    def __init__(self, deliver, prof):
        self.deliver = deliver
        self.p = prof
        self.q: list = []
        self.lock = threading.Lock()
        self.cv = threading.Condition(self.lock)
        self.seq = 0
        # Bandwidth is modelled as a serialisation delay on a shared "wire":
        # each packet occupies the link for size/rate seconds, and the next
        # cannot start before the previous finished. That produces real
        # queueing (and real bufferbloat) under load rather than a flat cap.
        self.wire_free = 0.0
        self.stats = dict(passed=0, dropped=0)
        threading.Thread(target=self._pump, daemon=True).start()

    def send(self, pkt: bytes):
        p = self.p
        if p["loss"] and random.random() < p["loss"]:
            self.stats["dropped"] += 1
            return
        now = time.monotonic()
        d = p["delay"]
        if p["jitter"]:
            d = max(0.0, random.gauss(d, p["jitter"]))
        if p["reorder"] and random.random() < p["reorder"]:
            d = max(0.0, d * 0.4)          # this one jumps the queue
        due = now + d
        if p["rate"]:
            serial = (len(pkt) * 8) / p["rate"]
            start = max(now, self.wire_free)
            self.wire_free = start + serial
            due = max(due, self.wire_free)
        self.stats["passed"] += 1
        with self.cv:
            self.seq += 1
            heapq.heappush(self.q, (due, self.seq, pkt))
            self.cv.notify()

    def _pump(self):
        while True:
            with self.cv:
                while not self.q:
                    self.cv.wait()
                due = self.q[0][0]
                wait = due - time.monotonic()
                if wait > 0:
                    self.cv.wait(timeout=wait)
                    continue
                _, _, pkt = heapq.heappop(self.q)
            try:
                self.deliver(pkt)
            except OSError:
                pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tun", required=True)
    ap.add_argument("--addr", required=True, help="e.g. 10.88.0.1/24")
    ap.add_argument("--carrier-bind", required=True)
    ap.add_argument("--carrier-peer", required=True)
    ap.add_argument("--profile", default="clean")
    ap.add_argument("--mtu", type=int, default=1400)
    ap.add_argument("--stats-file")
    a = ap.parse_args()

    prof = PROFILES[a.profile]
    tun = open_tun(a.tun, a.mtu)
    os.system(f"ip addr add {a.addr} dev {a.tun} >/dev/null 2>&1")
    os.system(f"ip link set {a.tun} mtu {a.mtu} up")

    bh, bp = a.carrier_bind.rsplit(":", 1)
    ph, pp = a.carrier_peer.rsplit(":", 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 << 20)
    sock.bind((bh, int(bp)))
    peer = (ph, int(pp))

    # Only the tun->carrier direction is impaired here; the peer process does
    # the same for the other direction. carrier->tun is delivered immediately.
    out = Link(lambda pkt: sock.sendto(pkt, peer), prof)

    sys.stderr.write(f"impair.py {a.tun} profile={a.profile} {prof}\n")
    sys.stderr.flush()

    while True:
        r, _, _ = select.select([tun, sock], [], [])
        if tun in r:
            try:
                out.send(os.read(tun, a.mtu + 64))
            except OSError:
                pass
        if sock in r:
            data, _ = sock.recvfrom(65535)
            try:
                os.write(tun, data)
            except OSError:
                pass


if __name__ == "__main__":
    main()
