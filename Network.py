"""
QuorumLog — network.py

asyncio UDP transport (JSON framing, 64 KiB cap, 2 s RPC timeout), a compact
Kademlia-style XOR routing table (256 buckets, PING / FIND_NODE), and the
deterministic witness-selection function (N=7 with /16 subnet diversity).

Wire format — every datagram is one JSON object:

    request   {"v":1,"type":"PING","rpc_id":"<hex16>",
               "sender":{"node_id","pubkey"},"payload":{...}}
    response  {"v":1,"type":"RESP","rpc_id":"<same>","resp":"PING",
               "sender":{...},"ok":true,"payload":{...}}

Node id = SHA256(pubkey). Every handler validates the sender block, so spoofed
identities are dropped before application code runs. Each node uses exactly one
UDP socket, therefore the datagram source address is both the return path and
the peer's canonical address.
"""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import ipaddress
import json
import logging
import random
import secrets
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Iterable, Optional, Tuple

from crypto import is_hex64, pubkey_to_node_id

log = logging.getLogger("quorumlog.net")

MAX_DATAGRAM = 65536            # hard 64 KiB cap per datagram
MAX_ENTRY_JSON = 16384          # single-entry JSON cap enforced by handlers
RPC_TIMEOUT = 2.0               # per-RPC timeout (seconds)
ACTIVE_WINDOW = 120.0           # peers seen within this window count as "active"
WITNESS_N = 7                   # witnesses per entry
KADEMILIA_K = 20                # routing-table bucket capacity
MAX_INFLIGHT = 1024             # concurrent inbound handler tasks

REQUEST_TYPES = frozenset({"PING", "FIND_NODE", "PROPOSE", "SYNC", "FRAUD_PROOF", "RECEIPT"})

RequestHandler = Callable[[Dict[str, Any], Tuple[str, int]], Awaitable[Optional[dict]]]
PeerObserver = Callable[[Dict[str, Any], Tuple[str, int]], None]


class RejectError(Exception):
    """Application-level rejection; surfaced to the sender as ok=false."""


class RPCTimeout(Exception):
    """No response within the timeout window."""


class TransportClosed(Exception):
    """The UDP transport has been closed."""


class MessageTooLarge(Exception):
    """Serialized request exceeds the datagram cap."""


# --------------------------------------------------------------------------
# Peers and XOR routing
# --------------------------------------------------------------------------

@dataclass
class PeerInfo:
    node_id: str
    addr: Tuple[str, int]
    pubkey: str
    last_seen: float = 0.0

    def is_active(self, window: float = ACTIVE_WINDOW, now: Optional[float] = None) -> bool:
        if now is None:
            now = time.time()
        return self.last_seen > 0 and (now - self.last_seen) <= window


def xor_distance(a_hex: str, b_hex: str) -> int:
    return int.from_bytes(bytes.fromhex(a_hex), "big") ^ int.from_bytes(bytes.fromhex(b_hex), "big")


def peer_from_sender(sender: Any, addr: Tuple[str, int],
                     now: float) -> Optional[PeerInfo]:
    """Validate a wire 'sender' block and bind it to the datagram source address."""
    if not isinstance(sender, dict):
        return None
    node_id, pubkey = sender.get("node_id"), sender.get("pubkey")
    if not is_hex64(node_id) or not is_hex64(pubkey):
        return None
    if node_id != pubkey_to_node_id(pubkey):
        return None
    host, port = addr
    if not isinstance(port, int) or not (0 <= port <= 65535):
        return None
    return PeerInfo(node_id=node_id, addr=(host, port), pubkey=pubkey, last_seen=now)


class RoutingTable:
    """Kademlia-style table: 256 buckets indexed by XOR bit-length, plus a flat
    index. `closest` sorts by exact XOR distance — identical results to bucket
    traversal for small tables, and far less code."""

    def __init__(self, self_node_id: str, k: int = KADEMILIA_K) -> None:
        self.self_id = self_node_id
        self.k = k
        self._buckets: Dict[int, Dict[str, PeerInfo]] = {}
        self._peers: Dict[str, PeerInfo] = {}

    def _bucket_index(self, node_id: str) -> int:
        return xor_distance(self.self_id, node_id).bit_length() - 1

    def touch(self, node_id: str, addr: Tuple[str, int], pubkey: str,
              now: Optional[float] = None) -> Optional[PeerInfo]:
        if node_id == self.self_id or not is_hex64(node_id) or not is_hex64(pubkey):
            return None
        if now is None:
            now = time.time()
        existing = self._peers.get(node_id)
        if existing is not None:
            existing.addr, existing.pubkey, existing.last_seen = addr, pubkey, now
            return existing
        bucket = self._buckets.setdefault(self._bucket_index(node_id), {})
        if len(bucket) >= self.k:
            stalest = min(bucket.values(), key=lambda p: p.last_seen)
            if now - stalest.last_seen <= ACTIVE_WINDOW:
                return None  # bucket full of live peers: drop the candidate
            del bucket[stalest.node_id]
            del self._peers[stalest.node_id]
        info = PeerInfo(node_id=node_id, addr=addr, pubkey=pubkey, last_seen=now)
        bucket[node_id] = info
        self._peers[node_id] = info
        return info

    def get(self, node_id: str) -> Optional[PeerInfo]:
        return self._peers.get(node_id)

    def all_peers(self) -> list:
        return list(self._peers.values())

    def active_peers(self, window: float = ACTIVE_WINDOW) -> list:
        now = time.time()
        return [p for p in self._peers.values() if p.is_active(window, now)]

    def closest(self, target_hex: str, n: int) -> list:
        peers = sorted(self._peers.values(), key=lambda p: xor_distance(p.node_id, target_hex))
        return peers[:n]

    def random_peers(self, n: int) -> list:
        pool = self.active_peers() or list(self._peers.values())
        return random.sample(pool, min(n, len(pool)))

    def __len__(self) -> int:
        return len(self._peers)


# --------------------------------------------------------------------------
# Witness selection (deterministic; identical view -> identical set)
# --------------------------------------------------------------------------

def subnet_key(ip_str: str, allow_localhost: bool) -> Optional[bytes]:
    """/16 prefix key; loopback exempted when allow_localhost (local test clusters)."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return b"invalid"
    if allow_localhost and ip.is_loopback:
        return None
    return ip.packed[:2]


def select_witnesses(peers: Iterable[PeerInfo], author_pubkey: str, seq: int,
                     n: int = WITNESS_N, allow_localhost: bool = True) -> list:
    """The N closest active peers to SHA256(f"{author}:{seq // 100}"), the author
    excluded, at most one peer per /16 IP subnet. Same inputs -> same set."""
    target = hashlib.sha256(f"{author_pubkey}:{seq // 100}".encode("utf-8")).hexdigest()
    ranked = sorted((p for p in peers if p.pubkey != author_pubkey and p.is_active()),
                    key=lambda p: xor_distance(p.node_id, target))
    chosen: list = []
    subnets: set = set()
    for peer in ranked:
        key = subnet_key(peer.addr[0], allow_localhost)
        if key is not None:
            if key in subnets:
                continue
            subnets.add(key)
        chosen.append(peer)
        if len(chosen) >= n:
            break
    return chosen


# --------------------------------------------------------------------------
# UDP transport
# --------------------------------------------------------------------------

class QuorumProtocol(asyncio.DatagramProtocol):
    """JSON-framed UDP protocol with per-RPC futures and a chaos hook
    (`drop_rate`) used by the packet-loss tests."""

    def __init__(self, node_id: str, pubkey: str, on_request: RequestHandler,
                 on_peer: Optional[PeerObserver] = None) -> None:
        self.node_id = node_id
        self.pubkey = pubkey
        self._sender = {"node_id": node_id, "pubkey": pubkey}
        self.on_request = on_request
        self.on_peer = on_peer
        self.transport: Optional[asyncio.DatagramTransport] = None
        self._waiters: Dict[str, asyncio.Future] = {}
        self.drop_rate = 0.0
        self.closed = False
        self._inflight = 0

    def connection_made(self, transport) -> None:  # type: ignore[override]
        self.transport = transport

    def connection_lost(self, exc) -> None:  # type: ignore[override]
        self.closed = True
        self._fail_waiters(TransportClosed("connection lost"))

    def error_received(self, exc: Exception) -> None:
        log.debug("udp error from transport: %s", exc)

    def datagram_received(self, data: bytes, addr) -> None:  # type: ignore[override]
        # NOTE: chaos loss is applied once per packet at the sender's outbound
        # path (_send_raw). Requests and responses are both outbound packets of
        # exactly one node, so drop_rate=0.25 there == "25% of UDP packets".
        if self.closed or not data or len(data) > MAX_DATAGRAM:
            return
        try:
            msg = json.loads(bytes(data).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            return
        if not isinstance(msg, dict):
            return
        sender, rpc_id = msg.get("sender"), msg.get("rpc_id")
        if peer_from_sender(sender, addr, time.time()) is None:
            return  # invalid or spoofed identity
        if self.on_peer is not None:
            self.on_peer(sender, addr)
        if msg.get("type") == "RESP":
            if isinstance(rpc_id, str) and rpc_id in self._waiters:
                fut = self._waiters.pop(rpc_id)
                if not fut.done():
                    fut.set_result(msg)
            return
        if msg.get("type") in REQUEST_TYPES and isinstance(rpc_id, str):
            if self._inflight >= MAX_INFLIGHT:
                return  # overloaded: shed load
            self._inflight += 1
            task = asyncio.get_running_loop().create_task(self._serve(msg, addr))
            task.add_done_callback(self._serve_done)

    def _serve_done(self, task: "asyncio.Task") -> None:
        self._inflight -= 1
        if not task.cancelled() and task.exception() is not None:
            log.debug("handler task error: %s", task.exception())

    async def _serve(self, msg: dict, addr: Tuple[str, int]) -> None:
        req_type, rpc_id = msg.get("type"), msg.get("rpc_id")
        try:
            payload = await self.on_request(msg, addr)
            resp = {"v": 1, "type": "RESP", "rpc_id": rpc_id, "resp": req_type,
                    "sender": self._sender, "ok": True, "payload": payload or {}}
        except RejectError as exc:
            resp = {"v": 1, "type": "RESP", "rpc_id": rpc_id, "resp": req_type,
                    "sender": self._sender, "ok": False, "error": str(exc)}
        except Exception as exc:  # never leak internals to the wire
            log.warning("request handler failed: %s: %s", type(exc).__name__, exc)
            resp = {"v": 1, "type": "RESP", "rpc_id": rpc_id, "resp": req_type,
                    "sender": self._sender, "ok": False, "error": "internal-error"}
        self._send(addr, resp)

    def _fail_waiters(self, exc: Exception) -> None:
        for fut in list(self._waiters.values()):
            if not fut.done():
                fut.set_exception(exc)
        self._waiters.clear()

    def _send_raw(self, addr: Tuple[str, int], data: bytes) -> None:
        if self.closed or self.transport is None:
            return
        if self.drop_rate > 0.0 and random.random() < self.drop_rate:
            return  # chaos: outbound loss
        with contextlib.suppress(OSError):
            self.transport.sendto(data, addr)

    def _send(self, addr: Tuple[str, int], msg: dict) -> None:
        try:
            data = json.dumps(msg, separators=(",", ":"), allow_nan=False).encode("utf-8")
        except (TypeError, ValueError):
            return
        if len(data) > MAX_DATAGRAM:
            log.debug("dropping oversize message (%d bytes)", len(data))
            return
        self._send_raw(addr, data)

    async def rpc(self, addr: Tuple[str, int], mtype: str, payload: dict,
                  timeout: float = RPC_TIMEOUT) -> dict:
        if self.closed:
            raise TransportClosed("transport is closed")
        rpc_id = secrets.token_hex(8)
        msg = {"v": 1, "type": mtype, "rpc_id": rpc_id, "sender": self._sender,
               "payload": payload}
        try:
            data = json.dumps(msg, separators=(",", ":"), allow_nan=False).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise MessageTooLarge(str(exc)) from None
        if len(data) > MAX_DATAGRAM:
            raise MessageTooLarge(f"request is {len(data)} bytes")
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        self._waiters[rpc_id] = fut
        self._send_raw(addr, data)
        try:
            return await asyncio.wait_for(fut, timeout)
        except asyncio.TimeoutError:
            raise RPCTimeout(f"{mtype} to {addr}") from None
        finally:
            self._waiters.pop(rpc_id, None)

    def notify(self, addr: Tuple[str, int], mtype: str, payload: dict) -> None:
        """Fire-and-forget message (no response awaited)."""
        self._send(addr, {"v": 1, "type": mtype, "rpc_id": secrets.token_hex(8),
                          "sender": self._sender, "payload": payload})

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        self._fail_waiters(TransportClosed("transport closed"))
        if self.transport is not None:
            self.transport.close()


class UDPTransport:
    """Thin handle over QuorumProtocol for opening / closing the socket."""

    def __init__(self, transport, protocol: QuorumProtocol) -> None:
        self.transport = transport
        self.protocol = protocol

    @classmethod
    async def open(cls, host: str, port: int, node_id: str, pubkey: str,
                   on_request: RequestHandler,
                   on_peer: Optional[PeerObserver] = None) -> "UDPTransport":
        loop = asyncio.get_running_loop()
        protocol = QuorumProtocol(node_id, pubkey, on_request, on_peer)
        transport, _ = await loop.create_datagram_endpoint(
            lambda: protocol, local_addr=(host, port))
        return cls(transport, protocol)

    @property
    def local_addr(self) -> Tuple[str, int]:
        sock = self.transport.get_extra_info("sockname") if self.transport else None
        return (sock[0], sock[1]) if sock else ("0.0.0.0", 0)

    async def rpc(self, addr: Tuple[str, int], mtype: str, payload: dict,
                  timeout: float = RPC_TIMEOUT) -> dict:
        return await self.protocol.rpc(addr, mtype, payload, timeout)

    def notify(self, addr: Tuple[str, int], mtype: str, payload: dict) -> None:
        self.protocol.notify(addr, mtype, payload)

    def close(self) -> None:
        self.protocol.close()


# --------------------------------------------------------------------------
# DHT operations (PING / FIND_NODE bootstrap)
# --------------------------------------------------------------------------

class DHT:
    def __init__(self, node_id: str, pubkey: str, table: RoutingTable,
                 transport: UDPTransport) -> None:
        self.node_id = node_id
        self.pubkey = pubkey
        self.table = table
        self.transport = transport

    async def ping(self, addr: Tuple[str, int], timeout: float = RPC_TIMEOUT) -> Optional[PeerInfo]:
        try:
            resp = await self.transport.rpc(addr, "PING", {}, timeout)
        except (RPCTimeout, TransportClosed, MessageTooLarge, OSError):
            return None
        return peer_from_sender(resp.get("sender"), addr, time.time())

    async def find_node(self, addr: Tuple[str, int], target: str,
                        timeout: float = RPC_TIMEOUT) -> list:
        try:
            resp = await self.transport.rpc(addr, "FIND_NODE", {"target": target}, timeout)
        except (RPCTimeout, TransportClosed, MessageTooLarge, OSError):
            return []
        if not resp.get("ok"):
            return []
        now = time.time()
        out: list = []
        for item in (resp.get("payload") or {}).get("nodes", []):
            if not isinstance(item, dict):
                continue
            node_id, pubkey = item.get("node_id"), item.get("pubkey")
            host, port = item.get("host"), item.get("port")
            if not is_hex64(node_id) or not is_hex64(pubkey) or node_id != pubkey_to_node_id(pubkey):
                continue
            if not isinstance(host, str) or not isinstance(port, int) or not (0 <= port <= 65535):
                continue
            out.append(PeerInfo(node_id=node_id, addr=(host, port), pubkey=pubkey, last_seen=now))
        return out

    async def bootstrap(self, addrs) -> int:
        """Ping the seeds, then FIND_NODE(self) and ping everything returned —
        this is what makes a freshly started node visible to the whole swarm."""
        learned = 0
        for addr in addrs:
            info = await self.ping(addr)
            if info is None:
                continue
            learned += 1
            for peer in await self.find_node(addr, self.node_id):
                if peer.node_id == self.node_id:
                    continue
                if await self.ping(peer.addr) is not None:
                    learned += 1
        return learned

    def handle_request(self, msg: dict, addr: Tuple[str, int]) -> Optional[dict]:
        mtype = msg.get("type")
        if mtype == "PING":
            return {}
        if mtype == "FIND_NODE":
            target = (msg.get("payload") or {}).get("target")
            if not is_hex64(target):
                raise RejectError("malformed-find-node")
            nodes = [{"node_id": p.node_id, "pubkey": p.pubkey,
                      "host": p.addr[0], "port": p.addr[1]}
                     for p in self.table.closest(target, KADEMILIA_K)]
            return {"nodes": nodes}
        return None