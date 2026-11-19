#!/usr/bin/env python3
"""
QuorumLog — cli.py

    quorumlog init       --dir ./node1 [--name n1] [--difficulty 14]
    quorumlog daemon     --dir ./node1 --port 8000 [--host 0.0.0.0]
                         [--bootstrap 127.0.0.1:8001 ...] [--difficulty 14]
    quorumlog transfer   --dir ./node1 --asset <id> --to <pubkey>
                         --terms <file> --out tx.bundle.json
                         [--bootstrap host:port ...] [--rounds 5] [--difficulty 14]
    quorumlog accept     --dir ./node1 --bundle tx.bundle.json
                         [--bootstrap host:port ...] [--note "..."]
    quorumlog verify     --bundle tx.bundle.json [--k 5] [--difficulty 14]
    quorumlog rotate-key --dir ./node1 --recovery-key ./node1/recovery_key.json
                         [--bootstrap host:port ...]

`verify` runs fully offline and exits 0 (valid) or 1 (invalid).
Every command on a data dir requires that `init` ran there first.

NOTE: --difficulty is a network-wide setting; run every node of a swarm with
the same value (witnesses verify PoW at their own configured difficulty).
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import logging
import os
import signal
import sys
import time
from typing import List, Optional, Tuple

from crypto import (DEFAULT_DIFFICULTY, DEFAULT_K, ZERO_HASH, Bundle, CryptoError, Entry,
                    MAX_ASSET_LEN, MAX_NOTE_LEN, MAX_TERMS_LEN, create_identity,
                    create_keypair, identity_exists, is_hex64, mine_pow, sign_entry,
                    save_identity, load_identity, load_key_file, verify_bundle,
                    Identity, SigningKey)
from node import CommitError, NodeNotInitialized, QuorumNode
from storage import Storage


# --------------------------------------------------------------------------
# shared helpers
# --------------------------------------------------------------------------

def parse_bootstrap(values: Optional[List[str]]) -> List[Tuple[str, int]]:
    out: List[Tuple[str, int]] = []
    for value in values or []:
        host, _, port_str = value.rpartition(":")
        try:
            port = int(port_str)
        except ValueError:
            raise CryptoError(f"bad --bootstrap {value!r}: port must be an integer")
        if not host or not (0 < port < 65536):
            raise CryptoError(f"bad --bootstrap {value!r}: expected host:port")
        out.append((host, port))
    return out


def initialize_node(dir_path: str, difficulty: int = DEFAULT_DIFFICULTY,
                    name: Optional[str] = None) -> dict:
    """Programmatic `init`: identity files (0600) + mined GENESIS entry."""
    os.makedirs(dir_path, exist_ok=True)
    if identity_exists(dir_path):
        raise CryptoError(f"directory already initialized: {dir_path}")
    identity = create_identity()
    save_identity(dir_path, identity)
    payload = {"recovery_pubkey": identity.recovery_pubkey}
    if name:
        payload["name"] = str(name)[:64]
    genesis = Entry(author=identity.pubkey, seq=0, prev_hash=ZERO_HASH,
                    timestamp=time.time(), type="GENESIS", payload=payload)
    mine_pow(genesis, difficulty)
    sign_entry(genesis, identity.sk)
    storage = Storage(os.path.join(dir_path, "log.db"))
    try:
        storage.append_local_entry(genesis, difficulty=difficulty)
    finally:
        storage.close()
    return {"dir": dir_path, "pubkey": identity.pubkey, "node_id": identity.node_id,
            "recovery_pubkey": identity.recovery_pubkey, "genesis_hash": genesis.entry_hash}


def load_bundle(path: str) -> Bundle:
    with open(path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    return Bundle.from_dict(raw)


def write_bundle(path: str, bundle: Bundle) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(bundle.to_dict(), fh, indent=2, sort_keys=True)
        fh.write("\n")
    os.chmod(path, 0o600)


async def warm_node(node: QuorumNode, bootstrap: List[Tuple[str, int]],
                    seconds: float, min_peers: int) -> None:
    """Best-effort DHT warm-up: keep bootstrapping until min_peers are active."""
    deadline = time.monotonic() + max(seconds, 0.0)
    while bootstrap and time.monotonic() < deadline:
        for addr in bootstrap:
            with contextlib.suppress(Exception):
                await node.dht.bootstrap([addr])
        if len(node.table.active_peers()) >= min_peers:
            return
        await asyncio.sleep(0.25)


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------

def cmd_init(args: argparse.Namespace) -> int:
    info = initialize_node(args.dir, difficulty=args.difficulty, name=args.name)
    print(json.dumps({"status": "initialized", **info}, indent=2))
    return 0


def cmd_daemon(args: argparse.Namespace) -> int:
    asyncio.run(_daemon(args))
    return 0


async def _daemon(args: argparse.Namespace) -> None:
    node = QuorumNode(args.dir, difficulty=args.difficulty)
    bootstrap = parse_bootstrap(args.bootstrap)
    await node.start(host=args.host, port=args.port, bootstrap=bootstrap)
    print(json.dumps({"status": "ready", "node_id": node.node_id, "pubkey": node.pubkey,
                      "port": node.addr[1], "active_peers": len(node.table.active_peers()),
                      "difficulty": args.difficulty}), flush=True)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError, RuntimeError):
            loop.add_signal_handler(sig, stop.set)
    try:
        await stop.wait()
    finally:
        await node.stop()
        print(json.dumps({"status": "stopped"}), flush=True)


def cmd_transfer(args: argparse.Namespace) -> int:
    asyncio.run(_transfer(args))
    return 0


async def _transfer(args: argparse.Namespace) -> None:
    with open(args.terms, "r", encoding="utf-8") as fh:
        terms = fh.read()
    if not (1 <= len(terms) <= MAX_TERMS_LEN):
        raise CryptoError(f"terms must be 1..{MAX_TERMS_LEN} chars")
    if not (1 <= len(args.asset) <= MAX_ASSET_LEN):
        raise CryptoError(f"asset must be 1..{MAX_ASSET_LEN} chars")
    if not is_hex64(args.to):
        raise CryptoError("--to must be a 64-hex Ed25519 public key")
    bootstrap = parse_bootstrap(args.bootstrap)
    if not bootstrap:
        raise CryptoError("transfer requires --bootstrap host:port")
    node = QuorumNode(args.dir, difficulty=args.difficulty)
    await node.start(host="127.0.0.1", port=args.port, bootstrap=bootstrap)
    try:
        await warm_node(node, bootstrap, args.warmup, args.min_peers)
        entry = node.build_entry(
            "TRANSFER", {"asset": args.asset, "to": args.to, "terms": terms})
        bundle = await node.commit_entry(entry, rounds=args.rounds)
    finally:
        await node.stop()
    write_bundle(args.out, bundle)
    print(json.dumps({"status": "committed", "entry_hash": bundle.entry.entry_hash,
                      "seq": bundle.entry.seq, "receipts": len(bundle.receipts),
                      "witnesses": [r.witness for r in bundle.receipts],
                      "out": args.out}, indent=2))


def cmd_accept(args: argparse.Namespace) -> int:
    asyncio.run(_accept(args))
    return 0


async def _accept(args: argparse.Namespace) -> None:
    bundle = load_bundle(args.bundle)
    ok, reason = verify_bundle(bundle, k=DEFAULT_K, difficulty=args.difficulty)
    if not ok:
        raise CryptoError(f"bundle verification failed: {reason}")
    node = QuorumNode(args.dir, difficulty=args.difficulty)
    status, existing = node.storage.record_witness(bundle.entry)
    if status == "FRAUD":
        raise CryptoError(
            f"conflict with already-witnessed entry {existing.entry_hash[:16]}...")
    for receipt in bundle.receipts:
        node.storage.add_receipt(receipt)
    committed: Optional[dict] = None
    bootstrap = parse_bootstrap(args.bootstrap)
    try:
        if bootstrap:
            await node.start(host="127.0.0.1", port=args.port, bootstrap=bootstrap)
            await warm_node(node, bootstrap, args.warmup, args.min_peers)
            payload = {"entry_hash": bundle.entry.entry_hash}
            if args.note:
                payload["note"] = args.note[:MAX_NOTE_LEN]
            accepted = await node.commit_entry(
                node.build_entry("ACCEPT", payload), rounds=args.rounds)
            committed = {"entry_hash": accepted.entry.entry_hash,
                         "seq": accepted.entry.seq,
                         "receipts": len(accepted.receipts)}
    finally:
        await node.stop()
    print(json.dumps({"status": "accepted", "entry_hash": bundle.entry.entry_hash,
                      "author": bundle.entry.author, "seq": bundle.entry.seq,
                      "accept_entry": committed}, indent=2))


def cmd_verify(args: argparse.Namespace) -> int:
    try:
        bundle = load_bundle(args.bundle)
    except (OSError, ValueError, CryptoError) as exc:
        print(json.dumps({"ok": False, "error": f"cannot load bundle: {exc}"}))
        return 1
    start = time.perf_counter()
    ok, reason = verify_bundle(bundle, k=args.k, difficulty=args.difficulty)
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    print(json.dumps({"ok": ok, "reason": reason,
                      "entry_hash": bundle.entry.entry_hash,
                      "author": bundle.entry.author, "seq": bundle.entry.seq,
                      "type": bundle.entry.type,
                      "witnesses": sorted({r.witness for r in bundle.receipts}),
                      "receipts": len(bundle.receipts),
                      "verify_ms": round(elapsed_ms, 3)}, indent=2))
    return 0 if ok else 1


def cmd_rotate_key(args: argparse.Namespace) -> int:
    asyncio.run(_rotate_key(args))
    return 0


async def _rotate_key(args: argparse.Namespace) -> None:
    identity = load_identity(args.dir)
    rec = load_key_file(args.recovery_key)
    if rec.get("pubkey") != identity.recovery_pubkey:
        raise CryptoError("recovery key file does not match the recorded recovery pubkey")
    rec_sk = SigningKey(bytes.fromhex(rec["seed"]))
    new_sk, new_pub = create_keypair()
    old_pub = identity.pubkey
    node = QuorumNode(args.dir, difficulty=args.difficulty)
    rotation = node.build_entry("KEY_ROTATE", {
        "new_pubkey": new_pub, "recovery_pubkey": identity.recovery_pubkey})
    bootstrap = parse_bootstrap(args.bootstrap)
    try:
        if bootstrap:
            await node.start(host="127.0.0.1", port=args.port, bootstrap=bootstrap)
            await warm_node(node, bootstrap, args.warmup, args.min_peers)
            rot_bundle = await node.commit_entry(rotation, rounds=args.rounds)
            node.set_identity(Identity(sk=new_sk, pubkey=new_pub,
                                       recovery_sk=rec_sk,
                                       recovery_pubkey=identity.recovery_pubkey))
            save_identity(args.dir, node.identity)
            genesis = node.build_entry("GENESIS", {
                "recovery_pubkey": identity.recovery_pubkey, "rotated_from": old_pub})
            genesis.prev_hash = rot_bundle.entry.entry_hash
            gen_bundle = await node.commit_entry(genesis, rounds=args.rounds)
            rotation_hash, genesis_hash = rot_bundle.entry.entry_hash, gen_bundle.entry.entry_hash
        else:
            node.finalize_entry(rotation)
            node.storage.append_local_entry(rotation, difficulty=args.difficulty)
            node.set_identity(Identity(sk=new_sk, pubkey=new_pub,
                                       recovery_sk=rec_sk,
                                       recovery_pubkey=identity.recovery_pubkey))
            genesis = node.build_entry("GENESIS", {
                "recovery_pubkey": identity.recovery_pubkey, "rotated_from": old_pub})
            genesis.prev_hash = rotation.entry_hash
            node.finalize_entry(genesis)
            node.storage.append_local_entry(genesis, difficulty=args.difficulty)
            save_identity(args.dir, node.identity)
            rotation_hash, genesis_hash = rotation.entry_hash, genesis.entry_hash
    finally:
        await node.stop()
    print(json.dumps({"status": "rotated", "old_pubkey": old_pub, "new_pubkey": new_pub,
                      "rotation_entry": rotation_hash, "new_genesis": genesis_hash,
                      "mode": "witnessed" if bootstrap else "local-only"}, indent=2))


# --------------------------------------------------------------------------
# argparse wiring
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="quorumlog",
        description="QuorumLog: p2p trust protocol — personal hash-chains, "
                    "Kademlia DHT routing, K-of-N threshold witness receipts.")
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p: argparse.ArgumentParser, with_dir: bool = True) -> None:
        if with_dir:
            p.add_argument("--dir", required=True, help="node data directory")
        p.add_argument("--difficulty", type=int, default=DEFAULT_DIFFICULTY,
                       help=f"PoW leading zero bits (network-wide, default {DEFAULT_DIFFICULTY})")
        p.add_argument("--bootstrap", action="append", default=[],
                       help="seed address host:port (repeatable)")
        p.add_argument("--port", type=int, default=0,
                       help="local UDP port (0 = ephemeral)")
        p.add_argument("--rounds", type=int, default=5,
                       help="max PROPOSE retry rounds for quorum")
        p.add_argument("--warmup", type=float, default=3.0,
                       help="seconds to wait for DHT warm-up")
        p.add_argument("--min-peers", type=int, default=5,
                       help="active peers required before committing")

    p = sub.add_parser("init", help="create identity + GENESIS entry")
    p.add_argument("--dir", required=True)
    p.add_argument("--name", default=None, help="optional human-readable label")
    p.add_argument("--difficulty", type=int, default=DEFAULT_DIFFICULTY)
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("daemon", help="run a long-lived node")
    p.add_argument("--host", default="0.0.0.0")
    common(p)
    p.set_defaults(func=cmd_daemon)

    p = sub.add_parser("transfer", help="commit a TRANSFER entry via witness quorum")
    p.add_argument("--asset", required=True)
    p.add_argument("--to", required=True, help="recipient 64-hex public key")
    p.add_argument("--terms", required=True, help="file with the transfer terms")
    p.add_argument("--out", default="tx.bundle.json")
    common(p)
    p.set_defaults(func=cmd_transfer)

    p = sub.add_parser("accept", help="verify + record a received bundle (and commit ACCEPT)")
    p.add_argument("--bundle", required=True)
    p.add_argument("--note", default=None)
    common(p)
    p.set_defaults(func=cmd_accept)

    p = sub.add_parser("verify", help="offline bundle verification; exit 0/1")
    p.add_argument("--bundle", required=True)
    p.add_argument("--k", type=int, default=DEFAULT_K)
    p.add_argument("--difficulty", type=int, default=DEFAULT_DIFFICULTY)
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("rotate-key", help="rotate the signing key (recovery-key co-signed)")
    common(p)
    p.add_argument("--recovery-key", required=True,
                   help="path to recovery_key.json written by init")
    p.set_defaults(func=cmd_rotate_key)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (CommitError, NodeNotInitialized, CryptoError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())