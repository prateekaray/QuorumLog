"""
QuorumLog — test.py

Single pytest suite:
  * test_crypto_and_tamper   — signature forgery, PoW, canonical JSON,
                               record_witness conflict semantics, 1-byte SQLite
                               mutation detection, bundle tampering.
  * test_e2e_transfer        — 12 local async nodes; Alice -> Bob -> Charlie
                               transfer with offline verification in < 10 ms.
  * test_double_spend_attack — conflicting seq=2 entries to overlapping
                               witnesses; FRAUD_PROOF emitted + gossiped,
                               neither fork reaches quorum, Alice blacklisted.
  * test_chaos_packet_loss   — 25% UDP packet loss + 2 of 7 witnesses killed
                               mid-flight; Alice still reaches 5-of-7 finality.
  * test_spam_defense        — invalid-PoW flood and >10 req/min flood are
                               cleanly dropped; the victim stays healthy.

Run:  python -m pytest test_quorumlog.py -v
"""
from __future__ import annotations

import asyncio
import random
import sqlite3
import time
from typing import List

import pytest

import crypto as C
from cli import initialize_node
from node import CommitError, QuorumNode
from storage import Storage

pytestmark = pytest.mark.asyncio

DIFF = 8          # test difficulty (fast PoW)
K = C.DEFAULT_K   # 5
N = 7


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

async def stop_all(nodes: List[QuorumNode]) -> None:
    for node in nodes:
        try:
            await node.stop()
        except Exception:
            pass


async def start_cluster(tmp_path, count: int) -> List[QuorumNode]:
    """Boot `count` nodes on ephemeral localhost ports and warm a full mesh."""
    nodes: List[QuorumNode] = []
    for i in range(count):
        node_dir = tmp_path / f"node{i}"
        initialize_node(str(node_dir), difficulty=DIFF)
        node = QuorumNode(str(node_dir), difficulty=DIFF)
        bootstrap = [nodes[0].addr] if nodes else []
        await node.start(host="127.0.0.1", port=0, bootstrap=bootstrap)
        nodes.append(node)
    for _ in range(2):
        await asyncio.gather(
            *(n.dht.bootstrap([nodes[0].addr]) for n in nodes[1:]),
            return_exceptions=True)
    assert all(len(n.table.active_peers()) >= count - 3 for n in nodes), \
        "cluster failed to warm up"
    return nodes


# --------------------------------------------------------------------------
# 1) crypto + tamper
# --------------------------------------------------------------------------

async def test_crypto_and_tamper(tmp_path):
    identity = C.create_identity()
    to_key, rec_pub = C.create_keypair()[1], C.create_keypair()[1]

    def fresh_entry() -> C.Entry:
        return C.Entry(author=identity.pubkey, seq=1, prev_hash="ab" * 32,
                       timestamp=time.time(), type="TRANSFER",
                       payload={"asset": "a1", "to": to_key, "terms": "original terms"})

    # -- happy path --------------------------------------------------------
    entry = fresh_entry()
    C.mine_pow(entry, DIFF)
    C.sign_entry(entry, identity.sk)
    ok, reason = C.verify_entry(entry, DIFF)
    assert ok, reason

    # -- payload forgery invalidates the signature --------------------------
    # (re-mine PoW so verification reaches the signature check: PoW is
    # reproducible by anyone, the author's signature is not)
    forged = C.Entry(**{**entry.to_dict(),
                        "payload": {**entry.payload, "terms": "forged terms"}})
    C.mine_pow(forged, DIFF)
    ok, reason = C.verify_entry(forged, DIFF)
    assert not ok and "signature" in reason

    # -- signature by the wrong key ----------------------------------------
    wrong = fresh_entry()
    C.mine_pow(wrong, DIFF)
    C.sign_entry(wrong, identity.recovery_sk)
    assert not C.verify_entry(wrong, DIFF)[0]

    # -- insufficient PoW ---------------------------------------------------
    under = fresh_entry()
    C.mine_pow(under, DIFF)
    C.sign_entry(under, identity.sk)  # signed, so validation reaches the PoW check
    ok, reason = C.verify_entry(under, DIFF + 8)  # demands 2^16 work
    assert not ok and reason == "insufficient proof-of-work"

    # -- canonical JSON & bit math -----------------------------------------
    assert C.canonical_json({"b": 1, "a": 2}) == C.canonical_json({"a": 2, "b": 1})
    with pytest.raises(C.CryptoError):
        C.canonical_json({"x": float("nan")})
    assert C.leading_zero_bits(b"\x00" * 32) == 256
    assert C.leading_zero_bits(b"\xff" + b"\x00" * 31) == 0
    assert C.leading_zero_bits(b"\x00\x00\xf0" + b"\x00" * 29) == 16

    # -- storage: record_witness conflict semantics -------------------------
    node_dir = tmp_path / "tamper"
    initialize_node(str(node_dir), difficulty=DIFF)
    local_identity = C.load_identity(str(node_dir))
    storage = Storage(str(node_dir / "log.db"))
    genesis = storage.last_local(local_identity.pubkey)
    first = C.Entry(author=local_identity.pubkey, seq=1, prev_hash=genesis.entry_hash,
                    timestamp=time.time(), type="TRANSFER",
                    payload={"asset": "car", "to": to_key, "terms": "v1"})
    C.mine_pow(first, DIFF)
    C.sign_entry(first, local_identity.sk)
    storage.append_local_entry(first, difficulty=DIFF)
    ok, reason = storage.verify_local_chain(local_identity.pubkey, DIFF)
    assert ok, reason

    wstorage = Storage(str(node_dir / "witness.db"))
    assert wstorage.record_witness(first)[0] == "OK"
    conflict = C.Entry(author=local_identity.pubkey, seq=1, prev_hash=genesis.entry_hash,
                       timestamp=time.time(), type="TRANSFER",
                       payload={"asset": "car", "to": rec_pub, "terms": "v2"})
    C.mine_pow(conflict, DIFF)
    C.sign_entry(conflict, local_identity.sk)
    assert conflict.entry_hash != first.entry_hash
    status, existing = wstorage.record_witness(conflict)
    assert status == "FRAUD" and existing.entry_hash == first.entry_hash
    assert wstorage.record_witness(first)[0] == "OK"  # idempotent identical hash

    proof = C.FraudProof(entry_a=existing, entry_b=conflict)
    assert C.verify_fraud_proof(proof, DIFF)[0]
    assert wstorage.add_fraud_proof(proof)
    assert wstorage.is_blacklisted(local_identity.pubkey)

    # -- 1-byte SQLite mutation detection ----------------------------------
    raw = sqlite3.connect(str(node_dir / "log.db"))
    doc = raw.execute("SELECT entry_json FROM local_entries WHERE seq=1").fetchone()[0]
    anchor = doc.index('"prev_hash":"') + len('"prev_hash":"')
    flipped = doc[:anchor] + ("0" if doc[anchor] != "0" else "1") + doc[anchor + 1:]
    raw.execute("UPDATE local_entries SET entry_json=? WHERE seq=1", (flipped,))
    raw.commit()
    ok, reason = storage.verify_local_chain(local_identity.pubkey, DIFF)
    assert not ok, "1-byte mutation was not detected"
    raw.execute("UPDATE local_entries SET entry_json=? WHERE seq=1", (doc,))
    raw.commit()
    assert storage.verify_local_chain(local_identity.pubkey, DIFF)[0]
    raw.execute("UPDATE local_entries SET entry_hash=? WHERE seq=1", ("f" * 64,))
    raw.commit()
    assert not storage.verify_local_chain(local_identity.pubkey, DIFF)[0]
    raw.close()
    storage.close()

    # -- bundle tampering ---------------------------------------------------
    receipts = []
    for _ in range(K):
        wsk, wpk = C.create_keypair()
        receipt = C.Receipt(entry_hash=first.entry_hash, author=first.author,
                            seq=first.seq, witness=wpk, seen_at=time.time())
        C.sign_receipt(receipt, wsk)
        receipts.append(receipt)
    bundle = C.Bundle(entry=first, receipts=receipts)
    assert C.verify_bundle(bundle, k=K, difficulty=DIFF)[0]

    tampered = C.Bundle(entry=first, receipts=[C.Receipt(**r.to_dict()) for r in receipts])
    tampered.receipts[2].seen_at += 1.0
    assert not C.verify_bundle(tampered, k=K, difficulty=DIFF)[0]

    assert not C.verify_bundle(C.Bundle(entry=first, receipts=receipts[:K - 1]),
                               k=K, difficulty=DIFF)[0]

    dup = C.Bundle(entry=first, receipts=receipts[:K - 1] + [C.Receipt(**receipts[0].to_dict())])
    assert not C.verify_bundle(dup, k=K, difficulty=DIFF)[0]


# --------------------------------------------------------------------------
# 2) end-to-end transfer
# --------------------------------------------------------------------------

async def test_e2e_transfer(tmp_path):
    nodes = await start_cluster(tmp_path, 12)
    try:
        alice, bob, charlie = nodes[0], nodes[1], nodes[2]

        bundle1 = await alice.commit_entry(alice.build_entry(
            "TRANSFER", {"asset": "asset-1", "to": bob.pubkey,
                         "terms": "sale of asset-1 to Bob"}))
        assert bundle1.entry.seq == 1
        ok, reason = C.verify_bundle(bundle1, k=K, difficulty=DIFF)
        assert ok, reason
        assert len(bundle1.receipts) == K

        # Bob accepts: record the bundle, then publish his own ACCEPT entry.
        assert bob.storage.record_witness(bundle1.entry)[0] == "OK"
        for receipt in bundle1.receipts:
            bob.storage.add_receipt(receipt)
        accepted = await bob.commit_entry(bob.build_entry(
            "ACCEPT", {"entry_hash": bundle1.entry.entry_hash}))
        ok, reason = C.verify_bundle(accepted, k=K, difficulty=DIFF)
        assert ok, reason

        # Bob -> Charlie.
        bundle2 = await bob.commit_entry(bob.build_entry(
            "TRANSFER", {"asset": "asset-1", "to": charlie.pubkey,
                         "terms": "sale of asset-1 to Charlie"}))

        # Fully offline verification by Charlie — must be < 10 ms.
        start = time.perf_counter()
        ok, reason = C.verify_bundle(bundle2, k=K, difficulty=DIFF)
        elapsed = time.perf_counter() - start
        assert ok, reason
        assert elapsed < 0.010, f"offline verify took {elapsed * 1000:.2f} ms"

        assert charlie.storage.record_witness(bundle2.entry)[0] == "OK"
        assert alice.storage.verify_local_chain(alice.pubkey, DIFF)[0]
        assert bob.storage.verify_local_chain(bob.pubkey, DIFF)[0]
    finally:
        await stop_all(nodes)


# --------------------------------------------------------------------------
# 3) double-spend attack
# --------------------------------------------------------------------------

async def test_double_spend_attack(tmp_path):
    nodes = await start_cluster(tmp_path, 12)
    try:
        alice = nodes[0]
        base = await alice.commit_entry(alice.build_entry(
            "TRANSFER", {"asset": "car-vin-42", "to": nodes[1].pubkey,
                         "terms": "sale v1"}))
        assert base.entry.seq == 1

        def craft(to_key: str, terms: str) -> C.Entry:
            entry = alice.build_entry(
                "TRANSFER", {"asset": "car-vin-42", "to": to_key, "terms": terms})
            entry.seq = 2
            entry.prev_hash = base.entry.entry_hash
            entry.timestamp = time.time()
            C.mine_pow(entry, DIFF)
            C.sign_entry(entry, alice.identity.sk)
            return entry

        entry_a = craft(nodes[2].pubkey, "sell to Charlie")
        entry_b = craft(nodes[3].pubkey, "sell to Dave")
        assert entry_a.entry_hash != entry_b.entry_hash
        assert entry_a.seq == entry_b.seq == 2

        wset = alice.witnesses_for(entry_a)
        assert len(wset) == N

        async def propose(entry: C.Entry, witness) -> dict:
            return await alice.transport.rpc(
                witness.addr, "PROPOSE", {"entry": entry.to_dict()}, timeout=2.0)

        # Overlapping split: entry_a -> w[0:4], entry_b -> w[3:7] (witness 3 sees both).
        responses = await asyncio.gather(
            *(propose(entry_a, w) for w in wset[:4]),
            *(propose(entry_b, w) for w in wset[3:]))

        receipts_a = [r for r in responses[:4]
                      if r.get("ok") and "receipt" in (r.get("payload") or {})]
        receipts_b = [r for r in responses[4:]
                      if r.get("ok") and "receipt" in (r.get("payload") or {})]
        frauds = [r for r in responses
                  if r.get("ok") and "fraud" in (r.get("payload") or {})]

        assert len(receipts_a) <= 4, "fork A reached quorum"
        assert len(receipts_b) <= 4, "fork B reached quorum"
        assert len(frauds) >= 1, "no witness emitted a FRAUD_PROOF"

        proof = C.FraudProof.from_dict(frauds[0]["payload"]["fraud"])
        ok, reason = C.verify_fraud_proof(proof, DIFF)
        assert ok, reason
        assert proof.accused == alice.pubkey

        # The proof gossips across the swarm and blacklists Alice permanently.
        await asyncio.sleep(0.6)
        blacklisted = [n for n in nodes if n.storage.is_blacklisted(alice.pubkey)]
        assert len(blacklisted) >= 2, "fraud proof did not propagate"

        # Any further commit by Alice must fail.
        with pytest.raises(CommitError):
            await alice.commit_entry(alice.build_entry(
                "TRANSFER", {"asset": "car-vin-42", "to": nodes[4].pubkey,
                             "terms": "late attempt"}),
                rounds=2, attempt_timeout=0.6)
    finally:
        await stop_all(nodes)


# --------------------------------------------------------------------------
# 4) chaos: packet loss + witness kills
# --------------------------------------------------------------------------

async def test_chaos_packet_loss(tmp_path):
    random.seed(0xC0FFEE)
    nodes = await start_cluster(tmp_path, 12)
    try:
        alice, bob = nodes[0], nodes[1]
        for node in nodes:
            node.transport.protocol.drop_rate = 0.25   # 25% of all datagrams die

        entry = alice.build_entry(
            "TRANSFER", {"asset": "chaos-asset", "to": bob.pubkey,
                         "terms": "finality under chaos"})
        wset = alice.witnesses_for(entry)
        assert len(wset) == N

        node_map = {n.node_id: n for n in nodes}
        victims = [node_map[w.node_id] for w in wset[:2]]  # 2 of 7 witnesses

        commit_task = asyncio.create_task(
            alice.commit_entry(entry, rounds=12, attempt_timeout=0.8))
        await asyncio.sleep(0.4)                            # mid-flight...
        for victim in victims:
            await victim.stop()                             # ...kill witnesses

        bundle = await asyncio.wait_for(commit_task, timeout=30)
        ok, reason = C.verify_bundle(bundle, k=K, difficulty=DIFF)
        assert ok, reason
        assert len(bundle.receipts) == K

        survivors = [n for n in nodes if n not in victims]
        # A single ping through 25% loss fails with p~0.44; retry like a real RPC.
        pings_ok = 0
        for _ in range(6):
            if await survivors[3].dht.ping(survivors[4].addr) is not None:
                pings_ok += 1
        assert pings_ok >= 1, "network unusable after chaos"
    finally:
        await stop_all(nodes)


# --------------------------------------------------------------------------
# 5) spam defense
# --------------------------------------------------------------------------

async def test_spam_defense(tmp_path):
    nodes = await start_cluster(tmp_path, 6)
    try:
        victim, attacker = nodes[0], nodes[5]

        # -- flood 1: 40 fresh authors with provably invalid PoW --------------
        rejected = 0
        for _ in range(40):
            _, rec_pub = C.create_keypair()
            while True:  # regenerate until nonce=0 is *definitely* insufficient
                sk, pk = C.create_keypair()
                entry = C.Entry(author=pk, seq=0, prev_hash=C.ZERO_HASH,
                                timestamp=time.time(), type="GENESIS",
                                payload={"recovery_pubkey": rec_pub}, pow_nonce=0, sig="")
                if not C.pow_target_ok(entry.entry_hash, 0, DIFF):
                    break
            C.sign_entry(entry, sk)  # valid signature, invalid PoW
            resp = await attacker.transport.rpc(
                victim.addr, "PROPOSE", {"entry": entry.to_dict()}, timeout=1.5)
            if not (resp.get("ok") and "receipt" in (resp.get("payload") or {})):
                rejected += 1
        assert rejected == 40, "invalid-PoW flood was not cleanly rejected"

        # -- flood 2: valid entries above 10 req/min get rate limited ---------
        last = attacker.storage.last_local(attacker.pubkey)
        entry = attacker.build_entry(
            "TRANSFER", {"asset": "spam-asset", "to": victim.pubkey, "terms": "flood"})
        entry.seq = 1
        entry.prev_hash = last.entry_hash
        entry.timestamp = time.time()
        C.mine_pow(entry, DIFF)
        C.sign_entry(entry, attacker.identity.sk)

        receipts = 0
        for _ in range(30):
            resp = await attacker.transport.rpc(
                victim.addr, "PROPOSE", {"entry": entry.to_dict()}, timeout=1.5)
            if resp.get("ok") and "receipt" in (resp.get("payload") or {}):
                receipts += 1
        assert 1 <= receipts <= 10, f"token bucket failed: {receipts} receipts"

        # -- victim stays healthy --------------------------------------------
        assert await attacker.dht.ping(victim.addr) is not None
        ok, reason = victim.storage.verify_local_chain(victim.pubkey, DIFF)
        assert ok, reason
    finally:
        await stop_all(nodes)