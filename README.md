# QuorumLog

A peer-to-peer trust protocol built from **personal hash-chains**, **Kademlia DHT
routing**, and **threshold witness receipts**. No blockchain, no global ledger, no
mining, no native token.

## Design

Each identity owns a *personal hash-chain* of signed entries:

```
GENESIS(seq 0) -> TRANSFER(1) -> ACCEPT(2) -> TRANSFER(3) -> ... -> KEY_ROTATE
```

Finality is **not** a global ledger. An entry is final when **K = 5 of N = 7**
witnesses have signed receipts for its `(author, seq)` slot. Witnesses are chosen
*deterministically*:

```
target     = SHA256("{author_pubkey}:{seq // 100}")
witnesses  = the 7 closest active peers to `target` by XOR distance
             (author excluded; at most 1 peer per /16 IP subnet)
```

Same peer view ⇒ same witness set, so everyone knows who is *supposed* to
witness a given entry. A witness that sees **two validly-signed entries claiming
the same `(author, seq)` with different hashes** emits a `FraudProof`, permanently
blacklists the author locally, and gossips the proof to 5 peers.

A `Bundle` (entry + K receipts) is the portable unit of finality: anyone can
verify it **fully offline** — structure, Ed25519 signatures, PoW, and K distinct
witness signatures — with zero network calls.

## Anti-abuse

| Vector            | Defense                                                        |
|-------------------|----------------------------------------------------------------|
| Entry flooding    | Hashcash PoW: `SHA256(entry_hash + nonce)` needs D=14 leading zero bits |
| Per-author spam   | Token bucket: burst 10, refill 10 req/min, per author pubkey   |
| Double spend      | Atomic `(author, seq)` uniqueness per witness + FraudProof gossip |
| Fraud propagation | FraudProof carries both conflicting signed entries — self-verifying |
| Key compromise    | `KEY_ROTATE` is dual-signed by the active key **and** the offline recovery key |

## Files

| File                | Role                                                          |
|---------------------|---------------------------------------------------------------|
| `crypto.py`         | Canonical JSON, SHA-256, Ed25519 (PyNaCl), PoW, offline Bundle/FraudProof verification |
| `storage.py`        | SQLite (WAL) logs, witnessed records, receipts, blacklist, peer cache; atomic `record_witness`; chain integrity checker |
| `network.py`        | asyncio UDP transport (64 KiB cap, 2 s RPC timeout), XOR routing table (PING/FIND_NODE), deterministic witness selection |
| `node.py`           | `QuorumNode`: PROPOSE/RECEIPT/FRAUD_PROOF/SYNC handlers, rate limiting, quorum collector with retries |
| `cli.py`            | `init` / `daemon` / `transfer` / `accept` / `verify` / `rotate-key` |
| `test_quorumlog.py` | Unit tamper tests, 12-node E2E, double-spend attack, 25% packet-loss chaos, spam defense |

## Quick start

```bash
pip install -r requirements.txt          # pynacl, pytest, pytest-asyncio
python -m pytest test_quorumlog.py -v    # full suite, incl. 12-node swarm
```

Run a real swarm (use the same `--difficulty` on every node):

```bash
for i in 1 2 3 4 5 6; do python cli.py init --dir ./node$i --difficulty 14 --name n$i; done

python cli.py daemon --dir ./node1 --port 8001 --difficulty 14 &
python cli.py daemon --dir ./node2 --port 8002 --difficulty 14 --bootstrap 127.0.0.1:8001 &
# ... start nodes 3..6 the same way, all bootstrapping to 8001

python cli.py transfer --dir ./node1 --asset deed-42 \
    --to $(python -c "import json;print(json.load(open('node2/identity.json'))['pubkey'])") \
    --terms terms.txt --out tx.bundle.json \
    --bootstrap 127.0.0.1:8001 --difficulty 14

python cli.py accept  --dir ./node2 --bundle tx.bundle.json \
    --bootstrap 127.0.0.1:8002 --difficulty 14
python cli.py verify  --bundle tx.bundle.json          # offline, exit 0/1
python cli.py rotate-key --dir ./node1 \
    --recovery-key ./node1/recovery_key.json \
    --bootstrap 127.0.0.1:8001 --difficulty 14
```

Key files (`identity.json`, `recovery_key.json`) are written atomically with
`0600` permissions; bundles are written `0600` as well.

## Threat model & guarantees

* **Finality**: K distinct witnesses (never the author) signed receipts for the
  exact `entry_hash` at `(author, seq)`. Offline verifiers trust that quorum,
  not any single server.
* **Chain integrity**: witnesses verify PoW, signatures and `prev_hash` linkage
  (pulling the author's chain via `SYNC` when needed) before receipting; local
  chains can be byte-tamper-checked anytime with `verify_local_chain`.
* **Conflict detection**: a witness that already recorded `(author, seq)` with a
  different hash returns a FraudProof instead of a receipt. Quorum becomes
  unreachable for both forks, and the author is permanently blacklisted.
* **Liveness under chaos**: the collector retries failed witnesses for several
  rounds, so K-of-N survives packet loss and dead witnesses as long as K nodes
  remain reachable.

## Known limitations (kept intentionally simple)

* UDP-only, single socket per node; NAT traversal is out of scope (LAN /
  public-IP deployments).
* `difficulty` is network-wide configuration, not difficulty-adjusted.
* Cross-author `KEY_ROTATE` linkage (old chain → new chain) is validated
  best-effort: witnesses that hold the author's old chain cross-check it; the
  cryptographic anchor is the dual signature inside the rotation entry.
* Witness-set membership is not re-verified offline (that would require the
  swarm's peer view); the offline check covers signatures, PoW, and K distinct
  valid receipts.