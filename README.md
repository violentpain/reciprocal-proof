# ReciprocalProof

AI-assisted, unaudited prototype. A standalone GenLayer Intelligent Contract for nonce-bound publication control across two public HTTPS resource URLs. It is an independent contribution, not a Project extract.

Use it when an integration needs a shared, independently verified observation that a wallet caused the same context-bound proof to appear at two resources. Leader and validators each fetch **both** resources, derive their own boolean pair, and compare the exact canonical pair through a custom `gl.vm.run_nondet_unsafe` validator. Only `[true,true]` changes state to VERIFIED. No LLM or private backend decides the attestation.

Same-host URLs are allowed. This does not establish distinct people, identity, legal ownership, authorship, or Sybil resistance. A shared service account controlling both resources can satisfy it.

## Standalone source and deployment

The only deployable file is `reciprocal_proof.py`. It pins runner `py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6`. Deploy with one constructor argument:

```json
[["raw.githubusercontent.com", "gist.githubusercontent.com"]]
```

The constructor may select one or both of these exact public content hosts. There is no owner override or mutable host configuration. No credentials/private keys are inputs.

Deployed on GenLayer Studionet, chain ID 61999, in Studio Normal (Full Consensus) mode. The recorded deployment transaction is FINALIZED with SUCCESS:

- Contract: `0x08d8B6bd6bC15dbdcF9A8cE4924C793fe624406F`
- Deployment transaction: `0xb55168a63f41c7e7cabc4a5a31df9e1f13f4e6d261106852b631ecc3a62caa9e`
- Deployed source SHA-256: `4f28974591c9a3e6282095eef7765f6f47abcad63d913c5b94dc3127fd6fceca`

See `evidence/deployment.json` for recorded parameters and verification scope. **Only constructor deployment has been verified live.** Opening, publishing and independently verifying an actual two-resource proof, plus revoke/expiry writes, remain unverified on the live network. The existing direct-test evidence remains separate from deployment evidence.

## API and use

| Method | Behavior |
|---|---|
| `open_challenge(url_a,url_b,audience,nonce,ttl_seconds) -> str` | Caller becomes requester; returns a 64-hex challenge ID. TTL is 300..86400 seconds; nonce is 64 lowercase hex characters and never reusable by that requester in this deployment. |
| `expected_proof(id) -> dict` | Exact JSON statement to publish at BOTH resources. Copy its complete output, including protocol, chain, contract, requester, audience, nonce, exact ordered URLs, deadline, sequence and challenge ID. |
| `verify(id)` | Requester only, once while OPEN and before deadline. Each validator fetches both resources independently; mismatch fails without attesting. |
| `revoke(id)` | Requester permanently revokes OPEN or VERIFIED. |
| `expire(id)` | Anyone can materialize EXPIRED at/after deadline. |
| `get_challenge(id) -> dict` | Full immutable proof context plus status/observation times. |
| `is_active(id,audience) -> bool` | True only for VERIFIED, exact audience match, and transaction time strictly before deadline. |

Create a challenge, publish its returned statement, then verify. Generate a fresh cryptographically random nonce off-chain; the contract checks uniqueness and format, not entropy. URL paths must contain only ASCII letters/digits and `/_.~-`, have no empty/dot segments, and be <=512 characters. Distinct URLs are required; HTTPS port/credentials/query/fragment/encoded path syntax are rejected. Audience is an exact integration identifier, 1..128 characters.

For integration, inspect the record and bind requester, audience, contract, chain and exact resource URLs to your own request. Read only the network's appropriately finalized state and handle appeals. Treat the proof as an observation made at `verified_at`, valid at most until its deadline. A resource change requires a fresh challenge/nonce; resource removal is **not monitored**. Integrators needing fresher control should request a short TTL and a new proof.

## Threat model and limits

Attackers may forge JSON, reuse proofs from another deployment/audience/address/URL pair, alter one resource, inject extra/duplicate keys, serve oversized bodies, or propose a dishonest leader result. The contract rejects these, preserves exact JSON number/bool distinctions, enforces caller access, and consumes each requester-scoped nonce when opening the challenge. The same public nonce used by another address cannot block the intended requester and produces a different challenge/proof. A dishonest leader must match validators' fresh derivation; JSON shape alone is insufficient.

The requested-host allowlist is intentionally narrow. **The pinned SDK has no redirect policy, final-URL field, or pre-download size setting.** The contract rejects exposed non-200 responses and bodies above 4096 bytes after receipt. Runtime transport behavior, any automatically followed redirects, DNS/TLS and the approved content platforms remain a trust boundary. It does not prove a network-level fetch stayed on the initial host or bound bandwidth before download. Do not expand it to arbitrary URLs without solving that transport boundary.

HTTPS responses must be UTF-8 JSON objects exactly matching the expected statement. Non-200 status, malformed JSON, duplicate keys, extras and mismatches cannot attest. Transient transport failures abort; they may require retry and do not mean control is disproven. Concurrent content changes may prevent consensus. Revocation is on-chain and requester controlled; key compromise defeats that authority. Storage grows with challenges and no deletion/garbage collection is implemented.

## Verification and reproducibility

Python 3.12+ is required. From this standalone directory:

```text
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements.txt
.venv/Scripts/python.exe tools/verify.py
```

On Linux/macOS use `.venv/bin/python`. Verification downloads the official GenVM `v0.2.12` artifact, loads the exact runner's SDK, executes this actual contract using official direct mode, then runs SDK semantic lint and ABI extraction. Test-only compatibility in `tests/conftest.py` defers gltest 0.29.2's Windows unlink of an open stdin message file and synchronizes its documented `warp()` metadata. It does not replace contract/storage/nondeterministic/validator algorithms. External HTTP is mocked at the official web boundary; captured validators execute for real and independently consume replaced resource fixtures.

Evidence: `evidence/tdd-red-valid.log` records the initial real NOT_IMPLEMENTED failure; `evidence/tdd-green.log` records the first 27 passing contract tests. A later requester-scoped nonce regression is preserved in `evidence/nonce-squatting-red.log`; the final verification suite includes that regression. `evidence/verification.json` is the historical local verification record and binds the source digest to tests/lint/schema results; its deployment field predates the separately recorded deployment in `evidence/deployment.json`. Earlier dependency/runner failures are preserved separately. Tests cover state transitions, replay, context forgery, changed validator resources, caller access, expiry and bad responses. Live proof fetches, proof-consensus writes and gas costs remain unverified. No users, audits or production outcomes are claimed.

Official references checked on 2026-10-21: [current boilerplate](https://github.com/genlayerlabs/genlayer-project-boilerplate), [storage](https://docs.genlayer.com/developers/intelligent-contracts/features/storage), [transaction context](https://docs.genlayer.com/developers/intelligent-contracts/features/transaction-context), [equivalence principles](https://docs.genlayer.com/developers/intelligent-contracts/equivalence-principle), [direct runner API](https://github.com/genlayerlabs/genlayer-testing-suite/blob/main/docs/direct-runner.md), [GenVM v0.2.12](https://github.com/genlayerlabs/genvm/releases/tag/v0.2.12). Actual pinned SDK source was inspected for web, message, storage and validator signatures.

MIT licensed. See `LICENSE`.
