# ReciprocalProof design and test plan

AI-assisted prototype, 2026-10-21. This is an independent IC contribution, not a Project extract.

Purpose: attest that an address caused a nonce-bound JSON statement to be published at two exact HTTPS public resources. Same-host resources are allowed. This is not proof of distinct people, legal ownership, identity, or Sybil resistance.

The contract owns immutable challenges, deadlines, replay protection, revocation and the consensus boundary. Resource operators own the JSON bytes. Integrators read `is_active` and bind the audience to their own application.

Only the predefined raw.githubusercontent.com and gist.githubusercontent.com public content hosts may be enabled at deployment. Only HTTPS, default port, no credentials, query or fragment; URL length <=512. The source fetch rejects exposed non-200 responses, non-UTF8/duplicate JSON keys/extra fields and bodies over 4096 bytes. The pinned SDK provides no redirect-policy/final-URL field or pre-download response-size setting: these checks apply to the requested URL and returned body. Runtime transport security and any automatically followed redirects remain a trust boundary, explicitly disclosed in README.

Challenge ID binds chain, deployed contract, sequence, requester, audience, exact URL pair and a 32-byte nonce never reusable by that requester. Replay keys are requester-scoped so a third party cannot burn somebody else's public nonce. Proof JSON additionally binds challenge ID and deadline. Both resources must return exactly the statement. Leader and validators independently fetch BOTH resources and derive an exact canonical pair of valid/invalid results using a custom `run_nondet_unsafe` validator. No LLM. Only both valid permits OPEN -> VERIFIED. Requester can revoke OPEN/VERIFIED; deadline makes either inactive and permits EXPIRED materialization. Verification is single use; a changed resource requires a new challenge/nonce. Attestations describe an observation, not continuous hosting control.

Tests execute the actual `.py` contract through official `genlayer-test` direct mode: valid pair, changed validator resource, forged leader result, mismatched caller/audience/URLs/contract/nonce, malformed/oversized JSON, redirect/error response, caller control, expiry boundaries, replay and revoke. External HTTP is mocked only at the official nondeterministic boundary. Network consensus and deployment remain pending until root supplies real evidence.
