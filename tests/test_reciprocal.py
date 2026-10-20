import json
from pathlib import Path
import pytest

CONTRACT = str(Path(__file__).parents[1] / "reciprocal_proof.py")
URL_A = "https://raw.githubusercontent.com/example/proofs/main/a.json"
URL_B = "https://gist.githubusercontent.com/example/123/raw/b.json"
NONCE = "12" * 32

def deployed(direct_vm, direct_deploy):
    direct_vm.warp("2026-10-21T00:00:00Z")
    return direct_deploy(CONTRACT, ["raw.githubusercontent.com", "gist.githubusercontent.com"])

def open_one(contract, nonce=NONCE):
    return contract.open_challenge(URL_A, URL_B, "demo-app", nonce, 3600)

def serve(direct_vm, proof, body=None, status=200):
    text = json.dumps(proof) if body is None else body
    direct_vm.mock_web(r"raw\.githubusercontent\.com", {"status": status, "body": text})
    direct_vm.mock_web(r"gist\.githubusercontent\.com", {"status": status, "body": text})

def test_pair_creates_consensus_attestation(direct_vm, direct_deploy):
    """Catches missing both-resource consensus and missing verified transition."""
    c = deployed(direct_vm, direct_deploy)
    cid = open_one(c)
    assert len(cid) == 64
    proof = c.expected_proof(cid)
    assert proof["audience"] == "demo-app"
    assert proof["urls"] == [URL_A, URL_B]
    assert proof["nonce"] == NONCE
    serve(direct_vm, proof)
    c.verify(cid)
    assert c.get_challenge(cid)["status"] == "VERIFIED"
    assert c.is_active(cid, "demo-app") is True
    assert direct_vm.run_validator() is True

def test_validator_refetches_changed_second_resource(direct_vm, direct_deploy):
    """Catches leader-only or schema-only validation."""
    c = deployed(direct_vm, direct_deploy)
    cid = open_one(c)
    proof = c.expected_proof(cid)
    serve(direct_vm, proof)
    c.verify(cid)
    direct_vm.clear_mocks()
    direct_vm.mock_web(r"raw\.githubusercontent\.com", {"status": 200, "body": json.dumps(proof)})
    forged = dict(proof, audience="other-app")
    direct_vm.mock_web(r"gist\.githubusercontent\.com", {"status": 200, "body": json.dumps(forged)})
    assert direct_vm.run_validator() is False

def test_no_replay_and_requester_can_revoke(direct_vm, direct_deploy):
    """Catches reused nonce, repeated verify and revoked activity."""
    c = deployed(direct_vm, direct_deploy)
    cid = open_one(c)
    serve(direct_vm, c.expected_proof(cid))
    c.verify(cid)
    with direct_vm.expect_revert("not open"):
        c.verify(cid)
    with direct_vm.expect_revert("nonce already used"):
        open_one(c)
    c.revoke(cid)
    assert c.get_challenge(cid)["status"] == "REVOKED"
    assert c.is_active(cid, "demo-app") is False

def test_public_nonce_squatting_cannot_block_another_requester(direct_vm, direct_deploy):
    """Catches a global nonce key that lets another caller burn a public nonce."""
    c = deployed(direct_vm, direct_deploy)
    first = open_one(c)
    from gltest.direct import create_address
    direct_vm.sender = create_address("second-requester")
    second = open_one(c)
    assert first != second
    assert c.expected_proof(first)["requester"] != c.expected_proof(second)["requester"]
    serve(direct_vm, c.expected_proof(second))
    c.verify(second)
    assert c.is_active(second, "demo-app") is True
    with direct_vm.expect_revert("nonce already used"):
        open_one(c)

def test_unauthorized_verify_or_revoke(direct_vm, direct_deploy):
    """Catches sender/origin confusion or missing caller guard."""
    c = deployed(direct_vm, direct_deploy)
    cid = open_one(c)
    from gltest.direct import create_address
    direct_vm.sender = create_address("intruder")
    for action in (c.verify, c.revoke):
        with direct_vm.expect_revert("requester only"):
            action(cid)

@pytest.mark.parametrize("field,value", [("nonce", "34"*32), ("audience", "other"), ("requester", "0x"+"00"*20), ("contract", "0x"+"00"*20), ("challenge_id", "00"*32), ("deadline", 1), ("urls", [URL_B, URL_A])])
def test_context_mismatch_fails_closed(direct_vm, direct_deploy, field, value):
    """Catches missing binding of each meaningful statement field."""
    c = deployed(direct_vm, direct_deploy)
    cid = open_one(c)
    proof = dict(c.expected_proof(cid))
    proof[field] = value
    serve(direct_vm, proof)
    with direct_vm.expect_revert("proof mismatch"):
        c.verify(cid)
    assert c.get_challenge(cid)["status"] == "OPEN"

@pytest.mark.parametrize("bad_url", ["http://raw.githubusercontent.com/a", "https://localhost/a", "https://127.0.0.1/a", "https://raw.githubusercontent.com.evil.com/a", "https://user@raw.githubusercontent.com/a", "https://raw.githubusercontent.com:443/a", "https://raw.githubusercontent.com/a?x=1", "https://raw.githubusercontent.com/a#x"])
def test_rejects_unsafe_urls(direct_vm, direct_deploy, bad_url):
    c = deployed(direct_vm, direct_deploy)
    with direct_vm.expect_revert():
        c.open_challenge(bad_url, URL_B, "demo-app", NONCE, 3600)

@pytest.mark.parametrize("body,status", [("{}", 200), ("[]", 200), ("x"*4097, 200), ("not-json", 200), ("{}", 302), ("{}", 404), ('{"nonce":"a","nonce":"b"}', 200)])
def test_rejects_bad_resources_without_attestation(direct_vm, direct_deploy, body, status):
    c = deployed(direct_vm, direct_deploy)
    cid = open_one(c)
    serve(direct_vm, {}, body=body, status=status)
    with direct_vm.expect_revert("proof mismatch"):
        c.verify(cid)
    assert c.get_challenge(cid)["status"] == "OPEN"

def test_expiry_boundary_and_audience(direct_vm, direct_deploy):
    c = deployed(direct_vm, direct_deploy)
    cid = open_one(c)
    serve(direct_vm, c.expected_proof(cid))
    c.verify(cid)
    assert c.is_active(cid, "another-app") is False
    direct_vm.warp("2026-10-21T01:00:00Z")
    assert c.is_active(cid, "demo-app") is False
    c.expire(cid)
    assert c.get_challenge(cid)["status"] == "EXPIRED"
