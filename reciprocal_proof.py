# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
from genlayer import *
import hashlib
import json
import re
from datetime import datetime, timezone


def _now() -> int:
    value = datetime.fromisoformat(gl.message_raw["datetime"].replace("Z", "+00:00"))
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    delta = value.astimezone(timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return delta.days * 86400 + delta.seconds


def _unique_object(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _matches(url: str, expected_json: str) -> bool:
    # Transport errors propagate and abort the transaction; they are not proofs.
    response = gl.nondet.web.get(url, headers={"Accept": "application/json"})
    if response.status != 200 or response.body is None or len(response.body) > 4096:
        return False
    try:
        data = json.loads(response.body.decode("utf-8"), object_pairs_hook=_unique_object)
        # Canonical JSON comparison preserves int/bool distinctions and rejects extras.
        return json.dumps(data, sort_keys=True, separators=(",", ":")) == expected_json
    except (ValueError, UnicodeError, TypeError):
        return False

class ReciprocalProof(gl.Contract):
    allowed_hosts: DynArray[str]
    challenges: TreeMap[str, str]
    used_nonces: TreeMap[str, bool]
    sequence: u256

    def __init__(self, allowed_hosts: list[str]):
        if not isinstance(allowed_hosts, list) or not 1 <= len(allowed_hosts) <= 2:
            raise gl.vm.UserError("[EXPECTED] select one or two public proof hosts")
        for host in allowed_hosts:
            if host not in ("raw.githubusercontent.com", "gist.githubusercontent.com"):
                raise gl.vm.UserError("[EXPECTED] host is not a supported public proof host")
            if host in self.allowed_hosts:
                raise gl.vm.UserError("[EXPECTED] duplicate host")
            self.allowed_hosts.append(host)

    def _url(self, url: str) -> None:
        if not isinstance(url, str) or not 12 <= len(url) <= 512:
            raise gl.vm.UserError("[EXPECTED] invalid URL length")
        match = re.fullmatch(r"https://([a-z.]+)/([A-Za-z0-9/_.~-]+)", url)
        if match is None or match[1] not in self.allowed_hosts:
            raise gl.vm.UserError("[EXPECTED] URL must use an enabled exact HTTPS public host")
        if any(part in ("", ".", "..") for part in match[2].split("/")):
            raise gl.vm.UserError("[EXPECTED] noncanonical path")

    def _get(self, challenge_id: str) -> dict:
        if challenge_id not in self.challenges:
            raise gl.vm.UserError("[EXPECTED] unknown challenge")
        return json.loads(self.challenges[challenge_id])

    def _requester(self, data: dict) -> None:
        if gl.message.sender_address.as_hex.lower() != data["proof"]["requester"]:
            raise gl.vm.UserError("[EXPECTED] requester only")

    def _save(self, challenge_id: str, data: dict) -> None:
        self.challenges[challenge_id] = json.dumps(data, sort_keys=True)

    @gl.public.write
    def open_challenge(self, url_a: str, url_b: str, audience: str, nonce: str, ttl_seconds: int) -> str:
        self._url(url_a)
        self._url(url_b)
        if url_a == url_b:
            raise gl.vm.UserError("[EXPECTED] two distinct resource URLs required")
        if not isinstance(audience, str) or not 1 <= len(audience) <= 128 or audience != audience.strip():
            raise gl.vm.UserError("[EXPECTED] audience length or whitespace")
        if not isinstance(nonce, str) or re.fullmatch(r"[0-9a-f]{64}", nonce) is None:
            raise gl.vm.UserError("[EXPECTED] nonce must be 32 bytes of lowercase hex")
        requester = gl.message.sender_address.as_hex.lower()
        nonce_key = requester + ":" + nonce
        if nonce_key in self.used_nonces:
            raise gl.vm.UserError("[EXPECTED] nonce already used")
        if type(ttl_seconds) is not int or not 300 <= ttl_seconds <= 86400:
            raise gl.vm.UserError("[EXPECTED] ttl must be 300..86400 seconds")
        proof = {
            "protocol": "genlayer-reciprocal-proof/v1",
            "chain_id": int(gl.message.chain_id),
            "contract": gl.message.contract_address.as_hex.lower(),
            "requester": requester,
            "audience": audience,
            "nonce": nonce,
            "urls": [url_a, url_b],
            "deadline": _now() + ttl_seconds,
            "sequence": int(self.sequence),
        }
        challenge_id = hashlib.sha256(json.dumps(proof, sort_keys=True).encode()).hexdigest()
        proof["challenge_id"] = challenge_id
        self._save(challenge_id, {"status": "OPEN", "proof": proof, "verified_at": 0, "revoked_at": 0})
        self.used_nonces[nonce_key] = True
        self.sequence = u256(int(self.sequence) + 1)
        return challenge_id

    @gl.public.view
    def expected_proof(self, challenge_id: str) -> dict:
        return self._get(challenge_id)["proof"]

    @gl.public.write
    def verify(self, challenge_id: str) -> None:
        data = self._get(challenge_id)
        self._requester(data)
        if data["status"] != "OPEN":
            raise gl.vm.UserError("[EXPECTED] challenge not open")
        if _now() >= data["proof"]["deadline"]:
            raise gl.vm.UserError("[EXPECTED] challenge expired")
        # Capture only memory values; no storage access in the nondet closure.
        expected_json = json.dumps(data["proof"], sort_keys=True, separators=(",", ":"))
        url_a, url_b = data["proof"]["urls"]

        def independently_check_pair() -> str:
            first = _matches(url_a, expected_json)
            second = _matches(url_b, expected_json)
            return json.dumps([first, second], separators=(",", ":"))

        def validate_pair(leader: gl.vm.Result) -> bool:
            if not isinstance(leader, gl.vm.Return) or not isinstance(leader.calldata, str):
                return False
            # Re-fetch BOTH resources. Compare exact normalized derived results.
            return independently_check_pair() == leader.calldata

        pair = gl.vm.run_nondet_unsafe(independently_check_pair, validate_pair)
        if pair != "[true,true]":
            raise gl.vm.UserError("[EXPECTED] public proof mismatch")
        data["status"] = "VERIFIED"
        data["verified_at"] = _now()
        self._save(challenge_id, data)

    @gl.public.write
    def revoke(self, challenge_id: str) -> None:
        data = self._get(challenge_id)
        self._requester(data)
        if data["status"] not in ("OPEN", "VERIFIED"):
            raise gl.vm.UserError("[EXPECTED] challenge is terminal")
        data["status"] = "REVOKED"
        data["revoked_at"] = _now()
        self._save(challenge_id, data)

    @gl.public.write
    def expire(self, challenge_id: str) -> None:
        data = self._get(challenge_id)
        if _now() < data["proof"]["deadline"]:
            raise gl.vm.UserError("[EXPECTED] deadline not reached")
        if data["status"] not in ("OPEN", "VERIFIED"):
            raise gl.vm.UserError("[EXPECTED] challenge is terminal")
        data["status"] = "EXPIRED"
        self._save(challenge_id, data)

    @gl.public.view
    def get_challenge(self, challenge_id: str) -> dict:
        return self._get(challenge_id)

    @gl.public.view
    def is_active(self, challenge_id: str, audience: str) -> bool:
        data = self._get(challenge_id)
        return data["status"] == "VERIFIED" and data["proof"]["audience"] == audience and _now() < data["proof"]["deadline"]
