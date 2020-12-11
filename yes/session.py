import hashlib
import secrets
from base64 import urlsafe_b64encode
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from abc import ABC, abstractmethod


@dataclass
class PKCE:
    verifier: str
    challenge: str

    def __init__(self):
        self.verifier = secrets.token_urlsafe(32)
        self.challenge = (
            urlsafe_b64encode(hashlib.sha256(bytes(self.verifier, "ascii")).digest())
            .decode("ascii")
            .replace("=", "")
        )


class YesSession(ABC):
    ac_state: str
    oidc_nonce: str
    pkce: PKCE
    issuer_url: Optional[str]
    server_config: Optional[Dict]
    authorization_code: Optional[str]
    access_token: Optional[str]

    @abstractmethod
    def __init__(self):
        self.ac_state = secrets.token_urlsafe(16)
        self.pkce = PKCE()


class YesIdentitySession(YesSession):
    claims: Dict
    acr_values: List
    oidc_nonce: str

    def __init__(self, claims, request_second_factor):
        super().__init__()
        self.claims = claims
        self.acr_values = (
            ["https://www.yes.com/acrs/online_banking_sca"]
            if request_second_factor
            else ["https://www.yes.com/acrs/online_banking"]
        )
        self.oidc_nonce = secrets.token_urlsafe(32)


class YesSigningSession(YesSession):
    qtsp_config: Optional[Dict]
    hash_algorithm_oid: str
    document_digests: Dict

    def __init__(self, hash_algorithm_oid: str, document_digests: Dict):
        super().__init__()
        self.hash_algorithm_oid = hash_algorithm_oid
        self.document_digests = document_digests
