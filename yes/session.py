import hashlib
import secrets
from base64 import urlsafe_b64encode
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


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


class YesSession:
    claims: Dict
    acr_values: List
    ac_state: str
    oidc_nonce: str
    pkce: PKCE
    issuer_url: Optional[str]
    oidc_config: Optional[Dict]
    authorization_code: Optional[str]
    access_token: Optional[str]

    def __init__(self, claims, acr_values):
        self.claims = claims
        self.acr_values = acr_values
        self.ac_state = secrets.token_urlsafe(16)
        self.pkce = PKCE()
        self.oidc_nonce = secrets.token_urlsafe(32)

