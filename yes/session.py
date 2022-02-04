import hashlib
import secrets
from abc import ABC, abstractmethod
from base64 import urlsafe_b64encode
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .documents import SigningDocument
from .hashes import HASH_ALGORITHMS, Hash


@dataclass
class PKCE:
    verifier: str
    challenge: str

    def __init__(self):
        self.verifier = secrets.token_urlsafe(64)
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
    hash_algorithm: Hash
    documents: List[SigningDocument]
    identity_assurance_claims: List[str]

    def __init__(
        self,
        documents: List[SigningDocument],
        identity_assurance_claims: List[str] = [],
        hash_algorithm: Hash = HASH_ALGORITHMS["SHA-256"],
    ):
        super().__init__()
        self.hash_algorithm = hash_algorithm
        self.identity_assurance_claims = identity_assurance_claims
        self.documents = []
        for document in documents:
            document.set_session(self)
            self.documents.append(document)

