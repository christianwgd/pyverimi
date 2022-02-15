import hashlib
import secrets
from abc import ABC, abstractmethod
from base64 import urlsafe_b64encode
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from decimal import Decimal, getcontext

from .documents import SigningDocument
from .hashes import HASH_ALGORITHMS, Hash
from .errors import YesError

@dataclass
class PKCE:
    """
    Class for managing PKCE (RFC7636). Automatically used by the yes flows.
    """
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
    oauth_configuration: Optional[Dict]
    service_configuration: Optional[Dict]
    authorization_code: Optional[str]
    access_token: Optional[str]
    authorization_details_enriched: Optional[Dict] = None

    @abstractmethod
    def __init__(self):
        self.ac_state = secrets.token_urlsafe(16)
        self.pkce = PKCE()


class YesIdentitySession(YesSession):
    """A session object for an identity flow."""
    claims: Dict
    acr_values: List
    oidc_nonce: str

    def __init__(self, claims: Dict[str, Dict], request_second_factor:bool):
        """
        Example:
            `claims` defines which claims are requested, using which verification level,
            and using which transport method.

            See https://yes.com/docs/rp-devguide/latest/IDENTITY/index.html#_requesting_claims for details on the syntax and semantics.

            Example:
            ```
            claims = {
                "id_token": {
                    "verified_claims": {
                        "claims": {"given_name": None,},
                        "verification": {"trust_framework": None},
                    }
                },
                "userinfo": {
                    "verified_claims": {
                        "claims": {"family_name": None,},
                        "verification": {"trust_framework": None},
                    }
                },
            }
            ```

        Args:
            claims (Dict[str, Dict]): Define the claims that are to be requested from the IDP and how they are transported.
            request_second_factor (bool): Demand the use of the second factor from the user.
        """
        YesSession.__init__(self)
        self.claims = claims
        self.acr_values = (
            ["https://www.yes.com/acrs/online_banking_sca"]
            if request_second_factor
            else ["https://www.yes.com/acrs/online_banking"]
        )
        self.oidc_nonce = secrets.token_urlsafe(32)


class YesSigningSession(YesSession):
    """A session object for a signing flow.
    
    When using PDFSigningDocuments, consider adding a more efficient
    session storage. See the documentation for yes.PDFSigningDocument
    for details.
    """
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
        """
        Args:
            documents (List[SigningDocument]): List of `yes.SigningDocument` objects to be signed.
            identity_assurance_claims (List[str], optional): Optional list of claims to be included in the certificate, see yes® documentation on QID/QESID. Defaults to [].
            hash_algorithm (Hash, optional): The hash algorithm to use for signing the document. Defaults to HASH_ALGORITHMS["SHA-256"].
        """
        YesSession.__init__(self)
        self.hash_algorithm = hash_algorithm
        self.identity_assurance_claims = identity_assurance_claims
        self.documents = []
        for document in documents:
            if not isinstance(document, SigningDocument):
                raise Exception(
                    f"Please provide documents as yes.SigningDocument instances, not {document!r}."
                )
            document._set_session(self)
            self.documents.append(document)


class YesIdentitySigningSession(YesIdentitySession, YesSigningSession):
    def __init__(
        self,
        claims,
        request_second_factor,
        documents: List[SigningDocument],
        identity_assurance_claims: List[str] = [],
        hash_algorithm: Hash = HASH_ALGORITHMS["SHA-256"],
    ):
        YesIdentitySession.__init__(self, claims, request_second_factor)
        YesSigningSession.__init__(
            self, documents, identity_assurance_claims, hash_algorithm
        )


class YesPaymentSession(YesSession):
    amount: Decimal
    remittance_information: str
    creditor_name: str
    creditor_account_iban: str
    debtor_account_holder_name: Optional[Tuple[str, str]]
    debtor_account_iban: Optional[str]
    debtor_account_holder_same_name: bool
    currency: str

    def __init__(
        self,
        amount: Decimal,
        remittance_information: str,
        creditor_name: str,
        creditor_account_iban: str,
        debtor_account_holder_name: Optional[Tuple[str, str]] = None,
        debtor_account_iban: Optional[str] = None,
        debtor_account_holder_same_name: bool = False,
        currency: str = "EUR",
    ):
        self.amount = amount
        self.remittance_information = remittance_information
        self.creditor_name = creditor_name
        self.creditor_account_iban = creditor_account_iban
        if debtor_account_holder_name is not None and debtor_account_holder_same_name:
            raise YesError(
                "If debtor_account_holder_same_name is True, debtor_account_holder_name must be None."
            )
        self.debtor_account_holder_name = debtor_account_holder_name
        self.debtor_account_iban = debtor_account_iban
        self.debtor_account_holder_same_name = debtor_account_holder_same_name
        self.currency = currency
        if self.currency != "EUR":
            raise YesError("Currency other than EUR are not supported by the yes ecosystem right now.")

        YesSession.__init__(self)

class YesPaymentSigningSession(YesPaymentSession, YesSigningSession):
    def __init__(
        self,
        amount: Decimal,
        remittance_information: str,
        creditor_name: str,
        creditor_account_iban: str,
        debtor_account_holder_name: Optional[Tuple[str, str]] = None,
        debtor_account_iban: Optional[str] = None,
        debtor_account_holder_same_name: bool = False,
        currency: str = "EUR",
        documents: List[SigningDocument] = None,
        identity_assurance_claims: List[str] = [],
        hash_algorithm: Hash = HASH_ALGORITHMS["SHA-256"],
    ):
        YesPaymentSession.__init__(
            self,
            amount,
            remittance_information,
            creditor_name,
            creditor_account_iban,
            debtor_account_holder_name,
            debtor_account_iban,
            debtor_account_holder_same_name,
            currency,
        )
        YesSigningSession.__init__(
            self, documents, identity_assurance_claims, hash_algorithm
        )

class YesIdentityPaymentSession(YesIdentitySession, YesPaymentSession):
    def __init__(
        self,
        claims,
        request_second_factor,
        amount: Decimal,
        remittance_information: str,
        creditor_name: str,
        creditor_account_iban: str,
        debtor_account_holder_name: Optional[Tuple[str, str]] = None,
        debtor_account_iban: Optional[str] = None,
        debtor_account_holder_same_name: bool = False,
        currency: str = "EUR",
    ):
        YesIdentitySession.__init__(self, claims, request_second_factor)
        YesPaymentSession.__init__(
            self,
            amount,
            remittance_information,
            creditor_name,
            creditor_account_iban,
            debtor_account_holder_name,
            debtor_account_iban,
            debtor_account_holder_same_name,
            currency,
        )