from abc import ABC, abstractmethod
from base64 import b64encode

from .errors import YesError
from .hashes import HASH_ALGORITHMS


class SigningDocument(ABC):
    def set_session(self, session):
        self.session = session

    @abstractmethod
    def get_authz_details(self):
        pass

    @abstractmethod
    def get_hash(self):
        pass

    def process_signature(self, signature_bytes, revocation_info_base64):
        self.signature = signature_bytes
        self.revocation_info = revocation_info_base64


class RawSigningDocument(SigningDocument):
    SUPPORTED_SIGNATURE_FORMATS = ("C", "P")

    def __init__(self, label, hash):
        self.hash = hash
        self.label = label

    def get_authz_details(self):
        return {
            "hash": self.hash,
            "label": self.label,
        }

    def get_hash(self):
        return self.hash


class TextSigningDocument(SigningDocument):
    SUPPORTED_SIGNATURE_FORMATS = ("C", "P")

    def __init__(self, label, text):
        self.text = text
        self.label = label

    def get_authz_details(self):
        algo = self.session.hash_algorithm.algo
        self.hash = b64encode(algo(self.text.encode("utf-8")).digest()).decode("ascii")
        return {
            "hash": self.hash,
            "label": self.label,
        }

    def get_hash(self):
        return self.hash



class DefaultSigningDocument(TextSigningDocument):
    SUPPORTED_SIGNATURE_FORMATS = "C"

    label = ""

    def __init__(self, allowed_languages):
        self.allowed_languages = allowed_languages

    def get_authz_details(self):
        # Inspect the QTSP's configuration to find the default document matching the requested language(s)
        chosen_default_doc = next(
            d
            for d in self.session.qtsp_config["default_signing_documents"]
            if d["lang"] in self.allowed_languages
        )
        if chosen_default_doc is None:
            raise YesError(
                f"No default document found with selected language(s). Available languages: {', '.join(d['lang'] for d in self.session.qtsp_config['default_signing_documents'])}"
            )
        self.text = chosen_default_doc['text']
        return super().get_authz_details()
