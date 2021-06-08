import hashlib
from dataclasses import dataclass

@dataclass
class Hash:
    name: str
    oid: str
    algo: object

    def __str__(self):
        return self.name

HASH_ALGORITHMS = {
    "SHA-256": Hash("SHA-256", "2.16.840.1.101.3.4.2.1", hashlib.sha256),
    "SHA-384": Hash("SHA-384", "2.16.840.1.101.3.4.2.2", hashlib.sha384),
    "SHA-512": Hash("SHA-512", "2.16.840.1.101.3.4.2.3", hashlib.sha512),
    "SHA3-256": Hash("SHA3-256", "2.16.840.1.101.3.4.2.8", hashlib.sha3_256),
    "SHA3-384": Hash("SHA3-384", "2.16.840.1.101.3.4.2.9", hashlib.sha3_384),
    "SHA3-512": Hash("SHA3-512", "2.16.840.1.101.3.4.2.10", hashlib.sha3_512),
}
