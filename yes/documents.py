import tempfile
from abc import ABC, abstractmethod
from base64 import b64decode, b64encode
from datetime import datetime
from io import BytesIO
from pathlib import Path

import tzlocal
from asn1crypto import crl
from asn1crypto.ocsp import OCSPResponse
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import fields, signers, validation
from pyhanko.sign.fields import SigSeedSubFilter

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
        self.text = chosen_default_doc["text"]
        return super().get_authz_details()


class PDFSigningDocument(SigningDocument):
    hash = None

    def __init__(self, label, pdffile):
        self.label = label
        self.input_file = pdffile

    def set_session(self, session):
        if session.hash_algorithm != HASH_ALGORITHMS["SHA-256"]:
            raise Exception("This library only supports SHA-256 for signing documents.")
        return super().set_session(session)

    def prepare_pdf(self):
        # write an in-place certification signature using the PdfCMSEmbedder
        # low-level API directly.
        self.input_file.seek(0)
        input_buf = BytesIO(self.input_file.read())
        w = IncrementalPdfFileWriter(input_buf)

        # Phase 1: coroutine sets up the form field
        cms_writer = signers.PdfCMSEmbedder().write_cms(
            field_name="Signature", writer=w
        )
        sig_field_ref = next(cms_writer)

        # just for kicks, let's check
        assert sig_field_ref.get_object()["/T"] == "Signature"

        # Phase 2: make a placeholder signature object,
        # wrap it up together with the MDP config we want, and send that
        # on to cms_writer
        timestamp = datetime.now(tz=tzlocal.get_localzone())
        sig_obj = signers.SignatureObject(
            timestamp=timestamp, bytes_reserved=20000, subfilter=SigSeedSubFilter.PADES
        )
        md_algorithm = "sha256"
        cms_writer.send(
            signers.SigObjSetup(
                sig_placeholder=sig_obj,
                mdp_setup=signers.SigMDPSetup(
                    md_algorithm=md_algorithm,
                    certify=True,
                    docmdp_perms=fields.MDPPerm.NO_CHANGES,
                ),
            )
        )
        # Phase 3: write & hash the document (with placeholder)
        document_hash = cms_writer.send(
            signers.SigIOSetup(md_algorithm=md_algorithm, in_place=True)
        )
        self.cms_writer = cms_writer
        self.hash = b64encode(document_hash).decode("ascii")

    def get_authz_details(self):
        return {
            "label": self.label,
            "hash": self.get_hash(),
        }

    def get_hash(self):
        if not self.hash:
            self.prepare_pdf()
        return self.hash

    def process_signature(self, signature_bytes, revocation_info_base64):
        parsed_ocsps = [
            OCSPResponse.load(b64decode(r.encode("ascii")))
            for r in revocation_info_base64["ocsp"]
        ]
        parsed_crls = [
            crl.CertificateList.load(b64decode(c.encode("ascii")))
            for c in revocation_info_base64["crl"]
        ]

        output, sig_contents = self.cms_writer.send(signature_bytes)

        validation.DocumentSecurityStore.add_dss(
            output_stream=output,
            sig_contents=sig_contents,
            certs=[],
            ocsps=parsed_ocsps,
            crls=parsed_crls,
        )
        self.signed_file = tempfile.NamedTemporaryFile('w+b')
        output.seek(0)
        while data := output.read(8192):
            self.signed_file.write(data)

        self.signed_file.seek(0)
