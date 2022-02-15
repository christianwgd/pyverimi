import tempfile
from abc import ABC, abstractmethod
from base64 import b64decode, b64encode
from datetime import datetime
from io import BytesIO
from typing import BinaryIO, List, Optional, Tuple
from pyhanko.pdf_utils.writer import BasePdfFileWriter, PdfFileWriter
from pyhanko.sign.signers.pdf_signer import PdfTBSDocument

from pyhanko_certvalidator import ValidationContext


from asn1crypto import crl
from asn1crypto.ocsp import OCSPResponse
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import fields, signers, validation
from pyhanko.sign.fields import SigSeedSubFilter

from .errors import YesError
from .hashes import HASH_ALGORITHMS

__pdoc__ = {"SigningDocument": False}


class SigningDocument(ABC):
    signature: Optional[bytes] = None
    revocation_info: Optional[str] = None
    SUPPORTED_SIGNATURE_FORMATS: Tuple[str]

    def _set_session(self, session):
        self.session = session

    @abstractmethod
    def _get_authz_details(self):
        pass

    @abstractmethod
    def _get_hash(self):
        pass

    def _process_signature(self, signature_bytes, revocation_info_base64):
        self.signature = signature_bytes
        self.revocation_info = revocation_info_base64


class RawSigningDocument(SigningDocument):
    """ 
    A document for signing using the yes® signing service where the document
    hash is provided. Should be used only for testing.

    Signature and revocation information will be available in `signature` and
    `revocation_info` after the flow.
    """

    SUPPORTED_SIGNATURE_FORMATS = ("C", "P")

    def __init__(self, label: str, hash: str):
        """
        Args:
            label (str): Label to be displayed to the user.
            hash (str): Hash, base64(!) encoded, using the hash algorithm selected for the flow.
        """
        self.hash = hash
        self.label = label

    def _get_authz_details(self):
        return {
            "hash": self.hash,
            "label": self.label,
        }

    def _get_hash(self):
        return self.hash


class TextSigningDocument(SigningDocument):
    """
    A raw text document for signing using the yes® signing service. The text is
    hashed and then signed. Not for use with PDF or other complex file types.

    Signature and revocation information will be available in `signature` and
    `revocation_info` after the flow.
    """

    SUPPORTED_SIGNATURE_FORMATS = ("C", "P")

    def __init__(self, label: str, text: str):
        """
        Args:
            label (str): Label to be displayed to the user.
            text (str): Text to be signed.
        """
        self.text = text
        self.label = label

    def _get_authz_details(self):
        algo = self.session.hash_algorithm.algo
        self.hash = b64encode(algo(self.text.encode("utf-8")).digest()).decode("ascii")
        return {
            "hash": self.hash,
            "label": self.label,
        }

    def _get_hash(self):
        return self.hash


class DefaultSigningDocument(TextSigningDocument):
    """
    An 'empty' signing document where the user only confirms that their data is
    correct. The text to be displayed is defined by the QTSP. A selection of
    languages can be provided to ensure that the text displayed to the user is
    in one of these languages. See the yes® documentation on QID and QESID for
    details. 

    Signature and revocation information will be available in `signature` and
    `revocation_info` after the flow.
    """

    SUPPORTED_SIGNATURE_FORMATS = "C"

    label = ""

    def __init__(self, allowed_languages: List[str]):
        """
        Args: 
            allowed_languages (List[str]): List of acceptable two-letter language codes (e.g., `en`).

        """
        self.allowed_languages = allowed_languages

    def _get_authz_details(self):
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
        return super()._get_authz_details()


class PDFSigningDocument(SigningDocument):
    """
    PDF document handler for signing by the yes® signing service. 

    After the signing flow, the signed document will be available in
    `signed_file` as a named temporary file open for reading.

    NOTE: In this implementation, the file is read to memory when
    creating the object. This is not efficient for large files, but
    enables a simple serialization of the object. It also means that 
    the serialized object can be quite large, e.g., in a session storage.
    Consider overriding `_store_file` and `_restore_file` to enable a 
    more efficient storage, e.g., based on local files.
    """

    hash = None
    signed_file_name: str
    signed_file: BinaryIO

    def __init__(self, label: str, pdffile: BinaryIO):
        """
        Args:
            label (str): Label for the document to be displayed to the user.
            pdffile (BinaryIO): File-like object, opened in binary mode, as the source for the PDF file.
        """
        self.label = label
        self._store_file(pdffile)

    def _store_file(self, pdffile: BinaryIO):
        self.pdf_file = pdffile.read()

    def _restore_file(self) -> BytesIO:
        return BytesIO(self.pdf_file)

    def _set_session(self, session):
        if session.hash_algorithm != HASH_ALGORITHMS["SHA-256"]:
            raise Exception("This library only supports SHA-256 for signing documents.")
        return super()._set_session(session)

    def _prepare_pdf(self):
        # write an in-place certification signature using the PdfCMSEmbedder
        # low-level API directly.
        input_buf = self._restore_file()
        w = IncrementalPdfFileWriter(input_buf)
        signed_file_obj = tempfile.NamedTemporaryFile("w+b", delete=False)
        self.signed_file_name = signed_file_obj.name

        pdf_signer = signers.PdfSigner(
            signers.PdfSignatureMetadata(
                use_pades_lta=False,
                md_algorithm="sha256",
                field_name="yes_signature",
                name="Signature 1",
            ),
            signers.ExternalSigner(None, None, signature_value=bytes(20000)),
        )
        prep_digest, tbs_document, output = pdf_signer.digest_doc_for_signing(
            w, bytes_reserved=20000, output=signed_file_obj
        )
        psi = tbs_document.post_sign_instructions

        self.signature_prepared_digest = prep_digest
        self.signature_psi = psi
        self.hash = b64encode(prep_digest.document_digest).decode("ascii")
        signed_file_obj.close()

    def _get_authz_details(self):
        return {
            "label": self.label,
            "hash": self._get_hash(),
        }

    def _get_hash(self):
        if not self.hash:
            self._prepare_pdf()
        return self.hash

    def _process_signature(self, signature_bytes, revocation_info_base64):
        parsed_ocsps = [
            OCSPResponse.load(b64decode(r.encode("ascii")))
            for r in revocation_info_base64["ocsp"]
        ]
        parsed_crls = [
            crl.CertificateList.load(b64decode(c.encode("ascii")))
            for c in revocation_info_base64["crl"]
        ]
        vc = ValidationContext(crls=parsed_crls, ocsps=parsed_ocsps)
        # output, sig_contents = self.cms_data.send(signature_bytes)
        self.signed_file = open(self.signed_file_name, "r+b")
        validation.DocumentSecurityStore.add_dss(
            output_stream=self.signed_file,
            ocsps=parsed_ocsps,
            crls=parsed_crls,
            sig_contents=signature_bytes,
        )
        PdfTBSDocument.finish_signing(
            self.signed_file,
            prepared_digest=self.signature_prepared_digest,
            signature_cms=signature_bytes,
            post_sign_instr=self.signature_psi,
            validation_context=vc,
        )
        self.signed_file.seek(0)
