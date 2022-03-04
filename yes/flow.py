import base64
import json
import logging
from abc import ABC
from typing import Dict, List, Optional, Tuple

import jwt
import requests
from furl import furl

from .documents import SigningDocument
from .errors import *
from .session import (
    YesIdentitySession,
    YesIdentitySigningSession,
    YesIdentityPaymentSession,
    YesSession,
    YesSigningSession,
    YesPaymentSession,
    YesPaymentSigningSession,
)
from .configuration import YesAuthzStyle, YesConfiguration, YesEnvironment


class YesFlow(ABC):
    """Base class for all yes® flows.
    """

    config: YesConfiguration
    session: YesSession
    log = None

    OAUTH_CONFIGURATION_SUFFIX: str

    def __init__(self, config: YesConfiguration, session: YesSession):
        """
        Args:
            config (YesConfiguration): Configuration defining the details of the flow. 
            session (YesSession): [description]

        Raises:
            Exception: [description]
        """
        self.config = config
        self.cert_config = (self.config.cert_file, self.config.key_file)
        self.session = session
        self.log = logging.getLogger("yes")

    def start_yes_flow(self) -> str:
        """
        First step for starting a yes® flow. This creates the URL to call the
        account chooser. User needs to be redirected to this URL.
        """
        return self._get_account_chooser_url()

    def _decode_or_raise_error(
        self, response, expected_status=200, expect_empty=False, is_oauth=False
    ):

        if response.status_code != expected_status:
            if not is_oauth:
                raise YesError(
                    f"Response status code {response.status_code}, response: '{response.text}'."
                )
            else:
                raise parse_oauth_error(response)

        if not expect_empty:
            try:
                response_contents = response.json()
            except Exception:
                raise YesError(
                    f"Unable to JSON decode response; status code={response.status_code}; contents='{response.text}'.\n"
                    f"Response from URL: {response.url}\n"
                    f"Request headers: {response.request.headers!r}\nRequest body: {response.request.body!r}"
                )
        else:
            response_contents = response.text

        return response_contents

    def _get_account_chooser_url(self, select_account=False):
        ac_redirect = furl(self.config.environment.url_account_chooser)
        ac_redirect.args["client_id"] = self.config.client_id
        ac_redirect.args["state"] = self.session.ac_state
        if select_account:
            ac_redirect.args["prompt"] = "select_account"
        return str(ac_redirect)

    def handle_ac_callback(
        self,
        state: str,
        issuer_url: Optional[str] = None,
        error: Optional[str] = None,
        selected_bic: str = None,
    ) -> str:
        """Second step in the yes® flow. The user is being redirected from the
        yes® account chooser to your registered account chooser redirect URI.
        This function needs to be called to handle the result.

        It returns the URL at the IDP to which the user then must be redirected.

        Args: 
            state (str): passed from the redirection URI
            issuer_url (Optional[str], optional): passed from the redirection URI
            error (Optional[str], optional): used when an error occured
            selected_bic (Optional[str], optional): not used, but returned from the yes® account chooser

        Raises: 
            YesError: General error, the flow should be aborted and restarted.
            YesUserCanceledError: The user pressed on 'cancel'
            YesUnknownIssuerError: The user's selected bank is not available.

        Returns: 
            str: The authorization URL to which the user's browser must now be redirected.
        """
        if state != self.session.ac_state:
            raise YesError("Invalid account chooser state.")
        elif error == "canceled":
            raise YesUserCanceledError()
        elif error == "unknown_issuer":
            raise YesUnknownIssuerError()
        elif error:
            raise YesError(error)

        self.log.debug(
            f"Accepted account chooser callback, incoming issuer url: {str(issuer_url)}."
        )

        self._check_issuer(issuer_url)

        self._retrieve_oauth_configuration()
        authz_parameters = self._encode_authz_parameters()
        if self.config.authz_style == YesAuthzStyle.PUSHED:
            authz_url = self._prepare_authz_url_pushed(authz_parameters)
        else:
            authz_url = self._prepare_authz_url_traditional(authz_parameters)

        return authz_url

    def _check_issuer(self, issuer_url):
        """
        Ensure that the issuer_url points to a valid issuer in the yes®
        ecosystem by retrieving the service configuration.
        """

        check_url = furl(self.config.environment.url_service_configuration)
        check_url.args["iss"] = issuer_url
        self.session.service_configuration = self._decode_or_raise_error(
            requests.get(check_url)
        )

        # issuer is taken from the service configuration document and can differ from the selected one
        self.session.issuer_url = self.session.service_configuration["identity"]["iss"]
        self.log.debug(
            f"validated issuer url (using service configuration) {self.session.issuer_url}"
        )

    def _retrieve_oauth_configuration(self):
        """
        Retrieve the ODIC/OAuth configuration from the discovered OIDC issuer.
        """
        wkdoc = self._decode_or_raise_error(
            requests.get(self.session.issuer_url + self.OAUTH_CONFIGURATION_SUFFIX)
        )

        if wkdoc["issuer"] != self.session.issuer_url:
            raise Exception("Illegal issuer url in openid configuration document!")

        self.session.oauth_configuration = wkdoc

    def _assemble_authz_parameters(self) -> Dict:
        parameters = {
            "client_id": self.config.client_id,
            "redirect_uri": self.config.redirect_uri,
            "response_type": "code",
            "code_challenge_method": "S256",
            "code_challenge": self.session.pkce.challenge,
            "authorization_details": [],
        }
        self.log.debug(
            f"Prepared authorization request parameters: {json.dumps(parameters)}"
        )
        return parameters

    def _encode_authz_parameters(self) -> Dict:
        parameters = self._assemble_authz_parameters()
        if len(parameters["authorization_details"]):
            parameters["authorization_details"] = json.dumps(
                parameters["authorization_details"]
            )
        else:
            del parameters["authorization_details"]
        if "claims" in parameters:
            parameters["claims"] = json.dumps(parameters["claims"])
        print(parameters)
        return parameters

    def _prepare_authz_url_pushed(self, par_ameters: Dict) -> str:
        """
        Instead of sending a "traditional" OAuth request, we're using OAuth
        Pushed Authorization Requests to send the authorization request in the
        backend. This provides integrity protection for the request contents.
        """
        par_endpoint = self.session.oauth_configuration[
            "pushed_authorization_request_endpoint"
        ]
        par_response_contents = self._decode_or_raise_error(
            requests.post(par_endpoint, data=par_ameters, cert=self.cert_config,),
            expected_status=201,
            is_oauth=True,
        )

        self.log.debug(f"Received PAR response: {json.dumps(par_response_contents)}")

        redirect_uri = furl(self.session.oauth_configuration["authorization_endpoint"])
        redirect_uri.args["request_uri"] = par_response_contents["request_uri"]
        redirect_uri.args["client_id"] = self.config.client_id
        self.log.debug(
            f"yes® OIDC provider pushed auth request redirection to {str(redirect_uri)}."
        )
        return str(redirect_uri)

    def _prepare_authz_url_traditional(self, parameters: Dict) -> str:
        """
        Assemble an RFC6749-style OAuth authorization request.
        """
        redirect_uri = furl(self.session.oauth_configuration["authorization_endpoint"])
        redirect_uri.args.update(parameters)
        self.log.debug(
            f"yes® OIDC provider traditional auth request redirection to {str(redirect_uri)}."
        )
        return str(redirect_uri)

    def handle_oidc_callback(
        self,
        iss: str,
        code: Optional[str] = None,
        error: Optional[str] = None,
        error_description: Optional[str] = None,
    ):
        """
        Third step - OpenID Connect callback endpoint. The user arrives here after going
        through the authentication/authorizaton steps at the bank.

        Note that the URL of this endpoint has to be registered with yes® for
        your client. 

        The YesAccountSelectionRequested exception that can be raised by this method 
        must be handled in a particular way, see below.

        After this callback has been processed, `send_token_request` and then
        (optionally) `send_userinfo_request` can be used.
        

        Args:
            iss (str): OAuth return parameter from URL
            code (Optional[str], optional): OAuth return parameter from URL. Defaults to None.
            error (Optional[str], optional): OAuth return parameter from URL. Defaults to None.
            error_description (Optional[str], optional): OAuth return parameter from URL. Defaults to None.

        Raises:
            YesError: Generic yes® error. The flow should be aborted and the user should have the option to start again.
            YesAccountSelectionRequested: The user selected to use another bank. Redirect the user to exception.redirect_uri!
        """
        if code is not None and iss != self.session.issuer_url:
            raise YesError(
                f"Mix-up Attack detected: illegal issuer URL. Expected '{self.session.issuer_url}', but received '{iss}'."
            )

        self.log.debug("Accepted OIDC callback (authorization response).")

        if code is not None:
            # Success - store the code for later!
            self.session.authorization_code = code
            return

        if error is None:
            raise YesError("No error code or error description received.")

        if error == "account_selection_requested":
            redir_error = YesAccountSelectionRequested()
            redir_error.redirect_uri = self._get_account_chooser_url(
                select_account=True
            )
            self.log.debug(
                f"Account selection requested, redirecting to {str(redir_error.redirect_uri)}."
            )
            raise redir_error
        else:
            oauth_error = YesOAuthError()
            oauth_error.oauth_error = error
            oauth_error.oauth_error_description = (
                error_description if error_description is not None else ""
            )
            raise oauth_error

    def send_token_request(self) -> Optional[Dict]:
        """
        Send the token request to the discovered issuer's token endpoint.

        Returns the decoded and validated ID token data if an identity flow is used.

        Also stores the access token from the IDP/AS. This can then be used in the function
        `send_userinfo_request` and, for signing flows, in `create_signatures`.
        """

        token_endpoint = self.session.oauth_configuration["token_endpoint"]
        token_parameters = {
            "client_id": self.config.client_id,
            "redirect_uri": self.config.redirect_uri,
            "grant_type": "authorization_code",
            "code": self.session.authorization_code,
            "code_verifier": self.session.pkce.verifier,
        }

        self.log.debug(f"Prepared token request: {json.dumps(token_parameters)}")

        token_response = self._decode_or_raise_error(
            requests.post(
                token_endpoint, data=token_parameters, cert=self.cert_config,
            ),
            is_oauth=True,
        )

        self._debug_token_response = token_response

        self.session.access_token = token_response["access_token"]

        if "authorization_details" in token_response:
            self.session.authorization_details_enriched = token_response[
                "authorization_details"
            ]

        if "id_token" in token_response:
            return self._decode_and_validate_id_token(token_response["id_token"])
        else:
            return

    def _decode_and_validate_id_token(self, id_token_encoded: str) -> Dict:
        jwks_doc = self._decode_or_raise_error(
            requests.get(self.session.oauth_configuration["jwks_uri"])
        )

        kid = jwt.get_unverified_header(id_token_encoded)["kid"]

        for jwk in jwks_doc["keys"]:
            if jwk["kid"] == kid:
                key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
                break
        else:
            raise Exception("KID not found during ID token verification.")

        id_token = jwt.decode(
            id_token_encoded,
            key=key,
            algorithms=["RS256"],
            issuer=self.session.oauth_configuration["issuer"],
            audience=self.config.client_id,
        )

        if id_token["nonce"] != self.session.oidc_nonce:
            raise Exception("Illegal nonce in ID token.")
        if (
            self.session.acr_values != []
            and id_token["acr"] not in self.session.acr_values
        ):
            raise Exception("Illegal acr value in ID token.")

        return id_token


class YesSigningFlow(YesFlow):
    OAUTH_CONFIGURATION_SUFFIX = "/.well-known/oauth-authorization-server"
    CREDENTIAL_ID = "qes_eidas"
    PROFILE = "http://uri.etsi.org/19432/v1.1.1#/creationprofile#"

    def __init__(self, config: YesConfiguration, session: YesSigningSession):
        if not isinstance(session, YesSigningSession):
            raise Exception("Signing flow must be called with a YesSigningSession")

        if not config.authz_style == YesAuthzStyle.PUSHED:
            raise Exception(
                "Signing flow only works with Pushed Authorization Requests."
            )

        super().__init__(config, session)

    def _check_issuer(self, issuer_url):
        super()._check_issuer(issuer_url)

        # from the existing QTSP configurations, select the one we want to use!
        if not self.config.qtsp_id:
            raise YesError(
                "Unable to select a QTSP. Please set a 'qtsp_id' key in the configuration to select a QTSP."
            )

        selected_qtsp_id = self.config.qtsp_id
        for qtsp in self.session.service_configuration["remote_signature_creation"]:
            if qtsp["qtsp_id"] == selected_qtsp_id:
                self.session.qtsp_config = qtsp
                break
        else:
            available_qtsp_ids = [
                qtsp["qtsp_id"]
                for qtsp in self.session.service_configuration[
                    "remote_signature_creation"
                ]
            ]
            raise YesError(
                f"Unable to find QTSP with id '{selected_qtsp_id}'! Available QTSP IDs: {', '.join(available_qtsp_ids)} Please ensure that the configuration value 'qtsp_id' contains a valid QTSP id."
            )

    def _assemble_authz_parameters(self) -> Dict:
        parameters = super()._assemble_authz_parameters()

        document_digests = list(
            doc._get_authz_details() for doc in self.session.documents
        )

        authorization_details = {
            "type": "sign",
            "locations": [self.session.qtsp_config["qtsp_id"]],
            "credentialID": self.CREDENTIAL_ID,
            "documentDigests": document_digests,
            "hashAlgorithmOID": self.session.hash_algorithm.oid,
        }

        if len(self.session.identity_assurance_claims):
            authorization_details["identity_assurance_claims"] = {
                claim: None for claim in self.session.identity_assurance_claims
            }

        parameters["authorization_details"].append(authorization_details)
        self.log.debug(
            f"Prepared authorization request parameters: {json.dumps(parameters)}"
        )
        return parameters

    def create_signatures(
        self,
        signature_format: Optional[str] = "P",
        conformance_level: Optional[str] = "AdES-B-LT",
        documents: Optional[List[SigningDocument]] = None,
    ) -> Dict:
        """Create the signatures by calling the QTSP with the relevant document hashes.

        The signatures will be available afterwards **in the respective document objects**.

        The raw signature is returned, but is only useful in special use cases.

        Args:
            signature_format (Optional[str], optional): The signature format to use, see the yes® documentation. Defaults to "P".
            conformance_level (Optional[str], optional): The conformance level to use, see the yes® documentation. Defaults to "AdES-B-LT".
            documents (Optional[List[SigningDocument]], optional): If defined, only the signatures for the referenced documents are created. Defaults to None (create signatures for all documents).

        """

        if documents is None:
            documents = self.session.documents

        if not self.session.access_token:
            raise Exception(
                "No access token found. send_token_request must be used first to retrieve an access token."
            )

        hashes_to_sign = list(doc._get_hash() for doc in documents)

        signdoc_data = {
            "SAD": self.session.access_token,
            "credentialID": self.CREDENTIAL_ID,
            "documentDigests": {
                "hashes": hashes_to_sign,
                "hashAlgorithmOID": self.session.hash_algorithm.oid,
            },
            "profile": self.PROFILE,
            "signature_format": signature_format,
            "conformance_level": conformance_level,
        }

        response = self._decode_or_raise_error(
            resp := requests.post(
                self.session.qtsp_config["signDoc"],
                headers={
                    # "Authorization": f"Bearer {self.session.access_token}",
                    "Accept": "*/*",
                },
                cert=self.cert_config,
                json=signdoc_data,
            ),
            expected_status=200,
        )

        self._debug_signdoc_response = resp

        assert len(response["SignatureObject"]) == len(documents)
        for doc, signature_base64 in zip(documents, response["SignatureObject"]):
            signature = base64.decodebytes(signature_base64.encode("ascii"))
            doc._process_signature(signature, response.get("revocationInfo", None))

        return response


class YesIdentityFlow(YesFlow):
    def __init__(self, config: YesConfiguration, session: YesIdentitySession):
        if not isinstance(session, YesIdentitySession):
            raise Exception("Identity flow must be called with a YesIdentitySession")

        super().__init__(config, session)

    OAUTH_CONFIGURATION_SUFFIX = "/.well-known/openid-configuration"

    def _assemble_authz_parameters(self) -> Dict:
        parameters = super()._assemble_authz_parameters()
        parameters.update(
            {
                "scope": "openid",
                "nonce": self.session.oidc_nonce,
                "claims": self.session.claims,
                "acr_values": " ".join(self.session.acr_values),
            }
        )
        self.log.debug(
            f"Prepared authorization request parameters: {json.dumps(parameters)}"
        )
        return parameters

    def send_userinfo_request(self) -> Dict:
        """
        Request identity data from the userinfo endpoint. Not required if all
        identity data is returned in the ID token (see the `claims` parameter).
        """
        if not self.session.access_token:
            raise Exception(
                "No access token found. send_token_request must be used first to retrieve an access token."
            )

        return self._decode_or_raise_error(
            requests.get(
                self.session.oauth_configuration["userinfo_endpoint"],
                headers={
                    "Authorization": f"Bearer {self.session.access_token}",
                    "accept": "*/*",
                },
                cert=self.cert_config,
            ),
            is_oauth=True,
        )


class YesIdentitySigningFlow(YesIdentityFlow, YesSigningFlow):
    def __init__(self, config: YesConfiguration, session: YesIdentitySigningSession):
        if not isinstance(session, YesIdentitySigningSession):
            raise Exception(
                "Identity+Signing flow must be called with a YesIdentitySigningSession"
            )

        if not config.authz_style == YesAuthzStyle.PUSHED:
            raise Exception(
                "Identity+Signing flow only works with Pushed Authorization Requests."
            )

        super().__init__(config, session)


class YesPaymentFlow(YesFlow):
    OAUTH_CONFIGURATION_SUFFIX = "/.well-known/oauth-authorization-server"

    def __init__(self, config: YesConfiguration, session: YesPaymentSession):
        if not isinstance(session, YesPaymentSession):
            raise Exception("Payment flow must be called with a YesPaymentSession")

        if not config.authz_style == YesAuthzStyle.PUSHED:
            raise Exception(
                "Payment flow only works with Pushed Authorization Requests."
            )

        super().__init__(config, session)

    def _check_issuer(self, issuer_url):
        super()._check_issuer(issuer_url)
        if not "payment_initiation" in self.session.service_configuration:
            raise YesError("Payment initiation not supported by this bank.")

    def _assemble_authz_parameters(self) -> Dict:
        parameters = super()._assemble_authz_parameters()

        authorization_details = {
            "type": "payment_initiation",
            "paymentProduct": "sepa-credit-transfers",
            "instructedAmount": {
                "currency": self.session.currency,
                "amount": str(self.session.amount),
            },
            "remittanceInformationUnstructured": self.session.remittance_information,
            "creditorName": self.session.creditor_name,
            "creditorAccount": {"iban": self.session.creditor_account_iban,},
        }
        if (
            self.session.debtor_account_holder_name is not None
            or self.session.debtor_account_iban is not None
            or self.session.debtor_account_holder_same_name
        ):
            authorization_details["debtorAccount"] = {}

        if self.session.debtor_account_holder_name is not None:
            (
                authorization_details["debtorAccount"]["holderGivenName"],
                authorization_details["debtorAccount"]["holderFamilyName"],
            ) = self.session.debtor_account_holder_name

        if self.session.debtor_account_holder_same_name:
            authorization_details["debtorAccount"]["holderSameName"] = True

        if self.session.debtor_account_iban is not None:
            authorization_details["debtorAccount"][
                "iban"
            ] = self.session.debtor_account_iban

        parameters["authorization_details"].append(authorization_details)
        self.log.debug(
            f"Prepared authorization request parameters: {json.dumps(parameters)}"
        )
        return parameters

    def get_payment_status(self) -> str:
        for el in self.session.authorization_details_enriched:
            if el["type"] == "payment_initiation":
                authz_details = el
                break
        else:
            raise YesError("Payment was not confirmed in authorization details.")

        return self._decode_or_raise_error(
            requests.get(
                authz_details["payment_information"]["status_href"],
                headers={
                    "Authorization": f"Bearer {self.session.access_token}",
                    "accept": "*/*",
                },
                cert=self.cert_config,
            ),
            is_oauth=False,
        )["transactionStatus"]


class YesPaymentSigningFlow(YesPaymentFlow, YesSigningFlow):
    def __init__(self, config: YesConfiguration, session: YesPaymentSigningSession):
        super().__init__(config, session)


class YesIdentityPaymentFlow(YesIdentityFlow, YesPaymentFlow):
    def __init__(self, config: YesConfiguration, session: YesIdentityPaymentSession):
        if not isinstance(session, YesIdentityPaymentSession):
            raise Exception(
                "Identity+Payment flow must be called with a YesIdentityPaymentSession"
            )

        if not config.authz_style == YesAuthzStyle.PUSHED:
            raise Exception(
                "Identity+Payment flow only works with Pushed Authorization Requests."
            )

        super().__init__(config, session)
