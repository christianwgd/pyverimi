import json
import logging
from typing import Dict, List, Optional, Tuple

import jwt
import requests
from furl import furl

from .errors import *
from .session import YesSession


class YesIdentityFlow:
    config: Dict
    session: YesSession
    urls: Optional[Dict]
    log = None

    DEFAULT_URLS = {
        "production": {
            "account_chooser": "https://accounts.yes.com/",
            "issuer_check_callback": "https://accounts.yes.com/idp/",
        },
        "sandbox": {
            "account_chooser": "https://accounts.sandbox.yes.com/",
            "issuer_check_callback": "https://accounts.sandbox.yes.com/idp/",
        },
    }

    def __init__(self, config: Dict, session: YesSession):
        self.config = config
        self.session = session
        self.log = logging.getLogger("yes")

        try:
            self.urls = self.DEFAULT_URLS[config["environment"]]
        except KeyError:
            raise Exception(
                f"configuration setting 'environment' MUST be one of {', '.join(self.DEFAULT_URLS.keys())}"
            )

    def start_yes_flow(self) -> str:
        """
        First step for starting a yes® flow. This creates the URL to call the
        account chooser. User needs to be redirected to this URL.
        """
        return self._get_account_chooser_url()

    def _get_account_chooser_url(self, select_account=False):
        ac_redirect = furl(self.urls["account_chooser"])
        ac_redirect.args["client_id"] = self.config["client_id"]
        ac_redirect.args["state"] = self.session.ac_state
        if select_account:
            ac_redirect.args["prompt"] = "select_account"
        return str(ac_redirect)

    def handle_ac_callback(
        self, state: str, issuer_url: Optional[str] = None, error: Optional[str] = None,
    ) -> str:
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
        self._retrieve_oidc_configuration()
        authz_parameters = self._assemble_authz_parameters()
        if self.config.get("authz_style", "pushed") == "pushed":
            authz_url = self._prepare_authz_url_pushed(authz_parameters)
        else:
            authz_url = self._prepare_authz_url_traditional(authz_parameters)

        return authz_url

    def _check_issuer(self, issuer_url):
        """
        Ensure that the issuer_url points to a valid issuer in the yes®
        ecosystem.
        """
        check_url = furl(self.urls["issuer_check_callback"])
        check_url.args["iss"] = issuer_url
        check = requests.get(check_url).status_code

        if check != 204:
            raise YesInvalidIssuerError(
                f"Invalid issuer url provided (got status code {check})."
            )

        self.session.issuer_url = issuer_url
        self.log.debug(f"validated issuer url {self.session.issuer_url}")

    def _retrieve_oidc_configuration(self):
        """
        Retrieve the ODIC configuration from the discovered OIDC issuer.
        """
        wkdoc = requests.get(
            self.session.issuer_url + "/.well-known/openid-configuration"
        ).json()

        if wkdoc["issuer"] != self.session.issuer_url:
            raise Exception("Illegal issuer url in openid configuration document!")

        self.session.oidc_config = wkdoc

    def _assemble_authz_parameters(self) -> Dict:
        parameters = {
            "client_id": self.config["client_id"],
            "redirect_uri": self.config["redirect_uri"],
            "scope": "openid",
            "response_type": "code",
            "code_challenge_method": "S256",
            "code_challenge": self.session.pkce.challenge,
            "nonce": self.session.oidc_nonce,
            "claims": json.dumps(self.session.claims),
            "acr_values": " ".join(self.session.acr_values),
        }
        self.log.debug(
            f"Prepared authorization request parameters: {json.dumps(parameters)}"
        )
        return parameters

    def _prepare_authz_url_pushed(self, par_ameters: Dict) -> str:
        """
        Instead of sending a "traditional" OAuth request, we're using OAuth
        Pushed Authorization Requests to send the authorization request in the
        backend. This provides integrity protection for the request contents.
        """
        par_endpoint = self.session.oidc_config["pushed_authorization_request_endpoint"]
        par_response = requests.post(
            par_endpoint,
            data=par_ameters,
            cert=(self.config["cert_file"], self.config["key_file"]),
        ).json()
        self.log.debug(f"Received PAR response: {json.dumps(par_response)}")

        if "error" in par_response:
            raise YesError(f"Error during PAR request: {json.dumps(par_response)}")

        redirect_uri = furl(self.session.oidc_config["authorization_endpoint"])
        redirect_uri.args["request_uri"] = par_response["request_uri"]
        redirect_uri.args["client_id"] = self.config["client_id"]
        self.log.debug(
            f"yes® OIDC provider pushed auth request redirection to {str(redirect_uri)}."
        )
        return str(redirect_uri)

    def _prepare_authz_url_traditional(self, parameters: Dict) -> str:
        """
        Assemble an RFC6749-style OAuth authorization request.
        """
        redirect_uri = furl(self.session.oidc_config["authorization_endpoint"])
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
        if iss != self.session.issuer_url:
            raise YesError("Mix-up Attack detected: illegal issuer URL.")

        self.log.debug("Accepted OIDC callback (authorization response).")

        if error is not None:
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
                oauth_error.oauth_error_description = error_description
                raise oauth_error

        # Store the code for later!
        self.session.authorization_code = code

    def send_token_request(self) -> Dict:
        """
        Send the token request to the discovered issuer's token endpoint.
        """

        token_endpoint = self.session.oidc_config["token_endpoint"]
        token_parameters = {
            "client_id": self.config["client_id"],
            "redirect_uri": self.config["redirect_uri"],
            "grant_type": "authorization_code",
            "code": self.session.authorization_code,
            "code_verifier": self.session.pkce.verifier,
        }
        self.log.debug(f"Prepared token request: {json.dumps(token_parameters)}")

        token_response = requests.post(
            token_endpoint,
            data=token_parameters,
            cert=(self.config["cert_file"], self.config["key_file"]),
        ).json()

        if "error" in token_response:
            raise YesError(f"Error in token request: {json.dumps(token_response)}")

        self.session.access_token = token_response["access_token"]

        return self._decode_and_validate_id_token(token_response["id_token"])

    def _decode_and_validate_id_token(self, id_token_encoded: str) -> Dict:
        jwks_doc = requests.get(self.session.oidc_config["jwks_uri"]).json()

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
            issuer=self.session.oidc_config["issuer"],
            audience=self.config["client_id"],
        )

        if id_token["nonce"] != self.session.oidc_nonce:
            raise Exception("Illegal nonce in ID token.")
        if (
            self.session.acr_values != []
            and id_token["acr"] not in self.session.acr_values
        ):
            raise Exception("Illegal acr value in ID token.")

        return id_token

    def send_userinfo_request(self) -> Dict:
        userinfo_response = requests.get(
            self.session.oidc_config["userinfo_endpoint"],
            headers={
                "Authorization": f"Bearer {self.session.access_token}",
                "accept": "*/*",
            },
            cert=(self.config["cert_file"], self.config["key_file"]),
        ).json()

        return userinfo_response

