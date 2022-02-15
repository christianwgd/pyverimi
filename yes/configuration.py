from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional
import os
from pprint import pp


class YesEnvironment:
    name: str
    url_account_chooser: Optional[str] = None
    url_issuer_check: Optional[str] = None
    url_service_configuration: Optional[str] = None

    PRODUCTION: "YesEnvironment"
    SANDBOX: "YesEnvironment"

    def __init__(
        self,
        name,
        url_account_chooser: Optional[str],
        url_service_configuration: Optional[str],
    ):
        self.name = name
        self.url_account_chooser = url_account_chooser
        self.url_service_configuration = url_service_configuration

    def __str__(self):
        return self.name


YesEnvironment.PRODUCTION = YesEnvironment(
    "production",
    url_account_chooser="https://accounts.yes.com/",
    url_service_configuration="https://api.yes.com/service-configuration/v1/",
)

YesEnvironment.SANDBOX = YesEnvironment(
    "sandbox",
    url_account_chooser="https://accounts.sandbox.yes.com/",
    url_service_configuration="https://api.sandbox.yes.com/service-configuration/v1/",
)


class YesAuthzStyle(Enum):
    """Defines the way the authorization request is made.

    Attributes:
        PUSHED: OAuth 2.0 Pushed Authorization Requests according to RFC9126 (more secure)
        FRONTEND: OAuth 2.0 classic authorization request as defined in RFC6749
    """

    PUSHED = "pushed"
    FRONTEND = "frontend"


@dataclass
class YesConfiguration:
    client_id: str
    cert_file: str
    key_file: str
    redirect_uri: str
    environment: YesEnvironment
    qtsp_id: Optional[str] = None
    authz_style: YesAuthzStyle = YesAuthzStyle.PUSHED

    def __post_init__(self):
        if not Path(self.cert_file).exists() or not Path(self.key_file).exists():
            raise Exception(
                f"Please provide a certificate and private key pair at the following "
                f"locations: {self.cert_file} / {self.key_file} or change the locations "
                f"in the configuration. If you are testing "
                f"this library, the files are available in the yes developer "
                f"documentation at https://yes.com/docs"
            )

    @staticmethod
    def from_dict(dct):
        return YesConfiguration(
            client_id=dct["client_id"],
            cert_file=dct["cert_file"],
            key_file=dct["key_file"],
            redirect_uri=dct["redirect_uri"],
            environment=dct.get("environment", "sandbox"),
            qtsp_id=dct.get("qtsp_id"),
            authz_style=YesAuthzStyle.PUSHED
            if (dct.get("authz_style", "pushed") == "pushed")
            else YesAuthzStyle.FRONTEND,
        )

    @staticmethod
    def sandbox_test_from_env():
        params = {
            "client_id": os.environ.get(
                "YES_SANDBOX_TEST_CLIENT_ID",
                "sandbox.yes.com:e85ff3bc-96f8-4ae7-b6b1-894d8dde9ebe",
            ),
            "cert_file": os.environ.get(
                "YES_SANDBOX_TEST_CERT", "yes_sandbox_test_cert.pem"
            ),
            "key_file": os.environ.get(
                "YES_SANDBOX_TEST_KEY", "yes_sandbox_test_key.pem"
            ),
            "redirect_uri": os.environ.get(
                "YES_SANDBOX_TEST_REDIRECT_URI", "http://localhost:3000/yes/oidccb"
            ),
            "environment": YesEnvironment.SANDBOX,
            "qtsp_id": os.environ.get(
                "YES_SANDBOX_TEST_QTSP_ID",
                "sp:sandbox.yes.com:85ac6820-8518-4aa1-ba85-de4307175b64",
            ),
        }
        print("Using the following configuration: ")
        pp(params)
        print()
        print("Modify the configuration using the following environment variables:")
        print(
            "YES_SANDBOX_TEST_CLIENT_ID, YES_SANDBOX_TEST_CERT, YES_SANDBOX_TEST_KEY, YES_SANDBOX_TEST_REDIRECT_URI, YES_SANDBOX_TEST_QTSP_ID"
        )
        print()
        return YesConfiguration(**params)

