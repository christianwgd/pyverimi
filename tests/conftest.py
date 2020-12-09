import os
import pathlib
import pytest

YES_SANDBOX_TEST_CERT = pathlib.Path(
    os.environ.get("YES_SANDBOX_TEST_CERT", "yes_sandbox_test_cert.pem")
)
YES_SANDBOX_TEST_KEY = pathlib.Path(
    os.environ.get("YES_SANDBOX_TEST_KEY", "yes_sandbox_test_key.pem")
)
YES_SANDBOX_TEST_CLIENT_ID = os.environ.get(
    "YES_SANDBOX_TEST_CLIENT_ID", "sandbox.yes.com:e85ff3bc-96f8-4ae7-b6b1-894d8dde9ebe"
)
YES_SANDBOX_REDIRECT_URI = os.environ.get(
    "YES_SANDBOX_REDIRECT_URI", "http://localhost:3000/yes/oidccb"
)

@pytest.fixture
def yes_sandbox_test_config():
    if not YES_SANDBOX_TEST_CERT.exists() or not YES_SANDBOX_TEST_KEY.exists():
        raise Exception(
            f"This test requires access to the yes® sandbox using the client id "
            f"{YES_SANDBOX_TEST_CLIENT_ID}. Please provide a "
            f"certificate and private key pair at the following locations: "
            f"{YES_SANDBOX_TEST_CERT} / {YES_SANDBOX_TEST_KEY}. These files are "
            f"available in the yes developer documentation at https://yes.com/docs . "
            f"To use a different client id or certificate/key locations, please set the "
            f"environment variables YES_SANDBOX_TEST_CLIENT_ID, YES_SANDBOX_TEST_CERT, "
            f"YES_SANDBOX_TEST_KEY, and/or YES_SANDBOX_REDIRECT_URI."
        )
    return {
        "client_id": YES_SANDBOX_TEST_CLIENT_ID,
        "cert_file": str(YES_SANDBOX_TEST_CERT),
        "key_file": str(YES_SANDBOX_TEST_KEY),
        "redirect_uri": YES_SANDBOX_REDIRECT_URI,
        "environment": "sandbox",
    }