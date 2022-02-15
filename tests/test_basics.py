import yes
import pickle

from yes.hashes import HASH_ALGORITHMS
import furl


def test_serializable_identity_session(yes_sandbox_test_config):
    session = yes.YesIdentitySession(
        {
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
        },
        True,
    )

    dumped = pickle.dumps(session)

    restored = pickle.loads(dumped)

    assert session.ac_state == restored.ac_state
    assert session.pkce == restored.pkce


def test_serializable_signing_session():
    s = yes.YesSigningSession([
        yes.RawSigningDocument("test", "test"),
        yes.DefaultSigningDocument(["en"]),
        yes.PDFSigningDocument("test document 1", open("tests/demo.pdf", 'rb')),
        yes.TextSigningDocument("test document 2", "This is just a test."),
    ], ['given_name', 'family_name', 'address']
    , HASH_ALGORITHMS["SHA-256"])

    dumped = pickle.dumps(s)

    restored = pickle.loads(dumped)

    assert s.ac_state == restored.ac_state
    assert s.pkce == restored.pkce