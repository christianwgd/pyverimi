from time import sleep

import pytest
import yes
from furl import furl
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait


def check_claims(expected_claims, actual_claims):
    print("Checking")
    print(actual_claims)
    print("against")
    print(expected_claims)
    for key, value in expected_claims.items():
        assert key in actual_claims
        if type(value) is dict:
            check_claims(value, actual_claims[key])
        else:
            if value == "!!any":
                assert actual_claims[key] is not None
            else:
                assert actual_claims[key] == value


CLAIMS_TESTS = [
    (
        "Peter",
        {"family_name": None, "given_name": None,},
        {"family_name": "Gottschalk", "given_name": "Peter",},
    ),
    (
        "Peter",
        {
            "verified_claims": {
                "claims": {"family_name": None, "given_name": None,},
                "verification": {"trust_framework": None},
            }
        },
        {
            "verified_claims": {
                "claims": {"family_name": "Gottschalk", "given_name": "Peter",},
                "verification": {"trust_framework": "de_aml"},
            }
        },
    ),
]

@pytest.mark.parametrize("authz_style", list(yes.YesAuthzStyle))
@pytest.mark.parametrize("username,claims,compare_data", CLAIMS_TESTS)
def test_identity_simple(yes_sandbox_test_config, username, claims, compare_data, authz_style):
    yes_sandbox_test_config.authz_style = authz_style
    acr_values = ["https://www.yes.com/acrs/online_banking_sca"]
    claims_req = {"id_token": claims, "userinfo": claims}
    session = yes.YesIdentitySession(claims_req, acr_values)

    flow = yes.YesIdentityFlow(yes_sandbox_test_config, session)

    ac_start = furl(flow.start_yes_flow())

    idp_uri = flow.handle_ac_callback(
        ac_start.args["state"], "https://testidp.sandbox.yes.com/issuer/10000005"
    )

    driver = webdriver.Chrome()
    driver.implicitly_wait(10)  # seconds
    wait = WebDriverWait(driver, 10)
    driver.get(idp_uri)

    driver.find_element_by_id("ui-login-username-input").send_keys(username)
    driver.find_element_by_id("ui-login-submit-button").click()
    sleep(1)
    driver.find_element_by_id("ui-second-factor-login-button").click()
    sleep(1)
    driver.find_element_by_id("ui-consent-submit-button").click()

    wait.until(EC.url_contains("code="))
    authorization_response = furl(driver.current_url)
    driver.quit()
    flow.handle_oidc_callback(
        authorization_response.args["iss"], authorization_response.args["code"]
    )
    data = flow.send_token_request()
    check_claims(compare_data, data)

    data = flow.send_userinfo_request()
    check_claims(compare_data, data)


def test_user_abort_in_ac(yes_sandbox_test_config):
    session = yes.YesIdentitySession({}, [])
    flow = yes.YesIdentityFlow(yes_sandbox_test_config, session)
    ac_start = furl(flow.start_yes_flow())

    with pytest.raises(yes.YesUserCanceledError):
        flow.handle_ac_callback(ac_start.args["state"], error="canceled")

    with pytest.raises(yes.YesUnknownIssuerError):
        flow.handle_ac_callback(ac_start.args["state"], error="unknown_issuer")

    with pytest.raises(yes.YesError):
        flow.handle_ac_callback(
            ac_start.args["state"], issuer_url="https://example.com/invalid"
        )


def test_account_selection(yes_sandbox_test_config):
    session = yes.YesIdentitySession({}, [])
    flow = yes.YesIdentityFlow(yes_sandbox_test_config, session)
    ac_start = furl(flow.start_yes_flow())

    idp_uri = flow.handle_ac_callback(
        ac_start.args["state"], "https://testidp.sandbox.yes.com/issuer/10000005"
    )

    driver = webdriver.Chrome()
    driver.implicitly_wait(10)  # seconds
    wait = WebDriverWait(driver, 10)
    driver.get(idp_uri)

    driver.find_element_by_id("ui-login-select-another-bank-button").click()
    wait.until(EC.url_contains("error="))
    authorization_response = furl(driver.current_url)
    driver.quit()

    with pytest.raises(yes.YesAccountSelectionRequested):
        flow.handle_oidc_callback(
            authorization_response.args["iss"],
            error=authorization_response.args["error"],
            error_description=authorization_response.args["error_description"],
        )


def test_user_abort_in_oidc(yes_sandbox_test_config):
    acr_values = ["https://www.yes.com/acrs/online_banking_sca"]
    session = yes.YesIdentitySession({}, acr_values)

    flow = yes.YesIdentityFlow(yes_sandbox_test_config, session)

    ac_start = furl(flow.start_yes_flow())

    idp_uri = flow.handle_ac_callback(
        ac_start.args["state"], "https://testidp.sandbox.yes.com/issuer/10000005"
    )

    driver = webdriver.Chrome()
    driver.implicitly_wait(10)  # seconds
    wait = WebDriverWait(driver, 10)
    driver.get(idp_uri)

    driver.find_element_by_id("ui-login-username-input").send_keys("Peter")
    driver.find_element_by_id("ui-login-submit-button").click()
    sleep(1)
    driver.find_element_by_id("ui-second-factor-decline-button").click()

    wait.until(EC.url_contains("error="))
    authorization_response = furl(driver.current_url)
    driver.quit()
    with pytest.raises(yes.YesOAuthError):
        flow.handle_oidc_callback(
            authorization_response.args["iss"],
            error=authorization_response.args["error"],
            error_description=authorization_response.args["error_description"],
        )
