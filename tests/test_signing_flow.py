from time import sleep

import pytest
import yes
from furl import furl
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

USERNAME = "test001e"
# QTSP_ID = "sp:sandbox.yes.com:635ae52b-5a3e-4495-b117-fed623030038" # infocert
QTSP_ID = "sp:sandbox.yes.com:85ac6820-8518-4aa1-ba85-de4307175b64"  # namirial


def test_signing_simple(yes_sandbox_test_config):
    document_digests = [
        {
            "hash": "sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI=",
            "label": "Kreditvertrag",
        },
        {
            "hash": "HZQzZmMAIWekfGH0/ZKW1nsdt0xg3H6bZYztgsMTLw0=",
            "label": "Vertrag Restschuldversicherung",
        },
    ]

    hash_algorithm_oid = "2.16.840.1.101.3.4.2.1"

    yes_sandbox_test_config["qtsp_id"] = QTSP_ID

    session = yes.YesSigningSession(hash_algorithm_oid, document_digests)

    flow = yes.YesSigningFlow(yes_sandbox_test_config, session)

    ac_start = furl(flow.start_yes_flow())
    idp_uri = flow.handle_ac_callback(
        ac_start.args["state"], "https://testidp.sandbox.yes.com/issuer/10000005"
    )

    driver = webdriver.Chrome()
    driver.implicitly_wait(10)  # seconds
    wait = WebDriverWait(driver, 10)
    driver.get(idp_uri)

    driver.find_element_by_id("ui-login-username-input").send_keys(USERNAME)
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
    flow.send_token_request()
    sigs = flow.create_signatures()
