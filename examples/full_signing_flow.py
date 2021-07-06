import yes
import cherrypy
from cherrypy.lib import static

import os
import pathlib
import tempfile


def yes_configuration():
    YES_SANDBOX_TEST_CERT = pathlib.Path(
        os.environ.get("YES_SANDBOX_TEST_CERT", "yes_sandbox_test_cert.pem")
    )
    YES_SANDBOX_TEST_KEY = pathlib.Path(
        os.environ.get("YES_SANDBOX_TEST_KEY", "yes_sandbox_test_key.pem")
    )
    YES_SANDBOX_TEST_CLIENT_ID = os.environ.get(
        "YES_SANDBOX_TEST_CLIENT_ID",
        "sandbox.yes.com:e85ff3bc-96f8-4ae7-b6b1-894d8dde9ebe",
    )
    YES_SANDBOX_TEST_REDIRECT_URI = os.environ.get(
        "YES_SANDBOX_TEST_REDIRECT_URI", "http://localhost:3000/yes/oidccb"
    )
    if not YES_SANDBOX_TEST_CERT.exists() or not YES_SANDBOX_TEST_KEY.exists():
        raise Exception(
            f"This example requires access to the yes® sandbox using the client id "
            f"{YES_SANDBOX_TEST_CLIENT_ID}. Please provide a "
            f"certificate and private key pair at the following locations: "
            f"{YES_SANDBOX_TEST_CERT} / {YES_SANDBOX_TEST_KEY}. These files are "
            f"available in the yes developer documentation at https://yes.com/docs . "
            f"To use a different client id or certificate/key locations, please set the "
            f"environment variables YES_SANDBOX_TEST_CLIENT_ID, YES_SANDBOX_TEST_CERT, "
            f"YES_SANDBOX_TEST_KEY, and/or YES_SANDBOX_TEST_REDIRECT_URI."
        )
    return {
        "client_id": YES_SANDBOX_TEST_CLIENT_ID,
        "cert_file": str(YES_SANDBOX_TEST_CERT),
        "key_file": str(YES_SANDBOX_TEST_KEY),
        "redirect_uri": YES_SANDBOX_TEST_REDIRECT_URI,
        "environment": "sandbox",
        "qtsp_id": "sp:sandbox.yes.com:85ac6820-8518-4aa1-ba85-de4307175b64"
    }


class YesExample:
    @cherrypy.expose
    def start(self, pdffile):
        """
        Starting the yes® flow after the user uploaded a file and clicked on the yes® button.
        """
        documents = [yes.PDFSigningDocument("Hochgeladenes Dokument", pdffile.file)]

        yessession = yes.YesSigningSession(documents)
        cherrypy.session["yes"] = yessession
        yesflow = yes.YesSigningFlow(yes_configuration(), cherrypy.session["yes"])
        ac_redirect = yesflow.start_yes_flow()

        cherrypy.log(f"Account chooser redirection to {ac_redirect}.")
        raise cherrypy.HTTPRedirect(ac_redirect)

    @cherrypy.expose
    def accb(self, state, issuer_url=None, error=None, selected_bic=None):
        """
        Account chooser callback. The user arrives here after selecting a bank.

        Note that the URL of this endpoint has to be registered with yes for
        your client. 
        """
        yessession = cherrypy.session["yes"]
        yesflow = yes.YesSigningFlow(yes_configuration(), yessession)

        try:
            authorization_endpoint_uri = yesflow.handle_ac_callback(
                state, issuer_url, error
            )
        except yes.YesUserCanceledError:
            cherrypy.HTTPRedirect("/")
        except yes.YesError as exception:
            # not implemented here: show nice error messages
            raise cherrypy.HTTPError(400, str(exception))

        raise cherrypy.HTTPRedirect(authorization_endpoint_uri)

    @cherrypy.expose
    def oidccb(self, iss, code=None, error=None, error_description=None):
        """
        OpenID Connect callback endpoint. The user arrives here after going
        through the authentication/authorizaton steps at the bank.

        Note that the URL of this endpoint has to be registered with yes for
        your client. 
        """
        yessession = cherrypy.session["yes"]
        yesflow = yes.YesSigningFlow(yes_configuration(), yessession)

        try:
            yesflow.handle_oidc_callback(iss, code, error, error_description)
        except yes.YesAccountSelectionRequested as exception:
            # user selected "select another bank" → must send user back to account chooser
            raise cherrypy.HTTPRedirect(exception.redirect_uri)
        except yes.YesError as exception:
            # not implemented here: show nice error messages
            raise cherrypy.HTTPError(400, str(exception))

        # id token and userinfo are alternative ways to retrieve user information - see developer guide
        yesflow.send_token_request()
        yesflow.create_signatures()

        return static.serve_file(
            yessession.documents[0].signed_file.name,
            "application/x-download",
            "attachment",
            "signed-document.pdf",
        )


class Root:
    @cherrypy.expose
    def default(self):
        return """
<form action="/yes/start" method="post" enctype="multipart/form-data">
PDF File <input type="file" name="pdffile" /><br />
Sign with my bank!<br>
<button type="submit">yes®</button></form><br>
<i>Note: This Example does not conform to the yes® user experience guidelines for signing.</i>
"""


cherrpy_config = {
    "global": {"server.socket_port": 3000},
    "/": {
        "tools.sessions.on": "True",
        "log.access_file": "access.log",
        "log.error_file": "error.log",
    },
}
cherrypy.tree.mount(Root(), "/", cherrpy_config)
cherrypy.quickstart(YesExample(), "/yes", cherrpy_config)

