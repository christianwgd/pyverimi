import cherrypy
import yes
from cherrypy.lib import static


configuration = yes.YesConfiguration.sandbox_test_from_env()


class YesExample:
    @cherrypy.expose
    def start(self, pdffile):
        """
        Starting the yes® flow after the user uploaded a file and clicked on the yes® button.
        """
        documents = [yes.PDFSigningDocument("Hochgeladenes Dokument", pdffile.file)]

        yessession = yes.YesSigningSession(documents)
        cherrypy.session["yes"] = yessession
        yesflow = yes.YesSigningFlow(configuration, cherrypy.session["yes"])
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
        yesflow = yes.YesSigningFlow(configuration, yessession)

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
        yesflow = yes.YesSigningFlow(configuration, yessession)

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

