class YesError(Exception):
    pass


class YesUserCanceledError(YesError):
    pass


class YesUnknownIssuerError(YesError):
    pass


class YesAccountSelectionRequested(YesError):
    redirect_uri: str


class YesOAuthError(YesError):
    oauth_error: str
    oauth_error_description: str

    def __str__(self):
        return f"OAuth error '{self.oauth_error}'; description: {self.oauth_error_description}."


class YesInvalidAuthorizationDetailsError(YesOAuthError):
    error_id = "invalid_authorization_details"


YES_OAUTH_ERRORS = (YesInvalidAuthorizationDetailsError,)


def parse_oauth_error(error_response):
    try:
        json = error_response.json()
        for error_class in YES_OAUTH_ERRORS:
            if error_class.error_id == json["error"]:
                break
        else:
            error_class = YesOAuthError

        e = error_class()
        e.oauth_error = json["error"]
        e.oauth_error_description = json["error_description"]
        return e
    except Exception as e:
        return YesError(
            f"Response status code {error_response.status_code}, response: '{error_response.text}'."
        )
