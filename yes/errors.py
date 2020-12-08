class YesError(Exception):
    pass


class YesUserCanceledError(YesError):
    pass


class YesUnknownIssuerError(YesError):
    pass


class YesInvalidIssuerError(YesError):
    pass


class YesAccountSelectionRequested(YesError):
    redirect_uri: str


class YesOAuthError(YesError):
    oauth_error: str
    oauth_error_description: str
