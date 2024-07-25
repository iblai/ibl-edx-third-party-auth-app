from social_core.backends import google_openidconnect
from social_core.backends.google_openidconnect import GoogleOpenIdConnect


class IblGoogleOpenIdConnectAuth(GoogleOpenIdConnect):
    ID_TOKEN_ISSUER = 'https://accounts.google.com'

def patch():
    google_openidconnect.GoogleOpenIdConnect = IblGoogleOpenIdConnectAuth