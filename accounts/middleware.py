from django.contrib.sessions.backends.db import SessionStore
from django.contrib.sessions.middleware import SessionMiddleware
from django.contrib.auth.middleware import AuthenticationMiddleware

class CustomSessionMiddleware(SessionMiddleware):
    """
    Middleware that accepts session IDs from cookies or X-Session-Id header.
    This allows frontend applications to include the session ID in request headers
    instead of relying on cookies.
    """
    def process_request(self, request):
        session_key = request.META.get('HTTP_X_SESSION_ID')
        if session_key:
            request.session = SessionStore(session_key)
        else:
            super().process_request(request)

class CustomAuthMiddleware(AuthenticationMiddleware):
    """
    Standard authentication middleware to be used after the custom session middleware
    """
    pass 