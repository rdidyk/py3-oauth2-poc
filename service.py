import os
import sys
import logging
import falcon
from oauthlib.oauth2 import RequestValidator, WebApplicationServer, FatalClientError, OAuth2Error
from urllib import parse

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = 'true'
log = logging.getLogger('oauthlib')
log.addHandler(logging.StreamHandler(sys.stdout))
log.setLevel(logging.DEBUG)

FakeUsersData = {
    'c622ece4-77e5-4859-ae18-2b9f27bdd041': {'user_id': 1, 'user_name': 'test', 'user_password': '1234', 'access_token': None, 'redirect_uri': 'http://example.client.callbacks.server'},
    '724f301d-44b0-4142-b178-73bbe8cd152c': {'user_id': 2, 'user_name': 'test1', 'user_password': '4321', 'access_token': None, 'redirect_uri': 'http://example.client.callbacks.server'},
    'ac04a1ed-047a-40fa-a89a-2db06e3087a3': {'user_id': 3, 'user_name': 'test2', 'user_password': '1342', 'access_token': None, 'redirect_uri': 'http://example.client.callbacks.server'},
}


class SimpleRequestValidator(RequestValidator):

    def validate_client_id(self, client_id, request, *args, **kwargs):
        # Simple validity check, does client exist? Not banned?
        return client_id in FakeUsersData

    def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        # Is the client allowed to use the supplied redirect_uri? i.e. has
        # the client previously registered this EXACT redirect uri.
        pass

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        # The redirect used if none has been supplied.
        # Prefer your clients to pre register a redirect uri rather than
        # supplying one on each authorization request.
        pass

    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        # Is the client allowed to access the requested scopes?
        pass

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        # Scopes a client will authorize for if none are supplied in the
        # authorization request.
        pass

    def validate_response_type(self, client_id, response_type, client, request, *args, **kwargs):
        # Clients should only be allowed to use one type of response type, the
        # one associated with their one allowed grant type.
        # In this case it must be "code".
        pass

    # Post-authorization

    def save_authorization_code(self, client_id, code, request, *args, **kwargs):
        # Remember to associate it with request.scopes, request.redirect_uri
        # request.client, request.state and request.user (the last is passed in
        # post_authorization credentials, i.e. { 'user': request.user}.
        pass

    # Token request

    def authenticate_client(self, request, *args, **kwargs):
        # Whichever authentication method suits you, HTTP Basic might work
        pass

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        # Don't allow public (non-authenticated) clients
        return False

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        # Validate the code belongs to the client. Add associated scopes,
        # state and user to request.scopes and request.user.
        pass

    def confirm_redirect_uri(self, client_id, code, redirect_uri, client, *args, **kwargs):
        # You did save the redirect uri with the authorization code right?
        pass

    def validate_grant_type(self, client_id, grant_type, client, request, *args, **kwargs):
        # Clients should only be allowed to use one type of grant.
        # In this case, it must be "authorization_code" or "refresh_token"
        pass

    def save_bearer_token(self, token, request, *args, **kwargs):
        # Remember to associate it with request.scopes, request.user and
        # request.client. The two former will be set when you validate
        # the authorization code. Don't forget to save both the
        # access_token and the refresh_token and set expiration for the
        # access_token to now + expires_in seconds.
        pass

    def invalidate_authorization_code(self, client_id, code, request, *args, **kwargs):
        # Authorization codes are use once, invalidate it when a Bearer token
        # has been acquired.
        pass

    # Protected resource request

    def validate_bearer_token(self, token, scopes, request):
        # Remember to check expiration and scope membership
        pass

    # Token refresh request

    def get_original_scopes(self, refresh_token, request, *args, **kwargs):
        # Obtain the token associated with the given refresh_token and
        # return its scopes, these will be passed on to the refreshed
        # access token if the client did not specify a scope during the
        # request.
        pass


class BaseHandler(object):

    def __init__(self, authorization_endpoint):
        self._auth_endpoint = authorization_endpoint

    def response_from_error(self, e):
        raise falcon.HTTPBadRequest('Evil client is unable to send a proper request.', e.description)

    def response_from_return(self, response: falcon.Response, headers, body, status):
        response.status = status
        response.body(body)
        for k, v in headers.items():
            response.append_header(k, v)


class AuthorizeHandler(BaseHandler):

    def __init__(self, *args, **kwargs):
        super(AuthorizeHandler, self).__init__(*args, **kwargs)
        self.frontend_url = 'http://example.frontend.server'

    def on_post(self, request: falcon.Request, response: falcon.Response, *args, **kwargs):
        self.authorize_request(request, response, *args, **kwargs)

    def on_get(self, request: falcon.Request, response: falcon.Response, *args, **kwargs):
        self.authorize_request(request, response, *args, **kwargs)

    def authorize_request(self, request: falcon.Request, response: falcon.Response, *args, **kwargs):
        scopes = ('all',)
        credentials = {'redirect_uri': 'http://example.callbacks.service'}  # default credentials

        try:
            headers, body, status = self._auth_endpoint.create_authorization_response(
                parse.quote(request.uri.encode('utf8')),
                request.method,
                str(request.stream.read()),
                request.headers,
                scopes,
                credentials
            )

            self.response_from_return(response, headers, body, status)

        except FatalClientError as e:
            log.exception(e)
            self.response_from_error(e)

        except OAuth2Error as e:
            # Less grave errors will be reported back to client
            client_redirect_uri = credentials.get('redirect_uri')
            response.status = falcon.HTTP_TEMPORARY_REDIRECT
            response.append_header('Location', e.in_uri(client_redirect_uri))


class TokenHandler(BaseHandler):

    def on_post(self, request: falcon.Request, response: falcon.Response):

        # uri, http_method, body, headers = extract_params(request)

        # If you wish to include request specific extra credentials for
        # use in the validator, do so here.
        credentials = {'foo': 'bar'}

        headers, body, status = self._auth_endpoint.create_token_response(
            urllib.parse.quote(request.uri.encode('utf8')),
            request.method,
            str(request.stream.read()),
            request.headers,
            credentials
        )

        # All requests to /token will return a json response, no redirection.
        self.response_from_return(response, headers, body, status)


auth_endpoint = WebApplicationServer(SimpleRequestValidator())
app = falcon.API()
app.add_route('/oauth/authorize', AuthorizeHandler(authorization_endpoint=auth_endpoint))
app.add_route('/oauth/token', TokenHandler(authorization_endpoint=auth_endpoint))

if __name__ == '__main__':
    from wsgiref.simple_server import make_server, urllib

    server = make_server('localhost', 8000, app)
    server.serve_forever()
