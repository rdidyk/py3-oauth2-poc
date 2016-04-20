import os
import sys
import logging
import falcon
import urllib
from oauthlib.oauth2 import RequestValidator, WebApplicationServer, FatalClientError, OAuth2Error
from urllib import parse

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = 'true'
log = logging.getLogger('oauthlib')
# log = logging.getLogger('auth_app')
log.addHandler(logging.StreamHandler(sys.stdout))
log.setLevel(logging.DEBUG)


class User:
    def __init__(self, **entries):
        self.__dict__.update(entries)


FakeUsersData = {
    'test': User(**{'user_id': 1, 'client_id': 'test', 'client_secret': '1234',
                    'default_redirect_uri': 'http://localhost:8000/oauth/callback', 'default_scopes': ['read']}),
    'test1': User(**{'user_id': 2, 'client_id': 'test1', 'client_secret': '4321',
                     'default_redirect_uri': 'http://localhost:8000/oauth/callback', 'default_scopes': ['read']}),
    'test2': User(**{'user_id': 3, 'client_id': 'test2', 'client_secret': '1342',
                     'default_redirect_uri': 'http://localhost:8000/oauth/callback', 'default_scopes': ['read']}),
}


class SimpleRequestValidator(RequestValidator):

    def validate_user(self, username, password, client, request, *args, **kwargs):
        pass

    def get_original_scopes(self, refresh_token, request, *args, **kwargs):
        pass

    def validate_bearer_token(self, token, scopes, request):
        pass

    def revoke_token(self, token, token_type_hint, request, *args, **kwargs):
        pass

    def validate_refresh_token(self, refresh_token, client, request, *args, **kwargs):
        pass

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        pass

    def client_authentication_required(self, request, *args, **kwargs):
        grant_types = ('password', 'authorization_code', 'refresh_token')
        return request.grant_type in grant_types

    def validate_client_id(self, client_id, request, *args, **kwargs):
        log.debug('Authenticate client id %r.', client_id)
        client = FakeUsersData.get(client_id)
        if not client:
            log.debug('Authenticate failed, client not found.')
            return False
        # attach client on request for convenience
        request.client = client
        return True

    def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        return True

    def validate_response_type(self, client_id, response_type, client, request, *args, **kwargs):
        return True

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        request.client = request.client or FakeUsersData.get(client_id)
        scopes = request.client.default_scopes
        log.debug('Found default scopes %r', scopes)
        return scopes

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        request.client = request.client or FakeUsersData.get(client_id)
        redirect_uri = request.client.default_redirect_uri
        log.debug('Found default redirect uri %r', redirect_uri)
        return redirect_uri

    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        return True

    def save_authorization_code(self, client_id, code, request, *args, **kwargs):
        log.debug(
            'Persist authorization code %r for client %r',
            code, client_id
        )
        return request.redirect_uri

    def authenticate_client(self, request, *args, **kwargs):
        client_id = request.client_id
        client_secret = request.client_secret
        client = FakeUsersData.get(client_id)

        if not client:
            return False

        if client.client_secret != client_secret:
            log.debug('Authenticate client failed, secret not match.')
            return False

        request.client = client
        log.debug('Authenticate client success.')
        return True

    def validate_grant_type(self, client_id, grant_type, client, request, *args, **kwargs):
        return True

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        if client_id not in FakeUsersData:
            return False
        request.state = kwargs.get('state')
        request.user = FakeUsersData.get(client_id)
        request.scopes = []
        return True

    def confirm_redirect_uri(self, client_id, code, redirect_uri, client, *args, **kwargs):
        log.debug('Confirm redirect uri for client %r and code %r.', client.client_id, code)
        testing = 'OAUTHLIB_INSECURE_TRANSPORT' in os.environ
        if testing and redirect_uri is None:
            # For testing
            return True

    def save_bearer_token(self, token, request, *args, **kwargs):
        log.debug('Save bearer token %r', token)
        return request.client.default_redirect_uri

    def invalidate_authorization_code(self, client_id, code, request,
                                      *args, **kwargs):
        log.debug('Destroy grant token for client %r, %r', client_id, code)


class BaseHandler(object):

    def __init__(self, authorization_endpoint):
        self._auth_endpoint = authorization_endpoint


class AuthorizeHandler(BaseHandler):

    def __init__(self, *args, **kwargs):
        super(AuthorizeHandler, self).__init__(*args, **kwargs)
        self.error_url = 'http://localhost:8000/oauth/error'

    def on_post(self, request: falcon.Request, response: falcon.Response):
        self.authorize_request(request, response)

    def authorize_request(self, request: falcon.Request, response: falcon.Response):
        uri, http_method, body, headers = extract_params(request)
        scope = request.params.get('scope') or ''
        scopes = scope.split()
        credentials = dict(
            client_id=request.params.get('client_id'),
            redirect_uri=request.params.get('redirect_uri', None),
            response_type=request.params.get('response_type', None),
            state=request.params.get('state', None)
        )
        log.debug('Fetched credentials from request %r.', credentials)

        try:
            headers, body, status = self._auth_endpoint.create_authorization_response(
                uri, http_method, body, headers, scopes, credentials)
            log.debug('Authorization successful.')
        except FatalClientError as e:
            log.debug('Fatal client error %r', e)
            response.status = falcon.HTTP_SEE_OTHER
            response.set_header('Location', e.in_uri(self.error_url))
        except OAuth2Error as e:
            log.debug('OAuth2Error: %r', e)
            response.status = falcon.HTTP_SEE_OTHER
            response.set_header('Location', e.in_uri(self.error_url))
        else:
            patch_response(response, headers, body, status)


class TokenHandler(BaseHandler):

    def on_post(self, request: falcon.Request, response: falcon.Response):
        uri, http_method, body, headers = extract_params(request)
        credentials = {}
        headers, body, status = auth_endpoint.create_token_response(
            uri, http_method, body, headers, credentials
        )
        patch_response(response, headers, body, status)


class CallbackHandler(object):
    def on_get(self, request: falcon.Request, response: falcon.Response):
        pass

    def on_post(self, request: falcon.Request, response: falcon.Response):
        pass


def url_fix(s):
    scheme, netloc, path, qs, anchor = urllib.parse.urlsplit(s)
    qs = urllib.parse.urlencode(dict(urllib.parse.parse_qsl(qs)))
    return urllib.parse.urlunsplit((scheme, netloc, path, qs, anchor))


def extract_params(req: falcon.Request):
    body = ''
    if req.method in ('POST', 'PUT', 'OPTIONS'):
        if req.content_type == 'application/x-www-form-urlencoded':
            body = urllib.parse.urlencode(req.params)
        else:
            body = req.stream.read()
    uri = url_fix(req.uri)
    return uri, req.method, body, req.headers


def patch_response(resp: falcon.Response, headers, body, status):
    if body:
        resp.body = body
    resp.set_headers(headers)
    if isinstance(status, int):
        status = getattr(falcon, 'HTTP_{}'.format(status))
    resp.status = status
    return resp


auth_endpoint = WebApplicationServer(SimpleRequestValidator())
app = falcon.API()
app.add_route('/oauth/authorize', AuthorizeHandler(authorization_endpoint=auth_endpoint))
app.add_route('/oauth/token', TokenHandler(authorization_endpoint=auth_endpoint))
app.add_route('/oauth/callback', CallbackHandler())
app.add_route('/oauth/error', CallbackHandler())

if __name__ == '__main__':
    from wsgiref.simple_server import make_server
    service = make_server('localhost', 8000, app)
    service.serve_forever()
