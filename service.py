import sys
import logging
import falcon
from oauthlib.oauth2 import RequestValidator, WebApplicationServer, FatalClientError, OAuth2Error

log = logging.getLogger('oauthlib')
log.addHandler(logging.StreamHandler(sys.stdout))
log.setLevel(logging.DEBUG)

FakeUsersData = {
    'simple_client_id_test': {'user_id': 1, 'user_name': 'test', 'user_password': '1234', 'access_token': None, 'redirect_uri': 'http://example.client.callbacks.server'},
    'simple_client_id_test1': {'user_id': 2, 'user_name': 'test1', 'user_password': '4321', 'access_token': None, 'redirect_uri': 'http://example.client.callbacks.server'},
    'simple_client_id_test2': {'user_id': 3, 'user_name': 'test2', 'user_password': '1342', 'access_token': None, 'redirect_uri': 'http://example.client.callbacks.server'},
}


class SimpleRequestValidator(RequestValidator):

    def validate_client_id(self, client_id, request, *args, **kwargs):
        # Simple validity check, does client exist? Not banned?
        return client_id in FakeUsersData

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        # Don't allow public (non-authenticated) clients
        return False

    def authenticate_client(self, request, *args, **kwargs):
        # Whichever authentication method suits you, HTTP Basic might work
        pass

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        # Validate the code belongs to the client. Add associated scopes,
        # state and user to request.scopes and request.user.
        pass

    def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        # Is the client allowed to use the supplied redirect_uri? i.e. has
        # the client previously registered this EXACT redirect uri.
        pass


class AuthorizeHandler(object):

    def __init__(self, authorization_endpoint):
        self._auth_endpoint = authorization_endpoint
        self.frontend_url = 'http://example.frontend.server'

    def on_post(self, request, response, *args, **kwargs):
        self.authorize_request(request, response, *args, **kwargs)

    def on_get(self, request, response, *args, **kwargs):
        self.authorize_request(request, response, *args, **kwargs)

    def authorize_request(self, request, response, *args, **kwargs):
        # :type request: falcon.Request
        # :type response: falcon.Response
        scopes = request.get_param('scopes') or ['all']
        credentials = {'redirect_uri': 'http://example.callbacks.service'}  # default credentials

        try:
            # print("%s, %s, %s, %s, %s, %s" % (request.uri, request.method, request.stream.read(), request.headers, scopes, credentials))

            headers, body, status = self._auth_endpoint.create_authorization_response(
                str(request.uri), str(request.method), str(request.stream.read()), dict(request.headers), scopes, credentials)

            # headers, body, status = self._auth_endpoint.create_authorization_response(
            #     request.uri, 'GET', '', {}, scopes, credentials)

            log.debug("status %s" % status)

            response.status = status
            response.body = body
            response.set_headers(headers)

            log.debug(response)

        except FatalClientError as e:
            log.debug("Exception")
            log.exception(e)
            raise falcon.HTTPError(status=falcon.HTTP_BAD_REQUEST, title='Invalid request')

        except OAuth2Error as e:
            log.debug("Oauth error")
            # Less grave errors will be reported back to client
            client_redirect_uri = credentials.get('redirect_uri')
            raise falcon.HTTPError(status=falcon.HTTP_FOUND, headers={'Location': e.in_uri(client_redirect_uri)})

auth_endpoint = WebApplicationServer(SimpleRequestValidator())
app = falcon.API()
app.add_route('/authorize', AuthorizeHandler(authorization_endpoint=auth_endpoint))

if __name__ == '__main__':
    from wsgiref.simple_server import make_server
    server = make_server('localhost', 8000, app)
    server.serve_forever()
