import requests
from rest_framework.authentication import BaseAuthentication
from django.contrib.auth import get_user_model
from allauth.socialaccount.providers.keycloak.views import KeycloakOAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from allauth.socialaccount.helpers import complete_social_login
from allauth.socialaccount.models import SocialAccount
from django.http import HttpResponseBadRequest, HttpResponseRedirect
from django.contrib.auth import login

from django.conf import settings

import traceback

from .models import ClientAccount

class KeycloakAdapter(KeycloakOAuth2Adapter):
    def get_callback_url(self, request, app):
        return settings.KEYCLOAK_CALLBACK_URL


class CookieAuthenticationWithExternalJWT(BaseAuthentication):
    """
        Authentication using JWT from keykloak.
        Await header "Authorization" with Bearer token.
        1. Parsing JWT to SocialToken object (simple wrapper)
        2. Validating JWT using adapter (adapter complete_login() method)
        3. Creating SocialLogin that contains SocialAccount (adapter complete_login() method)
        4. Check if social_account exist and return user

        TODO: Check only Authorization header (without cookie)
        TODO: Use Token Authentication from rest_framework.authentication
    """
    adapter_class = KeycloakAdapter
    # client_class = OAuth2Client

    def get_header(self, request):
        """
        Extracts the header containing the JSON web token from the given
        request.
        """
        header = request.META.get('HTTP_AUTHORIZATION')

        return header

    def get_raw_token(self, header):
        """
        Extracts an unvalidated JSON web token from the given "Authorization"
        header value.
        """
        parts = header.split()

        if len(parts) == 0:
            # Empty AUTHORIZATION header sent
            return None

        if parts[0] != 'Bearer':
            # Assume the header does not contain a JSON web token
            return None

        if len(parts) != 2:
            return None

        return parts[1]

    def try_to_retrieve_jwt(self, request):
        header = self.get_header(request)

        if header is None:
            return None

        raw_token = self.get_raw_token(header)

        if raw_token is None:
            return None
        
        return raw_token

    def authenticate(self, request):
        print('*' * 75)
        print('\nCookieAuthenticationWithExternalJWT\n')

        raw_token = self.try_to_retrieve_jwt(request)

        if raw_token is None:
            print('*' * 75)
            return None

        print("Bearer JWT are found, try to validate")

        adapter = self.adapter_class(request)

        try:
            app = adapter.get_provider().get_app(request)

            tokens_to_parse = {'access_token': raw_token}

            social_token = adapter.parse_token(tokens_to_parse)  # Social application token
            social_token.app = app
            # social_token.save()

            social_login = adapter.complete_login(request, app, social_token, raw_token)

            # social_login.account == SocialAccount, so SocialLogin is wrapper

            print('social_login.account.provider', social_login.account.provider)
            print('social_login.account.uid', social_login.account.uid)
            if not social_login.is_existing:
                return None

            social_account = SocialAccount.objects.get(uid=social_login.account.uid)
            print('social_account.user', social_account.user)
            print('*' * 75)

            return social_account.user, raw_token
        except Exception:
            print("adapter.complete_login(): ", traceback.format_exc())
            print('*' * 75)
            return None


class ClientAuthentication(BaseAuthentication):
    adapter_class = KeycloakAdapter

    def get_header(self, request):
        """
        Extracts the header containing the JSON web token from the given
        request.
        """
        header = request.META.get('HTTP_AUTHORIZATION')

        return header

    def get_raw_token(self, header):
        """
        Extracts an unvalidated JSON web token from the given "Authorization"
        header value.
        """
        parts = header.split()

        if len(parts) == 0:
            # Empty AUTHORIZATION header sent
            return None

        if parts[0] != 'Bearer':
            # Assume the header does not contain a JSON web token
            return None

        if len(parts) != 2:
            return None

        return parts[1]

    def try_to_retrieve_jwt(self, request):
        header = self.get_header(request)

        if header is None:
            return None

        raw_token = self.get_raw_token(header)

        if raw_token is None:
            return None
        
        return raw_token
    
    def introspect_client_token(self, client_token, adapter, request):
        app = adapter.get_provider().get_app(request)
        server_url = adapter.get_provider()._server_url

        data = {
            "client_id": app.client_id,
            "client_secret": app.secret,
            "token": client_token
        }

        response = requests.request(
            'POST',
            f'{server_url}/protocol/openid-connect/token/introspect',
            data=data
        )

        response.raise_for_status()
        introspection = response.json()
        if not introspection['active']:
            raise Exception()

        return introspection

    def authenticate(self, request):
        client_token = self.try_to_retrieve_jwt(request)

        if client_token is None:
            return
        
        adapter = self.adapter_class(request)
        try:
            info = self.introspect_client_token(client_token, adapter, request)
            client_id = info['client_id']

            client_account = ClientAccount.objects.get(client_id=client_id)

            return client_account.user, client_token
        except:
            return

