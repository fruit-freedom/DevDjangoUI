from allauth.socialaccount.providers.keycloak.views import KeycloakOAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from allauth.socialaccount.providers.oauth2.views import OAuth2CallbackView, OAuth2LoginView
from allauth.socialaccount.models import SocialLogin
from allauth.utils import get_request_param
from allauth.account.utils import has_verified_email
from allauth.account import app_settings as allauth_settings

from allauth.socialaccount.helpers import complete_social_login
from allauth.account import app_settings as allauth_account_settings

from dj_rest_auth.registration.serializers import SocialLoginSerializer
from dj_rest_auth.registration.views import SocialLoginView

from django.conf import settings
from django.http import HttpResponseBadRequest, HttpResponseRedirect, HttpResponse, JsonResponse
from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _

from rest_framework.exceptions import ValidationError
from rest_framework import serializers
from rest_framework.authentication import BaseAuthentication
from rest_framework import HTTP_HEADER_ENCODING
from rest_framework_simplejwt.exceptions import AuthenticationFailed

from requests.exceptions import HTTPError
import requests
import json

# class KeycloakLogin(SocialLoginView):
#     adapter_class = KeycloakOAuth2Adapter
#     client_class = OAuth2Client
#     callback_url = getattr(settings, 'KEYCLOAK_CALLBACK_URL', None)

class KeycloakAdapter(KeycloakOAuth2Adapter):
    def get_callback_url(self, request, app):
        return settings.KEYCLOAK_CALLBACK_URL


# ----    -----    -----    -----    -----    -----    -----    -----    -----    -----
# /auth/login/callback
# ----    -----    -----    -----    -----    -----    -----    -----    -----    -----

class OAuth2CallbackViewEx(OAuth2CallbackView):
    def dispatch(self, request, *args, **kwargs):
        # Distinguish cancel from error
        if (auth_error := request.GET.get('error', None)):
            if auth_error == self.adapter.login_cancelled_error:
                return HttpResponseRedirect(settings.SOCIALACCOUNT_CALLBACK_CANCELLED_URL)
            else: # unknown error
                raise ValidationError(auth_error)

        code = request.GET.get('code')

        # verify request state
        if self.adapter.supports_state:
            state = SocialLogin.verify_and_unstash_state(
                request, get_request_param(request, 'state')
            )
        else:
            state = SocialLogin.unstash_state(request)

        if not code:
            return HttpResponseBadRequest('Parameter code not found in request')
        print("OAuth2CallbackViewEx.dispatch()")
        return HttpResponseRedirect(
            f'{settings.SOCIAL_APP_LOGIN_REDIRECT_URL}/?provider={self.adapter.provider_id}&code={code}'
            f'&auth_params={state.get("auth_params")}&process={state.get("process")}'
            f'&scope={state.get("scope")}')


# ----    -----    -----    -----    -----    -----    -----    -----    -----    -----
# /auth/login/
# ----    -----    -----    -----    -----    -----    -----    -----    -----    -----

keycloak_login = OAuth2LoginView.adapter_view(KeycloakAdapter)
keycloak_callback = OAuth2CallbackViewEx.adapter_view(KeycloakAdapter)

# ----    -----    -----    -----    -----    -----    -----    -----    -----    -----
# /auth/login/token/
# ----    -----    -----    -----    -----    -----    -----    -----    -----    -----

class SocialLoginSerializerEx(SocialLoginSerializer):
    auth_params = serializers.CharField(required=False, allow_blank=True, default='')
    process = serializers.CharField(required=False, allow_blank=True, default='login')
    scope = serializers.CharField(required=False, allow_blank=True, default='')

    def get_social_login(self, adapter, app, token, response):
        # response is parsed json keycloak body response access_token, scope and etc 
        request = self._get_request()
        social_login = adapter.complete_login(request, app, token, response=response)
        social_login.token = token

        # social_login is allauth.socialaccount.models.SocialLogin
        # is_existing = False, state = {}, user -> <User: admin>, user.pk = None, user.password = '!mj...'

        social_login.state = {
            'process': self.initial_data.get('process'),
            'scope': self.initial_data.get('scope'),
            'auth_params': self.initial_data.get('auth_params'),
        }
        #  self.initial_data is MultiValueDict, it is like attrs
        return social_login

    def validate(self, attrs):
        view = self.context.get('view')
        request = self._get_request()

        if not view:
            raise serializers.ValidationError(
                _('View is not defined, pass it as a context variable'),
            )

        adapter_class = getattr(view, 'adapter_class', None)  # blog.engine.iam.KeycloakAdapter
        if not adapter_class:
            raise serializers.ValidationError(_('Define adapter_class in view'))

        adapter = adapter_class(request)  # blog.engine.iam.KeycloakAdapter
        # adapter.get_provider() allauth.socialaccount.providers.keycloak.provider.KeycloakProvider
        app = adapter.get_provider().get_app(request)  # SocialApp (client_id, client_secret)

        # More info on code vs access_token
        # http://stackoverflow.com/questions/8666316/facebook-oauth-2-0-code-and-token

        # attrs it is OrderedDict (access_token, code, id_token, auth_params, process, scope)
        access_token = attrs.get('access_token')
        code = attrs.get('code')
        # Case 1: We received the access_token
        if access_token:
            tokens_to_parse = {'access_token': access_token}
            token = access_token
            # For sign in with apple
            id_token = attrs.get('id_token')
            if id_token:
                tokens_to_parse['id_token'] = id_token

        # Case 2: We received the authorization code
        elif code:
            self.set_callback_url(view=view, adapter_class=adapter_class)
            self.client_class = getattr(view, 'client_class', None)  # allauth.socialaccount.providers.oauth2.client.OAuth2Client

            if not self.client_class:
                raise serializers.ValidationError(
                    _('Define client_class in view'),
                )

            provider = adapter.get_provider()
            scope = provider.get_scope(request)  # list ['openid', 'profile', 'email']
            client = self.client_class(
                request,
                app.client_id,
                app.secret,
                adapter.access_token_method,  # 'POST'
                adapter.access_token_url,  # 'http://10.24.65.226:7070/realms/master/protocol/openid-connect/token'
                self.callback_url,  # /auth/callback
                scope,
                scope_delimiter=adapter.scope_delimiter,
                headers=adapter.headers,  # None
                basic_auth=adapter.basic_auth,  # True
            )
            token = client.get_access_token(code) # dict
            # all fields from keycloak: access_token, refresh_token, scope (openid, profile email) etc...
            access_token = token['access_token']
            tokens_to_parse = {'access_token': access_token}

            # If available we add additional data to the dictionary
            for key in ['refresh_token', 'id_token', adapter.expires_in_key]:
                if key in token:
                    tokens_to_parse[key] = token[key]
        else:
            raise serializers.ValidationError(
                _('Incorrect input. access_token or code is required.'),
            )
        # tokens_to_parse is dict, contains different JWT access_token, refresh_token, id_token and expires_in
        social_token = adapter.parse_token(tokens_to_parse)  # SocialToken
        social_token.app = app
        #  social_token pk = None, id = None, token_secret = refresh_token, token = access_token
        try:
            if adapter.provider_id == 'google':
                login = self.get_social_login(adapter, app, social_token, response={'id_token': token})
            else:
                login = self.get_social_login(adapter, app, social_token, token)
            # Here login.user.pk = 5, user.password changed, is_existing = True
            ret = complete_social_login(request, login)  # HTTPResponseRedirect status_code = 302
        except HTTPError:
            raise serializers.ValidationError(_('Incorrect value'))

        if isinstance(ret, HttpResponseBadRequest):
            raise serializers.ValidationError(ret.content)

        if not login.is_existing:
            # We have an account already signed up in a different flow
            # with the same email address: raise an exception.
            # This needs to be handled in the frontend. We can not just
            # link up the accounts due to security constraints
            if allauth_account_settings.UNIQUE_EMAIL:  # True
                # Do we have an account already with this email address?
                account_exists = get_user_model().objects.filter(
                    email=login.user.email,
                ).exists()
                if account_exists:
                    raise serializers.ValidationError(
                        _('User is already registered with this e-mail address.'),
                    )

            login.lookup()
            login.save(request, connect=True)
            # Chacnged user fields groups, user_permissions
            self.post_signup(login, attrs)

        attrs['user'] = login.account.user
        attrs['access_token_from_keycloak'] = access_token
        print("TOKEN FROM KEYCLOAK: ", access_token)

        return attrs

# /auth/token
class SocialLoginViewEx(SocialLoginView):
    serializer_class = SocialLoginSerializerEx

    def post(self, request, *args, **kwargs):
        from rest_framework.renderers import JSONRenderer # Debug
        # we have to re-implement this method because
        # there is one case not covered by dj_rest_auth but covered by allauth
        # user can be logged in with social account and "unverified" email
        # (e.g. the provider doesn't provide information about email verification)
        print(f"---- SocialLoginViewEx.post() body:  {request.body}")

        self.request = request
        self.serializer = self.get_serializer(data=self.request.data)
        self.serializer.is_valid(raise_exception=True)

        if allauth_settings.EMAIL_VERIFICATION == allauth_settings.EmailVerificationMethod.MANDATORY and \
            not has_verified_email(self.serializer.validated_data.get('user')):
            return HttpResponseBadRequest('Unverified email')

        self.login()
        # return self.get_response()

        # Use self.access_token & self.refresh_token
        # print("---- validated data: ", self.serializer.validated_data)
        ret = self.get_response()
        # ret.accepted_renderer = JSONRenderer()
        # ret.accepted_media_type = "application/json"
        # ret.renderer_context = {}
        # ret.render()
        # print(f"---- SocialLoginViewEx.post() content:  {ret.content}")
        return ret
    
    # Custom login function to use externat JWT from keycloak
    # def login(self):
    #     self.user = self.serializer.validated_data['user']
    #     token_model = get_token_model()

    #     # Exchange authorization_code to JWT
    #     self.access_token, self.refresh_token = jwt_encode(self.user)

    #     if api_settings.SESSION_LOGIN:
    #         self.process_login()

# /keycloak/login/token
class KeycloakLogin(SocialLoginViewEx):
    adapter_class = KeycloakAdapter
    client_class = OAuth2Client
    # callback_url = getattr(settings, 'KEYCLOAK_CALLBACK_URL', None)


# ----    ----    ----    ----    ----    ----    ----    ----    ----    ----    ----    ----
# Updated to JWT only
# ----    ----    ----    ----    ----    ----    ----    ----    ----    ----    ----    ----

# ----    ----    ----    ----    ----    ----    ----    ----    ----    ----    ----    ----
# /auth/login_jwt
# ----    ----    ----    ----    ----    ----    ----    ----    ----    ----    ----    ----
class LoginViewJWT(OAuth2LoginView):
    adapter_class = KeycloakAdapter
    """
        Should be used with adapter_view() wrapper.
        View should check cookie 'TOKEN' and redirect to specific UI page like /social-login-app-keycloak.
        UI handle it and retrieve 
    """
    
    def get_header(self, request):
        header = request.META.get('HTTP_AUTHORIZATION')
        return header

    def get_raw_token(self, header):
        parts = header.split()

        if len(parts) == 0:
            # Empty AUTHORIZATION header sent
            return None

        if parts[0] != 'Bearer':
            # Assume the header does not contain a JSON web token
            return None

        if len(parts) != 2:
            raise AuthenticationFailed(
                _("Authorization header must contain two space-delimited values"),
                code="bad_authorization_header",
            )

        return parts[1]

    def try_to_retrieve_jwt(self, request):
        # cookie_name = api_settings.JWT_AUTH_COOKIE
        cookie_name = 'TOKEN'
        header = self.get_header(request)
        if header is None:
            if cookie_name:
                raw_token = request.COOKIES.get(cookie_name)
                # if api_settings.JWT_AUTH_COOKIE_ENFORCE_CSRF_ON_UNAUTHENTICATED: #True at your own risk
                #     self.enforce_csrf(request)
                # elif raw_token is not None and api_settings.JWT_AUTH_COOKIE_USE_CSRF:
                #     self.enforce_csrf(request)
            else:
                return None
        else:
            raw_token = self.get_raw_token(header)

        if raw_token is None:
            return None
        
        return raw_token

    def get_social_login(self, request, adapter, app, token, response):
        """
        Method like in SocialLoginSerializer from dj_rest_auth.registration.serializers
        """
        # response is parsed json keycloak body response access_token, scope and etc 
        social_login = adapter.complete_login(request, app, token, response=response)
        social_login.token = token  # token is SocialToken 
        return social_login

    def login(self, request, *args, **kwargs):
        raw_jwt = self.try_to_retrieve_jwt(request)

        if raw_jwt is None:
            return super().login(request, *args, **kwargs)

        app = self.adapter.get_provider().get_app(request)
        social_token = self.adapter.parse_token({
            'access_token': raw_jwt
        })
        social_token.app = app

        login = self.get_social_login(self, self.adapter, app, social_token, {
            'access_token': raw_jwt
        })

        ret = complete_social_login(request, login)

        if isinstance(ret, HttpResponseBadRequest):
            raise Exception(ret.content)

        if not login.is_existing:
            # We have an account already signed up in a different flow
            # with the same email address: raise an exception.
            # This needs to be handled in the frontend. We can not just
            # link up the accounts due to security constraints
            if allauth_account_settings.UNIQUE_EMAIL:  # True
                # Do we have an account already with this email address?
                account_exists = get_user_model().objects.filter(
                    email=login.user.email,
                ).exists()
                if account_exists:
                    raise Exception(_('User is already registered with this e-mail address.'),)

            login.lookup()
            login.save(request, connect=True)

        # return HttpResponseRedirect('/users/')

        return HttpResponse(
            """
            <html>
                <body>
                    <h1>Redirect to /auth/token for getting JWT</h1>
                    <h2>{}</h2>
                </body>
            </html>
            """.format(raw_jwt)
        )
    
keycloak_login_jwt = LoginViewJWT.adapter_view(KeycloakAdapter)

class SocialLoginSerializerJWT(SocialLoginSerializer):
    auth_params = serializers.CharField(required=False, allow_blank=True, default='')
    process = serializers.CharField(required=False, allow_blank=True, default='login')
    scope = serializers.CharField(required=False, allow_blank=True, default='')

    def validate(self, attrs):
        view = self.context.get('view')
        request = self._get_request()

        if not view:
            raise serializers.ValidationError(
                _('View is not defined, pass it as a context variable'),
            )

        adapter_class = getattr(view, 'adapter_class', None)  # blog.engine.iam.KeycloakAdapter
        if not adapter_class:
            raise serializers.ValidationError(_('Define adapter_class in view'))

        adapter = adapter_class(request)  # blog.engine.iam.KeycloakAdapter
        # adapter.get_provider() allauth.socialaccount.providers.keycloak.provider.KeycloakProvider
        app = adapter.get_provider().get_app(request)  # SocialApp (client_id, client_secret)

        # More info on code vs access_token
        # http://stackoverflow.com/questions/8666316/facebook-oauth-2-0-code-and-token

        # attrs it is OrderedDict (access_token, code, id_token, auth_params, process, scope)
        access_token = attrs.get('access_token')
        code = attrs.get('code')
        # Case 1: We received the access_token
        if access_token:
            tokens_to_parse = {'access_token': access_token}
            token = access_token
            # For sign in with apple
            id_token = attrs.get('id_token')
            if id_token:
                tokens_to_parse['id_token'] = id_token

        # Case 2: We received the authorization code
        elif code:
            self.set_callback_url(view=view, adapter_class=adapter_class)
            self.client_class = getattr(view, 'client_class', None)  # allauth.socialaccount.providers.oauth2.client.OAuth2Client

            if not self.client_class:
                raise serializers.ValidationError(
                    _('Define client_class in view'),
                )

            provider = adapter.get_provider()
            scope = provider.get_scope(request)  # list ['openid', 'profile', 'email']
            client = self.client_class(
                request,
                app.client_id,
                app.secret,
                adapter.access_token_method,  # 'POST'
                adapter.access_token_url,  # 'http://10.24.65.226:7070/realms/master/protocol/openid-connect/token'
                self.callback_url,  # /auth/callback
                scope,
                scope_delimiter=adapter.scope_delimiter,
                headers=adapter.headers,  # None
                basic_auth=adapter.basic_auth,  # True
            )
            token = client.get_access_token(code) # dict
            # all fields from keycloak: access_token, refresh_token, scope (openid, profile email) etc...
            access_token = token['access_token']
            tokens_to_parse = {'access_token': access_token}

            # If available we add additional data to the dictionary
            for key in ['refresh_token', 'id_token', adapter.expires_in_key]:
                if key in token:
                    tokens_to_parse[key] = token[key]
        else:
            raise serializers.ValidationError(
                _('Incorrect input. access_token or code is required.'),
            )
        # tokens_to_parse is dict, contains different JWT access_token, refresh_token, id_token and expires_in
        social_token = adapter.parse_token(tokens_to_parse)  # SocialToken
        social_token.app = app
        #  social_token pk = None, id = None, token_secret = refresh_token, token = access_token
        try:
            if adapter.provider_id == 'google':
                login = self.get_social_login(adapter, app, social_token, response={'id_token': token})
            else:
                login = self.get_social_login(adapter, app, social_token, token)
            # Here login.user.pk = 5, user.password changed, is_existing = True
            ret = complete_social_login(request, login)  # HTTPResponseRedirect status_code = 302
        except HTTPError:
            raise serializers.ValidationError(_('Incorrect value'))

        if isinstance(ret, HttpResponseBadRequest):
            raise serializers.ValidationError(ret.content)

        if not login.is_existing:
            # We have an account already signed up in a different flow
            # with the same email address: raise an exception.
            # This needs to be handled in the frontend. We can not just
            # link up the accounts due to security constraints
            if allauth_account_settings.UNIQUE_EMAIL:  # True
                # Do we have an account already with this email address?
                account_exists = get_user_model().objects.filter(
                    email=login.user.email,
                ).exists()
                if account_exists:
                    raise serializers.ValidationError(
                        _('User is already registered with this e-mail address.'),
                    )

            login.lookup()
            login.save(request, connect=True)
            # Chacnged user fields groups, user_permissions
            self.post_signup(login, attrs)

        attrs['user'] = login.account.user
        
        attrs['access_token'] = access_token
        attrs['expires_in'] = token['expires_in']

        attrs['refresh_token'] = token['refresh_token']
        attrs['refresh_expires_in'] = token['refresh_expires_in']
        
        attrs['scope'] = token['scope']

        return attrs

# ----    ----    ----    ----    ----    ----    ----    ----    ----    ----    ----    ----
# /auth/login/token
# ----    ----    ----    ----    ----    ----    ----    ----    ----    ----    ----    ----
class SocialLoginViewJWT(SocialLoginView):
    serializer_class = SocialLoginSerializerJWT
    client_class = OAuth2Client
    adapter_class = KeycloakAdapter

    def post(self, request, *args, **kwargs):
        # we have to re-implement this method because
        # there is one case not covered by dj_rest_auth but covered by allauth
        # user can be logged in with social account and "unverified" email
        # (e.g. the provider doesn't provide information about email verification)

        self.request = request
        self.serializer = self.get_serializer(data=self.request.data)
        self.serializer.is_valid(raise_exception=True)

        if allauth_settings.EMAIL_VERIFICATION == allauth_settings.EmailVerificationMethod.MANDATORY and \
            not has_verified_email(self.serializer.validated_data.get('user')):
            return HttpResponseBadRequest('Unverified email')

        # self.login()  # Create custom JWT or Token
        # TODO: In login function save JWT as Tokne medel in database and then in Auth backend select token with user foreign key

        validated_data = self.serializer.validated_data

        response = JsonResponse({
            'access_token': validated_data.get('access_token'),
            'expires_in': validated_data.get('expires_in'),
            'refresh_token': validated_data.get('refresh_token'),
            'refresh_expires_in': validated_data.get('refresh_expires_in'),
            'scope': validated_data.get('scope'),
        })

        response.set_cookie('TOKEN', validated_data.get('access_token'))
        return response