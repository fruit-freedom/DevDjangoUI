POST to `http://localhost:8000/dj-rest-auth/keycloak/` trigger:

Contains implementation of `complete_login` method (40 row) [here](.env/lib/python3.10/site-packages/allauth/socialaccount/providers/openid_connect/views.py)
make request to `http://10.24.65.226:7070/realms/master/protocol/openid-connect/userinfo` and got `403 Forbidden` statuc code



Idea
----
LoginViewJWT endpoint check cookie `TOKEN`.
* If cookie does not exist then redirect to keycloak login page e.i. standart authorization code flow.
* If cookie exists then redirect to specific UI page. UI go to token endpoint with specific process option: `login-from-cookie` that indicates endpoint to
use JWT from `TOKEN` cookie for authorization. TokenViewJWT return `access_token`.

Additionally `refresh_token` could be saves in request session or in db. After `access_token` expiration retrieve new token using refresh if refresh_token exists.




In simple way it use this backend to authenticate user:
```python
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'dj_rest_auth.jwt_auth.JWTCookieAuthentication',
    )
}
```

[Here](.env/lib/python3.10/site-packages/dj_rest_auth/jwt_auth.py) (126 row) is `authenticate` method that get JWT from header or from cookie.
At first, it use `AUTH_TOKEN_CLASSES` to validate token.
And then it retrieve `user_id` from JWT ang use it to obtain user model from database.

```python
SOCIALACCOUNT_LOGIN_ON_GET = True
```

[Here](.env/lib/python3.10/site-packages/rest_framework_simplejwt/authentication.py) (109 line) method that return user from JWT.

# How SocialAccount work

allauth define [SocialAccount](.env/lib/python3.10/site-packages/allauth/socialaccount/models.py) model. It is mapping from OpenID UID to user_id from Django db. Each SocialAccount record contains user foreing key and UID:
```python
class SocialAccount(models.Model):
    user = models.ForeignKey(allauth.app_settings.USER_MODEL, on_delete=models.CASCADE)
    provider = models.CharField(
        verbose_name=_("provider"),
        max_length=30,
        choices=providers.registry.as_choices(),
    )
    uid = models.CharField(
        verbose_name=_("uid"), max_length=app_settings.UID_MAX_LENGTH
    )
    # ...
```

[TokenAuthentication](.env/lib/python3.10/site-packages/rest_framework/authentication.py) use the same model. It use Token Authorize header. It keeps tokens that is simply mapping from token to user.
```python
class Token(models.Model):
    """
    The default authorization token model.
    """
    key = models.CharField(_("Key"), max_length=40, primary_key=True)
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, related_name='auth_token',
        on_delete=models.CASCADE, verbose_name=_("User")
    )
    # ...
```
Note: Token use one to one relations instead foreign key in allauth.


# Interseting functions
```python
def sociallogin_from_response(self, request, response):
        """
        Instantiates and populates a `SocialLogin` model based on the data
        retrieved in `response`. The method does NOT save the model to the
        DB.

        Data for `SocialLogin` will be extracted from `response` with the
        help of the `.extract_uid()`, `.extract_extra_data()`,
        `.extract_common_fields()`, and `.extract_email_addresses()`
        methods.

        :param request: a Django `HttpRequest` object.
        :param response: object retrieved via the callback response of the
            social auth provider.
        :return: A populated instance of the `SocialLogin` model (unsaved).
        """
        # NOTE: Avoid loading models at top due to registry boot...
        from allauth.socialaccount.models import SocialAccount, SocialLogin

        adapter = get_adapter(request)
        uid = self.extract_uid(response)
        extra_data = self.extract_extra_data(response)
        common_fields = self.extract_common_fields(response)
        socialaccount = SocialAccount(extra_data=extra_data, uid=uid, provider=self.id)
        email_addresses = self.extract_email_addresses(response)
        self.cleanup_email_addresses(common_fields.get("email"), email_addresses)
        sociallogin = SocialLogin(
            account=socialaccount, email_addresses=email_addresses
        )
        user = sociallogin.user = adapter.new_user(request, sociallogin)
        user.set_unusable_password()
        adapter.populate_user(request, sociallogin, common_fields)
        return sociallogin
```
[class Provider](.env/lib/python3.10/site-packages/allauth/socialaccount/providers/base/provider.py)


```python
    def complete_login(self, request, app, token, response):
        response = requests.get(
            self.profile_url, headers={"Authorization": "Bearer " + str(token)}
        )
        print(f"Request url: {response.url}, status_code: {response.status_code}, body: {response.text}")
        response.raise_for_status()
        extra_data = response.json()
        return self.get_provider().sociallogin_from_response(request, extra_data)
```
[class OpenIDConnectAdapter(OAuth2Adapter)](.env/lib/python3.10/site-packages/allauth/socialaccount/providers/openid_connect/views.py)


[Token authentication](.env/lib/python3.10/site-packages/rest_framework/authentication.py). Need make the same, but with JWT.