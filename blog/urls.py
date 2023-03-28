"""blog URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import include, path
from rest_framework import routers
from blog.engine import views
from blog.engine.iam import (
    keycloak_login,
    keycloak_callback,
    keycloak_callback_redirect_home,
    KeycloakLogin,
    keycloak_login_jwt,
    SocialLoginViewJWT,
    ClientRegisterView
    )


from django.contrib import admin

router = routers.DefaultRouter()
router.register(r'users', views.UserViewSet)
router.register(r'groups', views.GroupViewSet)

# Wire up our API using automatic URL routing.
# Additionally, we include login URLs for the browsable API.
urlpatterns = [
    path('', include(router.urls)),
    # path('api-auth/', include('rest_framework.urls', namespace='rest_framework')),
    path('dj-rest-auth/', include('dj_rest_auth.urls')),
    path('dj-rest-auth/registration/', include('dj_rest_auth.registration.urls')),
    # path('dj-rest-auth/keycloak/', KeycloakLogin.as_view(), name='kc_login'),
    path('auth/login', keycloak_login, name="keycloak_login"),
    path('auth/login_jwt', keycloak_login_jwt, name="keycloak_login_jwt"),
    path('auth/callback', keycloak_callback_redirect_home, name="keycloak_callback"),
    path('auth/token', KeycloakLogin.as_view(), name="keycloak_token"),
    path('auth/token_jwt', SocialLoginViewJWT.as_view(), name="keycloak_token_jwt"),
    path('auth/register-client', ClientRegisterView.as_view(), name="register_client"),
    path('home/', views.home, name='home'),
    path('cvat/', views.cvat, name='cvat'),
    path('admin/', admin.site.urls, name='admin'),
]
