from django.db import models
from django.utils.translation import gettext_lazy as _
import allauth.app_settings as allauth_app_settings
import allauth.socialaccount.providers as providers



# Create your models here.
class ClientAccount(models.Model):
    user = models.ForeignKey(allauth_app_settings.USER_MODEL, on_delete=models.CASCADE)
    provider = models.CharField(
        verbose_name=_("provider"),
        max_length=30,
        choices=providers.registry.as_choices(),
    )

    client_id = models.CharField(
        verbose_name=_("client_id"), max_length=191
    )
    last_login = models.DateTimeField(verbose_name=_("last login"), auto_now=True)
    date_joined = models.DateTimeField(verbose_name=_("date joined"), auto_now_add=True)

    class Meta:
        unique_together = ("provider", "client_id")
        verbose_name = _("client account")
        verbose_name_plural = _("client accounts")
