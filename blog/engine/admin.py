from django.contrib import admin


from django.contrib.sessions.models import Session
from .models import ClientAccount

class SessionAdmin(admin.ModelAdmin):
    def _session_data(self, obj):
        return obj.get_decoded()
    list_display = ['session_key', '_session_data', 'expire_date']
admin.site.register(Session, SessionAdmin)


class ClientAccountAdmin(admin.ModelAdmin):
    list_display = ['client_id', 'user']
admin.site.register(ClientAccount, ClientAccountAdmin)
