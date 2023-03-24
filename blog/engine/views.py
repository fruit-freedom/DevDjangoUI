from django.contrib.auth.models import User, Group
from rest_framework import viewsets
from rest_framework import permissions
from blog.engine.serializers import UserSerializer, GroupSerializer

from django.http import JsonResponse, HttpResponse

class UserViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows users to be viewed or edited.
    """
    queryset = User.objects.all().order_by('-date_joined')
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]


class GroupViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    queryset = Group.objects.all()
    serializer_class = GroupSerializer
    permission_classes = [permissions.IsAuthenticated]

def cvat(request):
    return HttpResponse(
        """
            <html>
                <body>
                    <h1><a href="http://localhost:3000/api/auth/keycloak/login/">Login to CVAT using keycloak</a></h2>
                    <h1><a href="http://localhost:3000/api/projects?org=&page=1&page_size=12">Go to projects page</a></h2>
                    {}
                </body>
            </html>
        """.format(request.META.get('HTTP_COOKIE'))
    )

def home(request):
    return HttpResponse(f'<html><body><h1>Authorization code</h1><h2>{request.GET.get("code")}</h2></body></html>')
    return JsonResponse({
        'method': request.method,
        'path': request.path,
        'QueryDict': str(request.GET)
    })