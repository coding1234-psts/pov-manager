from django.urls import path
from django.views.generic.base import TemplateView
from django.contrib.auth import views as auth_views
from django.conf import settings

from . import views


# Determine login view dynamically
login_view = (
    TemplateView.as_view(template_name='core/login_with_microsoft.html')
    if settings.MICROSOFT_AUTH_ENABLED
    else auth_views.LoginView.as_view(template_name='core/login.html')
)

urlpatterns = [
    path('', views.index, name='index'),
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),
    path('login/', login_view, name='login'),
]
