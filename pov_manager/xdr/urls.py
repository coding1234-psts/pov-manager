from django.urls import path

from . import views


urlpatterns = [
    path('dashboard/', views.xdr_dashboard, name='xdr-dashboard'),
    path('xdr-list', views.list_tenants, name='xdr-list'),
    path('tenants/actions/', views.xdr_post, name='xdr-tenants-submitted-actions'),
    path('tenant/<int:tenant_id>/', views.tenant_details, name='xdr_tenant_details'),
]
