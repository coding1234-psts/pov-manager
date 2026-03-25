from django.urls import path
from .endpoints import gc_tenant


urlpatterns = [
    path('tenant/gc/', gc_tenant, name='api-v1-run-tenant-gc'),
]
