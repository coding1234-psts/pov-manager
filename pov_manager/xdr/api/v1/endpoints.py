import json
from django.conf import settings
from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseNotFound
from django.views.decorators.http import require_POST
from django.contrib.auth.decorators import login_required
from taegis_sdk_python.services import GraphQLService
from taegis_sdk_python.services.tenants.queries import TenantsQuery

from pov_manager.common import get_access_token
from xdr.views import garbage_collect_tenant

from pprint import pprint as pp


def get_tenant(tenant_id):
    tenant = None
    service = GraphQLService()
    access_token = get_access_token(xdr_region=settings.XDR_DEFAULT_REGION, aws_region='us-east-1')

    with service(access_token=access_token, environment=settings.XDR_DEFAULT_REGION):
        result = service.tenants.query.tenants(tenants_query=TenantsQuery(
            max_results=1,
            ids=[str(tenant_id)]
        ))
        if result.total_count == 1:
            tenant = result.results[0]

    return tenant


@login_required
@require_POST
def gc_tenant(request):
    data = json.loads(request.body.decode("utf-8"))
    tenant_id = data.get('tenant_id')

    if tenant_id:
        if get_tenant(tenant_id):
            garbage_collect_tenant(tenant_id)

        return HttpResponse(tenant_id)

    return HttpResponseBadRequest
