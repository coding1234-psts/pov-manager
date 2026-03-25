import pytz
import re
import requests
from pov_manager.common import get_access_token
from datetime import datetime
from dateutil import parser
from django.conf import settings
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.views.decorators.http import require_POST
from django.http import Http404
from pov_manager.mongo_db import MongoDB
from operator import itemgetter
from orchestrator.models import AdvancedSearch
from taegis_sdk_python.services import GraphQLService
from taegis_sdk_python.services.queries.types import (CreateSavedQLQueryInput,
                                                      CreateSavedQLQuery)
from taegis_sdk_python.services.tenants.queries import (TenantsQuery,
                                                        TenantEnvironmentFilter,
                                                        TenantOrderField,
                                                        OrderDir)
from taegis_sdk_python.services.alerts.types import SearchRequestInput
from taegis_sdk_python.services.tenants.types import InputTenantLabel


GC_SUBSCRIPTIONS_TO_BE_REVOKED = [
    'ASK AN EXPERT',
    'DATA RETENTION: 12 MO',
    'JAPAN',
    'JPN CHAT',
    'XDR POV'
]


GC_SUBSCRIPTIONS_TO_BE_ASSIGNED = {
    # Subscription name capitalized: Subscription ID
    'DATA RETENTION: 1 MO': 'f3a547e2-c08f-4847-b672-34334e7bb348',
    'DISABLED': '1fc0b64b-2534-4b6c-8fc7-7599a2300524'
}


@login_required
def xdr_dashboard(request):
    mongo = MongoDB()
    stats_doc = mongo.find_documents(collection_name='stats_tenants', query={})
    stats = stats_doc[0]

    return render(request,
                  template_name='xdr/dashboard.html',
                  context={'title': 'XDR Dashboard',
                           'location': 'xdr-dashboard',
                           'total_xdr_pov_tenants': stats['total_xdr_pov_tenants'],
                           'total_mxdr_pov_tenants': stats['total_mxdr_pov_tenants'],
                           'total_mxdr_elite_pov_tenants': stats['total_mxdr_elite_pov_tenants'],
                           'total_jitlab_tenants': stats['total_jitlab_tenants']
                           }
                  )


def get_filtered_tenants(tenants_query_args):
    service = GraphQLService()

    access_token = get_access_token(xdr_region=settings.XDR_DEFAULT_REGION, aws_region='us-east-1')

    with service(access_token=access_token, environment=settings.XDR_DEFAULT_REGION):
        results = service.tenants.query.tenants(tenants_query=TenantsQuery(**tenants_query_args))

    tenants = []
    count_tenants = results.total_count

    for tenant_obj in results.results:
        created_at = parser.parse(tenant_obj.created_at)
        age = (datetime.now(pytz.utc) - created_at).days

        expires_at = None
        remaining_days = None
        if tenant_obj.expires_at:
            expires_at = parser.parse(tenant_obj.expires_at)
            remaining_days = (expires_at - datetime.now(pytz.utc)).days
            expires_at = expires_at.strftime("%Y-%m-%d")

        # Environments
        prod_env = False
        delta_env = False
        echo_env = False
        foxtrot_env = False

        for e in tenant_obj.environments:
            if e.name.lower() == 'production' and e.enabled:
                prod_env = True
            elif e.name.lower() == 'delta' and e.enabled:
                delta_env = True
            elif e.name.lower() == 'echo' and e.enabled:
                echo_env = True
            elif e.name.lower() == 'foxtrot' and e.enabled:
                foxtrot_env = True

        tenant_data = {'id': tenant_obj.id,
                       'name': tenant_obj.name,
                       'age': age,
                       'expires_at': expires_at,
                       'remaining_days': remaining_days,
                       'services': tenant_obj.granted_services,
                       'labels': tenant_obj.labels,
                       'prod_env': prod_env,
                       'delta_env': delta_env,
                       'echo_env': echo_env,
                       'foxtrot_env': foxtrot_env
                       }

        tenant_data['gc'], _ = valid_for_gc(tenant_data)
        tenants.append(tenant_data)

    return tenants, count_tenants


@login_required
@require_POST
def xdr_post(request):
    if request.POST.get('action') == 'garbage_collect' and request.POST.getlist('selected_tenant'):
        selected_tenants = request.POST.getlist('selected_tenant')

        tenants, count_tenants = get_filtered_tenants({
            "ids": selected_tenants,
            "max_results": 50,
            "order_by": TenantOrderField('CreatedAt'),
            "order_dir": OrderDir('desc')
        })

        valid_gb_tenants = []
        invalid_gb_tenants = []

        for tenant in tenants:
            valid, errors = valid_for_gc(tenant)
            if valid:
                valid_gb_tenants.append(tenant)
            else:
                tenant['gb_errors'] = errors
                invalid_gb_tenants.append(tenant)

        return render(request, 'xdr/confirm_action_tenants.html', {'title': 'XDR - Confirm action',
                                                                   'valid_gb_tenants': valid_gb_tenants,
                                                                   'invalid_gb_tenants': invalid_gb_tenants})


@login_required
def list_tenants(request):
    # Get query parameters:
    search_id = request.GET.get('search_id', None)
    search_name = request.GET.get('search_name', None)

    filter_tenant_type = request.GET.get('ttype', None)
    filter_environment = request.GET.get('environment', None)

    sort_field = request.GET.get('sort', 'created_at')  # Default sort by created date
    sort_order = int(request.GET.get('order', '-1'))  # Default sort order descending

    page = int(request.GET.get('page', '1'))
    page_size = int(request.GET.get('page_size', '50'))

    # Build MongoDB query
    query = {}
    if search_id:
        query['id'] = search_id

    if search_name:
        query['name'] = re.compile(search_name, re.IGNORECASE)

    location = 'xdr-list'
    if filter_tenant_type:
        location = filter_tenant_type.lower()
        if location == 'jitlab':
            query['labels.name'] = 'jitlab'
            query['labels.value'] = 'true'
        elif location == 'pov':
            query['all_services.name'] = 'XDR POC'
        elif location == 'mxdrpov':
            query['all_services.name'] = 'MXDR PoC'
        elif location == 'mxdrelitepov':
            query['all_services.name'] = 'MXDR Elite PoC'
        elif location == 'ssdt':
            query['labels.name'] = 'ssdt'
            query['labels.value'] = 'demo'

    if filter_environment:
        query['enabled_on_' + filter_environment] = True

    mongo = MongoDB()

    # Count total documents matching the query for pagination
    total_documents = mongo.count_documents(collection_name='tenants', query=query)

    # Execute MongoDB query with sorting and pagination
    tenants = mongo.find_documents_paginated(collection_name='tenants',
                                             query=query,
                                             sort={sort_field: sort_order},
                                             page=page,
                                             page_size=page_size)

    # Prepare tenant data
    tenants_list = list(tenants)

    for tenant in tenants_list:
        if tenant['expires_at']:
            expires_at = parser.parse(tenant['expires_at'])
            tenant['expires_at'] = expires_at.strftime("%Y-%m-%d")

    # Prepare response data
    total_pages = (total_documents + page_size - 1) // page_size  # Calculate total pages

    response_data = {
        # Page info
        'title': 'XDR Tenants',
        'location': location,

        # List
        'tenants': tenants_list,
        'search_id': search_id,
        'search_name': search_name,
        'sort': sort_field,
        'order': sort_order,
        'ttype': filter_tenant_type,
        'environment': filter_environment,

        # Pagination
        'total_pages':  total_pages,
        'current_page': page,
        'has_previous': page > 1,
        'has_next': page < total_pages
    }

    return render(request=request, template_name='xdr/xdr.html', context=response_data)


@login_required
def xdr(request):
    location = 'xdr'
    tenants_query_args = {
        'max_results': 50,
    }

    # --- Pagination ---- #
    # pages = request.GET.get('pages', '0')
    # pages = pages.split(',')
    # requested_page = int(request.GET.get('page', 0))

    # --- Search ---- #
    search_by_id = request.GET.get('search_by_id', '')
    search_by_name = request.GET.get('search_by_name', '')

    if search_by_id:
        search_by_id = search_by_id.strip()
        tenants_query_args['ids'] = [search_by_id]

    if search_by_name:
        search_by_name_value = search_by_name.strip()
        tenants_query_args['name'] = f"%{search_by_name_value}%"

    # --- Filters ---- #
    filter_env_enabled = request.GET.get('filter_env_enabled')

    if filter_env_enabled:
        tenants_query_args['environment_filter'] = TenantEnvironmentFilter(name=filter_env_enabled, enabled=True)

    # --- Sort ---- #
    sorted_by_gc = False
    gc_reverse_sort = False

    sort_by = request.GET.get('sort_by', 'CreatedAt')
    sort_dir = request.GET.get('sort_dir', 'desc')

    if sort_by == 'gc':
        sorted_by_gc = True
        gc_reverse_sort = True if sort_dir == 'asc' else False
        location = 'pov'
    else:
        tenants_query_args['order_by'] = TenantOrderField(sort_by)
        tenants_query_args['order_dir'] = OrderDir(sort_dir)

    # Rewrite filters for custom tenant types
    # if request.GET.get('ttype') and request.GET.get('ttype') in XDR_TENANTS_TYPES:
    #     location = request.GET.get('ttype').lower()
    #     tenants_query_args.update(XDR_TENANTS_TYPES[location])

        # Let's verify that we are really on the XDR PoV page or Jitlab page
        if sorted_by_gc and location not in ['pov', 'jitlab']:
            sorted_by_gc = False

    # if requested_page > 0:
    #     tenants_query_args['cursor_pos'] = pages[requested_page]

    service = GraphQLService()
    access_token = get_access_token(xdr_region=settings.XDR_DEFAULT_REGION, aws_region='us-east-1')

    with service(access_token=access_token, environment=settings.XDR_DEFAULT_REGION):
        results = service.tenants.query.tenants(tenants_query=TenantsQuery(**tenants_query_args))

    tenants = []
    # count_tenants = results.total_count
    #
    # if results.has_more:
    #     pages.append(results.cursor_pos)

    # prev_page = None
    # next_page = None
    # query_params = {k: v for k, v in request.GET.items() if v is not None and v not in ['pages', 'page']}
    #
    # if requested_page > 0:
    #     prev_page = f"?pages={','.join(pages)}&page={requested_page - 1}"
    #     if query_params:
    #         prev_page = f"{prev_page}&{parse.urlencode(query_params)}"
    #
    # if (requested_page >= 0) and (requested_page < (len(pages) - 1)):
    #     next_page = f"?pages={','.join(pages)}&page={requested_page + 1}"
    #     if query_params:
    #         next_page = f"{next_page}&{parse.urlencode(query_params)}"

    for tenant_obj in results.results:
        created_at = parser.parse(tenant_obj.created_at)
        age = (datetime.now(pytz.utc) - created_at).days

        expires_at = None
        remaining_days = None
        if tenant_obj.expires_at:
            expires_at = parser.parse(tenant_obj.expires_at)
            remaining_days = (expires_at - datetime.now(pytz.utc)).days
            expires_at = expires_at.strftime("%Y-%m-%d")

        # Environments
        prod_env = False
        delta_env = False
        echo_env = False
        foxtrot_env = False

        for e in tenant_obj.environments:
            if e.name.lower() == 'production' and e.enabled:
                prod_env = True
            elif e.name.lower() == 'delta' and e.enabled:
                delta_env = True
            elif e.name.lower() == 'echo' and e.enabled:
                echo_env = True
            elif e.name.lower() == 'foxtrot' and e.enabled:
                foxtrot_env = True

        tenant_data = {'id': tenant_obj.id,
                       'name': tenant_obj.name,
                       'age': age,
                       'expires_at': expires_at,
                       'remaining_days': remaining_days,
                       'labels': tenant_obj.labels,
                       'services': tenant_obj.granted_services,
                       'prod_env': prod_env,
                       'delta_env': delta_env,
                       'echo_env': echo_env,
                       'foxtrot_env': foxtrot_env
                       }
        tenant_data['gc'], _ = valid_for_gc(tenant_data)
        tenants.append(tenant_data)

    if sorted_by_gc:
        tenants = sorted(tenants, key=itemgetter('gc'), reverse=gc_reverse_sort)

    # return render(request, 'xdr/xdr.html', {'title': 'XDR Tenants',
    #                                         'location': location,
    #                                         'count_tenants': count_tenants,
    #                                         'pages': str(pages),
    #                                         'prev_page': prev_page,
    #                                         'current_page': requested_page + 1,
    #                                         'next_page': next_page,
    #                                         'tenants': tenants,
    #                                         'search': {
    #                                             'id': search_by_id,
    #                                             'name': search_by_name
    #                                         },
    #                                         'filter_env_enabled': filter_env_enabled,
    #                                         'sort': {
    #                                             'by': sort_by,
    #                                             'dir': sort_dir
    #                                         }})
    return


@login_required()
def tenant_details(request, tenant_id: int):
    if not tenant_id:
        return Http404

    mongo = MongoDB()

    tenant = mongo.find_one(collection_name='tenants', query={'id': tenant_id})

    created_at = parser.parse(tenant['created_at'])
    created_at = created_at.strftime("%Y-%m-%d")

    expires_at = None
    if tenant['expires_at']:
        expires_at = parser.parse(tenant['expires_at'])
        expires_at = expires_at.strftime("%Y-%m-%d")

    updated_at = parser.parse(tenant['updated_at'])
    updated_at = updated_at.strftime("%Y-%m-%d")

    # labels = [{'id': label.id, 'name': label.name, 'value': label.value} for
    #           label in tenant['labels']]

    # attached_services = [{'name': service['name'], 'description': service.description} for service in
    #                      tenant['granted_services']] if tenant['granted_services'] else None

    # Alerts
    alerts = []
    if tenant['enabled_on_delta']:

        access_token = get_access_token(xdr_region=settings.XDR_DEFAULT_REGION, aws_region='us-east-1')
        service = GraphQLService()

        with service(
                access_token=access_token,
                environment=settings.XDR_DEFAULT_REGION,
                tenant_id=str(tenant_id),
                output="alerts { list { id tenant_id metadata { title } } }"
        ):
            try:
                results = service.alerts.query.alerts_service_search(SearchRequestInput(
                    cql_query="FROM alert EARLIEST=-1d",
                    offset=0,
                    limit=10,
                ))
            except Exception as e:
                print('Exception on tenant_details', e)
            else:
                if len(results.alerts.list):
                    for alert in results.alerts.list:
                        created_at = None
                        first_seen_at = None

                        if alert.metadata.created_at:
                            created_at = parser.parse(alert.metadata.created_at)
                            created_at = created_at.strftime("%Y-%m-%d")

                        if alert.metadata.first_seen_at:
                            first_seen_at = parser.parse(alert.metadata.first_seen_at)
                            first_seen_at = first_seen_at.strftime("%Y-%m-%d")

                        alerts.append({
                            'name': alert.metadata.title,
                            'created_at': created_at,
                            'first_seen_at': first_seen_at,
                            'description': alert.metadata.description
                        })

    # Handle advanced search section
    advanced_searches = AdvancedSearch.objects.all()

    # Pagination
    per_page = int(request.GET.get('per_page', 10))
    paginator = Paginator(advanced_searches, per_page)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    if request.method == 'POST':
        selected_searches = request.POST.getlist('selected_searches')
        tenant_id = request.POST.get('tenant_id')

        if selected_searches:
            mongo = MongoDB()

            # Process selected searches
            searches = AdvancedSearch.objects.filter(id__in=advanced_searches)
            for search in searches:
                # Get tenant XDR region
                tenant = mongo.find_one(collection_name='tenants', query={'id': int(tenant_id)})

                xdr_region = None
                if tenant['enabled_in_production']:
                    xdr_region = 'charlie'
                elif tenant['enabled_on_delta']:
                    xdr_region = 'delta'
                elif tenant['enabled_on_echo']:
                    xdr_region = 'echo'
                elif tenant['enabled_on_foxtrot']:
                    xdr_region = 'foxtrot'

                push_advanced_search_query_to_xdr(tenants=[str(tenant_id)],
                                                  advanced_search=search,
                                                  xdr_region=xdr_region)

            return redirect('xdr_tenant_details', tenant_id=tenant_id)

    return render(request, 'xdr/tenant.html', {
        'tenant': tenant,
        'title': tenant['name'],
        'name': tenant['name'],
        'created_at': created_at,
        'age': tenant.get('age', None),
        'expires_at': expires_at,
        'remaining_days': tenant.get('remaining_days', None),
        'updated_at': updated_at,
        'support': tenant['support_enabled'],
        'alerts': alerts,

        # Advanced search section
        'advanced_searches': page_obj,
        'per_page': per_page
    })


# Garbage collector
def revoke_subscriptions_from_tenant(tenant_id: str, subscription_ids: list[str]):
    """
    In Taegis service labels are mapped as Subscriptions.
    This functions removes all the subscriptions from a tenant.

    The Service Label ID is the Subscription ID not the Service Label received when
    tenant details are returned

    :param str tenant_id:
    :param list[str] subscription_ids:
    :return: True/False
    """
    if not all([tenant_id, subscription_ids]):
        return False

    service = GraphQLService()
    access_token = get_access_token(xdr_region=settings.XDR_DEFAULT_REGION, aws_region='us-east-1')

    with service(access_token=access_token, environment=settings.XDR_DEFAULT_REGION):
        for slid in subscription_ids:
            service.tenants.mutation.unassign_subscription(tenant_id=tenant_id,
                                                           subscription_id=slid)
    return True


def assign_subscriptions_to_tenant(tenant_id: str, subscription_ids: list[str]):
    if not all([tenant_id, subscription_ids]):
        return False

    service = GraphQLService()
    access_token = get_access_token(xdr_region=settings.XDR_DEFAULT_REGION, aws_region='us-east-1')

    with service(access_token=access_token, environment=settings.XDR_DEFAULT_REGION):
        for sid in subscription_ids:
            service.tenants.mutation.assign_subscription(tenant_id=tenant_id,
                                                         subscription_id=sid)
    return True


def gc_updated_tenant_service_labels(tenant_id):
    access_token = get_access_token(xdr_region=settings.XDR_DEFAULT_REGION, aws_region='us-east-1')
    service = GraphQLService()

    with service(access_token=access_token, environment=settings.XDR_DEFAULT_REGION):
        results = service.tenants.query.tenants(tenants_query=TenantsQuery(ids=[str(tenant_id)]))

    tenant = results.results[0]
    assigned_subscriptions = tenant.granted_services
    subscription_ids_to_be_revoked = []

    subscription_names_to_be_assigned = GC_SUBSCRIPTIONS_TO_BE_ASSIGNED.keys()
    subscription_ids_to_be_assigned = list(GC_SUBSCRIPTIONS_TO_BE_ASSIGNED.values())

    # Revoke unwanted subscriptions (service labels)
    for subscription in assigned_subscriptions:
        subscription_name = subscription.name.upper()

        if subscription_name in GC_SUBSCRIPTIONS_TO_BE_REVOKED:
            subscription_ids_to_be_revoked.append(subscription.service_id)

        if subscription_name in subscription_names_to_be_assigned:
            subscription_ids_to_be_assigned.remove(GC_SUBSCRIPTIONS_TO_BE_ASSIGNED[subscription_name])

    revoke_subscriptions_from_tenant(tenant_id=tenant_id, subscription_ids=subscription_ids_to_be_revoked)
    assign_subscriptions_to_tenant(tenant_id=tenant_id, subscription_ids=subscription_ids_to_be_assigned)


def has_disabled_service_label(services) -> bool:
    if services:
        for service in services:
            if service.name.lower() == 'disabled':
                return True
    return False


def expired_for(days, expire_date):
    if expire_date:
        expire_date = datetime.strptime(expire_date, "%Y-%m-%d")
        expire_date = expire_date.replace(tzinfo=pytz.utc)
        return abs((expire_date - datetime.now(pytz.utc)).days) > int(days)
    return 0


def is_xdr_pov(services) -> bool:
    if services:
        for service in services:
            if service.name.lower() == 'xdr pov':
                return True
    return False


def is_jitlab(labels) -> bool:
    if labels:
        for label in labels:
            if label.name.lower() == 'jitlab' and label.value.lower() == 'true':
                return True
    return False


def isensor_service_enabled(services) -> bool:
    if services:
        for service in services:
            if 'isensor' in service.name.lower():
                return True
    return False


def gc_tenant_type(tenant) -> bool:
    """
    Checks if the type of the tenant is allowed to be garbage collected.
    Currently only PoV and JiTLab tenants are allowed.

    :param tenant:
    :return: bool
    """
    if is_xdr_pov(tenant['services']):
        return True
    elif is_jitlab(tenant['labels']):
        return True
    return False


def valid_for_gc(tenant):
    errors = []

    if not gc_tenant_type(tenant):
        errors.append('Tenant not allowed to run through GB. Only PoV and JiTLab tenants are allowed.')

    if has_disabled_service_label(services=tenant['services']):
        errors.append('Tenant is disabled.')

    if not expired_for(days=60, expire_date=tenant['expires_at']):
        errors.append('Tenant expiry date is not longer than 60 days.')

    if not any([tenant['prod_env'], tenant['delta_env'], tenant['echo_env'], tenant['foxtrot_env']]):
        errors.append('Tenant not enabled in production, delta, echo or foxtrot.')

    if isensor_service_enabled(services=tenant['services']):
        errors.append('Tenant has the iSensor service enabled.')

    return not bool(errors), errors


def garbage_collect_tenant(tid):
    """
    This is the function that garbage collect a tenant.

    :param tid: Tenant ID
    :return:
    """
    url = 'https://api-tenants.delta.taegis.secureworks.com/public/query'
    service = GraphQLService()
    access_token = get_access_token(xdr_region=settings.XDR_DEFAULT_REGION, aws_region='us-east-1')

    with service(access_token=access_token, environment=settings.XDR_DEFAULT_REGION):
        headers = {
            'Accept': 'application/json',
            'Content-type': 'application/json',
            'Authorization': f'Bearer {service.access_token}',
            'X-Tenant-Context': str(tid)
        }

        query = """
        mutation updateTenant($tenantID: ID!, $updateInput: TenantUpdateInput!) {
            updateTenant (tenantID: $tenantID, tenantUpdate: $updateInput) {
                id
            }
        }
        """

        variables = {
            "tenantID": tid,
            "updateInput": {
                "clearExpiration": True,
                "disable": True
            }
        }

        requests.post(url=url, json={'query': query, 'variables': variables}, headers=headers, timeout=300)

        # Append labs_garbage_collector label
        service.tenants.mutation.create_tenant_label(tenant_id=tid, label_input=InputTenantLabel(
            name="labs_garbage_collector",
            value=datetime.utcnow().isoformat()[:-3] + 'Z'
        ))

        gc_updated_tenant_service_labels(str(tid))


def push_advanced_search_query_to_xdr(tenants: list[str],
                                      advanced_search: AdvancedSearch,
                                      xdr_region: str) -> None:
    """
    Push advanced search query to multiple tenants.
    The query will appear in Advanced search -> Saved Searches -> My Organization's

    :param tenants: List ot tenant IDs
    :param advanced_search:
    :param xdr_region:
    :return: None
    """
    service = GraphQLService()
    access_token = get_access_token(xdr_region=xdr_region, aws_region='us-east-1')

    create_saved_ql_query = CreateSavedQLQuery(name=advanced_search.name,
                                               raw_query=advanced_search.query,
                                               caller_name='advanced-search-editor')
    create_saved_ql_query_input = CreateSavedQLQueryInput(tenants=tenants,
                                                          ql_query=create_saved_ql_query)

    with service(access_token=access_token, environment=xdr_region):
        service.queries.mutation.create_saved_ql_query(create_saved_ql_query_input)
