from django.conf import settings
from django.core.management.base import BaseCommand
from pov_manager.common import get_access_token
from pov_manager.mongo_db import MongoDB
from taegis_sdk_python.services import GraphQLService
from taegis_sdk_python.services.tenants.queries import TenantsQuery, TenantOrderField, OrderDir


class Command(BaseCommand):
    help = 'Fetch and calculate tenant statistics'

    def handle(self, *args, **kwargs):
        service = GraphQLService()
        access_token = get_access_token(xdr_region=settings.XDR_DEFAULT_REGION, aws_region='us-east-1')

        with service(access_token=access_token, environment=settings.XDR_DEFAULT_REGION):
            xdr_pov_service_results = service.tenants.query.tenants(tenants_query=TenantsQuery(
                max_results=50,
                with_service='XDR PoV',
                order_by=TenantOrderField('CreatedAt'),
                order_dir=OrderDir('desc')
            ))

            mxdr_pov_service_results = service.tenants.query.tenants(tenants_query=TenantsQuery(
                max_results=50,
                with_service='MXDR PoV',
                order_by=TenantOrderField('CreatedAt'),
                order_dir=OrderDir('desc')
            ))

            mxdr_elite_pov_service_results = service.tenants.query.tenants(tenants_query=TenantsQuery(
                max_results=50,
                with_service='MXDR Elite PoV',
                order_by=TenantOrderField('CreatedAt'),
                order_dir=OrderDir('desc')
            ))

            jitlab_results = service.tenants.query.tenants(tenants_query=TenantsQuery(
                max_results=50,
                name="%JITLab%",
                order_by=TenantOrderField('CreatedAt'),
                order_dir=OrderDir('desc')
            ))

        mongo = MongoDB()
        mongo.update_document(settings.CACHE_TENANTS_STATS_COLLECTION_NAME,  {}, {
            'total_xdr_pov_tenants': xdr_pov_service_results.total_count,
            'total_mxdr_pov_tenants': mxdr_pov_service_results.total_count,
            'total_mxdr_elite_pov_tenants': mxdr_elite_pov_service_results.total_count,
            'total_jitlab_tenants': jitlab_results.total_count
        })

        self.stdout.write(self.style.SUCCESS('Successfully fetched and saved data'))
