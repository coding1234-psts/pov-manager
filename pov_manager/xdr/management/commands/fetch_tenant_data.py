import pytz
from dataclasses import asdict
from datetime import datetime
from dateutil import parser
from django.conf import settings
from django.core.management.base import BaseCommand
from pov_manager.common import get_access_token
from pov_manager.mongo_db import MongoDB
from taegis_sdk_python.services import GraphQLService
from taegis_sdk_python.services.tenants.queries import TenantsQuery


class Command(BaseCommand):
    help = 'Fetch data from an Taegis API and save it to the database'

    def handle(self, *args, **kwargs):
        service = GraphQLService()
        access_token = get_access_token(xdr_region=settings.XDR_DEFAULT_REGION, aws_region='us-east-1')

        mongo = MongoDB()

        with service(access_token=access_token, environment=settings.XDR_DEFAULT_REGION):
            cursor_pos = None

            while True:
                results = service.tenants.query.tenants(tenants_query=TenantsQuery(max_results=50, cursor_pos=cursor_pos))

                # Modeling data
                for tenant in results.results:
                    tenant = asdict(tenant)

                    # Type tenant ID to int
                    tenant['id'] = int(tenant['id'])

                    # Calculate the age
                    created_at = parser.parse(tenant['created_at'])
                    tenant['age'] = (datetime.now(pytz.utc) - created_at).days

                    # Calculate remaining days
                    if tenant['expires_at']:
                        expires_at = parser.parse(tenant['expires_at'])
                        remaining_days = (expires_at - datetime.now(pytz.utc)).days

                        if remaining_days > 0:
                            tenant['remaining_days'] = remaining_days

                    # Set status per each environment
                    tenant['enabled_on_prod'] = False
                    tenant['enabled_on_delta'] = False
                    tenant['enabled_on_echo'] = False
                    tenant['enabled_on_foxtrot'] = False

                    for e in tenant['environments']:
                        if e['name'].lower() == 'production' and e['enabled']:
                            tenant['enabled_on_prod'] = True
                        elif e['name'].lower() == 'delta' and e['enabled']:
                            tenant['enabled_on_delta'] = True
                        elif e['name'].lower() == 'echo' and e['enabled']:
                            tenant['enabled_on_echo'] = True
                        elif e['name'].lower() == 'foxtrot' and e['enabled']:
                            tenant['enabled_on_foxtrot'] = True

                    # Upsert document
                    mongo.update_document(collection_name=settings.CACHE_TENANTS_DATA_COLLECTION_NAME,
                                          query={'id': tenant['id']},
                                          update=tenant,
                                          upsert=True)

                if not results.has_more:
                    break
                else:
                    cursor_pos = results.cursor_pos

        self.stdout.write(self.style.SUCCESS('Successfully fetched and saved data'))
