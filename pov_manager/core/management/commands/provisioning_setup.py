import json
import os

from django.conf import settings
from django.core.management.base import BaseCommand

from pov_manager.mongo_db import MongoDB
from django.contrib.sites.models import Site


class Command(BaseCommand):
    help = 'For local development run provisioning setup to insert data'

    def update_default_site(self):
        site = Site.objects.first()
        site.name = 'localhost'
        site.domain = 'localhost'
        site.save()
        self.stdout.write(self.style.SUCCESS('Updated to default site to localhost'))

    def insert_mock_tenants_data(self):
        mongo = MongoDB()

        script_dir = os.path.dirname(os.path.abspath(__file__))
        json_path = os.path.join(script_dir, 'mock_tenants_data.json')

        with open(json_path, 'r') as file:
            documents = json.load(file)

        result = mongo.insert_documents(
            collection_name=settings.CACHE_TENANTS_DATA_COLLECTION_NAME,
            documents=documents
        )
        self.stdout.write(self.style.SUCCESS(f'Successfully inserted {len(result)} documents for tenants data'))

    def insert_mock_tenants_stats(self):
        mongo = MongoDB()

        script_dir = os.path.dirname(os.path.abspath(__file__))
        json_path = os.path.join(script_dir, 'mock_tenants_stats.json')

        with open(json_path, 'r') as file:
            document = json.load(file)

        result = mongo.insert_document(
            collection_name=settings.CACHE_TENANTS_STATS_COLLECTION_NAME,
            document=document
        )
        self.stdout.write(self.style.SUCCESS(f'Successfully inserted document for tenants stats'))

    def handle(self, *args, **kwargs) -> None:
        self.update_default_site()
        self.insert_mock_tenants_data()
        self.insert_mock_tenants_stats()

        self.stdout.write(self.style.SUCCESS(f'Provisioning setup completed'))
