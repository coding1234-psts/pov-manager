from django.conf import settings
from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.cursor import Cursor
from pymongo.database import Database
from pymongo.typings import _DocumentType
from typing import Any, Dict, List, Optional


class MongoDB:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(MongoDB, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if not hasattr(self, '_initialized'):
            self.client = MongoClient(host=settings.MONGO_HOST,
                                      port=settings.MONGO_PORT,
                                      username=settings.MONGO_USER,
                                      password=settings.MONGO_PASSWORD,
                                      authSource=settings.MONGO_DB_NAME)
            self.db: Database = self.client[settings.MONGO_DB_NAME]
            self._initialized = True

    def get_collection(self, collection_name: str) -> Collection:
        return self.db[collection_name]

    def insert_document(self, collection_name: str, document: Dict[str, Any]) -> Any:
        collection = self.get_collection(collection_name)
        result = collection.insert_one(document)
        return result.inserted_id

    def insert_documents(self, collection_name: str, documents: List[Dict[str, Any]]) -> Any:
        collection = self.get_collection(collection_name)
        result = collection.insert_many(documents)
        return result.inserted_ids

    def find_one(self, collection_name: str, query: Dict[str, Any]) -> Optional[_DocumentType]:
        collection = self.get_collection(collection_name)
        return collection.find_one(query)

    def find_documents(self, collection_name: str,
                       query: Dict[str, Any],
                       sort: Dict[str, Any] | None = None) -> Optional[Cursor[_DocumentType]]:
        collection = self.get_collection(collection_name)
        if sort:
            return collection.find(query).sort(sort)
        else:
            return collection.find(query)

    def find_documents_paginated(self, collection_name: str,
                                 query: Dict[str, Any],
                                 sort: Dict[str, Any],
                                 page: int,
                                 page_size: int) -> Optional[Cursor[_DocumentType]]:
        collection = self.get_collection(collection_name)
        return collection.find(query).sort(sort).skip((page - 1) * page_size).limit(page_size)

    def update_document(self, collection_name: str, query: Dict[str, Any], update: Dict[str, Any],
                        upsert: bool = False) -> Any:
        collection = self.get_collection(collection_name)
        result = collection.update_one(query, {'$set': update}, upsert=upsert)
        return result.modified_count

    def count_documents(self, collection_name: str, query: Dict[str, Any]) -> int:
        collection = self.get_collection(collection_name)
        return collection.count_documents(query)
