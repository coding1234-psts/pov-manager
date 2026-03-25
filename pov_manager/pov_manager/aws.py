import boto3
import json
from botocore.exceptions import ClientError


def get_secrets(region_name: str, secret_name: str):
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )
    try:
        resp = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        raise e
    return json.loads(resp['SecretString'])
