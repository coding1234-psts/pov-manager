import boto3
import json


def get_access_token(xdr_region='delta', aws_region='us-east-1') -> str:
    client = boto3.client('lambda', region_name=aws_region)
    event = {"xdr_region": xdr_region, "xdr_tenant_id": 5000}
    response = client.invoke(
        FunctionName='XDR_API_Login',
        Payload=json.dumps(event),
    )

    payload = response['Payload'].read().decode("utf-8")
    payload = json.loads(payload)

    return payload['bearer_token']
