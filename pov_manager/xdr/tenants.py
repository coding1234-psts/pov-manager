import boto3
import json
from core.taegis.client import XDR


def aws_lambda_client(region_name):
    aws = boto3.Session(region_name=region_name)
    return aws.client("lambda")


def xdr_get_bearer_token(aws_client, xdr_region, xdr_tenant_id):
    params = {"xdr_region": xdr_region, "xdr_tenant_id": xdr_tenant_id}

    login_result = aws_client.invoke(
        FunctionName="XDR_API_Login",
        InvocationType="RequestResponse",
        Payload=json.dumps(params)
    )
    # The response from a lambda invocation == dict ; contains "Payload" key, value is of type StreamingBody
    # Use the read() function to actually get the response of the called lambda function.
    result_payload = json.loads(login_result["Payload"].read())
    if 'bearer_token' in result_payload.keys():
        return result_payload['bearer_token']
    else:
        print(result_payload)
        raise NotImplementedError("Login function did not return result!")


def query_taegis_tentants(token_bearer, xdr_region, xdr_tenant_id):
    api = XDR(bearer_token=token_bearer, region=xdr_region, tenant_id=xdr_tenant_id)

    """
    Tenant ID
    Tenant Name
    Tenant Environment (region)
    Tenant Created
    Tenant Last Updated
    Tenant Expiry
    """

    query = '''
    query tenants{
        tenants (tenantsQuery: {
            maxResults: 100
        }) {
            count
            totalCount
            cursorPos
            results {
                id
                name
                created_at
                updated_at
                expires_at                
                labels {
                    id
                    name                    
                }
                environments {
                    name
                    enabled
                }
            }
        }
    }
    '''
    # variables = '{"tenantsQuery":{"maxResults":10}}}'
    tenants_info = api.execute_query(query, apipath="/public/query")
    return tenants_info
