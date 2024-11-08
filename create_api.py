import boto3
import json
import time

def create_api_gateway():
    client = boto3.client('apigateway')
    
    try:
        # Create API
        api = client.create_rest_api(
            name='FogDataAPI',
            description='API for fog data processing'
        )
        api_id = api['id']
        print(f"Created API: {api_id}")
        
        # Get the API's root resource ID
        resources = client.get_resources(restApiId=api_id)
        root_id = resources['items'][0]['id']
        
        # Create resource
        resource = client.create_resource(
            restApiId=api_id,
            parentId=root_id,
            pathPart='fog-data'
        )
        resource_id = resource['id']
        
        # Create POST method
        client.put_method(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod='POST',
            authorizationType='NONE',
            apiKeyRequired=True
        )
        
        # Create method response
        client.put_method_response(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod='POST',
            statusCode='200',
            responseParameters={
                'method.response.header.Access-Control-Allow-Origin': True
            }
        )
        
        # Set up Lambda integration
        lambda_client = boto3.client('lambda')
        lambda_function = lambda_client.get_function(FunctionName='FogDataProcessor')
        lambda_arn = lambda_function['Configuration']['FunctionArn']
        
        # Get AWS account ID
        sts_client = boto3.client('sts')
        account_id = sts_client.get_caller_identity()['Account']
        
        # Add Lambda permission
        try:
            lambda_client.add_permission(
                FunctionName='FogDataProcessor',
                StatementId='apigateway-fog-test',
                Action='lambda:InvokeFunction',
                Principal='apigateway.amazonaws.com',
                SourceArn=f'arn:aws:execute-api:{client.meta.region_name}:{account_id}:{api_id}/*'
            )
            print("Added Lambda permission successfully")
        except lambda_client.exceptions.ResourceConflictException:
            print("Lambda permission already exists")
        
        # Create integration
        integration_response = client.put_integration(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod='POST',
            type='AWS_PROXY',
            integrationHttpMethod='POST',
            uri=f'arn:aws:apigateway:{client.meta.region_name}:lambda:path/2015-03-31/functions/{lambda_arn}/invocations',
            integrationResponses=[
                {
                    'statusCode': '200',
                    'responseParameters': {
                        'method.response.header.Access-Control-Allow-Origin': "'*'"
                    }
                }
            ]
        )
        
        # Add binary support if needed
        client.update_rest_api(
            restApiId=api_id,
            patchOperations=[
                {
                    'op': 'replace',
                    'path': '/binaryMediaTypes/*~1*',
                    'value': '*/*'
                }
            ]
        )
        
        # Add OPTIONS method for CORS
        client.put_method(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod='OPTIONS',
            authorizationType='NONE'
        )
        
        # Add OPTIONS method response
        client.put_method_response(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod='OPTIONS',
            statusCode='200',
            responseParameters={
                'method.response.header.Access-Control-Allow-Headers': True,
                'method.response.header.Access-Control-Allow-Methods': True,
                'method.response.header.Access-Control-Allow-Origin': True
            }
        )
        
        # Add OPTIONS integration
        client.put_integration(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod='OPTIONS',
            type='MOCK',
            requestTemplates={
                'application/json': '{"statusCode": 200}'
            }
        )
        
        # Add OPTIONS integration response
        client.put_integration_response(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod='OPTIONS',
            statusCode='200',
            responseParameters={
                'method.response.header.Access-Control-Allow-Headers': "'Content-Type,X-Amz-Date,Authorization,X-Api-Key'",
                'method.response.header.Access-Control-Allow-Methods': "'POST,OPTIONS'",
                'method.response.header.Access-Control-Allow-Origin': "'*'"
            },
            responseTemplates={
                'application/json': ''
            }
        )
        
        # Create deployment
        deployment = client.create_deployment(
            restApiId=api_id,
            stageName='prod',
            stageDescription='Production Stage',
            description='Production Deployment'
        )
        
        # Create usage plan
        usage_plan = client.create_usage_plan(
            name='FogServerUsagePlan',
            description='Usage plan for fog server',
            apiStages=[
                {
                    'apiId': api_id,
                    'stage': 'prod'
                }
            ]
        )
        
        # Create API key
        api_key = client.create_api_key(
            name='FogServerKey',
            description='API key for fog server',
            enabled=True
        )
        
        # Add API key to usage plan
        client.create_usage_plan_key(
            usagePlanId=usage_plan['id'],
            keyId=api_key['id'],
            keyType='API_KEY'
        )
        
        # Get the API endpoint URL
        api_url = f"https://{api_id}.execute-api.{client.meta.region_name}.amazonaws.com/prod/fog-data"
        
        print("\nAPI Gateway Setup Complete!")
        print(f"API Endpoint: {api_url}")
        print(f"API Key ID: {api_key['id']}")
        
        # Get the actual API key value
        api_key_value = client.get_api_key(
            apiKey=api_key['id'],
            includeValue=True
        )['value']
        
        print(f"API Key: {api_key_value}")
        
        # Save the credentials to a file
        credentials = {
            'api_endpoint': api_url,
            'api_key': api_key_value
        }
        
        with open('cloud_credentials.json', 'w') as f:
            json.dump(credentials, f, indent=2)
        print("\nCredentials saved to cloud_credentials.json")
        
    except Exception as e:
        print(f"Error creating API Gateway: {str(e)}")
        raise

if __name__ == "__main__":
    create_api_gateway() 