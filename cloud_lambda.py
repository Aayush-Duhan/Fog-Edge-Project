import boto3
import json
from datetime import datetime
import logging
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """AWS Lambda function to handle fog node data"""
    try:
        logger.info(f"Received event: {event}")
        
        # Handle both direct invocation and API Gateway events
        if 'body' in event:
            # API Gateway event
            try:
                if isinstance(event['body'], str):
                    body = json.loads(event['body'])
                else:
                    body = event['body']
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse body: {e}")
                return {
                    'statusCode': 400,
                    'body': json.dumps({'error': f'Invalid JSON: {str(e)}'})
                }
        else:
            # Direct invocation
            body = event
            
        logger.info(f"Parsed body: {body}")
        
        # Validate required fields
        required_fields = ['fog_id', 'data']
        if not all(field in body for field in required_fields):
            missing = [f for f in required_fields if f not in body]
            return {
                'statusCode': 400,
                'body': json.dumps({
                    'error': 'Missing required fields',
                    'missing': missing
                })
            }
        
        # Initialize DynamoDB
        try:
            dynamodb = boto3.resource('dynamodb')
            table = dynamodb.Table('fog_data')
        except Exception as e:
            logger.error(f"Failed to initialize DynamoDB: {e}")
            raise
        
        # Process data
        timestamp = datetime.now().isoformat()
        data_items = body['data'] if isinstance(body['data'], list) else [body['data']]
        
        stored_items = []
        errors = []
        
        for item in data_items:
            try:
                db_item = {
                    'device_id': item['device_id'],
                    'timestamp': timestamp,
                    'fog_id': body['fog_id'],
                    'message': item['message'],
                    'processed_at': item['processed_at']
                }
                
                # Store in DynamoDB
                table.put_item(Item=db_item)
                stored_items.append(db_item)
                logger.info(f"Successfully stored item: {db_item}")
                
            except ClientError as e:
                error_msg = f"DynamoDB error: {e.response['Error']['Message']}"
                logger.error(error_msg)
                errors.append(error_msg)
            except KeyError as e:
                error_msg = f"Missing field in item: {e}"
                logger.error(error_msg)
                errors.append(error_msg)
            except Exception as e:
                error_msg = f"Unexpected error: {str(e)}"
                logger.error(error_msg)
                errors.append(error_msg)
        
        # Return response
        response_body = {
            'message': 'Data processed',
            'items_processed': len(stored_items),
            'items': stored_items,
            'errors': errors if errors else None
        }
        
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps(response_body)
        } if stored_items else {
            'statusCode': 500,
            'body': json.dumps({
                'error': 'Failed to store any items',
                'errors': errors
            })
        }
            
    except Exception as e:
        logger.error(f"Critical error: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': 'Internal server error',
                'details': str(e)
            })
        } 