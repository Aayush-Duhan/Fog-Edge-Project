import requests
import json
from datetime import datetime

def test_api_gateway():
    # Load credentials
    with open('cloud_credentials.json', 'r') as f:
        credentials = json.load(f)
    
    api_url = credentials['api_endpoint']
    api_key = credentials['api_key']
    
    # Prepare test data
    test_data = {
        'fog_id': 'FOG_001',
        'data': [{
            'device_id': 'TEST_DEVICE',
            'message': 'API Gateway Test Message',
            'processed_at': datetime.now().isoformat()
        }]
    }
    
    # Set headers
    headers = {
        'x-api-key': api_key,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': 'none'
    }
    
    print("\n=== Testing API Gateway ===")
    print(f"\nEndpoint: {api_url}")
    print(f"\nHeaders:")
    for key, value in headers.items():
        print(f"{key}: {value}")
    
    print(f"\nRequest Data:")
    print(json.dumps(test_data, indent=2))
    
    try:
        print("\nSending request...")
        response = requests.post(
            api_url,
            json=test_data,
            headers=headers,
            verify=True  # Enable SSL verification
        )
        
        print(f"\nResponse Status: {response.status_code}")
        print(f"Response Headers: {dict(response.headers)}")
        print("\nResponse Body:")
        print(json.dumps(response.json(), indent=2))
        
        if response.status_code != 200:
            print("\nError Details:")
            try:
                error_details = response.json()
                print(json.dumps(error_details, indent=2))
            except:
                print(f"Raw response: {response.text}")
        
    except requests.exceptions.RequestException as e:
        print(f"\nRequest Error: {str(e)}")
    except Exception as e:
        print(f"\nUnexpected Error: {str(e)}")

if __name__ == "__main__":
    test_api_gateway() 