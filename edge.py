import requests
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

# Load private key for signing
with open("edge_private_key.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(key_file.read(), password=None)

# Shared secret key for generating auth token
SHARED_SECRET_KEY = "supersecretkey123"

# Fetch current key ID and encryption key from the fog server
def fetch_current_key():
    print("Fetching the current encryption key from the fog server...")
    response = requests.get("http://localhost:5000/get-current-key")
    response_data = response.json()
    key_id = response_data["key_id"]
    encryption_key = response_data["encryption_key"]
    
    print(f"Step 1: Fetched Key ID: {key_id}")
    print(f"Step 2: Fetched Encryption Key: {encryption_key}")
    
    return key_id, encryption_key

# Encrypt, sign, and send message to the fog server
def send_message():
    print("Sending message to fog server...\n")
    
    # Fetch current key and key ID
    key_id, encryption_key = fetch_current_key()

    # Create a cipher suite with the fetched encryption key
    cipher_suite = Fernet(encryption_key.encode())

    # Generate the auth token by encoding the shared secret key
    auth_token = base64.urlsafe_b64encode(SHARED_SECRET_KEY.encode()).decode()
    print(f"Step 3: Generated Auth Token: {auth_token}")

    # Encrypt the message
    message = "Sensitive data from edge device"
    encrypted_message = cipher_suite.encrypt(message.encode()).decode()
    print(f"Step 4: Encrypted Message: {encrypted_message}")

    # Combine auth token and encrypted message
    combined_data = f"{auth_token}::{encrypted_message}"
    print(f"Step 5: Combined Data (Auth Token + Encrypted Message): {combined_data}")

    # Sign the combined data using the RSA private key
    signature = private_key.sign(
        combined_data.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Base64 encode the signature for transmission
    signature_base64 = base64.b64encode(signature).decode()
    print(f"Step 6: Generated Digital Signature: {signature_base64}")

    # Prepare the data to send, including the current key ID and the signature
    data = {
        "combined_data": combined_data,
        "key_id": key_id,
        "signature": signature_base64
    }

    # Send data to the fog server
    print("Step 7: Sending Data to Fog Server...\n")
    response = requests.post("http://localhost:5000/process-data", json=data)

    # Print the server's response
    print(f"Fog Server Response: {response.json()}")

# Simulate sending the message
send_message()
