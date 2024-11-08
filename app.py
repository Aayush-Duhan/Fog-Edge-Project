from flask import Flask, request, jsonify
from cryptography.fernet import Fernet
import base64
from flask_limiter import Limiter
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import logging

app = Flask(__name__)

# Initialize logger
logging.basicConfig(level=logging.INFO)

# Load public key for verifying signatures
with open("edge_public_key.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(key_file.read())

# Shared secret key for authentication
SHARED_SECRET_KEY = "supersecretkey123"

# Keychain and key rotation logic
keychain = {}
current_key_id = 1
KEY_EXPIRATION_MINUTES = 10

# Initial key generation
def generate_new_key():
    global current_key_id
    new_key_id = current_key_id + 1
    new_key = Fernet.generate_key().decode()
    expiration_time = datetime.now() + timedelta(minutes=KEY_EXPIRATION_MINUTES)
    keychain[new_key_id] = {
        "key": new_key,
        "expiration": expiration_time
    }
    logging.info(f"Generated new key ID: {new_key_id}, expires at {expiration_time}")
    current_key_id = new_key_id

generate_new_key()

# API Rate Limiting
limiter = Limiter(app)

# Validate the auth token
def validate_auth_token(auth_token):
    expected_token = base64.urlsafe_b64encode(SHARED_SECRET_KEY.encode()).decode()
    return auth_token == expected_token

# Verify the digital signature
def verify_signature(combined_data, signature):
    try:
        public_key.verify(
            base64.b64decode(signature),
            combined_data.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Step 6: Signature verification successful!")
        return True
    except Exception as e:
        print(f"Step 6: Signature verification failed: {e}")
        return False

@app.route('/get-current-key', methods=['GET'])
def get_current_key():
    current_key_data = keychain[current_key_id]
    print(f"Step 1: Providing current key with Key ID: {current_key_id}")
    return jsonify({
        "key_id": current_key_id,
        "encryption_key": current_key_data["key"]
    })

@app.route('/process-data', methods=['POST'])
@limiter.limit("5 per minute")
def process_data():
    data = request.get_json()
    combined_data = data.get('combined_data')
    key_id = data.get('key_id')
    signature = data.get('signature')

    print(f"Step 2: Received Key ID: {key_id}")
    
    # Verify key validity
    key_data = keychain.get(key_id)
    if not key_data or key_data['expiration'] < datetime.now():
        print(f"Step 3: Invalid or expired key ID: {key_id}")
        return jsonify({"error": "Invalid or expired key ID"}), 403

    print(f"Step 3: Valid Key ID: {key_id}")

    # Verify the digital signature
    if not verify_signature(combined_data, signature):
        return jsonify({"error": "Invalid signature"}), 403

    # Split the combined data
    auth_token, encrypted_message = combined_data.split("::")
    print(f"Step 4: Received Auth Token: {auth_token}")
    print(f"Step 5: Received Encrypted Message: {encrypted_message}")

    # Validate the auth token
    if not validate_auth_token(auth_token):
        print("Step 7: Invalid Auth Token!")
        return jsonify({"error": "Invalid auth token"}), 403

    print("Step 7: Auth Token Validated Successfully")

    # Decrypt the message
    try:
        cipher_suite = Fernet(key_data["key"].encode())
        decrypted_message = cipher_suite.decrypt(encrypted_message.encode()).decode()
        print(f"Step 8: Decrypted Message: {decrypted_message}")
    except Exception as e:
        print(f"Step 8: Decryption failed: {e}")
        return jsonify({"error": "Decryption failed"}), 500

    return jsonify({
        "message": "Message received, verified, and decrypted",
        "decrypted_message": decrypted_message
    })

if __name__ == '__main__':
    app.run(port=5000)
