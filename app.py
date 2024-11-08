from flask import Flask, request, jsonify
from cryptography.fernet import Fernet
import base64
from flask_limiter import Limiter
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import logging
from typing import Dict, Any
import os
from functools import wraps
import traceback
from marshmallow import Schema, fields, ValidationError
from flask_talisman import Talisman
import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import queue
import webbrowser
import jwt
import hashlib
from collections import defaultdict
import time

class KeyManager:
    def __init__(self, rotation_minutes: int = 10, max_keys: int = 3):
        self.keychain: Dict[int, Dict[str, Any]] = {}
        self.current_key_id: int = 0
        self.rotation_minutes = rotation_minutes
        self.max_keys = max_keys
        self.generate_new_key()

    def generate_new_key(self) -> None:
        self.current_key_id += 1
        new_key = Fernet.generate_key().decode()
        expiration_time = datetime.now() + timedelta(minutes=self.rotation_minutes)
        
        self.keychain[self.current_key_id] = {
            "key": new_key,
            "expiration": expiration_time,
            "created_at": datetime.now()
        }
        
        if len(self.keychain) > self.max_keys:
            oldest_key_id = min(self.keychain.keys())
            del self.keychain[oldest_key_id]

    def get_key(self, key_id: int) -> Dict[str, Any]:
        return self.keychain.get(key_id)

    def cleanup_expired_keys(self) -> None:
        now = datetime.now()
        expired_keys = [k for k, v in self.keychain.items() 
                       if v['expiration'] < now and k != self.current_key_id]
        for key_id in expired_keys:
            del self.keychain[key_id]

def handle_errors(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            error_msg = f"Error in {f.__name__}: {str(e)}\n{traceback.format_exc()}"
            logging.error(error_msg)
            return jsonify({
                "error": "Internal server error",
                "message": str(e)
            }), 500
    return decorated_function

class ProcessDataSchema(Schema):
    device_id = fields.Str(required=True)
    api_key = fields.Str(required=True)
    combined_data = fields.Str(required=True)
    key_id = fields.Int(required=True)
    signature = fields.Str(required=True)

class FogServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Fog Server Monitor")
        self.root.geometry("900x700")
        
        # Message queue for communication between Flask and GUI
        self.message_queue = queue.Queue()
        
        # Configure style
        style = ttk.Style()
        style.configure("Success.TLabel", foreground="green")
        style.configure("Error.TLabel", foreground="red")
        
        # Create main frame
        main_frame = ttk.Frame(root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Server status frame
        status_frame = ttk.LabelFrame(main_frame, text="Server Status", padding="5")
        status_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        self.server_status = ttk.Label(status_frame, text="🔴 Server Stopped")
        self.server_status.grid(row=0, column=0, padx=5)
        
        self.active_keys = ttk.Label(status_frame, text="Active Keys: 0")
        self.active_keys.grid(row=0, column=1, padx=5)
        
        self.requests_count = ttk.Label(status_frame, text="Requests: 0")
        self.requests_count.grid(row=0, column=2, padx=5)
        
        # Control buttons
        control_frame = ttk.Frame(main_frame)
        control_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        self.start_button = ttk.Button(control_frame, text="Start Server", command=self.start_server)
        self.start_button.grid(row=0, column=0, padx=5)
        
        self.stop_button = ttk.Button(control_frame, text="Stop Server", command=self.stop_server, state='disabled')
        self.stop_button.grid(row=0, column=1, padx=5)
        
        # Key management frame
        key_frame = ttk.LabelFrame(main_frame, text="Key Management", padding="5")
        key_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        self.key_tree = ttk.Treeview(key_frame, columns=("ID", "Created", "Expires"), height=3)
        self.key_tree.heading("ID", text="Key ID")
        self.key_tree.heading("Created", text="Created At")
        self.key_tree.heading("Expires", text="Expires At")
        self.key_tree.column("#0", width=0, stretch=tk.NO)
        self.key_tree.column("ID", width=100)
        self.key_tree.column("Created", width=200)
        self.key_tree.column("Expires", width=200)
        self.key_tree.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
        # Log display
        log_frame = ttk.LabelFrame(main_frame, text="Server Log", padding="5")
        log_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        self.log_display = scrolledtext.ScrolledText(log_frame, height=20, width=90)
        self.log_display.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.request_count = 0
        self.server_running = False
        self.server_thread = None
        
        # Start checking for messages
        self.root.after(100, self.check_messages)

        # Add Device Monitor frame
        device_monitor_frame = ttk.LabelFrame(main_frame, text="Device Monitor", padding="5")
        device_monitor_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        self.device_tree = ttk.Treeview(
            device_monitor_frame, 
            columns=("ID", "Type", "Status", "Last Active", "Failed Attempts"),
            height=5
        )
        self.device_tree.heading("ID", text="Device ID")
        self.device_tree.heading("Type", text="Type")
        self.device_tree.heading("Status", text="Status")
        self.device_tree.heading("Last Active", text="Last Active")
        self.device_tree.heading("Failed Attempts", text="Failed Attempts")
        self.device_tree.column("#0", width=0, stretch=tk.NO)
        self.device_tree.grid(row=0, column=0, sticky=(tk.W, tk.E))

    def log_message(self, message, level="INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        if level == "ERROR":
            prefix = "❌ ERROR"
        elif level == "SUCCESS":
            prefix = "✅ SUCCESS"
        else:
            prefix = "ℹ️ INFO"
            
        log_entry = f"[{timestamp}] {prefix}: {message}\n"
        self.log_display.insert(tk.END, log_entry)
        self.log_display.see(tk.END)

    def update_key_tree(self, keychain):
        # Clear existing items
        for item in self.key_tree.get_children():
            self.key_tree.delete(item)
        
        # Add current keys
        for key_id, key_data in keychain.items():
            created = key_data['created_at'].strftime("%Y-%m-%d %H:%M:%S")
            expires = key_data['expiration'].strftime("%Y-%m-%d %H:%M:%S")
            self.key_tree.insert("", "end", values=(key_id, created, expires))
        
        # Update active keys count
        self.active_keys.config(text=f"Active Keys: {len(keychain)}")

    def start_server(self):
        if not self.server_running:
            self.server_running = True
            self.server_status.config(text="🟢 Server Running")
            self.start_button.config(state='disabled')
            self.stop_button.config(state='normal')
            self.log_message("Server started successfully", "SUCCESS")
            self.server_thread = threading.Thread(target=run_flask_app, args=(self.message_queue,))
            self.server_thread.daemon = True
            self.server_thread.start()
            # Open browser after a short delay
            self.root.after(1500, lambda: webbrowser.open('http://localhost:5000'))

    def stop_server(self):
        if self.server_running:
            self.server_running = False
            self.server_status.config(text="🔴 Server Stopped")
            self.start_button.config(state='normal')
            self.stop_button.config(state='disabled')
            self.log_message("Server stopped", "INFO")
            # Implement proper server shutdown here

    def check_messages(self):
        try:
            while True:
                message = self.message_queue.get_nowait()
                if message['type'] == 'log':
                    self.log_message(message['content'], message.get('level', 'INFO'))
                elif message['type'] == 'key_update':
                    self.update_key_tree(message['keychain'])
                elif message['type'] == 'request_count':
                    self.request_count += 1
                    self.requests_count.config(text=f"Requests: {self.request_count}")
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self.check_messages)

    def update_device_tree(self, devices):
        for item in self.device_tree.get_children():
            self.device_tree.delete(item)
        
        for device_id, device_data in devices.items():
            status = "🟢 Active" if (datetime.now() - device_data["last_active"]).seconds < 300 else "⚪ Inactive"
            if device_id in device_data.get("blacklist", []):
                status = "🔴 Blacklisted"
            
            self.device_tree.insert("", "end", values=(
                device_id,
                device_data["device_type"],
                status,
                device_data["last_active"].strftime("%Y-%m-%d %H:%M:%S"),
                device_data["failed_attempts"]
            ))

class InMemoryRateLimiter:
    def __init__(self):
        self.requests = defaultdict(list)
        self.max_requests = 5  # Max requests per minute
        self.time_window = 60  # Time window in seconds

    def is_allowed(self, device_id):
        now = time.time()
        # Remove old requests
        self.requests[device_id] = [
            req_time for req_time in self.requests[device_id]
            if now - req_time < self.time_window
        ]
        
        # Check if under limit
        if len(self.requests[device_id]) < self.max_requests:
            self.requests[device_id].append(now)
            return True
        return False

class DeviceRegistry:
    def __init__(self):
        self.devices = {}
        self.blacklist = set()
        self.suspicious_activity = {}
        self.rate_limiter = InMemoryRateLimiter()

    def register_device(self, device_id, api_key, device_type, capabilities, public_key):
        if device_id in self.blacklist:
            return False, "Device blacklisted"
        
        # Hash the API key for storage
        api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        self.devices[device_id] = {
            "api_key_hash": api_key_hash,
            "device_type": device_type,
            "capabilities": capabilities,
            "public_key": public_key,
            "registered_at": datetime.now(),
            "last_active": datetime.now(),
            "failed_attempts": 0
        }
        return True, "Device registered successfully"

    def validate_device(self, device_id, api_key):
        if device_id not in self.devices:
            return False, "Device not registered"
        
        if device_id in self.blacklist:
            return False, "Device blacklisted"
        
        device = self.devices[device_id]
        api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        if api_key_hash != device["api_key_hash"]:
            device["failed_attempts"] += 1
            if device["failed_attempts"] >= 5:
                self.blacklist.add(device_id)
                return False, "Device blacklisted due to multiple failed attempts"
            return False, "Invalid API key"
        
        # Check rate limit
        if not self.rate_limiter.is_allowed(device_id):
            return False, "Rate limit exceeded"
        
        device["last_active"] = datetime.now()
        device["failed_attempts"] = 0
        return True, "Device validated"

def create_app(message_queue):
    app = Flask(__name__)
    app.config['ENV'] = 'development'
    app.config['DEBUG'] = True
    
    # Initialize logger
    logging.basicConfig(level=logging.INFO)
    
    # Load public key for verifying signatures
    with open("edge_public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    
    # Shared secret key for authentication
    SHARED_SECRET_KEY = os.environ.get('SHARED_SECRET_KEY', 'development-secret-key')
    
    # Initialize key manager
    key_manager = KeyManager(rotation_minutes=10)
    
    # Initialize Limiter properly
    limiter = Limiter(
        app=app,
        key_func=lambda: request.remote_addr,  # Rate limit by IP address
        default_limits=["200 per day", "50 per hour"]
    )
    
    # Disable SSL for development
    app.config['PREFERRED_URL_SCHEME'] = 'http'
    
    # Initialize Redis for device registry and rate limiting
    rate_limiter = InMemoryRateLimiter()

    device_registry = DeviceRegistry()

    # Add rate limiting by device ID
    def rate_limit_by_device(device_id):
        return rate_limiter.is_allowed(device_id)

    @app.route('/get-current-key', methods=['GET'])
    @handle_errors
    def get_current_key():
        message_queue.put({
            'type': 'log',
            'content': f"Key request received. Providing key ID: {key_manager.current_key_id}",
            'level': 'INFO'
        })
        message_queue.put({'type': 'request_count'})
        message_queue.put({'type': 'key_update', 'keychain': key_manager.keychain})
        
        current_key_data = key_manager.get_key(key_manager.current_key_id)
        return jsonify({
            "key_id": key_manager.current_key_id,
            "encryption_key": current_key_data["key"]
        })

    @app.route('/process-data', methods=['POST'])
    @handle_errors
    def process_data():
        try:
            message_queue.put({
                'type': 'log',
                'content': "STEP 1: Received new message for processing",
                'level': 'INFO'
            })
            
            # Validate request schema
            schema = ProcessDataSchema()
            data = schema.load(request.get_json())
            message_queue.put({
                'type': 'log',
                'content': "STEP 2: Request schema validated",
                'level': 'SUCCESS'
            })
            
            # Extract device authentication data
            device_id = data['device_id']
            api_key = data['api_key']
            message_queue.put({
                'type': 'log',
                'content': f"STEP 3: Processing request from device: {device_id}",
                'level': 'INFO'
            })
            
            # Validate device first
            success, message = device_registry.validate_device(device_id, api_key)
            if not success:
                message_queue.put({
                    'type': 'log',
                    'content': f"STEP 4: Device validation failed: {message}",
                    'level': 'ERROR'
                })
                return jsonify({"error": message}), 403
            
            message_queue.put({
                'type': 'log',
                'content': "STEP 4: Device authentication successful",
                'level': 'SUCCESS'
            })

            # Check rate limit
            if not rate_limit_by_device(device_id):
                message_queue.put({
                    'type': 'log',
                    'content': f"STEP 5: Rate limit exceeded for device: {device_id}",
                    'level': 'ERROR'
                })
                return jsonify({"error": "Rate limit exceeded"}), 429
            
            message_queue.put({
                'type': 'log',
                'content': "STEP 5: Rate limit check passed",
                'level': 'SUCCESS'
            })

            # Process the message
            combined_data = data['combined_data']
            key_id = data['key_id']
            signature = data['signature']
            
            # Verify key validity
            key_data = key_manager.get_key(key_id)
            if not key_data or key_data['expiration'] < datetime.now():
                message_queue.put({
                    'type': 'log',
                    'content': f"STEP 6: Invalid or expired key ID: {key_id}",
                    'level': 'ERROR'
                })
                return jsonify({"error": "Invalid or expired key ID"}), 403
            
            message_queue.put({
                'type': 'log',
                'content': "STEP 6: Encryption key validated",
                'level': 'SUCCESS'
            })

            # Verify the digital signature
            if not verify_signature(combined_data, signature):
                message_queue.put({
                    'type': 'log',
                    'content': "STEP 7: Digital signature verification failed",
                    'level': 'ERROR'
                })
                return jsonify({"error": "Invalid signature"}), 403
            
            message_queue.put({
                'type': 'log',
                'content': "STEP 7: Digital signature verified",
                'level': 'SUCCESS'
            })

            # Split the combined data
            auth_token, encrypted_message = combined_data.split("::")
            message_queue.put({
                'type': 'log',
                'content': "STEP 8: Split auth token and encrypted message",
                'level': 'SUCCESS'
            })

            # Validate the auth token
            if not validate_auth_token(auth_token):
                message_queue.put({
                    'type': 'log',
                    'content': "STEP 9: Auth token validation failed",
                    'level': 'ERROR'
                })
                return jsonify({"error": "Invalid auth token"}), 403
            
            message_queue.put({
                'type': 'log',
                'content': "STEP 9: Auth token validated",
                'level': 'SUCCESS'
            })

            # Decrypt the message
            try:
                message_queue.put({
                    'type': 'log',
                    'content': "STEP 10: Attempting message decryption",
                    'level': 'INFO'
                })
                
                cipher_suite = Fernet(key_data["key"].encode())
                decrypted_message = cipher_suite.decrypt(encrypted_message.encode()).decode()
                
                message_queue.put({
                    'type': 'log',
                    'content': f"STEP 10: Successfully decrypted message: {decrypted_message}",
                    'level': 'SUCCESS'
                })
            except Exception as e:
                message_queue.put({
                    'type': 'log',
                    'content': f"STEP 10: Decryption failed: {str(e)}",
                    'level': 'ERROR'
                })
                return jsonify({"error": "Decryption failed"}), 500

            return jsonify({
                "message": "Message received, verified, and decrypted",
                "decrypted_message": decrypted_message
            })
            
        except ValidationError as err:
            message_queue.put({
                'type': 'log',
                'content': f"Validation error: {err.messages}",
                'level': 'ERROR'
            })
            return jsonify({"error": "Validation error", "details": err.messages}), 400

    def validate_auth_token(auth_token):
        try:
            expected_token = base64.urlsafe_b64encode(SHARED_SECRET_KEY.encode()).decode()
            return auth_token == expected_token
        except Exception as e:
            message_queue.put({
                'type': 'log',
                'content': f"Auth token validation failed: {str(e)}",
                'level': 'ERROR'
            })
            return False

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
            message_queue.put({
                'type': 'log',
                'content': "Signature verification successful",
                'level': 'SUCCESS'
            })
            return True
        except Exception as e:
            message_queue.put({
                'type': 'log',
                'content': f"Signature verification failed: {str(e)}",
                'level': 'ERROR'
            })
            return False

    @app.route('/register-device', methods=['POST'])
    @handle_errors
    def register_device():
        try:
            data = request.get_json()
            required_fields = ['device_id', 'api_key', 'device_type', 'capabilities', 'public_key']
            
            # Check for required fields
            if not all(field in data for field in required_fields):
                return jsonify({"error": "Missing required fields"}), 400
            
            success, message = device_registry.register_device(
                data['device_id'],
                data['api_key'],
                data['device_type'],
                data['capabilities'],
                data['public_key']
            )
            
            if success:
                message_queue.put({
                    'type': 'log',
                    'content': f"New device registered: {data['device_id']}",
                    'level': 'SUCCESS'
                })
                return jsonify({"message": message}), 200
            else:
                message_queue.put({
                    'type': 'log',
                    'content': f"Device registration failed: {message}",
                    'level': 'ERROR'
                })
                return jsonify({"error": message}), 403
        except Exception as e:
            message_queue.put({
                'type': 'log',
                'content': f"Registration error: {str(e)}",
                'level': 'ERROR'
            })
            return jsonify({"error": str(e)}), 500

    return app

def run_flask_app(message_queue):
    app = create_app(message_queue)
    # Make sure to bind to all interfaces
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)

def main():
    root = tk.Tk()
    app = FogServerGUI(root)
    root.mainloop()

if __name__ == '__main__':
    main()
