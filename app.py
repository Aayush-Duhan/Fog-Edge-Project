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
import requests
import json
from dotenv import load_dotenv
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import pandas as pd
from datetime import datetime, timedelta
import boto3
from boto3.dynamodb.conditions import Key

load_dotenv()

# Initialize shared components
shared_device_registry = None  # Initialize as None first

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

class CloudConnector:
    def __init__(self, message_queue):
        self.message_queue = message_queue
        
        # Load credentials from cloud_credentials.json
        try:
            with open('cloud_credentials.json', 'r') as f:
                credentials = json.load(f)
                self.cloud_endpoint = credentials['api_endpoint']
                self.api_key = credentials['api_key']
                self.message_queue.put({
                    'type': 'log',
                    'content': "Cloud credentials loaded successfully",
                    'level': 'SUCCESS'
                })
        except Exception as e:
            self.message_queue.put({
                'type': 'log',
                'content': f"Failed to load cloud credentials: {str(e)}",
                'level': 'ERROR'
            })
            self.cloud_endpoint = os.getenv('CLOUD_API_ENDPOINT', '')
            self.api_key = os.getenv('CLOUD_API_KEY', '')
        
        self.batch_size = 10
        self.data_buffer = []
        self.check_cloud_connection()  # Add initial connection check

    def check_cloud_connection(self):
        """Check if cloud connection is working"""
        try:
            headers = {
                'x-api-key': self.api_key,
                'Content-Type': 'application/json'
            }
            
            # Send a test payload
            test_data = {
                'fog_id': 'FOG_001',
                'data': [{
                    'device_id': 'TEST',
                    'message': 'Connection test',
                    'processed_at': datetime.now().isoformat()
                }]
            }
            
            response = requests.post(
                self.cloud_endpoint,
                json=test_data,
                headers=headers,
                timeout=5  # Add timeout
            )
            
            if response.status_code == 200:
                self.message_queue.put({
                    'type': 'log',
                    'content': "Cloud connection established successfully",
                    'level': 'SUCCESS'
                })
                return True
            else:
                self.message_queue.put({
                    'type': 'log',
                    'content': f"Cloud connection failed: {response.text}",
                    'level': 'ERROR'
                })
                return False
                
        except Exception as e:
            self.message_queue.put({
                'type': 'log',
                'content': f"Cloud connection error: {str(e)}",
                'level': 'ERROR'
            })
            return False

    def send_to_cloud(self, data):
        """Send data to cloud with basic retry logic"""
        try:
            headers = {
                'x-api-key': self.api_key,
                'Content-Type': 'application/json'
            }
            
            # Add metadata
            data_with_metadata = {
                'fog_id': 'FOG_001',
                'data': data if isinstance(data, list) else [data],
                'timestamp': datetime.now().isoformat()
            }
            
            # Debug logging
            self.message_queue.put({
                'type': 'log',
                'content': f"Sending to cloud endpoint: {self.cloud_endpoint}",
                'level': 'INFO'
            })
            self.message_queue.put({
                'type': 'log',
                'content': f"Headers: {headers}",
                'level': 'INFO'
            })
            self.message_queue.put({
                'type': 'log',
                'content': f"Data: {json.dumps(data_with_metadata)}",
                'level': 'INFO'
            })
            
            response = requests.post(
                self.cloud_endpoint,
                json=data_with_metadata,
                headers=headers,
                timeout=5
            )
            
            # Debug response
            self.message_queue.put({
                'type': 'log',
                'content': f"Cloud Response Status: {response.status_code}",
                'level': 'INFO'
            })
            self.message_queue.put({
                'type': 'log',
                'content': f"Cloud Response: {response.text}",
                'level': 'INFO'
            })
            
            if response.status_code == 200:
                self.message_queue.put({
                    'type': 'log',
                    'content': "Data successfully sent to cloud",
                    'level': 'SUCCESS'
                })
                return True
            else:
                self.message_queue.put({
                    'type': 'log',
                    'content': f"Failed to send data to cloud: {response.text}",
                    'level': 'ERROR'
                })
                return False
                
        except Exception as e:
            self.message_queue.put({
                'type': 'log',
                'content': f"Cloud communication error: {str(e)}",
                'level': 'ERROR'
            })
            return False

    def buffer_data(self, data):
        """Buffer data and send in batches"""
        self.data_buffer.append(data)
        
        if len(self.data_buffer) >= self.batch_size:
            success = self.send_to_cloud(self.data_buffer)
            if success:
                self.data_buffer = []
            return success
        
        # If buffer isn't full yet, still send single items immediately
        return self.send_to_cloud([data])

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
        self.message_queue = None
        self.alert_callbacks = {}  # Store callback functions for each device

    def set_message_queue(self, queue):
        self.message_queue = queue

    def update_gui(self):
        """Send device update to GUI"""
        if self.message_queue:
            # Convert datetime objects to strings for JSON serialization
            devices_copy = {}
            for device_id, device_data in self.devices.items():
                devices_copy[device_id] = {
                    **device_data,
                    'registered_at': device_data['registered_at'].strftime("%Y-%m-%d %H:%M:%S"),
                    'last_active': device_data['last_active'].strftime("%Y-%m-%d %H:%M:%S")
                }
            
            self.message_queue.put({
                'type': 'device_update',
                'devices': devices_copy,
                'blacklist': list(self.blacklist)
            })

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
        self.update_gui()  # Update GUI after registration
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
                self.update_gui()  # Update GUI after blacklisting
                return False, "Device blacklisted due to multiple failed attempts"
            self.update_gui()  # Update GUI after failed attempt
            return False, "Invalid API key"
        
        # Check rate limit
        if not self.rate_limiter.is_allowed(device_id):
            return False, "Rate limit exceeded"
        
        # Update last active time
        device["last_active"] = datetime.now()
        device["failed_attempts"] = 0
        self.update_gui()  # Update GUI after successful validation
        return True, "Device validated"

    def get_device_status(self, device_id):
        """Get current status of a device"""
        if device_id not in self.devices:
            return "Not Registered"
        
        if device_id in self.blacklist:
            return "🔴 Blacklisted"
        
        device = self.devices[device_id]
        time_since_active = (datetime.now() - device["last_active"]).total_seconds()
        
        if time_since_active < 300:  # 5 minutes
            return "🟢 Active"
        else:
            return "⚪ Inactive"

    def register_alert_callback(self, device_id, callback):
        """Register a callback function for alerts"""
        self.alert_callbacks[device_id] = callback

    def broadcast_alert(self, source_device_id, message):
        """Send alert to all registered devices except the source"""
        for device_id, callback in self.alert_callbacks.items():
            if device_id != source_device_id:
                try:
                    callback(f"Alert from {source_device_id}: {message}")
                except Exception as e:
                    if self.message_queue:
                        self.message_queue.put({
                            'type': 'log',
                            'content': f"Failed to send alert to {device_id}: {str(e)}",
                            'level': 'ERROR'
                        })

class FogServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Fog Server Monitor")
        self.root.geometry("900x700")
        
        # Configure grid weight to allow resizing
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        
        # Create canvas and scrollbar
        self.canvas = tk.Canvas(root)
        self.scrollbar = ttk.Scrollbar(root, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = ttk.Frame(self.canvas)
        
        # Configure canvas
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        
        # Pack scrollbar and canvas
        self.scrollbar.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)
        
        # Message queue for communication between Flask and GUI
        self.message_queue = queue.Queue()
        
        # Configure style
        style = ttk.Style()
        style.configure("Success.TLabel", foreground="green")
        style.configure("Error.TLabel", foreground="red")
        
        # Create main frame
        main_frame = ttk.Frame(self.scrollable_frame, padding="10")
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

        # Add Cloud Status frame
        cloud_frame = ttk.LabelFrame(main_frame, text="Cloud Connection", padding="5")
        cloud_frame.grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        self.cloud_status = ttk.Label(cloud_frame, text="⚪ Cloud: Not Connected")
        self.cloud_status.grid(row=0, column=0, padx=5)
        
        self.cloud_sync = ttk.Label(cloud_frame, text="📤 Last Sync: Never")
        self.cloud_sync.grid(row=0, column=1, padx=5)
        
        # Initialize cloud connector
        self.cloud_connector = CloudConnector(self.message_queue)

        # Add mouse wheel binding
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)

        # Use the shared device registry instead of creating a new one
        self.device_registry = shared_device_registry
        self.device_registry.set_message_queue(self.message_queue)

        # Create visualization panel with shared device registry
        self.data_viz = DataVisualizationPanel(main_frame, self.message_queue, self.device_registry)

        # Add refresh timer
        self.root.after(60000, self.refresh_visualization)

        # Add periodic device status update
        self.root.after(5000, self.check_device_status)  # Check every 5 seconds

        # Add periodic device refresh
        self.root.after(1000, self.refresh_device_monitor)  # Refresh every second

        # Add threshold configuration
        self.threshold_value = 100.0  # Default threshold
        
        # Add threshold configuration frame
        threshold_frame = ttk.LabelFrame(main_frame, text="Threshold Configuration", padding="5")
        threshold_frame.grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(threshold_frame, text="Threshold Value:").grid(row=0, column=0, padx=5)
        self.threshold_entry = ttk.Entry(threshold_frame)
        self.threshold_entry.grid(row=0, column=1, padx=5)
        self.threshold_entry.insert(0, str(self.threshold_value))
        
        ttk.Button(threshold_frame, text="Update Threshold", 
                  command=self.update_threshold).grid(row=0, column=2, padx=5)

        # Initialize Flask app and store reference
        self.flask_app = None
        
        # Start Flask server
        self.server_thread = None
        
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
            
            # Check cloud connection
            if self.cloud_connector.check_cloud_connection():
                self.cloud_status.config(text="🟢 Cloud: Connected")
            else:
                self.cloud_status.config(text="🔴 Cloud: Error")
            
            # Create and start Flask server
            self.server_thread = threading.Thread(target=self.run_flask_server)
            self.server_thread.daemon = True
            self.server_thread.start()
            
            # Open browser after a short delay
            self.root.after(1500, lambda: webbrowser.open('http://localhost:5000'))

    def run_flask_server(self):
        """Run Flask server and store app reference"""
        self.flask_app = create_app(self.message_queue)
        
        # Set this GUI instance in the Flask app
        if hasattr(self.flask_app, 'state'):
            self.flask_app.state.gui = self
            
        self.flask_app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)

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
                    
                    # Update cloud status if message is related to cloud
                    if 'cloud' in message['content'].lower():
                        if message['level'] == 'SUCCESS':
                            self.cloud_status.config(text="🟢 Cloud: Connected")
                            self.cloud_sync.config(text=f"📤 Last Sync: {datetime.now().strftime('%H:%M:%S')}")
                        elif message['level'] == 'ERROR':
                            self.cloud_status.config(text="🔴 Cloud: Error")
                
                elif message['type'] == 'key_update':
                    self.update_key_tree(message['keychain'])
                elif message['type'] == 'request_count':
                    self.request_count += 1
                    self.requests_count.config(text=f"Requests: {self.request_count}")
                elif message['type'] == 'device_update':
                    self.update_device_tree(message['devices'])
                
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self.check_messages)

    def update_device_tree(self, devices):
        """Update the device monitor tree"""
        # Clear existing items
        for item in self.device_tree.get_children():
            self.device_tree.delete(item)
        
        # Add current devices
        for device_id, device_data in devices.items():
            # Convert string timestamps back to datetime for comparison
            last_active = datetime.strptime(device_data["last_active"], "%Y-%m-%d %H:%M:%S")
            
            # Determine status
            if (datetime.now() - last_active).seconds < 300:  # 5 minutes
                status = "🟢 Active"
            else:
                status = "⚪ Inactive"
            
            if device_id in device_data.get("blacklist", []):
                status = "🔴 Blacklisted"
            
            # Insert device into tree
            self.device_tree.insert("", "end", values=(
                device_id,
                device_data["device_type"],
                status,
                device_data["last_active"],
                device_data["failed_attempts"]
            ))

    def _on_mousewheel(self, event):
        """Handle mouse wheel scrolling"""
        self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")

    def refresh_visualization(self):
        """Refresh visualization periodically"""
        if self.server_running:
            self.data_viz.refresh_data()
        self.root.after(60000, self.refresh_visualization)

    def check_device_status(self):
        """Update device status periodically"""
        for item in self.device_tree.get_children():
            device_id = self.device_tree.item(item)['values'][0]
            last_active = datetime.strptime(
                self.device_tree.item(item)['values'][3], 
                "%Y-%m-%d %H:%M:%S"
            )
            
            # Update status based on last activity
            if (datetime.now() - last_active).seconds > 300:  # 5 minutes
                self.device_tree.set(item, "Status", "⚪ Inactive")
        
        # Schedule next check
        self.root.after(5000, self.check_device_status)

    def refresh_device_monitor(self):
        """Periodically refresh device monitor"""
        if self.server_running:
            # Request device update
            if hasattr(self, 'device_registry'):
                self.device_registry.update_gui()
        
        # Schedule next refresh
        self.root.after(1000, self.refresh_device_monitor)

    def update_threshold(self):
        try:
            new_threshold = float(self.threshold_entry.get())
            self.threshold_value = new_threshold
            self.log_message(f"Threshold updated to: {new_threshold}")
        except ValueError:
            self.log_message("Invalid threshold value. Please enter a number.")

    def process_message(self, message, client_address):
        try:
            # Split auth token and encrypted message
            auth_token, encrypted_message = message.split("::")
            
            # Get the key from key manager
            if hasattr(self.flask_app, 'key_manager'):
                key_data = self.flask_app.key_manager.get_key(self.flask_app.key_manager.current_key_id)
                if key_data:
                    cipher_suite = Fernet(key_data["key"].encode())
                    decrypted_message = cipher_suite.decrypt(encrypted_message.encode()).decode()
                    
                    try:
                        # Convert the decrypted message to float
                        float_value = float(decrypted_message)
                        
                        # Check threshold and prepare response
                        if float_value > self.threshold_value:
                            # Send to cloud when threshold is exceeded
                            cloud_data = {
                                'device_id': client_address,
                                'message': f"ALERT: Value {float_value} exceeded threshold {self.threshold_value}",
                                'value': float_value,
                                'threshold': self.threshold_value,
                                'processed_at': datetime.now().isoformat()
                            }
                            
                            # Send alert to cloud
                            if self.cloud_connector.buffer_data(cloud_data):
                                self.log_message(f"Alert! Value {float_value} exceeded threshold {self.threshold_value}. Alert sent to cloud.", "WARNING")
                                
                                # Broadcast alert to all devices
                                if hasattr(self, 'device_registry'):
                                    self.device_registry.broadcast_alert(
                                        client_address,
                                        f"Threshold Exceeded (Value: {float_value})"
                                    )
                            else:
                                self.log_message("Failed to send alert to cloud", "ERROR")
                            
                            response = "Threshold Exceeded"
                        else:
                            response = str(float_value)
                            self.log_message(f"Received value: {float_value} (below threshold)")
                        
                    except ValueError:
                        response = "Error: Invalid numeric value"
                        self.log_message(f"Error: Received invalid numeric value: {decrypted_message}")
                    
                    # Encrypt the response
                    return cipher_suite.encrypt(response.encode()).decode()
            
            return self.encrypt_message("Error: Invalid key")
            
        except Exception as e:
            self.log_message(f"Error processing message: {str(e)}")
            return self.encrypt_message("Error processing message")

class DataVisualizationPanel:
    def __init__(self, parent_frame, message_queue, device_registry):
        self.parent_frame = parent_frame
        self.message_queue = message_queue
        self.device_registry = device_registry  # Store device registry reference
        
        # Create visualization frame
        self.frame = ttk.LabelFrame(parent_frame, text="Data Visualization", padding="5")
        self.frame.grid(row=6, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        # Controls frame
        controls_frame = ttk.Frame(self.frame)
        controls_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=5)
        
        # Time range selector
        ttk.Label(controls_frame, text="Time Range:").grid(row=0, column=0, padx=5)
        self.time_range = ttk.Combobox(controls_frame, 
            values=["Last Hour", "Last Day", "Last Week"],
            state="readonly", width=15)
        self.time_range.set("Last Hour")
        self.time_range.grid(row=0, column=1, padx=5)
        
        # Device selector
        ttk.Label(controls_frame, text="Device:").grid(row=0, column=2, padx=5)
        self.device_selector = ttk.Combobox(controls_frame, state="readonly", width=15)
        self.device_selector.grid(row=0, column=3, padx=5)
        
        # Refresh button
        self.refresh_btn = ttk.Button(controls_frame, text="Refresh", command=self.refresh_data)
        self.refresh_btn.grid(row=0, column=4, padx=5)
        
        # Add device refresh button
        ttk.Button(controls_frame, text="Refresh Devices", 
                  command=self.update_device_list).grid(row=0, column=5, padx=5)
        
        # Create matplotlib figure
        self.fig, (self.ax1, self.ax2) = plt.subplots(2, 1, figsize=(10, 8))
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.frame)
        self.canvas.get_tk_widget().grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Initialize data
        self.update_device_list()
        self.refresh_data()
        
        # Bind events
        self.time_range.bind('<<ComboboxSelected>>', lambda e: self.refresh_data())
        self.device_selector.bind('<<ComboboxSelected>>', lambda e: self.refresh_data())

    def update_device_list(self):
        """Update the device selector with all registered devices"""
        try:
            # Use the stored device registry reference
            if self.device_registry:
                registered_devices = list(self.device_registry.devices.keys())
                
                # Update device selector
                current_selection = self.device_selector.get()  # Save current selection
                self.device_selector['values'] = registered_devices
                
                # Restore previous selection if it still exists
                if current_selection in registered_devices:
                    self.device_selector.set(current_selection)
                elif registered_devices:
                    self.device_selector.set(registered_devices[0])
                
                self.message_queue.put({
                    'type': 'log',
                    'content': f"Found {len(registered_devices)} registered devices",
                    'level': 'INFO'
                })
            else:
                self.message_queue.put({
                    'type': 'log',
                    'content': "Device registry not available",
                    'level': 'ERROR'
                })
                
        except Exception as e:
            self.message_queue.put({
                'type': 'log',
                'content': f"Failed to update device list: {str(e)}",
                'level': 'ERROR'
            })

    def get_time_range(self):
        range_str = self.time_range.get()
        now = datetime.now()
        
        if range_str == "Last Hour":
            return now - timedelta(hours=1)
        elif range_str == "Last Day":
            return now - timedelta(days=1)
        else:  # Last Week
            return now - timedelta(weeks=1)

    def refresh_data(self):
        # Update device list before refreshing data
        self.update_device_list()
        
        try:
            # Clear previous plots
            self.ax1.clear()
            self.ax2.clear()
            
            # Get selected device
            device_id = self.device_selector.get()
            if not device_id:
                self.message_queue.put({
                    'type': 'log',
                    'content': "No device selected. Please select a device.",
                    'level': 'INFO'
                })
                self.ax1.text(0.5, 0.5, 'No device selected', 
                    horizontalalignment='center', verticalalignment='center')
                self.ax2.text(0.5, 0.5, 'Please select a device', 
                    horizontalalignment='center', verticalalignment='center')
                self.fig.tight_layout()
                self.canvas.draw()
                return
            
            # Get data from DynamoDB
            dynamodb = boto3.resource('dynamodb')
            table = dynamodb.Table('fog_data')
            
            start_time = self.get_time_range().isoformat()
            
            # Query DynamoDB
            try:
                response = table.query(
                    KeyConditionExpression=Key('device_id').eq(device_id) & 
                                         Key('timestamp').gt(start_time)
                )
                
                if not response['Items']:
                    self.message_queue.put({
                        'type': 'log',
                        'content': f"No data available for device {device_id} in selected time range",
                        'level': 'INFO'
                    })
                    self.ax1.text(0.5, 0.5, 'No data available', 
                        horizontalalignment='center', verticalalignment='center')
                    self.ax2.text(0.5, 0.5, 'Try different time range', 
                        horizontalalignment='center', verticalalignment='center')
                    self.fig.tight_layout()
                    self.canvas.draw()
                    return
                
                # Convert to pandas DataFrame
                df = pd.DataFrame(response['Items'])
                df['timestamp'] = pd.to_datetime(df['timestamp'])
                df = df.sort_values('timestamp')
                
                # Extract values from messages and create new columns
                def extract_value(msg):
                    if 'ALERT: Value' in str(msg):
                        try:
                            # Extract just the value from "ALERT: Value X exceeded threshold Y"
                            return float(msg.split(' ')[2])
                        except:
                            return None
                    return None

                # Add value column for threshold exceeded data
                df['extracted_value'] = df['message'].apply(extract_value)
                
                # Separate normal and threshold exceeded data
                threshold_data = df[df['message'].str.contains('ALERT', na=False)].copy()
                normal_data = df[~df['message'].str.contains('ALERT', na=False)].copy()
                
                # Plot message frequency over time
                if not normal_data.empty:
                    normal_freq = normal_data.resample('5T', on='timestamp').size()
                    self.ax1.plot(normal_freq.index, normal_freq.values, 
                                marker='o', color='blue', label='Normal Values')
                
                if not threshold_data.empty:
                    threshold_freq = threshold_data.resample('5T', on='timestamp').size()
                    self.ax1.plot(threshold_freq.index, threshold_freq.values, 
                                marker='o', color='red', label='Exceeded Values')
                
                self.ax1.set_title('Message Frequency Over Time')
                self.ax1.set_xlabel('Time')
                self.ax1.set_ylabel('Messages per 5 minutes')
                self.ax1.tick_params(axis='x', rotation=45)
                self.ax1.legend()
                
                # Plot value distribution
                if 'value' in df.columns or 'extracted_value' in df.columns:
                    values = df['value'] if 'value' in df.columns else df['extracted_value']
                    values = values.dropna().astype(float)
                    
                    if not values.empty:
                        self.ax2.hist(values, bins=20, color='blue', alpha=0.7, 
                                    label='All Values')
                        
                        if 'threshold' in df.columns and not df['threshold'].empty:
                            threshold = float(df['threshold'].iloc[0])
                            self.ax2.axvline(x=threshold, color='red', 
                                           linestyle='--', label=f'Threshold ({threshold})')
                        
                        self.ax2.set_title('Value Distribution')
                        self.ax2.set_xlabel('Value')
                        self.ax2.set_ylabel('Count')
                        self.ax2.legend()
                else:
                    # Simplified message type display
                    message_counts = pd.Series({
                        'Normal': len(normal_data),
                        'Exceeded': len(threshold_data)
                    })
                    colors = ['blue', 'red']
                    self.ax2.bar(message_counts.index, message_counts.values, color=colors)
                    self.ax2.set_title('Message Type Distribution')
                    self.ax2.set_xlabel('Type')
                    self.ax2.set_ylabel('Count')
                
                self.ax2.tick_params(axis='x', rotation=45)
                
                # Adjust layout and display
                self.fig.tight_layout()
                self.canvas.draw()
                
                self.message_queue.put({
                    'type': 'log',
                    'content': "Data visualization updated successfully",
                    'level': 'SUCCESS'
                })
                
            except Exception as e:
                self.message_queue.put({
                    'type': 'log',
                    'content': f"Failed to query DynamoDB: {str(e)}",
                    'level': 'ERROR'
                })
                raise
                
        except Exception as e:
            self.message_queue.put({
                'type': 'log',
                'content': f"Failed to refresh data: {str(e)}",
                'level': 'ERROR'
            })
            self.ax1.text(0.5, 0.5, 'Error refreshing data', 
                horizontalalignment='center', verticalalignment='center')
            self.ax2.text(0.5, 0.5, str(e), 
                horizontalalignment='center', verticalalignment='center')
            self.fig.tight_layout()
            self.canvas.draw()

def initialize_shared_components():
    global shared_device_registry
    shared_device_registry = DeviceRegistry()

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
    
    # Initialize cloud connector
    app.cloud_connector = CloudConnector(message_queue)
    
    # Disable SSL for development
    app.config['PREFERRED_URL_SCHEME'] = 'http'
    
    # Use the shared device registry
    device_registry = shared_device_registry
    device_registry.set_message_queue(message_queue)
    
    # Initialize rate limiter
    rate_limiter = InMemoryRateLimiter()

    # Add rate limiting by device ID
    def rate_limit_by_device(device_id):
        return rate_limiter.is_allowed(device_id)

    # Create an instance of FogServerGUI to handle message processing
    class AppState:
        pass
    app.state = AppState()
    app.state.gui = None

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

            # Process the message
            combined_data = data['combined_data']
            key_id = data['key_id']
            signature = data['signature']
            
            # Verify key validity
            key_data = key_manager.get_key(key_id)
            if not key_data or key_data['expiration'] < datetime.now():
                message_queue.put({
                    'type': 'log',
                    'content': f"STEP 5: Invalid or expired key ID: {key_id}",
                    'level': 'ERROR'
                })
                return jsonify({"error": "Invalid or expired key ID"}), 403
            
            # Process the message using the GUI instance
            if app.state.gui:
                response = app.state.gui.process_message(combined_data, device_id)
            else:
                message_queue.put({
                    'type': 'log',
                    'content': "GUI instance not available",
                    'level': 'ERROR'
                })
                return jsonify({"error": "Server not ready"}), 500
            
            return jsonify({
                "message": "Message processed successfully",
                "decrypted_message": response
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
                # Force update of device list in GUI
                if app.state.gui and hasattr(app.state.gui, 'data_viz'):
                    app.state.gui.data_viz.update_device_list()
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

    @app.route('/test-cloud', methods=['GET'])
    @handle_errors
    def test_cloud():
        """Test cloud connection"""
        try:
            test_data = {
                'device_id': 'TEST_DEVICE',
                'message': 'Test message from fog server',
                'processed_at': datetime.now().isoformat()
            }
            
            message_queue.put({
                'type': 'log',
                'content': "Testing cloud connection...",
                'level': 'INFO'
            })
            
            success = app.cloud_connector.buffer_data(test_data)
            
            if success:
                return jsonify({"message": "Cloud test successful"}), 200
            else:
                return jsonify({"error": "Cloud test failed"}), 500
                
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # Add this route after the test-cloud route
    @app.route('/generate-test-data', methods=['GET'])
    @handle_errors
    def generate_test_data():
        """Generate test data for visualization"""
        try:
            test_messages = [
                "Temperature: 25°C",
                "Temperature: 26°C",
                "Temperature: 24°C",
                "Humidity: 65%",
                "Humidity: 70%",
                "Status: Normal",
                "Status: Warning",
                "Pressure: 1013 hPa",
                "CO2: 400 ppm",
                "Motion: Detected"
            ]
            
            message_queue.put({
                'type': 'log',
                'content': "Starting test data generation...",
                'level': 'INFO'
            })
            
            success_count = 0
            for message in test_messages:
                test_data = {
                    'device_id': 'TEST_DEVICE',
                    'message': message,
                    'processed_at': datetime.now().isoformat()
                }
                
                if app.cloud_connector.buffer_data(test_data):
                    success_count += 1
                time.sleep(1)  # Wait between messages
            
            message_queue.put({
                'type': 'log',
                'content': f"Generated {success_count} test messages successfully",
                'level': 'SUCCESS'
            })
                
            return jsonify({
                "message": f"Test data generated successfully ({success_count}/{len(test_messages)} messages)"
            }), 200
            
        except Exception as e:
            message_queue.put({
                'type': 'log',
                'content': f"Test data generation failed: {str(e)}",
                'level': 'ERROR'
            })
            return jsonify({"error": str(e)}), 500

    @app.route('/debug-data', methods=['GET'])
    @handle_errors
    def debug_data():
        """Debug data storage"""
        try:
            # Generate test data
            test_data = [
                {
                    'device_id': 'DEBUG_DEVICE',
                    'message': f'Debug Message {i}',
                    'processed_at': datetime.now().isoformat()
                } for i in range(5)
            ]
            
            # Send each message
            results = []
            for data in test_data:
                success = app.cloud_connector.buffer_data(data)
                results.append({
                    'message': data['message'],
                    'success': success
                })
            
            return jsonify({
                'message': 'Debug complete',
                'results': results
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/get-alerts', methods=['GET'])
    @handle_errors
    def get_alerts():
        """Endpoint for devices to poll for alerts with optimization"""
        device_id = request.args.get('device_id')
        last_alert_time = request.args.get('last_alert_time')
        
        if not device_id:
            return jsonify({"error": "Device ID required"}), 400
        
        try:
            # Convert last_alert_time to datetime if provided
            if last_alert_time:
                last_alert_time = datetime.fromisoformat(last_alert_time)
            
            # Get only new alerts since last check
            alerts = []  # You'll implement alert storage
            
            # Add rate limiting information to response
            return jsonify({
                "alerts": alerts,
                "next_poll": 10  # Suggest client wait 10 seconds
            })
            
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # Store key_manager and cloud_connector in app for GUI access
    app.key_manager = key_manager
    app.cloud_connector = CloudConnector(message_queue)
    
    # Initialize app state
    app.state = AppState()
    app.state.gui = None
    
    return app

def main():
    root = tk.Tk()
    gui = FogServerGUI(root)
    root.mainloop()

if __name__ == '__main__':
    # Initialize shared components first
    initialize_shared_components()
    # Then set message queue
    shared_device_registry.set_message_queue(queue.Queue())
    # Finally start the main application
    main()
