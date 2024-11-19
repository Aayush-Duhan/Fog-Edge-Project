import requests
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import json
import urllib3
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from datetime import datetime
import threading
import time
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class EdgeDeviceGUI:
    # Add device counter for unique IDs
    device_counter = 0
    
    def __init__(self, root, device_id=None):
        self.root = root
        
        # Generate unique device ID if not provided
        if device_id is None:
            EdgeDeviceGUI.device_counter += 1
            self.device_id = f"EDGE_{EdgeDeviceGUI.device_counter:03d}"  # Format: EDGE_001, EDGE_002, etc.
        else:
            self.device_id = device_id
            
        self.root.title(f"Edge Device - {self.device_id}")
        
        # Main frame
        main_frame = ttk.Frame(root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Value input frame
        input_frame = ttk.LabelFrame(main_frame, text="Value Input", padding="5")
        input_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(input_frame, text="Enter Float Value:").grid(row=0, column=0, padx=5)
        self.value_entry = ttk.Entry(input_frame)
        self.value_entry.grid(row=0, column=1, padx=5)
        self.value_entry.insert(0, "0.0")
        
        self.send_button = ttk.Button(input_frame, text="Send Value", 
                                    command=self.send_value, state='disabled')
        self.send_button.grid(row=0, column=2, padx=5)
        
        self.register_button = ttk.Button(input_frame, text="Register Device", 
                                        command=self.register_device)
        self.register_button.grid(row=0, column=3, padx=5)
        
        # Auto-send frame
        auto_frame = ttk.LabelFrame(main_frame, text="Auto Send", padding="5")
        auto_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5)
        
        self.auto_send_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(auto_frame, text="Enable Auto Send", 
                       variable=self.auto_send_var,
                       command=self.toggle_auto_send).grid(row=0, column=0, padx=5)
        
        ttk.Label(auto_frame, text="Interval (seconds):").grid(row=0, column=1, padx=5)
        self.interval_entry = ttk.Entry(auto_frame, width=10)
        self.interval_entry.grid(row=0, column=2, padx=5)
        self.interval_entry.insert(0, "5")
        
        # Response display
        response_frame = ttk.LabelFrame(main_frame, text="Server Response", padding="5")
        response_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=5)
        
        self.response_display = scrolledtext.ScrolledText(response_frame, height=10, width=50)
        self.response_display.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
        # Initialize other variables
        self.current_key_id = None
        self.encryption_key = None
        self.auto_send_thread = None
        self.auto_send_active = False
        
        # Add device registration status
        self.is_registered = False
        
        # Add status label
        status_frame = ttk.LabelFrame(main_frame, text="Device Status", padding="5")
        status_frame.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=5)
        
        self.status_label = ttk.Label(status_frame, text="🔴 Not Registered")
        self.status_label.grid(row=0, column=0, padx=5)
        
        # Load keys
        self.load_keys()
        
        # Setup retry strategy with longer timeouts
        retry_strategy = Retry(
            total=5,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST"]  # Add allowed methods
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session = requests.Session()
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Add delay before first connection attempt
        self.root.after(2000, self.get_encryption_key)  # Wait 2 seconds before first attempt
        
        # Add alert display frame
        alert_frame = ttk.LabelFrame(main_frame, text="Alerts", padding="5")
        alert_frame.grid(row=4, column=0, sticky=(tk.W, tk.E), pady=5)
        
        self.alert_display = scrolledtext.ScrolledText(alert_frame, height=5, width=50)
        self.alert_display.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
        # Add alert polling interval (10 seconds instead of 1)
        self.alert_poll_interval = 10000  # milliseconds
        
        # Add alert status tracking
        self.last_alert_time = None

    def load_keys(self):
        try:
            with open("edge_private_key.pem", "rb") as key_file:
                self.private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None
                )
            self.log_message("Keys loaded successfully", "SUCCESS")
        except Exception as e:
            self.log_message(f"Error loading keys: {str(e)}", "ERROR")

    def setup_retry_session(self):
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session = requests.Session()
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def get_encryption_key(self):
        """Get encryption key with retry mechanism"""
        if not self.is_registered:
            self.log_message("Please register the device first", "INFO")
            return
            
        max_retries = 5
        retry_delay = 2  # seconds
        
        for attempt in range(max_retries):
            try:
                response = self.session.get('http://localhost:5000/get-current-key')
                if response.status_code == 200:
                    data = response.json()
                    self.current_key_id = data['key_id']
                    self.encryption_key = data['encryption_key']
                    self.log_message("Received new encryption key", "SUCCESS")
                    return
                else:
                    self.log_message(f"Failed to get encryption key (Attempt {attempt + 1}/{max_retries})", "ERROR")
            except Exception as e:
                self.log_message(f"Connection error (Attempt {attempt + 1}/{max_retries}): Server might not be ready", "INFO")
                if attempt < max_retries - 1:  # Don't sleep on the last attempt
                    time.sleep(retry_delay)
                    continue
                self.log_message("Failed to connect to server after all retries", "ERROR")

    def send_value(self):
        if not self.is_registered:
            self.log_message("Please register the device first", "ERROR")
            return
            
        try:
            # Get the value from entry
            value_str = self.value_entry.get()
            try:
                value = float(value_str)
            except ValueError:
                messagebox.showerror("Error", "Please enter a valid number")
                return
            
            # Create and encrypt message
            message = str(value)
            if not self.encryption_key:
                self.get_encryption_key()
            
            if not self.encryption_key:
                self.log_message("No encryption key available. Please ensure device is registered.", "ERROR")
                return
            
            cipher_suite = Fernet(self.encryption_key.encode())
            encrypted_message = cipher_suite.encrypt(message.encode()).decode()
            
            # Create auth token
            auth_token = base64.urlsafe_b64encode(b'development-secret-key').decode()
            
            # Combine auth token and encrypted message
            combined_data = f"{auth_token}::{encrypted_message}"
            
            # Sign the combined data
            signature = base64.b64encode(
                self.private_key.sign(
                    combined_data.encode(),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            ).decode()
            
            # Send to server
            response = self.session.post(
                'http://localhost:5000/process-data',
                json={
                    'device_id': self.device_id,
                    'api_key': f'test-api-key-{self.device_id}',
                    'combined_data': combined_data,
                    'key_id': self.current_key_id,
                    'signature': signature
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                encrypted_response = data.get('decrypted_message', '')
                
                try:
                    # Decrypt the response using the same cipher suite
                    decrypted_response = cipher_suite.decrypt(encrypted_response.encode()).decode()
                    
                    # Handle the decrypted response
                    if decrypted_response == "Threshold Exceeded":
                        self.log_message("⚠️ ALERT: Threshold Exceeded!", "WARNING")
                    else:
                        try:
                            returned_value = float(decrypted_response)
                            self.log_message(f"Value processed: {returned_value}", "SUCCESS")
                        except ValueError:
                            self.log_message(f"Unexpected response format: {decrypted_response}", "ERROR")
                except Exception as e:
                    self.log_message(f"Error decrypting response: {str(e)}", "ERROR")
            else:
                self.log_message(f"Error: {response.text}", "ERROR")
                
        except Exception as e:
            self.log_message(f"Error sending value: {str(e)}", "ERROR")

    def toggle_auto_send(self):
        if not self.is_registered:
            self.log_message("Please register the device first", "ERROR")
            self.auto_send_var.set(False)
            return
            
        if self.auto_send_var.get():
            try:
                interval = float(self.interval_entry.get())
                self.auto_send_active = True
                self.auto_send_thread = threading.Thread(target=self.auto_send_loop)
                self.auto_send_thread.daemon = True
                self.auto_send_thread.start()
                self.log_message("Auto-send started", "INFO")
            except ValueError:
                messagebox.showerror("Error", "Please enter a valid interval")
                self.auto_send_var.set(False)
        else:
            self.auto_send_active = False
            self.log_message("Auto-send stopped", "INFO")

    def auto_send_loop(self):
        while self.auto_send_active:
            self.send_value()
            try:
                interval = float(self.interval_entry.get())
                time.sleep(interval)
            except ValueError:
                self.auto_send_active = False
                self.auto_send_var.set(False)
                self.log_message("Auto-send stopped due to invalid interval", "ERROR")
                break

    def log_message(self, message, level="INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        if level == "ERROR":
            prefix = "❌ ERROR"
        elif level == "SUCCESS":
            prefix = "✅ SUCCESS"
        elif level == "WARNING":
            prefix = "⚠️ WARNING"
        else:
            prefix = "ℹ️ INFO"
            
        log_entry = f"[{timestamp}] {prefix}: {message}\n"
        self.response_display.insert(tk.END, log_entry)
        self.response_display.see(tk.END)

    def register_device(self):
        try:
            # Update registration data with unique device ID
            registration_data = {
                'device_id': self.device_id,
                'api_key': f'test-api-key-{self.device_id}',  # Unique API key per device
                'device_type': 'sensor',
                'capabilities': ['temperature', 'humidity'],
                'public_key': self.get_public_key()
            }
            
            response = self.session.post(
                'http://localhost:5000/register-device',
                json=registration_data
            )
            
            if response.status_code == 200:
                self.log_message("Device registered successfully", "SUCCESS")
                self.is_registered = True
                self.status_label.config(text="🟢 Registered")
                self.send_button.config(state='normal')  # Enable send button
                self.register_button.config(state='disabled')  # Disable register button
                
                # Start alert polling after registration
                self.start_alert_polling()
                
                # Get encryption key after successful registration
                self.get_encryption_key()
                return True
            else:
                self.log_message(f"Registration failed: {response.text}", "ERROR")
                return False
                
        except Exception as e:
            self.log_message(f"Registration error: {str(e)}", "ERROR")
            return False

    def get_public_key(self):
        """Get public key in PEM format"""
        public_key = self.private_key.public_key()
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode('utf-8')

    def start_alert_polling(self):
        """Start polling for alerts with a longer interval"""
        if not hasattr(self, 'last_poll_time'):
            self.last_poll_time = time.time()
        self.poll_alerts()

    def poll_alerts(self):
        """Poll server for alerts every 10 seconds"""
        if self.is_registered:
            current_time = time.time()
            
            try:
                response = self.session.get(
                    'http://localhost:5000/get-alerts',
                    params={
                        'device_id': self.device_id,
                        'last_alert_time': self.last_alert_time.isoformat() if self.last_alert_time else None
                    }
                )
                
                if response.status_code == 200:
                    alerts = response.json().get('alerts', [])
                    if alerts:  # Only process if there are new alerts
                        for alert in alerts:
                            self.display_alert(alert)
                        self.last_alert_time = datetime.now()
                        
            except Exception as e:
                # Only log polling errors every minute to reduce spam
                if current_time - self.last_poll_time >= 60:
                    self.log_message(f"Error polling alerts: {str(e)}", "ERROR")
                    self.last_poll_time = current_time
            
            # Schedule next poll with longer interval
            self.root.after(self.alert_poll_interval, self.poll_alerts)

    def display_alert(self, alert_message):
        """Display alert in the alert display"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        alert_entry = f"[{timestamp}] 🚨 {alert_message}\n"
        self.alert_display.insert(tk.END, alert_entry)
        self.alert_display.see(tk.END)
        
        # Flash the window to get attention
        self.root.attributes('-topmost', True)
        self.root.attributes('-topmost', False)
        
        # Optional: Play a sound
        self.root.bell()

# Add function to create new edge device window
def create_new_edge_device():
    new_window = tk.Toplevel()
    EdgeDeviceGUI(new_window)

def main():
    root = tk.Tk()
    root.title("Edge Device Manager")
    
    # Create frame for buttons
    button_frame = ttk.Frame(root, padding="10")
    button_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
    
    # Add button to create new edge device
    ttk.Button(
        button_frame, 
        text="Create New Edge Device", 
        command=create_new_edge_device
    ).grid(row=0, column=0, padx=5, pady=5)
    
    # Create first edge device
    create_new_edge_device()
    
    root.mainloop()

if __name__ == "__main__":
    main()
