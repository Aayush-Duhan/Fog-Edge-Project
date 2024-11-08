import requests
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import json
import urllib3
import tkinter as tk
from tkinter import ttk, scrolledtext
from datetime import datetime
import threading
import time
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class EdgeDeviceGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Edge Device Communication Monitor")
        self.root.geometry("800x600")
        
        # Configure style
        style = ttk.Style()
        style.configure("Success.TLabel", foreground="green")
        style.configure("Error.TLabel", foreground="red")
        
        # Create main frame
        main_frame = ttk.Frame(root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Status indicators
        self.status_frame = ttk.LabelFrame(main_frame, text="Status", padding="5")
        self.status_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        self.connection_status = ttk.Label(self.status_frame, text="⚪ Not Connected")
        self.connection_status.grid(row=0, column=0, padx=5)
        
        self.key_status = ttk.Label(self.status_frame, text="🔑 No Key")
        self.key_status.grid(row=0, column=1, padx=5)
        
        # Message input
        input_frame = ttk.LabelFrame(main_frame, text="Message Input", padding="5")
        input_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        self.message_input = ttk.Entry(input_frame, width=50)
        self.message_input.insert(0, "Hello from edge device!")
        self.message_input.grid(row=0, column=0, padx=5)
        
        self.send_button = ttk.Button(input_frame, text="Send Message", command=self.send_message_thread)
        self.send_button.grid(row=0, column=1, padx=5)
        
        # Log display
        log_frame = ttk.LabelFrame(main_frame, text="Communication Log", padding="5")
        log_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        self.log_display = scrolledtext.ScrolledText(log_frame, height=20, width=80)
        self.log_display.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Load keys
        with open("edge_private_key.pem", "rb") as key_file:
            self.private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )
        
        # Configuration
        self.FOG_SERVER_URL = "http://127.0.0.1:5000"
        self.SHARED_SECRET_KEY = "development-secret-key"
        
        # Device Authentication
        self.DEVICE_ID = "EDGE_001"  # Unique device identifier
        self.API_KEY = "your-secure-api-key-here"  # Secure API key
        self.device_registered = False
        
        # Configure requests session with retry logic
        self.session = requests.Session()
        retry_strategy = Retry(
            total=5,  # number of retries
            backoff_factor=1,  # wait 1, 2, 4, 8, 16 seconds between retries
            status_forcelist=[500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Add connection retry
        self.retry_connection()

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

    def update_status(self, connected=False, has_key=False):
        self.connection_status.config(
            text=f"{'🟢' if connected else '⚪'} {'Connected' if connected else 'Not Connected'}"
        )
        self.key_status.config(
            text=f"{'🔑' if has_key else '❌'} {'Key Active' if has_key else 'No Key'}"
        )

    def retry_connection(self):
        """Retry connection to server with backoff"""
        max_retries = 5
        retry_delay = 2  # seconds
        
        for attempt in range(max_retries):
            if self.check_server_connection():
                if self.register_device():
                    return True
            
            if attempt < max_retries - 1:  # Don't sleep on last attempt
                self.log_message(f"Retrying connection in {retry_delay} seconds... (Attempt {attempt + 1}/{max_retries})")
                time.sleep(retry_delay)
                retry_delay *= 2  # Exponential backoff
        
        return False

    def check_server_connection(self):
        """Check server connection and return True if successful"""
        try:
            response = self.session.get(
                f"{self.FOG_SERVER_URL}/get-current-key",
                verify=False,
                allow_redirects=False,
                timeout=5
            )
            if response.status_code == 200:
                self.log_message("Successfully connected to fog server", "SUCCESS")
                self.update_status(connected=True)
                return True
            else:
                self.log_message(f"Failed to connect to fog server: {response.status_code}", "ERROR")
                self.update_status(connected=False)
                return False
        except requests.exceptions.RequestException as e:
            self.log_message(f"Server connection failed: {str(e)}", "ERROR")
            self.update_status(connected=False)
            return False

    def fetch_current_key(self):
        self.log_message("Fetching encryption key from fog server...")
        try:
            response = self.session.get(
                f"{self.FOG_SERVER_URL}/get-current-key",
                verify=False,
                allow_redirects=False,
                timeout=5
            )
            response.raise_for_status()
            data = response.json()
            self.log_message("Successfully received encryption key", "SUCCESS")
            self.update_status(connected=True, has_key=True)
            return data["key_id"], data["encryption_key"]
        except requests.exceptions.RequestException as e:
            self.log_message(f"Failed to fetch encryption key: {str(e)}", "ERROR")
            self.update_status(connected=False, has_key=False)
            raise

    def create_auth_token(self):
        return base64.urlsafe_b64encode(self.SHARED_SECRET_KEY.encode()).decode()

    def sign_message(self, message: str) -> str:
        signature = self.private_key.sign(
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()

    def send_message_thread(self):
        # Disable send button while processing
        self.send_button.config(state='disabled')
        # Start message sending in a separate thread
        threading.Thread(target=self.send_message, daemon=True).start()

    def send_message(self):
        try:
            self.log_message("STEP 1: Starting message transmission process", "INFO")
            
            if not self.device_registered:
                self.log_message("STEP 1.1: Device not registered, initiating registration", "INFO")
                if not self.retry_connection():
                    self.log_message("STEP 1.2: Registration failed, aborting", "ERROR")
                    return
                self.log_message("STEP 1.3: Registration successful", "SUCCESS")

            # Get the message from input
            message = self.message_input.get()
            self.log_message("STEP 2: Message prepared: " + message, "INFO")
            
            # Get the current encryption key
            self.log_message("STEP 3: Requesting encryption key from fog server", "INFO")
            key_id, encryption_key = self.fetch_current_key()
            self.log_message(f"STEP 3.1: Received key ID: {key_id}", "SUCCESS")
            
            # Create Fernet cipher suite
            self.log_message("STEP 4: Initializing encryption", "INFO")
            cipher_suite = Fernet(encryption_key.encode())
            
            # Encrypt the message
            encrypted_message = cipher_suite.encrypt(message.encode()).decode()
            self.log_message("STEP 4.1: Message encrypted successfully", "SUCCESS")
            
            # Create auth token
            self.log_message("STEP 5: Generating authentication token", "INFO")
            auth_token = self.create_auth_token()
            self.log_message("STEP 5.1: Auth token generated", "SUCCESS")
            
            # Combine auth token and encrypted message
            combined_data = f"{auth_token}::{encrypted_message}"
            self.log_message("STEP 6: Combined auth token with encrypted message", "SUCCESS")
            
            # Sign the combined data
            self.log_message("STEP 7: Signing message with private key", "INFO")
            signature = self.sign_message(combined_data)
            self.log_message("STEP 7.1: Digital signature created", "SUCCESS")
            
            # Prepare the payload
            self.log_message("STEP 8: Preparing payload with device authentication", "INFO")
            payload = {
                "device_id": self.DEVICE_ID,
                "api_key": self.API_KEY,
                "combined_data": combined_data,
                "key_id": key_id,
                "signature": signature
            }
            self.log_message("STEP 8.1: Payload prepared", "SUCCESS")
            
            # Send the request
            self.log_message("STEP 9: Sending message to fog server", "INFO")
            response = self.session.post(
                f"{self.FOG_SERVER_URL}/process-data",
                json=payload,
                verify=False,
                allow_redirects=False
            )
            
            # Handle the response
            if response.status_code == 200:
                response_data = response.json()
                self.log_message("STEP 10: Message delivered successfully!", "SUCCESS")
                self.log_message(f"STEP 10.1: Server response: {response_data['decrypted_message']}", "SUCCESS")
            else:
                self.log_message(f"STEP 10: Delivery failed - {response.status_code} - {response.text}", "ERROR")
                
        except Exception as e:
            self.log_message(f"Process failed: {str(e)}", "ERROR")
        finally:
            self.root.after(0, lambda: self.send_button.config(state='normal'))

    def register_device(self):
        """Register the device with the fog server"""
        try:
            response = self.session.post(
                f"{self.FOG_SERVER_URL}/register-device",
                json={
                    "device_id": self.DEVICE_ID,
                    "api_key": self.API_KEY,
                    "device_type": "edge_sensor",
                    "capabilities": ["temperature", "humidity"],
                    "public_key": self.get_public_key()
                },
                verify=False,
                timeout=5
            )
            if response.status_code == 200:
                self.device_registered = True
                self.log_message("Device registered successfully", "SUCCESS")
                return True
            else:
                self.log_message(f"Device registration failed: {response.text}", "ERROR")
                return False
        except Exception as e:
            self.log_message(f"Registration error: {str(e)}", "ERROR")
            return False

    def get_public_key(self):
        """Export device's public key for registration"""
        public_key = self.private_key.public_key()
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode()

def main():
    root = tk.Tk()
    app = EdgeDeviceGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
