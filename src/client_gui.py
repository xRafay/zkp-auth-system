import tkinter as tk
from tkinter import messagebox
import socket
import secrets
import ssl
import logging
from argon2.low_level import hash_secret, Type

# Set up logging to debug issues
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

N = int('EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3', 16)
g = 2
q = (N - 1) // 2
BYTE_LEN = (N.bit_length() + 7) // 8

def int_to_bytes(i: int) -> bytes:
    return i.to_bytes(BYTE_LEN, 'big')

def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, 'big')

def derive_x(password: str, salt: bytes) -> int:
    raw_hash = hash_secret(
        password.encode('utf-8'),
        salt,
        time_cost=3,
        memory_cost=64 * 1024,
        parallelism=4,
        hash_len=32,
        type=Type.ID
    )
    return bytes_to_int(raw_hash) % q

class AuthApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ZKP Authentication System")
        self.root.geometry("400x300")
        
        tk.Label(root, text="Username").pack(pady=10)
        self.username_entry = tk.Entry(root)
        self.username_entry.pack()
        
        tk.Label(root, text="Password").pack(pady=10)
        self.password_entry = tk.Entry(root, show="*")
        self.password_entry.pack()
        
        tk.Button(root, text="Register", command=self.register).pack(pady=10)
        tk.Button(root, text="Login", command=self.login).pack(pady=10)
        
        self.status_label = tk.Label(root, text="")
        self.status_label.pack(pady=10)
    
    def connect(self):
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(10)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            secure_client = context.wrap_socket(client, server_hostname="localhost")
            secure_client.connect(('localhost', 12345))
            logging.debug("Connected to server at localhost:12345")
            return secure_client
        except Exception as e:
            logging.error(f"Connection failed: {e}")
            raise
    
    def register(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not username or not password:
            logging.warning("Empty username or password entered")
            messagebox.showerror("Error", "Please enter username and password")
            self.status_label.config(text="Error: Empty input")
            return
        
        try:
            client = self.connect()
            client.send(b'register')
            client.send(username.encode('utf-8'))
            logging.debug(f"Sent register command for username: {username}")
            
            salt = secrets.token_bytes(16)
            x = derive_x(password, salt)
            verifier = pow(g, x, N)
            
            client.send(salt)
            client.send(int_to_bytes(verifier))
            logging.debug("Sent salt and verifier")
            
            response = client.recv(1024).decode('utf-8')
            logging.debug(f"Received response: {response}")
            self.status_label.config(text=response)
            messagebox.showinfo("Result", response)
            client.close()
        except Exception as e:
            error_msg = f"Registration failed: {e}"
            logging.error(error_msg)
            messagebox.showerror("Error", error_msg)
            self.status_label.config(text="Registration failed")
    
    def login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not username or not password:
            logging.warning("Empty username or password entered")
            messagebox.showerror("Error", "Please enter username and password")
            self.status_label.config(text="Error: Empty input")
            return
        
        try:
            client = self.connect()
            client.send(b'login')
            client.send(username.encode('utf-8'))
            logging.debug(f"Sent login command for username: {username}")
            
            salt = client.recv(16)
            logging.debug(f"Received salt: {salt.hex()}, length: {len(salt)}")
            x = derive_x(password, salt)
            
            k = secrets.randbelow(q)
            t = pow(g, k, N)
            client.send(int_to_bytes(t))
            logging.debug("Sent t value")
            
            e_bytes = client.recv(BYTE_LEN)
            e = bytes_to_int(e_bytes)
            logging.debug("Received e value")
            
            s = (k + e * x) % q
            client.send(int_to_bytes(s))
            logging.debug("Sent s value")
            
            response = client.recv(1024).decode('utf-8')
            logging.debug(f"Received response: {response}")
            self.status_label.config(text=response)
            messagebox.showinfo("Result", response)
            client.close()
        except Exception as e:
            error_msg = f"Login failed: {e}"
            logging.error(error_msg)
            messagebox.showerror("Error", error_msg)
            self.status_label.config(text="Login failed")

if __name__ == "__main__":
    root = tk.Tk()
    app = AuthApp(root)
    root.mainloop()