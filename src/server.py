import socket
import threading
import sqlite3
import secrets
import logging
import ssl
import os
from argon2.low_level import hash_secret, Type

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

N = int('EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3', 16)
g = 2
q = (N - 1) // 2
BYTE_LEN = (N.bit_length() + 7) // 8

def int_to_bytes(i: int) -> bytes:
    return i.to_bytes(BYTE_LEN, 'big')

def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, 'big')

# Set database path to root directory (zkp-auth-system)
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'users.db')

# Initialize database in main thread
if not os.path.exists(DB_PATH):
    logging.info("Creating database...")
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users 
                      (username TEXT PRIMARY KEY, salt BLOB, verifier BLOB)''')
    conn.commit()
    conn.close()

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

def handle_client(client_socket: socket.socket):
    # Create a new SQLite connection for this thread
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cursor = conn.cursor()
    
    try:
        command = client_socket.recv(1024).decode('utf-8')
        username = client_socket.recv(1024).decode('utf-8')
        logging.debug(f"Received command: {command}, username: {username}")
        
        if command == 'register':
            salt = client_socket.recv(16)
            logging.debug(f"Received salt: {salt.hex()}, length: {len(salt)}")
            verifier_bytes = client_socket.recv(BYTE_LEN)
            verifier = bytes_to_int(verifier_bytes)
            logging.debug(f"Received verifier, length: {len(verifier_bytes)}")
            
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            if cursor.fetchone():
                client_socket.send(b'Username exists')
                logging.debug(f"Username {username} already exists")
                return
            
            cursor.execute("INSERT INTO users (username, salt, verifier) VALUES (?, ?, ?)",
                           (username, salt, verifier_bytes))
            conn.commit()
            client_socket.send(b'Registration successful')
            logging.info(f"User {username} registered")
        
        elif command == 'login':
            cursor.execute("SELECT salt, verifier FROM users WHERE username = ?", (username,))
            result = cursor.fetchone()
            if not result:
                client_socket.send(b'User not found')
                logging.debug(f"User {username} not found")
                return
            salt, verifier_bytes = result
            logging.debug(f"Retrieved salt: {salt.hex()}, length: {len(salt)}")
            verifier = bytes_to_int(verifier_bytes)
            
            client_socket.send(salt)
            logging.debug(f"Sent salt to client, length: {len(salt)}")
            
            t_bytes = client_socket.recv(BYTE_LEN)
            t = bytes_to_int(t_bytes)
            logging.debug(f"Received t, length: {len(t_bytes)}")
            
            e = secrets.randbelow(q)
            client_socket.send(int_to_bytes(e))
            logging.debug(f"Sent e")
            
            s_bytes = client_socket.recv(BYTE_LEN)
            s = bytes_to_int(s_bytes)
            logging.debug(f"Received s, length: {len(s_bytes)}")
            
            left = pow(g, s, N)
            right = (t * pow(verifier, e, N)) % N
            if left == right:
                client_socket.send(b'Authentication successful')
                logging.info(f"User {username} authenticated")
            else:
                client_socket.send(b'Authentication failed')
                logging.warning(f"Authentication failed for {username}")
    
    except Exception as ex:
        logging.error(f"Error handling client: {ex}")
    finally:
        conn.close()
        client_socket.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 12345))
    server.listen(5)
    
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="../certs/server.crt", keyfile="../certs/server.key")
    
    secure_server = context.wrap_socket(server, server_side=True)
    
    logging.info("Secure server listening on localhost:12345")
    
    while True:
        client_socket, addr = secure_server.accept()
        logging.info(f"Secure connection from {addr}")
        threading.Thread(target=handle_client, args=(client_socket,)).start()

if __name__ == "__main__":
    start_server()
