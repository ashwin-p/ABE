import socket
import json
import sqlite3
import base64
import hashlib
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# Connect to database
conn = sqlite3.connect('EHR.db')
cursor = conn.cursor()

def encrypt(plaintext, key):
    # Convert the plaintext and key to bytes
    plaintext_bytes = plaintext.encode('utf-8')
    
    # Pad the plaintext to a multiple of 128 bits (16 bytes)
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext_bytes) + padder.finalize()

    # Initialize the cipher with AES algorithm, ECB mode, and the provided key
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    # Encrypt the padded plaintext
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    return ciphertext

def handle_request(data):
    action = data.get('action')
    
    if action == 'login':
        return handleLogin(data)
    elif action == 'signup':
        return handleSignUp(data)
    else:
        return json.dumps({'error': 'Invalid action'}), 400


def handleLogin(request):
    """Check if valid credentaisl are given.

    If so return a login token or else notify the client
    """
    username = request.get('username')
    password = request.get('password')
    cursor.execute('SELECT * FROM USERS WHERE username = ? AND password = ?',
                   (username, password))
    exists = cursor.fetchone()
    if exists:
        return json.dumps({'success': username}), 200
    else:
        return json.dumps({'error': 'Invalid username or password'}), 401


def handleSignUp(request):
    """Add user to database.

    If user exists, notify the client
    """
    username = request.get('username')
    password = request.get('password')
    role = request.get('role')
    cursor.execute("SELECT MAX(user_id) FROM Users")
    maxUserId = cursor.fetchone()[0]
    newUserId = maxUserId + 1 if maxUserId is not None else 1

    try:
        cursor.execute("INSERT INTO Users (user_id, username, password, role)\
        VALUES (?, ?, ?, ?)", (newUserId, username, password, role))
        conn.commit()
        return json.dumps({'message': 'User signed up successfully'}), 200
    except sqlite3.IntegrityError:
        return json.dumps({'error': 'Username already exists'}), 400

def handleGetData(request):
    query = request.get('query')
    role = request.get('role')
    firstname = request.get('uname').split('.')[0]
    if role == 'patient' or role == 'doctor':
        if firstname not in query:
            return json.dumps({'error': 'Invalid query.'}), 400
    try:
        cursor.execute(query)
        res = cursor.fetchall()
        res = str(res)
        return json.dumps({'message': encrypt(res, "secret")}), 200
    except sqlite3.IntegrityError:
        return json.dumps({'error': 'Invalid query.'}), 400


def main():
    """Entry point for server."""
    server_address = ('localhost', 8888)
    buffer_size = 1024

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind(server_address)
        server_socket.listen(5)
        print('Server is listening on', server_address)

        while True:
            client_socket, client_address = server_socket.accept()
            print('Connection from', client_address)

            data = client_socket.recv(buffer_size).decode()
            print('Received data:', data)

            if data:
                request = json.loads(data)
                action = request.get('action')

                if action == 'login':
                    response, status = handleLogin(request)
                elif action == 'signup':
                    response, status = handleSignUp(request)
                elif action == 'getData':
                    response, status = handleGetData(request)
                else:
                    response = json.dumps({'error': 'Invalid action'}), 400
                    # status = 400
                client_socket.sendall(response.encode())
                print('Response sent:', response)

            client_socket.close()


if __name__ == '__main__':
    main()
