import socket
import json
import hashlib
import base64
import hashlib
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


isLoggedIn = False
uname = ""
urole = ""

def decrypt(ciphertext, key):
    # Convert the base64 encoded ciphertext to bytes
    ciphertext_bytes = base64.b64decode(ciphertext)

    # Initialize the cipher with AES algorithm, ECB mode, and the provided key
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    padded_plaintext = decryptor.update(ciphertext_bytes) + decryptor.finalize()

    # Unpad the plaintext
    unpadder = padding.PKCS7(128).unpadder()
    plaintext_bytes = unpadder.update(padded_plaintext) + unpadder.finalize()

    # Convert the plaintext bytes to a string
    plaintext = plaintext_bytes.decode('utf-8')

    return plaintext


def login_or_signup():
    while True:
        choice =\
            input("Do you want to login or signup? (login/signup): ").lower()
        if choice == 'login' or choice == 'signup':
            return choice
        else:
            print("Invalid choice. Please enter 'login' or 'signup'.")

 
def get_credentials():
    global uname
    global urole
    username = input("Enter your username: ")
    uname = username
    password = input("Enter your password: ")
    role = input("Enter your role: ")
    urole = role
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    return {'username': username, 'password': hashed_password, 'role': role}


def send_request(request):
    server_address = ('localhost', 8888)
    buffer_size = 1024

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect(server_address)
        # print('Connected to server:', server_address)

        client_socket.sendall(json.dumps(request).encode())
        # print('Request sent:', request)

        response = client_socket.recv(buffer_size).decode()
        # print('Response received:', response)

    return json.loads(response)

def buildQuery():
    query = "SELECT "
    print("Enter the table you want to fetch data from: ")
    print("1.Doctors\n2.HealthRecords\n3.Patients\n4.Users")
    choice = int(input("Enter number of desired table"))
    table = ['Doctors', 'HealthRecords', 'Patients', 'Users'][choice - 1]
    print("Enter the desired row names(space separated, * for all rows) ")
    rows = input()
    query = query + rows + " FROM " + table
    print("Would you like to include a where condition?(y/n) ")
    while True:
        needsWhere = input()
        if not (needsWhere == 'y' or needsWhere == 'n'):
            needsWhere = input("Invalid choice, try again")
        else:
            break
    if needsWhere == 'y':
        whereClause = input("Enter the conditon(e.g. id < 5) ")
        query = query + " WHERE " + whereClause
    query = query + ';'
    return {'query': query}

def notLoggedIn():
    global isLoggedIn
    while True:
        action = login_or_signup()
        if action == 'login':
            request = {'action': 'login', **get_credentials()}
        elif action == 'signup':
            request = {'action': 'signup', **get_credentials()}

        response = send_request(request)
        if response.get('error', '') != '':
            print('Error:', response.get('error', ''))
        else:
            print('Server message:', response.get('message', ''))
            if action == 'login':
                isLoggedIn = True
                break
def loggedIn():
    request = {'action': 'getData', **buildQuery(), 'role': urole}
    response = send_request(request)
    if response.get('error', '') != '':
        print('Error: ', response.get('error', ''))
    else:
        print('Query successful: ', decrypt(response.get('message', '')))

def main():
    global isLoggedIn
    global uname
    while True:
        while not isLoggedIn:
            notLoggedIn()
        while isLoggedIn:
            print('Do you want to get data or logout?(data/logout)')
            choice = input()
            if choice == 'logout':
                isLoggedIn = False
                break
            elif choice == 'data':
                print('Welcome, ', uname)
                loggedIn()

if __name__ == '__main__':
    main()
