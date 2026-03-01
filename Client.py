from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
import pickle
import webbrowser
import requests
import base64
import warnings
from urllib3.exceptions import InsecureRequestWarning



class Client:

    def __init__(self):

        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        self.established_connection = False

        warnings.filterwarnings('ignore', category=InsecureRequestWarning)


    def encrypt_message(self, public_key, message):

        encrypted_message = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_message
    
    def decrypt_message(self, encrypted_message):

        decrypted_message = self.private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_message.decode()


    def get_public_key(self):

        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    

    def verify_certificate(self, server, ca):

        cert_pem = server.get_cert()

        if cert_pem == None:
            return False

        cert = x509.load_pem_x509_certificate(cert_pem)
        ca_cert_pem = ca.get_cert()
        ca_public_key = x509.load_pem_x509_certificate(ca_cert_pem).public_key()
        
        if pickle.loads(ca.check_certificate(cert_pem)) != "Valid certificate":
            return False

        try:
            ca_public_key.verify(
                cert.signature, 
                cert.tbs_certificate_bytes, 
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
            return True
        except Exception as e:
            return False
        

    def connect_to_app(self, server, ca):

        cert_is_valid = self.verify_certificate(server, ca)

        if cert_is_valid:
            print("Certificate check successful")

            self.send_public_key_to_web()

            print("Connection with website established")
            #webbrowser.open('https://localhost:443')
            self.established_connection = True

        else:
            print("Can't connect to the website because of an invalid certificate")


    def send_public_key_to_web(self):

        client_public_key_bytes = self.get_public_key()
        client_public_key = serialization.load_pem_public_key(client_public_key_bytes, backend=default_backend())

        client_public_key_pem = client_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        response = requests.post(
            f"https://localhost:443/establish_connection", 
            json={"key": client_public_key_pem},
            verify=False 
        )

        if response.status_code == 200:
            print("Public key sent successfully:", response.json())
        else:
            try:
                error_message = response.json()
            except requests.JSONDecodeError:
                error_message = response.text
            print("Failed to send public key:", error_message)


    def request_update(self, server, new_text):

        if not self.established_connection:
            print("Client must first establish connection with the web page.")
            return

        server_public_key_bytes = server.get_public_key()
        server_public_key = serialization.load_pem_public_key(server_public_key_bytes, backend=default_backend())
        encrypted_text = self.encrypt_message(server_public_key, new_text)
        encrypted_text_b64 = base64.b64encode(encrypted_text).decode('utf-8')

        update_response = requests.post(f"https://localhost:443/update_text", json={"text": encrypted_text_b64}, verify=False)

        if update_response.status_code == 200:
            print("Text updated successfully.")
        else:
            print("Failed to update text:", update_response.json())


    def request_text(self):

        if not self.established_connection:
            print("Client must first establish connection with the web page.")
            return

        get_response = requests.get(f"https://localhost:443/get_text", verify=False)

        if get_response.status_code == 200:
            current_text_encrypted = get_response.json().get("text", "")
            current_text_encrypted_bytes = base64.b64decode(current_text_encrypted)
            current_text = self.decrypt_message(current_text_encrypted_bytes)

            print("Text currently on the web page:", current_text)
        else:
            print("Failed to retrieve text:", get_response.json())