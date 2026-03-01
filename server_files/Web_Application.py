from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import base64
from Server import Server


class Web_Application:
    
    def __init__(self):
        Server().save_self_signed_certificate()
        self.app = Flask(__name__)

        self.app.add_url_rule('/', 'home', self.home)
        self.app.add_url_rule('/update_text', 'update_text', self.update_text, methods=['POST'])
        self.app.add_url_rule('/get_text', 'get_text', self.get_text, methods=['GET'])
        self.app.add_url_rule('/establish_connection', 'establish_connection', self.save_key, methods=['POST'])

        self.text = "Default text"


    def home(self):
        return self.text
    

    def run(self, **kwargs):
        self.app.run(ssl_context=("certificate.pem", 
                                  "private_key.pem"), port=443, **kwargs)
        
    
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
    

    def get_client_public_key(self):

        with open("client_public_key.pem", "rb") as key_file:
            key_pem = key_file.read()

        key = serialization.load_pem_public_key(key_pem, backend=default_backend())

        return key
    
    
    def get_private_key(self):

        with open("private_key.pem", "rb") as key_file:

            key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )

        return key
    
    def decrypt_message(self, encrypted_message):

        decrypted_message = self.get_private_key().decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_message.decode()


    def update_text(self):

        data = request.json
        if 'text' in data:
            encrypted_text = data['text']
            encrypted_text_bytes = base64.b64decode(encrypted_text)

            self.text = self.decrypt_message(encrypted_text_bytes)

            return jsonify({"message": "Text updated successfully"}), 200
        else:
            return jsonify({"error": "No text provided"}), 400
        
    def get_text(self):

        client_key = self.get_client_public_key()
        encrypted_text = self.encrypt_message(client_key, self.text)
        encrypted_text_b64 = base64.b64encode(encrypted_text).decode('utf-8')

        return jsonify({"text": encrypted_text_b64})
    

    def save_key(self):
        data = request.json

        if 'key' in data:
            client_key_pem = data['key']

            client_key = serialization.load_pem_public_key(
                client_key_pem.encode('utf-8'),
                backend=default_backend()
            )

            with open("client_public_key.pem", "wb") as key_file:
                key_file.write(
                    client_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
            )
            return jsonify({"message": "Public key received successfuly"}), 200
        
        else:
            return jsonify({"error": "No key provided"}), 400


        

if __name__ == "__main__":
    
    app = Web_Application()
    app.run(host='127.0.0.1', debug=True)