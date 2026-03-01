from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
import datetime



class Server:

    def __init__(self):

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        with open("private_key.pem", "wb"):
            pass
        with open("public_key.pem", "wb"):
            pass
        with open("certificate.pem", "wb"):
            pass
        with open("client_public_key.pem", "wb"):
            pass

        self.save_keys(private_key, public_key)


    def save_keys(self, private_key, public_key):
        
        with open("private_key.pem", "wb") as key_file:
            key_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )

        with open("public_key.pem", "wb") as key_file:
            key_file.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )


    def get_public_key(self):

        with open("public_key.pem", "rb") as key_file:
            key_pem = key_file.read()

        return key_pem
    

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
    

    def create_csr(self, common_name):
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([
                x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name),
            ])
        ).sign(self.get_private_key(), hashes.SHA256(), default_backend())


        csr_pem = csr.public_bytes(encoding=serialization.Encoding.PEM)
        return csr_pem
    
    
    def save_cert(self, cert_pem):

        with open("certificate.pem", "wb") as cert_file:
            cert_file.write(cert_pem)
    

    def get_cert(self):

        with open("certificate.pem", "rb") as cert_file:
            cert_pem = cert_file.read()

        return cert_pem
        

    def save_self_signed_certificate(self):
        subject = x509.Name([
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, u"CN"),
            x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, u"China"),
            x509.NameAttribute(x509.NameOID.LOCALITY_NAME, u"Hong Kong"),
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, u"Scam.INC"),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, u"SINK"),
        ])

        invalid_certificate = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            subject
        ).public_key(
            self.get_private_key().public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.UTC)
        ).not_valid_after(
            datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=3650)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        ).sign(self.get_private_key(), hashes.SHA256(), default_backend())

        cert_pem = invalid_certificate.public_bytes(encoding=serialization.Encoding.PEM)
        self.save_cert(cert_pem)