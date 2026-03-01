from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
import datetime
from datetime import timezone
import pickle



class Certificate_Authority:

    def __init__(self):

        with open("private_key.pem", "wb"):
            pass
        with open("public_key.pem", "wb"):
            pass
        with open("certificate.pem", "wb"):
            pass


        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        public_key = private_key.public_key()

        self.save_keys(private_key, public_key)

        subject = x509.Name([
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, u"SR"),
            x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, u"Slovakia"),
            x509.NameAttribute(x509.NameOID.LOCALITY_NAME, u"Trnava"),
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, u"CNK"),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, u"CNK"),
        ])

        ca_certificate = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            subject
        ).public_key(
            serialization.load_pem_public_key(
                self.get_public_key(),
                backend=default_backend()
            )
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.UTC)
        ).not_valid_after(
            datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=3650)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        ).sign(self.get_private_key(), hashes.SHA256(), default_backend())

        cert_pem = ca_certificate.public_bytes(encoding=serialization.Encoding.PEM)
        self.save_cert(cert_pem)

        self.certificate_logs = {}


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
        

    def sign_csr(self, csr):

        cert = x509.CertificateBuilder().subject_name(
            csr.subject
        ).issuer_name(
            x509.load_pem_x509_certificate(
                self.get_cert(),
                backend=default_backend()
            ).subject
        ).public_key(
            csr.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.UTC)
        ).not_valid_after(
            datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=3650)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        ).sign(self.get_private_key(), hashes.SHA256(), default_backend())

        self.log_certificate(cert)

        return cert
    

    def receive_csr(self, csr_pem):
        csr = x509.load_pem_x509_csr(csr_pem, default_backend())

        if self.check_csr_exists(csr):
            return None
        else:
            signed_cert = self.sign_csr(csr)
            return signed_cert.public_bytes(encoding=serialization.Encoding.PEM)
        

    def check_csr_exists(self, csr):
        for cert_data in self.certificate_logs.values():
            issued_cert_pubkey = cert_data['certificate'].public_key() 
            if csr.public_key().public_numbers() == issued_cert_pubkey.public_numbers():
                return True
        return False
    
        
    def log_certificate(self, cert):
        self.certificate_logs[cert.serial_number] = {'certificate': cert, 'revoked': False}


    def display_logs(self):
        for serial_number, details in self.certificate_logs.items():
            cert = details['certificate']
            revoked_status = "Revoked" if details['revoked'] else "Valid"
            print(f"Serial Number: {serial_number}, Status: {revoked_status}, Not Valid After: {cert.not_valid_after_utc}")


    def check_certificate(self, cert_pem):

        cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
        serial_number = cert.serial_number

        if serial_number in self.certificate_logs:
            is_revoked = self.certificate_logs[serial_number]['revoked']
            expiration_date = self.certificate_logs[serial_number]['certificate'].not_valid_after_utc
            expiration_date = expiration_date.replace(tzinfo=timezone.utc)

            if is_revoked:
                return pickle.dumps("Revoked certificate")
            elif datetime.datetime.now(datetime.UTC) > expiration_date:
                return pickle.dumps("Expired certificate")
            else:
                return pickle.dumps("Valid certificate")
        else:
            return pickle.dumps("Certificate not issued")


    def revoke_certificate(self, cert_pem):
        if cert_pem is None:
            return
        cert = x509.load_pem_x509_certificate(cert_pem)
        serial_number = cert.serial_number
        if serial_number in self.certificate_logs:
            self.certificate_logs[serial_number]['revoked'] = True


    def remove_certificate(self, cert_pem):
        if cert_pem is None:
            return
        cert = x509.load_pem_x509_certificate(cert_pem)
        if cert.serial_number in self.certificate_logs:
            del self.certificate_logs[cert.serial_number]
    
    
    def save_cert(self, cert_pem):

        with open("certificate.pem", "wb") as cert_file:
            cert_file.write(cert_pem)
    

    def get_cert(self):

        with open("certificate.pem", "rb") as cert_file:
            cert_pem = cert_file.read()

        return cert_pem

