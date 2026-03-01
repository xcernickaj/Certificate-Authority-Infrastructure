from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from ca_files.Certificate_Authority import *
from server_files.Server import Server
from Client import *



def next_cmd(cmd):
    split_cmd = cmd.split(".")
    return split_cmd[1]



def server_cmd(cmd):
    
    if cmd == "csr":
        csr = server.create_csr("different_name.com")
        signed_cert = ca.receive_csr(csr)
        if signed_cert != None:
            server.save_cert(signed_cert)
        print("Successfully saved a valid certificate on the server.")

    elif cmd == "fakecer":
        cert_pem = server.get_cert()
        ca.remove_certificate(cert_pem)
        server.save_self_signed_certificate()
        print("Successfully saved an invalid certificate on the server.")
    
    else:
        print("Unkown server command.")



def ca_cmd(cmd):

    if cmd == "revoke":
        cert_pem = server.get_cert()
        ca.revoke_certificate(cert_pem)
        print("Successfully revoked server certificate.")

    elif cmd == "remove":
        cert_pem = server.get_cert()
        ca.remove_certificate(cert_pem)
        print("Successfully removed the server certificate.")

    elif cmd == "log":
        print("\nLOGS:")
        ca.display_logs()

    else:
        print("Unkown ca command.")



def client_cmd(cmd):
    
    if cmd == "msg":
        msg = input("Input what message you want to send to the server: ")
        
        if client.verify_certificate(server, ca):
            communication(server, client, msg)
        else:
            print("Can't communicate with the server because of an invalid certificate.")

    elif cmd == "connect":
        client.connect_to_app(server, ca)

    elif cmd == "get":
        client.request_text()

    elif cmd == "post":
        msg = input("Input what message you want the web page message to update to: ")
        client.request_update(server, msg)
    
    else:
        print("Unkown client command.")



def communication(server, client, msg):
    server_public_key_bytes = server.get_public_key()

    server_public_key = serialization.load_pem_public_key(server_public_key_bytes, backend=default_backend())
    encrypted_message = client.encrypt_message(server_public_key, msg)

    decrypted_message = server.decrypt_message(encrypted_message)
    print(f"Server successfully received the following message: {decrypted_message}")





if __name__ == "__main__":
    

    server = Server()
    client = Client()
    ca = Certificate_Authority()

    while True:

        cmd = input("Input what you want to happen in the public key infrastructure (server.csr, server.fakecer, ca.revoke, ca.remove, ca.log, client.msg, client.connect, client.get, client.post, exit): ")

        print()

        if cmd.startswith("server."):
            server_cmd(next_cmd(cmd))

        elif cmd.startswith("client."):
            client_cmd(next_cmd(cmd))

        elif cmd.startswith("ca."):
            ca_cmd(next_cmd(cmd))

        elif cmd == "exit":
            break

        else:
            print("Unkown command.")

        print("\n")

