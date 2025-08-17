import OpenSSL
import os

def generate_self_signed_cert():
    key = OpenSSL.crypto.PKey()
    key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
    
    cert = OpenSSL.crypto.X509()
    cert.get_subject().CN = "localhost"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, 'sha256')
    
    with open("server.crt", "wb") as f:
        f.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert))
    with open("server.key", "wb") as f:
        f.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key))

if __name__ == "__main__":
    if not os.path.exists("server.crt") or not os.path.exists("server.key"):
        print("Generating self-signed certificate and key...")
        generate_self_signed_cert()
        print("Certificates generated: server.crt, server.key")
    else:
        print("Certificates already exist.")