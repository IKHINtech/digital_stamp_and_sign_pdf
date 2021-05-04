import datetime

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key

import os
from config import Config
from app import app

cert_name = 'upb-root-new.crt'
key_name = 'upb-key-new.pem'
cert = os.path.join(app.config['CERTIFICATE'],cert_name)
key = os.path.join(app.config['CERTIFICATE'],key_name)

with open(cert, 'rb') as f:
    a = f.read()
    cert = x509.load_pem_x509_certificate(a)
with open(key, 'rb') as f:
    b = f.read()
    key_f = load_pem_private_key(b, password=b'rahasia')

root_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096,
    backend=default_backend()
)
def create_root():
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ID"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"West Java"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Bekasi"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Pelita Bangsa University"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"UPB DigiSign"),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS,u"helpdesk@digisign.pelitabangsa.ac.id")
    ])
    root_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        root_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)
    ).add_extension(
        x509.KeyUsage(digital_signature=True, 
        key_encipherment=True,key_cert_sign=True,
        key_agreement=False, content_commitment=True,
        data_encipherment=True,
        crl_sign=False, encipher_only=False, 
        decipher_only=False),
        critical=False,
    ).sign(root_key, hashes.SHA256(), default_backend())
    with open(cert, "wb") as f:
        f.write(root_cert.public_bytes(serialization.Encoding.PEM))
    with open(key, "wb") as f:
        f.write(root_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.BestAvailableEncryption(b"rahasia"),))
    
    return 

def create_cert(name:str, password:str, email:str, active:int, cert_name, key_name ):
    cert_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096,
    backend=default_backend()
    )
    new_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ID"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"West Java"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Bekasi"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"DigiSign Pelita Bangsa"),
        x509.NameAttribute(NameOID.COMMON_NAME, str(name)),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, str(email))
    ])
    cert_new = x509.CertificateBuilder().subject_name(
        new_subject
    ).issuer_name(
        cert.issuer
    ).public_key(
        cert_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
    datetime.datetime.utcnow() + datetime.timedelta(days=active)
    ).add_extension(
        x509.KeyUsage(digital_signature=True, 
        key_encipherment=True,key_cert_sign=True,
        key_agreement=False, content_commitment=True,
        data_encipherment=True,
        crl_sign=False, encipher_only=False, 
        decipher_only=False),
        critical=False,
    ).sign(key_f, hashes.SHA256(), default_backend())
    with open(cert_name, "wb") as f:
        f.write(cert_new.public_bytes(serialization.Encoding.PEM))
    with open(key_name, "wb") as f:
        f.write(cert_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(bytes(password, encoding='utf-8'))))
    return 'success'

def read_cert(cert):
    with open(cert, 'rb') as f:
        a = f.read()
        cert = x509.load_pem_x509_certificate(a)
        return cert

