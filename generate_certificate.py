from OpenSSL import crypto, SSL
from socket import gethostname
from pprint import pprint
from time import gmtime, mktime
# Lai izmantotu OpenSSL, ir jāinstalē pyopenssl modulis
# `python -m pip install pyopenssl`

# Ar "R" prefiksu atzīmē prasību (Requirement) no mājasdarba

CERT_FILE = "self_signed.crt"
KEY_FILE = "private.key"

def create_self_signed_cert():

    # create a key pair
    k = crypto.PKey()

    # R: RSA algorithm; desirably with at least 2048 bit key
    k.generate_key(crypto.TYPE_RSA, 2048) 

    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = "UK"
    cert.get_subject().ST = "London"
    cert.get_subject().L = "London"
    cert.get_subject().O = "Dummy Company Ltd"
    cert.get_subject().OU = "Dummy Company Ltd"
    cert.get_subject().CN = gethostname()
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(60*60*24)
    
    cert.set_issuer(cert.get_subject()) # Issuer būs tāds pats kā Subject 
    
    
    cert.set_pubkey(k) #R: The certificate should sign your public encryption key of RSA algorithm
    cert.sign(k, 'sha256') #R: certificate itself should be signed using RSA and SHA-2 message digest algorithm

    with open(CERT_FILE, "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

    with open(KEY_FILE, "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))

create_self_signed_cert()