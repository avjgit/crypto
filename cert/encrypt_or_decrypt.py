from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# --------------------------------- 
# Funkcija iešifrēšanai
# --------------------------------- 
def encrypt(
    plainttextFilename, 
    certificateFilename,
    outputFilename):

    print(f"----- Nolasa publisko atslēgu no {certificateFilename}")
    with open(certificateFilename, "rb") as cert_file: 
        public_key = x509.load_pem_x509_certificate(
            cert_file.read(), 
            default_backend()).public_key()

    print(f"----- Nolasa tekstu iešifrēšanai no {plainttextFilename}")
    with open(plainttextFilename, "r") as f:
        plaintext = f.read()

    print(f"----- Iešifrē tekstu: {plaintext}")
    ciphertext = public_key.encrypt(
        bytes(plaintext, "utf-8"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print(f"----- Saglabā iešifrēto {outputFilename} failā")
    with open(outputFilename, "wb") as outputFile:
            outputFile.write(ciphertext)
    print(f"----- Iešifrēšana pabeigta")

# --------------------------------- 
# Funkcija atšifrēšanai
# --------------------------------- 
def decrypt(
        ciphertextFilename, 
        keyFilename,
        keyFilePassword,
        outputFilename):

    print(f"----- Nolasa privāto atslēgu no {keyFilename}")
    with open("keys.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=bytes(keyFilePassword, "utf-8"),
            backend=default_backend()
        )

    print(f"----- Nolasa šifrēto ziņu no {ciphertextFilename}")
    with open(ciphertextFilename, "rb") as f:
        ciphertext = f.read()

    print(f"----- Atšifrē")
    decrypted = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print(f"----- Atšifrēja tekstu: {decrypted}")
    print(f"----- Ieraksta {outputFilename} failā")
    with open(outputFilename, "wb") as outputFile:
            outputFile.write(decrypted)
    print(f"----- Atšifrēšana pabeigta")

encrypt(
    plainttextFilename  = "input.txt", 
    certificateFilename = "certificate.pem", 
    outputFilename      = "encrypted.txt"
)

decrypt(
    ciphertextFilename  = "encrypted.txt",
    keyFilename         = "keys.pem",
    keyFilePassword     = "pilnigi slepeni",
    outputFilename      = "decrypted.txt"
)

