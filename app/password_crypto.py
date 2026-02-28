import base64
import os
from getpass import getpass

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
    return key

def main():
    # Dans un vrai système, on doit garder le même salt pour pouvoir redéchiffrer.
    salt_b64 = os.environ.get("SALT_B64")
    if not salt_b64:
        salt = os.urandom(16)
        salt_b64 = base64.b64encode(salt).decode()
        print("SALT_B64 est absente, donc on génère une valeur de test :")
        print(salt_b64)
        print("Pour réutiliser le même salt : export SALT_B64='" + salt_b64 + "'")
    else:
        salt = base64.b64decode(salt_b64)

    password = getpass("Mot de passe : ")
    key = derive_key(password, salt)
    f = Fernet(key)

    msg = "Secret protégé par mot de passe + salt"
    token = f.encrypt(msg.encode())

    print("\nToken chiffré :", token.decode())
    clear = f.decrypt(token).decode()
    print("Message déchiffré :", clear)

if __name__ == "__main__":
    main()
