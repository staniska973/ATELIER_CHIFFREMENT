import os
from cryptography.fernet import Fernet

def load_key() -> bytes:
    """
    Charge la clé depuis la variable d'environnement FERNET_KEY.
    Si absente, on en génère une, on l'affiche et on l'export dans le système.
    """
    key = os.environ.get("FERNET_KEY")
    if not key:
        new_key = Fernet.generate_key()
        print("FERNET_KEY est absente, donc on génère une clé pour tester.")
        print(new_key.decode())
        print("\nPour la garder, on peut l'ajouter dans l'environnement :")
        print("export FERNET_KEY='" + new_key.decode() + "'")
        return new_key
    return key.encode()

def main():
    key = load_key()
    f = Fernet(key)

    message = "Bonjour, on teste un petit message secret"
    token = f.encrypt(message.encode("utf-8"))

    print("\n=== Chiffrement ===")
    print("Message clair :", message)
    print("Token chiffré :", token.decode("utf-8"))

    print("\n=== Déchiffrement ===")
    clear = f.decrypt(token).decode("utf-8")
    print("Message déchiffré :", clear)

if __name__ == "__main__":
    main()

