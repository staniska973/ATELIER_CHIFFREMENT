import argparse
import os
from pathlib import Path
from cryptography.fernet import Fernet

def get_fernet() -> Fernet:
    key = os.environ.get("FERNET_KEY")
    if not key:
        raise SystemExit(
            "FERNET_KEY non définie. Exemple : export FERNET_KEY='...'\n"
            "On peut générer une clé avec : python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        )
    return Fernet(key.encode())

def encrypt_file(input_path: Path, output_path: Path) -> None:
    f = get_fernet()
    data = input_path.read_bytes()
    token = f.encrypt(data)
    output_path.write_bytes(token)

def decrypt_file(input_path: Path, output_path: Path) -> None:
    f = get_fernet()
    token = input_path.read_bytes()
    data = f.decrypt(token)  # lève InvalidToken si la clé est mauvaise ou si le fichier est altéré
    output_path.write_bytes(data)

def main():
    p = argparse.ArgumentParser(description="Chiffrement/Déchiffrement de fichiers avec Fernet (cryptography).")
    p.add_argument("mode", choices=["encrypt", "decrypt"])
    p.add_argument("input", help="Fichier d'entrée")
    p.add_argument("output", help="Fichier de sortie")
    args = p.parse_args()

    in_path = Path(args.input)
    out_path = Path(args.output)

    if not in_path.exists():
        raise SystemExit(f"Fichier introuvable : {in_path}")

    if args.mode == "encrypt":
        encrypt_file(in_path, out_path)
        print(f"Fichier chiffré : {in_path} -> {out_path}")
    else:
        decrypt_file(in_path, out_path)
        print(f"Fichier déchiffré : {in_path} -> {out_path}")

if __name__ == "__main__":
    main()
