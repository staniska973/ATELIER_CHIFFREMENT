import argparse
import base64
import os
from getpass import getpass
from pathlib import Path

from nacl import exceptions, pwhash, secret, utils


def charger_salt() -> bytes:
    """
    On lit le salt depuis SALT_B64.
    Si la variable n'existe pas, on en génère un et on l'affiche pour qu'on puisse le réutiliser.
    """
    salt_b64 = os.environ.get("SALT_B64")
    if not salt_b64:
        salt = utils.random(pwhash.argon2id.SALTBYTES)
        salt_b64 = base64.b64encode(salt).decode("utf-8")
        print("SALT_B64 absente. On vient de générer une valeur :")
        print(salt_b64)
        print("On peut la réutiliser avec : export SALT_B64='...'")
        return salt

    try:
        salt = base64.b64decode(salt_b64)
    except Exception as exc:
        raise SystemExit("SALT_B64 n'est pas un base64 valide.") from exc

    if len(salt) != pwhash.argon2id.SALTBYTES:
        raise SystemExit(
            f"SALT_B64 invalide : il faut {pwhash.argon2id.SALTBYTES} octets après décodage."
        )
    return salt


def derive_key_from_password(password: str, salt: bytes) -> bytes:
    return pwhash.argon2id.kdf(
        size=secret.SecretBox.KEY_SIZE,
        password=password.encode("utf-8"),
        salt=salt,
        opslimit=pwhash.argon2id.OPSLIMIT_MODERATE,
        memlimit=pwhash.argon2id.MEMLIMIT_MODERATE,
    )


def chiffrer_fichier(entree: Path, sortie: Path, box: secret.SecretBox) -> None:
    donnees = entree.read_bytes()
    ciphertext = box.encrypt(donnees)
    sortie.write_bytes(ciphertext)


def dechiffrer_fichier(entree: Path, sortie: Path, box: secret.SecretBox) -> None:
    ciphertext = entree.read_bytes()
    try:
        donnees = box.decrypt(ciphertext)
    except exceptions.CryptoError as exc:
        raise SystemExit(
            "Impossible de déchiffrer : mauvais mot de passe, mauvais salt ou fichier modifié."
        ) from exc
    sortie.write_bytes(donnees)


def parser_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Atelier 2 - Chiffrement de fichiers avec PyNaCl SecretBox"
    )
    parser.add_argument("mode", choices=["encrypt", "decrypt"], help="Action à effectuer")
    parser.add_argument("input", help="Fichier d'entrée")
    parser.add_argument("output", help="Fichier de sortie")
    return parser.parse_args()


def main() -> None:
    args = parser_arguments()
    chemin_entree = Path(args.input)
    chemin_sortie = Path(args.output)

    if not chemin_entree.exists():
        raise SystemExit(f"Le fichier d'entrée est introuvable : {chemin_entree}")

    salt = charger_salt()
    mot_de_passe = getpass("Mot de passe : ")
    key = derive_key_from_password(mot_de_passe, salt)
    box = secret.SecretBox(key)

    if args.mode == "encrypt":
        chiffrer_fichier(chemin_entree, chemin_sortie, box)
        print(f"Fichier chiffré : {chemin_entree} -> {chemin_sortie}")
    else:
        dechiffrer_fichier(chemin_entree, chemin_sortie, box)
        print(f"Fichier déchiffré : {chemin_entree} -> {chemin_sortie}")


if __name__ == "__main__":
    main()
