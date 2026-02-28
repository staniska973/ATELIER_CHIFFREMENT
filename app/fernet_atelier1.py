import argparse
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

# Réalisé par : STANISLAS-CONSTANTIN


def charger_fernet_depuis_secret() -> Fernet:
    """
    On récupère la clé Fernet depuis la variable d'environnement FERNET_KEY.
    Dans GitHub Actions, cette valeur vient d'un Repository Secret.
    """
    cle = os.environ.get("FERNET_KEY")
    if not cle:
        raise SystemExit(
            "FERNET_KEY est absente. On doit la définir dans l'environnement "
            "(ou dans un Repository Secret GitHub)."
        )

    try:
        return Fernet(cle.encode("utf-8"))
    except Exception as exc:
        raise SystemExit(
            "FERNET_KEY existe mais son format est invalide. "
            "On attend une clé Fernet (base64 url-safe)."
        ) from exc


def chiffrer_fichier(entree: Path, sortie: Path) -> None:
    fernet = charger_fernet_depuis_secret()
    donnees = entree.read_bytes()
    token = fernet.encrypt(donnees)
    sortie.write_bytes(token)


def dechiffrer_fichier(entree: Path, sortie: Path) -> None:
    fernet = charger_fernet_depuis_secret()
    token = entree.read_bytes()

    try:
        donnees = fernet.decrypt(token)
    except InvalidToken as exc:
        raise SystemExit(
            "Impossible de déchiffrer : la clé n'est pas la bonne "
            "ou le fichier chiffré a été modifié."
        ) from exc

    sortie.write_bytes(donnees)


def parser_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Atelier 1 - Chiffrer et déchiffrer un fichier avec Fernet + Repository Secret."
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

    if args.mode == "encrypt":
        chiffrer_fichier(chemin_entree, chemin_sortie)
        print(f"Fichier chiffré : {chemin_entree} -> {chemin_sortie}")
    else:
        dechiffrer_fichier(chemin_entree, chemin_sortie)
        print(f"Fichier déchiffré : {chemin_entree} -> {chemin_sortie}")


if __name__ == "__main__":
    main()
