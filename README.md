# Atelier – Chiffrement/Déchiffrement (Python `cryptography`) dans GitHub Codespaces

Réalisé par : **STANISLAS-CONSTANTIN**

## 1) Lancer le projet dans Codespaces
- Fork / clone ce repo
- Bouton **Code** → **Create codespace on main**

## 2) Installer la bibliothèque Python Cryptographie
```bash
pip install -r requirements.txt
```
## 3) Partie A – Chiffrer/Déchiffrer un texte
```
python app/fernet_demo.py
```
**Quel est le rôle de la clé Fernet ?**  
La clé Fernet est une clé symétrique secrète de 256 bits encodée en Base64, utilisée pour chiffrer et authentifier les données avec AES et HMAC issue de la bibliothèque python cryptography. Un token Fernet (c'est à dire le résultat chiffré) contient :  
```
| Version | Timestamp | IV | Ciphertext | HMAC |
```
* Version (1 octet) : Valeur actuelle : 0x80
* Timestamp (8 octets) : Permet l'expiration des tokens
* IV (16 octets) : Généré aléatoirement - Garantit que deux messages identiques produisent des ciphertexts différents
* Ciphertext (variable) : Résultat du chiffrement AES-128-CBC qui contient les données
* HMAC (32 octets) : Protège contre toute modification
  
## 4) Partie B – Chiffrer/Déchiffrer un fichier
Créer un fichier de test :  
```
echo "Message Top secret !" > secret.txt
```
Chiffrer :
```
python app/file_crypto.py encrypt secret.txt secret.enc
```
Déchiffrer :
```
python app/file_crypto.py decrypt secret.enc secret.dec.txt
cat secret.dec.txt
```
**Que se passe-t-il si on modifie un octet du fichier chiffré ?**  
Le déchiffrement échoue. Fernet vérifie l'intégrité avec un HMAC. Donc si un seul octet change, la vérification ne passe plus et la librairie refuse de renvoyer des données.
 
**Pourquoi ne faut-il pas commiter la clé dans Git ?**   
Parce que toute personne qui récupère la clé peut déchiffrer les données. Même si on supprime la clé plus tard, elle reste souvent dans l'historique Git. On doit la stocker dans un secret (ex: Repository Secret GitHub), pas dans le code.

## 5) Atelier 1 :
Dans cet atelier, la clé Fernet n'est plus générée dans le code mais stockée dans un Repository Secret Github. Ecrivez un nouveau programme **python app/fernet_atelier1.py** qui utilisera une clé Fernet caché dans un Secret GitHub pour encoder et décoder vos fichiers.

Le programme est disponible dans le repo :
```
app/fernet_atelier1.py
```

Exemple local :
```
export FERNET_KEY='ta_cle_fernet_base64'
python app/fernet_atelier1.py encrypt secret.txt secret.at1.enc
python app/fernet_atelier1.py decrypt secret.at1.enc secret.at1.dec.txt
cat secret.at1.dec.txt
```

Exemple GitHub Actions (principe) :
- On crée un Repository Secret `FERNET_KEY`
- Le workflow expose ce secret dans la variable d'environnement `FERNET_KEY`
- Le script lit directement cette variable

## 6) Atelier 2 :
Les bibliothèques qui proposent un système complet, sûr par défaut et simple d’usage comme Fernet de la bibliothèse Cryptographie sont relativement rares. Toutefois, la bibliothèque PyNaCl via l'outil SecretBox est une très bonne alternative. **travail demandé :** Construire une solution de chiffrement/déchiffrement basé sur l'outils SecretBox de la bibliothèque PyNaCl.

Le programme est disponible dans le repo :
```
app/secretbox_atelier2.py
```

Principe simple :
- On demande un mot de passe
- On dérive une clé avec Argon2id (fonction KDF moderne de PyNaCl)
- On chiffre/déchiffre le fichier avec SecretBox

Commandes :
```
# Optionnel : fixer un salt constant pour pouvoir rechiffrer/déchiffrer dans plusieurs sessions
export SALT_B64='un_salt_base64'

python app/secretbox_atelier2.py encrypt secret.txt secret.at2.enc
python app/secretbox_atelier2.py decrypt secret.at2.enc secret.at2.dec.txt
cat secret.at2.dec.txt
```









