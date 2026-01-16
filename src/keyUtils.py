import subprocess
import os

from constants import Constants


class KeyUtils:
    """
    Questa classe gestisce le chiavi degli utenti. In particolare, fornisce
    un metodo per firmare messaggi e un metodo per varificare la firma.
    """

    def _checkFileExtension(self, filePath, extension):
        """
        Controlla se l'estensione del file è corretta.

        Args:
            file_path (str): Il percorso del file.
            extension (str): L'estensione corretta del file.

        Returns:
            bool: True se l'estensione è corretta, False altrimenti.

        Raises:
            Exception: Se l'estensione non è corretta.
        """
        _, fileExtension = os.path.splitext(filePath)
        if fileExtension == extension:
            return True
        else:
            raise Exception(Constants.FILE_EXTENSION_MESSAGE_ERR)

    def sign(self, message, ecdsaKeyFile, signatureFile):
        """
        Firma il messaggio con la chiave privata dell'utente.

        Args:
            message (str): Il messaggio da firmare.
            ecdsaKeyFile (str): Il percorso del file contenente la chiave privata dell'utente.
            signatureFile (str): Il percorso del file dove verrà salvata la firma.
        """
        if self._checkFileExtension(ecdsaKeyFile, '.pem') and self._checkFileExtension(signatureFile, '.bin'):
            com = [Constants.OPENSSL, 'dgst', '-sign', ecdsaKeyFile, '-out', signatureFile]
            subprocess.check_output(com, input=str(message).encode())

    def verifySign(self, message, signature, publicKey):
        """
        Verifica la firma del messaggio.

        Args:
            message (str): Il messaggio da verificare.
            signature (str): Il percorso del file contenente la firma.
            publicKey (str): Il percorso del file contenente la chiave pubblica per la verifica.

        Returns:
            bool: True se la firma è corretta, False altrimenti.
        """
        com = [Constants.OPENSSL, 'dgst', '-verify', publicKey, '-signature', signature]
        out = subprocess.check_output(com, input=str(message).encode())
        return out == b'Verified OK\n'