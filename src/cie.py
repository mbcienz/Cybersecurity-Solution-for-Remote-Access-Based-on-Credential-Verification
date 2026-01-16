import os
from enum import Enum
from constants import Constants
from keyUtils import KeyUtils


class FieldCIE(Enum):
    """
    FieldCIE è una classe enum che contiene tutti i campi della CIE.
    """

    NOME = "Mario"
    COGNOME = "Rossi"
    SESSO = "M"
    DATA_NASCITA = "01-01-1980"
    LUOGO_NASCITA = "RM"
    STATURA = "180"
    DATA_EMISSIONE = "30-01-2024"
    CITTADINANZA = "ITA"
    SCADENZA = "01-01-2034"
    SERIALE = "RU65839UJ"


class CIE:
    __slots__ = ('pin', 'puk', 'field', '_ecdsaKeyFile', '_ecdsaPubFile', '_ecdsaParamFile', '_myfolder', '_keyUtils',
                 'error_pin', '_certificate', '_blocked')

    def __init__(self, myfolder):
        """
        Inizializza l'istanza CIE con valori predefiniti e percorsi per i file delle chiavi.

        Args:
            myfolder (str): Il percorso della directory utente.
        """
        self.pin = "0123456789"
        self.puk = "0000000000"
        self._blocked = False
        self.field = {field: field.value for field in FieldCIE}
        self._myfolder = myfolder
        self._keyUtils = KeyUtils()
        self.error_pin = 0
        self._certificate = self._myfolder + Constants.CERTIFICATE_FILENAME
        self._ecdsaKeyFile = self._myfolder + Constants.ECDSA_KEY_FILENAME
        self._ecdsaPubFile = self._myfolder + Constants.ECDSA_PUB_FILENAME
        self._ecdsaParamFile = self._myfolder + Constants.ECDSA_PARAM_FILENAME

    def sign(self, pin, hash, ecdsaKeyFile, signatureFile):
        """
        Firma un hash utilizzando la chiave privata ECDSA se il PIN è corretto.

        Args:
            pin (str): Il PIN da verificare.
            hash (str): L'hash del messaggio da firmare.
            ecdsaKeyFile (str): Il percorso del file contenente la chiave privata ECDSA.
            signatureFile (str): Il percorso del file in cui salvare la firma.

        Returns:
            bool: True se la firma ha successo, False altrimenti.
        """
        if self._blocked:
            print('CIE bloccata...!')
            return False

        if pin != self.pin:
            print("PIN non valido...!")
            self.error_pin += 1
            if self.error_pin >= 3:
                self._blocked = True
                print("CIE BLOCCATA...PIN SBAGLIATO PER 3 volte")
            return False

        if not os.path.exists(self._ecdsaKeyFile):
            print("Chiave privata non trovata...!")
            return False

        if not self._blocked:
            self._keyUtils.sign(hash, ecdsaKeyFile, signatureFile)
            self.error_pin = 0
            print("Pin corretto, messaggio firmato...!")
            return True

    def unlock(self, puk):
        """
        Sblocca la CIE utilizzando il PUK.

        Args:
            puk (str): Il PUK da verificare.

        Returns:
            bool: True se la CIE è sbloccata, False altrimenti.
        """
        if puk != self.puk:
            print("PUK non valido")
            return False
        else:
            self.error_pin = 0
            print("CIE SBLOCCATA")
            self._blocked = False
            return True

    def getPubKeyFile(self):
        """
        Restituisce il percorso del file della chiave pubblica ECDSA.

        Returns:
            str: Il percorso del file della chiave pubblica ECDSA.
        """
        return self._ecdsaPubFile

    def getSerialNumber(self):
        """
        Restituisce il numero di serie della CIE.

        Returns:
            str: Il numero di serie della CIE.
        """
        return self.field[FieldCIE.SERIALE]

    def getExpirationDate(self):
        """
        Restituisce la data di scadenza della CIE.

        Returns:
            str: La data di scadenza della CIE.
        """
        return self.field[FieldCIE.SCADENZA]

    def isBlocked(self):
        """
        Restituisce vero se la carta è bloccata, falso altrimenti.

        Returns:
            bool: Se la carta è bloccata ritorna vero, falso altrimenti.
        """
        return self._blocked
