import shutil
import subprocess
import time
from cie import CIE
from constants import Constants
from mtls import MTLSClientHandler
from server import Server
from tls import TLSClientHandler


class User:
    """
    Questa classe rappresenta un utente.
    """

    __slots__ = '_IP', '_server', '_tlsHandler', '_CIE', '_myfolder', '_cred'

    def __init__(self, IP):
        """
        Inizializza l'utente con l'indirizzo IP fornito.

        Args:
            IP (str): L'indirizzo IP dell'utente.
        """
        self._cred = None
        self._tlsHandler = None
        self._IP = IP
        self._myfolder = Constants.USER_DIR
        self._server = None
        self._CIE = CIE(self._myfolder)

    def connectTLS(self, server):
        """
        Connette l'utente al server fornito utilizzando TLS.

        Args:
            server (Server): Il server a cui connettersi.
        """
        if not isinstance(server, Server):
            print('[User {}]: '.format(self), Constants.SERVER_MESSAGE_ERR)
            return Constants.ERR

        self._server = server
        print('[User {}]: '.format(self), 'Connessione a {}...'.format(server))
        time.sleep(1)
        self._server.startConnection(self)

        # TLS handshake
        print('\n[User {}]: '.format(self), 'Avvio handshake TLS...')
        time.sleep(1)
        self._tlsHandler = TLSClientHandler(self, self._myfolder, self._server)
        self._tlsHandler.handshakeStep(1)

    def connectMTLS(self, server):
        """
        Connette l'utente al server fornito utilizzando mTLS.

        Args:
            server (Server): Il server a cui connettersi.
        """
        if not isinstance(server, Server):
            print('[User {}]: '.format(self), Constants.SERVER_MESSAGE_ERR)
            return Constants.ERR

        self._server = server
        print('[User {}]: '.format(self), 'Connessione a {}...'.format(server))
        time.sleep(1)
        self._server.startConnection(self)

        # TLS handshake
        print('\n[User {}]: '.format(self), 'Avvio handshake TLS...')
        time.sleep(1)
        self._tlsHandler = MTLSClientHandler(self, self._myfolder, self._server)
        self._tlsHandler.handshakeStep(1)

    def closeConnection(self):
        """
        Chiude la connessione con il server.
        """
        self._server.closeConnection(self)
        self._server = None
        self._tlsHandler = None

    def requestCredentials(self):
        """
        Invia le credenziali al server.
        """
        print('\n[User {}]: '.format(self), 'Invio richiesta credenziali...')
        time.sleep(1)
        message = (self._CIE.getSerialNumber(), self._CIE.getExpirationDate(), self._CIE.getPubKeyFile())
        encryptedMessage, tagMac, iv = self._tlsHandler.encryptMessage(message)
        return self._server.receiveInfoCIE({'message': encryptedMessage, 'tagMac': tagMac, 'iv': iv}, self)

    def receiveCredentials(self, cred):
        """
        Riceve le credenziali dal server.

        Args:
            cred (Credenziali): Le credenziali ricevute dal server.
        """
        print('[User {}]: '.format(self), 'Credenziali ricevute')
        time.sleep(1)
        self._cred = cred
        shutil.move(self._cred.getSignature(), self._myfolder + Constants.CRED_SIGNATURE_FILENAME)
        self._cred.setSignature(self._myfolder + Constants.CRED_SIGNATURE_FILENAME)

        print('[User {}]: '.format(self), 'Chiusura connessione...')
        time.sleep(1)
        self.closeConnection()
        return

    def sign_CIE(self, message, ecdsaKeyFile, signatureFile):
        """
        Firma un messaggio con la chiave privata ECDSA dell'utente, contenuta nella CIE.

        Args:
            message (str): Il messaggio da firmare.
            ecdsaKeyFile (str): Il percorso del file contenente la chiave privata ECDSA.
            signatureFile (str): Il percorso del file dove salvare la firma.

        Returns:
            bool: True se la firma ha successo, False altrimenti.
        """
        while not self._CIE.isBlocked():
            print('Inserire pin per firmare il messaggio')
            pin = input()
            time.sleep(1)

            # Firma l'hash del msg
            com = [Constants.OPENSSL, 'dgst', '-sha256']
            hash_msg = subprocess.check_output(com, input=message.encode('utf-8')).decode('utf-8').strip()

            if self._CIE.sign(pin, hash_msg, ecdsaKeyFile, signatureFile):
                return True

        return False

    def receiveRandomString(self, params):
        """
        Funzione per ricevere random string da firmare per dimostrare di avere
        la private_key associata alla public_key del certificato della CIE

        Returns:
            str: Percorso del file dove è salvata la firma.
        """
        print('\n[User {}]: '.format(self), 'Random string ricevuta...')
        time.sleep(1)
        random_string = self._tlsHandler.decryptMessage(params['message'], params['tagMac'], params['iv'])
        signature_file = self._myfolder + Constants.SIGNATURE_FILENAME

        # Finchè la CIE non è bloccata si prova a firmare col pin
        if not self.sign_CIE(random_string, self._myfolder + Constants.ECDSA_KEY_FILENAME, signature_file):
            self.closeConnection()
            return Constants.ERR

        print('\n[User {}]: '.format(self), 'Invio random string firmata...')
        time.sleep(1)
        return signature_file

    def sendInitialInfoCredentials(self):
        """
        Manda le informazioni iniziali al server, ovvero la chiave pubblica (presente nel
        certificato della CIE) con la relativa proof e la root del certificato con la firma.
        Inizia cosi la comunicazione per l'accesso al servizio
        """
        if self._cred is not None:
            print('\n[User {}]: '.format(self), 'Invio delle informazioni iniziali sulle credenziali...')
            time.sleep(1)
            message = (self._cred.getData("pubKey"), self._cred.getDataProof("pubKey"), self._cred.getSignature())
            encryptedMessage, tagMac, iv = self._tlsHandler.encryptMessage(message)
            self._server.step1ReceiveInfoCredentials({'message': encryptedMessage, 'tagMac': tagMac, 'iv': iv}, self)

        else:
            print(Constants.CREDENTIALS_MESSAGE_ERR)
            self.closeConnection()
            return Constants.ERR

    def requestResidence(self):
        """
        Funzione per inviare le proprie credenziali sulla residenza
        """
        if self._cred is not None:
            print('\n[User {}]: '.format(self), 'Invio credenziali residenza...')
            time.sleep(1)
            message = (self._cred.getData('residenza'), self._cred.getDataProof('residenza'))
            encryptedMessage, tagMac, iv = self._tlsHandler.encryptMessage(message)
            self._server.step3ReceiveResidenceCredential({'message': encryptedMessage, 'tagMac': tagMac, 'iv': iv}, self)

        else:
            print(Constants.CREDENTIALS_MESSAGE_ERR)
            self.closeConnection()
            return Constants.ERR

    def requestISEE(self):
        """
        Funzione per inviare le proprie credenziali sull'isee e data di nascita
        """
        if self._cred is not None:
            print('\n[User {}]: '.format(self), 'Invio credenziali isee e data di nascita...')
            time.sleep(1)
            message = (self._cred.getData('isee'), self._cred.getDataProof('isee'),
                       self._cred.getData('data_nascita'), self._cred.getDataProof('data_nascita'))
            encryptedMessage, tagMac, iv = self._tlsHandler.encryptMessage(message)
            self._server.step3ReceiveISEECredential({'message': encryptedMessage, 'tagMac': tagMac, 'iv': iv}, self)

        else:
            print(Constants.CREDENTIALS_MESSAGE_ERR)
            self.closeConnection()
            return Constants.ERR

    def __str__(self) -> str:
        """
        Restituisce la rappresentazione in stringa dell'utente.

        Returns:
            str: L'indirizzo IP dell'utente.
        """
        return self._IP
