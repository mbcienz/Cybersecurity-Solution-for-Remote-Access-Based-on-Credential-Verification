from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from certificateUtils import CertificateUtils
from keyUtils import KeyUtils
import subprocess
import inspect
import math
import os
import time
from constants import Constants


class TLSClientHandler:
    """
    Questa classe gestisce l'handshake TLS dal lato del client.
    """
    def __init__(self, user, myfolder, server):
        """
        Inizializza il gestore TLS con l'utente, il nome della cartella e il server forniti.

        Args:
            user (User): L'utente.
            myfolder (str): Il nome della cartella contenente i file dell'utente.
            server (Server): Il server.
        """
        self._keyUtils = KeyUtils()
        self._server = server
        self._myfolder = myfolder
        self._user = user

    @property
    def q(self):
        """
        Returns:
            int: L'ordine della curva ellittica utilizzata per l'algoritmo ECDSA.
        """
        return self._q

    @property
    def g(self):
        """
        Returns:
            int: Il generatore della curva ellittica utilizzata per l'algoritmo ECDSA.
        """
        return self._g

    @property
    def p(self):
        """
        Returns:
            int: Il modulo primo della curva ellittica utilizzata per l'algoritmo ECDSA.
        """
        return self._p

    @property
    def x(self):
        """
        Returns:
            int: La chiave privata dell'utente.
        """
        return self._x

    @property
    def pks(self):
        """
        Returns:
            int: La chiave pubblica del server.
        """
        return self._pks

    def handshakeStep(self, step, params=None):
        """
        Esegue uno specifico passo dell'handshake TLS.

        Parameters:
            step (int): Il numero del passo dell'handshake da eseguire (1, 2 o 3).
            params (dict): Parametri aggiuntivi richiesti per passi specifici. Facoltativo.
        """
        if step == 1:
            self._step1Handshake()

        elif step == 2 and params is not None:
            self._step2KeyDerivation(params)

        elif step == 3 and params is not None:
            self._step3MessageDecryptionAndVerification(params)

    def _step1Handshake(self):
        """
        Esegue il primo passo della'handshake TLS.
        """
        print('[User {}]: '.format(self._user), 'Generazione dei parametri DH...\n')
        self.dhParamFile = self._myfolder + Constants.DH_PARAM_FILENAME
        self.dhKeyFile = self._myfolder + Constants.DH_KEY_FILENAME

        # Generate DH parameters and key
        if not os.path.exists(self.dhParamFile):
            com = [Constants.OPENSSL, 'dhparam', '-out', self.dhParamFile, '2048']
            subprocess.check_output(com)
        else:
            print(f"Utilizzando il file dei parametri DH esistente: {self.dhParamFile}")

        com = [Constants.OPENSSL, 'genpkey', '-paramfile', self.dhParamFile, '-out', self.dhKeyFile]
        subprocess.check_output(com)

        with open(self.dhParamFile, 'rb') as f:
            dhparams = serialization.load_pem_parameters(f.read())
        self._g = dhparams.parameter_numbers().g
        self._p = dhparams.parameter_numbers().p
        self._q = (self._p - 1) // 2

        with open(self.dhKeyFile, 'rb') as f:
            keys = serialization.load_pem_private_key(f.read(), password=None)
        self._x = keys.private_numbers().x

        A = pow(self._g, self._x, self._p)

        print('\n[User {}]: '.format(self._user), 'Invio del contributo DH...')
        time.sleep(1)
        self._server.tlsHandler.tlsHandshake({'user': self._user, 'p': self._p, 'q': self._q, 'g': self._g, 'A': A})

    def _step2KeyDerivation(self, params):
        """
        Esegue il secondo passo dell'handshake TLS.

        Args:
            params (dict): I parametri ricevuti dal server.
        """
        print('[User {}]: '.format(self._user), 'Generazione della chiave DH...')
        time.sleep(1)
        print('[User {}]: '.format(self._user), 'Creazione delle chiavi TLS...')
        time.sleep(1)
        K = pow(params['B'], self._x, self._p)

        labels = [b'key 1', b'key 2', b'key 3', b'key 4']
        self.keys = []
        for label in labels:
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=label,
                backend=default_backend()
            )

            key = hkdf.derive(K.to_bytes(256, byteorder='big'))
            self.keys.append(key)

    def _step3MessageDecryptionAndVerification(self, params):
        """
        Esegue il terzo passo dell'handshake TLS.

        Args:
            params (dict): I parametri ricevuti dal server.
        """
        print('[User {}]: '.format(self._user), 'Verifica del certificato del server...')
        time.sleep(1)
        com = [Constants.OPENSSL, 'enc', '-d', '-aes-256-ctr', '-K', self.keys[0].hex(), '-iv', params['iv']]
        decryptedMessage = subprocess.check_output(com, input=params['encryptedMessage']).decode().strip()

        self._pks = decryptedMessage.split('\n')[0].strip()
        serverCertificate = decryptedMessage.split('\n')[1].strip()

        if CertificateUtils.verifyCertificate(serverCertificate, Constants.CA_FILE_PATH):
            com = [Constants.OPENSSL, 'enc', '-d', '-aes-256-ctr', '-K', self.keys[0].hex(), '-iv', params['iv']]
            decryptedSignature = subprocess.check_output(com, input=params['encryptedSignature']).decode().strip()

            if self._keyUtils.verifySign(decryptedMessage, decryptedSignature, self._pks):
                os.remove(decryptedSignature)
                print('[User {}]: '.format(self._user), 'Certificato verificato correttamente!')
                time.sleep(1)
                print('[User {}]: '.format(self._user), 'TLS handshake completato')
                time.sleep(1)
            else:
                print('[User {}]: '.format(self._user), 'Certificato non verificato!')
                self._user.closeConnection()
                return

    def encryptMessage(self, message):
        """
        Cifra un messaggio utilizzando AES-256-CTR. Il messaggio è anche autenticato utilizzando HMAC-SHA256.

        Args:
            message (str): Il messaggio da cifrare.

        Returns:
            tuple: Il messaggio cifrato, il tag HMAC e l'IV utilizzato per la cifratura.
        """
        com = [Constants.OPENSSL, 'rand', '16']
        iv = subprocess.check_output(com)

        com = [Constants.OPENSSL, 'enc', '-e', '-aes-256-ctr', '-K', self.keys[2].hex(), '-iv', iv.hex()]
        encryptedMessage = subprocess.check_output(com, input=str(message).encode('latin-1'))

        com = [Constants.OPENSSL, 'mac', '-digest', 'sha256', '-macopt', 'hexkey:' + self.keys[3].hex(), 'HMAC']
        tagMac = subprocess.check_output(com, input=encryptedMessage)

        return encryptedMessage, tagMac, iv

    def decryptMessage(self, encryptedMessage, tagMac, iv):
        """"
        Decifra un messaggio utilizzando AES-256-CTR. Il messaggio è anche autenticato utilizzando HMAC-SHA256.

        Args:
            encryptedMessage (str): Il messaggio cifrato.
            tagMac (str): Il tag HMAC.
            iv (str): L'IV utilizzato per la cifratura.

        Returns:
            str: Il messaggio decifrato.
        """
        com = [Constants.OPENSSL, 'mac', '-digest', 'sha256', '-macopt', 'hexkey:' + self.keys[3].hex(), 'HMAC']
        tagMacTemp = subprocess.check_output(com, input=encryptedMessage)

        if tagMacTemp == tagMac:
            com = [Constants.OPENSSL, 'enc', '-d', '-aes-256-ctr', '-K', self.keys[2].hex(), '-iv', iv.hex()]
            decryptedMessage = subprocess.check_output(com, input=encryptedMessage).decode('latin-1').strip()
            return decryptedMessage
        else:
            print(Constants.AUTHENTICATION_MESSAGE_ERR)
            self._user.closeConnection()
            return


class TLSServerHandler:
    """
    Questa classe gestisce l'handshake TLS dal lato del server.
    """
    def __init__(self, server, myfolder):
        """
        Inizializza la classe.

        Args:
            server (Server): L'oggetto server.
            myfolder (str): Il nome della cartella dove sono memorizzati i file del server.
        """
        self._myfolder = myfolder
        self._server = server
        self._connections = {}
        self._keyUtils = KeyUtils()

    @property
    def q(self):
        """
        Restituisce il parametro q dello scambio di chiavi Diffie-Hellman.
        """
        return self._q

    @property
    def g(self):
        """
        Restituisce il parametro g dello scambio di chiavi Diffie-Hellman.
        """
        return self._g

    @property
    def p(self):
        """
        Restituisce il parametro p dello scambio di chiavi Diffie-Hellman.
        """
        return self._p

    @property
    def connections(self):
        """
        Restituisce il dizionario delle connessioni.
        """
        return self._connections

    def tlsHandshake(self, params):
        """
        Esegue l'handshake TLS.

        Args:
            params (dict): I parametri ricevuti dal client.
        """
        callerFrame = inspect.currentframe().f_back
        callerSelf = callerFrame.f_locals.get('self', None)

        if params is not None:
            self._step1GenerateBAndK(params, callerSelf)
            self._step2SignAndEncrypt(params['user'], callerSelf)

    def _step1GenerateBAndK(self, params, callerSelf):
        """
        Esegue il primo passo dell'handshake TLS.

        Args:
            params (dict): I parametri ricevuti dal client.
            callerSelf (object): L'oggetto che ha chiamato la funzione.
        """
        print('[Server {}]: '.format(self._server), 'Invio del contributo DH...')
        time.sleep(1)
        print('[Server {}]: '.format(self._server), 'Generazione della chiave DH...')
        time.sleep(1)
        print('[Server {}]: '.format(self._server), 'Creazione delle chiavi TLS...')
        time.sleep(1)
        self._q = params['q']
        self._g = params['g']
        self._p = params['p']

        bytes_q = math.ceil((math.log2(abs(self._q) + 1)) / 8)
        com = [Constants.OPENSSL, 'rand', str(bytes_q)]
        y = int.from_bytes(subprocess.check_output(com), byteorder='big')

        B = pow(self._g, y, self._p)
        callerSelf.handshakeStep(2, {'B': B})

        K = pow(params['A'], y, self._p)

        labels = [b'key 1', b'key 2', b'key 3', b'key 4']
        self.keys = []
        for label in labels:
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=label,
                backend=default_backend()
            )

            key = hkdf.derive(K.to_bytes(256, byteorder='big'))
            self.keys.append(key)

        self._connections[params['user']] = self.keys

    def _step2SignAndEncrypt(self, user, callerSelf):
        """
        Esegue il secondo passo dell'handshake TLS.

        Args:
            user (str): L'utente che sta eseguendo l'handshake.
            callerSelf (object): L'oggetto che ha chiamato la funzione.
        """
        print('[Server {}]: '.format(self._server), 'Invio della chiave pubblica e del certificato...')
        time.sleep(1)
        signatureFile = self._myfolder + Constants.SIGNATURE_FILENAME
        message = self._myfolder + Constants.ECDSA_PUB_FILENAME + "\n" + self._myfolder + Constants.CERTIFICATE_FILENAME
        self._keyUtils.sign(message, self._myfolder + Constants.ECDSA_KEY_FILENAME, signatureFile)

        com = [Constants.OPENSSL, 'rand', '16']
        self.iv = subprocess.check_output(com)

        com = [Constants.OPENSSL, 'enc', '-e', '-aes-256-ctr', '-K', self._connections[user][0].hex(), '-iv',
               self.iv.hex()]
        encryptedMessage = subprocess.check_output(com, input=message.encode()).strip()

        message = self._myfolder + Constants.SIGNATURE_FILENAME
        com = [Constants.OPENSSL, 'enc', '-e', '-aes-256-ctr', '-K', self._connections[user][0].hex(), '-iv',
               self.iv.hex()]
        encryptedSignature = subprocess.check_output(com, input=message.encode())

        callerSelf.handshakeStep(3, {
            'encryptedMessage': encryptedMessage,
            'encryptedSignature': encryptedSignature,
            'iv': self.iv.hex()
        })

    def encryptMessage(self, message, user):
        """
        Cifra un messaggio.

        Args:
            message (str): Il messaggio da cifrare.
            user (str): L'utente che sta inviando il messaggio.

        Returns:
            tuple: Il messaggio cifrato, il tag MAC e l'IV utilizzato per la cifratura.
        """
        com = [Constants.OPENSSL, 'rand', '16']
        iv = subprocess.check_output(com)

        com = [Constants.OPENSSL, 'enc', '-e', '-aes-256-ctr', '-K', self._connections[user][2].hex(), '-iv', iv.hex()]
        encryptedMessage = subprocess.check_output(com, input=str(message).encode('latin-1'))

        com = [Constants.OPENSSL, 'mac', '-digest', 'sha256', '-macopt', 'hexkey:' + self._connections[user][3].hex(),
               'HMAC']
        tagMac = subprocess.check_output(com, input=encryptedMessage)

        return encryptedMessage, tagMac, iv

    def decryptMessage(self, encryptedMessage, tagMac, iv, user):
        """
        Decifra un messaggio.

        Args:
            encryptedMessage (bytes): Il messaggio cifrato.
            tagMac (bytes): Il tag MAC.
            iv (bytes): Il vettore di inizializzazione.
            user (str): L'utente che sta ricevendo il messaggio.

        Returns:
            str: Il messaggio decifrato.
        """
        com = [Constants.OPENSSL, 'mac', '-digest', 'sha256', '-macopt', 'hexkey:' + self._connections[user][3].hex(),
               'HMAC']
        tagMacTemp = subprocess.check_output(com, input=encryptedMessage)

        if tagMacTemp == tagMac:
            com = [Constants.OPENSSL, 'enc', '-d', '-aes-256-ctr', '-K', self._connections[user][2].hex(), '-iv',
                   iv.hex()]
            decryptedMessage = subprocess.check_output(com, input=encryptedMessage).decode('latin-1').strip()
            return decryptedMessage
        else:
            print(Constants.AUTHENTICATION_MESSAGE_ERR)
            self._server.closeConnection(user)
            return
