import datetime
import ast
import subprocess
import time
from constants import Constants
from credentials import Credentials, VerifierCredentials
from database import Database
from keyUtils import KeyUtils
from mtls import MTLSServerHandler
from tls import TLSServerHandler


class Server:
    """
    Classe Server. Gestisce la connessione con il client.

    Attributes:
        _connections (dict): Dizionario delle connessioni attive
        _IP (str): Indirizzo IP del server
        _keyUtils (KeyUtils): Oggetto per la gestione delle chiavi
        _tlsHandler (TLSServerHandler): Oggetto gestore TLS
    """

    __slots__ = '_IP', '_keyUtils', '_connections', '_tlsHandler'

    def __init__(self, IP):
        """
        Costruttore della classe Server.

        Args:
            IP (str): Indirizzo IP del server
        """
        self._connections = {}
        self._IP = IP
        self._tlsHandler = None
        self._keyUtils = KeyUtils()

    def startConnection(self, user):
        """
        Avvia una nuova connessione con il client.

        Args:
            user (User): Oggetto utente
        """
        print('[Server {}]: '.format(self), 'Nuova connessione da {}'.format(user))
        self._connections[user] = None

    def closeConnection(self, user):
        """
        Chiude la connessione con il client.

        Args:
            user (User): Oggetto utente
        """
        print('[Server {}]: '.format(self), 'Chiusura connessione con {}...'.format(user))
        time.sleep(1)
        del self._connections[user]
        del self._tlsHandler._connections[user]
        print('[Server {}]: '.format(self), 'Connessione chiusa')

    @property
    def tlsHandler(self):
        """
        Getter dell'oggetto gestore TLS.
        """
        return self._tlsHandler

    @property
    def connections(self):
        """
        Getter del dizionario delle connessioni attive.
        """
        return self._connections


class ServerARC(Server):
    """
    Classe che estende la classe Server. Rappresenta il server dell'autorità del rilascio delle credenziali (ARC).

    Attributi:
        _internalDB (Database): Oggetto database interno
    """

    __slots__ = '_internalDB', '_myfolder', '_ecdsaKeyFile', '_ecdsaPubFile', '_ecdsaParamFile'

    def __init__(self, IP):
        """
        Costruttore della classe ServerARC.

        Args:
            IP (str): Indirizzo IP del server
        """
        super().__init__(IP)
        self._myfolder = Constants.SERVER_ARC_DIR
        self._ecdsaKeyFile = self._myfolder + Constants.ECDSA_KEY_FILENAME
        self._ecdsaPubFile = self._myfolder + Constants.ECDSA_PUB_FILENAME
        self._ecdsaParamFile = self._myfolder + Constants.ECDSA_PARAM_FILENAME
        self._tlsHandler = MTLSServerHandler(self, self._myfolder)
        self._internalDB = Database()

    def receiveInfoCIE(self, params, user):
        """
        Riceve le informazioni della CIE dal client.
        Se le informazioni sono corrette, invia invia le credenziali al client.
        Altrimenti, chiude la connessione.

        Args:
            params (dict): Dizionario dei parametri
            user (User): Oggetto utente
        """
        message = self._tlsHandler.decryptMessage(params['message'], params['tagMac'], params['iv'], user)
        message = ast.literal_eval(message)
        serial_CIE = message[0]
        expirationDateCIE = message[1]
        userPublicKey = message[2]
        print('[Server {}]: '.format(self), 'Informazioni sulla CIE ricevute')

        print('[Server {}]: '.format(self), 'Verifiche delle informazioni...')
        time.sleep(1)
        if not self._internalDB.checkUser(serial_CIE):
            print('[Server {}]: '.format(self), 'Utente non trovato')
            self.closeConnection(user)
            return Constants.ERR

        if datetime.datetime.strptime(expirationDateCIE, '%d-%m-%Y') < datetime.datetime.now():
            print('[Server {}]: '.format(self), 'CIE scaduta')
            self.closeConnection(user)
            return Constants.ERR

        print('[Server {}]: '.format(self), 'informazioni dell\'utente corrette')
        time.sleep(1)
        self.createAndSendCredentials(serial_CIE, userPublicKey, user)

    def createAndSendCredentials(self, serial_CIE, userPublicKey, user):
        """
        Crea e invia le credenziali all'utente.

        Args:
            serial_CIE (str): Numero di serie della CIE
            userPublicKey (str): Chiave pubblica dell'utente
            user (User): Oggetto utente
        """
        print('[Server {}]: '.format(self), 'Ricerca credenziali richieste nel database...')
        time.sleep(1)
        self._internalDB.addUserPubKey(serial_CIE, userPublicKey)
        print('[Server {}]: '.format(self), 'Creazione credenziali...')
        time.sleep(1)
        cred = Credentials(list(self._internalDB.getUserInfo(serial_CIE).items()))
        signatureFile = self._myfolder + Constants.CRED_SIGNATURE_FILENAME
        self._keyUtils.sign(cred.getCredentialsFootprint().decode(), self._ecdsaKeyFile, signatureFile)
        cred.setSignature(signatureFile)
        print('[Server {}]: '.format(self), 'Invio credenziali...')
        time.sleep(1)
        user.receiveCredentials(cred)
        print('[Server {}]: '.format(self), 'Credenziali inviate')
        time.sleep(1)

    def __str__(self) -> str:
        """
        Rappresentazione in stringa dell'oggetto.
        """
        return 'Server_ARC_' + self._IP


def check_residence(residence):
    """
        Controlla se l'utente è residente in Spagna
        Args:
            residence (str): Residenza utente
        """
    if residence == 'ES':
        return True
    else:
        return False


class ServerResidence(Server):
    """
    Classe che estende la classe Server. Rappresenta il server residence.

    """

    __slots__ = '_internalDB', '_myfolder', '_ecdsaKeyFile', '_ecdsaPubFile', '_ecdsaParamFile'

    def __init__(self, IP):
        """
        Costruttore della classe ServerResidence.

        Args:
            IP (str): Indirizzo IP del server
        """
        super().__init__(IP)
        self._myfolder = Constants.SERVER_RESIDENCE_DIR
        self._ecdsaKeyFile = self._myfolder + Constants.ECDSA_KEY_FILENAME
        self._ecdsaPubFile = self._myfolder + Constants.ECDSA_PUB_FILENAME
        self._ecdsaParamFile = self._myfolder + Constants.ECDSA_PARAM_FILENAME
        self._tlsHandler = TLSServerHandler(self, self._myfolder)

    def step1ReceiveInfoCredentials(self, params, user):
        """
        Riceve e verifica le informazioni iniziali sulle credenziali. In caso di esito positivo,
        continua con l'autenticazione dell'utente; in caso contrario, termina la connessione.

        Args:
            params (dict): dizionario dei parametri
            user (User): oggetto utente
        """
        if user not in self._connections:
            print('[Server {}]: '.format(self), Constants.USER_MESSAGE_ERR)
            time.sleep(1)
            self.closeConnection(user)
            return

        message = self._tlsHandler.decryptMessage(params['message'], params['tagMac'], params['iv'], user)
        message = ast.literal_eval(message)

        pubkeyUser, pubkeyUserProof = message[0], message[1]
        cred_signature = message[2]

        # La chiave dell'ARC viene considerata pubblica e accessibile a tutti
        pubkeyARC = Constants.SERVER_ARC_DIR + Constants.ECDSA_PUB_FILENAME

        # Calcola la root a partire dal dato e la sua proof
        credFootprint = VerifierCredentials.computeRootFromProof(pubkeyUser, pubkeyUserProof)

        # Verifica firma root credenziali
        if self._keyUtils.verifySign(credFootprint.decode(), cred_signature, pubkeyARC):
            self._connections[user] = {'pubkey': pubkeyUser, 'credFootprint': credFootprint}
            print('[Server {}]: '.format(self), Constants.CREDENTIALS_SIGNATURE_MESSAGE_OK)
            time.sleep(1)
        else:
            print('[Server {}]: '.format(self), Constants.CREDENTIALS_SIGNATURE_MESSAGE_ERR)
            time.sleep(1)
            self.closeConnection(user)
            return

        # Autenticazione utente
        self.step2AuthenticateUser(user)

    def step2AuthenticateUser(self, user):
        """
        Controlla se l'utente possiede la chiave privata associata alla chiave pubblica delle credenziali,
        facendogli firmare una stringa random a 256bit.

        Args:
            user (User): oggetto utente
        """
        print('[Server {}]: '.format(self), 'Inizio autenticazione utente -> creazione stringa random a 256bit...')
        time.sleep(1)

        com = [Constants.OPENSSL, 'rand', '-hex', '32']
        r = subprocess.check_output(com).decode('utf-8').strip()
        encryptedMessage, tagMac, iv = self._tlsHandler.encryptMessage(r, user)
        print('[Server {}]: '.format(self), 'Invio stringa random a 256bit...')
        time.sleep(1)

        signature_r = user.receiveRandomString({'message': encryptedMessage, 'tagMac': tagMac, 'iv': iv})
        print('[Server {}]: '.format(self), 'Verifica firma utente della stringa random a 256bit...')
        time.sleep(1)
        pubkeyUser = self._connections[user]['pubkey']

        # L'utente firma con la CIE l'hash del msg
        com = [Constants.OPENSSL, 'dgst', '-sha256']
        r_hashed = subprocess.check_output(com, input=r.encode('utf-8')).decode('utf-8').strip()

        # Verifica della firma
        if self._keyUtils.verifySign(r_hashed, signature_r, pubkeyUser):
            print('[Server {}]: '.format(self), Constants.AUTH_USER_MESSAGE_OK)
            time.sleep(1)
        else:
            print('[Server {}]: '.format(self), Constants.AUTH_USER_MESSAGE_ERR)
            time.sleep(1)
            self.closeConnection(user)
            return
        user.requestResidence()

    def step3ReceiveResidenceCredential(self, params, user):
        """
        Funzione per ricevere e verificare le credenziali sulla residenza. In caso di esito positivo,
        viene concesso l'accesso al servizio; in caso contrario, l'accesso viene negato.

        Args:
            params (dict): dizionario dei parametri
            user (User): oggetto utente
        """
        if user not in self._connections:
            print('[Server {}]: '.format(self), Constants.USER_MESSAGE_ERR)
            time.sleep(1)
            self.closeConnection(user)
            return

        print('[Server {}]: '.format(self), 'Credenziale residenza ricevuto...!')
        time.sleep(1)

        message = self._tlsHandler.decryptMessage(params['message'], params['tagMac'], params['iv'], user)
        message = ast.literal_eval(message)
        residence, residenceProof = message[0], message[1]
        credFootprint = self._connections[user]['credFootprint']

        print('[Server {}]: '.format(self), 'Verifica validità credenziale residenza...')
        time.sleep(1)

        # Verifica se la root calcolata dal dato e dalla sua proof è uguale a quella del documento calcolata precedentemente
        if VerifierCredentials.computeRootFromProof(residence, residenceProof) == credFootprint:
            print('[Server {}]: '.format(self), Constants.CREDENTIALS_VERIFIED_MESSAGE_OK)
            time.sleep(1)

            if check_residence(residence):
                print('[Server {}]: '.format(self), 'Accesso al servizio consentito, requisiti rispettati...!')
                time.sleep(1)
                self.releaseService()
                self.closeConnection(user)
                return
            else:
                print('[Server {}]: '.format(self), 'Accesso al servizio negato, requisiti non rispettati...!')
                time.sleep(1)
                self.closeConnection(user)
                return
        else:
            print('[Server {}]: '.format(self), Constants.CREDENTIALS_VERIFIED_MESSAGE_ERR)
            time.sleep(1)
            self.closeConnection(user)
            return

    def releaseService(self):
        """
        Funzione per simulare il rilascio del servizio riservato ai residenti in spagna
        """
        for i in range(10):
            print("BIT Servizio riservato ad utenti maggiorenni con ISEE < 40000 ...")
            time.sleep(1)

    def __str__(self) -> str:
        """
        String representation of the object.
        """
        return 'Server_residence_' + self._IP


def check_ISEE(isee):
    """
    Controlla se l'utente ha ISEE <= 40000
    Args:
        isee (str): isee utente
    """
    return int(isee) <= 40000


def check_date(date):
    """
    Controlla se l'utente è maggiorenne
    Args:
        date (str): data di nascita utente
    """
    birth_date = datetime.datetime.strptime(date, "%d-%m-%Y")

    # Calcola la data attuale
    today = datetime.datetime.today()

    # Calcola l'età
    age = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))

    # Verifica se l'età è almeno 18 anni
    return age >= 18


class ServerISEE(Server):
    """
    Classe che estende la classe Server. Rappresenta il server isee.

    """

    __slots__ = '_internalDB', '_myfolder', '_ecdsaKeyFile', '_ecdsaPubFile', '_ecdsaParamFile'

    def __init__(self, IP):
        """
        Costruttore della classe ServerISEE.

        Args:
            IP (str): Indirizzo IP del server
        """
        super().__init__(IP)
        self._myfolder = Constants.SERVER_ISEE_DIR
        self._ecdsaKeyFile = self._myfolder + Constants.ECDSA_KEY_FILENAME
        self._ecdsaPubFile = self._myfolder + Constants.ECDSA_PUB_FILENAME
        self._ecdsaParamFile = self._myfolder + Constants.ECDSA_PARAM_FILENAME
        self._tlsHandler = TLSServerHandler(self, self._myfolder)

    def step1ReceiveInfoCredentials(self, params, user):
        """
        Riceve e verifica le informazioni iniziali sulle credenziali. In caso di esito positivo,
        continua con l'autenticazione dell'utente; in caso contrario, termina la connessione.

        Args:
            params (dict): dizionario dei parametri
            user (User): oggetto utente
        """
        if user not in self._connections:
            print('[Server {}]: '.format(self), Constants.USER_MESSAGE_ERR)
            time.sleep(1)
            self.closeConnection(user)
            return

        message = self._tlsHandler.decryptMessage(params['message'], params['tagMac'], params['iv'], user)
        message = ast.literal_eval(message)

        pubkeyUser, pubkeyUserProof = message[0], message[1]
        cred_signature = message[2]

        # La chiave dell'ARC viene considerata pubblica e accessibile a tutti
        pubkeyARC = Constants.SERVER_ARC_DIR + Constants.ECDSA_PUB_FILENAME

        # Calcola la root a partire dal dato e la sua proof
        credFootprint = VerifierCredentials.computeRootFromProof(pubkeyUser, pubkeyUserProof)

        # Verifica firma root credenziali
        if self._keyUtils.verifySign(credFootprint.decode(), cred_signature, pubkeyARC):
            self._connections[user] = {'pubkey': pubkeyUser, 'credFootprint': credFootprint}
            print('[Server {}]: '.format(self), Constants.CREDENTIALS_SIGNATURE_MESSAGE_OK)
            time.sleep(1)
        else:
            print('[Server {}]: '.format(self), Constants.CREDENTIALS_SIGNATURE_MESSAGE_ERR)
            time.sleep(1)
            self.closeConnection(user)
            return

        # Autenticazione utente
        self.step2AuthenticateUser(user)

    def step2AuthenticateUser(self, user):
        """
        Controlla se l'utente possiede la chiave privata associata alla chiave pubblica delle credenziali,
        facendogli firmare una stringa random a 256bit.

        Args:
            user (User): oggetto utente
        """
        print('[Server {}]: '.format(self), 'Inizio autenticazione utente -> creazione stringa random a 256bit...')
        time.sleep(1)

        com = [Constants.OPENSSL, 'rand', '-hex', '32']
        r = subprocess.check_output(com).decode('utf-8').strip()
        encryptedMessage, tagMac, iv = self._tlsHandler.encryptMessage(r, user)
        print('[Server {}]: '.format(self), 'Invio stringa random a 256bit...')
        time.sleep(1)

        signature_r = user.receiveRandomString({'message': encryptedMessage, 'tagMac': tagMac, 'iv': iv})
        print('[Server {}]: '.format(self), 'Verifica firma utente della stringa random a 256bit...')
        time.sleep(1)
        pubkeyUser = self._connections[user]['pubkey']

        # L'utente firma con la CIE l'hash del msg
        com = [Constants.OPENSSL, 'dgst', '-sha256']
        r_hashed = subprocess.check_output(com, input=r.encode('utf-8')).decode('utf-8').strip()

        # Verifica della firma
        if self._keyUtils.verifySign(r_hashed, signature_r, pubkeyUser):
            print('[Server {}]: '.format(self), Constants.AUTH_USER_MESSAGE_OK)
            time.sleep(1)
        else:
            print('[Server {}]: '.format(self), Constants.AUTH_USER_MESSAGE_ERR)
            time.sleep(1)
            self.closeConnection(user)
            return
        user.requestISEE()

    def step3ReceiveISEECredential(self, params, user):
        """
        Funzione per ricevere le credenziali su isee e data_nascita. In caso di esito positivo,
        viene concesso l'accesso al servizio; in caso contrario, l'accesso viene negato.
        Args:
            params (dict): dizionario dei parametri
            user (User): oggetto utente
        """
        if user not in self._connections:
            print('[Server {}]: '.format(self), Constants.USER_MESSAGE_ERR)
            time.sleep(1)
            self.closeConnection(user)
            return

        print('[Server {}]: '.format(self), 'Credenziali ISEE e data di nascita ricevute...!')
        time.sleep(1)

        message = self._tlsHandler.decryptMessage(params['message'], params['tagMac'], params['iv'], user)
        message = ast.literal_eval(message)
        isee, iseeProof = message[0], message[1]
        date, dateProof = message[2], message[3]
        credFootprint = self._connections[user]['credFootprint']

        print('[Server {}]: '.format(self), 'Verifica validità credenziali ISEE e data di nascita...')
        time.sleep(1)

        # Verifica se la root calcolata dal dato e dalla sua proof è uguale a quella del documento calcolata precedentemente (per ogni credenziale)
        if ((VerifierCredentials.computeRootFromProof(isee, iseeProof) == credFootprint) and
                (VerifierCredentials.computeRootFromProof(date, dateProof) == credFootprint)):
            print('[Server {}]: '.format(self), Constants.CREDENTIALS_VERIFIED_MESSAGE_OK)
            time.sleep(1)

            if check_ISEE(isee) and check_date(date):
                print('[Server {}]: '.format(self), 'Accesso al servizio consentito, requisiti rispettati...!')
                time.sleep(1)
                self.releaseService()
                self.closeConnection(user)
                return
            else:
                print('[Server {}]: '.format(self), 'Accesso al servizio negato, requisiti non rispettati...!')
                time.sleep(1)
                self.closeConnection(user)
                return
        else:
            print('[Server {}]: '.format(self), Constants.CREDENTIALS_VERIFIED_MESSAGE_ERR)
            time.sleep(1)
            self.closeConnection(user)
            return

    def releaseService(self):
        """
        Funzione per simulare il rilascio del servizio riservato a utenti maggiorenni con ISEE < 40000
        """
        for i in range(10):
            print("BIT Servizio riservato ad utenti maggiorenni con ISEE < 40000 ...")
            time.sleep(1)

    def __str__(self) -> str:
        """
        String representation of the object.
        """
        return 'Server_ISEE_' + self._IP
