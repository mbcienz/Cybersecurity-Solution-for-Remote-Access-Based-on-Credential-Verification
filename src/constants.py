class Constants:
    """
    Classe che contiene delle costanti di utilità.
    """

    ERR = -1

    # main.py constants
    IP_ARC = '163.202.113.13'
    IP_SR = '224.53.42.73'
    IP_SI = '192.123.365.7'
    IP_USER = '127.0.0.1'

    # openssl path
    OPENSSL = "openssl"

    # Key file path
    ECDSA_KEY_FILENAME = '/ecdsa_key.pem'
    ECDSA_PUB_FILENAME = '/ecdsa_pub.pem'
    ECDSA_PARAM_FILENAME = '/prime256v1.pem'
    DH_PARAM_FILENAME = '/dhparam.pem'
    DH_KEY_FILENAME = '/dhkey.pem'
    SIGNATURE_FILENAME = '/signature.bin'
    CERTIFICATE_FILENAME = '/cert.pem'
    CRED_SIGNATURE_FILENAME = '/Cred_signature.bin'

    # dir
    USER_DIR = './user'
    CA_DIR = './CA'
    SERVER_ARC_DIR = './server_arc'
    SERVER_ISEE_DIR = './server_isee'
    SERVER_RESIDENCE_DIR = './server_residence'
    CA_FILE_PATH = 'CA/cacert.pem'

    AUTHENTICATION_MESSAGE_ERR = 'Decifratura del messaggio fallita'

    # key_utils.py constants
    FILE_EXTENSION_MESSAGE_ERR = 'Estensione file sbagliata'

    # user.py constants
    SERVER_MESSAGE_ERR = 'Server non valido'
    CREDENTIALS_MESSAGE_ERR = '\nNon hai credenziali salvate!\n'

    # server.py constants
    USER_MESSAGE_ERR = 'Utente non trovato'
    CREDENTIALS_VERIFIED_MESSAGE_OK = 'Credenziali verificate'
    CREDENTIALS_VERIFIED_MESSAGE_ERR = 'Credenziali non verificate'
    CREDENTIALS_SIGNATURE_MESSAGE_OK = 'Firma delle credenziali verificata'
    CREDENTIALS_SIGNATURE_MESSAGE_ERR = 'Firma delle credenziali non verificata'
    AUTH_USER_MESSAGE_OK = 'Utente verificato correttamente...!'
    AUTH_USER_MESSAGE_ERR = 'Utente non verificato...!'
