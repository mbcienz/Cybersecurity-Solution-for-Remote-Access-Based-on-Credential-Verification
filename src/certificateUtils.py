from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature


class CertificateUtils:
    """
    Questa classe contiene alcuni metodi di utilità per i certificati.
    """

    @staticmethod
    def loadCertificate(filePath):
        """
        Carica un certificato dal percorso del file fornito.

        Args:
            filePath (str): Il percorso del file contenente il certificato.
        """
        with open(filePath, 'rb') as file:
            certData = file.read()
        return x509.load_pem_x509_certificate(certData, default_backend())

    @staticmethod
    def verifyCertificate(certPath, caCertPath):
        """
        Verifica il certificato fornito utilizzando il certificato CA fornito.

        Args:
            certPath (str): Il percorso del file contenente il certificato da verificare.
            caCertPath (str): Il percorso del file contenente il certificato CA.

        Returns:
            bool: True se il certificato è valido, False altrimenti.
        """
        cert = CertificateUtils.loadCertificate(certPath)
        caCert = CertificateUtils.loadCertificate(caCertPath)

        publicKey = caCert.public_key()
        try:
            publicKey.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            return False