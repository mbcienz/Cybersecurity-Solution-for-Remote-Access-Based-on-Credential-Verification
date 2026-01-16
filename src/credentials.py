from merkle_tree import MerkleTree


class Credentials:
    """
    Classe che rappresenta un sistema di gestione delle credenziali digitali.

    Attributi:
        _merkleTree (MerkleTree): Il Merkle Tree che contiene i dati delle credenziali.
        _signature (str): La firma delle credenziali.
    """

    __slots__ = '_merkleTree', '_signature'

    def __init__(self, data):
        """
        Costruttore della classe Credentials.

        Args:
            data (dict): I dati da memorizzare nel Merkle Tree.
        """
        self._signature = None
        self._merkleTree = MerkleTree(data)

    def getData(self, id):
        """
        Restituisce i dati associati all'ID fornito.

        Args:
            id (str): L'identificatore dei dati da recuperare.

        Returns:
            I dati associati all'ID fornito.
        """
        return self._merkleTree.getDataFromId(id)

    def getDataProof(self, data):
        """
        Restituisce la prova dei dati forniti.

        Args:
            data (str): I dati di cui ottenere la prova.

        Returns:
            list: La prova dei dati forniti.
        """
        return self._merkleTree.getProof(data)

    def getCredentialsFootprint(self):
        """
        Restituisce la radice del Merkle Tree.

        Returns:
            str: La radice del Merkle Tree.
        """
        return self._merkleTree.getRootHash()

    def setSignature(self, signature):
        """
        Imposta la firma delle credenziali.

        Args:
            signature (str): La firma delle credenziali.
        """
        self._signature = signature

    def getSignature(self):
        """
        Restituisce la firma delle credenziali.

        Returns:
            str: La firma delle credenziali.
        """
        return self._signature


class VerifierCredentials:
    """
    Classe che contiene un metodo per verificare le credenziali digitali.
    """

    @staticmethod
    def computeRootFromProof(data, proof):
        """
        Calcola la root a partire da un dato e la sua proof.

        Args:
            data (str): I dati da verificare.
            proof (list): La prova dei dati forniti.

        Returns:
            root (str): La radice del Merkle Tree calcolata.
        """
        return MerkleTree.computeRootFromProof(data, proof)
