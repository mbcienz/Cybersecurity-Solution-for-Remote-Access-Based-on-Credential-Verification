
import subprocess

from constants import Constants

class Node:
    """
    Classe Node, utilizzata per costruire il Merkle Tree.

    Attributi:
        _left (Node): Il figlio sinistro del nodo.
        _right (Node): Il figlio destro del nodo.
        _father (Node): Il padre del nodo.
        _data (str): I dati del nodo.
    """

    __slots__ = '_left', '_right', '_father' ,'_data'

    def __init__(self, data):
        """
        Costruttore della classe Node.

        Args:
            data (str): I dati del nodo.
        """
        self._left = None
        self._right = None
        self._father = None
        self._data = data

    def __str__(self):
        """
        Restituisce la rappresentazione in stringa del nodo.
        """
        return str(self._data)
    
    
class LeafNode(Node):
    """
    Classe LeafNode, utilizzata per costruire il Merkle Tree.

    Attributi:
        _rowData (str): I dati del nodo.
    """

    __slots__ = '_rowData'

    def __init__(self, data):
        """
        Costruttore della classe LeafNode.

        Args:
            data (str): I dati del nodo.
        """
        com = [Constants.OPENSSL, 'dgst', '-sha256']
        super().__init__(subprocess.check_output(com, input=data.encode('utf-8')).strip())
        self._rowData = data

    def __str__(self):
        """
        Restituisce la rappresentazione in stringa del nodo foglia.
        """
        return "Leaf Node: " + str(self._rowData) + " " + str(self._data)


class MerkleTree:
    """
    Classe Merkle Tree.

    Attributi:
        _root (Node): La radice del Merkle Tree.
        _leaves (dict): Le foglie del Merkle Tree.
    """

    __slots__ = '_root', '_leaves'

    def __init__(self, data):
        """
        Costruttore della classe MerkleTree.

        Args:
            data (list): I dati da memorizzare nel Merkle Tree.
        """
        self._leaves = {}
        if len(data) % 2 != 0:
            data.append(data[-1])
        self._root = self._buildTree(data)
    
    def _buildTree(self, data):
        """
        Costruisce il Merkle Tree dai dati forniti.

        Args:
            data (list): I dati da memorizzare nel Merkle Tree.

        Returns:
            Node: La radice del Merkle Tree.
        """
        queue = []
        for elem in data:
            temp = LeafNode(elem[1])
            self._leaves[elem[0]] = temp
            queue.append(temp)
        while len(queue) > 1:
            left = queue.pop(0)
            right = queue.pop(0)
            queue.append(self._makeNode(left, right))
        return queue.pop(0)
    
    def getDataFromId(self, id):
        """
        Restituisce i dati associati all'ID fornito.

        Args:
            id (str): L'ID dei dati da restituire.

        Returns:
            str: I dati associati all'ID fornito.
        """
        return self._leaves[id]._rowData

    def getProof(self, data):
        """
        Restituisce la prova dei dati forniti.

        Args:
            data (str): I dati di cui ottenere la prova.

        Returns:
            list: La prova dei dati forniti.
        """
        proof = []
        node = self._leaves[data]
        if node == None:
            raise Exception("Data not found")
        while node._father != None:
            if node._father._left == node:
                proof.append((node._father._right._data, True))
            else:
                proof.append((node._father._left._data, False))
            node = node._father
        return proof
    
    @staticmethod
    def computeRootFromProof(data, proof):
        """
        Calcola la root a partire da un dato e la sua proof.

        Args:
            data (str): I dati da verificare.
            proof (list): La prova dei dati forniti.

        Returns:
            res (str): La radice del Merkle Tree calcolata.
        """
        if data is None or proof is None or len(proof) == 0:
            return False 
        com = [Constants.OPENSSL, 'dgst', '-sha256']
        res = subprocess.check_output(com, input=data.encode('utf-8')).strip()
        while len(proof) > 0:
            elem = proof.pop(0)
            if not elem[1]:
                # elem is a left child
                com = [Constants.OPENSSL, 'dgst', '-sha256']
                res = subprocess.check_output(com, input=elem[0] + res).strip()
            else:
                # elem is a right child
                com = [Constants.OPENSSL, 'dgst', '-sha256']
                res = subprocess.check_output(com, input=res + elem[0]).strip()
        return res
    
    def getRoot(self):
        """
        Restituisce la radice del Merkle Tree.

        Returns:
            Node: La radice del Merkle Tree.
        """
        return self._root
    
    def getRootHash(self):
        """
        Restituisce l'hash della radice del Merkle Tree.

        Returns:
            str: L'hash della radice del Merkle Tree.
        """
        return self._root._data

    def _makeNode(self, left, right):
        """
        Crea un nuovo nodo dai nodi forniti.

        Args:
            left (Node): Il figlio sinistro del nuovo nodo.
            right (Node): Il figlio destro del nuovo nodo.

        Returns:
            Node: Il nuovo nodo.
        """
        com = [Constants.OPENSSL, 'dgst', '-sha256']
        node = Node(subprocess.check_output(com, input=left._data + right._data).strip())
        node._left = left
        node._right = right
        node._left._father = node
        node._right._father = node
        return node
    
    def __str__(self):
        """
        Restituisce la rappresentazione in stringa del Merkle Tree.
        """
        return self._printTree(self._root, 0)
    
    def _printTree(self, node, level):
        """
        Restituisce la rappresentazione in stringa del Merkle Tree.

        Args:
            node (Node): Il nodo da stampare.
            level (int): Il livello del nodo.

        Returns:
            str: La rappresentazione in stringa del Merkle Tree.
        """
        if node == None:
            return ""
        else:
            return self._printTree(node._left, level+1) + "\n" + "\t"*level + str(node) + self._printTree(node._right, level+1)
