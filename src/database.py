class Database:
    """
    La classe Database rappresenta un database che memorizza informazioni sugli utenti e le loro Carte d'Identità Elettroniche (CIE).
    Ogni utente è identificato univocamente dal numero seriale della CIE e le corrispondenti informazioni della CIE sono memorizzate in un dizionario.
    La classe fornisce metodi per verificare l'esistenza di un utente, aggiungere una chiave pubblica di un utente e recuperare le informazioni degli utenti dal database.
    """

    users = {
            "RU65839UJ": {
                "nome": "Mario Rossi",
                "isee": "39000",
                "residenza": "IT",
                "data_nascita": "01-01-1980"
            },
            "AB12345CD": {
                "nome": "Luca Bianchi",
                "isee": "43000",
                "residenza": "IT",
                "data_nascita": "15-03-1992"
            },
            "EF67890GH": {
                "nome": "Giulia Verdi",
                "isee": "25000",
                "residenza": "IT",
                "data_nascita": "22-07-1985"
            },
            "IJ12345KL": {
                "nome": "Roberto Neri",
                "isee": "48000",
                "residenza": "IT",
                "data_nascita": "09-11-1978"
            },
            "MN67890OP": {
                "nome": "Elena Rossi",
                "isee": "32000",
                "residenza": "IT",
                "data_nascita": "30-05-1990"
            }
        }

    def checkUser(self, user):
        """
        Verifica se l'utente identificato dalla CIE fornita esiste nel database.

        Args:
            user (str): Il Seriale della CIE dell'utente da verificare.

        Returns:
            bool: True se l'utente esiste nel database, False altrimenti.
        """
        if user not in self.users.keys():
            return False
        return True

    def addUserPubKey(self, user, pubKey):
        """
        Aggiunge la chiave pubblica di un utente nel database.

        Args:
            user (str): Il Seriale della CIE dell'utente.
            pubKey (str): La chiave pubblica associata all'utente.
        """
        self.users[user]['pubKey'] = pubKey

    def getUserInfo(self, user):
        """
        Recupera le informazioni di un utente specifico dal database.

        Args:
            user (str): Il Seriale della CIE dell'utente.

        Returns:
            dict: Un dizionario contenente le informazioni dell'utente.
        """
        return self.users[user]
