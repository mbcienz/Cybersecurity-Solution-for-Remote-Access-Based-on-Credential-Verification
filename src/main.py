import sys
import time
from constants import Constants
from server import ServerARC, ServerResidence, ServerISEE
from user import User

serverARC = ServerARC(Constants.IP_ARC)
serverResidence = ServerResidence(Constants.IP_SR)
serverISEE = ServerISEE(Constants.IP_SI)
user = User(Constants.IP_USER)

print("\n$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$")
print("\n$                INIZIO SIMULAZIONE                 $")
print("\n$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$")

time.sleep(1)

print("\n$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$")
print("\n$                RICHIESTA CREDENZIALI              $")
print("\n$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$")

if user.connectMTLS(serverARC) == Constants.ERR:
    print("ERRORE")
    sys.exit(1)

time.sleep(1)

if user.requestCredentials() == Constants.ERR:
    print("ERRORE")
    sys.exit(1)

time.sleep(1)

print("\n$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$")
print("\n$            ACCESSO AL SERVIZIO RESIDENZA          $")
print("\n$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$")

if user.connectTLS(serverResidence) == Constants.ERR:
    print("ERRORE")
    sys.exit(1)

time.sleep(1)

if user.sendInitialInfoCredentials() == Constants.ERR:
    print("ERRORE")
    sys.exit(1)

time.sleep(1)

print("\n$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$")
print("\n$                ACCESSO AL SERVIZIO ISEE           $")
print("\n$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$")

if user.connectTLS(serverISEE) == Constants.ERR:
    print("ERRORE")
    sys.exit(1)

time.sleep(1)

if user.sendInitialInfoCredentials() == Constants.ERR:
    print("ERRORE")
    sys.exit(1)

time.sleep(1)

print("\n$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$")
print("\n$                   FINE SIMULAZIONE                $")
print("\n$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n")