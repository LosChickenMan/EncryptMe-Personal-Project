import secrets
import base64

class EncryptMyData:
    def __init__(self):
        self._plaindata = ''
        self._cipherdata = ''
        self._encryptionalg = ''
        self._processComplete = False
        self._timeOfExecution = ''

    def _inputdata(self, data: str):
        self._plaindata = data

    def _setTimeofExecution(self, timestamp: str):
        self._timeOfExecution = timestamp

    def _setCompletion(self, status: bool):
        self._processComplete = status

    def setAlgor(self, algorithm: str):
        self._encryptionalg = algorithm
# A salt is added to a hash to make it less predicatble when trying to crack the hash
# This algorithm generates a psuedorandom value from the OS and converts it to a value in b64 
# which is reable for the program.

class SaltGenerator(EncryptMyData): 
    def generate_salt(self, length: int=32) -> bytes:
        salt = secrets.token_bytes(length)
        self._cipherdata = base64.b64encode(salt).decode('utf-8')
        self._setCompletion(True)
        return salt
