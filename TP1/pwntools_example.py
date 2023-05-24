from pwn import *
from Crypto.Util.number import *
import codecs
import json

r = remote('socket.cryptohack.org', 13377, level = 'debug')

def json_recv():
    line = r.recvline()
    return json.loads(line.decode())

def json_send(hsh):
    request = json.dumps(hsh).encode()
    r.sendline(request)

def decode(jsonEncode):
    #{"type": "base64", "encoded": "d2FsbHBhcGVyX3VwcGVyX3R1Yg=="}
    encoding = jsonEncode["type"]
    encoded = jsonEncode["encoded"]
    flag = jsonEncode.get("flag")
    if(flag is not None): print('flag', flag)

    if encoding == "base64":
        #encoded = base64.b64encode(self.challenge_words.encode()).decode() # wow so encode
        deco = base64.b64decode(encoded).decode()
    elif encoding == "hex":
        #encoded = self.challenge_words.encode().hex()
        deco = bytes.fromhex(encoded).decode()
    elif encoding == "rot13":
        #encoded = codecs.encode(self.challenge_words, 'rot_13')
        deco = codecs.decode(encoded, 'rot13')
    elif encoding == "bigint":
        #encoded = hex(bytes_to_long(self.challenge_words.encode()))
        #deco = long_to_bytes(bytes.fromhex(encoded[2:])).decode()
        deco = bytes.fromhex(encoded[2:]).decode()
    elif encoding == "utf-8":
        #encoded = [ord(b) for b in self.challenge_words]
        deco = str().join([chr(b) for b in encoded])

    print('Decoded: ', deco)
    return {"decoded": deco}

for i in range(105):
    received = json_recv()
    json_send(decode(received))

