import base64
from Crypto.Util.number import *
from pwn import xor
import numpy
from PIL import Image
from gmpy2 import *
from Crypto.PublicKey import RSA
#TP1

#Encoding
print("1. ASCII")
print("Se recorre cada elemento del vector y se muestra su valor ASCII en el caracter que representa")
asciiArray = [99, 114, 121, 112, 116, 111, 123, 65, 83, 67, 73, 73, 95, 112, 114, 49, 110, 116, 52, 98, 108, 51, 125]
for code in asciiArray:
    print(chr(code), end='')
print("")
"FLAG=crypto{ASCII_pr1nt4bl3}"

print("2. Hex")
print("Cada par de digito hexadecimal se asocia a un valor ascii que representa un caracter.")
print(bytes.fromhex('63727970746f7b596f755f77696c6c5f62655f776f726b696e675f776974685f6865785f737472696e67735f615f6c6f747d'))
"FLAG=crypto{You_will_be_working_with_hex_strings_a_lot}"

print("3. Base64")
print("Cada par de digito hexadecimal se traduce a ascii y luego se presenta la salida en base64 agrupando de a 6 bits.")
decodeHex = bytes.fromhex('72bca9b68fc16ac7beeb8f849dca1d8a783e8acf9679bf9269f7bf')
print("Decode hex:", decodeHex)
encodeBase64 = base64.b64encode(decodeHex)
print("Encode base64:", encodeBase64)
"FLAG=crypto/Base+64+Encoding+is+Web+Safe/"

print("4. Bytes and Big Integers")
print("Se pasa de base decimal a bytes, cada caracter ascii ocupa un byte. Es necesario pasar primero a base hexadecimal para facilitar calculos")
baseDecimal = '11515195063862318899931685488813747395775516287289682636499965282714637259206269'
print(long_to_bytes(baseDecimal))
"FLAG=crypto{3nc0d1n6_4ll_7h3_w4y_d0wn}"

print("5. Encoding Challenge")
print("Se debe aplicar las operaciones inversas a como lo cifra el servidor")
"FLAG=crypto{3nc0d3_d3c0d3_3nc0d3}"

#XOR
print("1. XOR Starter")
print("Se debe enmascarar bit a bit operando con un xor obteniendo un nuevo valor de cadena")
print(xor('label'.encode(), 13))
"FLAG=crypto{aloha}"

print("2. XOR Properties")
print("Xor es una operacion reversible, aplicandola bit a bit desde la base hexadecimal"
+" se puede despejar cada key hasta encontrar los bytes de flag")
"""
Commutative: A ⊕ B = B ⊕ A
Associative: A ⊕ (B ⊕ C) = (A ⊕ B) ⊕ C
Identity: A ⊕ 0 = A
Self-Inverse: A ⊕ A = 0
"""
KEY1 = 'a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313'
KEY2_KEY1 = '37dcb292030faa90d07eec17e3b1c6d8daf94c35d4c9191a5e1e'
KEY2_KEY3 = 'c1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1'
FLAG_KEY1_KEY3_KEY2 = '04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf'
#DECODE
KEY2 = xor(bytes.fromhex(KEY1), bytes.fromhex(KEY2_KEY1))
#print("KEY2", KEY2)
#print("KEY2 HEX", KEY2.hex())

KEY3 = xor(KEY2, bytes.fromhex(KEY2_KEY3))
#print("KEY3", KEY3)
#print("KEY3 HEX", KEY3.hex())

FLAG_KEY1_KEY3 = xor(bytes.fromhex(FLAG_KEY1_KEY3_KEY2), KEY2)
#print("FLAG_KEY1_KEY2", FLAG_KEY1_KEY3)
#print("FLAG_KEY1_KEY2 HEX", FLAG_KEY1_KEY3.hex())

FLAG_KEY1 = xor(FLAG_KEY1_KEY3, KEY3)
#print("FLAG_KEY1", FLAG_KEY1)
#print("FLAG_KEY1 HEX", FLAG_KEY1.hex())

FLAG = xor(FLAG_KEY1, bytes.fromhex(KEY1))
print("FLAG", FLAG)
#print("FLAG HEX", FLAG.hex())
"FLAG=crypto{x0r_i5_ass0c1at1v3}"

print("3. Favourite byte")
print("Se recorre el espacio de un byte 0 a 256, y con cada valor se hace xor bit a bit sobre la llave")
BYTE_ENCODED_HEX = '73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d'

BYTE_ENCODED = bytes.fromhex(BYTE_ENCODED_HEX)
for byte in range(256):
    flag_bytes = xor(byte, BYTE_ENCODED)
    flag = flag_bytes.decode()
    if flag.startswith("crypto"):
        print(flag)
        break
"FLAG=crypto{0x10_15_my_f4v0ur173_by7e}"

print("4. You either know, XOR you don't")
print("Se hace xor con el comienzo del flag conocido 'crypto{' obteniendo la key con la que se cifro el mensaje."
+" Luego se utiliza esa key repetidamente bit a bit para decifrar el flag")
BYTE_ENCODED_HEX = '0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104'
#SECRET_KEY = b'crypto{'
SECRET_KEY = b'myXORkey'

print(xor(SECRET_KEY, bytes.fromhex(BYTE_ENCODED_HEX)))
"FLAG=crypto{1f_y0u_Kn0w_En0uGH_y0u_Kn0w_1t_4ll}"

print("5. Lemour XOR")
print("Se asume que cada pixel RGB es son 8bits."
+" Se hace XOR byte a byte entre las dos imagenes para mostrar una nueva imagen")


img1 = Image.open('lemur.png')
img1_mat = numpy.array(img1)
img2 = Image.open('flag.png')
img2_mat = numpy.array(img2)

result_image = numpy.bitwise_xor(img1_mat, img2_mat).astype(numpy.uint8)
Image.fromarray(result_image).save('result.png')
"FLAG=crypto{X0Rly_n0t!}"

#Mathematics
print("1. Greatest Common Divisor")
print("Se obtiene el divisor comun mayor a traves del metodo de Euclides")
"""def gcd(a, b):
    while b != 0:
        t = b
        b = a%b
        a = t
    return a"""

print(gcd(66528, 52920))
"FLAG=1512"

print("2. Extended GCD")
print("Se buscan dos multiplos de numeros primos en el cual la suma sea igual a 1")
print(gcdext(26513, 32321))
"FLAG=-8404"

print("3. Modular Arithmetic 1")
print("Para obtener el valor decimal en el espacio de modulo, se divide dicho numero por el modulo, el resto sera su valor en dicho espacio")

#11 = x mod 6
x=11%6 #5

#8146798528947 ≡ y mod 17
y=8146798528947%17 #4

"FLAG=4"

print("4. Modular Arithmetic 2")
print("Un numero elevado al modulo-1, siempre termina siendo 1 en el espacio del modulo")
#273246787654**65536%65537=1
"FLAG=1"

print("5. Modular Inverting")
print("La inversa de un numero multiplicada por el numero es igual a 1 en el modulo p")
#3*9=26
#26/13=1
#3*9=1 mod 13
"FLAG=9"

#DATA FORMATS
print("1. Privacy-Enhanced Mail?")
print("Se debe abrir un archivo y descifrar su contenido usando el algoritmo RSA. Que se compone por un cifrado DER ASN.1 y luego base64")
pemFile = open("./privacy_enhanced_mail.pem", 'r')
rsaKey = RSA.importKey(pemFile.read())

print(rsaKey)
rsaKeyStr = rsaKey.exportKey().decode()
print(rsaKeyStr)
print(rsaKeyStr[len("-----BEGIN RSA PRIVATE KEY-----")+1:-len("-----END RSA PRIVATE KEY-----")-1])

print(bytes.fromhex(rsaKeyStr))