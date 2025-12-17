# Ejemplo: cifrado AES-GCM con la librería cryptography
# Importamos la clase AESGCM (AES en modo Galois/Counter)
# que permite cifrar y autenticar datos en una sola operación
from cryptography.hazmat.primitives.ciphers.aead import AESGCM 

# se le añade el siguiente código, al principio del código en donde se importa “InvalidTag”
from cryptography.exceptions import InvalidTag

# Librerías estándar:
# - os: para generar números aleatorios seguros (nonce)
# - base64: para mostrar el resultado cifrado en un formato legible
import os, base64 

# Generamos una clave secreta AES de 128 bits (16 bytes). Esta clave 
# solo se le ofrece al usuario receptor de manera confidencial, esto aligual con “nonce”
# Esta clave es la "llave" que servirá para cifrar y descifrar
key = AESGCM.generate_key(bit_length=128)

# Generamos un nonce (Number Used Once) de 12 bytes aleatorios
# GCM recomienda usar 12 bytes de longitud
# Sirve como "número único" para evitar repeticiones en el cifrado
nonce = os.urandom(12)

# Definimos el mensaje original (texto en claro) que queremos proteger
# La 'b' indica que es un string en formato de bytes
texto = b'Numero de tarjeta 4111-1111-1111-1111' 

# Creamos un objeto AESGCM usando la clave secreta
# Este objeto sabe cómo cifrar y descifrar con AES-GCM
aesgcm = AESGCM(key) 

# Ciframos el mensaje usando la clave y el nonce
# encrypt(nonce, texto, None) → devuelve el mensaje cifrado + tag de autenticación
# El "None" indica que no usamos datos adicionales (AAD) en este ejemplo
cifrado = aesgcm.encrypt(nonce, texto, None)

# Imprimimos el texto cifrado convertido a Base64 para hacerlo legible
print("Cifrado:", base64.b64encode(cifrado).decode()) 

# Desciframos el mensaje usando la misma clave y el mismo nonce
# Recuperamos el texto original (si el cifrado se hubiera manipulado, daría error)
claro = aesgcm.decrypt(nonce, cifrado, None) 

# Mostramos el texto en claro recuperado
#print("Claro:", claro.decode())

# Luego se escribe los parámetros o el código para descifrar el texto
try:
    claro_bytes = aesgcm.decrypt(nonce, cifrado, None) # devuelve bytes
    claro_texto = claro_bytes.decode() # convertir bytes -> str (utf-8)
    print("Mensaje descifrado (directo):", claro_texto)
except InvalidTag:
    print("Error: autenticación fallida al descifrar (tag inválido).")
