import hashlib
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def hashear_maestra(password_maestra: str) -> str:
    """
    Toma la contraseña maestra en texto plano, la pasa por SHA-256
    y devuelve el hash en formato de texto (hexadecimal).
    
    ¿Para qué sirve? Para guardarlo en la base de datos la primera vez 
    y luego verificar si el usuario ingresó la contraseña correcta al loguearse,
    ¡sin necesidad de guardar la contraseña real en ningún lado!
    """
    # .encode() transforma el string a bytes (ej: "hola" -> b"hola") porque hashlib solo procesa bytes.
    # .hexdigest() convierte el resultado matemático en un texto legible de 64 caracteres.
    hash_resultante = hashlib.sha256(password_maestra.encode()).hexdigest()
    return hash_resultante


def generar_clave_desde_maestra(password_maestra: str, salt: bytes) -> bytes:
    """
    Toma la contraseña maestra y un 'salt' (sal) en bytes, y genera una clave 
    robusta de 32 bytes codificada en Base64, lista para ser usada por Fernet (AES).
    
    ¿Para qué sirve? Es el motor de seguridad. Transforma una contraseña común
    en una clave criptográfica de nivel bancario.
    """
    # Configuramos el derivador de claves (PBKDF2)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), # Usamos SHA-256 como base matemática
        length=32,                  # Queremos una clave final de 32 bytes (AES-256)
        salt=salt,                  # Datos aleatorios para que la clave sea única en el mundo
        iterations=100000,          # 100.000 vueltas de tuerca para ralentizar ataques de fuerza bruta
    )
    
    # .derive() ejecuta el algoritmo matemático. Requiere la contraseña en bytes.
    clave_primaria = kdf.derive(password_maestra.encode())
    
    # Fernet exige estrictamente que la clave esté en formato Base64 seguro para URLs.
    clave_final_base64 = base64.urlsafe_b64encode(clave_primaria)
    
    return clave_final_base64


def encriptar_dato(texto_plano: str, clave: bytes) -> str:
    """
    Toma una contraseña común (ej: 'mi_clave_de_netflix') y la clave derivada.
    Devuelve un string completamente cifrado e ilegible.
    """
    # Inicializamos el motor de cifrado Fernet con nuestra clave
    f = Fernet(clave)
    
    # Ciframos el texto. Como f.encrypt solo acepta bytes, usamos .encode()
    datos_cifrados_bytes = f.encrypt(texto_plano.encode())
    
    # El resultado son bytes raros. Usamos .decode() para transformarlo
    # en un string común (texto) y poder guardarlo fácil en la base de datos.
    texto_encriptado_str = datos_cifrados_bytes.decode()
    
    return texto_encriptado_str


def desencriptar_dato(texto_encriptado: str, clave: bytes) -> str:
    """
    Toma el texto raro/encriptado de la base de datos y la clave derivada.
    Si la clave es la correcta, revierte el proceso y devuelve la contraseña original.
    """
    # Inicializamos Fernet con la misma clave que se usó para encriptar
    f = Fernet(clave)
    
    # f.decrypt requiere bytes, así que pasamos el string encriptado a bytes
    datos_descifrados_bytes = f.decrypt(texto_encriptado.encode())
    
    # El resultado descifrado está en bytes. Lo pasamos a texto limpio con .decode()
    texto_original_str = datos_descifrados_bytes.decode()
    
    return texto_original_str
