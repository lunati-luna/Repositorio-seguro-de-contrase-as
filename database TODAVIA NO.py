



#NO USANDO PORQUE NO TENGO SQLITE POR AHORA










import sqlite3
import os

class PasswordDB:
    def __init__(self, db_name="storage.db"):
        """
        Al instanciar la clase, se conecta al archivo de la base de datos.
        Si el archivo no existe, SQLite lo crea automáticamente.
        """
        self.db_name = db_name
        self.crear_tablas()

    def _conectar(self):
        """Método interno para abrir una conexión limpia con la base de datos."""
        return sqlite3.connect(self.db_name)

    def crear_tablas(self):
        """Crea las tablas necesarias si es la primera vez que se ejecuta la app."""
        conexion = self._conectar()
        cursor = conexion.cursor()
        
        # 1. Tabla de configuración (guarda el hash maestro y el salt en bytes)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS config (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                master_hash TEXT NOT NULL,
                salt BLOB NOT NULL
            )
        """)
        
        # 2. Tabla de credenciales (guarda las contraseñas encriptadas)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sitio TEXT NOT NULL,
                usuario TEXT NOT NULL,
                password_encriptada TEXT NOT NULL
            )
        """)
        
        conexion.commit()
        conexion.close()

    
    # MÉTODOS PARA LA CONFIGURACIÓN INICIAL (SISTEMA DE LOGIN)
    

    def guardar_config_inicial(self, master_hash: str, salt: bytes):
        """Guarda el hash de la contraseña maestra y su salt (Solo se usa una vez)."""
        conexion = self._conectar()
        cursor = conexion.cursor()
        
        cursor.execute(
            "INSERT INTO config (master_hash, salt) VALUES (?, ?)",
            (master_hash, salt)
        )
        
        conexion.commit()
        conexion.close()

    def obtener_config(self):
        """
        Recupera el hash maestro y el salt. 
        Devuelve una tupla (master_hash, salt) o None si la base de datos está vacía.
        """
        conexion = self._conectar()
        cursor = conexion.cursor()
        
        cursor.execute("SELECT master_hash, salt FROM config LIMIT 1")
        resultado = cursor.fetchone() # Trae la primera fila encontrada
        
        conexion.close()
        return resultado # Puede ser (hash, salt) o None

    
    # MÉTODOS PARA GESTIONAR LAS CREDENCIALES (EL DASHBOARD)
    

    def guardar_credencial(self, sitio: str, usuario: str, password_encriptada: str):
        """Inserta una nueva cuenta encriptada en la base de datos."""
        conexion = self._conectar()
        cursor = conexion.cursor()
        
        # Usamos '?' como placeholders para evitar ataques de Inyección SQL (Buena práctica)
        cursor.execute(
            "INSERT INTO credentials (sitio, usuario, password_encriptada) VALUES (?, ?, ?)",
            (sitio, usuario, password_encriptada)
        )
        
        conexion.commit()
        conexion.close()

    def obtener_todas_las_credenciales(self):
        """Trae de la base de datos todas las cuentas guardadas."""
        conexion = self._conectar()
        cursor = conexion.cursor()
        
        cursor.execute("SELECT id, sitio, usuario, password_encriptada FROM credentials")
        resultados = cursor.fetchall() # Trae una lista de tuplas
        
        conexion.close()
        return resultados


