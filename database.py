import json
import os

class PasswordDB:
    def __init__(self, db_name="storage.json"):
        self.db_name = db_name
        self.crear_tablas()

    def crear_tablas(self):
        if not os.path.exists(self.db_name):
            estructura_inicial = {
                "config": [],       # [{"usuario_admin": ..., "master_hash": ..., "salt_hex": ...}]
                "credentials": []   # [{"id": 1, "sitio": ..., "usuario": ..., "password_encriptada": ...}]
            }
            self._guardar_archivo(estructura_inicial)

    def _leer_archivo(self) -> dict:
        try:
            with open(self.db_name, "r", encoding="utf-8") as archivo:
                return json.load(archivo)
        except Exception:
            return {"config": [], "credentials": []}

    def _guardar_archivo(self, datos: dict):
        with open(self.db_name, "w", encoding="utf-8") as archivo:
            json.dump(datos, archivo, ensure_ascii=False, indent=4)

    def guardar_config_inicial(self, usuario_admin: str, master_hash: str, salt: bytes):
        datos = self._leer_archivo()
        datos["config"].append({
            "usuario_admin": usuario_admin,
            "master_hash": master_hash,
            "salt_hex": salt.hex()
        })
        self._guardar_archivo(datos)

    def obtener_config(self):
        datos = self._leer_archivo()
        if not datos["config"]:
            return None
        c = datos["config"][0]
        return (c["usuario_admin"], c["master_hash"], bytes.fromhex(c["salt_hex"]))

    def guardar_credencial(self, sitio: str, usuario: str, password_encriptada: str):
        datos = self._leer_archivo()
        nuevo_id = len(datos["credentials"]) + 1
        datos["credentials"].append({
            "id": nuevo_id,
            "sitio": sitio,
            "usuario": usuario,
            "password_encriptada": password_encriptada
        })
        self._guardar_archivo(datos)

    def actualizar_credencial(self, id_credencial: int, sitio: str, usuario: str, password_encriptada: str):
        """Busca una credencial por ID y actualiza sus campos."""
        datos = self._leer_archivo()
        for c in datos["credentials"]:
            if c["id"] == id_credencial:
                c["sitio"] = sitio
                c["usuario"] = usuario
                c["password_encriptada"] = password_encriptada
                break
        self._guardar_archivo(datos)

    def obtener_todas_las_credenciales(self):
        datos = self._leer_archivo()
        return [(c["id"], c["sitio"], c["usuario"], c["password_encriptada"]) for c in datos["credentials"]]