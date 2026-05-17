import sys
import os
from PyQt6 import QtWidgets, uic
from PyQt6.QtWidgets import QMessageBox

from database import PasswordDB
import crypto

class PasswordManagerApp:
    def __init__(self):
        self.db = PasswordDB("storage.json")
        self.clave_transmision = None 
        self.config_actual = self.db.obtener_config() # (usuario, hash, salt) o None
        self.id_registro_actual = None # Almacena el ID del elemento que estamos editando

        # Cargar rutas absolutas
        ruta_carpeta = os.path.dirname(os.path.abspath(__file__))
        self.ventana_login = uic.loadUi(os.path.join(ruta_carpeta, "login.ui"))
        self.ventana_dashboard = uic.loadUi(os.path.join(ruta_carpeta, "dashboard.ui"))

        self.ventana_login.input_maestra.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
        self.preparar_ventana_inicio()

    def preparar_ventana_inicio(self):
        if self.config_actual is None:
            self.ventana_login.setWindowTitle("Crear Administrador")
            self.ventana_login.btn_entrar.setText("Registrar Administrador")
            self.ventana_login.btn_entrar.clicked.connect(self.procesar_registro)
        else:
            self.ventana_login.setWindowTitle("Iniciar Sesión")
            self.ventana_login.btn_entrar.setText("Ingresar")
            self.ventana_login.btn_entrar.clicked.connect(self.procesar_login)
        self.ventana_login.show()

    def procesar_registro(self):
        usuario = self.ventana_login.input_usuario.text().strip()
        password = self.ventana_login.input_maestra.text()

        if not usuario or len(password) < 4:
            QMessageBox.warning(self.ventana_login, "Error", "Completa el usuario y asegura una clave de 4+ caracteres.")
            return

        salt = os.urandom(16)
        master_hash = crypto.hashear_maestra(password)
        self.db.guardar_config_inicial(usuario, master_hash, salt)
        self.clave_transmision = crypto.generar_clave_desde_maestra(password, salt)
        
        QMessageBox.information(self.ventana_login, "Éxito", f"¡Bienvenido {usuario}! Base de datos inicializada.")
        self.abrir_dashboard()

    def procesar_login(self):
        usuario_ingresado = self.ventana_login.input_usuario.text().strip()
        password_ingresada = self.ventana_login.input_maestra.text()
        
        usuario_guardado, hash_guardado, salt_guardado = self.config_actual
        hash_ingresado = crypto.hashear_maestra(password_ingresada)

        if usuario_ingresado == usuario_guardado and hash_ingresado == hash_guardado:
            self.clave_transmision = crypto.generar_clave_desde_maestra(password_ingresada, salt_guardado)
            self.abrir_dashboard()
        else:
            QMessageBox.critical(self.ventana_login, "Error", "Usuario o Contraseña Maestra incorrectos.")

    def abrir_dashboard(self):
        self.ventana_login.close()
        self.ventana_dashboard.show()
        
        # Conexiones de los componentes del Dashboard
        self.ventana_dashboard.btn_nueva_cuenta.clicked.connect(self.preparar_nuevo_registro)
        self.ventana_dashboard.btn_guardar_cambios.clicked.connect(self.guardar_o_actualizar)
        self.ventana_dashboard.lista_cuentas.itemClicked.connect(self.mostrar_detalle_cuenta)
        
        self.actualizar_lista_visual()

    def actualizar_lista_visual(self):
        self.ventana_dashboard.lista_cuentas.clear()
        self.todas_las_cuentas = self.db.obtener_todas_las_credenciales()
        for fila in self.todas_las_cuentas:
            self.ventana_dashboard.lista_cuentas.addItem(fila[1]) # Agrega el nombre del sitio

    def preparar_nuevo_registro(self):
        """Limpia el formulario derecho para poder escribir una plataforma nueva de cero."""
        self.id_registro_actual = None # Indicamos que es un registro NUEVO
        self.ventana_dashboard.input_sitio.clear()
        self.ventana_dashboard.input_usuario_plataforma.clear()
        self.ventana_dashboard.input_password_plataforma.clear()
        self.ventana_dashboard.input_sitio.setFocus()

    def mostrar_detalle_cuenta(self, item):
        """Muestra y desencripta los datos de la plataforma seleccionada en los inputs."""
        nombre_sitio = item.text()
        for fila in self.todas_las_cuentas:
            id_db, sitio, usuario, pwd_encriptada = fila
            if sitio == nombre_sitio:
                self.id_registro_actual = id_db # Recordamos qué ID estamos editando
                self.ventana_dashboard.input_sitio.setText(sitio)
                self.ventana_dashboard.input_usuario_plataforma.setText(usuario)
                
                # Desencriptamos la contraseña específica de esta plataforma
                password_real = crypto.desencriptar_dato(pwd_encriptada, self.clave_transmision)
                self.ventana_dashboard.input_password_plataforma.setText(password_real)
                break

    def guardar_o_actualizar(self):
        """Decide si guarda una plataforma nueva o actualiza una existente basándose en el ID."""
        sitio = self.ventana_dashboard.input_sitio.text().strip()
        usuario = self.ventana_dashboard.input_usuario_plataforma.text().strip()
        password = self.ventana_dashboard.input_password_plataforma.text()

        if not sitio or not usuario or not password:
            QMessageBox.warning(self.ventana_dashboard, "Campos Vacíos", "Por favor completa todos los campos del registro.")
            return

        # Encriptamos la contraseña con nuestra clave de sesión
        password_cifrada = crypto.encriptar_dato(password, self.clave_transmision)

        if self.id_registro_actual is None:
            # Caso NUEVO: Guardamos en el archivo
            self.db.guardar_credencial(sitio, usuario, password_cifrada)
            QMessageBox.information(self.ventana_dashboard, "Éxito", f"Plataforma '{sitio}' agregada.")
        else:
            # Caso EXISTENTE (Edición): Actualizamos el registro usando su ID
            self.db.actualizar_credencial(self.id_registro_actual, sitio, usuario, password_cifrada)
            QMessageBox.information(self.ventana_dashboard, "Éxito", f"Datos de '{sitio}' actualizados correctamente.")

        self.actualizar_lista_visual()


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    ejecutable = PasswordManagerApp()
    sys.exit(app.exec())