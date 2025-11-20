#!/usr/bin/env python3
"""
Sistema de Autenticación (CLI)
Implementa: registro, login, ver info de usuario, logout, editar perfil,
recuperación de contraseña (simulada), logs en MongoDB, diferenciación admin.
"""
import mysql.connector
from mysql.connector import errorcode
from pymongo import MongoClient
import bcrypt
import getpass
import os
from dotenv import load_dotenv
from datetime import datetime
import sys
import traceback

load_dotenv()

# Config
MYSQL_HOST = os.getenv('MYSQL_HOST', 'localhost')
MYSQL_PORT = int(os.getenv('MYSQL_PORT', 3306))
MYSQL_USER = os.getenv('MYSQL_USER', 'root')
MYSQL_PASSWORD = os.getenv('MYSQL_PASSWORD', '')
MYSQL_DB = os.getenv('MYSQL_DB', 'examen_auth')
MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/examen_auth')
APP_IP = os.getenv('APP_IP', '127.0.0.1')

class SistemaAutenticacion:
    def __init__(self):
        # Conectar MySQL
        try:
            self.mysql_conn = mysql.connector.connect(
                host=MYSQL_HOST,
                port=MYSQL_PORT,
                user=MYSQL_USER,
                password=MYSQL_PASSWORD,
                database=MYSQL_DB,
                autocommit=False
            )
            self.mysql_cursor = self.mysql_conn.cursor(dictionary=True)
        except mysql.connector.Error as e:
            print("Error al conectar MySQL:", e)
            sys.exit(1)

        # Conectar MongoDB (versión funcional)
        try:
            self.mongo_client = MongoClient(MONGO_URI)
            self.mdb = self.mongo_client.get_database()  # usa DB de la URI
            self.mongo_usuarios = self.mdb['usuarios']
            self.logs = self.mdb['logs']
        except Exception as e:
            print("Error al conectar MongoDB:", e)
            sys.exit(1)

        self.current_user = None  # en memoria

    # ----- Hashing -----
    def hash_password(self, password: str) -> str:
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        return hashed.decode('utf-8')

    def verificar_password(self, password: str, password_hash: str) -> bool:
        try:
            return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
        except Exception:
            return False

    # ----- Logs -----
    def registrar_log(self, user_id, username, accion, ip=APP_IP, meta=None):
        doc = {
            'user_id': int(user_id) if user_id is not None else None,
            'username': username,
            'accion': accion,
            'fecha': datetime.utcnow(),
            'ip': ip,
            'meta': meta or {}
        }
        try:
            self.logs.insert_one(doc)
        except Exception as e:
            print("Aviso: no se pudo escribir log en MongoDB:", e)

    # ----- Registro -----
    def registrar_usuario(self):
        try:
            print("=== Registro de usuario ===")
            username = input("Username: ").strip()
            email = input("Email: ").strip()
            if not username or not email:
                print("username y email requeridos.")
                return

            while True:
                password = getpass.getpass("Password: ")
                password2 = getpass.getpass("Confirmar password: ")
                if password != password2:
                    print("Las contraseñas no coinciden.")
                elif len(password) < 6:
                    print("La contraseña debe tener al menos 6 caracteres.")
                else:
                    break

            pw_hash = self.hash_password(password)

            # Insert en MySQL
            try:
                sql = ("INSERT INTO usuarios (username, email, password_hash, activo, is_admin) "
                       "VALUES (%s, %s, %s, %s, %s)")
                vals = (username, email, pw_hash, True, 0)
                self.mysql_cursor.execute(sql, vals)
                self.mysql_conn.commit()
                user_id = self.mysql_cursor.lastrowid
            except mysql.connector.IntegrityError:
                self.mysql_conn.rollback()
                print("Error: username o email ya existe.")
                return
            except Exception as e:
                self.mysql_conn.rollback()
                print("Error al insertar en MySQL:", e)
                return

            # Insert en Mongo
            perfil = {
                'user_id': int(user_id),
                'username': username,
                'email': email,
                'bio': '',
                'settings': {},
                'fecha_registro': datetime.utcnow(),
                'activo': True
            }
            try:
                self.mongo_usuarios.insert_one(perfil)
            except Exception as e:
                self.mysql_cursor.execute("DELETE FROM usuarios WHERE id = %s", (user_id,))
                self.mysql_conn.commit()
                print("Error al crear perfil en MongoDB:", e)
                return

            self.registrar_log(user_id, username, 'registro')
            print("Usuario registrado correctamente. ID:", user_id)
        except Exception as e:
            print("Error en registro:", e)
            traceback.print_exc()

    # ----- Login -----
    def login(self):
        try:
            print("=== Login ===")
            username = input("Username: ").strip()
            password = getpass.getpass("Password: ")

            if not username or not password:
                print("username y password requeridos.")
                return

            self.mysql_cursor.execute("SELECT * FROM usuarios WHERE username = %s", (username,))
            row = self.mysql_cursor.fetchone()
            if not row:
                print("Credenciales inválidas.")
                return

            if not row.get('activo', True):
                print("Cuenta desactivada.")
                return

            if not self.verificar_password(password, row['password_hash']):
                self.registrar_log(row['id'], username, 'login_fallido')
                print("Credenciales inválidas.")
                return

            self.current_user = {
                'id': int(row['id']),
                'username': row['username'],
                'email': row['email'],
                'is_admin': bool(row.get('is_admin', 0))
            }

            self.registrar_log(row['id'], username, 'login_exitoso')
            print(f"Login correcto. Bienvenido, {username}!")
            self.mostrar_menu_principal()
        except Exception as e:
            print("Error en login:", e)
            traceback.print_exc()

    # ----- Logout -----
    def logout(self):
        if not self.current_user:
            print("No hay usuario logueado.")
            return
        uid = self.current_user['id']
        username = self.current_user['username']
        self.current_user = None
        self.registrar_log(uid, username, 'logout')
        print("Sesión cerrada.")

    # ----- Recuperación de contraseña -----
    def recuperar_contrasena(self):
        try:
            print("=== Recuperación (simulada) ===")
            email = input("Ingrese su email registrado: ").strip()
            if not email:
                print("Email requerido.")
                return

            self.mysql_cursor.execute("SELECT id, username FROM usuarios WHERE email = %s", (email,))
            row = self.mysql_cursor.fetchone()
            if not row:
                print("Email no encontrado.")
                return

            token = bcrypt.gensalt().decode('utf-8')[:8]
            print(f"(Simulado) Token enviado: {token}")

            self.registrar_log(row['id'], row['username'], 'recuperacion_solicitada', {'token': token})

            usar = input("¿Desea restablecer la contraseña ahora? (s/n): ").strip().lower()
            if usar != 's':
                return

            nuevo = getpass.getpass("Nueva password: ")
            nuevo2 = getpass.getpass("Confirmar: ")
            if nuevo != nuevo2:
                print("No coinciden.")
                return

            pw_hash = self.hash_password(nuevo)
            self.mysql_cursor.execute("UPDATE usuarios SET password_hash = %s WHERE id=%s", (pw_hash, row['id']))
            self.mysql_conn.commit()

            self.mongo_usuarios.update_one({'user_id': int(row['id'])},
                                           {'$set': {'fecha_mod_pass': datetime.utcnow()}})

            self.registrar_log(row['id'], row['username'], 'recuperacion_exitosa')
            print("Contraseña actualizada.")
        except Exception as e:
            print("Error:", e)

    # ----- Editar perfil -----
    def editar_perfil(self):
        if not self.current_user:
            print("Debes iniciar sesión.")
            return

        uid = self.current_user['id']
        print("=== Editar perfil ===")

        perfil = self.mongo_usuarios.find_one({'user_id': uid}, {'_id': 0})
        print("Perfil actual:", perfil)

        cambios = {}

        bio = input("Nueva bio (vacío = igual): ").strip()
        if bio:
            cambios['bio'] = bio

        nuevo_email = input("Nuevo email (vacío = igual): ").strip()
        if nuevo_email:
            self.mysql_cursor.execute("SELECT id FROM usuarios WHERE email=%s AND id!=%s",
                                      (nuevo_email, uid))
            if self.mysql_cursor.fetchone():
                print("Email ya en uso.")
                return

            self.mysql_cursor.execute("UPDATE usuarios SET email=%s WHERE id=%s",
                                      (nuevo_email, uid))
            self.mysql_conn.commit()
            cambios['email'] = nuevo_email

        if cambios:
            self.mongo_usuarios.update_one({'user_id': uid}, {'$set': cambios})
            self.registrar_log(uid, self.current_user['username'], 'perfil_actualizado', cambios)
            print("Perfil actualizado.")
        else:
            print("No hubo cambios.")

    # ----- Ver logs -----
    def ver_logs_admin(self):
        if not self.current_user or not self.current_user['is_admin']:
            print("Acceso denegado.")
            return

        print("=== Logs recientes ===")
        cursor = self.logs.find({}).sort('fecha', -1).limit(50)
        for doc in cursor:
            print(doc)

    # ----- Usuarios prueba -----
    def insertar_usuarios_prueba(self):
        users = [
            ('alice', 'alice@example.com', 'passwordA', 0),
            ('bob', 'bob@example.com', 'passwordB', 0),
            ('admin', 'admin@example.com', 'adminpass', 1)
        ]

        for u, e, p, a in users:
            try:
                pw = self.hash_password(p)
                self.mysql_cursor.execute(
                    "INSERT INTO usuarios (username,email,password_hash,activo,is_admin) VALUES (%s,%s,%s,%s,%s)",
                    (u, e, pw, True, a)
                )
                self.mysql_conn.commit()
                uid = self.mysql_cursor.lastrowid

                perfil = {
                    'user_id': uid,
                    'username': u,
                    'email': e,
                    'bio': '',
                    'settings': {},
                    'fecha_registro': datetime.utcnow(),
                    'activo': True
                }
                self.mongo_usuarios.insert_one(perfil)
                print(f"Usuario prueba creado: {u}")

            except mysql.connector.IntegrityError:
                print(f"Usuario {u} ya existe.")
            except Exception as ex:
                print("Error:", ex)

    # ----- Menú principal -----
    def mostrar_menu_principal(self):
        while self.current_user:
            print("\n=== Menú Principal ===")
            print("1) Ver mi información")
            print("2) Editar perfil")
            print("3) Recuperar contraseña")
            print("4) Cerrar sesión")
            if self.current_user['is_admin']:
                print("5) Ver logs (admin)")

            op = input("Opción: ").strip()

            if op == '1':
                print("Usuario:", self.current_user)
                perfil = self.mongo_usuarios.find_one({'user_id': self.current_user['id']}, {'_id': 0})
                print("Perfil:", perfil)
            elif op == '2':
                self.editar_perfil()
            elif op == '3':
                self.recuperar_contrasena()
            elif op == '4':
                self.logout()
                break
            elif op == '5' and self.current_user['is_admin']:
                self.ver_logs_admin()
            else:
                print("Opción inválida.")

    # ----- Menú inicial -----
    def main(self):
        try:
            while True:
                print("\n=== Sistema de Autenticación (CLI) ===")
                print("1) Registrar usuario")
                print("2) Login")
                print("3) Recuperar contraseña")
                print("4) Insertar 3 usuarios de prueba")
                print("5) Salir")

                op = input("Opción: ").strip()

                if op == '1':
                    self.registrar_usuario()
                elif op == '2':
                    self.login()
                elif op == '3':
                    self.recuperar_contrasena()
                elif op == '4':
                    self.insertar_usuarios_prueba()
                elif op == '5':
                    print("Saliendo. Hasta luego.")
                    break
                else:
                    print("Opción inválida.")

        except KeyboardInterrupt:
            print("\nInterrumpido por usuario.")
        finally:
            try:
                self.mysql_cursor.close()
                self.mysql_conn.close()
                self.mongo_client.close()
            except:
                pass


if __name__ == "__main__":
    app = SistemaAutenticacion()
    app.main()
