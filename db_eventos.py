import sqlite3
import bcrypt
def crear_tablas():
    try:
        conn = sqlite3.connect('eventos.db')
        print("Conexión a la base de datos SQLite3 establecida.")
        cursor = conn.cursor()

        # Tabla Clientes con restricciones
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS Clientes (
            idCliente INTEGER PRIMARY KEY AUTOINCREMENT,
            Nombre VARCHAR(250) NOT NULL,
            Telefono VARCHAR(15) CHECK(length(Telefono) >= 10 AND Telefono GLOB '[0-9]*'),
            Email VARCHAR(250) CHECK(Email LIKE '%_@__%.__%'),
            CI_RUC VARCHAR(15) NOT NULL UNIQUE
        )
        ''')
        print("Tabla Clientes creada correctamente.")
        
        # Tabla Salones
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS Salones (
            idSalon INTEGER PRIMARY KEY AUTOINCREMENT,
            Nombre VARCHAR(250) NOT NULL,
            Capacidad INTEGER CHECK(Capacidad > 0),
            Precio REAL CHECK(Precio >= 0)
        )
        ''')
        print("Tabla Salones creada correctamente.")
        
        # Tabla Reservas
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS Reservas (
            idReserva INTEGER PRIMARY KEY AUTOINCREMENT,
            FechaReserva TEXT NOT NULL,
            idCliente INTEGER NOT NULL,
            idSalon INTEGER NOT NULL,
            FOREIGN KEY (idCliente) REFERENCES Clientes(idCliente),
            FOREIGN KEY (idSalon) REFERENCES Salones(idSalon)
        )
        ''')
        print("Tabla Reservas creada correctamente.")
        
        # Tabla Eventos
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS Eventos (
            idEvento INTEGER PRIMARY KEY AUTOINCREMENT,
            Tipo VARCHAR(100) NOT NULL,
            Descripcion VARCHAR(300),
            FechaEvento TEXT NOT NULL,
            idReserva INTEGER NOT NULL,
            FOREIGN KEY (idReserva) REFERENCES Reservas(idReserva)
        )
        ''')
        print("Tabla Eventos creada correctamente.")
        
        # Tabla Servicios
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS Servicios (
            idServicio INTEGER PRIMARY KEY AUTOINCREMENT,
            Nombre VARCHAR(250) NOT NULL,
            Precio REAL NOT NULL CHECK(Precio >= 0)
        )
        ''')
        print("Tabla Servicios creada correctamente.")
        
        # Tabla intermedia Reserva_Servicio
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS Reserva_Servicio (
            idReserva INTEGER NOT NULL,
            idServicio INTEGER NOT NULL,
            PRIMARY KEY (idReserva, idServicio),
            FOREIGN KEY (idReserva) REFERENCES Reservas(idReserva),
            FOREIGN KEY (idServicio) REFERENCES Servicios(idServicio)
        )
        ''')
        print("Tabla Reserva_Servicio creada correctamente.")
        
        # Tabla Facturas
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS Facturas (
            idFactura INTEGER PRIMARY KEY AUTOINCREMENT,
            Timbrado INTEGER NOT NULL UNIQUE,
            FechaFactura TEXT NOT NULL,
            Total REAL NOT NULL CHECK(Total >= 0),
            idReserva INTEGER NOT NULL,
            FOREIGN KEY (idReserva) REFERENCES Reservas(idReserva)
        )
        ''')
        print("Tabla Facturas creada correctamente.")
        
        # Tabla Usuarios
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS Usuarios (
            idUsuario INTEGER PRIMARY KEY AUTOINCREMENT,
            Nombre VARCHAR(250) NOT NULL,
            Clave VARCHAR(100) NOT NULL,
            Rol VARCHAR(100) NOT NULL CHECK(Rol IN ('Administrador', 'Empleado', 'Invitado'))
        )
        ''')
        print("Tabla Usuarios creada correctamente.")
        
        conn.commit()
        print("Tablas creadas exitosamente.")
    except sqlite3.Error as e:
        print(f"Error al conectar o crear las tablas: {e}")
    finally:
        conn.close()
        print("Conexión cerrada.")

crear_tablas()

# Insertar un usuario de prueba con contraseña cifrada
conn = sqlite3.connect('eventos.db')
cursor = conn.cursor()

# Cifrar la contraseña con bcrypt
clave_plana = 'admin'
hashed_clave = bcrypt.hashpw(clave_plana.encode('utf-8'), bcrypt.gensalt())

# Insertar el usuario con la contraseña cifrada
cursor.execute('''
INSERT INTO Usuarios (Nombre, Clave, Rol) 
VALUES ('admin', ?, 'Administrador')
''', (hashed_clave,))

conn.commit()
conn.close()

print("Usuario de prueba agregado correctamente con contraseña cifrada.")



# Insertar un usuario de prueba con contraseña cifrada
conn = sqlite3.connect('eventos.db')
cursor = conn.cursor()

# Cifrar la contraseña con bcrypt
clave_plana = 'user'
hashed_clave = bcrypt.hashpw(clave_plana.encode('utf-8'), bcrypt.gensalt())

# Insertar el usuario con la contraseña cifrada
cursor.execute('''
INSERT INTO Usuarios (Nombre, Clave, Rol) 
VALUES ('user', ?, 'Empleado')
''', (hashed_clave,))

conn.commit()
conn.close()

print("Usuario de prueba agregado correctamente con contraseña cifrada.")


