from flask import Flask, render_template, request, redirect, url_for, session, jsonify, make_response
import sqlite3
import bcrypt
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Image
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
import io
import random
from datetime import datetime
app = Flask(__name__)
app.secret_key = 'THG_tpingsft'

# ============================
# RUTAS DE AUTENTICACIÓN
# ============================
@app.route('/')
def login():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def handle_login():
    usuario = request.form['usuario']
    clave = request.form['clave']
    rol = request.form['rol']  # Obtenemos el rol seleccionado por el usuario

    conn = sqlite3.connect('eventos.db')
    cursor = conn.cursor()
    cursor.execute("SELECT idUsuario, Nombre, Clave, Rol FROM Usuarios WHERE Nombre = ?", (usuario,))
    user = cursor.fetchone()
    conn.close()

    # Verificamos la contraseña cifrada y que el rol coincida
    if user and bcrypt.checkpw(clave.encode('utf-8'), user[2]) and user[3] == rol:
        session['user_id'] = user[0]
        session['username'] = user[1]
        session['role'] = user[3]
        
        if user[3] == 'Administrador':
            return redirect(url_for('admin_dashboard'))
        elif user[3] == 'Empleado':
            return redirect(url_for('empleado_dashboard'))
    else:
        return "<script>alert('Usuario, contraseña o rol incorrectos.'); window.location.href='/';</script>"

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Nueva ruta para manejar el botón "Inicio"
@app.route('/inicio')
def inicio():
    if 'user_id' in session:
        if session['role'] == 'Administrador':
            return redirect(url_for('admin_dashboard'))
        elif session['role'] == 'Empleado':
            return redirect(url_for('empleado_dashboard'))
    return redirect(url_for('login'))  # Si no hay sesión, redirige al login

# ============================
# RUTAS PARA ADMINISTRADORES
# ============================
@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' in session and session['role'] == 'Administrador':
        conn = sqlite3.connect('eventos.db')
        cursor = conn.cursor()
        cursor.execute('SELECT idUsuario, Nombre, Rol FROM Usuarios')
        usuarios = cursor.fetchall()
        conn.close()
        return render_template('admin_dashboard.html', usuarios=usuarios)
    return redirect(url_for('login'))

@app.route('/usuarios')
def usuarios():
    if 'user_id' in session and session['role'] == 'Administrador':
        conn = sqlite3.connect('eventos.db')
        cursor = conn.cursor()
        cursor.execute('SELECT idUsuario, Nombre, Rol FROM Usuarios')
        usuarios = cursor.fetchall()
        conn.close()
        return render_template('usuarios.html', usuarios=usuarios)
    return redirect(url_for('login'))

@app.route('/guardar_usuario', methods=['POST'])
def guardar_usuario():
    if 'user_id' in session and session['role'] == 'Administrador':
        nombre = request.form['nombre']
        clave = request.form['clave']
        rol = request.form['rol']

        # Cifrar la contraseña con bcrypt
        hashed_clave = bcrypt.hashpw(clave.encode('utf-8'), bcrypt.gensalt())

        conn = sqlite3.connect('eventos.db')
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO Usuarios (Nombre, Clave, Rol) VALUES (?, ?, ?)", (nombre, hashed_clave, rol))
            conn.commit()
            mensaje = "Usuario agregado correctamente."
        except sqlite3.Error as e:
            conn.rollback()
            mensaje = f"Error al agregar usuario: {e}"
        finally:
            conn.close()

        # Redirigir a la página de usuarios en lugar del panel principal
        return f"<script>alert('{mensaje}'); window.location.href='/usuarios';</script>"
    return redirect(url_for('login'))

@app.route('/gestionar_usuario', methods=['POST'])
def gestionar_usuario():
    if 'user_id' in session and session['role'] == 'Administrador':
        id_usuario = request.form.get('id_usuario')
        accion = request.form.get('accion')

        conn = sqlite3.connect('eventos.db')
        cursor = conn.cursor()
        try:
            if accion == 'eliminar':
                # Evitar que un administrador elimine su propio usuario
                if int(id_usuario) == session['user_id']:
                    return "<script>alert('No puedes eliminar tu propio usuario.'); window.location.href='/usuarios';</script>"
                cursor.execute("DELETE FROM Usuarios WHERE idUsuario = ?", (id_usuario,))
                conn.commit()
                mensaje = "Usuario eliminado correctamente."
            elif accion == 'editar':
                nuevo_nombre = request.form['nuevo_nombre']
                nuevo_rol = request.form['nuevo_rol']

                # Validar que el nuevo rol sea válido
                if nuevo_rol not in ['Administrador', 'Empleado']:
                    return "<script>alert('Rol no válido.'); window.location.href='/usuarios';</script>"

                cursor.execute("UPDATE Usuarios SET Nombre = ?, Rol = ? WHERE idUsuario = ?", (nuevo_nombre, nuevo_rol, id_usuario))
                conn.commit()
                mensaje = "Usuario actualizado correctamente."
            else:
                mensaje = "Acción no válida."
        except sqlite3.Error as e:
            mensaje = f"Error al gestionar usuario: {e}"
        finally:
            conn.close()

        return f"<script>alert('{mensaje}'); window.location.href='/usuarios';</script>"
    return redirect(url_for('login'))

@app.route('/cambiar_contrasena', methods=['POST'])
def cambiar_contrasena():
    if 'user_id' in session and session['role'] == 'Administrador':
        id_usuario = request.form['id_usuario']
        nueva_contrasena = request.form['nueva_contrasena']
        confirmar_contrasena = request.form['confirmar_contrasena']

        # Validar que las contraseñas coincidan
        if nueva_contrasena != confirmar_contrasena:
            return "<script>alert('Las contraseñas no coinciden.'); window.location.href='/usuarios';</script>"

        # Cifrar la nueva contraseña
        hashed_contrasena = bcrypt.hashpw(nueva_contrasena.encode('utf-8'), bcrypt.gensalt())

        # Actualizar la contraseña en la base de datos
        conn = sqlite3.connect('eventos.db')
        cursor = conn.cursor()
        try:
            cursor.execute("UPDATE Usuarios SET Clave = ? WHERE idUsuario = ?", (hashed_contrasena, id_usuario))
            conn.commit()
            mensaje = "Contraseña actualizada correctamente."
        except sqlite3.Error as e:
            conn.rollback()
            mensaje = f"Error al actualizar la contraseña: {e}"
        finally:
            conn.close()

        return f"<script>alert('{mensaje}'); window.location.href='/usuarios';</script>"
    return redirect(url_for('login'))
# ============================
# RUTAS PARA EMPLEADOS
# ============================
@app.route('/empleado_dashboard')
def empleado_dashboard():
    if 'user_id' in session and session['role'] in ['Administrador', 'Empleado']:
        return render_template('empleado_dashboard.html', username=session['username'])
    return redirect(url_for('login'))

# ============================
# GESTIÓN DE CLIENTES
# ============================
@app.route('/clientes')
def clientes():
    if 'user_id' in session and session['role'] in ['Administrador', 'Empleado']:
        conn = sqlite3.connect('eventos.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM Clientes')
        clientes = cursor.fetchall()
        conn.close()

        # Obtener mensajes de éxito o error de la sesión
        success_message = session.pop('success_message', None)
        error_message = session.pop('error_message', None)

        return render_template(
            'clientes.html',
            clientes=clientes,
            role=session['role'],
            success_message=success_message,
            error_message=error_message
        )
    return redirect(url_for('login'))


@app.route('/guardar_cliente', methods=['POST'])
def guardar_cliente():
    if 'user_id' in session and session['role'] in ['Administrador', 'Empleado']:
        nombre = request.form['nombre'].strip()
        telefono = request.form['telefono'].strip()
        email = request.form['email'].strip()
        ci_ruc = request.form['ci_ruc'].strip()

        # Validaciones
        if not nombre:
            session['error_message'] = 'El nombre es obligatorio.'
            return redirect(url_for('clientes'))
        if not telefono.isdigit():
            session['error_message'] = 'El teléfono debe contener solo números.'
            return redirect(url_for('clientes'))
        if '@' not in email or '.' not in email:
            session['error_message'] = 'El correo electrónico no es válido.'
            return redirect(url_for('clientes'))
        if not ci_ruc:
            session['error_message'] = 'El CI/RUC es obligatorio.'
            return redirect(url_for('clientes'))

        conn = sqlite3.connect('eventos.db')
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO Clientes (Nombre, Telefono, Email, CI_RUC)
                VALUES (?, ?, ?, ?)
            ''', (nombre, telefono, email, ci_ruc))
            conn.commit()
            session['success_message'] = 'Cliente agregado correctamente.'
        except sqlite3.IntegrityError:
            session['error_message'] = 'El CI/RUC o el correo ya están registrados.'
        except sqlite3.Error as e:
            session['error_message'] = f'Error al agregar cliente: {e}'
        finally:
            conn.close()

        return redirect(url_for('clientes'))
    return redirect(url_for('login'))


@app.route('/editar_cliente', methods=['POST'])
def editar_cliente():
    if 'user_id' in session and session['role'] in ['Administrador', 'Empleado']:
        id_cliente = request.form['id_cliente'].strip()
        nombre = request.form['nombre'].strip()
        telefono = request.form['telefono'].strip()
        email = request.form['email'].strip()
        ci_ruc = request.form['ci_ruc'].strip()

        # Validaciones
        if not id_cliente:
            return "<script>alert('El ID del cliente es obligatorio.'); window.location.href='/clientes';</script>"
        if not nombre:
            return "<script>alert('El nombre es obligatorio.'); window.location.href='/clientes';</script>"
        if not telefono.isdigit():
            return "<script>alert('El teléfono debe contener solo números.'); window.location.href='/clientes';</script>"
        if '@' not in email or '.' not in email:
            return "<script>alert('El correo electrónico no es válido.'); window.location.href='/clientes';</script>"
        if not ci_ruc:
            return "<script>alert('El CI/RUC es obligatorio.'); window.location.href='/clientes';</script>"

        conn = sqlite3.connect('eventos.db')
        cursor = conn.cursor()
        try:
            cursor.execute('''
                UPDATE Clientes
                SET Nombre = ?, Telefono = ?, Email = ?, CI_RUC = ?
                WHERE idCliente = ?
            ''', (nombre, telefono, email, ci_ruc, id_cliente))
            conn.commit()
            return "<script>alert('Cliente actualizado correctamente.'); window.location.href='/clientes';</script>"
        except sqlite3.IntegrityError:
            return "<script>alert('El CI/RUC o el correo ya están registrados.'); window.location.href='/clientes';</script>"
        except sqlite3.Error as e:
            return f"<script>alert('Error al actualizar cliente: {e}'); window.location.href='/clientes';</script>"
        finally:
            conn.close()
    return "<script>alert('No autorizado.'); window.location.href='/login';</script>"

@app.route('/eliminar_cliente', methods=['POST'])
def eliminar_cliente():
    if 'user_id' in session and session['role'] in ['Administrador', 'Empleado']:
        id_cliente = request.form['id_cliente']

        conn = sqlite3.connect('eventos.db')
        cursor = conn.cursor()
        try:
            cursor.execute('DELETE FROM Clientes WHERE idCliente = ?', (id_cliente,))
            conn.commit()
            mensaje = "Cliente eliminado correctamente."
        except sqlite3.Error as e:
            mensaje = f"Error al eliminar cliente: {e}"
        finally:
            conn.close()

        return f"<script>alert('{mensaje}'); window.location.href='/clientes';</script>"
    return redirect(url_for('login'))

@app.route('/buscar_cliente', methods=['POST'])
def buscar_cliente():
    data = request.get_json()  # Obtener los datos enviados como JSON
    cedula = data.get('cedula', '').strip()  # Extraer la cédula del JSON

    conn = sqlite3.connect('eventos.db')
    cursor = conn.cursor()
    cursor.execute("""
        SELECT idCliente, Nombre, CI_RUC 
        FROM Clientes 
        WHERE CI_RUC = ?
    """, (cedula,))
    cliente = cursor.fetchone()
    conn.close()

    if cliente:
        return jsonify({'id': cliente[0], 'nombre': cliente[1], 'cedula': cliente[2]})
    else:
        return jsonify({'error': 'Cliente no encontrado'}), 404

# ============================
# GESTIÓN DE SALONES
# ============================
@app.route('/salones')
def salones():
    if 'user_id' in session and session['role'] in ['Administrador', 'Empleado']:
        conn = sqlite3.connect('eventos.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM Salones')
        salones = cursor.fetchall()
        conn.close()
        return render_template('salones.html', salones=salones, role=session['role'])
    return redirect(url_for('login'))

@app.route('/guardar_salon', methods=['POST'])
def guardar_salon():
    if 'user_id' in session and session['role'] in ['Administrador', 'Empleado']:
        nombre = request.form['nombre']
        capacidad = request.form['capacidad']
        precio = request.form['precio']

        conn = sqlite3.connect('eventos.db')
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO Salones (Nombre, Capacidad, Precio)
                VALUES (?, ?, ?)
            ''', (nombre, capacidad, precio))
            conn.commit()
            mensaje = "Salón agregado correctamente."
        except sqlite3.Error as e:
            mensaje = f"Error al agregar salón: {e}"
        finally:
            conn.close()

        return f"<script>alert('{mensaje}'); window.location.href='/salones';</script>"
    return redirect(url_for('login'))

@app.route('/editar_salon', methods=['POST'])
def editar_salon():
    if 'user_id' in session and session['role'] in ['Administrador', 'Empleado']:
        id_salon = request.form['id_salon']
        nombre = request.form['nombre']
        capacidad = request.form['capacidad']
        precio = request.form['precio']

        conn = sqlite3.connect('eventos.db')
        cursor = conn.cursor()
        try:
            cursor.execute('''
                UPDATE Salones
                SET Nombre = ?, Capacidad = ?, Precio = ?
                WHERE idSalon = ?
            ''', (nombre, capacidad, precio, id_salon))
            conn.commit()
            mensaje = "Salón actualizado correctamente."
        except sqlite3.Error as e:
            mensaje = f"Error al actualizar salón: {e}"
        finally:
            conn.close()

        return f"<script>alert('{mensaje}'); window.location.href='/salones';</script>"
    return redirect(url_for('login'))

@app.route('/eliminar_salon', methods=['POST'])
def eliminar_salon():
    if 'user_id' in session and session['role'] in ['Administrador', 'Empleado']:
        id_salon = request.form['id_salon']

        conn = sqlite3.connect('eventos.db')
        cursor = conn.cursor()
        try:
            cursor.execute('DELETE FROM Salones WHERE idSalon = ?', (id_salon,))
            conn.commit()
            mensaje = "Salón eliminado correctamente."
        except sqlite3.Error as e:
            mensaje = f"Error al eliminar salón: {e}"
        finally:
            conn.close()

        return f"<script>alert('{mensaje}'); window.location.href='/salones';</script>"
    return redirect(url_for('login'))

# ============================
# GESTIÓN DE RESERVAS
# ============================
@app.route('/reservas')
def reservas():
    if 'user_id' in session and session['role'] in ['Administrador', 'Empleado']:
        conn = sqlite3.connect('eventos.db')
        cursor = conn.cursor()

        # Obtener clientes
        cursor.execute('SELECT idCliente, Nombre FROM Clientes')
        clientes = cursor.fetchall()

        # Obtener salones
        cursor.execute('SELECT idSalon, Nombre FROM Salones')
        salones = cursor.fetchall()

        # Obtener reservas con servicios asociados
        cursor.execute('''
            SELECT r.idReserva, r.FechaReserva, c.Nombre AS Cliente, s.Nombre AS Salon,
                   COALESCE(GROUP_CONCAT(serv.Nombre || ' ($' || serv.Precio || ')', ', '), 'No hay servicios contratados') AS Servicios
            FROM Reservas r
            JOIN Clientes c ON r.idCliente = c.idCliente
            JOIN Salones s ON r.idSalon = s.idSalon
            LEFT JOIN Reserva_Servicio rs ON r.idReserva = rs.idReserva
            LEFT JOIN Servicios serv ON rs.idServicio = serv.idServicio
            GROUP BY r.idReserva, r.FechaReserva, c.Nombre, s.Nombre
        ''')
        reservas = cursor.fetchall()

        # Obtener servicios
        cursor.execute('SELECT * FROM Servicios')
        servicios = cursor.fetchall()

        conn.close()

        return render_template('reservas.html', clientes=clientes, salones=salones, reservas=reservas, servicios=servicios, role=session['role'])
    return redirect(url_for('login'))

@app.route('/guardar_reserva', methods=['POST'])
def guardar_reserva():
    data = request.get_json()  # Obtener los datos enviados como JSON
    fecha_reserva = data.get('fecha_reserva')
    id_cliente = data.get('id_cliente')
    id_salon = data.get('id_salon')
    id_servicios = data.get('id_servicios', [])  # Lista de servicios seleccionados

    # Validar los datos
    if not fecha_reserva or not id_cliente or not id_salon:
        return jsonify({"success": False, "message": "Faltan datos obligatorios."})

    conn = sqlite3.connect('eventos.db')
    cursor = conn.cursor()
    try:
        # Insertar la reserva
        cursor.execute('''
            INSERT INTO Reservas (FechaReserva, idCliente, idSalon)
            VALUES (?, ?, ?)
        ''', (fecha_reserva, id_cliente, id_salon))
        id_reserva = cursor.lastrowid  # Obtener el ID de la reserva recién creada

        # Insertar los servicios seleccionados en la tabla intermedia
        for id_servicio in id_servicios:
            cursor.execute('INSERT INTO Reserva_Servicio (idReserva, idServicio) VALUES (?, ?)', (id_reserva, id_servicio))

        conn.commit()
        return jsonify({"success": True})
    except sqlite3.Error as e:
        conn.rollback()
        return jsonify({"success": False, "message": str(e)})
    finally:
        conn.close()
@app.route('/obtener_reserva/<int:id_reserva>')
def obtener_reserva(id_reserva):
    if 'user_id' in session and session['role'] in ['Administrador', 'Empleado']:
        conn = sqlite3.connect('eventos.db')
        cursor = conn.cursor()

        # Obtener los datos de la reserva
        cursor.execute('''
            SELECT r.idReserva, r.FechaReserva, r.idCliente, r.idSalon,
                   COALESCE(GROUP_CONCAT(rs.idServicio), '') AS id_servicios
            FROM Reservas r
            LEFT JOIN Reserva_Servicio rs ON r.idReserva = rs.idReserva
            WHERE r.idReserva = ?
            GROUP BY r.idReserva
        ''', (id_reserva,))
        reserva = cursor.fetchone()
        conn.close()

        if reserva:
            return jsonify({
                "id": reserva[0],
                "fecha_reserva": reserva[1],
                "id_cliente": reserva[2],
                "id_salon": reserva[3],
                "id_servicios": [int(s) for s in reserva[4].split(',')] if reserva[4] else []
            })
        return jsonify({"error": "Reserva no encontrada"}), 404
    return redirect(url_for('login'))

@app.route('/editar_reserva', methods=['POST'])
def editar_reserva():
    if 'user_id' in session and session['role'] in ['Administrador', 'Empleado']:
        data = request.get_json()
        id_reserva = data.get('id_reserva')
        fecha_reserva = data.get('fecha_reserva')
        id_cliente = data.get('id_cliente')
        id_salon = data.get('id_salon')
        id_servicios = data.get('id_servicios', [])

        conn = sqlite3.connect('eventos.db')
        cursor = conn.cursor()
        try:
            # Actualizar la reserva
            cursor.execute('''
                UPDATE Reservas
                SET FechaReserva = ?, idCliente = ?, idSalon = ?
                WHERE idReserva = ?
            ''', (fecha_reserva, id_cliente, id_salon, id_reserva))

            # Actualizar los servicios asociados
            cursor.execute('DELETE FROM Reserva_Servicio WHERE idReserva = ?', (id_reserva,))
            for id_servicio in id_servicios:
                cursor.execute('INSERT INTO Reserva_Servicio (idReserva, idServicio) VALUES (?, ?)', (id_reserva, id_servicio))

            conn.commit()
            return jsonify({"success": True})
        except sqlite3.Error as e:
            conn.rollback()
            return jsonify({"success": False, "message": str(e)})
        finally:
            conn.close()
    return jsonify({"success": False, "message": "No autorizado."})

@app.route('/eliminar_reserva', methods=['POST'])
def eliminar_reserva():
    data = request.get_json()  # Obtener los datos enviados como JSON
    id_reserva = data.get('id_reserva')

    if not id_reserva:
        return jsonify({"success": False, "message": "ID de reserva no proporcionado."})

    conn = sqlite3.connect('eventos.db')
    cursor = conn.cursor()
    try:
        # Eliminar los servicios asociados a la reserva
        cursor.execute('DELETE FROM Reserva_Servicio WHERE idReserva = ?', (id_reserva,))
        # Eliminar la reserva
        cursor.execute('DELETE FROM Reservas WHERE idReserva = ?', (id_reserva,))
        conn.commit()
        return jsonify({"success": True})
    except sqlite3.Error as e:
        conn.rollback()
        return jsonify({"success": False, "message": str(e)})
    finally:
        conn.close()

# ============================
# GESTIÓN DE SERVICIOS
# ============================
@app.route('/servicios')
def servicios():
    if 'user_id' in session and session['role'] in ['Administrador', 'Empleado']:
        conn = sqlite3.connect('eventos.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM Servicios')
        servicios = cursor.fetchall()
        conn.close()
        return render_template('servicios.html', servicios=servicios, role=session['role'])
    return redirect(url_for('login'))

@app.route('/guardar_servicio', methods=['POST'])
def guardar_servicio():
    if 'user_id' in session and session['role'] in ['Administrador', 'Empleado']:
        nombre = request.form['nombre']
        precio = request.form['precio']

        conn = sqlite3.connect('eventos.db')
        cursor = conn.cursor()
        try:
            cursor.execute('INSERT INTO Servicios (Nombre, Precio) VALUES (?, ?)', (nombre, precio))
            conn.commit()
            mensaje = "Servicio agregado correctamente."
        except sqlite3.Error as e:
            conn.rollback()
            mensaje = f"Error al agregar servicio: {e}"
        finally:
            conn.close()

        # Mostrar mensaje emergente y redirigir
        return f"<script>alert('{mensaje}'); window.location.href='/servicios';</script>"
    return redirect(url_for('login'))

@app.route('/editar_servicio', methods=['POST'])
def editar_servicio():
    id_servicio = request.form['id_servicio']
    nombre = request.form['nombre']
    precio = request.form['precio']
    conn = sqlite3.connect('eventos.db')
    cursor = conn.cursor()
    cursor.execute('UPDATE Servicios SET Nombre = ?, Precio = ? WHERE idServicio = ?', (nombre, precio, id_servicio))
    conn.commit()
    conn.close()
    return redirect('/servicios')

@app.route('/eliminar_servicio', methods=['POST'])
def eliminar_servicio():
    id_servicio = request.form['id_servicio']
    conn = sqlite3.connect('eventos.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM Servicios WHERE idServicio = ?', (id_servicio,))
    conn.commit()
    conn.close()
    return redirect('/servicios')


@app.route('/facturas')
def facturas():
    if 'user_id' in session and session['role'] in ['Administrador', 'Empleado']:
        conn = sqlite3.connect('eventos.db')
        cursor = conn.cursor()
        cursor.execute('''
            SELECT f.idFactura, f.Timbrado, f.FechaFactura, f.Total, c.Nombre AS Cliente, r.FechaReserva
            FROM Facturas f
            JOIN Reservas r ON f.idReserva = r.idReserva
            JOIN Clientes c ON r.idCliente = c.idCliente
        ''')
        facturas = cursor.fetchall()

        # Obtener todos los clientes para el filtro por CI
        cursor.execute('SELECT idCliente, Nombre, CI_RUC FROM Clientes')
        clientes = cursor.fetchall()

        conn.close()
        return render_template('facturas.html', facturas=facturas, clientes=clientes, role=session['role'])
    return redirect(url_for('login'))

@app.route('/generar_factura', methods=['POST'])
def generar_factura():
    if 'user_id' in session and session['role'] in ['Administrador', 'Empleado']:
        id_reserva = request.form['id_reserva']

        conn = sqlite3.connect('eventos.db')
        cursor = conn.cursor()

        try:
            # Generar un timbrado único de 6 dígitos
            while True:
                timbrado = random.randint(100000, 999999)  # Número aleatorio de 6 dígitos
                cursor.execute("SELECT COUNT(*) FROM Facturas WHERE Timbrado = ?", (timbrado,))
                if cursor.fetchone()[0] == 0:  # Verificar que no exista en la base de datos
                    break

            # Calcular el total de la factura
            cursor.execute('''
                SELECT SUM(serv.Precio)
                FROM Reserva_Servicio rs
                JOIN Servicios serv ON rs.idServicio = serv.idServicio
                WHERE rs.idReserva = ?
            ''', (id_reserva,))
            total_servicios = cursor.fetchone()[0] or 0

            cursor.execute('''
                SELECT s.Precio
                FROM Reservas r
                JOIN Salones s ON r.idSalon = s.idSalon
                WHERE r.idReserva = ?
            ''', (id_reserva,))
            precio_salon = cursor.fetchone()[0] or 0

            total = total_servicios + precio_salon

            # Insertar la factura con el timbrado generado
            cursor.execute('''
                INSERT INTO Facturas (Timbrado, FechaFactura, Total, idReserva)
                VALUES (?, DATE('now'), ?, ?)
            ''', (timbrado, total, id_reserva))
            conn.commit()
            mensaje = f"Factura generada correctamente con Timbrado: {timbrado}."
        except sqlite3.Error as e:
            conn.rollback()
            mensaje = f"Error al generar factura: {e}"
        finally:
            conn.close()

        return f"<script>alert('{mensaje}'); window.location.href='/facturas';</script>"
    return redirect(url_for('login'))

@app.route('/factura_pdf/<int:id_factura>')
def factura_pdf(id_factura):
    if 'user_id' in session and session['role'] in ['Administrador', 'Empleado']:
        conn = sqlite3.connect('eventos.db')
        cursor = conn.cursor()

        # Obtener los datos de la factura
        cursor.execute('''
            SELECT f.idFactura, f.Timbrado, f.FechaFactura, 
                   c.Nombre AS Cliente, c.CI_RUC, c.Telefono, 
                   s.Nombre AS Salon, s.Precio AS PrecioSalon, r.idReserva
            FROM Facturas f
            JOIN Reservas r ON f.idReserva = r.idReserva
            JOIN Clientes c ON r.idCliente = c.idCliente
            JOIN Salones s ON r.idSalon = s.idSalon
            WHERE f.idFactura = ?
        ''', (id_factura,))
        factura = cursor.fetchone()

        if not factura:
            return "<script>alert('Factura no encontrada.'); window.location.href='/facturas';</script>"

        # Obtener los servicios contratados para la reserva
        cursor.execute('''
            SELECT serv.Nombre, serv.Precio
            FROM Reserva_Servicio rs
            JOIN Servicios serv ON rs.idServicio = serv.idServicio
            WHERE rs.idReserva = ?
        ''', (factura[8],))
        servicios = cursor.fetchall()

        conn.close()

        # Crear el PDF en memoria
        buffer = io.BytesIO()
        pdf = SimpleDocTemplate(buffer, pagesize=letter)
        elements = []
        styles = getSampleStyleSheet()

        # Encabezado con logo e información de la empresa
        logo_path = "static/images/logothegrandhall.jpg"
        try:
            logo = Image(logo_path, width=1.5 * inch, height=1.5 * inch)
        except Exception:
            logo = Paragraph("LOGO NO DISPONIBLE", styles['Normal'])

        encabezado_data = [
            [logo, Paragraph("<b>THE GRAND HALL</b>", styles['Title']), ""],
        ]
        encabezado_table = Table(encabezado_data, colWidths=[2 * inch, 4 * inch, 1 * inch])
        encabezado_table.setStyle(TableStyle([
            ('SPAN', (1, 0), (2, 0)),  # Combinar celdas para el título
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ]))

        # Información del cliente y factura
        cliente_data = [
            ["Timbrado N°:", factura[1], "Fecha:", factura[2]],
            ["Cliente:", factura[3], "CI/RUC:", factura[4]],
            ["Teléfono:", factura[5], "", ""]
        ]
        cliente_table = Table(cliente_data, colWidths=[100, 200, 100, 150])
        cliente_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))

        # Tabla de servicios y salón
        data = [["ID Reserva", "Descripción", "Precio"]]
        data.append([factura[8], factura[6], f"{factura[7]:,.2f} Gs"])  # ID Reserva, Salón y su precio

        # Agregar los servicios contratados
        for servicio in servicios:
            data.append(["", servicio[0], f"{servicio[1]:,.2f} Gs"])

        # Calcular el total
        total = factura[7] + sum(servicio[1] for servicio in servicios)
        data.append(["", "Total", f"{total:,.2f} Gs"])

# Crear la tabla de servicios y total
        table = Table(data, colWidths=[100, 300, 100])
        table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#192841")),  # Encabezado azul oscuro
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),  # Texto blanco en encabezado
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, -1), (-1, -1), colors.HexColor("#192841")),  # Fondo azul oscuro para toda la fila del total
        ('TEXTCOLOR', (0, -1), (-1, -1), colors.white),  # Texto blanco para toda la fila del total
        ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, -1), (-1, -1), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))

        # Agrupar todo dentro de un cuadro con espaciado adecuado
        content_data = [
            [encabezado_table],
            [Paragraph("<br/>", styles['Normal'])],  # Espaciado entre secciones
            [cliente_table],
            [Paragraph("<br/>", styles['Normal'])],  # Espaciado entre secciones
            [table],
            [Paragraph("<br/><br/>Gracias por su preferencia.", styles['Italic'])],
            [Paragraph("Dirección: Avda. Hall 2054, Asuncion", styles['Normal'])],
            [Paragraph("Teléfono: +595 981 234 567", styles['Normal'])],
            [Paragraph("Sitio web: www.thegrandhall.com", styles['Normal'])]
        ]
        content_table = Table(content_data, colWidths=[580])  # Más ancho para cubrir mejor la hoja
        content_table.setStyle(TableStyle([
            ('BOX', (0, 0), (-1, -1), 2, colors.black),
            ('PADDING', (0, 0), (-1, -1), 20),  # Más cómodo
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),  # Alineado al borde izquierdo
        ]))

        elements.append(content_table)

        # Generar el PDF
        pdf.build(elements)
        buffer.seek(0)

        # Enviar el PDF como respuesta
        response = make_response(buffer.getvalue())
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'inline; filename=factura_{factura[0]}.pdf'
        return response
    return redirect(url_for('login'))

@app.route('/buscar_reservas', methods=['POST'])
def buscar_reservas():
    data = request.get_json()  # Recibir datos en formato JSON
    ci_ruc = data.get('ci_ruc', '').strip()  # Obtener el CI/RUC del cliente

    conn = sqlite3.connect('eventos.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT r.idReserva, r.FechaReserva, c.Nombre AS Cliente, s.Nombre AS Salon
        FROM Reservas r
        JOIN Clientes c ON r.idCliente = c.idCliente
        JOIN Salones s ON r.idSalon = s.idSalon
        WHERE c.CI_RUC = ?
    ''', (ci_ruc,))
    reservas = cursor.fetchall()
    conn.close()

    if reservas:
        return jsonify({'reservas': reservas})
    else:
        return jsonify({'error': 'No se encontraron reservas para el CI proporcionado.'}), 404

# ============================
# SECCION DE REPORTES
# ============================

@app.route('/reportes')
def reportes():
    if 'user_id' in session and session['role'] == 'Administrador':
        return render_template('reportes.html')
    return redirect(url_for('login'))

@app.route('/reporte_clientes')
def reporte_clientes():
    if 'user_id' in session and session['role'] == 'Administrador':
        conn = sqlite3.connect('eventos.db')
        cursor = conn.cursor()
        cursor.execute('SELECT idCliente, Nombre, Telefono, Email, CI_RUC FROM Clientes')
        clientes = cursor.fetchall()
        conn.close()

        # Crear el PDF
        buffer = io.BytesIO()
        pdf = SimpleDocTemplate(buffer, pagesize=letter)
        elements = []
        styles = getSampleStyleSheet()

        # Encabezado
        encabezado = Paragraph(f"<b>The Grand Hall</b><br/><b>Reporte de Clientes</b><br/>Generado el {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}", styles['Title'])
        elements.append(encabezado)
        elements.append(Paragraph("<br/>", styles['Normal']))

        # Tabla de clientes
        data = [["ID", "Nombre", "Teléfono", "Email", "CI/RUC"]]
        for cliente in clientes:
            data.append(cliente)

        table = Table(data, colWidths=[50, 150, 100, 150, 100])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#192841")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        elements.append(table)

        # Generar el PDF
        pdf.build(elements)
        buffer.seek(0)

        response = make_response(buffer.getvalue())
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = 'inline; filename=reporte_clientes.pdf'
        return response
    return redirect(url_for('login'))

@app.route('/reporte_reservas')
def reporte_reservas():
    if 'user_id' in session and session['role'] == 'Administrador':
        conn = sqlite3.connect('eventos.db')
        cursor = conn.cursor()
        cursor.execute('''
            SELECT r.idReserva, r.FechaReserva, c.Nombre AS Cliente, s.Nombre AS Salon,
                   COALESCE(GROUP_CONCAT(serv.Nombre, ', '), 'No hay servicios contratados') AS Servicios
            FROM Reservas r
            JOIN Clientes c ON r.idCliente = c.idCliente
            JOIN Salones s ON r.idSalon = s.idSalon
            LEFT JOIN Reserva_Servicio rs ON r.idReserva = rs.idReserva
            LEFT JOIN Servicios serv ON rs.idServicio = serv.idServicio
            GROUP BY r.idReserva, r.FechaReserva, c.Nombre, s.Nombre
        ''')
        reservas = cursor.fetchall()
        conn.close()

        # Crear el PDF
        buffer = io.BytesIO()
        pdf = SimpleDocTemplate(buffer, pagesize=letter)
        elements = []
        styles = getSampleStyleSheet()

        # Encabezado
        encabezado = Paragraph(f"<b>The Grand Hall</b><br/><b>Reporte de Reservas</b><br/>Generado el {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}", styles['Title'])
        elements.append(encabezado)
        elements.append(Paragraph("<br/>", styles['Normal']))

        # Tabla de reservas
        data = [["ID", "Fecha", "Cliente", "Salón", "Servicios"]]
        for reserva in reservas:
            data.append(reserva)

        table = Table(data, colWidths=[50, 100, 150, 150, 200])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#192841")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        elements.append(table)

        # Generar el PDF
        pdf.build(elements)
        buffer.seek(0)

        response = make_response(buffer.getvalue())
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = 'inline; filename=reporte_reservas.pdf'
        return response
    return redirect(url_for('login'))

@app.route('/eliminar_factura', methods=['POST'])
def eliminar_factura():
    if 'user_id' in session and session['role'] in ['Administrador', 'Empleado']:
        data = request.get_json()
        id_factura = data.get('id_factura')

        if not id_factura:
            return jsonify({"success": False, "message": "ID de factura no proporcionado."})

        conn = sqlite3.connect('eventos.db')
        cursor = conn.cursor()
        try:
            # Eliminar la factura
            cursor.execute('DELETE FROM Facturas WHERE idFactura = ?', (id_factura,))
            conn.commit()
            return jsonify({"success": True})
        except sqlite3.Error as e:
            conn.rollback()
            return jsonify({"success": False, "message": str(e)})
        finally:
            conn.close()
    return jsonify({"success": False, "message": "No autorizado."})

@app.route('/reporte_usuarios')
def reporte_usuarios():
    if 'user_id' in session and session['role'] == 'Administrador':
        conn = sqlite3.connect('eventos.db')
        cursor = conn.cursor()
        cursor.execute('SELECT idUsuario, Nombre, Rol FROM Usuarios')
        usuarios = cursor.fetchall()
        conn.close()

        # Crear el PDF
        buffer = io.BytesIO()
        pdf = SimpleDocTemplate(buffer, pagesize=letter)
        elements = []
        styles = getSampleStyleSheet()

        # Encabezado
        encabezado = Paragraph(f"<b>The Grand Hall</b><br/><b>Reporte de Usuarios</b><br/>Generado el {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}", styles['Title'])
        elements.append(encabezado)
        elements.append(Paragraph("<br/>", styles['Normal']))

        # Tabla de usuarios
        data = [["ID", "Nombre", "Rol"]]
        for usuario in usuarios:
            data.append(usuario)

        table = Table(data, colWidths=[50, 200, 100])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#192841")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        elements.append(table)

        # Generar el PDF
        pdf.build(elements)
        buffer.seek(0)

        response = make_response(buffer.getvalue())
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = 'inline; filename=reporte_usuarios.pdf'
        return response
    return redirect(url_for('login'))


# ============================
# INICIAR SERVIDOR
# ============================
if __name__ == '__main__':
    app.run(debug=True)



