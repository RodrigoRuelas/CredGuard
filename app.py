from datetime import datetime
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_sqlalchemy import SQLAlchemy
import bcrypt
from analyzer import evaluar_contrasena

app = Flask(__name__)
app.config['SECRET_KEY'] = 'clave_secreta_super_segura_credguard'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ==========================================
# MODELOS DE BASE DE DATOS (SQLite)
# ==========================================

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False) # Requisito 6: Hash de clave
    failed_attempts = db.Column(db.Integer, default=0)        # Requisito 12: Control de intentos fallidos
    lock_until = db.Column(db.DateTime, nullable=True)         # Requisito 12: Bloqueo temporal

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    action = db.Column(db.String(50), nullable=False)          # 'EXITOSO' o 'FALLIDO'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow) # Requisito 11: Fecha y hora

# Crear las tablas automáticamente al iniciar
with app.app_context():
    db.create_all()

# ==========================================
# RUTAS DEL BLOQUE 1 (Analizador)
# ==========================================
@app.route('/', methods=['GET', 'POST'])
def index():
    resultado = None
    password_ingresada = ""
    if request.method == 'POST':
        password_ingresada = request.form.get('password', '')
        if password_ingresada:
            resultado = evaluar_contrasena(password_ingresada)
    return render_template('index.html', resultado=resultado, password=password_ingresada)

# ==========================================
# RUTAS DEL BLOQUE 2 (Autenticación y Bitácora)
# ==========================================

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Verificar si el usuario ya existe
        if User.query.filter_by(username=username).first():
            flash('El nombre de usuario ya está en uso.', 'danger')
            return redirect(url_for('register'))

        # Requisito 6: Derivación de clave lenta con bcrypt (nunca texto plano)
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

        nuevo_usuario = User(username=username, password_hash=hashed_password)
        db.session.add(nuevo_usuario)
        db.session.commit()

        flash('Registro exitoso. Ahora puedes iniciar sesión.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    MAX_INTENTOS = 3  # Requisito 12: Número configurable de intentos fallidos
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()

        if user:
            # Requisito 12: Verificar si la cuenta está bloqueada temporalmente
            if user.lock_until and user.lock_until > datetime.utcnow():
                flash('Cuenta temporalmente bloqueada por múltiples intentos fallidos. Intente más tarde.', 'danger')
                return render_template('login.html')

            # Requisito 7: Validar comparando contra el hash almacenado
            if bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
                # Inicio de sesión exitoso -> Reiniciar intentos fallidos
                user.failed_attempts = 0
                user.lock_until = None
                
                # Requisito 11: Registrar en bitácora (Exitoso)
                log = AuditLog(username=username, action='EXITOSO')
                db.session.add(log)
                db.session.commit()

                session['user'] = username
                flash(f'¡Bienvenido, {username}!', 'success')
                return redirect(url_for('dashboard'))
            else:
                # Contraseña incorrecta
                user.failed_attempts += 1
                
                # Requisito 12: Bloquear si supera el límite
                if user.failed_attempts >= MAX_INTENTOS:
                    from datetime import timedelta
                    user.lock_until = datetime.utcnow() + timedelta(minutes=5) # Bloqueo por 5 minutos
                    flash('Demasiados intentos fallidos. Cuenta bloqueada temporalmente por 5 minutos.', 'danger')
                else:
                    flash(f'Contraseña incorrecta. Intentos restantes: {MAX_INTENTOS - user.failed_attempts}', 'warning')

                # Requisito 11: Registrar en bitácora (Fallido)
                log = AuditLog(username=username, action='FALLIDO')
                db.session.add(log)
                db.session.commit()
        else:
            flash('El usuario no existe.', 'danger')

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        flash('Por favor inicia sesión primero.', 'warning')
        return redirect(url_for('login'))
    
    # Requisito 11: Consultar la bitácora para mostrarla en pantalla
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    return render_template('dashboard.html', logs=logs, username=session['user'])

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('Has cerrado sesión.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)