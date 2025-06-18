from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from modules.db import get_connection

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['role'] = user[5]  # role
            return redirect(url_for('index'))  # change si t’as une autre route
        else:
            flash("Identifiants invalides.")
    return render_template('auth/login.html')

@auth_bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.login'))

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        role = request.form.get('role', 'technicien')

        hashed_password = generate_password_hash(password)

        conn = get_connection()
        cur = conn.cursor()
        cur.execute("INSERT INTO users (username, password_hash, email, role) VALUES (%s, %s, %s, %s)", 
                    (username, hashed_password, email, role))
        conn.commit()
        cur.close()
        conn.close()

        flash("Compte créé, connecte-toi.")
        return redirect(url_for('auth.login'))
    
    return render_template('auth/register.html')
