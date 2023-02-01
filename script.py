from flask import Flask, request, render_template, redirect, url_for
import os
import uuid
import base64
import sqlite3
import secrets
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

app = Flask(__name__, static_folder='static')

@app.route("/")
def index():
    return render_template("index.html")

@app.route('/create', methods=['GET', 'POST'])
def create():
    message = request.form.get("message")
    if not message:
        return "Nachricht nicht gefunden", 400
    message = message.encode()
    password = request.form.get("password")
    encrypted = message
    encrypted_with_password = False
    salt = None
    if password:
        salt = secrets.token_bytes(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512,
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        fernet = Fernet(key)
        encrypted = fernet.encrypt(message)
        encrypted_with_password = True
    encoded = base64.urlsafe_b64encode(encrypted).decode()

    conn = sqlite3.connect('messages.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS messages (id text, message text, encrypted_with_password boolean, salt text)''')
    message_id = str(uuid.uuid4())
    c.execute("INSERT INTO messages VALUES (?, ?, ?, ?)", (message_id, encoded, encrypted_with_password, base64.b64encode(salt).decode() if salt else None))
    conn.commit()
    conn.close()

    return redirect(url_for("show_link", message_id=message_id))

@app.route('/show_link/<message_id>')
def show_link(message_id):
    link = url_for('show_message', message_id=message_id)
    return render_template('show_link.html', link=link, message_id=message_id)


@app.route('/message/<message_id>', methods=['GET', 'POST'])
def show_message(message_id):
    conn = sqlite3.connect('messages.db')
    c = conn.cursor()
    c.execute("SELECT message, encrypted_with_password, salt FROM messages WHERE id=?", (message_id,))
    message = c.fetchone()
    if not message:
        return "Nachricht nicht gefunden", 404
    encoded, encrypted_with_password, salt = message
    decoded = base64.urlsafe_b64decode(encoded.encode())
    password = request.form.get("password")
    decrypted = decoded
    if encrypted_with_password:
        if not password:
            return render_template("password.html", message_id=message_id)
        salt = base64.b64decode(salt.encode())
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512,
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        fernet = Fernet(key)
        decrypted = fernet.decrypt(decoded)
    conn.execute("DELETE FROM messages WHERE id=?", (message_id,))
    conn.commit()
    conn.close()
    return render_template("show_message.html", message=decrypted.decode())


if __name__ == "__main__":
    app.run(debug=True)