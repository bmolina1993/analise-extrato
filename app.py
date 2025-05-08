from flask import Flask, request, render_template_string, send_file, redirect, url_for, session
import os
import fitz  # PyMuPDF
import pandas as pd
from werkzeug.utils import secure_filename
from fpdf import FPDF
import io
from functools import wraps
import sqlite3
import bcrypt
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Inicializa banco de dados
def init_db():
    with sqlite3.connect('users.db') as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )''')
        conn.execute('''CREATE TABLE IF NOT EXISTS historico (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            arquivo TEXT,
            total_entradas REAL,
            total_saidas REAL,
            renda_media REAL,
            qtd_entradas INTEGER,
            qtd_saidas INTEGER,
            data_analisada TEXT
        )''')
init_db()

# Decorador de login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Autenticação

def get_user(username):
    with sqlite3.connect('users.db') as conn:
        cur = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
        return cur.fetchone()

def create_user(username, password):
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    try:
        with sqlite3.connect('users.db') as conn:
            conn.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
        return True
    except sqlite3.IntegrityError:
        return False

def check_password(password, password_hash):
    return bcrypt.checkpw(password.encode('utf-8'), password_hash)

# Extração e análise dos PDFs
def extract_text_from_pdf(path):
    text = ""
    try:
        doc = fitz.open(path)
        for page in doc:
            text += page.get_text("text")
    except Exception as e:
        text = ""
    return text

def analyze_text(text):
    lines = text.splitlines()
    entradas, saidas = [], []
    for line in lines:
        if 'Pix recebido' in line or 'Transferência recebida' in line:
            for s in line.split():
                if 'R$' in s:
                    try:
                        valor = float(s.replace('R$', '').replace('.', '').replace(',', '.'))
                        entradas.append(valor)
                    except:
                        continue
        elif 'Pix enviado' in line or 'Pagamento' in line:
            for s in line.split():
                if 'R$' in s:
                    try:
                        valor = float(s.replace('R$', '').replace('.', '').replace(',', '.'))
                        saidas.append(valor)
                    except:
                        continue
    return {
        'total_entradas': sum(entradas),
        'total_saidas': sum(saidas),
        'renda_media_aproximada': sum(entradas) / 3 if entradas else 0,
        'qtd_entradas': len(entradas),
        'qtd_saidas': len(saidas)
    }

# HTML com Bootstrap
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <title>Análise de Extratos</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="p-4">
<div class="container">
    <h1 class="mb-4">Upload de Extratos Bancários</h1>
    <a href="/logout" class="btn btn-outline-danger float-end">Sair</a>
    <form action="/upload" method="post" enctype="multipart/form-data">
        <div class="mb-3">
            <input class="form-control" type="file" name="files" multiple required>
        </div>
        <button class="btn btn-primary" type="submit">Analisar</button>
    </form>

    {% if resultados %}
    <h2 class="mt-5">Resultados:</h2>
    {% for r in resultados %}
    <div class="card mt-3">
        <div class="card-body">
            <h5 class="card-title">Arquivo: {{ r['arquivo'] }}</h5>
            <p>Total de Entradas: R$ {{ r['total_entradas'] }}</p>
            <p>Total de Saídas: R$ {{ r['total_saidas'] }}</p>
            <p>Renda Média Aproximada: R$ {{ r['renda_media_aproximada'] }}</p>
            <p>Qtd de Entradas: {{ r['qtd_entradas'] }}</p>
            <p>Qtd de Saídas: {{ r['qtd_saidas'] }}</p>
        </div>
    </div>
    {% endfor %}
    {% endif %}
</div>
</body>
</html>
'''

@app.route('/')
@login_required
def index():
    return render_template_string(HTML_TEMPLATE, resultados=None)

@app.route('/upload', methods=['POST'])
@login_required
def upload_files():
    uploaded_files = request.files.getlist("files")
    resultados = []
    username = session.get('username', 'anonimo')
    for file in uploaded_files:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        texto = extract_text_from_pdf(filepath)
        resultado = analyze_text(texto)
        resultado['arquivo'] = filename
        resultados.append(resultado)

        # Salvar no histórico
        with sqlite3.connect('users.db') as conn:
            conn.execute('''INSERT INTO historico (username, arquivo, total_entradas, total_saidas, renda_media, qtd_entradas, qtd_saidas, data_analisada)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                         (username, filename, resultado['total_entradas'], resultado['total_saidas'], resultado['renda_media_aproximada'],
                          resultado['qtd_entradas'], resultado['qtd_saidas'], datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    return render_template_string(HTML_TEMPLATE, resultados=resultados)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port, debug=False)
