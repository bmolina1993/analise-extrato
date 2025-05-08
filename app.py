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
            <p class="fw-bold">Autenticidade: 
              {% if r['autenticidade'] == 'verdadeiro' %}
                <span class="text-success">{{ r['autenticidade'] }}</span>
              {% else %}
                <span class="text-danger">{{ r['autenticidade'] }}</span>
              {% endif %}
            </p>
            {% if r['motivos'] %}
            <ul class="text-danger">
              {% for motivo in r['motivos'].split(' | ') if motivo %}
                <li>{{ motivo }}</li>
              {% endfor %}
            </ul>
            {% endif %}
        </div>
    </div>
    {% endfor %}
    {% endif %}
</div>
</body>
</html>
'''

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
            autenticidade TEXT,
            motivos TEXT,
            data_analisada TEXT
        )''')
init_db()

# Decorador de login

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('user_login'))
        return f(*args, **kwargs)
    return decorated_function

# Extração e análise dos PDFs
def extract_text_from_pdf(path):
    text = ""
    try:
        doc = fitz.open(path)
        for page in doc:
            page_text = page.get_text("text")
            if not page_text.strip():
                blocks = page.get_text("blocks")
                page_text = " ".join([b[4] for b in blocks if isinstance(b[4], str)])
            text += page_text + "\n"
        print("--- TEXTO EXTRAÍDO DO PDF ---")
        print(text)
    except Exception as e:
        print(f"Erro ao extrair texto: {e}")
    return text

def analyze_text(text):
    import re
    lines = text.splitlines()
    entradas, saidas = [], []
    suspeitas = []
    contexto = None  # entrada ou saída

    for i, line in enumerate(lines):
        l = line.lower()
        if 'pix recebida' in l or 'transferência recebida' in l:
            contexto = 'entrada'
        elif any(p in l for p in ['pix enviada', 'pagamento', 'retirado', 'reserva']):
            contexto = 'saida'

        # Captura valores no formato R$ 300,00 ou R$300,00
        valores = re.findall(r'r\$\s*[\d\.,-]+', line, re.IGNORECASE)
        for v in valores:
            try:
                valor = float(
                    v.lower()
                    .replace('r$', '')
                    .replace(' ', '')
                    .replace('.', '')
                    .replace(',', '.')
                )
                if contexto == 'entrada':
                    if valor < 0:
                        suspeitas.append(f"Entrada com valor negativo: R$ {valor:.2f}")
                    entradas.append(abs(valor))
                elif contexto == 'saida':
                    if valor > 0:
                        suspeitas.append(f"Saída com valor positivo: R$ {valor:.2f}")
                    saidas.append(abs(valor))
                contexto = None
            except:
                continue

    autenticidade = "verdadeiro" if not suspeitas else "possivelmente adulterado"

    return {
        'total_entradas': sum(entradas),
        'total_saidas': sum(saidas),
        'renda_media_aproximada': sum(entradas) / 3 if entradas else 0,
        'qtd_entradas': len(entradas),
        'qtd_saidas': len(saidas),
        'autenticidade': autenticidade,
        'motivos': suspeitas
    }

        'total_entradas': sum(entradas),
        'total_saidas': sum(saidas),
        'renda_media_aproximada': sum(entradas) / 3 if entradas else 0,
        'qtd_entradas': len(entradas),
        'qtd_saidas': len(saidas),
        'autenticidade': autenticidade,
        'motivos': suspeitas
    }

@app.route('/')
@login_required
def index():
    return redirect(url_for('historico'))

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

        with sqlite3.connect('users.db') as conn:
            conn.execute('''INSERT INTO historico (username, arquivo, total_entradas, total_saidas, renda_media, qtd_entradas, qtd_saidas, autenticidade, motivos, data_analisada)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                         (username, filename, resultado['total_entradas'], resultado['total_saidas'], resultado['renda_media_aproximada'],
                          resultado['qtd_entradas'], resultado['qtd_saidas'], resultado['autenticidade'], " | ".join(resultado['motivos']), datetime.now().strftime('%Y-%m-%d %H:%M:%S')))

    session['resultados'] = resultados
    return redirect(url_for('resultado'))

@app.route('/resultado')
@login_required
def resultado():
    resultados = session.pop('resultados', [])
    return render_template_string(HTML_TEMPLATE, resultados=resultados)

@app.route('/historico')
@login_required
def historico():
    username = session.get('username')
    with sqlite3.connect('users.db') as conn:
        cur = conn.execute("SELECT arquivo, total_entradas, total_saidas, renda_media, qtd_entradas, qtd_saidas, autenticidade, motivos, data_analisada FROM historico WHERE username = ? ORDER BY data_analisada DESC", (username,))
        dados = [dict(zip([column[0] for column in cur.description], row)) for row in cur.fetchall()]
    return render_template_string(HTML_TEMPLATE, resultados=dados)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('user_login'))

@app.route('/login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = get_user(username)
        if user and check_password(password, user[2]):
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('index'))
        else:
            return '<h3>Login inválido</h3><a href="/login">Tentar novamente</a>'
    return '''<h2>Login</h2><form method="post">Usuário: <input type="text" name="username"><br>Senha: <input type="password" name="password"><br><input type="submit" value="Entrar"></form><p>Ou <a href="/register">cadastre-se</a></p>'''

@app.route('/register', methods=['GET', 'POST'])
def register():
    admin_key_required = 'super123'
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        admin_key = request.form.get('admin_key')
        if admin_key != admin_key_required:
            return '<h3>Chave de administrador inválida</h3><a href="/register">Tente novamente</a>'
        if create_user(username, password):
            return redirect(url_for('user_login'))
        else:
            return 'Usuário já existe. <a href="/register">Tente novamente</a>'
    return '''<h2>Cadastro</h2>
    <form method="post">
        Usuário: <input type="text" name="username"><br>
        Senha: <input type="password" name="password"><br>
        Chave de Administrador: <input type="password" name="admin_key"><br>
        <input type="submit" value="Cadastrar">
    </form>'''


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


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port, debug=False)

