
from flask import Flask, request, render_template_string, send_file, redirect, url_for, session
import os
import fitz  # PyMuPDF
import pandas as pd
from werkzeug.utils import secure_filename
from fpdf import FPDF
import io
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
app.config['UPLOAD_FOLDER'] = 'uploads'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def extract_text_from_pdf(path):
    text = ""
    doc = fitz.open(path)
    for page in doc:
        text += page.get_text()
    return text

def analyze_text(text):
    lines = text.splitlines()
    entries = []
    exits = []
    for line in lines:
        if 'Pix recebido' in line or 'Transferência recebida' in line:
            for s in line.split():
                if s.startswith('R$'):
                    value = float(s.replace('R$', '').replace('.', '').replace(',', '.'))
                    entries.append(value)
        elif 'Pix enviado' in line or 'Pagamento' in line:
            for s in line.split():
                if s.startswith('R$'):
                    value = float(s.replace('R$', '').replace('.', '').replace(',', '.'))
                    exits.append(value)
    return {
        'total_entradas': sum(entries),
        'total_saidas': sum(exits),
        'renda_media_aproximada': sum(entries) / 3 if entries else 0,
        'qtd_entradas': len(entries),
        'qtd_saidas': len(exits)
    }

def generate_report(results):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Extrato Analysis Report", ln=True, align='C')
    pdf.ln(10)
    for r in results:
        for k, v in r.items():
            pdf.cell(200, 10, txt=f"{k}: {v}", ln=True)
        pdf.ln(5)
    output = io.BytesIO()
    pdf.output(output)
    output.seek(0)
    return output

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form.get('username')
        password = request.form.get('password')
        if user == 'admin' and password == '1234':
            session['logged_in'] = True
            return redirect(url_for('index'))
        else:
            return '<h3>Invalid login</h3><a href="/login">Try again</a>'
    return '''
    <h2>Login</h2>
    <form method="post">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <input type="submit" value="Login">
    </form>
    '''

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

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
    <a href="/download-relatorio" class="btn btn-success mt-4">Baixar Relatório em PDF</a>
    {% endif %}
</div>
</body>
</html>
'''

results_cache = []

@app.route('/', methods=['GET'])
@login_required
def index():
    return render_template_string(HTML_TEMPLATE, resultados=None)

@app.route('/upload', methods=['POST'])
@login_required
def upload_files():
    global results_cache
    uploaded_files = request.files.getlist("files")
    resultados = []
    for file in uploaded_files:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        text = extract_text_from_pdf(filepath)
        result = analyze_text(text)
        result['arquivo'] = filename
        resultados.append(result)
    results_cache = resultados
    return render_template_string(HTML_TEMPLATE, resultados=resultados)

@app.route('/download-relatorio')
@login_required
def download_relatorio():
    output = generate_report(results_cache)
    return send_file(output, as_attachment=True, download_name="relatorio_analise.pdf", mimetype='application/pdf')

if __name__ == '__main__':
    import os
port = int(os.environ.get("PORT", 10000))
app.run(host="0.0.0.0", port=port, debug=False)


