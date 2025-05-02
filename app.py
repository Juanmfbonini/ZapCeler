from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_bcrypt import Bcrypt
from flask_login import login_user, login_required, logout_user, current_user
import plotly_express as px
import sqlite3 as bancodedados
import pyautogui as auto
import webbrowser as wb
import pyperclip
import time
import flask_login
import stripe

#Email teste: teste@gmail.com
#Senha teste: teste123

app = Flask(__name__)

# Configurações de login
bcrypt = Bcrypt(app)
login_manager = flask_login.LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Configurações Stripe

#Email do ADM

# Conexões de Banco de Dados
def conectar_clientes():
    return bancodedados.connect("Clientes.db")

def conectar_sistema():
    return bancodedados.connect("Sistema.db")

# Criação de tabelas
def banco():
    conn = conectar_clientes()
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS Clientes(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            Nome TEXT,
            Numero TEXT,
            usuario_id INTEGER
        )
    ''')
    conn.commit()
    conn.close()

def criar_tabela_usuarios():
    conn = conectar_sistema()
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS Users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            senha_hash TEXT,
            plano_id INTEGER,
            status TEXT DEFAULT 'nao_pago'
        )
    ''')
    conn.commit()
    conn.close()

def criar_tabela_planos():
    conn = conectar_sistema()
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS Planos(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT,
            preco_cents INTEGER,
            stripe_price_id TEXT
        )
    ''')
    conn.commit()
    conn.close()

# Modelos e Login
class User(flask_login.UserMixin):
    pass

@login_manager.user_loader
def load_user(user_id):
    conn = conectar_sistema()
    c = conn.cursor()
    c.execute("SELECT id, email, senha_hash, plano_id, status FROM Users WHERE id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    if row:
        user = User()
        user.id, user.email, user.senha_hash, user.plano_id, user.status = row
        return user
    return None

# Funções de Clientes
def adicionar_clientes(nome, numero, usuario_id):
    conn = conectar_clientes()
    c = conn.cursor()
    c.execute("INSERT INTO Clientes (Nome, Numero, usuario_id) VALUES (?, ?, ?)", (nome, numero, usuario_id))
    conn.commit()
    conn.close()

def excluir_clientes(id, usuario_id):
    conn = conectar_clientes()
    c = conn.cursor()
    c.execute("DELETE FROM Clientes WHERE id = ? AND usuario_id = ?", (id, usuario_id))
    conn.commit()
    conn.close()

def buscar_cliente_por_id(id, usuario_id):
    conn = conectar_clientes()
    c = conn.cursor()
    c.execute("SELECT id, Nome, Numero FROM Clientes WHERE id = ? AND usuario_id = ?", (id, usuario_id))
    cliente = c.fetchone()
    conn.close()
    return cliente

def editar_clientes(id, novo_nome, novo_numero, usuario_id):
    conn = conectar_clientes()
    c = conn.cursor()
    c.execute("UPDATE Clientes SET Nome = ?, Numero = ? WHERE id = ? AND usuario_id = ?", (novo_nome, novo_numero, id, usuario_id))
    conn.commit()
    conn.close()

def buscar_clientes(usuario_id):
    conn = conectar_clientes()
    c = conn.cursor()
    c.execute("SELECT id, Nome, Numero FROM Clientes WHERE usuario_id = ?", (usuario_id,))
    clientes = c.fetchall()
    conn.close()
    return clientes

# Automação de Mensagens
def envio_mensagem_para_clientes(lista_numeros, mensagem):
    for numero in lista_numeros:
        link = f"https://wa.me/{numero}"
        wb.open(link)
        time.sleep(2)

        auto.press(["tab"] * 11)
        auto.press("enter")
        time.sleep(1)

        auto.press(["tab"] * 2)
        auto.press("enter")
        time.sleep(7)

        pyperclip.copy(mensagem)
        auto.hotkey("ctrl", "v")

        auto.press("enter")
        time.sleep(1)
        auto.hotkey("alt", "f4")
        time.sleep(2)

# Rotas públicas
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form["email"]
        senha = request.form["senha"]
        hash_ = bcrypt.generate_password_hash(senha).decode('utf-8')
        conn = conectar_sistema()
        c = conn.cursor()
        try:
            c.execute("INSERT INTO Users (email, senha_hash) VALUES (?, ?)", (email, hash_))
            conn.commit()
            return redirect(url_for('login'))
        except bancodedados.IntegrityError:
            flash("Email já cadastrado.")
        finally:
            conn.close()
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        senha = request.form["senha"]
        conn = conectar_sistema()
        c = conn.cursor()
        c.execute("SELECT id, senha_hash FROM Users WHERE email = ?", (email,))
        row = c.fetchone()
        conn.close()
        if row and bcrypt.check_password_hash(row[1], senha):
            user = User()
            user.id = row[0]
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash("Credenciais inválidas.")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Rotas protegidas (usuário logado)
@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    if current_user.status not in ["pagou", "gratuito"]:
        return redirect(url_for("planos"))

    clientes = buscar_clientes(current_user.id)
    if request.method == "POST":
        ids = request.form.getlist("clientes")
        mensagem = request.form["mensagem"]
        lista = []
        if "Todos" in ids:
            lista = [c[2] for c in clientes]
        else:
            for c in clientes:
                if str(c[0]) in ids:
                    lista.append(c[2])
        envio_mensagem_para_clientes(lista, mensagem)
        return redirect(url_for('index'))
    return render_template("index.html", clientes=clientes)

@app.route("/cadastro", methods=["GET", "POST"])
@login_required
def cadastro():
    if current_user.status not in ["pagou", "gratuito"]:
        return redirect(url_for("planos"))

    if request.method == "POST":
        nome = request.form["nome"]
        numero = request.form["numero"]
        adicionar_clientes(nome, numero, current_user.id)
    return render_template("cadC.html")

@app.route("/editar/<int:id>", methods=["GET", "POST"])
@login_required
def editar(id):
    if current_user.status not in ["pagou", "gratuito"]:
        return redirect(url_for("planos"))

    cliente = buscar_cliente_por_id(id, current_user.id)
    if request.method == "POST":
        nome = request.form["nome"]
        numero = request.form["numero"]
        editar_clientes(id, nome, numero, current_user.id)
    return render_template("editar.html", cliente=cliente)

@app.route("/excluir/<int:id>", methods=["POST"])
@login_required
def excluir(id):
    if current_user.status not in ["pagou", "gratuito"]:
        return redirect(url_for("planos"))

    excluir_clientes(id, current_user.id)
    return redirect(url_for('listar_clientes'))

@app.route("/clientes", methods=["GET", "POST"])
@login_required
def listar_clientes():
    if current_user.status not in ["pagou", "gratuito"]:
        return redirect(url_for("planos"))

    query = request.form.get('search', '').strip() if request.method == "POST" else ''
    conn = conectar_clientes()
    c = conn.cursor()
    if query:
        c.execute("SELECT id, Nome, Numero FROM Clientes WHERE usuario_id = ? AND (Nome LIKE ? OR Numero LIKE ?) ORDER BY Nome", (current_user.id, f'%{query}%', f'%{query}%'))
    else:
        c.execute("SELECT id, Nome, Numero FROM Clientes WHERE usuario_id = ? ORDER BY Nome", (current_user.id,))
    clientes = c.fetchall()
    conn.close()
    return render_template("clientes.html", clientes=clientes, search_query=query)

# Planos e cobrança
@app.route("/planos")
def planos():
    conn = conectar_sistema()
    c = conn.cursor()
    c.execute("SELECT id, nome, preco_cents, descricao FROM Planos WHERE nome != 'Gratuito Ilimitado'")
    planos = c.fetchall()
    conn.close()
    return render_template("planos.html", planos=planos)

@app.route("/create-checkout-session/<int:plano_id>", methods=["POST"])
@login_required
def create_checkout_session(plano_id):
    conn = conectar_sistema()
    c = conn.cursor()
    c.execute("SELECT stripe_price_id FROM Planos WHERE id = ?", (plano_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return "Plano inválido.", 400
    session = stripe.checkout.Session.create(
        customer_email=current_user.email,
        payment_method_types=['card'],
        line_items=[{'price': row[0], 'quantity': 1}],
        mode='subscription',
        success_url=DOMAIN + '/success',
        cancel_url=DOMAIN + '/planos',
        metadata={'user_id': current_user.id, 'plano_id': plano_id}
    )
    return redirect(session.url, code=303)

@app.route("/success")
@login_required
def success():
    flash("Pagamento confirmado com sucesso! Você já pode usar todos os recursos.")
    return redirect(url_for("index"))

@app.route("/webhook", methods=["POST"])
def webhook():
    payload = request.get_data()
    sig_header = request.headers.get('Stripe-Signature')
    event = stripe.Webhook.construct_event(payload, sig_header, endpoint_secret)
    if event['type'] == 'checkout.session.completed':
        sess = event['data']['object']
        user_id = int(sess['metadata']['user_id'])
        plano_id = int(sess['metadata']['plano_id'])
        conn = conectar_sistema()
        c = conn.cursor()
        c.execute("UPDATE Users SET status = ?, plano_id = ? WHERE id = ?", ("pagou", plano_id, user_id))
        conn.commit()
        conn.close()
    return '', 200

# Administração de usuários
@app.route("/admin/usuarios")
@login_required
def listar_usuarios():
    if current_user.email != ADMIN_EMAIL:
        abort(403)

    conn = conectar_sistema()
    c = conn.cursor()
    c.execute("""
        SELECT u.id, u.email, u.status, p.nome
        FROM Users u
        LEFT JOIN Planos p ON u.plano_id = p.id
        ORDER BY u.email
    """)
    usuarios = c.fetchall()
    conn.close()
    return render_template("usuarios.html", usuarios=usuarios)

@app.route("/admin/usuario/<int:user_id>/set-free", methods=["POST"])
@login_required
def set_free(user_id):
    free = (request.form.get('free') == 'on')
    conn = conectar_sistema()
    c = conn.cursor()
    c.execute("SELECT id FROM Planos WHERE nome = ?", ("Gratuito Ilimitado",))
    row = c.fetchone()
    if row:
        free_plan_id = row[0]
        if free:
            c.execute("UPDATE Users SET status = ?, plano_id = ? WHERE id = ?", ("gratuito", free_plan_id, user_id))
        else:
            c.execute("UPDATE Users SET status = ?, plano_id = NULL WHERE id = ?", ("nao_pago", user_id))
        conn.commit()
    conn.close()
    return redirect(url_for('listar_usuarios'))

# Inicialização
if __name__ == "__main__":
    banco()
    criar_tabela_usuarios()
    criar_tabela_planos()
    app.run(debug=True)
