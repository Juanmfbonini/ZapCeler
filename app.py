from flask import Flask, render_template, request, redirect, url_for, flash, abort, session, jsonify
from flask_bcrypt import Bcrypt
from flask_login import login_user, login_required, logout_user, current_user
from dotenv import load_dotenv
from apscheduler.schedulers.background import BackgroundScheduler
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
from security import encrypt_token, decrypt_token
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from twilio.rest import Client
import plotly_express as px
import sqlite3 as bancodedados
import requests
import pandas as pd
import os
import flask_login
import stripe

#Email teste: teste@gmail.com
#Senha teste: teste123

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("CHAVE_SECRETA_SITE")
limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])

# Configurações de login
bcrypt = Bcrypt(app)
login_manager = flask_login.LoginManager()
login_manager.init_app(app)
login_manager.login_view = "register"

# Configurações API
stripe.api_key = os.getenv("API_STRIPE")
ENDPOINT = os.getenv("ENDPOINT") 
WHATSAPP_API_TOKEN = os.getenv("WHATSAPP_API_TOKEN")
PHONE_NUMBER_ID = os.getenv("NUMERO_DE_TELEFONE_ID")
API_URL = f"https://graph.facebook.com/v18.0/{PHONE_NUMBER_ID}/messages"
DOMAIN = "https://8bc7-2804-7f0-3f5-f914-69c7-371b-fe76-fb97.ngrok-free.app"

# Configurações dos Provedores
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
TAKEBLIP_API_KEY = os.getenv("TAKEBLIP_API_KEY")

# Conexões de Banco de Dados
def conectar_clientes():
    return bancodedados.connect("Clientes.db")

def conectar_sistema():
    return bancodedados.connect("Sistema.db")

# Administração de usuários
@app.context_processor
def inject_admin_email():
    return dict(ADMIN_EMAIL="juanmfbonini@gmail.com")

def is_admin():
    return current_user.is_authenticated and current_user.email == inject_admin_email()["ADMIN_EMAIL"]

app.config['ADMIN_EMAIL'] = "juanmfbonini@gmail.com"  # Seu email de admin



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
    
def criar_tabela_envios_teste():
    conn = conectar_sistema()
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS EnviosTeste(
            usuario_id INTEGER PRIMARY KEY,
            qtd_mensagens INTEGER DEFAULT 0,
            qtd_clientes INTEGER DEFAULT 0,
            FOREIGN KEY(usuario_id) REFERENCES Users(id)
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
            status TEXT DEFAULT 'nao_pago',
            whatsapp_business_id TEXT,
            whatsapp_api_token TEXT,
            whatsapp_phone_number TEXT,  
            whatsapp_token_expiry TIMESTAMP,
            business_manager_id TEXT,
            limite_clientes INTEGER,
            data_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
            stripe_price_id TEXT,
            descricao TEXT,
            limite_clientes INTEGER
        )
    ''')
    conn.commit()
    conn.close()

def criar_tabela_logs():
    conn = conectar_sistema()
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS MensagensLog(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id INTEGER,
            destinatario TEXT,
            data_envio TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT,
            FOREIGN KEY(usuario_id) REFERENCES Users(id)
        )
    ''')
    conn.commit()
    conn.close()

def get_onboarding_progress(user_id):
    conn = conectar_sistema()
    c = conn.cursor()
    
    c.execute("""
        SELECT 
            CASE WHEN whatsapp_phone_number IS NOT NULL THEN 1 ELSE 0 END,
            CASE WHEN whatsapp_api_token IS NOT NULL THEN 1 ELSE 0 END
        FROM Users WHERE id = ?
    """, (user_id,))
    
    has_number, has_token = c.fetchone()
    conn.close()
    
    step_completed = 0
    if has_token:
        step_completed = 2
    elif has_number:
        step_completed = 1
        
    return step_completed

key = os.getenv('ENCRYPTION_KEY')
cipher_suite = Fernet(key)

def verificar_limites(usuario_id):
    # Conexão 1: Conta clientes em Clientes.db
    conn_clientes = conectar_clientes()
    c_clientes = conn_clientes.cursor()
    c_clientes.execute('''SELECT COUNT(*) FROM Clientes WHERE usuario_id = ?''', (usuario_id,))
    total_clientes = c_clientes.fetchone()[0]
    conn_clientes.close()  # Fecha a conexão

    # Conexão 2: Pega o limite em Sistema.db
    conn_sistema = conectar_sistema()
    c_sistema = conn_sistema.cursor()
    c_sistema.execute('''SELECT limite_clientes FROM Users WHERE id = ?''', (usuario_id,))
    limite = c_sistema.fetchone()[0]
    conn_sistema.close()  # Fecha a conexão

    return total_clientes < limite

def encrypt_token(token):
    return cipher_suite.encrypt(token.encode())

def decrypt_token(encrypted_token):
    return cipher_suite.decrypt(encrypted_token).decode()

def renovar_tokens():
    conn = conectar_sistema()
    c = conn.cursor()
    c.execute('''
        SELECT id, whatsapp_api_token FROM Users 
        WHERE whatsapp_token_expiry <= ?
    ''', (datetime.now() + timedelta(days=7),))
    usuarios = c.fetchall()
    
    for usuario_id, encrypted_token in usuarios:
        try:
            # 2. Descriptografa o token
            token = decrypt_token(encrypted_token)
            
            # 3. Renova o token
            response = requests.post(
                "https://graph.facebook.com/v18.0/oauth/access_token",
                params={
                    "grant_type": "fb_exchange_token",
                    "client_id": os.getenv("APP_ID"),
                    "client_secret": os.getenv("APP_SECRET"),
                    "fb_exchange_token": token
                }
            )
            
            if response.status_code == 200:
                new_token = response.json()["access_token"]
                new_expiry = datetime.now() + timedelta(days=60)
                
                # 4. Atualiza no banco (com criptografia)
                c.execute('''
                    UPDATE Users SET 
                        whatsapp_api_token = ?,
                        whatsapp_token_expiry = ?
                    WHERE id = ?
                ''', (
                    encrypt_token(new_token),
                    new_expiry,
                    usuario_id
                ))
                
                # 5. Registra no log
                c.execute('''
                    INSERT INTO Logs (usuario_id, acao, detalhes)
                    VALUES (?, ?, ?)
                ''', (
                    usuario_id,
                    'TOKEN_RENOVADO',
                    f'Token renovado automaticamente. Novo expiry: {new_expiry}'
                ))
                
        except Exception as e:
            print(f"Erro ao renovar token para usuário {usuario_id}: {str(e)}")
    conn.commit()
    conn.close()

    # Agendador (executa diariamente às 2AM)
    scheduler = BackgroundScheduler()
    scheduler.add_job(renovar_tokens, 'cron', hour=2)
    scheduler.start()

# Modelos e Login
class User(flask_login.UserMixin):
    pass

@login_manager.user_loader
def load_user(user_id):
    conn = conectar_sistema()
    c = conn.cursor()
    c.execute("SELECT id, email, senha_hash, plano_id, status, whatsapp_business_id, whatsapp_api_token FROM Users WHERE id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    if row:
        user = User()
        user.id, user.email, user.senha_hash, user.plano_id, user.status, user.whatsapp_business_id, user.whatsapp_api_token = row
        return user
    return None

# Funções de Clientes
def adicionar_clientes(nome, numero, usuario_id):
    conn = conectar_clientes()
    c = conn.cursor()
    c.execute("INSERT INTO Clientes (Nome, Numero, usuario_id) VALUES (?, ?, ?)", (nome, numero, usuario_id,))
    conn.commit()
    conn.close()

def excluir_clientes(id, usuario_id):
    conn = conectar_clientes()
    c = conn.cursor()
    c.execute("DELETE FROM Clientes WHERE id = ? AND usuario_id = ?", (id, usuario_id,))
    conn.commit()
    conn.close()

def buscar_cliente_por_id(id, usuario_id):
    conn = conectar_clientes()
    c = conn.cursor()
    c.execute("SELECT id, Nome, Numero FROM Clientes WHERE id = ? AND usuario_id = ?", (id, usuario_id,))
    cliente = c.fetchone()
    conn.close()
    return cliente

def editar_clientes(id, novo_nome, novo_numero, usuario_id):
    conn = conectar_clientes()
    c = conn.cursor()
    c.execute("UPDATE Clientes SET Nome = ?, Numero = ? WHERE id = ? AND usuario_id = ?", (novo_nome, novo_numero, id, usuario_id,))
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
        headers = {
            "Authorization": f"Bearer {WHATSAPP_API_TOKEN}",
            "Content-Type": "application/json"
        }

        payload = {
            "messaging_product": "whatsapp",
            "recipient_type": "individual",
            "to": numero,
            "type": "text", #mudar dps para q o usuario possa escolher
            "text": {"body": mensagem}
            }
        
        try:
            response = requests.post(
                f"https://graph.facebook.com/v18.0/{PHONE_NUMBER_ID}/messages",
                headers=headers,
                json=payload
            )
            response.raise_for_status()
            print(f"Mensagem enviada para {numero}: {response.json()}")  # Log de sucesso
            
        except requests.exceptions.RequestException as e:
            print(f"Erro ao enviar para {numero}: {str(e)}") 

#Função de graficos para o ADMIN
def graficos():
    conn = conectar_sistema()
    df = pd.read_sql_query("""
            SELECT
                Planos.nome AS Planos,
                COUNT(Users.id) AS Usuarios
            FROM Users
            JOIN Planos ON Users.plano_id = Planos.id
            GROUP BY Planos.nome
""", conn)
    conn.close()
    return df

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
            c.execute("INSERT INTO Users (email, senha_hash) VALUES (?, ?)", (email, hash_,))
            conn.commit()
            c.execute("SELECT id, senha_hash FROM Users WHERE email = ?", (email,))
            row = c.fetchone()
            conn.close()
            if row and bcrypt.check_password_hash(row[1], senha):
                user = User()
                user.id = row[0]
                login_user(user)
                return redirect(url_for('onboarding_whatsapp'))
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
    if current_user.status not in ["pagou", "gratuito", "testando"]:
        return redirect(url_for("planos"))

    clientes = buscar_clientes(current_user.id)
    
    if request.method == "POST":
        if current_user.status == "testando":
            conn = conectar_sistema()
            c = conn.cursor()
            c.execute("SELECT qtd_mensagens FROM EnviosTeste WHERE usuario_id = ?", (current_user.id,))
            qtd_mensagens = c.fetchone()[0]
            
            if qtd_mensagens >= 3:
                conn.close()
                flash("Você atingiu o limite de 50 mensagens no modo de teste")
                return redirect(url_for("planos"))
                
            # Atualiza contador de mensagens
            c.execute("UPDATE EnviosTeste SET qtd_mensagens = qtd_mensagens + ? WHERE usuario_id = ?", 
                     (len(request.form.getlist("clientes")), current_user.id))
            conn.commit()
            conn.close()

        ids = request.form.getlist("clientes")
        mensagem = request.form["mensagem"]
        lista = []
        if "Todos" in ids:
            lista = [c[2] for c in clientes]
        else:
            for c in clientes:
                if str(c[0]) in ids:
                    lista.append(c[2])
        
        for numero in lista:
            success, result = envio_mensagem_para_clientes()(
            destinatario=numero,
            mensagem=mensagem,
            user_id=current_user.id
    )
    
    if not success:
        flash(f"Falha ao enviar para {numero}: {result}")
    else:
        # Registra no log
        conn = conectar_sistema()
        c = conn.cursor()
        c.execute("""
            INSERT INTO MensagensLog (usuario_id, destinatario, status)
            VALUES (?, ?, ?)
        """, (current_user.id, numero, "enviado"))
        conn.commit()
        conn.close()

        flash("Mensagens enviadas via API WhatsApp!")
        return redirect(url_for('index'))
    
    # Verifica se o teste foi encerrado
    if current_user.status == "testando":
        conn = conectar_sistema()
        c = conn.cursor()
        c.execute("SELECT qtd_mensagens FROM EnviosTeste WHERE usuario_id = ?", (current_user.id,))
        qtd_mensagens = c.fetchone()[0]
        conn.close()
        
        if qtd_mensagens >= 3:
            conn = conectar_sistema()
            c = conn.cursor()
            c.execute("UPDATE Users SET status = 'nao_pago' WHERE id = ?", (current_user.id,))
            conn.commit()
            conn.close()
            flash("Limite de mensagens do teste atingido!")
            return redirect(url_for("planos"))
            
    return render_template("index.html", clientes=clientes)

@app.route("/cadastro", methods=["GET", "POST"])
@login_required
def cadastro():
    if current_user.status not in ["pagou", "gratuito", "testando"]:
        return redirect(url_for("planos"))

    if current_user.status == "testando":
        conn = conectar_sistema()
        c = conn.cursor()
        c.execute("SELECT qtd_clientes FROM EnviosTeste WHERE usuario_id = ?", (current_user.id,))
        qtd_clientes = c.fetchone()[0]
        conn.close()
        
        if qtd_clientes >= 5:
            flash("Você atingiu o limite de 5 clientes no modo de teste")
            return redirect(url_for("listar_clientes"))

    if request.method == "POST":
        nome = request.form["nome"]
        numero = request.form["numero"]
        adicionar_clientes(nome, numero, current_user.id)
        
        conn = conectar_sistema()
        c = conn.cursor()

# Verifica o total de clientes cadastrados
        c.execute("SELECT COUNT(*) FROM Clientes WHERE usuario_id = ?", (current_user.id,))
        total_clientes = c.fetchone()[0]

# Verifica o limite do plano
        c.execute("SELECT limite_clientes FROM Users WHERE id = ?", (current_user.id,))
        limite = c.fetchone()[0]
        conn.close()

# Bloqueia se excedeu o limite
        if total_clientes >= limite:
            flash("Você atingiu o limite de clientes do seu plano.")
            return redirect(url_for("listar_clientes"))            
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
    c.execute("SELECT id, nome, preco_cents, descricao FROM Planos WHERE nome != 'Plano Gratuito'")
    planos = c.fetchall()
    
    test_used = False
    if current_user.is_authenticated:
        c.execute("SELECT id FROM EnviosTeste WHERE usuario_id = ?", (current_user.id,))
        test_used = c.fetchone() is not None
    
    conn.close()
    return render_template("planos.html", planos=planos, test_used=test_used)

@app.route("/create-checkout-session/<int:plano_id>", methods=["POST"])
@login_required
def create_checkout_session(plano_id):
    if plano_id == 1:  # Plano teste
        conn = conectar_sistema()
        c = conn.cursor()
        
        try:
            # Atualiza status para 'testando' e define o plano_id
            c.execute("UPDATE Users SET status = 'testando', plano_id = ? WHERE id = ?", 
                      (plano_id, current_user.id))
            
            # Insere registro inicial na tabela EnviosTeste
            c.execute("INSERT INTO EnviosTeste (usuario_id, qtd_mensagens) VALUES (?, 0)",
                     (current_user.id,))
            
            conn.commit()
            flash("Plano teste ativado com sucesso! Você tem 50 mensagens para testar.")
            return redirect(url_for('index'))  # Redirecionamento CORRETO
            
        except Exception as e:
            conn.rollback()
            flash(f"Erro ao ativar teste: {str(e)}")
            return redirect(url_for('planos'))
        
        finally:
            conn.close()
    conn = conectar_sistema()
    c = conn.cursor()
    c.execute("SELECT stripe_price_id FROM Planos WHERE id = ?", (plano_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return "Plano inválido.", 400
    try:
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
    except Exception as e:
        print(f"Erro ao criar sessão do Stripe: {e}")
        flash("Erro ao iniciar o pagamento.")
        return redirect(url_for("planos"))

@app.route("/ativar-teste-gratis", methods=["POST"])
@login_required
def ativar_teste_gratis():
    print("Função ativar_teste_gratis chamada")
    conn = conectar_sistema()
    c = conn.cursor()

    try:
        # Verifica se já usou o teste antes
        c.execute("SELECT id FROM EnviosTeste WHERE usuario_id = ?", (current_user.id,))
        if c.fetchone():
            flash("Você já utilizou seu teste gratuito!")
            return redirect(url_for('planos'))

        # Ativa o teste no banco
        c.execute("UPDATE Users SET status = 'testando', plano_id = 1 WHERE id = ?", (current_user.id,))
        c.execute("INSERT INTO EnviosTeste (usuario_id, qtd_mensagens, qtd_clientes) VALUES (?, 0, 0)", (current_user.id,))
        conn.commit()

        # Atualiza o status na sessão atual
        c.execute("SELECT id, email, senha_hash, plano_id, status FROM Users WHERE id = ?", (current_user.id,))
        row = c.fetchone()
        if row:
            user = User()
            user.id, user.email, user.senha_hash, user.plano_id, user.status = row
            login_user(user)

        flash("Teste ativado! Você tem 50 mensagens e pode cadastrar até 5 clientes para avaliar o sistema.")
        return redirect(url_for('index'))

    except Exception as e:
        conn.rollback()
        flash(f"Erro ao ativar teste: {str(e)}")
        return redirect(url_for('planos'))

    finally:
        conn.close()  

@app.route("/success")
@login_required
def success():
    flash("Pagamento confirmado com sucesso! Você já pode usar todos os recursos.")
    return redirect(url_for("index"))

@app.route("/webhook", methods=["POST"])
def webhook():
    try:
        payload = request.get_data()
        sig_header = request.headers.get('Stripe-Signature')
        event = stripe.Webhook.construct_event(payload, sig_header, ENDPOINT)

        if event['type'] == 'checkout.session.completed':
            sess = event['data']['object']
            user_id = int(sess['metadata']['user_id'])
            plano_id = int(sess['metadata']['plano_id'])

            conn = conectar_sistema()
            c = conn.cursor()

            # NOVO: busca o limite de clientes do plano
            c.execute("SELECT limite_clientes FROM Planos WHERE id = ?", (plano_id,))
            row = c.fetchone()
            limite = row[0] if row else 100  # fallback

            # Atualiza status, plano e limite de clientes
            c.execute("""
                UPDATE Users SET 
                    status = ?, 
                    plano_id = ?, 
                    limite_clientes = ?
                WHERE id = ?
            """, ("pagou", plano_id, limite, user_id))

            conn.commit()
            conn.close()
        if event['type'] == 'checkout.session.completed':
            user_id = int(sess['metadata']['user_id'])
            twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
            twilio_client.api.accounts(user_id).update()
        return '', 200

    except Exception as e:
        print(f"Erro no webhook: {str(e)}")
        return "", 400

@app.route("/admin/usuarios")
@login_required
def listar_usuarios():
    if not is_admin():
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
    #teste1 = (request.form.get('basico') == 'on')
    #teste2 = (request.form.get('padrao') == 'on')
    #teste3 = (request.form.get('premium') == 'on')
    conn = conectar_sistema()
    c = conn.cursor()
    c.execute("SELECT id FROM Planos WHERE nome = ?", ("Plano Gratuito",))
    row_free = c.fetchone()
    #c.execute("SELECT id FROM Planos WHERE nome = ?", ("Plano Básico",))
    #row_basico = c.fetchone()
    #c.execute("SELECT id FROM Planos WHERE nome = ?", ("Plano Padrão",))
    #row_padrao = c.fetchone()
    #c.execute("SELECT id FROM Planos WHERE nome = ?", ("Plano Premium",))
    #row_premium = c.fetchone()
    if free:
        c.execute("UPDATE Users SET status = ?, plano_id = ? WHERE id = ?", ("gratuito", row_free[0], user_id,))
    #if teste1 and row_basico:
    #        c.execute("UPDATE Users SET status = ?, plano_id = ? WHERE id = ?", ("basico", row_basico[0], user_id,))
    #if teste2 and row_padrao:
    #        c.execute("UPDATE Users SET status = ?, plano_id = ? WHERE id = ?", ("padrao", row_padrao[0], user_id,))
    #if teste3 and row_premium:
    #        c.execute("UPDATE Users SET status = ?, plano_id = ? WHERE id = ?", ("premium", row_premium[0], user_id,))
    #if not (free or teste1 or teste2 or teste3):
    #        c.execute("UPDATE Users SET status = ?, plano_id = NULL WHERE id = ?", ("nao_pago", user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('listar_usuarios'))

@app.route("/admin/planos")
@login_required
def admin_planos():
    if not is_admin():
        abort(403)
    df = graficos()
    grafico = px.bar(df, x="Planos", y="Usuarios")
    grafico2 = px.pie(df, names="Planos", values="Usuarios", title="Distribuição de Usuarios nos Planos")
    grafico_html1 = grafico.to_html(full_html=False, include_plotlyjs='cdn')
    grafico_html2 = grafico2.to_html(full_html=False, include_plotlyjs='cdn')
    return render_template('plano.html', grafico_html1=grafico_html1, grafico_html2=grafico_html2)

@app.route("/onboarding-whatsapp")
@login_required
def onboarding_whatsapp():
    # Verifica o progresso do usuário
    conn = conectar_sistema()
    c = conn.cursor()
    
    # Verifica se já configurou o número
    c.execute("SELECT whatsapp_phone_number FROM Users WHERE id = ?", (current_user.id,))
    has_number = c.fetchone()[0] is not None
    
    # Verifica se já verificou o código
    c.execute("SELECT whatsapp_api_token FROM Users WHERE id = ?", (current_user.id,))
    has_token = c.fetchone()[0] is not None
    
    conn.close()
    
    # Calcula o progresso
    # Versão para 2 passos interativos + 1 automático
    step_completed = 0
    if has_number:
        step_completed = 1
    if has_token:
        step_completed = 2

    # Considera 3 passos no total (incluindo o automático)
    progress = (step_completed / 2) * 100  # Divide por 2 porque o 3º passo é automático

    steps = [
        "1. Vincular número",
        "2. Verificar código SMS",
    ]
    
    return render_template(
        "onboarding.html", 
        steps=steps,
        step_completed=step_completed,
        progress=progress
    )

@app.route("/configurar-whatsapp", methods=["GET", "POST"])
@login_required
def configurar_whatsapp():
    if get_onboarding_progress(current_user.id) >= 2:
        return redirect(url_for('index'))

    # Obter a opção selecionada (padrão é 2 - Usar Número Existente)
    opcoes_numeros = request.form.get("opcoes_numeros", "1")
    
    # Se for GET, verificar se já tem na sessão
    if request.method == "GET":
        opcoes_numeros = session.get('opcoes_numeros', "1")
    else:
        # Se for POST, salvar na sessão
        session['opcoes_numeros'] = opcoes_numeros

    # Processar o formulário apenas se for POST e opção for "Usar Número Existente" (2)
    if request.method == "POST" and opcoes_numeros == "2":
        phone_number = request.form.get("phone_number")
        
        if not phone_number or not phone_number.isdigit() or len(phone_number) < 10:
            flash("Número inválido. Digite apenas números com DDD.", "error")
            return render_template("configurar_whatsapp.html", opcoes_numeros=opcoes_numeros)
        
        session['whatsapp_number'] = phone_number
        
        try:
            headers = {
                "Authorization": f"Bearer {WHATSAPP_API_TOKEN}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "messaging_product": "whatsapp",
                "to": phone_number,
                "type": "template",
                "template": {
                    "name": "codigo_verificacao",
                    "language": {"code": "pt_BR"}
                }
            }
            
            response = requests.post(API_URL, headers=headers, json=payload)
            
            if response.status_code == 200:
                flash("Código de verificação enviado para seu WhatsApp!", "success")
                return redirect(url_for('verificar_codigo'))
            else:
                error_msg = response.json().get('error', {}).get('message', 'Erro desconhecido')
                flash(f"Falha ao enviar código: {error_msg}", "error")
                
        except Exception as e:
            flash(f"Erro na comunicação com a API: {str(e)}", "error")
    
    return render_template("configurar_whatsapp.html", opcoes_numeros=opcoes_numeros)

@limiter.limit("5 per minute")
@app.route("/verificar-codigo", methods=["GET", "POST"])
@login_required
def verificar_codigo():
    # Verifica se veio do fluxo correto
    if 'whatsapp_number' not in session:
        flash("Complete a vinculação do número primeiro", "error")
        return redirect(url_for('configurar_whatsapp'))
    
    phone_number = session['whatsapp_number']
    
    if request.method == "POST":
        code = request.form.get("verification_code", "").strip()
        
        # Validação do código
        if not code or len(code) != 6 or not code.isdigit():
            flash("Código inválido. Deve conter 6 dígitos.", "error")
            return redirect(url_for('verificar_codigo'))
        
        try:
            # Verifica o código com a API
            headers = {
                "Authorization": f"Bearer {WHATSAPP_API_TOKEN}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "phone_number": phone_number,
                "code": code
            }
            
            response = requests.post(
                f"https://graph.facebook.com/v18.0/{PHONE_NUMBER_ID}/verify_code",
                headers=headers,
                json=payload
            )
            
            if response.status_code == 200:
                # Salva os dados no banco
                conn = conectar_sistema()
                c = conn.cursor()
                
                # Atualiza o usuário com os dados verificados
                c.execute('''
                    UPDATE Users SET 
                        whatsapp_phone_number = ?,
                        whatsapp_verified = 1,
                        verification_date = ?
                    WHERE id = ?
                ''', (phone_number, datetime.now(), current_user.id))
                
                # Atualiza o limite de clientes baseado no plano
                c.execute('''
                    UPDATE Users 
                    SET limite_clientes = (
                        SELECT limite_clientes FROM Planos 
                        WHERE id = Users.plano_id
                    )
                    WHERE id = ?
                ''', (current_user.id,))
                
                conn.commit()
                conn.close()
                
                # Limpa a sessão
                session.pop('whatsapp_number', None)
                
                flash("WhatsApp vinculado com sucesso!", "success")
                return redirect(url_for('vinculacao_sucesso'))
            
            else:
                error_msg = response.json().get('error', {}).get('message', 'Código inválido')
                flash(f"Falha na verificação: {error_msg}", "error")
                
        except Exception as e:
            flash(f"Erro ao verificar código: {str(e)}", "error")
    
    return render_template("verificar_codigo.html", phone_number=phone_number)

@app.route("/vinculacao-sucesso")
@login_required
def vinculacao_sucesso():
    conn = conectar_sistema()
    c = conn.cursor()
    
    # Obtém os dados atualizados do usuário
    c.execute('''
        SELECT u.whatsapp_phone_number, p.limite_clientes, p.nome
        FROM Users u
        JOIN Planos p ON u.plano_id = p.id
        WHERE u.id = ?
    ''', (current_user.id,))
    
    whatsapp_number, limite, plano_nome = c.fetchone()
    conn.close()
    
    return render_template(
        "vinculacao_sucesso.html",
        whatsapp_number=whatsapp_number,
        limite_clientes="Ilimitado" if limite == -1 else limite,
        plano_nome=plano_nome
    )

@app.route("/reenviar-codigo", methods=["POST"])
@login_required
def reenviar_codigo():
    if 'whatsapp_number' not in session:
        return jsonify({"success": False, "error": "Número não encontrado"}), 400
    
    phone_number = session['whatsapp_number']
    
    try:
        headers = {
            "Authorization": f"Bearer {WHATSAPP_API_TOKEN}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "messaging_product": "whatsapp",
            "to": phone_number,
            "type": "template",
            "template": {
                "name": "codigo_verificacao",
                "language": {"code": "pt_BR"}
            }
        }
        
        response = requests.post(API_URL, headers=headers, json=payload)
        
        if response.status_code == 200:
            return jsonify({"success": True})
        else:
            error_msg = response.json().get('error', {}).get('message', 'Erro desconhecido')
            return jsonify({"success": False, "error": error_msg}), 400
            
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.before_request
def verificar_onboarding():
    # Ignora arquivos estáticos (css, js, img etc.)
    if request.endpoint is None or request.endpoint.startswith('static'):
        return

    # Se o usuário não estiver logado, não faz nada
    if not current_user.is_authenticated:
        return

    # Admin tem acesso total ao site, sem bloqueios
    if is_admin():
        return

    # Rotas que podem ser acessadas mesmo sem completar onboarding
    rotas_liberadas = {
        'logout',
        'onboarding_whatsapp',
        'configurar_whatsapp',
        'verificar_codigo',
        'reenviar_codigo',
        'vinculacao_sucesso',
        'success',
        'planos',
        'create_checkout_session',
        'ativar_teste_gratis',
        'webhook',
    }

    # Se o usuário não completou o onboarding, redireciona
    if get_onboarding_progress(current_user.id) < 2:
        if request.endpoint not in rotas_liberadas:
            return redirect(url_for('onboarding_whatsapp'))


# Rotas de erro personalizadas
@app.errorhandler(403)
def erro_403(e):
    return render_template("403.html"), 403

@app.errorhandler(404)
def erro_404(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def erro_500(e):
    return render_template("500.html"), 500

@app.context_processor
def inject_limits():
    total_clientes, limite_clientes = 0, 0
    if current_user.is_authenticated:
        conn = conectar_sistema()
        conn2 = conectar_clientes()
        c = conn.cursor()
        c2 = conn2.cursor()
        c2.execute("SELECT COUNT(*) FROM Clientes WHERE usuario_id = ?", (current_user.id,))
        resultado = c2.fetchone()
        total_clientes = resultado[0] if resultado else 0
        c.execute("SELECT limite_clientes FROM Planos WHERE id = ?", (current_user.id,))
        resultado = c.fetchone()
        limite_clientes = resultado[0] if resultado else 0
        conn.close()
        conn2.close()
    return dict(total_clientes=total_clientes, limite_clientes=limite_clientes)

# Verifica token WhatsApp válido antes de enviar mensagens
@app.before_request
def verificar_token_whatsapp():
    if current_user.is_authenticated and request.endpoint == 'index':
        conn = conectar_sistema()
        c = conn.cursor()
        c.execute("SELECT whatsapp_api_token, whatsapp_token_expiry FROM Users WHERE id = ?", (current_user.id,))
        row = c.fetchone()
        conn.close()
        if not row or not row[0] or not row[1] or datetime.strptime(row[1], "%Y-%m-%d %H:%M:%S.%f") < datetime.now():
            flash("Seu WhatsApp ainda não está vinculado corretamente. Conclua o onboarding.", "error")
            return redirect(url_for('onboarding_whatsapp'))

def criar_indices():
    conn = conectar_clientes()
    c = conn.cursor()
    c.execute("CREATE INDEX IF NOT EXISTS idx_clientes_usuario ON Clientes(usuario_id)")
    conn.commit()
    conn.close()

@app.cli.command("listar-indices")
def listar_indices():
    """Lista todos os índices do banco"""
    conn = conectar_clientes()
    c = conn.cursor()
    c.execute("SELECT name FROM sqlite_master WHERE type = 'index'")
    print("Índices existentes:", c.fetchall())
    conn.close()

def remover_coluna(nome_coluna):
    conn = conectar_sistema()  # Ou conectar_clientes() dependendo do banco
    c = conn.cursor()
    
    try:
        c.execute(f"ALTER TABLE Users DROP COLUMN {nome_coluna}")
        conn.commit()
        print(f"Coluna {nome_coluna} removida com sucesso!")
    except Exception as e:
        print(f"Erro ao remover coluna: {str(e)}")
        conn.rollback()
    finally:
        conn.close()

def remover_coluna_segura(nome_coluna):
    conn = conectar_sistema()
    c = conn.cursor()
    
    try:
        # 1. Criar tabela temporária sem a coluna
        c.execute("""
            CREATE TABLE IF NOT EXISTS Users_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE,
                senha_hash TEXT
                -- Liste TODAS as outras colunas exceto a que quer remover
            )
        """)
        
        # 2. Copiar dados
        c.execute("""
            INSERT INTO Users_new (id, email, senha_hash)
            SELECT id, email, senha_hash FROM Users
        """)
        
        # 3. Remover tabela antiga
        c.execute("DROP TABLE Users")
        
        # 4. Renomear nova tabela
        c.execute("ALTER TABLE Users_new RENAME TO Users")
        
        conn.commit()
        print(f"Coluna {nome_coluna} removida com sucesso!")
    except Exception as e:
        print(f"Erro ao remover coluna: {str(e)}")
        conn.rollback()
    finally:
        conn.close()

def verificar_coluna(nome_coluna):
    conn = conectar_sistema()
    c = conn.cursor()
    c.execute("PRAGMA table_info(Users)")
    colunas = [col[1] for col in c.fetchall()]
    conn.close()
    return nome_coluna in colunas

# Inicialização
if __name__ == "__main__":
    banco()
    criar_tabela_usuarios()
    criar_tabela_planos()
    criar_tabela_logs()
    criar_tabela_envios_teste()
    criar_indices()
    app.run(debug=True)
