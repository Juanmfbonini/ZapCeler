from flask import Flask, render_template, request, redirect
import sqlite3 as bancodedados
import pyautogui as auto
import webbrowser as wb
import pyperclip
import time

def banco():
    conn = bancodedados.connect("Clientes.db")
    conexao = conn.cursor()
    conexao.execute('''
                        CREATE TABLE IF NOT EXISTS Clientes(
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            Nome TEXT,
                            Numero TEXT
                        )
                    ''')
    conn.commit()
    conn.close()

def adicionar_clientes(nome, numero):
    conn = bancodedados.connect("Clientes.db")
    conexao = conn.cursor()
    conexao.execute("INSERT INTO Clientes (Nome, Numero) VALUES (?, ?)", (nome, numero))
    conn.commit()
    conn.close()

def excluir_clientes(id):
    conn = bancodedados.connect("Clientes.db")
    conexao = conn.cursor()
    conexao.execute("DELETE FROM Clientes WHERE id = ?", (id,))
    conn.commit()
    conn.close()

def buscar_cliente_por_id(id):
    conn = bancodedados.connect("Clientes.db")
    conexao = conn.cursor()
    conexao.execute("SELECT id, Nome, Numero FROM Clientes WHERE id = ?", (id,))
    cliente = conexao.fetchone()
    conn.commit()
    conn.close()
    return cliente

def editar_clientes(id, novo_nome, novo_numero):
    conn = bancodedados.connect("Clientes.db")
    conexao = conn.cursor()
    conexao.execute("UPDATE Clientes SET Nome = ?, Numero = ? WHERE id = ?", (novo_nome, novo_numero, id))
    conn.commit()
    conn.close()

def buscar_clientes():
    conn = bancodedados.connect("Clientes.db")
    conexao = conn.cursor()
    conexao.execute("SELECT id, Nome, Numero FROM Clientes")
    clientes = conexao.fetchall()
    conn.close()
    return clientes

def envio_mensagem_para_clientes(lista_numeros, mensagem):
    for numero in lista_numeros:
        link = f"https://wa.me/{numero}"
        wb.open(link)
        time.sleep(2)

        auto.press(["tab"] * 11)  # 11 tabs
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

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    clientes = buscar_clientes()
    if request.method == "POST":
        ids_selecionados = request.form.getlist("clientes")
        mensagem = request.form["mensagem"]
        numeros_para_enviar = []
        if "Todos" in ids_selecionados:
            numeros_para_enviar = [cliente[2] for cliente in clientes]
        else:
            for cliente in clientes:
                if str(cliente[0]) in ids_selecionados:
                    numeros_para_enviar.append(cliente[2])
        envio_mensagem_para_clientes(numeros_para_enviar, mensagem)
        return redirect("/")
    return render_template("index.html", clientes=clientes)

@app.route("/cadastro", methods=["GET", "POST"])
def cadastro():
    if request.method == "POST":
        nome = request.form["nome"]
        numero = request.form["numero"]
        adicionar_clientes(nome, numero)
    return render_template("cadC.html")

@app.route("/editar/<int:id>", methods=["GET", "POST"])
def editar(id):
    cliente = buscar_cliente_por_id(id)
    if request.method == "POST":
        nome = request.form["nome"]
        numero = request.form["numero"]
        editar_clientes(id, nome, numero)
    return render_template("editar.html", cliente=cliente)

@app.route("/excluir/<int:id>", methods=["POST"])
def excluir(id):
    excluir_clientes(id)
    return redirect("/clientes")

@app.route("/clientes", methods=["GET", "POST"])
def listar_clientes():
    search_query = request.form.get('search', '').strip() if request.method == "POST" else ''
    
    conn = bancodedados.connect("Clientes.db")
    conexao = conn.cursor()
    
    if search_query:
        # Busca por nome OU número
        conexao.execute("""
            SELECT id, Nome, Numero FROM Clientes 
            WHERE Nome LIKE ? OR Numero LIKE ?
            ORDER BY Nome
        """, (f'%{search_query}%', f'%{search_query}%'))
    else:
        # Lista todos se não houver busca
        conexao.execute("SELECT id, Nome, Numero FROM Clientes ORDER BY Nome")
    
    clientes = conexao.fetchall()
    conn.close()
    
    return render_template("clientes.html", clientes=clientes, search_query=search_query)

if __name__ == "__main__":
    banco()
    app.run(debug=True)