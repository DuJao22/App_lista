from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'DuJao_api_serve'  # Replace with your secret key

def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    max_items INTEGER NOT NULL
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS lista (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    item TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )''')
    conn.commit()
    conn.close()

@app.route("/")
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('pagina_inicial'))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username == 'DUJAO22' and password == '20e10':
            session['admin'] = True
            return redirect(url_for('admin'))
        
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT id, password FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()
        if user and check_password_hash(user[1], password):
            session['user_id'] = user[0]
            return redirect(url_for('pagina_inicial'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route("/admin", methods=["GET", "POST"])
def admin():
    if 'admin' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        max_items = request.form['max_items']
        hashed_password = generate_password_hash(password, method='sha256')
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        try:
            c.execute('INSERT INTO users (username, password, max_items) VALUES (?, ?, ?)', (username, hashed_password, max_items))
            conn.commit()
            flash('User added successfully!', 'success')
        except sqlite3.IntegrityError:
            flash('Username already taken', 'danger')
        conn.close()
    return render_template('admin.html')

@app.route("/pagina_inicial")
def pagina_inicial():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if 'Lista' not in session:
        session['Lista'] = []
        carregar(session['user_id'])
    em_processo = len(session['Lista']) == 0
    return render_template("inicial.html", lista=session['Lista'], ativo=em_processo)

@app.route("/adicionar", methods=["POST"])
def adicionar():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT max_items FROM users WHERE id = ?', (session['user_id'],))
    max_items = c.fetchone()[0]
    conn.close()
    if len(session.get('Lista', [])) >= max_items:
        flash('You can only have up to {} items in your list'.format(max_items), 'danger')
        return redirect(url_for('pagina_inicial'))
    item = request.form['item']
    session['Lista'].append(item)
    salvar(session['user_id'])
    return redirect(url_for('pagina_inicial'))

@app.route("/remover", methods=["POST"])
def remover():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    output = request.form.to_dict()
    for item in output.keys():
        session['Lista'].remove(item)
    salvar(session['user_id'])
    return redirect(url_for('pagina_inicial'))

def salvar(user_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('DELETE FROM lista WHERE user_id = ?', (user_id,))
    for item in session.get('Lista', []):
        c.execute('INSERT INTO lista (user_id, item) VALUES (?, ?)', (user_id, item))
    conn.commit()
    conn.close()

def carregar(user_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT item FROM lista WHERE user_id = ?', (user_id,))
    session['Lista'] = [row[0] for row in c.fetchall()]
    conn.close()

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
