"""
Application Flask vulnérable pour tester les scanners de vulnérabilités web.
Les failles implémentées dans cet exemple sont :
  - XSS : Injection de script via un paramètre GET non échappé.
  - SQL Injection : Requête SQL construite par concaténation sans échappement.
  - CSRF : Formulaire POST sans protection CSRF.
  
Attention : Ce site est uniquement destiné à des fins de test dans un environnement contrôlé.
"""

from flask import Flask, request, render_template_string, g
from urllib.parse import urljoin, urlparse
import sqlite3
import os

app = Flask(__name__)
app.config['DEBUG'] = True

DATABASE = 'vuln_site.db'

# ---------------------------
# Base de données SQLite vulnérable
# ---------------------------
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

def init_db():
    """Initialise la base de données avec une table 'users' et quelques enregistrements."""
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                email TEXT NOT NULL
            )
        ''')
        cursor.execute("SELECT COUNT(*) FROM users")
        count = cursor.fetchone()[0]
        if count == 0:
            cursor.executemany("INSERT INTO users (username, email) VALUES (?, ?)", [
                ('alice', 'alice@example.com'),
                ('bob', 'bob@example.com'),
                ('charlie', 'charlie@example.com')
            ])
            db.commit()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# ---------------------------
# Route vulnérable à l'injection XSS
# ---------------------------
@app.route('/xss')
def xss():
    user_input = request.args.get('input', '')
    html = f"""
    <html>
      <head>
        <title>Test XSS</title>
      </head>
      <body>
        <h1>Test XSS</h1>
        <p>Vous avez saisi : {user_input}</p>
        <p>Si input contient du code JavaScript, il sera exécuté !</p>
      </body>
    </html>
    """
    return html

# ---------------------------
# Route vulnérable à la SQL Injection
# ---------------------------
@app.route('/sqli')
def sqli():
    user_id = request.args.get('id', '1')
    db = get_db()
    cursor = db.cursor()
    query = "SELECT id, username, email FROM users WHERE id = " + user_id
    try:
        cursor.execute(query)
        results = cursor.fetchall()
    except Exception as e:
        return f"<h1>Erreur SQL :</h1><p>{e}</p>"
    output = "<h1>Test SQL Injection</h1>"
    if results:
        for row in results:
            output += f"<p>ID: {row[0]}, Username: {row[1]}, Email: {row[2]}</p>"
    else:
        output += "<p>Aucun utilisateur trouvé.</p>"
    output += "<p>Essayez de manipuler le paramètre 'id' pour voir une injection SQL.</p>"
    return output

# ---------------------------
# Route vulnérable à la CSRF
# ---------------------------
@app.route('/csrf_form', methods=['GET', 'POST'])
def csrf_form():
    if request.method == 'POST':
        new_email = request.form.get('email', '')
        return f"""
        <html>
          <head><title>CSRF Test</title></head>
          <body>
            <h1>Test CSRF</h1>
            <p>L'email a été mis à jour vers : {new_email}</p>
            <a href="/csrf_form">Retour</a>
          </body>
        </html>
        """
    html = """
    <html>
      <head>
        <title>Test CSRF</title>
      </head>
      <body>
        <h1>Test CSRF</h1>
        <form method="POST" action="/csrf_form">
          <label for="email">Nouveau Email:</label>
          <input type="email" name="email" required>
          <button type="submit">Mettre à jour</button>
        </form>
      </body>
    </html>
    """
    return html

# ---------------------------
# Page d'accueil du site vulnérable
# ---------------------------
@app.route('/')
def index():
    html = """
    <html>
      <head>
        <title>Site Vulnérable</title>
      </head>
      <body>
        <h1>Bienvenue sur le site vulnérable</h1>
        <ul>
          <li><a href="/xss">Tester XSS</a></li>
          <li><a href="/sqli">Tester SQL Injection</a></li>
          <li><a href="/csrf_form">Tester CSRF</a></li>
        </ul>
      </body>
    </html>
    """
    return html

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5001)
