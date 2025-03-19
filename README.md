# 🔍 Scanner de Vulnérabilités Web

## 🛡️ Description
Ce projet est un scanner de vulnérabilités web permettant d'identifier des failles communes telles que :
- 🕷 **Cross-Site Scripting (XSS)**
- 🛑 **Injection SQL (SQLi)**
- 🔒 **Cross-Site Request Forgery (CSRF)**

Le projet comprend deux applications distinctes :
1. 🖥 **Un scanner web** qui explore un site cible et identifie ses vulnérabilités.
2. 🎭 **Un site vulnérable** pour tester le scanner.

## 🚀 Fonctionnalités
- 🔎 Crawler pour détecter les pages et endpoints d'un site web.
- 💉 Injection automatique de payloads XSS et SQLi pour tester les vulnérabilités.
- 📊 Analyse des réponses HTTP pour identifier les vulnérabilités présentes.
- 📈 Calcul d'un score CVSS pour évaluer la gravité des vulnérabilités.
- 🖥 Interface web pour visualiser les scans effectués.

## 🛠 Technologies Utilisées
- 🐍 **Flask** (Python) pour l'application web et le site vulnérable.
- 🗃 **SQLite** pour stocker les données du site vulnérable.
- 🎨 **Bootstrap** pour un design responsive de l'interface web.
- 🌍 **Requests & BeautifulSoup** pour le scraping et l'analyse des pages web.

## 📦 Installation
### 1️⃣ Cloner le référentiel
```bash
git clone https://github.com/abdelaaziz0/CRAWLER
```

### 2️⃣ Installer les dépendances
Assurez-vous d'avoir Python 3 installé, puis exécutez :
```bash
pip install -r requirements.txt
```

### 3️⃣ Lancer le site vulnérable
```bash
python site.py
```
Le site vulnérable sera accessible sur [http://localhost:5001](http://localhost:5001).

### 4️⃣ Lancer le scanner
Dans un autre terminal :
```bash
python app.py
```
L'interface du scanner sera accessible sur [http://localhost:5002](http://localhost:5002).

## 📖 Utilisation
1. 🌐 Accédez à l'interface du scanner sur [http://localhost:5002](http://localhost:5002).
2. ✍️ Entrez l'URL cible (ex: `http://localhost:5001`).
3. 🚀 Lancez un scan et consultez les rapports.

## 📂 Structure du Projet
```
scanner-vulnerabilites/
├── app.py                # Application du scanner
├── site.py               # Site web vulnérable pour les tests
├── templates/            # Templates HTML Flask
│   ├── base.html
│   ├── home.html
│   ├── scans.html
│   ├── scan_report.html
├── requirements.txt      # Fichiers des dépendances
├── README.md             # Documentation
```

## 🤝 Contributions
Les contributions sont les bienvenues ! N'hésitez pas à soumettre des pull requests.

## 📜 Licence
Ce projet est sous licence MIT. Vous êtes libre de l'utiliser et de le modifier.

## ⚠️ Avertissement
**Ce projet est destiné à un usage éducatif uniquement.** N'utilisez pas cet outil pour scanner des sites sans autorisation. Tester ce scanner sur des sites sans consentement explicite est illégal et pourrait entraîner des poursuites judiciaires.

