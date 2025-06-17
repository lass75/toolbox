
# 🛠️ CyberToolbox

CyberToolbox est une toolbox automatisée pour réaliser des tests d'intrusion et des analyses forensiques.

## 🚀 Fonctions principales

- Scan réseau et ports (Nmap)
- Analyse de vulnérabilités (OpenVAS, Nessus)
- Post-exploitation (Metasploit)
- Analyse de binaires (Cuckoo, YARA, etc.)
- Génération de rapports (HTML/PDF)
- Interface web sécurisée (Flask)



## 🧰 Lancer le projet

```bash
git clone https://github.com/feres92/cybertoolbox.git
cd cybertoolbox
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

## 📦 Stack technique

- Python (Flask, Jinja2)
- Tailwind CSS
- Nmap, OpenVAS, YARA, etc.

---

### 👥 Collaboration

> Bienvenue sur le projet **CyberToolbox** – merci de contribuer au projet 💪

#### ⚙️ Pour cloner et lancer le projet :

```bash
git clone https://github.com/feres92/cybertoolbox.git
cd cybertoolbox
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

#### 🔁 Pour contribuer :

1. Avant toute modif, récupérez la dernière version :
```bash
git pull origin main
```

2. Faites vos modifs (dans les modules, l’interface ou autres)

3. Enregistrez vos changements :
```bash
git add .
git commit -m "votre message ici"
git push origin main
```

#### 📂 Organisation des fichiers :

- `app.py` → le cœur du site Flask
- `templates/` → les pages HTML
- `modules/` → les outils de scan et d’analyse
- `static/` → les fichiers CSS/JS (si besoin)
- `requirements.txt` → les dépendances
- `README.md` → ce guide
