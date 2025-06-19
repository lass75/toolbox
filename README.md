# CyberToolbox

CyberToolbox est une application web de pentesting automatisé permettant de lancer différents outils de sécurité (Nmap, OpenVAS, Metasploit, ZAP, etc.) via une interface simple. Elle génère également un rapport PDF professionnel à partir des derniers scans.

## Fonctionnalités

- Authentification (login/register)
- Lancement de scans Nmap, OpenVAS, etc.
- Visualisation des résultats
- Génération automatique de rapports PDF professionnels
- Base de données PostgreSQL pour stocker les résultats
- Conteneurisation via Docker

## Prérequis

- Docker et Docker Compose
- Git (pour cloner le projet)
- Port 5000 disponible sur votre machine

## Installation

```bash
git clone https://github.com/lass75/toolbox.git
cd toolbox
docker-compose up --build
```

L'application sera accessible à l'adresse : http://localhost:5000

## Structure du projet

```
toolbox/
├── app.py                  # Point d'entrée principal
├── modules/                # Contient les modules (nmap, metasploit, db, etc.)
├── templates/              # Templates HTML (login, index, résultats)
├── static/                 # Fichiers statiques (PDF généré, CSS, JS)
├── docker/                 # Fichiers de configuration docker (init.sql etc.)
├── docker-compose.yml      # Configuration Docker complète
└── requirements.txt        # Dépendances Python
```

## Développement

Ajoute tes modules dans le dossier `modules/` et tes routes dans `app.py`. Pour les templates, modifie les fichiers dans `templates/`.

## Connexion à la base de données

Tu peux accéder à PostgreSQL via :

```bash
docker exec -it toolbox_db psql -U admin -d toolbox
```

## Générer un rapport

Clique sur le bouton "Générer un rapport" depuis l'interface web. Le rapport PDF sera généré dans `static/scan_report.pdf`.

## Auteurs

Projet réalisé par l’équipe CyberToolbox dans le cadre d’un projet de Master Cybersécurité.
