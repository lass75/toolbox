#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cybersecurity Toolbox - Application Flask
Projet Scolaire - Le partenaire
"""

from flask import Flask, render_template, request, jsonify, flash, redirect, url_for
import threading
import time
import os
from datetime import datetime

# Import des modules
from modules.nmap_module import run_nmap_scan, nmap_quick_scan, nmap_ping_sweep
from modules.aircrack_module import scan_wifi_networks, monitor_mode_start, monitor_mode_stop, get_wifi_interfaces
from modules.wireshark_module import capture_traffic, analyze_pcap_file, get_network_interfaces, filter_traffic
from modules.owasp_zap_module import run_zap_baseline_scan, zap_spider_scan, zap_active_scan, zap_quick_scan, simulate_zap_scan
from modules.hydra_module import run_hydra_attack, hydra_ssh_attack, hydra_ftp_attack, hydra_http_attack, get_hydra_services, generate_username_list
from modules.nikto_module import run_nikto_scan, nikto_quick_scan, nikto_full_scan, nikto_ssl_scan, nikto_cgi_scan
from modules.metasploit_module import run_metasploit_exploit, metasploit_web_exploit, metasploit_smb_exploit, metasploit_ssh_exploit, metasploit_ftp_exploit, metasploit_rdp_exploit, metasploit_port_scan
from modules.openvas_module import run_openvas_scan, openvas_discovery_scan, openvas_full_scan, openvas_web_scan, openvas_network_scan, openvas_custom_scan

app = Flask(__name__)
app.secret_key = 'cybersec_toolbox_2024'

# Stockage des résultats en mémoire
scan_results = {}
scan_status = {}

@app.route('/')
def index():
    """Page d'accueil"""
    return render_template('index.html')

@app.route('/network-security')
def network_security():
    """Interface de sélection des modules de sécurité réseau"""
    return render_template('network_security.html')

@app.route('/nmap')
def nmap_page():
    """Page dédiée Nmap Scanner"""
    return render_template('nmap.html')

@app.route('/zap')
def zap_page():
    """Page dédiée OWASP ZAP Scanner"""
    return render_template('owasp_zap.html')

@app.route('/wireshark')
def wireshark_page():
    """Page dédiée Wireshark Analyzer"""
    return render_template('wireshark.html')

@app.route('/aircrack')
def aircrack_page():
    """Page dédiée Aircrack-ng WiFi Scanner"""
    return render_template('aircrack.html')

@app.route('/hydra')
def hydra_page():
    """Page dédiée Hydra Password Attack Tool"""
    return render_template('hydra.html')

# ====== ROUTES NMAP ======
@app.route('/scan/nmap', methods=['POST'])
def nmap_scan():
    """Endpoint pour scan Nmap - Support AJAX"""
    target = request.form.get('target')
    scan_type = request.form.get('scan_type', 'basic')
    
    if not target:
        if request.headers.get('Content-Type') == 'application/x-www-form-urlencoded':
            # Requête AJAX
            return jsonify({'error': 'Veuillez spécifier une cible'}), 400
        else:
            # Requête normale
            flash('Veuillez spécifier une cible', 'error')
            return redirect(url_for('nmap_page'))
    
    scan_id = f"nmap_{int(time.time())}"
    scan_status[scan_id] = {
        'status': 'running', 
        'tool': 'Nmap', 
        'target': target,
        'scan_type': scan_type,
        'start_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    def run_scan():
        try:
            # Ajouter un délai pour simuler un scan réel
            time.sleep(2)
            result = run_nmap_scan(target, scan_type)
            scan_results[scan_id] = {
                'success': True,
                'output': result,
                'tool': 'Nmap',
                'target': target,
                'scan_type': scan_type,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            scan_status[scan_id]['status'] = 'completed'
        except Exception as e:
            scan_results[scan_id] = {
                'success': False,
                'error': str(e),
                'tool': 'Nmap',
                'target': target,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            scan_status[scan_id]['status'] = 'error'
    
    thread = threading.Thread(target=run_scan)
    thread.start()
    
    # Réponse différente selon le type de requête
    if 'XMLHttpRequest' in request.headers.get('X-Requested-With', ''):
        # Requête AJAX
        return jsonify({
            'success': True,
            'scan_id': scan_id, 
            'message': f'Scan Nmap démarré sur {target}',
            'status': 'running'
        })
    else:
        # Requête normale
        flash(f'Scan Nmap démarré sur {target}', 'success')
        return redirect(url_for('nmap_page'))

@app.route('/scan/nmap/quick', methods=['POST'])
def nmap_quick():
    """Scan Nmap rapide"""
    target = request.form.get('target')
    
    if not target:
        return jsonify({'error': 'Cible manquante'}), 400
    
    scan_id = f"nmap_quick_{int(time.time())}"
    scan_status[scan_id] = {
        'status': 'running', 
        'tool': 'Nmap Quick', 
        'target': target,
        'start_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    def run_scan():
        try:
            result = nmap_quick_scan(target)
            scan_results[scan_id] = {
                'success': True,
                'output': result,
                'tool': 'Nmap Quick',
                'target': target,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            scan_status[scan_id]['status'] = 'completed'
        except Exception as e:
            scan_results[scan_id] = {
                'success': False,
                'error': str(e),
                'tool': 'Nmap Quick',
                'target': target,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            scan_status[scan_id]['status'] = 'error'
    
    thread = threading.Thread(target=run_scan)
    thread.start()
    
    return jsonify({
        'success': True,
        'scan_id': scan_id, 
        'message': f'Scan Nmap rapide démarré sur {target}',
        'status': 'running'
    })

@app.route('/scan/nmap/progress/<scan_id>')
def nmap_progress(scan_id):
    """API pour suivre le progrès d'un scan Nmap"""
    if scan_id not in scan_status:
        return jsonify({'error': 'Scan non trouvé'}), 404
    
    status = scan_status[scan_id]
    result = scan_results.get(scan_id)
    
    response = {
        'scan_id': scan_id,
        'status': status['status'],
        'tool': status['tool'],
        'target': status.get('target'),
        'start_time': status.get('start_time')
    }
    
    if result:
        response['result'] = {
            'success': result['success'],
            'output': result.get('output', ''),
            'error': result.get('error', ''),
            'timestamp': result.get('timestamp')
        }
    
    return jsonify(response)

# ====== ROUTES HYDRA ======
@app.route('/scan/hydra', methods=['POST'])
def hydra_attack():
    """Endpoint pour attaque Hydra - Support AJAX"""
    target = request.form.get('target')
    service = request.form.get('service', 'ssh')
    username = request.form.get('username')
    attack_mode = request.form.get('attack_mode', 'default_credentials')
    port = request.form.get('port')
    
    if not target:
        if 'XMLHttpRequest' in request.headers.get('X-Requested-With', ''):
            return jsonify({'error': 'Veuillez spécifier une cible'}), 400
        else:
            flash('Veuillez spécifier une cible', 'error')
            return redirect(url_for('hydra_page'))
    
    if not username:
        if 'XMLHttpRequest' in request.headers.get('X-Requested-With', ''):
            return jsonify({'error': 'Veuillez spécifier un nom d\'utilisateur'}), 400
        else:
            flash('Veuillez spécifier un nom d\'utilisateur', 'error')
            return redirect(url_for('hydra_page'))
    
    attack_id = f"hydra_{int(time.time())}"
    scan_status[attack_id] = {
        'status': 'running', 
        'tool': 'Hydra', 
        'target': target,
        'service': service,
        'username': username,
        'attack_mode': attack_mode,
        'port': port,
        'start_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    def run_attack():
        try:
            # Ajouter un délai pour simuler une attaque réelle
            time.sleep(2)
            result = run_hydra_attack(target, service, username, attack_mode, port)
            scan_results[attack_id] = {
                'success': True,
                'output': result,
                'tool': 'Hydra',
                'target': target,
                'service': service,
                'username': username,
                'attack_mode': attack_mode,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            scan_status[attack_id]['status'] = 'completed'
        except Exception as e:
            scan_results[attack_id] = {
                'success': False,
                'error': str(e),
                'tool': 'Hydra',
                'target': target,
                'service': service,
                'username': username,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            scan_status[attack_id]['status'] = 'error'
    
    thread = threading.Thread(target=run_attack)
    thread.start()
    
    # Réponse différente selon le type de requête
    if 'XMLHttpRequest' in request.headers.get('X-Requested-With', ''):
        # Requête AJAX
        return jsonify({
            'success': True,
            'attack_id': attack_id, 
            'message': f'Attaque Hydra démarrée sur {target}:{service}',
            'status': 'running'
        })
    else:
        # Requête normale
        flash(f'Attaque Hydra démarrée sur {target}:{service}', 'success')
        return redirect(url_for('hydra_page'))

@app.route('/scan/hydra/progress/<attack_id>')
def hydra_progress(attack_id):
    """API pour suivre le progrès d'une attaque Hydra"""
    if attack_id not in scan_status:
        return jsonify({'error': 'Attaque non trouvée'}), 404
    
    status = scan_status[attack_id]
    result = scan_results.get(attack_id)
    
    response = {
        'attack_id': attack_id,
        'status': status['status'],
        'tool': status['tool'],
        'target': status.get('target'),
        'service': status.get('service'),
        'username': status.get('username'),
        'attack_mode': status.get('attack_mode'),
        'start_time': status.get('start_time')
    }
    
    if result:
        response['result'] = {
            'success': result['success'],
            'output': result.get('output', ''),
            'error': result.get('error', ''),
            'timestamp': result.get('timestamp')
        }
    
    return jsonify(response)

@app.route('/hydra/services/api')
def hydra_services_api():
    """API pour récupérer les services supportés par Hydra"""
    try:
        services = get_hydra_services()
        return jsonify({'success': True, 'services': services})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/hydra/usernames/api')
def hydra_usernames_api():
    """API pour récupérer la liste des utilisateurs communs"""
    try:
        usernames = generate_username_list()
        return jsonify({'success': True, 'usernames': usernames})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/scan/hydra/ssh', methods=['POST'])
def hydra_ssh():
    """Attaque SSH spécialisée avec Hydra"""
    target = request.form.get('target')
    username = request.form.get('username')
    
    if not target or not username:
        return jsonify({'error': 'Cible et nom d\'utilisateur requis'}), 400
    
    attack_id = f"hydra_ssh_{int(time.time())}"
    scan_status[attack_id] = {
        'status': 'running', 
        'tool': 'Hydra SSH', 
        'target': target,
        'username': username,
        'start_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    def run_ssh_attack():
        try:
            result = hydra_ssh_attack(target, username)
            scan_results[attack_id] = {
                'success': True,
                'output': result,
                'tool': 'Hydra SSH',
                'target': target,
                'username': username,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            scan_status[attack_id]['status'] = 'completed'
        except Exception as e:
            scan_results[attack_id] = {
                'success': False,
                'error': str(e),
                'tool': 'Hydra SSH',
                'target': target,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            scan_status[attack_id]['status'] = 'error'
    
    thread = threading.Thread(target=run_ssh_attack)
    thread.start()
    
    return jsonify({
        'success': True,
        'attack_id': attack_id, 
        'message': f'Attaque SSH Hydra démarrée sur {target}',
        'status': 'running'
    })

@app.route('/scan/hydra/ftp', methods=['POST'])
def hydra_ftp():
    """Attaque FTP spécialisée avec Hydra"""
    target = request.form.get('target')
    username = request.form.get('username')
    
    if not target or not username:
        return jsonify({'error': 'Cible et nom d\'utilisateur requis'}), 400
    
    attack_id = f"hydra_ftp_{int(time.time())}"
    scan_status[attack_id] = {
        'status': 'running', 
        'tool': 'Hydra FTP', 
        'target': target,
        'username': username,
        'start_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    def run_ftp_attack():
        try:
            result = hydra_ftp_attack(target, username)
            scan_results[attack_id] = {
                'success': True,
                'output': result,
                'tool': 'Hydra FTP',
                'target': target,
                'username': username,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            scan_status[attack_id]['status'] = 'completed'
        except Exception as e:
            scan_results[attack_id] = {
                'success': False,
                'error': str(e),
                'tool': 'Hydra FTP',
                'target': target,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            scan_status[attack_id]['status'] = 'error'
    
    thread = threading.Thread(target=run_ftp_attack)
    thread.start()
    
    return jsonify({
        'success': True,
        'attack_id': attack_id, 
        'message': f'Attaque FTP Hydra démarrée sur {target}',
        'status': 'running'
    })

@app.route('/scan/hydra/http', methods=['POST'])
def hydra_http():
    """Attaque HTTP Basic Auth spécialisée avec Hydra"""
    target = request.form.get('target')
    username = request.form.get('username')
    path = request.form.get('path', '/')
    
    if not target or not username:
        return jsonify({'error': 'Cible et nom d\'utilisateur requis'}), 400
    
    attack_id = f"hydra_http_{int(time.time())}"
    scan_status[attack_id] = {
        'status': 'running', 
        'tool': 'Hydra HTTP', 
        'target': target,
        'username': username,
        'path': path,
        'start_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    def run_http_attack():
        try:
            result = hydra_http_attack(target, username, path)
            scan_results[attack_id] = {
                'success': True,
                'output': result,
                'tool': 'Hydra HTTP',
                'target': target,
                'username': username,
                'path': path,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            scan_status[attack_id]['status'] = 'completed'
        except Exception as e:
            scan_results[attack_id] = {
                'success': False,
                'error': str(e),
                'tool': 'Hydra HTTP',
                'target': target,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            scan_status[attack_id]['status'] = 'error'
    
    thread = threading.Thread(target=run_http_attack)
    thread.start()
    
    return jsonify({
        'success': True,
        'attack_id': attack_id, 
        'message': f'Attaque HTTP Hydra démarrée sur {target}',
        'status': 'running'
    })

# ====== ROUTES AIRCRACK-NG ======
@app.route('/scan/wifi', methods=['POST'])
def wifi_scan():
    """Endpoint pour scan WiFi - Support AJAX"""
    interface = request.form.get('interface', 'wlan0')
    
    if not interface:
        if 'XMLHttpRequest' in request.headers.get('X-Requested-With', ''):
            return jsonify({'error': 'Veuillez spécifier une interface WiFi'}), 400
        else:
            flash('Veuillez spécifier une interface WiFi', 'error')
            return redirect(url_for('aircrack_page'))
    
    scan_id = f"wifi_{int(time.time())}"
    scan_status[scan_id] = {
        'status': 'running', 
        'tool': 'Aircrack-ng (Sécurité Wifi)', 
        'interface': interface,
        'start_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    def run_scan():
        try:
            # Délai de simulation pour un scan WiFi
            time.sleep(3)
            result = scan_wifi_networks(interface)
            scan_results[scan_id] = {
                'success': True,
                'output': result,
                'tool': 'Aircrack-ng (Sécurité Wifi)',
                'interface': interface,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            scan_status[scan_id]['status'] = 'completed'
        except Exception as e:
            scan_results[scan_id] = {
                'success': False,
                'error': str(e),
                'tool': 'Aircrack-ng (Sécurité Wifi)',
                'interface': interface,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            scan_status[scan_id]['status'] = 'error'
    
    thread = threading.Thread(target=run_scan)
    thread.start()
    
    # Réponse différente selon le type de requête
    if 'XMLHttpRequest' in request.headers.get('X-Requested-With', ''):
        # Requête AJAX
        return jsonify({
            'success': True,
            'scan_id': scan_id, 
            'message': f'Scan WiFi démarré sur {interface}',
            'status': 'running'
        })
    else:
        # Requête normale
        flash(f'Scan WiFi démarré sur {interface}', 'success')
        return redirect(url_for('aircrack_page'))

@app.route('/scan/wifi/progress/<scan_id>')
def wifi_progress(scan_id):
    """API pour suivre le progrès d'un scan WiFi"""
    if scan_id not in scan_status:
        return jsonify({'error': 'Scan non trouvé'}), 404
    
    status = scan_status[scan_id]
    result = scan_results.get(scan_id)
    
    response = {
        'scan_id': scan_id,
        'status': status['status'],
        'tool': status['tool'],
        'interface': status.get('interface'),
        'start_time': status.get('start_time')
    }
    
    if result:
        response['result'] = {
            'success': result['success'],
            'output': result.get('output', ''),
            'error': result.get('error', ''),
            'timestamp': result.get('timestamp')
        }
    
    return jsonify(response)

@app.route('/wifi/monitor/start', methods=['POST'])
def start_monitor_mode():
    """Active le mode monitor"""
    interface = request.form.get('interface', 'wlan0')
    
    try:
        result = monitor_mode_start(interface)
        return jsonify({'success': True, 'result': result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/wifi/monitor/stop', methods=['POST'])
def stop_monitor_mode():
    """Désactive le mode monitor"""
    interface = request.form.get('interface', 'wlan0mon')
    
    try:
        result = monitor_mode_stop(interface)
        return jsonify({'success': True, 'result': result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/wifi/interfaces/api')
def wifi_interfaces_api():
    """API pour récupérer les interfaces WiFi disponibles"""
    try:
        interfaces = get_wifi_interfaces()
        return jsonify({'success': True, 'interfaces': interfaces})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ====== ROUTES WIRESHARK ======
@app.route('/scan/wireshark', methods=['POST'])
def wireshark_capture():
    """Endpoint pour capture Wireshark - Support AJAX"""
    interface = request.form.get('interface', 'eth0')
    duration = int(request.form.get('duration', 30))
    filter_rule = request.form.get('filter', '')
    
    if not interface:
        if 'XMLHttpRequest' in request.headers.get('X-Requested-With', ''):
            return jsonify({'error': 'Veuillez spécifier une interface'}), 400
        else:
            flash('Veuillez spécifier une interface', 'error')
            return redirect(url_for('wireshark_page'))
    
    scan_id = f"wireshark_{int(time.time())}"
    scan_status[scan_id] = {
        'status': 'running', 
        'tool': 'Wireshark', 
        'interface': interface,
        'duration': duration,
        'filter': filter_rule,
        'start_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    def run_capture():
        try:
            time.sleep(1)  # Petit délai pour l'interface utilisateur
            if filter_rule:
                result = filter_traffic(interface, filter_rule, duration)
            else:
                result = capture_traffic(interface, duration)
            
            scan_results[scan_id] = {
                'success': True,
                'output': result,
                'tool': 'Wireshark',
                'interface': interface,
                'duration': duration,
                'filter': filter_rule,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            scan_status[scan_id]['status'] = 'completed'
        except Exception as e:
            scan_results[scan_id] = {
                'success': False,
                'error': str(e),
                'tool': 'Wireshark',
                'interface': interface,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            scan_status[scan_id]['status'] = 'error'
    
    thread = threading.Thread(target=run_capture)
    thread.start()
    
    if 'XMLHttpRequest' in request.headers.get('X-Requested-With', ''):
        return jsonify({
            'success': True,
            'scan_id': scan_id, 
            'message': f'Capture Wireshark démarrée sur {interface} ({duration}s)',
            'status': 'running'
        })
    else:
        flash(f'Capture Wireshark démarrée sur {interface} ({duration}s)', 'success')
        return redirect(url_for('wireshark_result', scan_id=scan_id))

@app.route('/scan/wireshark/progress/<scan_id>')
def wireshark_progress(scan_id):
    """API pour suivre le progrès d'une capture Wireshark"""
    if scan_id not in scan_status:
        return jsonify({'error': 'Capture non trouvée'}), 404
    
    status = scan_status[scan_id]
    result = scan_results.get(scan_id)
    
    response = {
        'scan_id': scan_id,
        'status': status['status'],
        'tool': status['tool'],
        'interface': status.get('interface'),
        'duration': status.get('duration'),
        'filter': status.get('filter'),
        'start_time': status.get('start_time')
    }
    
    if result:
        response['result'] = {
            'success': result['success'],
            'output': result.get('output', ''),
            'error': result.get('error', ''),
            'timestamp': result.get('timestamp')
        }
    
    return jsonify(response)

@app.route('/wireshark/interfaces/api')
def wireshark_interfaces_api():
    """API pour récupérer les interfaces réseau disponibles"""
    try:
        interfaces = get_network_interfaces()
        return jsonify({'success': True, 'interfaces': interfaces})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/analyze/pcap', methods=['POST'])
def analyze_pcap():
    """Analyser un fichier PCAP uploadé"""
    if 'pcap_file' not in request.files:
        return jsonify({'error': 'Aucun fichier PCAP fourni'}), 400
    
    file = request.files['pcap_file']
    if file.filename == '':
        return jsonify({'error': 'Nom de fichier vide'}), 400
    
    if file and (file.filename.endswith('.pcap') or file.filename.endswith('.pcapng')):
        # Créer le dossier temp s'il n'existe pas
        temp_dir = 'temp'
        os.makedirs(temp_dir, exist_ok=True)
        
        # Sauvegarder temporairement le fichier
        filename = f"temp_{int(time.time())}_{file.filename}"
        filepath = os.path.join(temp_dir, filename)
        
        try:
            file.save(filepath)
            
            # Analyser le fichier
            result = analyze_pcap_file(filepath)
            
            # Nettoyer le fichier temporaire
            if os.path.exists(filepath):
                os.remove(filepath)
            
            scan_id = f"pcap_analysis_{int(time.time())}"
            scan_results[scan_id] = {
                'success': True,
                'output': result,
                'tool': 'Wireshark PCAP Analysis',
                'filename': file.filename,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
            flash(f'Analyse PCAP terminée : {file.filename}', 'success')
            return redirect(url_for('wireshark_page'))
            
        except Exception as e:
            # Nettoyer le fichier en cas d'erreur
            if os.path.exists(filepath):
                os.remove(filepath)
            flash(f'Erreur lors de l\'analyse: {str(e)}', 'error')
            return redirect(url_for('wireshark_page'))
    
    flash('Format de fichier non supporté (utilisez .pcap ou .pcapng)', 'error')
    return redirect(url_for('wireshark_page'))

@app.route('/wireshark/result/<scan_id>')
def wireshark_result(scan_id):
    """Page de résultats Wireshark avec téléchargement"""
    if scan_id not in scan_status:
        flash('Capture non trouvée', 'error')
        return redirect(url_for('wireshark_page'))
    
    status = scan_status[scan_id]
    result = scan_results.get(scan_id)
    
    return render_template('wireshark_result.html', 
                         scan_id=scan_id, 
                         status=status, 
                         result=result)

@app.route('/wireshark/download/<scan_id>')
def download_wireshark_result(scan_id):
    """Télécharger le résultat de capture Wireshark en PDF"""
    if scan_id not in scan_results:
        flash('Résultat non trouvé', 'error')
        return redirect(url_for('wireshark_page'))
    
    result = scan_results[scan_id]
    
    if not result['success']:
        flash('Impossible de télécharger - capture échouée', 'error')
        return redirect(url_for('wireshark_result', scan_id=scan_id))
    
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Preformatted
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.lib import colors
        from io import BytesIO
        import tempfile
        
        # Créer un buffer en mémoire
        buffer = BytesIO()
        
        # Créer le document PDF
        doc = SimpleDocTemplate(buffer, pagesize=A4, 
                              topMargin=inch, bottomMargin=inch,
                              leftMargin=inch, rightMargin=inch)
        
        # Styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=18,
            spaceAfter=30,
            textColor=colors.darkblue
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=14,
            spaceAfter=12,
            textColor=colors.darkgreen
        )
        
        # Contenu du PDF
        story = []
        
        # Titre
        story.append(Paragraph("Rapport de Capture Wireshark", title_style))
        story.append(Spacer(1, 12))
        
        # Informations générales
        story.append(Paragraph("Informations de la Capture", heading_style))
        
        info_data = f"""
        <b>ID de capture:</b> {scan_id}<br/>
        <b>Interface:</b> {result.get('interface', 'N/A')}<br/>
        <b>Durée:</b> {result.get('duration', 'N/A')} secondes<br/>
        <b>Filtre:</b> {result.get('filter', 'Aucun')}<br/>
        <b>Timestamp:</b> {result.get('timestamp', 'N/A')}<br/>
        <b>Outil:</b> {result.get('tool', 'Wireshark')}
        """
        
        story.append(Paragraph(info_data, styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Résultats de la capture
        story.append(Paragraph("Résultats de la Capture", heading_style))
        
        # Formatter la sortie pour le PDF
        output_text = result.get('output', 'Aucun résultat')
        if len(output_text) > 10000:  # Limiter la taille pour le PDF
            output_text = output_text[:10000] + "\n... (résultats tronqués pour le PDF)"
        
        # Utiliser Preformatted pour conserver le formatage
        pre_style = ParagraphStyle(
            'CodeStyle',
            parent=styles['Code'],
            fontSize=8,
            fontName='Courier',
            leftIndent=10,
            backgroundColor=colors.lightgrey,
            borderColor=colors.grey,
            borderWidth=1,
            borderPadding=5
        )
        
        story.append(Preformatted(output_text, pre_style))
        
        # Pied de page
        story.append(Spacer(1, 30))
        footer_text = f"Rapport généré par Cybersecurity Toolbox - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        story.append(Paragraph(footer_text, styles['Normal']))
        
        # Construire le PDF
        doc.build(story)
        
        # Préparer la réponse
        buffer.seek(0)
        pdf_data = buffer.read()
        buffer.close()
        
        # Créer la réponse de téléchargement
        from flask import Response
        response = Response(
            pdf_data,
            mimetype='application/pdf',
            headers={
                'Content-Disposition': f'attachment; filename=wireshark_rapport_{scan_id}.pdf'
            }
        )
        
        return response
        
    except ImportError:
        # Si reportlab n'est pas installé, fallback vers du texte
        content = f"""Rapport de Capture Wireshark - {scan_id}
=====================================
Interface: {result.get('interface', 'N/A')}
Durée: {result.get('duration', 'N/A')} secondes
Filtre: {result.get('filter', 'Aucun')}
Timestamp: {result.get('timestamp', 'N/A')}

Résultats:
----------
{result.get('output', 'Aucun résultat')}

NOTE: Pour générer des rapports PDF, installez reportlab: pip install reportlab
"""
        
        from flask import Response
        response = Response(
            content,
            mimetype='text/plain',
            headers={
                'Content-Disposition': f'attachment; filename=wireshark_capture_{scan_id}.txt'
            }
        )
        
        return response
    
    except Exception as e:
        flash(f'Erreur lors de la génération du PDF: {str(e)}', 'error')
        return redirect(url_for('wireshark_result', scan_id=scan_id))

# ====== ROUTES OWASP ZAP ======
@app.route('/scan/zap', methods=['POST'])
def zap_scan():
    """Endpoint pour scan OWASP ZAP - Support AJAX"""
    target_url = request.form.get('target_url')
    scan_type = request.form.get('zap_scan_type', 'baseline')
    
    if not target_url:
        if 'XMLHttpRequest' in request.headers.get('X-Requested-With', ''):
            # Requête AJAX
            return jsonify({'error': 'Veuillez spécifier une URL cible'}), 400
        else:
            # Requête normale
            flash('Veuillez spécifier une URL cible', 'error')
            return redirect(url_for('zap_page'))
    
    scan_id = f"zap_{int(time.time())}"
    scan_status[scan_id] = {
        'status': 'running', 
        'tool': 'OWASP ZAP', 
        'target': target_url,
        'scan_type': scan_type,
        'start_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    def run_scan():
        try:
            # Ajouter un délai pour simuler un scan réel
            time.sleep(2)
            if scan_type == 'baseline':
                result = run_zap_baseline_scan(target_url)
            elif scan_type == 'spider':
                result = zap_spider_scan(target_url)
            elif scan_type == 'active':
                result = zap_active_scan(target_url)
            elif scan_type == 'quick':
                result = zap_quick_scan(target_url)
            else:
                result = simulate_zap_scan(target_url)
            
            scan_results[scan_id] = {
                'success': True,
                'output': result,
                'tool': 'OWASP ZAP',
                'target': target_url,
                'scan_type': scan_type,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            scan_status[scan_id]['status'] = 'completed'
        except Exception as e:
            scan_results[scan_id] = {
                'success': False,
                'error': str(e),
                'tool': 'OWASP ZAP',
                'target': target_url,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            scan_status[scan_id]['status'] = 'error'
    
    thread = threading.Thread(target=run_scan)
    thread.start()
    
    # Réponse différente selon le type de requête
    if 'XMLHttpRequest' in request.headers.get('X-Requested-With', ''):
        # Requête AJAX
        return jsonify({
            'success': True,
            'scan_id': scan_id, 
            'message': f'Scan OWASP ZAP démarré sur {target_url}',
            'status': 'running'
        })
    else:
        # Requête normale
        flash(f'Scan OWASP ZAP démarré sur {target_url}', 'success')
        return redirect(url_for('zap_page'))

@app.route('/scan/zap/progress/<scan_id>')
def zap_progress(scan_id):
    """API pour suivre le progrès d'un scan ZAP"""
    if scan_id not in scan_status:
        return jsonify({'error': 'Scan non trouvé'}), 404
    
    status = scan_status[scan_id]
    result = scan_results.get(scan_id)
    
    response = {
        'scan_id': scan_id,
        'status': status['status'],
        'tool': status['tool'],
        'target': status.get('target'),
        'start_time': status.get('start_time')
    }
    
    if result:
        response['result'] = {
            'success': result['success'],
            'output': result.get('output', ''),
            'error': result.get('error', ''),
            'timestamp': result.get('timestamp')
        }
    
    return jsonify(response)

# ====== ROUTES STATUT ET RÉSULTATS ======
@app.route('/status/<scan_id>')
def check_scan_status(scan_id):
    """API pour vérifier le statut d'un scan"""
    if scan_id in scan_status:
        return jsonify(scan_status[scan_id])
    return jsonify({'status': 'not_found'}), 404

@app.route('/scan/<scan_id>')
def view_scan_result(scan_id):
    """Page pour visualiser les résultats d'un scan spécifique"""
    if scan_id not in scan_results:
        flash('Résultat non trouvé', 'error')
        return redirect(url_for('all_results'))
    
    result = scan_results[scan_id]
    status = scan_status.get(scan_id, {})
    
    return render_template('scan_result.html', 
                         scan_id=scan_id, 
                         result=result, 
                         status=status)

@app.route('/results')
def all_results():
    """Page de tous les résultats"""
    return render_template('all_results.html', results=scan_results)

@app.route('/api/result/<scan_id>')
def get_result_api(scan_id):
    """API pour récupérer un résultat"""
    if scan_id in scan_results:
        return jsonify(scan_results[scan_id])
    return jsonify({'error': 'Résultat non trouvé'}), 404

@app.route('/api/results')
def get_all_results_api():
    """API pour récupérer tous les résultats"""
    return jsonify(scan_results)

# ====== ROUTES UTILITAIRES ======
@app.route('/clear-results', methods=['POST'])
def clear_results():
    """Nettoie tous les résultats"""
    global scan_results, scan_status
    scan_results.clear()
    scan_status.clear()
    flash('Résultats effacés', 'success')
    return redirect(url_for('all_results'))

@app.route('/health')
def health_check():
    """Vérification de santé de l'application"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'active_scans': len([s for s in scan_status.values() if s['status'] == 'running']),
        'total_results': len(scan_results),
        'available_tools': {
            'nmap': True,
            'wireshark': True,
            'owasp_zap': True,
            'aircrack_ng': True,
            'hydra': True
        }
    })

@app.route('/export/results/<format>')
def export_results(format):
    """Exporter tous les résultats dans un format donné"""
    if format not in ['json', 'csv', 'txt']:
        return jsonify({'error': 'Format non supporté'}), 400
    
    if format == 'json':
        from flask import Response
        import json
        
        export_data = {
            'export_timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'total_scans': len(scan_results),
            'results': scan_results
        }
        
        response = Response(
            json.dumps(export_data, indent=2),
            mimetype='application/json',
            headers={
                'Content-Disposition': f'attachment; filename=cybersec_results_{int(time.time())}.json'
            }
        )
        return response
    
    elif format == 'csv':
        from flask import Response
        import csv
        from io import StringIO
        
        output = StringIO()
        writer = csv.writer(output)
        
        # Headers
        writer.writerow(['Scan ID', 'Tool', 'Target/Interface', 'Success', 'Timestamp', 'Output Preview'])
        
        # Data
        for scan_id, result in scan_results.items():
            writer.writerow([
                scan_id,
                result.get('tool', 'Unknown'),
                result.get('target', result.get('interface', 'N/A')),
                'Success' if result.get('success', False) else 'Failed',
                result.get('timestamp', 'N/A'),
                result.get('output', result.get('error', ''))[:100] + '...' if len(result.get('output', result.get('error', ''))) > 100 else result.get('output', result.get('error', ''))
            ])
        
        response = Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={
                'Content-Disposition': f'attachment; filename=cybersec_results_{int(time.time())}.csv'
            }
        )
        return response
    
    elif format == 'txt':
        from flask import Response
        
        content = f"""Cybersecurity Toolbox - Export des Résultats
===============================================
Date d'export: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Nombre total de scans: {len(scan_results)}

"""
        
        for scan_id, result in scan_results.items():
            content += f"""
{'='*50}
Scan ID: {scan_id}
Outil: {result.get('tool', 'Unknown')}
Cible/Interface: {result.get('target', result.get('interface', 'N/A'))}
Statut: {'Succès' if result.get('success', False) else 'Échec'}
Timestamp: {result.get('timestamp', 'N/A')}

Résultats:
{'-'*20}
{result.get('output', result.get('error', 'Aucun résultat'))}

"""
        
        response = Response(
            content,
            mimetype='text/plain',
            headers={
                'Content-Disposition': f'attachment; filename=cybersec_results_{int(time.time())}.txt'
            }
        )
        return response

# ====== ROUTES D'ERREUR ======
@app.errorhandler(404)
def not_found_error(error):
    """Gestionnaire d'erreur 404"""
    return render_template('error.html', 
                         error_code=404, 
                         error_message="Page non trouvée"), 404

@app.errorhandler(500)
def internal_error(error):
    """Gestionnaire d'erreur 500"""
    return render_template('error.html', 
                         error_code=500, 
                         error_message="Erreur interne du serveur"), 500

# ====== FONCTIONS UTILITAIRES ======
def cleanup_old_results():
    """Nettoie les anciens résultats (plus de 24h)"""
    current_time = time.time()
    to_remove = []
    
    for scan_id in scan_results:
        # Extraire le timestamp du scan_id
        try:
            scan_timestamp = int(scan_id.split('_')[-1])
            if current_time - scan_timestamp > 86400:  # 24 heures
                to_remove.append(scan_id)
        except (ValueError, IndexError):
            continue
    
    for scan_id in to_remove:
        scan_results.pop(scan_id, None)
        scan_status.pop(scan_id, None)
    
    return len(to_remove)

@app.route('/admin/cleanup', methods=['POST'])
def admin_cleanup():
    """Route administrateur pour nettoyer les anciens résultats"""
    cleaned = cleanup_old_results()
    flash(f'{cleaned} anciens résultats supprimés', 'success')
    return redirect(url_for('all_results'))

@app.route('/nikto')
def nikto_page():
    """Page dédiée Nikto Web Scanner"""
    return render_template('nikto.html')

# ====== ROUTES NIKTO ======
@app.route('/scan/nikto', methods=['POST'])
def nikto_scan():
    """Endpoint pour scan Nikto - Support AJAX"""
    target_url = request.form.get('target_url')
    scan_type = request.form.get('nikto_scan_type', 'basic')
    
    if not target_url:
        if 'XMLHttpRequest' in request.headers.get('X-Requested-With', ''):
            # Requête AJAX
            return jsonify({'error': 'Veuillez spécifier une URL cible'}), 400
        else:
            # Requête normale
            flash('Veuillez spécifier une URL cible', 'error')
            return redirect(url_for('nikto_page'))
    
    scan_id = f"nikto_{int(time.time())}"
    scan_status[scan_id] = {
        'status': 'running', 
        'tool': 'Nikto', 
        'target': target_url,
        'scan_type': scan_type,
        'start_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    def run_scan():
        try:
            # Ajouter un délai pour simuler un scan réel
            time.sleep(2)
            if scan_type == 'basic':
                result = run_nikto_scan(target_url, "basic")
            elif scan_type == 'quick':
                result = nikto_quick_scan(target_url)
            elif scan_type == 'full':
                result = nikto_full_scan(target_url)
            elif scan_type == 'ssl':
                result = nikto_ssl_scan(target_url)
            elif scan_type == 'cgi':
                result = nikto_cgi_scan(target_url)
            else:
                result = run_nikto_scan(target_url, "basic")
            
            scan_results[scan_id] = {
                'success': True,
                'output': result,
                'tool': 'Nikto',
                'target': target_url,
                'scan_type': scan_type,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            scan_status[scan_id]['status'] = 'completed'
        except Exception as e:
            scan_results[scan_id] = {
                'success': False,
                'error': str(e),
                'tool': 'Nikto',
                'target': target_url,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            scan_status[scan_id]['status'] = 'error'
    
    thread = threading.Thread(target=run_scan)
    thread.start()
    
    # Réponse différente selon le type de requête
    if 'XMLHttpRequest' in request.headers.get('X-Requested-With', ''):
        # Requête AJAX
        return jsonify({
            'success': True,
            'scan_id': scan_id, 
            'message': f'Scan Nikto démarré sur {target_url}',
            'status': 'running'
        })
    else:
        # Requête normale
        flash(f'Scan Nikto démarré sur {target_url}', 'success')
        return redirect(url_for('nikto_page'))

@app.route('/scan/nikto/progress/<scan_id>')
def nikto_progress(scan_id):
    """API pour suivre le progrès d'un scan Nikto"""
    if scan_id not in scan_status:
        return jsonify({'error': 'Scan non trouvé'}), 404
    
    status = scan_status[scan_id]
    result = scan_results.get(scan_id)
    
    response = {
        'scan_id': scan_id,
        'status': status['status'],
        'tool': status['tool'],
        'target': status.get('target'),
        'start_time': status.get('start_time')
    }
    
    if result:
        response['result'] = {
            'success': result['success'],
            'output': result.get('output', ''),
            'error': result.get('error', ''),
            'timestamp': result.get('timestamp')
        }
    
    return jsonify(response)

@app.route('/scan/nikto/quick', methods=['POST'])
def nikto_quick():
    """Scan Nikto rapide"""
    target_url = request.form.get('target_url')
    
    if not target_url:
        return jsonify({'error': 'URL cible manquante'}), 400
    
    scan_id = f"nikto_quick_{int(time.time())}"
    scan_status[scan_id] = {
        'status': 'running', 
        'tool': 'Nikto Quick', 
        'target': target_url,
        'start_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    def run_scan():
        try:
            result = nikto_quick_scan(target_url)
            scan_results[scan_id] = {
                'success': True,
                'output': result,
                'tool': 'Nikto Quick',
                'target': target_url,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            scan_status[scan_id]['status'] = 'completed'
        except Exception as e:
            scan_results[scan_id] = {
                'success': False,
                'error': str(e),
                'tool': 'Nikto Quick',
                'target': target_url,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            scan_status[scan_id]['status'] = 'error'
    
    thread = threading.Thread(target=run_scan)
    thread.start()
    
    return jsonify({
        'success': True,
        'scan_id': scan_id, 
        'message': f'Scan Nikto rapide démarré sur {target_url}',
        'status': 'running'
    })

@app.route('/metasploit')
def metasploit_page():
    """Page dédiée Metasploit Framework"""
    return render_template('metasploit.html')

# ====== ROUTES METASPLOIT ======
@app.route('/scan/metasploit', methods=['POST'])
def metasploit_exploit():
    """Endpoint pour exploit Metasploit - Support AJAX"""
    target = request.form.get('target')
    exploit_type = request.form.get('exploit_type', 'basic')
    port = request.form.get('port')
    payload = request.form.get('payload', 'generic/shell_reverse_tcp')
    
    if not target:
        if 'XMLHttpRequest' in request.headers.get('X-Requested-With', ''):
            # Requête AJAX
            return jsonify({'error': 'Veuillez spécifier une cible'}), 400
        else:
            # Requête normale
            flash('Veuillez spécifier une cible', 'error')
            return redirect(url_for('metasploit_page'))
    
    exploit_id = f"metasploit_{int(time.time())}"
    scan_status[exploit_id] = {
        'status': 'running', 
        'tool': 'Metasploit', 
        'target': target,
        'exploit_type': exploit_type,
        'port': port,
        'payload': payload,
        'start_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    def run_exploit():
        try:
            # Ajouter un délai pour simuler un exploit réel
            time.sleep(2)
            if exploit_type == 'basic':
                result = metasploit_port_scan(target)
            elif exploit_type == 'web_app':
                result = metasploit_web_exploit(target, int(port) if port else 80)
            elif exploit_type == 'smb_vuln':
                result = metasploit_smb_exploit(target, int(port) if port else 445)
            elif exploit_type == 'ssh_exploit':
                result = metasploit_ssh_exploit(target, int(port) if port else 22)
            elif exploit_type == 'ftp_exploit':
                result = metasploit_ftp_exploit(target, int(port) if port else 21)
            elif exploit_type == 'rdp_exploit':
                result = metasploit_rdp_exploit(target, int(port) if port else 3389)
            else:
                result = run_metasploit_exploit(target, exploit_type, int(port) if port else None, payload)
            
            scan_results[exploit_id] = {
                'success': True,
                'output': result,
                'tool': 'Metasploit',
                'target': target,
                'exploit_type': exploit_type,
                'port': port,
                'payload': payload,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            scan_status[exploit_id]['status'] = 'completed'
        except Exception as e:
            scan_results[exploit_id] = {
                'success': False,
                'error': str(e),
                'tool': 'Metasploit',
                'target': target,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            scan_status[exploit_id]['status'] = 'error'
    
    thread = threading.Thread(target=run_exploit)
    thread.start()
    
    # Réponse différente selon le type de requête
    if 'XMLHttpRequest' in request.headers.get('X-Requested-With', ''):
        # Requête AJAX
        return jsonify({
            'success': True,
            'exploit_id': exploit_id, 
            'message': f'Exploit Metasploit démarré sur {target}',
            'status': 'running'
        })
    else:
        # Requête normale
        flash(f'Exploit Metasploit démarré sur {target}', 'success')
        return redirect(url_for('metasploit_page'))

@app.route('/scan/metasploit/progress/<exploit_id>')
def metasploit_progress(exploit_id):
    """API pour suivre le progrès d'un exploit Metasploit"""
    if exploit_id not in scan_status:
        return jsonify({'error': 'Exploit non trouvé'}), 404
    
    status = scan_status[exploit_id]
    result = scan_results.get(exploit_id)
    
    response = {
        'exploit_id': exploit_id,
        'status': status['status'],
        'tool': status['tool'],
        'target': status.get('target'),
        'exploit_type': status.get('exploit_type'),
        'start_time': status.get('start_time')
    }
    
    if result:
        response['result'] = {
            'success': result['success'],
            'output': result.get('output', ''),
            'error': result.get('error', ''),
            'timestamp': result.get('timestamp')
        }
    
    return jsonify(response)

@app.route('/scan/metasploit/quick', methods=['POST'])
def metasploit_quick():
    """Exploit Metasploit rapide (scanner)"""
    target = request.form.get('target')
    
    if not target:
        return jsonify({'error': 'Cible manquante'}), 400
    
    exploit_id = f"metasploit_quick_{int(time.time())}"
    scan_status[exploit_id] = {
        'status': 'running', 
        'tool': 'Metasploit Quick', 
        'target': target,
        'start_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    def run_exploit():
        try:
            result = metasploit_port_scan(target)
            scan_results[exploit_id] = {
                'success': True,
                'output': result,
                'tool': 'Metasploit Quick',
                'target': target,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            scan_status[exploit_id]['status'] = 'completed'
        except Exception as e:
            scan_results[exploit_id] = {
                'success': False,
                'error': str(e),
                'tool': 'Metasploit Quick',
                'target': target,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            scan_status[exploit_id]['status'] = 'error'
    
    thread = threading.Thread(target=run_exploit)
    thread.start()
    
    return jsonify({
        'success': True,
        'exploit_id': exploit_id, 
        'message': f'Scan Metasploit rapide démarré sur {target}',
        'status': 'running'
    })

# ====== DÉMARRAGE DE L'APPLICATION ======
if __name__ == '__main__':
    # Créer les dossiers nécessaires
    os.makedirs('temp', exist_ok=True)
    os.makedirs('logs', exist_ok=True)
    
    # Nettoyer les anciens résultats au démarrage
    cleanup_old_results()
    
    print("🔒 Cybersecurity Toolbox - Démarrage...")
    print("📡 Modules disponibles:")
    print("   • Nmap Scanner (Découverte réseau)")
    print("   • OWASP ZAP (Test applications web)")
    print("   • Wireshark (Analyse trafic réseau)")
    print("   • Aircrack-ng (Sécurité WiFi)")
    print("   • Hydra (Test robustesse mots de passe)")
    print(f"🌐 Application accessible sur: http://127.0.0.1:5000")
    print("⚠️  Utilisez uniquement sur vos propres systèmes ou avec autorisation!")
    
    app.run(debug=True, host='127.0.0.1', port=5000)



@app.route('/openvas')
def openvas_page():
    """Page dédiée OpenVAS Scanner"""
    return render_template('openvas.html')

@app.route('/scan/openvas', methods=['POST'])
def openvas_scan():
    """Endpoint pour scan OpenVAS - Support AJAX"""
    target = request.form.get('target')
    scan_type = request.form.get('openvas_scan_type', 'basic')
    port_range = request.form.get('port_range')
    
    if not target:
        if 'XMLHttpRequest' in request.headers.get('X-Requested-With', ''):
            return jsonify({'error': 'Veuillez spécifier une cible'}), 400
        else:
            flash('Veuillez spécifier une cible', 'error')
            return redirect(url_for('openvas_page'))
    
    scan_id = f"openvas_{int(time.time())}"
    scan_status[scan_id] = {
        'status': 'running', 
        'tool': 'OpenVAS', 
        'target': target,
        'scan_type': scan_type,
        'port_range': port_range,
        'start_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    def run_scan():
        try:
            time.sleep(2)  # Délai de démarrage
            
            if scan_type == 'basic':
                result = run_openvas_scan(target, "basic", port_range)
            elif scan_type == 'discovery':
                result = openvas_discovery_scan(target)
            elif scan_type == 'full':
                result = openvas_full_scan(target)
            elif scan_type == 'web':
                result = openvas_web_scan(target)
            elif scan_type == 'network':
                result = openvas_network_scan(target)
            elif scan_type == 'custom':
                result = openvas_custom_scan(target, port_range)
            else:
                result = run_openvas_scan(target, scan_type, port_range)
            
            scan_results[scan_id] = {
                'success': True,
                'output': result,
                'tool': 'OpenVAS',
                'target': target,
                'scan_type': scan_type,
                'port_range': port_range,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            scan_status[scan_id]['status'] = 'completed'
            
        except Exception as e:
            scan_results[scan_id] = {
                'success': False,
                'error': str(e),
                'tool': 'OpenVAS',
                'target': target,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            scan_status[scan_id]['status'] = 'error'
    
    thread = threading.Thread(target=run_scan)
    thread.start()
    
    if 'XMLHttpRequest' in request.headers.get('X-Requested-With', ''):
        return jsonify({
            'success': True,
            'scan_id': scan_id, 
            'message': f'Scan OpenVAS démarré sur {target}',
            'status': 'running'
        })
    else:
        flash(f'Scan OpenVAS démarré sur {target}', 'success')
        return redirect(url_for('openvas_page'))

@app.route('/scan/openvas/progress/<scan_id>')
def openvas_progress(scan_id):
    """API pour suivre le progrès d'un scan OpenVAS"""
    if scan_id not in scan_status:
        return jsonify({'error': 'Scan non trouvé'}), 404
    
    status = scan_status[scan_id]
    result = scan_results.get(scan_id)
    
    response = {
        'scan_id': scan_id,
        'status': status['status'],
        'tool': status['tool'],
        'target': status.get('target'),
        'scan_type': status.get('scan_type'),
        'start_time': status.get('start_time')
    }
    
    if result:
        response['result'] = {
            'success': result['success'],
            'output': result.get('output', ''),
            'error': result.get('error', ''),
            'timestamp': result.get('timestamp')
        }
    
    return jsonify(response)

@app.route('/scan/openvas/quick', methods=['POST'])
def openvas_quick():
    """Scan OpenVAS rapide (discovery)"""
    target = request.form.get('target')
    
    if not target:
        return jsonify({'error': 'Cible manquante'}), 400
    
    scan_id = f"openvas_quick_{int(time.time())}"
    scan_status[scan_id] = {
        'status': 'running', 
        'tool': 'OpenVAS Quick', 
        'target': target,
        'start_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    def run_scan():
        try:
            result = openvas_discovery_scan(target)
            scan_results[scan_id] = {
                'success': True,
                'output': result,
                'tool': 'OpenVAS Quick',
                'target': target,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            scan_status[scan_id]['status'] = 'completed'
        except Exception as e:
            scan_results[scan_id] = {
                'success': False,
                'error': str(e),
                'tool': 'OpenVAS Quick',
                'target': target,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            scan_status[scan_id]['status'] = 'error'
    
    thread = threading.Thread(target=run_scan)
    thread.start()
    
    return jsonify({
        'success': True,
        'scan_id': scan_id, 
        'message': f'Scan OpenVAS rapide démarré sur {target}',
        'status': 'running'
    })