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
from modules.aircrack_module import scan_wifi_networks, simulate_wifi_scan, monitor_mode_start, monitor_mode_stop
from modules.wireshark_module import capture_traffic, analyze_pcap_file, get_network_interfaces, filter_traffic
from modules.owasp_zap_module import run_zap_baseline_scan, zap_spider_scan, simulate_zap_scan

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

# ====== NOUVELLE ROUTE POUR SUIVRE LE PROGRES ======
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

# ====== ROUTES AIRCRACK ======
@app.route('/scan/wifi', methods=['POST'])
def wifi_scan():
    """Endpoint pour scan WiFi"""
    interface = request.form.get('interface', 'wlan0')
    
    scan_id = f"wifi_{int(time.time())}"
    scan_status[scan_id] = {'status': 'running', 'tool': 'WiFi Scanner', 'interface': interface}
    
    def run_scan():
        try:
            result = scan_wifi_networks(interface)
            scan_results[scan_id] = {
                'success': True,
                'output': result,
                'tool': 'WiFi Scanner',
                'interface': interface,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            scan_status[scan_id]['status'] = 'completed'
        except Exception as e:
            scan_results[scan_id] = {
                'success': False,
                'error': str(e),
                'tool': 'WiFi Scanner',
                'interface': interface,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            scan_status[scan_id]['status'] = 'error'
    
    thread = threading.Thread(target=run_scan)
    thread.start()
    
    flash(f'Scan WiFi démarré sur {interface}', 'success')
    return redirect(url_for('network_security'))

@app.route('/wifi/monitor/start', methods=['POST'])
def start_monitor_mode():
    """Active le mode monitor"""
    interface = request.form.get('interface', 'wlan0')
    result = monitor_mode_start(interface)
    return jsonify({'result': result})

@app.route('/wifi/monitor/stop', methods=['POST'])
def stop_monitor_mode():
    """Désactive le mode monitor"""
    interface = request.form.get('interface', 'wlan0mon')
    result = monitor_mode_stop(interface)
    return jsonify({'result': result})

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
    """Télécharger le résultat de capture Wireshark"""
    if scan_id not in scan_results:
        flash('Résultat non trouvé', 'error')
        return redirect(url_for('wireshark_page'))
    
    result = scan_results[scan_id]
    
    if not result['success']:
        flash('Impossible de télécharger - capture échouée', 'error')
        return redirect(url_for('wireshark_result', scan_id=scan_id))
    
    # Créer le contenu du fichier
    content = f"""Capture Wireshark - {scan_id}
=====================================
Interface: {result.get('interface', 'N/A')}
Durée: {result.get('duration', 'N/A')} secondes
Filtre: {result.get('filter', 'Aucun')}
Timestamp: {result.get('timestamp', 'N/A')}

Résultats:
----------
{result.get('output', 'Aucun résultat')}
"""
    
    # Créer la réponse de téléchargement
    from flask import Response
    response = Response(
        content,
        mimetype='text/plain',
        headers={
            'Content-Disposition': f'attachment; filename=wireshark_capture_{scan_id}.txt'
        }
    )
    
    return response

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

# ====== NOUVELLE ROUTE POUR SUIVRE LE PROGRES ZAP ======
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
        'total_results': len(scan_results)
    })

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)