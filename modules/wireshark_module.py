# modules/wireshark.py
import subprocess
import os

def capture_traffic(interface="eth0", duration=30):
    """Capture le trafic réseau avec tshark"""
    try:
        cmd = ["tshark", "-i", interface, "-a", f"duration:{duration}", "-T", "text"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=duration+10)
        if result.returncode == 0:
            return result.stdout
        else:
            return f"Erreur Wireshark : {result.stderr}"
    except subprocess.TimeoutExpired:
        return "Erreur Wireshark : Timeout de capture"
    except FileNotFoundError:
        return "Erreur : tshark non installé ou non trouvé dans le PATH"
    except Exception as e:
        return f"Erreur Wireshark : {e}"

def analyze_pcap_file(pcap_file):
    """Analyse un fichier .pcap existant"""
    try:
        if not os.path.exists(pcap_file):
            return f"Erreur : Le fichier {pcap_file} n'existe pas"
        
        cmd = ["tshark", "-r", pcap_file, "-T", "text"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            return result.stdout
        else:
            return f"Erreur lors de l'analyse du fichier PCAP: {result.stderr}"
            
    except FileNotFoundError:
        return "Erreur : tshark non installé ou non trouvé dans le PATH"
    except Exception as e:
        return f"Erreur analyse PCAP : {e}"

def get_network_interfaces():
    """Liste les interfaces réseau disponibles"""
    try:
        cmd = ["tshark", "-D"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            return result.stdout
        else:
            return f"Erreur : {result.stderr}"
    except FileNotFoundError:
        return "Erreur : tshark non installé ou non trouvé dans le PATH"
    except Exception as e:
        return f"Erreur lors de la liste des interfaces : {e}"

def filter_traffic(interface="eth0", filter_rule="tcp", duration=30):
    """Capture avec filtre spécifique"""
    try:
        cmd = ["tshark", "-i", interface, "-f", filter_rule, "-a", f"duration:{duration}", "-T", "text"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=duration+10)
        if result.returncode == 0:
            return result.stdout
        else:
            return f"Erreur capture filtrée : {result.stderr}"
    except FileNotFoundError:
        return "Erreur : tshark non installé ou non trouvé dans le PATH"
    except Exception as e:
        return f"Erreur capture filtrée : {e}"

def get_capture_statistics(interface="eth0", duration=10):
    """Obtient des statistiques sur une interface"""
    try:
        cmd = ["tshark", "-i", interface, "-a", f"duration:{duration}", "-q", "-z", "io,stat,1"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=duration+10)
        if result.returncode == 0:
            return result.stdout
        else:
            return f"Erreur statistiques : {result.stderr}"
    except FileNotFoundError:
        return "Erreur : tshark non installé ou non trouvé dans le PATH"
    except Exception as e:
        return f"Erreur statistiques : {e}"

def analyze_protocols(pcap_file):
    """Analyse les protocoles dans un fichier PCAP"""
    try:
        cmd = ["tshark", "-r", pcap_file, "-q", "-z", "io,phs"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            return result.stdout
        else:
            return f"Erreur analyse protocoles : {result.stderr}"
    except FileNotFoundError:
        return "Erreur : tshark non installé ou non trouvé dans le PATH"
    except Exception as e:
        return f"Erreur analyse protocoles : {e}"

def get_conversations(pcap_file):
    """Extrait les conversations réseau d'un fichier PCAP"""
    try:
        cmd = ["tshark", "-r", pcap_file, "-q", "-z", "conv,ip"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            return result.stdout
        else:
            return f"Erreur conversations : {result.stderr}"
    except FileNotFoundError:
        return "Erreur : tshark non installé ou non trouvé dans le PATH"
    except Exception as e:
        return f"Erreur conversations : {e}"

def extract_http_objects(pcap_file, output_dir="/tmp/wireshark_objects"):
    """Extrait les objets HTTP d'un fichier PCAP"""
    try:
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        cmd = ["tshark", "-r", pcap_file, "--export-objects", f"http,{output_dir}"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            # Lister les fichiers extraits
            extracted_files = os.listdir(output_dir) if os.path.exists(output_dir) else []
            return f"Objets HTTP extraits dans {output_dir}:\n" + "\n".join(extracted_files)
        else:
            return f"Erreur extraction HTTP : {result.stderr}"
    except FileNotFoundError:
        return "Erreur : tshark non installé ou non trouvé dans le PATH"
    except Exception as e:
        return f"Erreur extraction HTTP : {e}"

def follow_tcp_stream(pcap_file, stream_number=0):
    """Suit un flux TCP spécifique"""
    try:
        cmd = ["tshark", "-r", pcap_file, "-q", "-z", f"follow,tcp,ascii,{stream_number}"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            return result.stdout
        else:
            return f"Erreur suivi TCP : {result.stderr}"
    except FileNotFoundError:
        return "Erreur : tshark non installé ou non trouvé dans le PATH"
    except Exception as e:
        return f"Erreur suivi TCP : {e}"

def get_expert_info(pcap_file):
    """Obtient les informations d'expert de Wireshark"""
    try:
        cmd = ["tshark", "-r", pcap_file, "-q", "-z", "expert"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            return result.stdout
        else:
            return f"Erreur expert info : {result.stderr}"
    except FileNotFoundError:
        return "Erreur : tshark non installé ou non trouvé dans le PATH"
    except Exception as e:
        return f"Erreur expert info : {e}"