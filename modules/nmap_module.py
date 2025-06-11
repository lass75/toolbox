# modules/nmap_module.py
import subprocess

def run_nmap_scan(target, scan_type="basic"):
    """Exécute un scan Nmap"""
    try:
        if scan_type == "basic":
            cmd = ["nmap", "-sS", "-O", target]
        elif scan_type == "port_scan":
            cmd = ["nmap", "-sS", "-p", "1-1000", target]
        elif scan_type == "service_scan":
            cmd = ["nmap", "-sV", "-sC", target]
        elif scan_type == "vuln_scan":
            cmd = ["nmap", "-sV", "--script=vuln", target]
        else:
            cmd = ["nmap", "-sV", "-vv", target]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return result.stdout
    except subprocess.TimeoutExpired:
        return "Erreur Nmap : Timeout (5 minutes)"
    except Exception as e:
        return f"Erreur Nmap : {e}"

def nmap_quick_scan(target):
    """Scan rapide Nmap"""
    try:
        cmd = ["nmap", "-T4", "-F", target]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return result.stdout
    except Exception as e:
        return f"Erreur scan rapide : {e}"

def nmap_ping_sweep(network):
    """Ping sweep d'un réseau"""
    try:
        cmd = ["nmap", "-sn", network]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return result.stdout
    except Exception as e:
        return f"Erreur ping sweep : {e}"