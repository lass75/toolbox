#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test du module Nmap
Cybersecurity Toolbox - Projet Scolaire
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from nmap_module import run_nmap_scan, nmap_quick_scan, nmap_ping_sweep

def test_nmap_basic_scan():
    """Test du scan basique Nmap"""
    print("=== Test Scan Basique ===")
    target = "scanme.nmap.org"  # Site de test officiel Nmap
    result = run_nmap_scan(target, "basic")
    print(f"Résultat scan basique sur {target}:")
    print(result[:500] + "..." if len(result) > 500 else result)
    print()

def test_nmap_port_scan():
    """Test du scan de ports"""
    print("=== Test Scan de Ports ===")
    target = "scanme.nmap.org"
    result = run_nmap_scan(target, "port_scan")
    print(f"Résultat scan de ports sur {target}:")
    print(result[:500] + "..." if len(result) > 500 else result)
    print()

def test_nmap_service_scan():
    """Test du scan de services"""
    print("=== Test Scan de Services ===")
    target = "scanme.nmap.org"
    result = run_nmap_scan(target, "service_scan")
    print(f"Résultat scan de services sur {target}:")
    print(result[:500] + "..." if len(result) > 500 else result)
    print()

def test_nmap_quick_scan():
    """Test du scan rapide"""
    print("=== Test Scan Rapide ===")
    target = "google.com"
    result = nmap_quick_scan(target)
    print(f"Résultat scan rapide sur {target}:")
    print(result[:500] + "..." if len(result) > 500 else result)
    print()

def test_nmap_ping_sweep():
    """Test du ping sweep"""
    print("=== Test Ping Sweep ===")
    network = "192.168.1.0/24"  # Adapter selon votre réseau
    result = nmap_ping_sweep(network)
    print(f"Résultat ping sweep sur {network}:")
    print(result[:500] + "..." if len(result) > 500 else result)
    print()

def test_invalid_target():
    """Test avec une cible invalide"""
    print("=== Test Cible Invalide ===")
    target = "invalid.target.xyz"
    result = run_nmap_scan(target, "basic")
    print(f"Résultat avec cible invalide {target}:")
    print(result)
    print()

if __name__ == "__main__":
    print("🔍 Tests du module Nmap")
    print("=" * 50)
    
    try:
        # Test basique
        test_nmap_basic_scan()
        
        # Test scan de ports
        test_nmap_port_scan()
        
        # Test scan rapide
        test_nmap_quick_scan()
        
        # Test avec cible invalide
        test_invalid_target()
        
        # Test ping sweep (optionnel)
        # test_nmap_ping_sweep()
        
        print("✅ Tests terminés")
        
    except KeyboardInterrupt:
        print("\n❌ Tests interrompus par l'utilisateur")
    except Exception as e:
        print(f"❌ Erreur durant les tests: {e}")