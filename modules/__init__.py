# modules/__init__.py
"""
Modules simples pour la Cybersecurity Toolbox
Projet scolaire - Le partenaire
"""

from . import nmap_module
from . import aircrack_module  
from . import wireshark_module
from . import owasp_zap_module

__all__ = [
    'nmap_module',
    'aircrack_module', 
    'wireshark_module',
    'owasp_zap_module'
]

__version__ = '1.0.0'