#!/usr/bin/env python3
"""
WiFi Audit Automation Script
Executes structured penetration test workflows from JSON plans
Integrates with Th3 Thirty3 Golden Ratio Learning System
"""

import json
import subprocess
import time
import sys
import os
import signal

# --- CONFIGURATION ---
JSON_FILE = 'audit_plan.json'
DRY_RUN = True  # Mettre à False pour exécuter réellement
DEFAULT_TIMEOUT = 15  # Temps en secondes pour les commandes bloquantes (airodump)

# Configuration Cible (À adapter selon votre reconnaissance)
TARGET_CONFIG = {
    "<interface>": "wlan0mon",
    "<channel>": "6",
    "<BSSID>": "00:11:22:33:44:55",
    "<output_file>": "capture_result",
    "<client_mac>": "AA:BB:CC:DD:EE:FF",
    "<wordlist>": "/usr/share/wordlists/rockyou.txt",
    "<capture_file>": "capture_result-01"
}

# Liste des outils qui ne s'arrêtent pas seuls
BLOCKING_TOOLS = ["airodump-ng", "kismet", "wireshark"]

def check_root():
    """Vérifie si le script est lancé avec sudo."""
    if not DRY_RUN and os.geteuid() != 0:
        print("[!] ERREUR : Ce script doit être lancé en root (sudo) pour manipuler les cartes Wi-Fi.")
        sys.exit(1)

def load_plan(filename):
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"[!] Erreur : Le fichier {filename} est introuvable.")
        sys.exit(1)

def format_command(raw_command, config):
    """Remplace les placeholders par les valeurs de config."""
    if not raw_command: return None
    cmd = raw_command
    for key, value in config.items():
        if key in cmd:
            cmd = cmd.replace(key, value)
    return cmd

def run_command(cmd, tool_name):
    """Exécute une commande avec gestion du timeout pour les outils bloquants."""
    print(f"[*] Exécution : {cmd}")
    
    if DRY_RUN:
        print("    [SIMULATION] Commande validée.")
        return

    try:
        # Si l'outil est bloquant, on utilise un timeout
        if tool_name in BLOCKING_TOOLS:
            print(f"    -> Outil bloquant détecté. Arrêt automatique dans {DEFAULT_TIMEOUT}s...")
            try:
                subprocess.run(cmd, shell=True, check=True, timeout=DEFAULT_TIMEOUT)
            except subprocess.TimeoutExpired:
                print("    [+] Timeout atteint, passage à l'étape suivante.")
        else:
            # Commande standard (ex: aircrack-ng, aireplay-ng)
            subprocess.run(cmd, shell=True, check=True)

    except subprocess.CalledProcessError as e:
        print(f"[X] Erreur critique lors de l'exécution : {e}")
        # On ne quitte pas forcément, car certaines attaques peuvent échouer (ex: pas de handshake)
    except KeyboardInterrupt:
        print("\n[!] Interruption utilisateur.")
        sys.exit(0)

def execute_step(step_data):
    print(f"\n{'='*60}")
    print(f"ÉTAPE {step_data['step']}: {step_data['phase']}")
    print(f"Description: {step_data['description']}")
    print(f"{'='*60}")
    
    commands_to_run = []

    # Normalisation des commandes (gestion liste vs item unique)
    if 'command' in step_data:
        commands_to_run.append((step_data.get('tool', 'unknown'), step_data['command']))
    elif 'tools' in step_data:
        for t in step_data['tools']:
            # Gestion du cas où "process" est décrit mais pas de commande (ex: hashcat dans le JSON)
            if 'command' in t:
                commands_to_run.append((t['name'], t['command']))
            else:
                print(f"[i] Info manuelle ({t['name']}) : {t.get('process', 'Pas de commande auto')}")

    for tool_name, raw_cmd in commands_to_run:
        final_cmd = format_command(raw_cmd, TARGET_CONFIG)
        
        # Vérification de sécurité : placeholders manquants
        if "<" in final_cmd:
            print(f"[!] ATTENTION : Variable manquante dans la commande -> {final_cmd}")
            print("    Vérifiez votre TARGET_CONFIG.")
            continue

        run_command(final_cmd, tool_name)
        time.sleep(1) # Pause de sécurité entre les commandes

def main():
    check_root()
    print(f"Chargement du plan d'attaque depuis {JSON_FILE}...")
    plan = load_plan(JSON_FILE)
    
    print(f"Titre : {plan.get('title', 'Audit Sans Titre')}")
    print(f"Mode : {'🛑 SIMULATION (DRY RUN)' if DRY_RUN else '⚡ LIVE ATTACK (ROOT)'}")
    
    for step in plan['workflow']:
        # Vérification conditionnelle (ex: étape 5 "If successful")
        if 'condition' in step:
            print(f"\n[?] Étape conditionnelle ({step['condition']}). Voulez-vous continuer ? (o/n)")
            if input("> ").lower() != 'o':
                continue

        execute_step(step)
        
        if not DRY_RUN:
            # Pause pour laisser l'utilisateur lire ou annuler
            input("\n[Pause] Pressez Entrée pour continuer (Ctrl+C pour quitter)...")

if __name__ == "__main__":
    main()
