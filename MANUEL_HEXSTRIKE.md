# 🦅 MANUEL D'UTILISATION - HEXSTRIKE AI (Th3 Thirty3)

## 📌 Présentation
Vous avez activé le module **HexStrike AI**, une suite offensive complète intégrant **150+ outils de cybersécurité** pilotés par l'intelligence artificielle. Ce module est désormais intégré à votre stack Th3 Thirty3.

## 🚀 Activation & Démarrage
Pour utiliser HexStrike, il vous suffit de lancer votre raccourci bureau habituel :
**"Th3 Thirty3 - Secure Mode"**

Ceci démarrera automatiquement :
1. **Tor Proxy** (pour l'anonymat)
2. **Backend Server** (Cerveau)
3. **HexStrike Container** (Bras armé avec les outils Kali)
4. **Interface Web**

> **⚠️ NOTE IMPORTANTE :** Le premier démarrage après l'installation de ce jour sera plus long (5-10 minutes) car le système installe les nouveaux outils (Aircrack, Wireshark, etc.).

## 🛠️ Outils Activés
Nous avons mis à jour votre environnement pour inclure les outils suivants :

| Catégorie | Outils Principaux | Usage |
|-----------|-------------------|-------|
| **Réseau** | `Nmap`, `Masscan`, `Responder`, `Wireshark` | Scanning ports, interception trafic, poisoning LLMNR |
| **WiFi** | `Aircrack-ng` suite | Ecoute/Crack WiFi (nécessite interface compatible) |
| **Web** | `SQLMap`, `Nikto`, `Gobuster`, `WafW00f` | Injections SQL, scan vulnérabilités web |
| **Pass** | `Hydra`, `John`, `Hashcat` | Cracking de mots de passe (GPU supporté) |
| **AD** | `Bloodhound`, `Impacket`, `Mimikatz` | Attaque Active Directory et latéraux |
| **Exploit**| `Metasploit`, `Searchsploit` | Framework d'exploitation |

## 🤖 Comment l'utiliser ?

### Via le Chat (Interface Th3 Thirty3)
HexStrike est connecté à vos agents experts. Vous pouvez demander :
- *"Scan l'IP 192.168.1.15 avec un scan agressif"*
- *"Analyse ce site web pour des failles SQL"*
- *"Comment cracker un hash NTLM avec ma RTX 4050 ?"*

L'IA va :
1. Comprendre votre demande.
2. Sélectionner l'outil HexStrike approprié.
3. Générer la commande.
4. (Si autorisé) Exécuter la commande dans le conteneur sécurisé et vous donner le résultat.

### Via API (Avancé)
Le serveur HexStrike écoute sur `http://localhost:8888`.
Documentation API disponible sur : `http://localhost:8888/docs` (une fois lancé).

## 🛡️ Sécurité
- HexStrike tourne dans un conteneur **Docker isolé**.
- Le trafic externe peut passer par **Tor** (selon config).
- **Attention** : Vous disposez d'outils réels. Utilisez-les uniquement sur des cibles que vous êtes autorisé à tester.

---
*Th3 Thirty3 - "We see everything."*
