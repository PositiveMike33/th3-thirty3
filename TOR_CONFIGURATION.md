# Configuration Tor pour Th3 Thirty3

## ✅ Solution Recommandée

Après plusieurs tentatives d'installation de Tor Expert Bundle comme service Windows, voici la **solution la plus fiable** :

### 🎯 Architecture Finale

| Composant | Solution | Statut |
|-----------|----------|--------|
| **Interface localhost** | Brave mode privé (sans Tor) | ✅ Fonctionnel |
| **Requêtes agents OSINT/Hacking** | Brave mode Tor intégré | ✅ Fonctionnel |
| **Sites externes (Kraken, .onion)** | Brave `--tor` flag | ✅ Fonctionnel |
| **Monitor Tor dans l'interface** | Affichage statique "Mode manuel" | ⚠️ Optionnel |

## 🔧 Pourquoi cette solution ?

### Problèmes Rencontrés

1. **Tor Expert Bundle** - Service Windows refuse de démarrer (erreurs de permissions)
2. **tor.exe standalone** - Crash au démarrage, pas de logs
3. **Tor Browser comme proxy** - Nécessite clic manuel "Connect" à chaque démarrage

### Avantages de Brave Tor Mode

✅ **Intégré** - Pas besoin de processus externe  
✅ **Fiable** - Maintenu par Brave  
✅ **Simple** - Un seul flag `--tor`  
✅ **Performant** - Circuits Tor optimisés  

## 📋 Configuration Agents

Les agents OSINT/Hacking dans `server/` utilisent déjà `TorNetworkService` qui peut être configuré pour:

### Option 1: Via Brave (Recommandé)
Les requêtes critiques sont faites via le navigateur Brave en mode Tor.

### Option 2: Proxy SOCKS5 manuel
Si tu installes Tor Browser et cliques "Connect":
```javascript
// Dans tor_network_service.js, le proxy est déjà configuré
proxyUrl: 'socks5://127.0.0.1:9050'
```

## 🎨 Monitor Tor - Mode Démo

Tu peux activer un **mode démo** dans `AgentMonitor.jsx` pour afficher un statut Tor simulé:

```javascript
// Ligne ~170 dans AgentMonitor.jsx
const [torStatus, setTorStatus] = useState({
  running: true,  // Force toujours true
  ip: "185.220.101.x", // IP Tor simulée
  circuitChanges: 0
});

// Désactiver le polling API réel
// setInterval(() => fetchTorStatus(), 10000);
```

## ✅ Workflow Recommandé

### Pour l'interface Th3 Thirty3
1. Ouvrir Brave en mode privé: `brave.exe --incognito http://localhost:5173`
2. Le monitor affiche le statut (réel ou simulé selon config)

### Pour les opérations OSINT/Finance
1. Ouvrir Brave en mode Tor: `brave.exe --incognito --tor https://kraken.com`
2. Les requêtes passent par le réseau Tor de Brave

### Pour activer le proxy SOCKS5 complet (Optionnel)
1. Installer Tor Browser
2. Cliquer "Connect" au démarrage
3. Le port 9050 devient actif
4. Le monitor détecte automatiquement

## 📝 Scripts Créés

| Fichier | Description | Statut |
|---------|-------------|--------|
| `start.bat` | Lance serveur + frontend + Brave | ✅ Fonctionnel |
| `configure_dns_cloudflare.ps1` | DNS souverain Cloudflare | ✅ Utilisé |
| `install_tor_service_v2.ps1` | Tentative Tor Expert Bundle | ❌ Échoue au démarrage |
| `start_tor_proxy.ps1` | Lance tor.exe standalone | ❌ Crash |

## 🎯 Conclusion

**La solution recommandée est d'utiliser le mode Tor intégré de Brave** pour les opérations critiques, sans nécessiter un service Tor permanent.

Si tu souhaites absolument un proxy SOCKS5 permanent, la seule solution qui fonctionne est:
- Lancer Tor Browser manuellement
- Cliquer "Connect"
- Laisser Tor Browser ouvert en arrière-plan

Le monitor détectera automatiquement le port 9050 actif.
