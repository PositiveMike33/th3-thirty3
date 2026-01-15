const fs = require('fs');
const path = require('path');
const net = require('net');
const http = require('http');

// Configuration des Ports (Ajustez si votre .env est différent)
const PORTS = {
    SERVER: 3000, // Adjusted to match .env
    FRONTEND: 5174 // Port par défaut de Vite (ou 5174 sioccupé)
};

// Couleurs pour la console
const colors = {
    reset: "\x1b[0m",
    green: "\x1b[32m",
    red: "\x1b[31m",
    yellow: "\x1b[33m",
    cyan: "\x1b[36m"
};

const log = (msg, color = colors.reset) => console.log(`${color}${msg}${colors.reset}`);

console.log(`\n${colors.cyan}=== DIAGNOSTIC SYSTÈME TH3-THIRTY3 ===${colors.reset}\n`);

// 1. Vérification Structurelle (Fichiers critiques)
function checkFiles() {
    log(`[1/3] Vérification de l'intégrité des fichiers...`, colors.yellow);

    const criticalFiles = [
        'package.json',
        'server/index.js',
        'interface/vite.config.js',
        'interface/package.json',
        'scripts/start.bat' // On vérifie que le déplacement a bien eu lieu
    ];

    let allGood = true;
    criticalFiles.forEach(file => {
        if (fs.existsSync(path.resolve(__dirname, '..', file))) {
            log(`  ✔ Found: ${file}`, colors.green);
        } else {
            log(`  ✘ MISSING: ${file}`, colors.red);
            allGood = false;
        }
    });

    if (!allGood) log(`  ⚠️ Attention: Certains fichiers critiques sont manquants.\n`, colors.red);
    else log(`  Structure fichiers: OK.\n`, colors.green);
}

// 2. Vérification des Ports (Le serveur tourne-t-il ?)
function checkPort(port, name) {
    return new Promise((resolve) => {
        const socket = new net.Socket();
        socket.setTimeout(2000);

        socket.on('connect', () => {
            log(`  ✔ ${name} est EN LIGNE (Port ${port})`, colors.green);
            socket.destroy();
            resolve(true);
        });

        socket.on('timeout', () => {
            log(`  ✘ ${name} ne répond pas (Timeout sur Port ${port})`, colors.red);
            socket.destroy();
            resolve(false);
        });

        socket.on('error', (err) => {
            log(`  ✘ ${name} est HORS LIGNE (Port ${port} fermé)`, colors.red);
            resolve(false);
        });

        socket.connect(port, 'localhost');
    });
}

// 3. Exécution
async function runDiagnostics() {
    checkFiles();

    log(`[2/3] Vérification des Services en cours d'exécution...`, colors.yellow);
    log(`(Assurez-vous d'avoir lancé 'npm start' et le frontend dans d'autres terminaux)`, colors.reset);

    const serverUp = await checkPort(PORTS.SERVER, "Serveur Backend");
    const frontUp = await checkPort(PORTS.FRONTEND, "Interface Vite");

    log(`\n[3/3] Résultat Global`, colors.yellow);
    if (serverUp && frontUp) {
        log(`🚀 SYSTÈME OPÉRATIONNEL. Prêt pour le développement.`, colors.green);
    } else {
        log(`⚠️ SYSTÈME PARTIELLEMENT HORS LIGNE.`, colors.red);
        if (!serverUp) log(`   -> Lancez le serveur : 'npm start'`, colors.reset);
        if (!frontUp) log(`   -> Lancez le frontend : cd interface && npm run dev`, colors.reset);
    }
    process.exit(0);
}

runDiagnostics();
