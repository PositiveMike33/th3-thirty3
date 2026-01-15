const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..'); // Assuming this script is in /scripts
const SERVER = path.join(ROOT, 'server');
const SERVER_TESTS = path.join(SERVER, 'tests');
const SCRIPTS_DIR = path.join(ROOT, 'scripts');

// Ensure directories exist
if (!fs.existsSync(SERVER_TESTS)) fs.mkdirSync(SERVER_TESTS, { recursive: true });
if (!fs.existsSync(SCRIPTS_DIR)) fs.mkdirSync(SCRIPTS_DIR, { recursive: true });

function moveAndRewrite(src, dest, replacements = []) {
    if (!fs.existsSync(src)) return false;

    console.log(`Processing: ${src} -> ${dest}`);
    let content = fs.readFileSync(src, 'utf8'); // Assuming text files for JS/BAT/PS1/PY

    replacements.forEach(r => {
        content = content.replace(r.from, r.to);
    });

    fs.writeFileSync(dest, content);
    fs.unlinkSync(src);
    console.log(`✅ Moved & Updated: ${path.basename(src)}`);
    return true;
}

// 1. Move Root Tests -> server/tests/
const rootTestFiles = fs.readdirSync(ROOT).filter(f =>
    (f.startsWith('test_') || f.startsWith('verify_')) && f.endsWith('.js')
);

rootTestFiles.forEach(f => {
    moveAndRewrite(path.join(ROOT, f), path.join(SERVER_TESTS, f), [
        // ./server/X -> ../X
        { from: /require\(['"]\.\/server\//g, to: "require('../" },
        // ./X -> ../X (if it refers to root files, but usually tests refer to server files)
        // Adjusting safe default: if it required './server/foo', it is now '../foo'.
        // If it required './foo' (root), and is now in server/tests, it becomes '../../foo'.
        // BUT most root tests likely import from ./server.
    ]);
});

// 2. Move Server Tests (Flat) -> server/tests/
const serverTestFiles = fs.readdirSync(SERVER).filter(f =>
    (f.startsWith('test_') || f.startsWith('verify_') || f === 'global_test.js' || f === 'train_zero_click.js') && f.endsWith('.js')
);

serverTestFiles.forEach(f => {
    moveAndRewrite(path.join(SERVER, f), path.join(SERVER_TESTS, f), [
        // ./X -> ../X
        { from: /require\(['"]\.\//g, to: "require('../" },
        { from: /require\(['"]\.\.\//g, to: "require('../../" }
    ]);
});

// 3. Move Root Scripts -> scripts/
const rootDiffFiles = fs.readdirSync(ROOT).filter(f =>
    f.endsWith('.bat') || f.endsWith('.ps1') || f.endsWith('.py') ||
    ['check_server.js', 'analyze_pack.js', 'check_creds.js'].includes(f)
);

rootDiffFiles.forEach(f => {
    if (f === 'node_modules' || f === 'server' || f === 'scripts') return;

    const replacements = [];
    if (f.endsWith('.js')) {
        replacements.push({ from: /require\(['"]\.\/server\//g, to: "require('../server/" });
        replacements.push({ from: /require\(['"]dotenv['"]\)\.config\(\)/g, to: "require('dotenv').config({ path: require('path').join(__dirname, '../.env') })" });
    }
    // For .bat/.ps1, we might need to adjust 'node server/index.js' to 'node ../server/index.js' if we run from scripts dir.
    // BUT usually bat files in root are entry points. If we move them to scripts/, the user must run them from scripts/.
    // We will assume relative paths in bat/ps1 need adjustment if they reference files.
    // e.g. "python convert_icon.py" -> "python convert_icon.py" (same dir)
    // "node server/index.js" -> "node ../server/index.js"
    if (f.endsWith('.bat') || f.endsWith('.ps1')) {
        replacements.push({ from: /server\\index\.js/g, to: "..\\server\\index.js" });
        replacements.push({ from: /server\/index\.js/g, to: "../server/index.js" });
    }

    moveAndRewrite(path.join(ROOT, f), path.join(SCRIPTS_DIR, f), replacements);
});

// 4. Update package.json
const pkgPath = path.join(ROOT, 'package.json');
if (fs.existsSync(pkgPath)) {
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
    pkg.scripts = pkg.scripts || {};

    // Add clean
    pkg.scripts.clean = "rm -rf node_modules && npm install";

    // Update existing scripts if they point to moved files
    // e.g. "test": "node test_diagnostics.js" -> "node server/tests/test_diagnostics.js"
    for (const [key, val] of Object.entries(pkg.scripts)) {
        if (val.includes('node test_')) {
            pkg.scripts[key] = val.replace('node test_', 'node server/tests/test_');
        }
        if (val.includes('node check_server.js')) {
            pkg.scripts[key] = val.replace('node check_server.js', 'node scripts/check_server.js');
        }
    }

    fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2));
    console.log('✅ Updated package.json');
}

// 5. Remove Nested th3-thirty3
const nestedDir = path.join(ROOT, 'th3-thirty3');
if (fs.existsSync(nestedDir)) {
    try {
        fs.rmSync(nestedDir, { recursive: true, force: true });
        console.log('✅ Removed nested th3-thirty3 directory');
    } catch (e) {
        console.error('⚠️ Could not remove nested directory:', e.message);
    }
}

console.log('🎉 Refactoring Complete!');
