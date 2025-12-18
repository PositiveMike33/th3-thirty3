
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

// Find pack idx files
const packDir = path.join('.git', 'objects', 'pack');
if (!fs.existsSync(packDir)) {
    console.log('No pack dir found');
    process.exit(0);
}

const idxFiles = fs.readdirSync(packDir).filter(f => f.endsWith('.idx'));
if (idxFiles.length === 0) {
    console.log('No idx files found');
    process.exit(0);
}

console.log(`Analyzing ${idxFiles.length} pack files...`);

const objects = [];

function analyzePack(index) {
    if (index >= idxFiles.length) {
        processObjects();
        return;
    }

    const idxPath = path.join(packDir, idxFiles[index]).replace(/\\/g, '/');
    const verify = spawn('git', ['verify-pack', '-v', idxPath]);

    let buffer = '';
    
    verify.stdout.on('data', (data) => {
        buffer += data.toString();
        const lines = buffer.split('\n');
        buffer = lines.pop(); 
        
        for (const line of lines) {
            // SHA1 type size size-in-pack offset
            const parts = line.trim().split(/\s+/);
            if (parts.length >= 3) {
                const size = parseInt(parts[2]);
                if (!isNaN(size) && size > 50 * 1024 * 1024) { // > 50MB
                    objects.push({ sha: parts[0], size: size });
                }
            }
        }
    });

    verify.on('close', () => {
        analyzePack(index + 1);
    });
    
    verify.on('error', (err) => {
        console.error('Error verifying pack:', err);
        analyzePack(index + 1);
    });
}

function processObjects() {
    objects.sort((a, b) => b.size - a.size);
    const top20 = objects.slice(0, 20);
    const topShas = new Set(top20.map(o => o.sha));
    
    console.log(`Found ${objects.length} objects > 50MB. Identifying paths for top 20...`);
    
    const revList = spawn('git', ['rev-list', '--objects', '--all']);
    let revBuffer = '';
    
    revList.stdout.on('data', (data) => {
        revBuffer += data.toString();
        const lines = revBuffer.split('\n');
        revBuffer = lines.pop();
        
        for (const line of lines) {
            const spaceIdx = line.indexOf(' ');
            if (spaceIdx > 0) {
                const sha = line.substring(0, spaceIdx);
                if (topShas.has(sha)) {
                    const obj = top20.find(o => o.sha === sha);
                    if (obj) obj.path = line.substring(spaceIdx + 1);
                }
            }
        }
    });
    
    revList.on('close', () => {
        console.log('\nTOP LARGE FILES IN GIT HISTORY:');
        top20.forEach(o => {
            console.log(`${(o.size / 1024 / 1024).toFixed(2)} MB - ${o.path || '???'} (${o.sha})`);
        });
        process.exit(0);
    });
}

analyzePack(0);
