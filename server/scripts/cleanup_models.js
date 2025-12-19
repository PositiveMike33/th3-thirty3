/**
 * Model Cleanup Script
 * Replaces deprecated models with available ones
 */

const fs = require('fs');
const path = require('path');

// Mapping old models to new available models
const MODEL_MAPPING = {
    'granite3.1-moe:1b': 'granite3.1-moe:1b',
    'mistral:7b-instruct': 'mistral:7b-instruct',
    'qwen2.5-coder:7b': 'qwen2.5-coder:7b',
    'granite3.1-moe:1b': 'granite3.1-moe:1b',
    "'mistral:7b-instruct'": "'mistral:7b-instruct'",
    '"mistral:7b-instruct"': '"mistral:7b-instruct"'
};

const serverDir = path.join(__dirname, '..');

function findJSFiles(dir, files = []) {
    try {
        const items = fs.readdirSync(dir);
        for (const item of items) {
            if (item === 'node_modules' || item.startsWith('.')) continue;
            
            const fullPath = path.join(dir, item);
            try {
                const stat = fs.statSync(fullPath);
                if (stat.isDirectory()) {
                    findJSFiles(fullPath, files);
                } else if (item.endsWith('.js') && !item.includes('.min.')) {
                    files.push(fullPath);
                }
            } catch (e) {
                // Skip inaccessible files
            }
        }
    } catch (e) {
        // Skip inaccessible directories
    }
    return files;
}

function cleanupModels() {
    console.log('=== MODEL CLEANUP SCRIPT ===\n');
    console.log('Available models:');
    console.log('  - qwen2.5-coder:7b (code/technical)');
    console.log('  - mistral:7b-instruct (strategy/general)');
    console.log('  - granite3.1-moe:1b (fast/fallback)');
    console.log('  - nomic-embed-text:latest (embeddings)\n');
    
    console.log('Mapping deprecated models:');
    for (const [old, newModel] of Object.entries(MODEL_MAPPING)) {
        console.log(`  ${old} -> ${newModel}`);
    }
    console.log('');
    
    const files = findJSFiles(serverDir);
    console.log(`Found ${files.length} JavaScript files to scan\n`);
    
    const changedFiles = [];
    let totalReplacements = 0;
    
    for (const file of files) {
        try {
            let content = fs.readFileSync(file, 'utf-8');
            let originalContent = content;
            let fileReplacements = 0;
            
            for (const [oldModel, newModel] of Object.entries(MODEL_MAPPING)) {
                const count = (content.match(new RegExp(oldModel.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g')) || []).length;
                if (count > 0) {
                    content = content.split(oldModel).join(newModel);
                    fileReplacements += count;
                }
            }
            
            if (content !== originalContent) {
                fs.writeFileSync(file, content);
                changedFiles.push({
                    file: path.relative(serverDir, file),
                    replacements: fileReplacements
                });
                totalReplacements += fileReplacements;
            }
        } catch (e) {
            console.error(`Error processing ${file}:`, e.message);
        }
    }
    
    console.log('=== RESULTS ===\n');
    console.log(`Files modified: ${changedFiles.length}`);
    console.log(`Total replacements: ${totalReplacements}\n`);
    
    if (changedFiles.length > 0) {
        console.log('Modified files:');
        for (const { file, replacements } of changedFiles) {
            console.log(`  - ${file} (${replacements} replacements)`);
        }
    }
    
    console.log('\n✅ Model cleanup complete!');
}

cleanupModels();
