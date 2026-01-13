const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const crypto = require('crypto');

const pythonRunner = {
    name: 'python_interpreter',
    description: 'Executes Python code in a temporary file and returns stdout/stderr. Use this for calculations, data processing, or running scripts.',
    inputSchema: {
        type: 'object',
        properties: {
            code: {
                type: 'string',
                description: 'The Python code to execute.'
            }
        },
        required: ['code']
    },
    handler: async ({ code }) => {
        return new Promise((resolve, reject) => {
            const tempDir = path.join(__dirname, '..', 'temp');
            if (!fs.existsSync(tempDir)) {
                fs.mkdirSync(tempDir, { recursive: true });
            }

            const fileName = `script_${crypto.randomUUID()}.py`;
            const filePath = path.join(tempDir, fileName);

            fs.writeFileSync(filePath, code);

            exec(`python "${filePath}"`, (error, stdout, stderr) => {
                // Cleanup
                try { fs.unlinkSync(filePath); } catch (e) { }

                if (error) {
                    resolve(`Error: ${error.message}\nStderr: ${stderr}`);
                } else {
                    resolve(stdout || stderr || "No output.");
                }
            });
        });
    }
};

module.exports = pythonRunner;
