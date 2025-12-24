
const { exec } = require('child_process');

// Option 1: API Check
fetch('http://localhost:11434/api/tags')
  .then(res => res.json())
  .then(data => {
    console.log("=== OLLAMA MODELS (VIA API) ===");
    data.models.forEach(m => console.log(m.name));
  })
  .catch(err => {
    console.error("API Error:", err.message);
    // Option 2: CLI Fallback logic if needed, but API is preferred
  });
