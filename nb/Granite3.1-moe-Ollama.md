# Granite 3.1 MoE (1B) - Setup & Info

**Project Status**: This project has migrated from Llama 3 / Qwen 2.5 to **Granite 3.1 MoE (1B)**.

## Why Granite 3.1 MoE?
- **Lightweight**: 1B parameters (Mixture of Experts) means it runs extremely fast on local hardware.
- **Efficient**: Low VRAM usage, perfect for running alongside other apps (like games).
- **Capable**: Despite its size, it follows instructions well for chat and roleplay.

## Setup Instructions

1.  **Install Ollama**: Ensure Ollama is installed and running.
2.  **Pull the Model**:
    ```bash
    ollama pull granite3.1-moe:1b
    ```
3.  **Verify**:
    Run `ollama list` to confirm the model is available.

## Configuration
The server is configured to use this model by default in `server/index.js`:
```javascript
const modelName = "granite3.1-moe:1b";
```

## Note on Fine-tuning
The previous `Llama3_(8B)-Ollama.ipynb` notebook was removed to avoid confusion. If you wish to fine-tune Granite, please refer to the official IBM Granite documentation or Unsloth updates.
