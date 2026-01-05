$env:OLLAMA_HOST = "0.0.0.0"
$env:OLLAMA_ORIGINS = "*"
Start-Process "ollama" -ArgumentList "serve" -NoNewWindow
