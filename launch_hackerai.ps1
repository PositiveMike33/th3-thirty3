
Write-Host "⚠️ Docker detection failed via npx. Switching to Host Mode (Dangerous)..."
# Pas besoin de path docker ici puisque on tourne sur l'hôte
& npx -y @hackerai/local@latest --token hsb_6fcf5517544310ed4213f5e6a4eea82e64efb99abcbb2e4b7f81cc0f29a4ed82 --name "My Machine" --dangerous
