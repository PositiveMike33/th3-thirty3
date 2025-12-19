# Expert Models Installation Script for Network Defense & Reverse Engineering Training
# This script installs the recommended specialized models for each cybersecurity domain

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "   EXPERT MODELS INSTALLATION SCRIPT" -ForegroundColor Cyan
Write-Host "   For Network Defense & Reverse Engineering" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

# Check if Ollama is running
try {
    $ollamaStatus = Invoke-RestMethod -Uri "http://localhost:11434/api/tags" -Method GET -ErrorAction Stop
    Write-Host "[OK] Ollama is running" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Ollama is not running. Please start Ollama first." -ForegroundColor Red
    Write-Host "Run: ollama serve" -ForegroundColor Yellow
    exit 1
}

# Define models to install (priority order)
$models = @(
    @{
        Name = "qwen2.5-coder:7b"
        Size = "4.7GB"
        Priority = "HIGH"
        Domains = "Code Analysis, Vulnerability Detection, Secure Coding"
    },
    @{
        Name = "codellama:13b"
        Size = "7.4GB"
        Priority = "HIGH"
        Domains = "Reverse Engineering, Binary Analysis, Exploit Development"
    },
    @{
        Name = "mistral:7b-instruct"
        Size = "4.1GB"
        Priority = "HIGH"
        Domains = "Offensive Security, General Cybersec, Report Writing"
    },
    @{
        Name = "deepseek-coder:6.7b"
        Size = "3.8GB"
        Priority = "MEDIUM"
        Domains = "Code Review, Malware Analysis, Decompilation"
    },
    @{
        Name = "dolphin-mistral:7b"
        Size = "4.1GB"
        Priority = "MEDIUM"
        Domains = "Uncensored Analysis, CTF Challenges, Exploit Research"
    }
)

Write-Host ""
Write-Host "Models to install:" -ForegroundColor Yellow
Write-Host "==================" -ForegroundColor Yellow

foreach ($model in $models) {
    $priorityColor = if ($model.Priority -eq "HIGH") { "Red" } else { "Yellow" }
    Write-Host "[$($model.Priority)] $($model.Name) ($($model.Size))" -ForegroundColor $priorityColor
    Write-Host "    Domains: $($model.Domains)" -ForegroundColor Gray
}

Write-Host ""
$confirm = Read-Host "Do you want to install these models? (yes/no)"

if ($confirm -ne "yes") {
    Write-Host "Installation cancelled." -ForegroundColor Yellow
    exit 0
}

# Install each model
$installed = 0
$failed = 0

foreach ($model in $models) {
    Write-Host ""
    Write-Host "Installing $($model.Name)..." -ForegroundColor Cyan
    
    try {
        $process = Start-Process -FilePath "ollama" -ArgumentList "pull $($model.Name)" -Wait -PassThru -NoNewWindow
        
        if ($process.ExitCode -eq 0) {
            Write-Host "[OK] $($model.Name) installed successfully" -ForegroundColor Green
            $installed++
        } else {
            Write-Host "[WARN] $($model.Name) may have issues (exit code: $($process.ExitCode))" -ForegroundColor Yellow
            $failed++
        }
    } catch {
        Write-Host "[ERROR] Failed to install $($model.Name): $_" -ForegroundColor Red
        $failed++
    }
}

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "   INSTALLATION COMPLETE" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "Installed: $installed models" -ForegroundColor Green
if ($failed -gt 0) {
    Write-Host "Failed: $failed models" -ForegroundColor Red
}

# List all models
Write-Host ""
Write-Host "Current Ollama models:" -ForegroundColor Yellow
ollama list

Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "1. Restart the Th3Thirty3 server to load new knowledge base" -ForegroundColor White
Write-Host "2. Navigate to Fine-Tuning Dashboard to start training" -ForegroundColor White
Write-Host "3. Use /train <domain> to start specialized training sessions" -ForegroundColor White
