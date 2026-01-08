$ConfigContent = @"
[wsl2]
memory=10GB
swap=12GB
processors=auto
localhostForwarding=true

[experimental]
autoMemoryReclaim=gradual
"@

$ConfigPath = "$env:UserProfile\.wslconfig"
Set-Content -Path $ConfigPath -Value $ConfigContent
Write-Host "WSL2 configuration optimized at $ConfigPath"
Write-Host "NOTE: You must restart WSL (wsl --shutdown) for changes to take effect."
