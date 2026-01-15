# Create NEXUS33 Desktop Shortcut
$WshShell = New-Object -ComObject WScript.Shell
$DesktopPath = [Environment]::GetFolderPath("Desktop")
$Shortcut = $WshShell.CreateShortcut("$DesktopPath\NEXUS33.lnk")
$Shortcut.TargetPath = "C:\Users\th3th\Th3-Thirty3\th3-thirty3\NEXUS33-docker.bat"
$Shortcut.WorkingDirectory = "C:\Users\th3th\Th3-Thirty3\th3-thirty3"
$Shortcut.IconLocation = "C:\Users\th3th\Th3-Thirty3\th3-thirty3\icon.ico"
$Shortcut.Description = "NEXUS33 - AI Cybersecurity Platform"
$Shortcut.Save()
Write-Host "Shortcut created on Desktop!" -ForegroundColor Green
