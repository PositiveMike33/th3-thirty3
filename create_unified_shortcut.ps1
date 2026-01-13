$WshShell = New-Object -comObject WScript.Shell
$DesktopPath = [Environment]::GetFolderPath("Desktop")
$ShortcutPath = Join-Path $DesktopPath "Th3 Thirty3 - Secure Mode.lnk"
$TargetPath = "c:\Users\th3th\th3-thirty3\start.bat"
$WorkingDirectory = "c:\Users\th3th\th3-thirty3"
$IconPath = "c:\Users\th3th\th3-thirty3\interface\public\logo_security_clean.png"

$Shortcut = $WshShell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = $TargetPath
$Shortcut.WorkingDirectory = $WorkingDirectory
$Shortcut.IconLocation = "$IconPath"
$Shortcut.Description = "Launch Th3 Thirty3 Secure Envrionment (Tor + Docker + GPU)"
$Shortcut.Save()

Write-Host "Shortcut created successfully at: $ShortcutPath"
