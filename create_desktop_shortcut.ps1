$WshShell = New-Object -ComObject WScript.Shell
$DesktopPath = "C:\Users\MSI-USER\Desktop"
$ShortcutPath = Join-Path $DesktopPath "Th3 Thirty3.lnk"
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = "c:\Users\MSI-USER\th3-thirty3\th3-thirty3\start.bat"
$Shortcut.WorkingDirectory = "c:\Users\MSI-USER\th3-thirty3\th3-thirty3"
$Shortcut.IconLocation = "c:\Users\MSI-USER\th3-thirty3\th3-thirty3\icon.ico"
$Shortcut.Description = "Lance Th3 Thirty3 - Secure OSINT Environment"
$Shortcut.Save()
Write-Host "Raccourci cree avec succes!" -ForegroundColor Green
Write-Host "Emplacement: $ShortcutPath" -ForegroundColor Cyan
