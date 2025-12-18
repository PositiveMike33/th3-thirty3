$WshShell = New-Object -comObject WScript.Shell
$DesktopPath = "C:\Users\MSI-USER\OneDrive\Bureau"
$ShortcutName = "Th3 Thirty3.lnk"
$Shortcut = $WshShell.CreateShortcut("$DesktopPath\$ShortcutName")
$Shortcut.TargetPath = "c:\Users\MSI-USER\th3-thirty3\th3-thirty3\start.bat"
$Shortcut.WorkingDirectory = "c:\Users\MSI-USER\th3-thirty3\th3-thirty3"
$Shortcut.IconLocation = "c:\Users\MSI-USER\th3-thirty3\th3-thirty3\icon.ico"
$Shortcut.Description = "Lance Th3 Thirty3 - Secure OSINT/Hacking Environment"
$Shortcut.Save()
Write-Host "Raccourci cree avec succes!" -ForegroundColor Green
Write-Host "Emplacement: $DesktopPath\$ShortcutName" -ForegroundColor Cyan
