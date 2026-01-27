$WshShell = New-Object -comObject WScript.Shell
$DesktopPath = "C:\Users\th3th\OneDrive\Desktop"
$ShortcutPath = Join-Path $DesktopPath "Th3 Thirty3 - Secure Mode.lnk"
$TargetPath = "C:\Users\th3th\th3-thirty3\scripts\start.bat"
$WorkingDirectory = "C:\Users\th3th\th3-thirty3\scripts"
$IconPath = "C:\Users\th3th\th3-thirty3\icon.ico"

$Shortcut = $WshShell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = $TargetPath
$Shortcut.WorkingDirectory = $WorkingDirectory
$Shortcut.IconLocation = "$IconPath"
$Shortcut.Description = "Launch Th3 Thirty3 Secure Environment (Tor + Docker + GPU)"
$Shortcut.Save()

Write-Host "New shortcut created at: $ShortcutPath"

$OldShortcutPath = Join-Path $DesktopPath "Th3 Thirty3 - Elite Platform.lnk"
if (Test-Path $OldShortcutPath) {
    Remove-Item $OldShortcutPath -Force
    Write-Host "Old shortcut removed: $OldShortcutPath"
}
else {
    Write-Host "Old shortcut not found."
}
