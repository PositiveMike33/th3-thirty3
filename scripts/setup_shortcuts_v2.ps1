$WshShell = New-Object -comObject WScript.Shell
$DesktopPath = [Environment]::GetFolderPath("Desktop")
$ShortcutPath = Join-Path $DesktopPath "Th3 Thirty3.lnk"
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)
$ProjectRoot = "c:\Users\th3th\th3-thirty3"
$Shortcut.TargetPath = Join-Path $ProjectRoot "start_smart.bat"
$Shortcut.WorkingDirectory = $ProjectRoot
$Shortcut.IconLocation = Join-Path $ProjectRoot "icon.ico"
$Shortcut.Description = "Th3 Thirty3 - Smart Mode Launcher"
$Shortcut.Save()
Write-Host "Shortcut created: $ShortcutPath"
