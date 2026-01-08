$WshShell = New-Object -comObject WScript.Shell
$DesktopPath = [Environment]::GetFolderPath("Desktop")
$ShortcutPath = Join-Path $DesktopPath "Th3 Thirty3 GPU.lnk"
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)
$ProjectRoot = "c:\Users\th3th\th3-thirty3"
$Shortcut.TargetPath = Join-Path $ProjectRoot "NEXUS33-docker.bat"
$Shortcut.Arguments = "--gpu"
$Shortcut.WorkingDirectory = $ProjectRoot
$Shortcut.IconLocation = Join-Path $ProjectRoot "icon.ico"
$Shortcut.Description = "Th3 Thirty3 - GPU Docker Training Mode"
$Shortcut.Save()
Write-Host "GPU Shortcut created: $ShortcutPath"
