$TargetFile = "$PSScriptRoot\start_th3_thirty3.bat"
$DesktopPath = [Environment]::GetFolderPath("Desktop")
$ShortcutFile = "$DesktopPath\Th3 Thirty3.lnk"
$WScriptShell = New-Object -ComObject WScript.Shell
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
$Shortcut.TargetPath = $TargetFile
$Shortcut.WorkingDirectory = $PSScriptRoot
# Attempt to set icon if available (assuming .ico format, but we might have .png from generation)
# Windows shortcuts need .ico. We'll stick to default or try to convert if possible, 
# but for now let's just create the shortcut.
# $Shortcut.IconLocation = "$PSScriptRoot\icon.ico" 
$Shortcut.Save()

Write-Host "Shortcut created successfully at $ShortcutFile" -ForegroundColor Green
