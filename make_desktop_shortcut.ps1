$WshShell = New-Object -comObject WScript.Shell
$DesktopPath = "C:\Users\MSI-USER\OneDrive\Bureau"
$Shortcut = $WshShell.CreateShortcut("$DesktopPath\Th3 Thirty3 (FIXED).lnk")
$Shortcut.TargetPath = "c:\Users\MSI-USER\th3-thirty3\th3-thirty3\start_th3_thirty3.bat"
$Shortcut.WorkingDirectory = "c:\Users\MSI-USER\th3-thirty3\th3-thirty3"
$Shortcut.IconLocation = "c:\Users\MSI-USER\th3-thirty3\th3-thirty3\icon.ico"
$Shortcut.Save()
Write-Host "Shortcut created at $DesktopPath\Th3 Thirty3 (FIXED).lnk"
