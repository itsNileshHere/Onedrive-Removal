# Check for Admin privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script must be run as Administrator. Please re-run it with administrative privileges." -ForegroundColor Red
    Read-Host -Prompt "Press Enter to exit"
    Exit
}

$OneDrivePath = $env:OneDrive
$process = Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue
if ($process) {
    taskkill.exe /F /IM "OneDrive.exe"
}
taskkill.exe /F /IM "explorer.exe"
Write-Host "`nRemoving OneDrive..."

if (Test-Path "$env:systemroot\SysWOW64\OneDriveSetup.exe") {
    & "$env:systemroot\SysWOW64\OneDriveSetup.exe" /uninstall
}

if (Test-Path "$env:systemroot\System32\OneDriveSetup.exe") {
    & "$env:systemroot\System32\OneDriveSetup.exe" /uninstall
}

$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\OneDriveSetup.exe"
if (Test-Path $regPath) {
    $uninstallString = (Get-ItemProperty -Path "$regPath" -Name "UninstallString").UninstallString
    Start-Process -FilePath ($uninstallString -replace ' /uninstall', '') -ArgumentList "/uninstall" -NoNewWindow -Wait -ErrorAction SilentlyContinue
}
else {
    Write-Host "`nOnedrive is not installed."
    Start-Process "explorer.exe"
    Read-Host -Prompt "Press Enter to exit"
    Exit
}

# Manually copying user folders
Write-Host "`nCopying downloaded files from the OneDrive folder to the root UserProfile..."
$null = xcopy.exe "$OneDrivePath" "$env:USERPROFILE" /E /I /H /R /Y /J

if ((Get-ChildItem "$OneDrivePath" -Recurse | Measure-Object).Count -eq 0) {
    Remove-Item -Path "$OneDrivePath" -Recurse -Force -ErrorAction SilentlyContinue
}
else {
    Write-Host "`nThere are some Files left in '$OneDrivePath'. Consider Copying them before deleting the folder"
}

# Remove leftovers
Write-Host "`nRemoving OneDrive leftovers..."
Remove-Item -Path "$env:localappdata\Microsoft\OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:localappdata\OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:programdata\Microsoft OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:systemroot\System32\OneDriveSetup.exe" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:systemroot\SysWOW64\OneDriveSetup.exe" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" -Force -ErrorAction SilentlyContinue > $null 2>&1
$oneDriveSetupPath = Get-Item -ErrorAction SilentlyContinue "$env:systemroot\WinSxS\*microsoft-windows-onedrive-setup*\OneDriveSetup.exe" | Select-Object -ExpandProperty FullName
if ($null -ne $oneDriveSetupPath) {
    foreach ($file in $oneDriveSetupPath3) {
        takeown /F "$file" /A > $null 2>&1
        icacls "$file" /grant:R Administrators:F /T /C > $null 2>&1
        Remove-Item -Path "$file" -Recurse -Force
    }
}

# Remove registry entries
reg delete "HKCU\Software\Microsoft\OneDrive" /f > $null 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\OneDriveSetup.exe" /f > $null 2>&1

# Prevent usage of OneDrive for file storage
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d 1 /f

# Remove from Explorer
reg add "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d 0 /f
reg add "HKCR\WOW6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "HiddenByDefault" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\NonEnum" /v "{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /t REG_DWORD /d 1 /f

# Remove from default user
reg load "HKLM\zNTUSER" "$env:systemdrive\Users\Default\NTUSER.DAT"
reg delete "HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f > $null 2>&1
reg unload "HKLM\zNTUSER"

# Remove scheduled tasks
Write-Host "Removing OneDrive scheduled tasks..."
Get-ScheduledTask -TaskPath '\' -TaskName 'OneDrive*' -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f > $null 2>&1

# Fix User Folders back to defaults
Write-Host "`nFixing shell folders..."
$shellFolders = @(
    @{ Name = "AppData"; Path = "$env:userprofile\AppData\Roaming" },
    @{ Name = "Cache"; Path = "$env:userprofile\AppData\Local\Microsoft\Windows\INetCache" },
    @{ Name = "Cookies"; Path = "$env:userprofile\AppData\Local\Microsoft\Windows\INetCookies" },
    @{ Name = "Favorites"; Path = "$env:userprofile\Favorites" },
    @{ Name = "History"; Path = "$env:userprofile\AppData\Local\Microsoft\Windows\History" },
    @{ Name = "Local AppData"; Path = "$env:userprofile\AppData\Local" },
    @{ Name = "My Music"; Path = "$env:userprofile\Music" },
    @{ Name = "My Video"; Path = "$env:userprofile\Videos" },
    @{ Name = "NetHood"; Path = "$env:userprofile\AppData\Roaming\Microsoft\Windows\Network Shortcuts" },
    @{ Name = "PrintHood"; Path = "$env:userprofile\AppData\Roaming\Microsoft\Windows\Printer Shortcuts" },
    @{ Name = "Programs"; Path = "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs" },
    @{ Name = "Recent"; Path = "$env:userprofile\AppData\Roaming\Microsoft\Windows\Recent" },
    @{ Name = "SendTo"; Path = "$env:userprofile\AppData\Roaming\Microsoft\Windows\SendTo" },
    @{ Name = "Start Menu"; Path = "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu" },
    @{ Name = "Startup"; Path = "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" },
    @{ Name = "Templates"; Path = "$env:userprofile\AppData\Roaming\Microsoft\Windows\Templates" },
    @{ Name = "Desktop"; Path = "$env:userprofile\Desktop" },
    @{ Name = "My Pictures"; Path = "$env:userprofile\Pictures" },
    @{ Name = "Personal"; Path = "$env:userprofile\Documents" },
    @{ Name = "SavedGames"; Path = "$env:userprofile\Saved Games" },
    @{ Name = "{374DE290-123F-4565-9164-39C4925E467B}"; Path = "$env:userprofile\Downloads" },
    @{ Name = "{F42EE2D3-909F-4907-8871-4C22FC0BF756}"; Path = "$env:userprofile\Documents" },
    @{ Name = "{0DDD015D-B06C-45D5-8C4C-F59713854639}"; Path = "$env:userprofile\Pictures" }
)

foreach ($folder in $shellFolders) {
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v $folder.Name /t REG_EXPAND_SZ /d $folder.Path /f
}

# Restart Explorer
Write-Host "`nStarting Explorer..."
Start-Process "explorer.exe"

Start-Sleep -Milliseconds 1500
Write-Host "`OneDrive Removed Successfully."
Read-Host -Prompt "Done. Press Enter to exit"
