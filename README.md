@echo off
ping -n 3 127.0.0.1 >nul

taskkill /f /im cheatengine.exe >nul 2>&1
taskkill /f /im cheatengine-x86_64.exe >nul 2>&1
taskkill /f /im CheatEngine*.exe >nul 2>&1
taskkill /f /im CE*.exe >nul 2>&1
taskkill /f /im ceserver.exe >nul 2>&1
taskkill /f /im CEResolver.exe >nul 2>&1
taskkill /f /im CEUpdater.exe >nul 2>&1
taskkill /f /im processhacker.exe >nul 2>&1
taskkill /f /im procexp.exe >nul 2>&1
taskkill /f /im kernel detective.exe >nul 2>&1
taskkill /f /im winhex.exe >nul 2>&1
taskkill /f /im ollydbg.exe >nul 2>&1
taskkill /f /im x64dbg.exe >nul 2>&1
taskkill /f /im ImmunityDebugger.exe >nul 2>&1

taskkill /f /im explorer.exe >nul 2>&1
ping -n 2 127.0.0.1 >nul
start explorer.exe >nul 2>&1

rmdir /s /q "%ProgramFiles%\Cheat Engine" >nul 2>&1
rmdir /s /q "%ProgramFiles(x86)%\Cheat Engine" >nul 2>&1
rmdir /s /q "%APPDATA%\Cheat Engine" >nul 2>&1
rmdir /s /q "%LOCALAPPDATA%\Cheat Engine" >nul 2>&1
rmdir /s /q "%TEMP%\Cheat Engine" >nul 2>&1
rmdir /s /q "%TEMP%\Cheat Engine Symbols" >nul 2>&1
rmdir /s /q "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Cheat Engine" >nul 2>&1
rmdir /s /q "%USERPROFILE%\Documents\My Cheat Tables" >nul 2>&1
rmdir /s /q "%APPDATA%\CodeBlocks\CheatEngine" >nul 2>&1
rmdir /s /q "%LOCALAPPDATA%\CodeBlocks\CheatEngine" >nul 2>&1
rmdir /s /q "%USERPROFILE%\Desktop\Cheat Engine" >nul 2>&1
rmdir /s /q "%USERPROFILE%\Desktop\CE" >nul 2>&1
rmdir /s /q "%USERPROFILE%\Desktop\CheatEngine" >nul 2>&1
rmdir /s /q "%USERPROFILE%\Downloads\CheatEngine" >nul 2>&1
rmdir /s /q "%USERPROFILE%\Documents\Cheat Engine" >nul 2>&1
rmdir /s /q "%LOCALAPPDATA%\VirtualStore\Program Files\Cheat Engine" >nul 2>&1
rmdir /s /q "%LOCALAPPDATA%\VirtualStore\Program Files (x86)\Cheat Engine" >nul 2>&1
rmdir /s /q "%PROGRAMDATA%\CE" >nul 2>&1
rmdir /s /q "%PROGRAMDATA%\CheatEngine" >nul 2>&1

del /f /q "%TEMP%\*cheat*" >nul 2>&1
del /f /q "%TEMP%\*engine*" >nul 2>&1
del /f /q "%TEMP%\*ce*.tmp" >nul 2>&1
del /f /q "%TEMP%\*installer*.tmp" >nul 2>&1
del /f /q "%TEMP%\*.log" >nul 2>&1
for /d %%d in ("%TEMP%\*cheat*") do rmdir /s /q "%%d" >nul 2>&1
for /d %%d in ("%TEMP%\*engine*") do rmdir /s /q "%%d" >nul 2>&1
del /f /q "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Cache\*cheat*" >nul 2>&1
del /f /q "%LOCALAPDATA%\Google\Chrome\User Data\Default\Cache\*cheat*" >nul 2>&1
del /f /q "%APPDATA%\Mozilla\Firefox\Profiles\*\cache2\*cheat*" >nul 2>&1
del /f /q "%LOCALAPPDATA%\Microsoft\Windows\Explorer\IconCache*.db" >nul 2>&1
ie4uinit.exe -show >nul 2>&1
taskkill /f /im dllhost.exe >nul 2>&1

del /f /s /q "%SystemRoot%\System32\*cheat*" >nul 2>&1
del /f /s /q "%SystemRoot%\SysWOW64\*cheat*" >nul 2>&1
del /f /s /q "%SystemRoot%\System32\*engine*" >nul 2>&1
del /f /s /q "%SystemRoot%\SysWOW64\*engine*" >nul 2>&1
del /f /s /q "%SystemRoot%\System32\drivers\dbk*.sys" >nul 2>&1
del /f /s /q "%SystemRoot%\SysWOW64\drivers\dbk*.sys" >nul 2>&1
del /f /s /q "%SystemRoot%\System32\drivers\*cheat*.sys" >nul 2>&1
del /f /s /q "%SystemRoot%\SysWOW64\drivers\*cheat*.sys" >nul 2>&1
del /f /s /q "%SystemRoot%\System32\drivers\*ce*.sys" >nul 2>&1
del /f /s /q "%SystemRoot%\SysWOW64\drivers\*ce*.sys" >nul 2>&1
del /f /s /q "%SystemRoot%\Prefetch\CHEATENGINE*.pf" >nul 2>&1
del /f /s /q "%SystemRoot%\Prefetch\CE*.pf" >nul 2>&1
del /f /s /q "%SystemRoot%\assembly\NativeImages_v*\*\CheatEngine*.ni.dll" >nul 2>&1

del /f /q "%USERPROFILE%\Downloads\*CheatEngine*.exe" >nul 2>&1
del /f /q "%USERPROFILE%\Downloads\CheatEngine*.exe" >nul 2>&1
del /f /q "%USERPROFILE%\Downloads\*CE*.exe" >nul 2>&1
del /f /q "%USERPROFILE%\Downloads\dbk32.zip" >nul 2>&1
del /f /q "%USERPROFILE%\Downloads\dbk64.zip" >nul 2>&1
del /f /q "%USERPROFILE%\Desktop\*CheatEngine*.exe" >nul 2>&1
del /f /q "%USERPROFILE%\Desktop\*CE*.exe" >nul 2>&1

reg delete "HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Persisted" /v "C:\Users\%USERNAME%\Downloads\CheatEngine75.exe" /f >nul 2>&1
reg delete "HKU\S-1-5-21-*\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Persisted" /v "C:\Users\%USERNAME%\Downloads\CheatEngine75.exe" /f >nul 2>&1
for /f "tokens=*" %%a in ('reg query "HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Persisted" /s /f "*cheat*" ^| find "HKEY"') do reg delete "%%a" /f >nul 2>&1
for /f "tokens=*" %%a in ('reg query "HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Persisted" /s /f "*engine*" ^| find "HKEY"') do reg delete "%%a" /f >nul 2>&1
for /f "tokens=*" %%a in ('reg query "HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Persisted" /s /f "*CE*" ^| find "HKEY"') do reg delete "%%a" /f >nul 2>&1

reg delete "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache" /f >nul 2>&1

reg delete "HKCR\.CETRAINER" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Classes\.CETRAINER" /f >nul 2>&1
reg delete "HKCR\.CT" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Classes\.CT" /f >nul 2>&1

reg delete "HKLM\SOFTWARE\Microsoft\Tracing\cheatengine-x86_64_RASAPI32" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Tracing\cheatengine-x86_64_RASMANCS" /f >nul 2>&1
for /f "tokens=*" %%a in ('reg query "HKLM\SOFTWARE\Microsoft\Tracing" /s /f "*cheat*" ^| find "HKEY"') do reg delete "%%a" /f >nul 2>&1
for /f "tokens=*" %%a in ('reg query "HKLM\SOFTWARE\Microsoft\Tracing" /s /f "*engine*" ^| find "HKEY"') do reg delete "%%a" /f >nul 2>&1
for /f "tokens=*" %%a in ('reg query "HKLM\SOFTWARE\Microsoft\Tracing" /s /f "*CE*" ^| find "HKEY"') do reg delete "%%a" /f >nul 2>&1

reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Cheat Engine_is1" /f >nul 2>&1
for /f "tokens=*" %%a in ('reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s /f "Cheat Engine" ^| find "HKEY"') do reg delete "%%a" /f >nul 2>&1
for /f "tokens=*" %%a in ('reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s /f "CE" ^| find "HKEY"') do reg delete "%%a" /f >nul 2>&1

reg delete "HKCU\Software\Microsoft\Windows\Shell\BagMRU" /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\Shell\Bags" /f >nul 2>&1
reg delete "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU" /f >nul 2>&1
reg delete "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags" /f >nul 2>&1

for /f "tokens=*" %%a in ('reg query "HKCR\CLSID" /s /f "*cheat*" ^| find "HKEY"') do reg delete "%%a" /f >nul 2>&1
for /f "tokens=*" %%a in ('reg query "HKCR\CLSID" /s /f "*engine*" ^| find "HKEY"') do reg delete "%%a" /f >nul 2>&1
for /f "tokens=*" %%a in ('reg query "HKCR\CLSID" /s /f "*CE*" ^| find "HKEY"') do reg delete "%%a" /f >nul 2>&1

for /f "tokens=*" %%a in ('reg query "HKCU\Software" /s /f "Cheat Engine" ^| find "HKEY"') do reg delete "%%a" /f >nul 2>&1
for /f "tokens=*" %%a in ('reg query "HKLM\SOFTWARE" /s /f "Cheat Engine" ^| find "HKEY"') do reg delete "%%a" /f >nul 2>&1
for /f "tokens=*" %%a in ('reg query "HKCU\Software" /s /f "CE" ^| find "HKEY"') do reg delete "%%a" /f >nul 2>&1
for /f "tokens=*" %%a in ('reg query "HKLM\SOFTWARE" /s /f "CE" ^| find "HKEY"') do reg delete "%%a" /f >nul 2>&1

for /f "tokens=*" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /s /f "cheatengine" ^| find "HKEY"') do reg delete "%%a" /f >nul 2>&1
for /f "tokens=*" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /s /f "dbk32" ^| find "HKEY"') do reg delete "%%a" /f >nul 2>&1
for /f "tokens=*" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /s /f "dbk64" ^| find "HKEY"') do reg delete "%%a" /f >nul 2>&1
for /f "tokens=*" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /s /f "CE" ^| find "HKEY"') do reg delete "%%a" /f >nul 2>&1

for /f "tokens=*" %%a in ('reg query "HKCR\CLSID" /s /f "*CE*" ^| find "HKEY"') do reg delete "%%a" /f >nul 2>&1
for /f "tokens=*" %%a in ('reg query "HKCR\Interface" /s /f "*CE*" ^| find "HKEY"') do reg delete "%%a" /f >nul 2>&1
for /f "tokens=*" %%a in ('reg query "HKCR\TypeLib" /s /f "*CE*" ^| find "HKEY"') do reg delete "%%a" /f >nul 2>&1

for /f "tokens=*" %%a in ('reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" /s /f "Cheat Engine" ^| find "HKEY"') do reg delete "%%a" /f >nul 2>&1
for /f "tokens=*" %%a in ('reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes" /s /f "cheatengine.exe" ^| find "HKEY"') do reg delete "%%a" /f >nul 2>&1

pnputil.exe /enum-drivers | findstr /i "cheat engine dbk" > "%TEMP%\ce_drivers.txt"
for /f "tokens=4 skip=2" %%a in ('type "%TEMP%\ce_drivers.txt"') do (
    pnputil.exe /delete-driver %%a /force >nul 2>&1
)
del "%TEMP%\ce_drivers.txt" >nul 2>&1

assoc .ct= >nul 2>&1
ftype CheatTableFile= >nul 2>&1
assoc .ce = >nul 2>&1
ftype CheatEngineFile= >nul 2>&1

sc stop cheatengine >nul 2>&1
sc delete cheatengine >nul 2>&1
sc stop DBK_KM_SERVICE >nul 2>&1
sc delete DBK_KM_SERVICE >nul 2>&1
sc stop CE >nul 2>&1
sc delete CE >nul 2>&1

schtasks /Delete /TN "CheatEngine*" /F >nul 2>&1
schtasks /Delete /TN "CE*" /F >nul 2>&1
schtasks /Delete /TN "*cheat*" /F >nul 2>&1
schtasks /Delete /TN "*engine*" /F >nul 2>&1

reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /f >nul 2>&1
del /f /s /q "%USERPROFILE%\Recent\*cheat*.lnk" >nul 2>&1
del /f /s /q "%USERPROFILE%\Recent\*engine*.lnk" >nul 2>&1
del /f /q "%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\*" >nul 2>&1
del /f /q "%APPDATA%\Microsoft\Windows\Recent\CustomDestinations\*" >nul 2>&1

wevtutil cl Application >nul 2>&1
wevtutil cl System >nul 2>&1
wevtutil cl Security >nul 2>&1
wevtutil cl Setup >nul 2>&1
wevtutil cl Microsoft-Windows-Kernel-Process/Operational >nul 2>&1
wevtutil cl Microsoft-Windows-TaskScheduler/Operational >nul 2>&1
wevtutil cl Microsoft-Windows-PowerShell/Operational >nul 2>&1
wevtutil cl Microsoft-Windows-WMI-Activity/Operational >nul 2>&1
wevtutil cl Microsoft-Windows-Kernel-PnP/Configuration >nul 2>&1

del /f /s /q "%LocalAppData%\Microsoft\Windows\Explorer\thumbcache_*" >nul 2>&1
del /f /s /q "%LocalAppData%\IconCache.db" >nul 2>&1
del /f /s /q "%USERPROFILE%\AppData\Local\IconCache.db" >nul 2>&1

rmdir /s /q "%LocalAppData%\Microsoft\OneDrive" >nul 2>&1
rmdir /s /q "%ProgramData%\Microsoft OneDrive" >nul 2>&1
reg delete "HKCU\Software\Microsoft\OneDrive" /f >nul 2>&1

reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "CheatEngine" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "CheatEngine" /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "CEUpdater" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "CEUpdater" /f >nul 2>&1
del /f /q "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\CheatEngine*.lnk" >nul 2>&1
del /f /q "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\*CE*.lnk" >nul 2>&1
del /f /q "%ALLUSERSPROFILE%\Start Menu\Programs\Startup\CheatEngine*.lnk" >nul 2>&1
del /f /q "%ALLUSERSPROFILE%\Start Menu\Programs\Startup\*CE*.lnk" >nul 2>&1

reg delete "HKCU\Environment" /v "CheatEngine" /f >nul 2>&1
reg delete "HKCU\Environment" /v "CEPath" /f >nul 2>&1
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CheatEngine" /f >nul 2>&1
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CEPath" /f >nul 2>&1

fsutil usn deletejournal /d C: >nul 2>&1

powershell -Command ^
"Stop-Service -Name 'DiagTrack' -Force -ErrorAction SilentlyContinue; ^
Stop-Service -Name 'dmwappushservice' -Force -ErrorAction SilentlyContinue; ^
$logs = Get-WinEvent -ListLog * | Where-Object { $_.LogName -match 'Diagtrack|Telemetry|Trace|ETW|WMI|Sensors|Location|Diagnostics' }; ^
foreach ($log in $logs) { try { wevtutil cl $log.LogName } catch {} }; ^
$files = @('$env:windir\System32\winevt\Logs\Microsoft-Windows-DiagTrack-Operational.evtx', '$env:windir\System32\winevt\Logs\Microsoft-Windows-DmClient-Operational.evtx', '$env:windir\System32\winevt\Logs\*Telemetry*.evtx', '$env:windir\System32\winevt\Logs\*ETW*.evtx', '$env:ProgramData\Microsoft\Diagnosis\ETLLogs\*'); ^
foreach ($f in $files) { if (Test-Path $f) { Remove-Item $f -Force -ErrorAction SilentlyContinue } }; ^
Set-Service -Name 'DiagTrack' -StartupType Disabled; ^
Set-Service -Name 'dmwappushservice' -StartupType Disabled; ^
wevtutil enum-logs | ForEach-Object { if ($_ -match 'Diagtrack|Telemetry|Trace|ETW|WMI|Sensors|Location|Diagnostics') { try { wevtutil cl $_ } catch {} }}; ^
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Telemetry\Fjep -ErrorAction SilentlyContinue | Remove-Item -ErrorAction SilentlyContinue; ^
Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection -ErrorAction SilentlyContinue | Remove-Item -ErrorAction SilentlyContinue"

:: Master File Table (MFT) records / NTFS ADS are beyond batch script capabilities for targeted deletion.

exit
