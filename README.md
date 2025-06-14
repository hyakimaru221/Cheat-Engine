@echo off
title ANIQUILADOR DE RASTRO - CHEAT ENGINE V2
color 0C
cls

echo ==== FINALIZANDO PROCESSOS ====
taskkill /f /im cheatengine.exe >nul 2>&1
taskkill /f /im cheatengine-x86_64.exe >nul 2>&1

echo ==== DELETANDO PASTAS ====
rmdir /s /q "%ProgramFiles%\Cheat Engine" >nul 2>&1
rmdir /s /q "%ProgramFiles(x86)%\Cheat Engine" >nul 2>&1
rmdir /s /q "%APPDATA%\Cheat Engine" >nul 2>&1
rmdir /s /q "%LOCALAPPDATA%\Cheat Engine" >nul 2>&1
rmdir /s /q "%TEMP%\Cheat Engine" >nul 2>&1
rmdir /s /q "%TEMP%\Cheat Engine Symbols" >nul 2>&1

echo ==== LIMPEZA DE TEMP ====
del /f /q "%TEMP%\*cheat*" >nul 2>&1
del /f /q "%TEMP%\*engine*" >nul 2>&1
for /d %%d in ("%TEMP%\*cheat*") do rmdir /s /q "%%d" >nul 2>&1
for /d %%d in ("%TEMP%\*engine*") do rmdir /s /q "%%d" >nul 2>&1

echo ==== DETONANDO DLLs ====
del /f /s /q "%SystemRoot%\System32\*cheat*" >nul 2>&1
del /f /s /q "%SystemRoot%\SysWOW64\*cheat*" >nul 2>&1

echo ==== CAÇANDO REGISTROS ESCONDIDOS ====
rem AppCompatFlags Persisted
reg delete "HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Persisted" /v "C:\Users\%USERNAME%\Downloads\CheatEngine75.exe" /f >nul 2>&1
reg delete "HKU\S-1-5-21-*\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Persisted" /v "C:\Users\%USERNAME%\Downloads\CheatEngine75.exe" /f >nul 2>&1

rem MuiCache
reg delete "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache" /f >nul 2>&1

rem Extensões .CETRAINER
reg delete "HKCR\.CETRAINER" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Classes\.CETRAINER" /f >nul 2>&1

rem Tracing logs
reg delete "HKLM\SOFTWARE\Microsoft\Tracing\cheatengine-x86_64_RASAPI32" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Tracing\cheatengine-x86_64_RASMANCS" /f >nul 2>&1

rem Uninstall entries
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Cheat Engine_is1" /f >nul 2>&1

rem Shell Bags
reg delete "HKCU\Software\Microsoft\Windows\Shell\BagMRU" /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\Shell\Bags" /f >nul 2>&1
reg delete "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU" /f >nul 2>&1
reg delete "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags" /f >nul 2>&1

rem CLSID geral
for /f "tokens=*" %%a in ('reg query "HKCR\CLSID" /s /f "*cheat*" ^| find "HKEY"') do reg delete "%%a" /f >nul 2>&1
for /f "tokens=*" %%a in ('reg query "HKCR\CLSID" /s /f "*engine*" ^| find "HKEY"') do reg delete "%%a" /f >nul 2>&1

echo ==== QUEBRANDO ASSOCIAÇÕES DE EXTENSÕES ====
assoc .ct= >nul 2>&1
ftype CheatTableFile= >nul 2>&1

echo ==== MATANDO SERVICES ====
sc stop cheatengine >nul 2>&1
sc delete cheatengine >nul 2>&1

echo ==== APAGANDO TAREFAS AGENDADAS ====
schtasks /Delete /TN "CheatEngine*" /F >nul 2>&1

echo ==== ELIMINANDO HISTÓRICO DE EXECUÇÃO ====
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /f >nul 2>&1

echo ==== DELETANDO ATALHOS ====
del /f /s /q "%USERPROFILE%\Recent\*cheat*.lnk" >nul 2>&1

echo ==== ACESSO RÁPIDO E DESTINATIONS ====
del /f /q "%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\*" >nul 2>&1
del /f /q "%APPDATA%\Microsoft\Windows\Recent\CustomDestinations\*" >nul 2>&1

echo ==== EXPURGANDO LOGS DO EVENT VIEWER ====
wevtutil cl Application >nul 2>&1
wevtutil cl System >nul 2>&1

echo ==== DELETANDO THUMBNAIL CACHE ====
del /f /s /q "%LocalAppData%\Microsoft\Windows\Explorer\thumbcache_*" >nul 2>&1

echo ==== ANIQUILANDO ONEDRIVE ====
rmdir /s /q "%LocalAppData%\Microsoft\OneDrive" >nul 2>&1
rmdir /s /q "%ProgramData%\Microsoft OneDrive" >nul 2>&1
reg delete "HKCU\Software\Microsoft\OneDrive" /f >nul 2>&1

echo ==== NEUTRALIZANDO AUTOBOOT ====
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "CheatEngine" /f >nul 2>&1
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "CheatEngine" /f >nul 2>&1
del /f /q "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\CheatEngine*.lnk" >nul 2>&1

echo ==== VARIÁVEIS DE AMBIENTE ====
reg delete "HKCU\Environment" /v "CheatEngine" /f >nul 2>&1
reg delete "HKCU\Environment" /v "CEPath" /f >nul 2>&1
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CheatEngine" /f >nul 2>&1
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CEPath" /f >nul 2>&1

echo ==== DELETANDO USN JOURNAL ====
fsutil usn deletejournal /d C: >nul 2>&1

echo ==== ANIQUILANDO JOURNALTRACE & ETW ====
powershell -Command ^
"Stop-Service -Name 'DiagTrack' -Force -ErrorAction SilentlyContinue; ^
Stop-Service -Name 'dmwappushservice' -Force -ErrorAction SilentlyContinue; ^
$logs = Get-WinEvent -ListLog * | Where-Object { $_.LogName -match 'Diagtrack|Telemetry|Trace' }; ^
foreach ($log in $logs) { try { wevtutil cl $log.LogName } catch {} }; ^
$files = @('$env:windir\System32\winevt\Logs\Microsoft-Windows-DiagTrack-Operational.evtx', '$env:windir\System32\winevt\Logs\Microsoft-Windows-DmClient-Operational.evtx', '$env:windir\System32\winevt\Logs\*Telemetry*.evtx'); ^
foreach ($f in $files) { if (Test-Path $f) { Remove-Item $f -Force -ErrorAction SilentlyContinue } }; ^
Set-Service -Name 'DiagTrack' -StartupType Disabled; ^
Set-Service -Name 'dmwappushservice' -StartupType Disabled; ^
wevtutil enum-logs | ForEach-Object { if ($_ -match 'Diagtrack|Telemetry|Trace') { try { wevtutil cl $_ } catch {} } }"

echo 🔥 ANIQUILAÇÃO COMPLETA 🔥

choice /m "Quer reiniciar AGORA pra consolidar a limpeza? (SIM/NAO)"
if %errorlevel%==1 (
  echo Reiniciando em 3 segundos...
  shutdown /r /t 3 /f /c "Reiniciando... O CHEAT ENGINE VAI SUMIR!"
) else (
  echo Reinício cancelado. Se liga, não deixa rastro!
  timeout /t 2 >nul
)

exit
