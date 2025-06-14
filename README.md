@echo off
title ANIQUILADOR DE RASTRO - CHEAT ENGINE
color 0C
cls

echo FINALIZANDO TODOS OS PROCESSOS DO CHEAT ENGINE...
taskkill /f /im cheatengine.exe >nul 2>&1
taskkill /f /im cheatengine-x86_64.exe >nul 2>&1

echo APAGANDO PASTAS EM %PROGRAMFILES% E %PROGRAMFILES(X86)%...
rmdir /s /q "%ProgramFiles%\Cheat Engine" >nul 2>&1
rmdir /s /q "%ProgramFiles(x86)%\Cheat Engine" >nul 2>&1

echo LIMPANDO %APPDATA% E %LOCALAPPDATA%...
rmdir /s /q "%APPDATA%\Cheat Engine" >nul 2>&1
rmdir /s /q "%LOCALAPPDATA%\Cheat Engine" >nul 2>&1

echo DELETANDO TEMPORÁRIOS DO %TEMP%...
del /f /q "%TEMP%\*cheat*" >nul 2>&1
del /f /q "%TEMP%\*engine*" >nul 2>&1
for /d %%d in ("%TEMP%\*cheat*") do rmdir /s /q "%%d" >nul 2>&1
for /d %%d in ("%TEMP%\*engine*") do rmdir /s /q "%%d" >nul 2>&1
rmdir /s /q "%TEMP%\Cheat Engine" >nul 2>&1
rmdir /s /q "%TEMP%\Cheat Engine Symbols" >nul 2>&1

echo CAÇANDO DLLS MALDITAS...
del /f /s /q "%SystemRoot%\System32\*cheat*" >nul 2>&1
del /f /s /q "%SystemRoot%\SysWOW64\*cheat*" >nul 2>&1

echo APAGANDO ARQUIVOS NO DESKTOP, DOCUMENTOS E DOWNLOADS...
del /f /q "%USERPROFILE%\Desktop\*cheat*" >nul 2>&1
del /f /q "%USERPROFILE%\Documents\*cheat*" >nul 2>&1
del /f /q "%USERPROFILE%\Downloads\*cheat*" >nul 2>&1

echo LIMPANDO PREFETCH...
del /f /q "%SystemRoot%\Prefetch\*CHEAT*.pf" >nul 2>&1

echo EXPURGANDO REGISTROS MALDITOS...
reg delete "HKCU\Software\Cheat Engine" /f >nul 2>&1
reg delete "HKLM\Software\Cheat Engine" /f >nul 2>&1
reg delete "HKCR\CheatEngine" /f >nul 2>&1

echo ANIQUILANDO RASTROS DO SHELL...
reg delete "HKCU\Software\Microsoft\Windows\Shell\BagMRU" /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\Shell\Bags" /f >nul 2>&1
reg delete "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU" /f >nul 2>&1
reg delete "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags" /f >nul 2>&1

echo LIMPANDO CLSID & FILEASSOCS MALDITOS...
for /f "tokens=*" %%a in ('reg query "HKCR\CLSID" /s /f "*cheat*" ^| findstr /i "CLSID"') do reg delete "%%a" /f >nul 2>&1
for /f "tokens=*" %%a in ('reg query "HKCR\CLSID" /s /f "*engine*" ^| findstr /i "CLSID"') do reg delete "%%a" /f >nul 2>&1
reg delete "HKCR\*\shell\Cheat Engine" /f >nul 2>&1

echo DESASSOCIANDO EXTENSÕES...
assoc .ct= >nul 2>&1
ftype CheatTableFile= >nul 2>&1

echo EXTERMINANDO SERVICES MALDITOS...
sc stop cheatengine >nul 2>&1
sc delete cheatengine >nul 2>&1

echo APAGANDO TAREFAS AGENDADAS...
schtasks /Delete /TN "CheatEngine*" /F >nul 2>&1

echo LIMPANDO HISTÓRICO DE EXECUÇÃO...
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /f >nul 2>&1

echo ELIMINANDO ATALHOS FANTASMAS...
del /f /s /q "%USERPROFILE%\Recent\*cheat*.lnk" >nul 2>&1

echo LIMPANDO ACESSO RÁPIDO E ITENS FREQUENTES...
del /f /q "%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\*" >nul 2>&1
del /f /q "%APPDATA%\Microsoft\Windows\Recent\CustomDestinations\*" >nul 2>&1

echo LIMPANDO LOGS DO EVENT VIEWER...
wevtutil cl Application >nul 2>&1
wevtutil cl System >nul 2>&1

echo APAGANDO THUMBNAIL CACHE...
del /f /s /q "%LocalAppData%\Microsoft\Windows\Explorer\thumbcache_*" >nul 2>&1

echo ANIQUILANDO RESTOS DO MENU INICIAR & ONEDRIVE...
powershell -Command ^
  "$startMenu='C:\ProgramData\Microsoft\Windows\Start Menu\Programs';" ^
  "$targetFolder=Join-Path $startMenu 'Cheat Engine';" ^
  "if (Test-Path $targetFolder) {Remove-Item $targetFolder -Recurse -Force};" ^
  "Get-ChildItem $startMenu -Filter '*Cheat Engine*' -Recurse | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue" >nul 2>&1
rmdir /s /q "%LocalAppData%\Microsoft\OneDrive" >nul 2>&1
rmdir /s /q "%ProgramData%\Microsoft OneDrive" >nul 2>&1
reg delete "HKCU\Software\Microsoft\OneDrive" /f >nul 2>&1

echo NEUTRALIZANDO INICIALIZAÇÕES AUTOMÁTICAS...
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "CheatEngine" /f >nul 2>&1
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "CheatEngine" /f >nul 2>&1
del /f /q "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\CheatEngine*.lnk" >nul 2>&1

echo REMOVENDO VARIÁVEIS DE AMBIENTE...
reg delete "HKCU\Environment" /v "CheatEngine" /f >nul 2>&1
reg delete "HKCU\Environment" /v "CEPath" /f >nul 2>&1
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CheatEngine" /f >nul 2>&1
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CEPath" /f >nul 2>&1

echo DELETANDO O USN JOURNAL (RASPANDO ATÉ O OSSO)...
fsutil usn deletejournal /d C: >nul 2>&1

echo ANIQUILAÇÃO CHEAT ENGINE COMPLETA.

echo.
echo INICIANDO ANIQUILADOR DE JOURNALTRACE & ETW LOGS...

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

echo ANIQUILAÇÃO JOURNALTRACE COMPLETA.

choice /m "Quer reiniciar AGORA pra consolidar a limpeza? (SIM/NAO)"
if %errorlevel%==1 (
  echo Reiniciando em 3 segundos...
  shutdown /r /t 3 /f /c "Reiniciando... O CHEAT ENGINE VAI SUMIR!"
) else (
  echo Reinício cancelado. Se liga, não deixa rastro!
  timeout /t 2 >nul
)

exit
