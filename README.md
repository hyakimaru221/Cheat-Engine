@echo off
title Aniquilador de Rastro - Cheat Engine
color 0C
cls

echo [01/21] FINALIZANDO PROCESSOS DO CHEAT ENGINE...
taskkill /f /im cheatengine.exe >nul 2>&1
taskkill /f /im cheatengine-x86_64.exe >nul 2>&1

echo [02/21] EXCLUINDO PASTAS EM %PROGRAMFILES% E %PROGRAMFILES(X86)%...
rmdir /s /q "%ProgramFiles%\Cheat Engine" >nul 2>&1
rmdir /s /q "%ProgramFiles(x86)%\Cheat Engine" >nul 2>&1

echo [03/21] LIMPANDO %APPDATA% E %LOCALAPPDATA%...
rmdir /s /q "%APPDATA%\Cheat Engine" >nul 2>&1
rmdir /s /q "%LOCALAPPDATA%\Cheat Engine" >nul 2>&1

echo [04/21] DELETANDO ARQUIVOS TEMPORÁRIOS VINCULADOS...
del /f /q "%TEMP%\*cheat*" >nul 2>&1
del /f /q "%TEMP%\*engine*" >nul 2>&1

echo [04B/21] ELIMINANDO PASTAS TEMP DO CHEAT ENGINE (MESMO VAZIAS)...
rmdir /s /q "C:\Users\florl\AppData\Local\Temp\Cheat Engine" >nul 2>&1
rmdir /s /q "C:\Users\florl\AppData\Local\Temp\Cheat Engine Symbols" >nul 2>&1

echo [05/21] CAÇANDO DLLS DO MAL EM SYSTEM32 E SYSWOW64...
del /f /s /q "%SystemRoot%\System32\*cheat*" >nul 2>&1
del /f /s /q "%SystemRoot%\SysWOW64\*cheat*" >nul 2>&1

echo [06/21] ELIMINANDO ARQUIVOS NO DESKTOP...
del /f /q "%USERPROFILE%\Desktop\*cheat*" >nul 2>&1

echo [07/21] CAÇANDO NO DOCUMENTOS E DOWNLOADS...
del /f /q "%USERPROFILE%\Documents\*cheat*" >nul 2>&1
del /f /q "%USERPROFILE%\Downloads\*cheat*" >nul 2>&1

echo [08/21] CAÇADA NO PREFETCH (NINJA INVISÍVEL)...
del /f /q "%SystemRoot%\Prefetch\*CHEAT*.pf" >nul 2>&1

echo [09/21] EXPURGANDO DO REGEDIT (HKCU, HKLM, HKCR)...
reg delete "HKCU\Software\Cheat Engine" /f >nul 2>&1
reg delete "HKLM\Software\Cheat Engine" /f >nul 2>&1
reg delete "HKCR\CheatEngine" /f >nul 2>&1

echo [10/21] LIMPANDO CLSID E FILEASSOCS...
reg delete "HKCR\CLSID\{*cheat*}" /f >nul 2>&1
reg delete "HKCR\*\shell\Cheat Engine" /f >nul 2>&1

echo [11/21] CAÇANDO EXTENSÕES .CT E OUTROS VESTÍGIOS...
assoc .ct= >nul 2>&1
ftype CheatTableFile= >nul 2>&1

echo [12/21] REVOADA NO SERVICES.MSC (BACKDOORS OCULTOS)...
sc stop cheatengine >nul 2>&1
sc delete cheatengine >nul 2>&1

echo [13/21] RASTREAMENTO EM TAREFAS AGENDADAS...
schtasks /Delete /TN "CheatEngine*" /F >nul 2>&1

echo [14/21] LIXANDO O HISTÓRICO DE EXECUÇÃO...
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /f >nul 2>&1

echo [15/21] DELETANDO ATALHOS OCULTOS (.lnk)...
del /f /s /q "%USERPROFILE%\Recent\*cheat*.lnk" >nul 2>&1

echo [16/21] LIMPANDO LOGS DO EVENT VIEWER...
wevtutil cl Application >nul 2>&1
wevtutil cl System >nul 2>&1

echo [17/21] APAGANDO THUMBNAIL CACHE (VISUALIZAÇÕES)...
del /f /s /q "%LocalAppData%\Microsoft\Windows\Explorer\thumbcache_*" >nul 2>&1

echo [18/21] EXTERMINANDO RESTOS DO START MENU E ONEDRIVE...
powershell -Command ^
    "$startMenu = 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs'; ^
    $targetFolder = Join-Path $startMenu 'Cheat Engine'; ^
    if (Test-Path $targetFolder) {Remove-Item $targetFolder -Recurse -Force}; ^
    Get-ChildItem $startMenu -Filter '*Cheat Engine*' -Recurse | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue" >nul 2>&1
rmdir /s /q "%LocalAppData%\Microsoft\OneDrive" >nul 2>&1
rmdir /s /q "%ProgramData%\Microsoft OneDrive" >nul 2>&1
reg delete "HKCU\Software\Microsoft\OneDrive" /f >nul 2>&1

echo [19/21] NEUTRALIZANDO INICIALIZAÇÕES AUTOMÁTICAS...
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "CheatEngine" /f >nul 2>&1
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "CheatEngine" /f >nul 2>&1
del /f /q "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\CheatEngine*.lnk" >nul 2>&1

echo [20/21] REMOVENDO VARIÁVEIS DE AMBIENTE SUSPEITAS...
setx CheatEngine "" >nul 2>&1
setx CEPath "" >nul 2>&1
reg delete "HKCU\Environment" /v "CheatEngine" /f >nul 2>&1
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CheatEngine" /f >nul 2>&1

echo [21/21] ANIQUILAÇÃO FINAL CONCLUÍDA COM SUCESSO.
echo.
echo Sistema purificado. Zero rastro. Blackout completo.
echo Nenhum atalho, nenhum registro, nenhuma variável. O fantasma foi exorcizado.
echo.

choice /m "Deseja reiniciar agora para consolidar a limpeza total?"
if %errorlevel%==1 (
    echo Reiniciando em 3 segundos...
    shutdown /r /t 3 /f /c "Reiniciando... Limpeza finalizada."
) else (
    echo Reinício cancelado. Encerrando sem reboot.
    timeout /t 2 >nul
)

exit /b
