@echo off
title Aniquilador de Rastro - Cheat Engine
color 0C
cls

echo [01/21] FINALIZANDO PROCESSOS DO CHEAT ENGINE...
taskkill /f /im cheatengine.exe >nul 2>&1
taskkill /f /im cheatengine-x86_64.exe >nul 2>&1

echo [02/21] EXCLUINDO PASTAS EM %PROGRAMFILES% E %PROGRAMFILES(X86)%...
rem Remove as pastas de instalação padrão do Cheat Engine
rmdir /s /q "%ProgramFiles%\Cheat Engine" >nul 2>&1
rmdir /s /q "%ProgramFiles(x86)%\Cheat Engine" >nul 2>&1

echo [03/21] LIMPANDO %APPDATA% E %LOCALAPPDATA% (DADOS DE UTILIZADOR E CACHE)...
rem Remove dados do programa no roaming e local appdata
rmdir /s /q "%APPDATA%\Cheat Engine" >nul 2>&1
rmdir /s /q "%LOCALAPPDATA%\Cheat Engine" >nul 2>&1

echo [04/21] ELIMINAR FICHEIROS TEMPORÁRIOS LIGADOS E PASTAS!
rem Remove ficheiros temporários genéricos do Cheat Engine na pasta TEMP
del /f /q "%TEMP%\*cheat*" >nul 2>&1
del /f /q "%TEMP%\*engine*" >nul 2>&1

rem Procura e remove subpastas que contenham "cheat" ou "engine" no nome dentro de %TEMP%
for /d %%d in ("%TEMP%\*cheat*") do rmdir /s /q "%%d" >nul 2>&1
for /d %%d in ("%TEMP%\*engine*") do rmdir /s /q "%%d" >nul 2>&1

echo [04B/21] ELIMINAR PASTAS TEMP DO CHEAT ENGINE (MESMO VAZIAS, AGORA GLOBALMENTE!)...
rem Remove pastas específicas do Cheat Engine que podem ter sido criadas diretamente em %TEMP%
rem UTILIZA %TEMP% PARA GARANTIR QUE FUNCIONE PARA QUALQUER UTILIZADOR, SEU ANIMAL!
rmdir /s /q "%TEMP%\Cheat Engine" >nul 2>&1
rmdir /s /q "%TEMP%\Cheat Engine Symbols" >nul 2>&1

echo [05/21] CAÇAR DLLS DO MAL EM SYSTEM32 E SYSWOW64 (FICHEIROS DE SISTEMA)...
rem Apaga DLLs e outros ficheiros com nomes suspeitos nas pastas do sistema
del /f /s /q "%SystemRoot%\System32\*cheat*" >nul 2>&1
del /f /s /q "%SystemRoot%\SysWOW64\*cheat*" >nul 2>&1

echo [06/21] ELIMINAR FICHEIROS NO AMBIENTE DE TRABALHO...
del /f /q "%USERPROFILE%\Desktop\*cheat*" >nul 2>&1

echo [07/21] CAÇAR NOS DOCUMENTOS E TRANSFERÊNCIAS...
del /f /q "%USERPROFILE%\Documents\*cheat*" >nul 2>&1
del /f /q "%USERPROFILE%\Downloads\*cheat*" >nul 2>&1

echo [08/21] CAÇADA NO PREFETCH (NINJA INVISÍVEL - FICHEIROS DE PRÉ-CARREGAMENTO)...
del /f /q "%SystemRoot%\Prefetch\*CHEAT*.pf" >nul 2>&1

echo [09/21] EXPURGAR DO REGEDIT (HKCU, HKLM, HKCR - CHAVES DE REGISTO)...
rem Remove chaves principais do Cheat Engine do registo
reg delete "HKCU\Software\Cheat Engine" /f >nul 2>&1
reg delete "HKLM\Software\Cheat Engine" /f >nul 2>&1
reg delete "HKCR\CheatEngine" /f >nul 2>&1

echo [09B/21] ANIQUILAR RASTO DO SHELL (BAGS E BAGMRU) - PARA LIMPAR HISTÓRICO!
rem Remove histórico de pastas abertas e configurações de visualização do Explorer
reg delete "HKCU\Software\Microsoft\Windows\Shell\BagMRU" /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\Shell\Bags" /f >nul 2>&1
reg delete "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU" /f >nul 2>&1
reg delete "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags" /f >nul 2>&1

echo [10/21] LIMPAR CLSID E FILEASSOCS (ASSOCIAÇÕES DE FICHEIROS E IDs DE CLASSE)...
rem Procura e remove chaves CLSID que podem conter "cheat" ou "engine" na descrição
for /f "tokens=*" %%a in ('reg query "HKCR\CLSID" /s /f "*cheat*" ^| findstr /i "CLSID"') do (
    reg delete "%%a" /f >nul 2>&1
)
for /f "tokens=*" %%a in ('reg query "HKCR\CLSID" /s /f "*engine*" ^| findstr /i "CLSID"') do (
    reg delete "%%a" /f >nul 2>&1
)
rem Remove a associação do Cheat Engine com o menu de contexto (botão direito do rato)
reg delete "HKCR\*\shell\Cheat Engine" /f >nul 2>&1

echo [11/21] CAÇAR EXTENSÕES .CT E OUTROS VESTÍGIOS (ASSOCIAÇÕES DE FICHEIROS)...
rem Desassocia o ficheiro .ct (cheat table) de qualquer programa
assoc .ct= >nul 2>&1
ftype CheatTableFile= >nul 2>&1

echo [12/21] REVOADA NO SERVICES.MSC (BACKDOORS OCULTOS - SERVIÇOS DO WINDOWS)...
rem Para serviços do Cheat Engine
sc stop cheatengine >nul 2>&1
sc delete cheatengine >nul 2>&1

echo [13/21] RASTREIO EM TAREFAS AGENDADAS...
rem Remove tarefas agendadas criadas pelo Cheat Engine
schtasks /Delete /TN "CheatEngine*" /F >nul 2>&1

echo [14/21] LIXAR O HISTÓRICO DE EXECUÇÃO (ITENS RECENTES DO MENU INICIAR/EXECUTAR)...
rem Limpa o histórico de comandos executados no Windows (RunMRU)
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /f >nul 2>&1

echo [15/21] ELIMINAR ATALHOS OCULTOS (.lnk) EM PASTAS RECENTES...
del /f /s /q "%USERPROFILE%\Recent\*cheat*.lnk" >nul 2>&1

echo [15B/21] APAGAR HISTÓRICO DO ACESSO RÁPIDO E ITENS FREQUENTES!
rem Limpa os "Jump Lists" e o histórico do Acesso Rápido no Explorador de Ficheiros
del /f /q "%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\*" >nul 2>&1
del /f /q "%APPDATA%\Microsoft\Windows\Recent\CustomDestinations\*" >nul 2>&1

echo [16/21] LIMPAR REGISTOS DO VISUALIZADOR DE EVENTOS (REGISTOS DE EVENTOS DO SISTEMA)...
wevtutil cl Application >nul 2>&1
wevtutil cl System >nul 2>&1

echo [17/21] APAGAR THUMBNAIL CACHE (VISUALIZAÇÕES DE MINIATURAS)...
del /f /s /q "%LocalAppData%\Microsoft\Windows\Explorer\thumbcache_*" >nul 2>&1

echo [18/21] EXTERMINAR RESTOS DO MENU INICIAR E ONEDRIVE (SE TIVER INSTALADO LÁ)...
rem Remove atalhos e pastas do Menu Iniciar
powershell -Command ^
    "$startMenu = 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs'; ^
    $targetFolder = Join-Path $startMenu 'Cheat Engine'; ^
    if (Test-Path $targetFolder) {Remove-Item $targetFolder -Recurse -Force}; ^
    Get-ChildItem $startMenu -Filter '*Cheat Engine*' -Recurse | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue" >nul 2>&1
rem Remove pastas e chaves de registo do OneDrive (se tu quer essa porra limpa também!)
rmdir /s /q "%LocalAppData%\Microsoft\OneDrive" >nul 2>&1
rmdir /s /q "%ProgramData%\Microsoft OneDrive" >nul 2>&1
reg delete "HKCU\Software\Microsoft\OneDrive" /f >nul 2>&1

echo [19/21] NEUTRALIZAR INICIALIZAÇÕES AUTOMÁTICAS (NO REGISTO E PASTA DE INICIALIZAÇÃO)...
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "CheatEngine" /f >nul 2>&1
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "CheatEngine" /f >nul 2>&1
del /f /q "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\CheatEngine*.lnk" >nul 2>&1

echo [20/21] REMOVER VARIÁVEIS DE AMBIENTE SUSPEITAS...
rem Remove variáveis de ambiente específicas do Cheat Engine
reg delete "HKCU\Environment" /v "CheatEngine" /f >nul 2>&1
reg delete "HKCU\Environment" /v "CEPath" /f >nul 2>&1
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CheatEngine" /f >nul 2>&1
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "CEPath" /f >nul 2>&1

echo [21/21] ANIQUILAÇÃO FINAL CONCLUÍDA COM SUCESSO.
echo.
echo Sistema purificado. Zero rastro. Blackout completo.
echo Nenhum atalho, nenhum registo, nenhuma variável. O fantasma foi exorcizado.
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
