@echo off
REM Builds a standalone Windows executable for AlertForge.
REM Requires: pip install -r requirements.txt

REM --collect-data bundles pyspellchecker's word-frequency dictionary
REM files, which PyInstaller doesn't pick up automatically - without
REM this flag the built exe would silently run with spell-check
REM disabled (the app catches the missing dictionary gracefully, but
REM there's no reason to ship it broken).
pyinstaller --onefile --windowed --name AlertForge --collect-data spellchecker app.py

echo.
echo Copying field_mappings.json next to the built exe...
copy /Y field_mappings.json dist\field_mappings.json

echo.
echo Done. Your executable is at dist\AlertForge.exe
echo IMPORTANT: field_mappings.json must stay in the same folder as the exe.
echo An alertforge.db file will be created there automatically on first run.
pause
