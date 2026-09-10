@echo off
cd /d "%~dp0"
AutoLootCompatibilityCheck.exe "%~dp0ACOdyssey.exe"
echo.
echo Send AutoLootCompatibilityReport.txt to the AutoLoot author.
echo Do not send ACOdyssey.exe.
pause

