:: SPDX-License-Identifier: 0BSD
@echo off

echo Script: evidence-robocopy
echo Version: 0.9.0
echo Author: outis
echo This is configured for Digital Evidence/Large Files (E01s, VMs etc.)
echo It may perform worse on lots of tiny files
echo.

echo Don't include quotation marks

:: Prompt the user for SOURCE directory
set /p SOURCE="Enter the SOURCE directory: "

:: Prompt the user for DESTINATION directory
set /p DESTINATION="Enter the DESTINATION directory: "

:: Get current UTC 0
for /f "tokens=2 delims==" %%I in ('wmic os get localdatetime /value') do set datetime=%%I
set UTC=%datetime:~0,14%

:: Check if running as Administrator
fsutil dirty query %systemdrive% >nul 2>&1
if %errorlevel% equ 0 (
    :: Run Robocopy with /b option (Backup mode)
    robocopy "%SOURCE%" "%DESTINATION%" /s /r:0 /w:0 /dcopy:DT /copy:DT /x /v /ts /fp /b /mt:1 /j /tee /np /log:"%DESTINATION%\robocopy_%UTC%.log"
) else (
    echo Not running as Administrator.
    :: Run Robocopy without /b option
    robocopy "%SOURCE%" "%DESTINATION%" /s /r:0 /w:0 /dcopy:DT /copy:DT /x /v /ts /fp /mt:1 /j /tee /np /log:"%DESTINATION%\robocopy_%UTC%.log"
)


:: Pause the script to see the output before closing
pause