:: SPDX-License-Identifier: 0BSD
@echo off
setlocal enabledelayedexpansion

echo Script: evidence-robocopy
echo Version: 1.0.0
echo Author: outis
echo.


set THREADS=1
set ROBO_FLAGS= 

:: Check if running as Administrator
fsutil dirty query %systemdrive% >nul 2>&1
if %errorlevel% equ 0 (
    set is_admin=true
	set ROBO_FLAGS=!ROBO_FLAGS!/b 
    echo You are running as Administrator. You will be able to override folder and file permissions, but may be slower.
	echo.
) else (
	set is_admin=false
    echo You are not running as Administrator. You will not be able to override folder and file permissions.
	echo.
)

:: Select transfer style
: transfer_size
echo Select the type of files you will be copying:
echo 1. Large files (E01s, VMs etc.)
echo 2. Small files (Documents etc.)
set /p file_size_choice="> "
if "%file_size_choice%"=="1" (
	:: Large files; Thread count remains 1, add /j
    set ROBO_FLAGS=!ROBO_FLAGS!/j 
) else if "%file_size_choice%"=="2" (
	:: Small files; Thread count is half threads on system
	echo Remember to Disable AV Real Time Scanning if you have lots of files!
	for /f "skip=1" %%I in ('wmic cpu get NumberOfLogicalProcessors') do if not defined NUM_THREADS set NUM_THREADS=%%I
    set /a THREADS=!NUM_THREADS! / 2
) else (
    echo Invalid Input %file_size_choice%
	echo.
	goto transfer_size
)
echo.


echo Don't include quotation marks around directories

:: Prompt the user for SOURCE directory
set /p SOURCE="Enter the SOURCE directory: "

:: Prompt the user for DESTINATION directory
set /p DESTINATION="Enter the DESTINATION directory: "

:: Get current UTC 0
for /f "tokens=2 delims==" %%I in ('wmic os get localdatetime /value') do set datetime=%%I
set UTC=%datetime:~0,14%

robocopy "%SOURCE% " "%DESTINATION% " *.* /xd "%SOURCE:~0,1%:\$RECYCLE.BIN" /xd "%SOURCE:~0,1%:\System Volume Information" /v /x /ts /fp /tee /s /dcopy:DT /copy:DT%ROBO_FLAGS%/np /A-:SH /mt:%THREADS% /r:0 /w:0 /log:"%DESTINATION%\robocopy_%UTC%.log"

:: Large files with admin (/b, /mt:1, /j)
:: Small files with admin (/b, /mt:%THREADS%)
:: Large files without admin (/mt:1, /j)
:: Small files without admin (/mt:%THREADS%)

:: Pause the script to see the output before closing
pause