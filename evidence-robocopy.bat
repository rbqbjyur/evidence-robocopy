:: SPDX-License-Identifier: 0BSD
@echo off
setlocal enabledelayedexpansion

echo Script: evidence-robocopy
echo Version: 1.0.2
echo Author: outis
echo Remember to Disable AV Real Time Scanning if you have lots of small files!
echo.

set robo_flags=

:: Check if running as Administrator
fsutil dirty query %systemdrive% >nul 2>&1
if %errorlevel% equ 0 (
    set is_admin=true
	set robo_flags=!robo_flags! /b
    echo You are running as Administrator. You will be able to override folder and file permissions, but may be slower.
	echo.
) else (
	set is_admin=false
    echo You are not running as Administrator. You will not be able to override folder and file permissions.
	echo.
)



:: Decide between Log File (/np /tee (no /eta), /log added later) or ETA and Percentage; /eta (no /np /tee /log)
: log_decision
echo Would you prefer a log file, or ETA and Percentage:
echo 1. Log File (but no ETA or percentage)
echo 2. ETA and percentage (but no Log File)
set /p log_choice="> "
if "%log_choice%"=="1" (
	set robo_flags=!robo_flags! /np /tee
) else if "%log_choice%"=="2" (
	set robo_flags=!robo_flags! /eta
) else (
    echo Invalid Input %log_choice%
	echo.
	goto log_decision
)
echo.


echo Don't include quotation marks around directories

:: Prompt the user for SOURCE directory
set /p source="Enter the SOURCE directory: "

:: Prompt the user for DESTINATION directory
set /p destination="Enter the DESTINATION directory: "

:: Get current UTC 0
for /f "tokens=2 delims==" %%I in ('wmic os get localdatetime /value') do set datetime=%%I
set UTC=%datetime:~0,14%


:: Large files (>=100 MiB); Thread count 1, add /j
call :run_robocopy "!robo_flags! /j /min:104857600" "1" "large_files"

:: Small files (<100 MiB); Thread count is half threads on system
for /f "skip=1" %%I in ('wmic cpu get NumberOfLogicalProcessors') do if not defined threads set threads=%%I
set /a half_threads=!threads! / 2
call :run_robocopy "!robo_flags! /max:104857599" "!threads!" "small_files"


:: Large files with admin (/b, /mt:1, /j)
:: Small files with admin (/b, /mt:%threads%)
:: Large files without admin (/mt:1, /j)
:: Small files without admin (/mt:%threads%)

:: Pause the script to see the output before closing
pause
endlocal
exit /b

:: specify Log File if chosen
:run_robocopy
set end_robo_flags=
if "%log_choice%"=="1" (
	set end_robo_flags=%~1 /log:"!destination!\robocopy_!UTC!_%~3.log"
) else if "%log_choice%"=="2" (
	set end_robo_flags=%~1
) else (
    echo Unknown Log Choice %log_choice%
)
robocopy "%source% " "%destination% " *.* /xd "%source:~0,1%:\$RECYCLE.BIN" /xd "%source:~0,1%:\System Volume Information" /v /x /ts /fp /s /dcopy:DT /copy:DT /A-:SH /mt:%~2 /r:0 /w:0%end_robo_flags%
goto :eof
