:: SPDX-License-Identifier: 0BSD
@echo off
setlocal enabledelayedexpansion

echo Script: evidence-robocopy
echo Version: 1.0.3
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
echo.

:: Decide to compare hashes
: hash_decision
echo Once complete, would you like to compare SHA-256 of every file?:
echo 1. Compare SHA-256
echo 2. Do not compare hashes
set /p hash_choice="> "
if "%hash_choice%"=="1" (
	goto hash_decided
) else if "%hash_choice%"=="2" (
	goto hash_decided
) else (
    echo Invalid Input %hash_choice%
	echo.
	goto hash_decision
)
: hash_decided
echo.


:: Get current UTC 0
for /f "tokens=2 delims==" %%I in ('wmic os get localdatetime /value') do set datetime=%%I
set UTC=%datetime:~0,14%


:: Large files (>=100 MiB); Thread count 1, add /j
call :run_robocopy "!robo_flags! /j /min:104857600" "1"

:: Small files (<100 MiB); Thread count is half threads on system
for /f "skip=1" %%I in ('wmic cpu get NumberOfLogicalProcessors') do if not defined threads set threads=%%I
set /a half_threads=!threads! / 2
call :run_robocopy "!robo_flags! /max:104857599" "!threads!"

:: Large files with admin (/b, /mt:1, /j)
:: Small files with admin (/b, /mt:%threads%)
:: Large files without admin (/mt:1, /j)
:: Small files without admin (/mt:%threads%)

:: Generate hashes, if chosen
if "%hash_choice%"=="1" (
	call :hash_dir "%source%" "source"
	call :hash_dir "%destination%" "destination"
	
	call :hash_file "destination" "robocopy_!UTC!_hashes_source.csv" "%destination%\robocopy_!UTC!_hashes_source.csv"
	set "HASH_SOURCE=!HASH!"
	call :hash_file "destination" "robocopy_!UTC!_hashes_destination.csv" "%destination%\robocopy_!UTC!_hashes_destination.csv"
	set "HASH_DESTINATION=!HASH!"
	echo.
	
	:: Compare hashes
	if "!HASH_SOURCE!"=="!HASH_DESTINATION!" (
		echo The hashes MATCH
		echo !HASH_SOURCE!
	) else (
		echo The hashes DO NOT match!
		echo "robocopy_!UTC!_hashes_source.csv","!HASH!"
		echo "robocopy_!UTC!_hashes_destination.csv","!HASH!"
	)
	echo.
)

:: Pause the script to see the output before closing
pause
endlocal
exit /b

:: specify Log File if chosen
:run_robocopy
set end_robo_flags=
if "%log_choice%"=="1" (
	set end_robo_flags=%~1 /log+:"!destination!\robocopy_!UTC!.log"
) else if "%log_choice%"=="2" (
	set end_robo_flags=%~1
) else (
    echo Unknown Log Choice %log_choice%
)
robocopy "%source% " "%destination% " *.* /xd "%source:~0,1%:\$RECYCLE.BIN" /xd "%source:~0,1%:\System Volume Information" /v /x /ts /fp /s /dcopy:DT /copy:DT /A-:SH /mt:%~2 /r:0 /w:0%end_robo_flags%
echo.
goto :eof

:: generate hash csv
:hash_dir
echo Hashing %~2 Started
set "hash_dir=%~1"
set "hash_dir_label=%~2"
set "hashes_output="!destination!\robocopy_!UTC!_hashes_!hash_dir_label!.csv"
echo "File","SHA-256" > "%hashes_output%"

:: Get length of hash_dir
set "tempstr=%hash_dir%"
set /a SOURCE_LENGTH=0
:strlen_loop
if defined tempstr (
    set "tempstr=!tempstr:~1!"
    set /a SOURCE_LENGTH+=1
    goto strlen_loop
)

for /R "%hash_dir%" %%F in (*) do (
	:: Get Relative Path of Current File
	set "FULL=%%F"
	set "RELATIVE=!FULL:~%SOURCE_LENGTH%!"
	if "!RELATIVE:~0,1!"=="\" set "RELATIVE=!RELATIVE:~1!"

	if /i "!RELATIVE:~0,23!"=="robocopy_!UTC!" (
        echo Skipping "!RELATIVE!"
    ) else (
		call :hash_file "!hash_dir_label!" "!RELATIVE!" "%%F"
		:: Output
		echo "!RELATIVE!","!HASH!" >> "%hashes_output%"
    )
)
echo Hashing !hash_dir_label! Finished
echo.
goto :eof

:hash_file
set "hash_dir_label=%~1"
set "file_label=%~2"
set "target_file=%~3"

:: Extract hash (2nd Line) from certutil
echo Hashing !hash_dir_label!: "!file_label!"
set "HASH="
for /f "skip=1 tokens=*" %%H in ('certutil -hashfile "!target_file!" SHA256') do (
	if not defined HASH (
		set "HASH=%%H"
		set "HASH=!HASH: =!"
	)
)
goto :eof