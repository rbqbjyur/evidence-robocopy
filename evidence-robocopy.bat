:: SPDX-License-Identifier: 0BSD
@echo off
rem ===========================================================================
rem evidence-robocopy - copy digital evidence between drives with robocopy,
rem verify every file by SHA-256 against a reference record and by size and
rem last-modified time, and leave chain-of-custody records with the evidence.
rem
rem Usage:   evidence-robocopy.bat       forensic mode (default): log file and
rem                                      SHA-256 verification, no questions
rem                                      beyond source and destination
rem          evidence-robocopy.bat /nonforensic
rem                                      ask whether to keep a log and verify
rem          evidence-robocopy.bat /?    show help
rem          Run as administrator for backup mode (/b).
rem Exit:    0 PASS, 1 FAIL, 2 UNVERIFIED (see EXIT_CODE_* in CONFIG)
rem Changes: see CHANGELOG.md. Licence: 0BSD, see LICENSE.
rem
rem Conventions for contributors. This script is the documented procedure for
rem copying evidence, so it is written to be read plainly by anyone checking
rem how evidence was handled:
rem  - Names are full words and say exactly what a variable holds or what a
rem    function does. A variable keeps one meaning for its whole life.
rem  - MAIN lists every step of a run in order; each step is one function.
rem  - Delayed expansion is OFF in the main flow. Paths may contain ! % ^ & ( )
rem    so they are only ever expanded as !var! inside helpers that enable
rem    delayed expansion, or as "%var%" inside quotes in the main flow. Never
rem    pass a path to CALL as a value: pass the variable's NAME instead.
rem  - Never return a path from a SETLOCAL helper with "endlocal & set": into a
rem    delayed-expansion caller that mangles "!". Such helpers run in the
rem    caller's scope instead (marked "Caller's scope"), and name their
rem    working variables after themselves so they can't clash.
rem  - "side" is "source" or "destination". Per-side variables are named
rem    <side>_path (no trailing backslash), <side>_with_backslash (exactly
rem    one, for building paths inside the folder), and so on; helpers build
rem    these names from the side.
rem  - "Drive root" is the top of a volume (E:\), always written in full.
rem    "Root" alone is the top level of the chosen source or destination
rem    folder (e.g. "the source root").
rem  - Output goes through :show (console only) or :show_and_log (console and,
rem    in log mode, the log):
rem        set "msg=Some text" & call :show_and_log msg
rem  - Lists of similar items are tables in CONFIG: add a row, not code.
rem ===========================================================================
setlocal EnableExtensions DisableDelayedExpansion

rem ============================== CONFIG =====================================

set "TOOL_NAME=evidence-robocopy"
set "TOOL_VERSION=1.5.1"

rem Robocopy retries for each file that fails (count, seconds between tries).
rem Fail fast on purpose: one short retry covers transient faults (network
rem blip, AV holding a file), while a real problem fails within seconds per
rem file instead of retrying for hours and looking like progress.
set "RETRY_COUNT=1"
set "RETRY_WAIT_SECONDS=2"

rem Files of at least this many bytes go to the large-file pass.
set "LARGE_FILE_BYTES=104857600"
set /a "SMALL_FILE_MAX_BYTES=LARGE_FILE_BYTES - 1, LARGE_FILE_MIB=LARGE_FILE_BYTES / 1048576"

rem Thread count for "auto" passes: logical processors / THREAD_DIVISOR,
rem kept within 1..THREAD_MAX (robocopy's /mt limit is 128).
set "THREAD_DIVISOR=2"
set "THREAD_MAX=128"

rem Volume housekeeping skipped only when the source or destination folder IS
rem a drive root (E:\): what Windows, macOS and Linux leave on a drive they
rem are plugged into, not evidence. Anywhere else (inside a folder, or any UNC
rem path, which can't be told apart from a folder) these names are contents
rem and are copied: wrongly copying them fails visibly, wrongly skipping them
rem would silently leave evidence out. Before copying, each drive root is
rem checked and only the items actually present are excluded, by exact path,
rem and listed in the log. Items are separated by "|" (invalid in Windows
rem names; a plain FOR would treat * and ? as a file search), * and ? are
rem allowed. One row per origin: add a row, not code.
rem Folders:
rem   Windows: recycle bins (Vista+, 2000/XP/2003 NTFS, 9x/ME FAT), system data
set "DRIVE_ROOT_HOUSEKEEPING_DIRS=$RECYCLE.BIN|RECYCLER|RECYCLED|System Volume Information"
rem   macOS: trash, Spotlight index, file-system events, temp, version store
set "DRIVE_ROOT_HOUSEKEEPING_DIRS=%DRIVE_ROOT_HOUSEKEEPING_DIRS%|.Trashes|.Spotlight-V100|.fseventsd|.TemporaryItems|.DocumentRevisions-V100"
rem   Linux desktops: trash on removable media, one per user (.Trash-<uid>)
set "DRIVE_ROOT_HOUSEKEEPING_DIRS=%DRIVE_ROOT_HOUSEKEEPING_DIRS%|.Trash-*"
rem Files:
rem   macOS: Finder data, AppleDouble files, volume icon, Time Machine and
rem   Spotlight markers
set "DRIVE_ROOT_HOUSEKEEPING_FILES=.DS_Store|._*|.apdisk|.VolumeIcon.icns|.com.apple.timemachine.donotpresent|.metadata_never_index*"
rem   Windows: thumbnail cache
set "DRIVE_ROOT_HOUSEKEEPING_FILES=%DRIVE_ROOT_HOUSEKEEPING_FILES%|Thumbs.db"
rem   Linux desktops: GNOME volume info, KDE folder settings
set "DRIVE_ROOT_HOUSEKEEPING_FILES=%DRIVE_ROOT_HOUSEKEEPING_FILES%|.xdg-volume-info|.directory"

rem Folders of recovered fragments at a drive root ("|"-separated, * and ?
rem allowed): chkdsk (FOUND.000, ...) and Android (LOST.DIR). They are copied
rem as contents, never skipped (they may hold pieces of evidence files), but
rem their presence means the drive has had file-system repairs: a warning.
set "DRIVE_ROOT_RECOVERED_DIRS=FOUND.???|LOST.DIR"

rem Copy passes, run in the order listed in COPY_PASSES. Fields per pass <id>:
rem   PASS_<id>_LABEL    text shown in the console and log
rem   PASS_<id>_FILTER   robocopy file-size filter
rem   PASS_<id>_THREADS  /mt thread count, or "auto" (see THREAD_DIVISOR)
rem   PASS_<id>_FLAGS    extra robocopy flags for this pass only
rem Every pass uses /j (unbuffered I/O): file contents go straight to the drive
rem rather than through the Windows cache, so verification reads them back
rem from the drive. A pass without /j is named in a warning
rem (:check_write_mode).
set "COPY_PASSES=large small"
set "PASS_large_LABEL=Large files (%LARGE_FILE_MIB% MiB and over)"
set "PASS_large_FILTER=/min:%LARGE_FILE_BYTES%"
set "PASS_large_THREADS=1"
set "PASS_large_FLAGS=/j"
set "PASS_small_LABEL=Small files (under %LARGE_FILE_MIB% MiB)"
set "PASS_small_FILTER=/max:%SMALL_FILE_MAX_BYTES%"
set "PASS_small_THREADS=auto"
set "PASS_small_FLAGS=/j"

rem Robocopy flags used by every copy pass (COPY_FLAGS), and by the file
rem listing that drives verification (LIST_FLAGS: list only, full paths, no
rem headers, sizes or classes). Files and subfolders keep their data,
rem attributes and timestamps (DAT), so anything hidden in the evidence stays
rem hidden; owner and ACLs are not copied. /bytes logs exact sizes. /e
rem includes empty folders. /xj doesn't follow junctions: only what is
rem physically inside the source is copied, and junction loops (e.g.
rem "Application Data" in a user profile) can't recurse forever.
set "COPY_FLAGS=/e /xj /v /x /ts /fp /bytes /dcopy:DAT /copy:DAT"
set "LIST_FLAGS=/l /e /xj /njh /njs /ndl /nc /ns /fp /r:0 /w:0"

rem Post-copy metadata check: robocopy in list-only mode, source against
rem destination, lists only files it would copy, i.e. whose size or
rem last-modified time differ (or that are missing). /xx leaves out files that
rem exist only in the destination (custody records). No /v or class column,
rem so nothing localised is parsed. Attributes and creation time are copied
rem but not compared: exFAT can't hold every NTFS attribute.
set "METADATA_FLAGS=/l /e /xj /xx /njh /njs /ndl /nc /ns /fp /r:0 /w:0"
rem File systems with coarse timestamps: if the source or destination is one,
rem times are compared to 2 s (/fft) instead of exactly.
set "COARSE_TIME_FILESYSTEMS=FAT FAT32 exFAT"

rem Robocopy exit code bits, checked highest first. Fields per bit <n>:
rem   ROBOCOPY_EXIT_<n>_SEVERITY  FAIL (copy failed), WARN or INFO
rem   ROBOCOPY_EXIT_<n>_TEXT      explanation written to the console and log
set "ROBOCOPY_EXIT_BITS=16 8 4 2 1"
set "ROBOCOPY_EXIT_16_SEVERITY=FAIL"
set "ROBOCOPY_EXIT_16_TEXT=Fatal error: nothing was copied (bad usage, or no access to source or destination)."
set "ROBOCOPY_EXIT_8_SEVERITY=FAIL"
set "ROBOCOPY_EXIT_8_TEXT=Some files or directories could not be copied (see ERROR lines above)."
set "ROBOCOPY_EXIT_4_SEVERITY=FAIL"
set "ROBOCOPY_EXIT_4_TEXT=Mismatched files or directories (a file and a directory share a name): those items were not copied."
set "ROBOCOPY_EXIT_2_SEVERITY=WARN"
set "ROBOCOPY_EXIT_2_TEXT=Extra files or directories in the destination that are not in the source."
set "ROBOCOPY_EXIT_1_SEVERITY=INFO"
set "ROBOCOPY_EXIT_1_TEXT=Files were copied."
rem Bits whose severity is FAIL, as a mask for the verdict (16 + 8 + 4).
set "ROBOCOPY_FAIL_MASK=28"

rem Source and destination folders are containers, not evidence: their own
rem attributes are never carried across. Robocopy copies the source folder's
rem attributes onto the destination folder; these are cleared again unless
rem the destination folder already had them. With Read-only or System set,
rem Explorer applies a copied desktop.ini, so the destination would show the
rem source folder's name and icon (e.g. Downloads). Fields per row, separated
rem by ":": position in a FOR %%~a attribute string, attrib letter, name.
set "CONTAINER_ATTRIBUTES=1:r:Read-only 3:h:Hidden 4:s:System"

rem The script travels with the evidence (expected layout: the evidence, the
rem script's logs and the script, together in one folder). A copy of the
rem script at a source or destination root is a custody tool, like the logs,
rem not evidence: root files named SCRIPT_FILE_PREFIX*SCRIPT_FILE_EXT are left
rem out of the source hash record and counted as custody records in the
rem destination (so updating the script never fails a later copy). They are
rem still copied, and covered by the metadata check.
set "SCRIPT_FILE_PREFIX=evidence-robocopy"
set "SCRIPT_FILE_EXT=.bat"

rem SHA-256 of zero bytes. certutil -hashfile fails on empty files, so a file
rem that certutil can't hash but whose size is 0 gets this value.
set "EMPTY_SHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

rem Ordered fallbacks: each name is a helper (:utc_from_<name> or
rem :elevation_check_<name>), tried in turn until one succeeds. Pure batch and
rem built-in tools only. The robocopy clock works on every Windows version
rem with robocopy (Vista and later); wmic is deprecated and absent by default
rem from Windows 11 24H2.
set "UTC_METHODS=robocopy wmic"
set "ELEVATION_CHECKS=fsutil net"

rem Power settings that can stop a long copy, read with "powercfg /q" (no admin
rem needed). One row per setting, "subgroup:setting" aliases. The earliest
rem non-zero timeout of these, on mains (AC) and on battery (DC), is reported.
set "SLEEP_SETTINGS=SUB_SLEEP:STANDBYIDLE SUB_SLEEP:HIBERNATEIDLE"
rem A timeout of 0, a negative value, or more than this many seconds counts as
rem Never: depending on the Windows version, Settings stores "Never" as 0 or
rem as a huge sentinel (seen: about 0x7FFFFFFF). No copy runs for a year.
set "SLEEP_NEVER_ABOVE_SECONDS=31536000"

rem File systems recognised in fsutil / chkntfs output (matched as whole words,
rem so it works in any display language), and the ways to read a volume's
rem file system, tried in order (each is a :filesystem_from_<name> helper).
set "KNOWN_FILESYSTEMS=NTFS ReFS exFAT FAT32 FAT UDF CDFS"
set "FILESYSTEM_METHODS=fsutil chkntfs"

rem Destination file systems that get a warning
rem (FILESYSTEM_WARNING_<name>=reason).
set "FILESYSTEM_WARNING_FAT32=FAT32 can't hold files of 4 GiB or more, and keeps timestamps to 2 s only."
set "FILESYSTEM_WARNING_FAT=FAT can't hold files of 2 GiB or more, and keeps timestamps to 2 s only."

rem Invalid answers allowed per prompt before the run aborts. Stops an endless
rem loop when there is no console input (e.g. input redirected or closed).
set "MAX_PROMPT_ATTEMPTS=10"

rem Final verdicts and their exit codes.
set "EXIT_CODE_PASS=0"
set "EXIT_CODE_FAIL=1"
set "EXIT_CODE_UNVERIFIED=2"

rem =============================== MAIN ======================================

if "%~1"=="/?" goto :show_help
set "script_path=%~f0"
set "script_file_name=%~nx0"
set "script_dir=%~dp0"

call :init_state
call :parse_args "%~1" "%~2" || goto :abort
call :show_banner
call :check_robocopy || goto :abort
call :detect_elevation
rem Forensic mode (the default) always keeps a log and verifies, without
rem asking. Only /nonforensic asks about either.
if "%run_mode%"=="forensic" call :use_log_mode
if "%run_mode%"=="forensic" set "verification_enabled=1"
if "%run_mode%"=="nonforensic" call :ask_progress_mode || goto :abort
call :ask_paths || goto :abort
if "%run_mode%"=="nonforensic" call :ask_verification || goto :abort
call :init_run || goto :abort
call :hash_this_script
call :check_environment
call :write_header
for %%P in (%COPY_PASSES%) do call :run_copy_pass %%P
call :restore_destination_attributes
if "%verification_enabled%"=="1" call :verify_copy
call :stage_script_copy
call :report_result
call :write_seal
call :publish_records
call :cleanup_temp
pause
exit /b %exit_code%

rem ============================ FUNCTIONS ====================================

rem --------------------------- Run steps -------------------------------------

:show_help
echo %TOOL_NAME% %TOOL_VERSION%
echo.
echo Copies the CONTENTS of a source folder (digital evidence of any kind) into a
echo destination folder with robocopy, keeping data, attributes and timestamps,
echo then verifies every file by SHA-256 and by size and last-modified time.
echo The two folders are containers, not evidence: their own attributes are not
echo carried across.
echo Run as administrator to use backup mode (/b).
echo.
echo Default (forensic mode): a log file is kept and every file is verified by
echo SHA-256; the script asks only for the source and destination.
echo /nonforensic: also asks whether to keep a log (or show ETA instead) and
echo whether to verify, each with a confirmation, for non-evidence copies.
echo The script is meant to travel with the evidence: run from the evidence
echo folder, Enter at the source prompt picks that folder. Run
echo from elsewhere, it puts a copy of itself beside the logs in the
echo destination, unless the source already holds one.
echo Output in the destination root (timestamps are UTC):
echo   robocopy_YYYYMMDDTHHMMSSZ.log                     (log mode only)
echo   robocopy_YYYYMMDDTHHMMSSZ_hashes_source.csv       (only if the source has none)
echo   robocopy_YYYYMMDDTHHMMSSZ_hashes_destination.csv
echo   robocopy_YYYYMMDDTHHMMSSZ.sha256                  (seal: hashes of the above)
echo Verification compares the destination with the reference record: the
echo oldest source hash record in the source or, if it holds none, the source
echo hashed now. Every file in it must be in the destination, unchanged, and
echo every copied file must match its source in size and last-modified time.
echo A reference record carried with the evidence must still match its seal.
echo Files and records are written unbuffered (robocopy /j), so verification
echo reads them back from the drive, not from the Windows cache.
echo.
echo Exit codes: %EXIT_CODE_PASS% PASS, %EXIT_CODE_FAIL% FAIL, %EXIT_CODE_UNVERIFIED% UNVERIFIED (copied, not verified).
exit /b 0

:init_state
rem Counters and flags used across the run, all given a starting value here.
rem   copy_exit_codes            robocopy exit codes of all passes, OR-ed
rem   hashed_count_<side>        files hashed in the source / destination
rem   unexpected_listing_lines   listing lines that weren't a path in the folder
rem   hash_check_incomplete      1 if a listing, certutil or the reference
rem                              record was unavailable
rem   metadata_differ_count      files the metadata check listed
rem   metadata_check_incomplete  1 if the metadata check itself failed
rem   metadata_check_ran         defined once the metadata check has run
rem   reference_row_count        rows read from the reference record
rem   match_count                reference files in the destination with the
rem                              same SHA-256
rem   differ_count               reference files whose SHA-256 differs
rem   missing_count              reference files not in the destination
rem   unreadable_count           reference files that couldn't be hashed in
rem                              the destination
rem   invalid_row_count          reference rows without a valid hash, or a
rem                              path listed twice
rem   added_record_count         custody records added since the reference
rem                              record (logs, CSVs, seals, script copies)
rem   added_other_count          other files added since the reference record
rem   reference_seal_failed      1 if the reference record fails its seal check
rem   utc_clock_failed           1 if no UTC_METHODS worked (see :get_utc_now)
for %%V in (copy_exit_codes hashed_count_source hashed_count_destination unexpected_listing_lines hash_check_incomplete) do set "%%V=0"
for %%V in (metadata_differ_count metadata_check_incomplete reference_row_count match_count differ_count missing_count) do set "%%V=0"
for %%V in (unreadable_count invalid_row_count added_record_count added_other_count reference_seal_failed utc_clock_failed) do set "%%V=0"
set "metadata_check_ran="
set "metadata_time_precision=exact"
set "log_ready="
set "exit_code=%EXIT_CODE_FAIL%"
set "result_script_copy=not attempted"
set "staged_script_copy_path="
set "staging_dir="
set "source_record_name="
set "reference_name="
set "reference_csv_path="
set "reference_seal_result_text="
set "reference_seal_missing_warned="
exit /b 0

:parse_args  arg1  arg2
rem Forensic mode unless /nonforensic is given. Anything else (an unknown
rem option, a folder dropped on the script, a second argument) stops the run,
rem so a typo can't silently fall back to a different mode than intended.
set "run_mode=forensic"
if /i "%~1"=="/nonforensic" set "run_mode=nonforensic"
if "%run_mode%"=="forensic" if not "%~1"=="" (
    set "abort_reason=Unknown option. Run with /? for the options."
    exit /b 1
)
if not "%~2"=="" (
    set "abort_reason=Too many options. Run with /? for the options."
    exit /b 1
)
if "%run_mode%"=="forensic" (
    set "header_mode=forensic (default): log file and SHA-256 verification"
) else (
    set "header_mode=non-forensic (/nonforensic): log and verification chosen at the prompts"
)
exit /b 0

:show_banner
echo Script: %TOOL_NAME%
echo Version: %TOOL_VERSION%
echo Author: outis
echo Licence: 0BSD
echo.
echo Note: real-time antivirus scanning, where active, scans each file as it
echo       is written: it slows copies of many small files, and a file it
echo       quarantines fails verification as MISSING.
echo Tip: don't click inside this window while it runs: a QuickEdit selection
echo      pauses the copy until you press Esc.
echo.
exit /b 0

:check_robocopy
where /q robocopy.exe && exit /b 0
set "abort_reason=robocopy.exe was not found."
exit /b 1

:detect_elevation
rem Elevated if any check in ELEVATION_CHECKS succeeds; unknown counts as not
rem elevated. An elevated run uses robocopy's backup mode (/b).
set "is_elevated="
set "elevation_detected_by=none"
for %%M in (%ELEVATION_CHECKS%) do if not defined is_elevated call :elevation_check_%%M && (
    set "is_elevated=1"
    set "elevation_detected_by=%%M"
)
if defined is_elevated (
    set "backup_flag=/b"
    set "header_elevated=yes (detected by %elevation_detected_by%), backup mode /b"
    echo You are running as Administrator. Backup mode lets robocopy read files
    echo regardless of their permissions, but may be slower.
) else (
    set "backup_flag="
    set "header_elevated=no"
    echo You are not running as Administrator. Files your account can't read
    echo will fail to copy.
)
echo.
exit /b 0

:elevation_check_fsutil
fsutil dirty query %SystemDrive% >nul 2>&1
exit /b %errorlevel%

:elevation_check_net
net session >nul 2>&1
exit /b %errorlevel%

:use_log_mode
rem Keep a log file. /np /tee: no progress figures, output to console and log.
set "log_enabled=1"
set "robocopy_progress_flags=/np /tee"
set "header_progress=log file (/np /tee)"
exit /b 0

:use_eta_mode
rem Show ETA and percentage (/eta) and keep no log file: not a custody record.
set "log_enabled=0"
set "robocopy_progress_flags=/eta"
set "header_progress=ETA and percentage, no log file (/eta): not a custody record"
exit /b 0

:init_run
rem Fix the run's UTC timestamp and output paths, and create the destination
rem folder, the staging folder and, in log mode, the working log. This run's
rem custody records (log, hash CSVs, seal, script copy) are written to the
rem staging folder in TEMP and put into the destination at the end
rem (:publish_records): inside the destination, robocopy would count the log
rem as an extra file (exit bit 2), and hashing would list the records.
call :get_utc_now
set "start_utc_iso=%utc_iso%"
set "start_utc_source=%utc_method%"
set "run_utc_stamp=%utc_compact%"
set "log_file_name=robocopy_%run_utc_stamp%.log"
set "log_destination_path=%destination_with_backslash%%log_file_name%"
set "log_destination_text=%log_destination_path%"
rem Temporary folder for working files and the staging folder, in order:
rem TEMP, TMP, LOCALAPPDATA\Temp. Never the destination: files there would be
rem hashed as evidence.
set "temp_dir="
if defined TEMP if exist "%TEMP%\" set "temp_dir=%TEMP%"
if not defined temp_dir if defined TMP if exist "%TMP%\" set "temp_dir=%TMP%"
if not defined temp_dir if defined LOCALAPPDATA if exist "%LOCALAPPDATA%\Temp\" set "temp_dir=%LOCALAPPDATA%\Temp"
if not defined temp_dir (
    set "abort_reason=No temporary folder found (TEMP, TMP or LOCALAPPDATA\Temp)."
    exit /b 1
)
set "temp_path_prefix=%temp_dir%\%TOOL_NAME%_%run_utc_stamp%_%RANDOM%"
set "temp_file_list=%temp_path_prefix%_list.tmp"
set "temp_metadata_list=%temp_path_prefix%_metadata.tmp"
set "temp_hash_rows_source=%temp_path_prefix%_source.tmp"
set "temp_hash_rows_destination=%temp_path_prefix%_destination.tmp"
set "temp_compare_lines=%temp_path_prefix%_compare.tmp"
set "temp_compare_lines_sorted=%temp_path_prefix%_compare_sorted.tmp"
set "temp_problems=%temp_path_prefix%_problems.tmp"
set "temp_warnings=%temp_path_prefix%_warnings.tmp"
set "temp_clock_status=%temp_path_prefix%_clock.tmp"
set "temp_housekeeping_source=%temp_path_prefix%_housekeeping_source.tmp"
set "temp_housekeeping_destination=%temp_path_prefix%_housekeeping_destination.tmp"
set "staging_dir=%temp_path_prefix%_records"
set "log_staged_path=%staging_dir%\%log_file_name%"
set "staged_hash_csv_source=%staging_dir%\robocopy_%run_utc_stamp%_hashes_source.csv"
set "staged_hash_csv_destination=%staging_dir%\robocopy_%run_utc_stamp%_hashes_destination.csv"
set "seal_file_name=robocopy_%run_utc_stamp%.sha256"
set "staged_seal_path=%staging_dir%\%seal_file_name%"
if "%verification_enabled%"=="1" call :find_source_hash_record
set "destination_attributes_before="
if exist "%destination_with_backslash%" for %%A in ("%destination_path%") do set "destination_attributes_before=%%~aA"
if not exist "%destination_with_backslash%" mkdir "%destination_path%" >nul 2>&1
if not exist "%destination_with_backslash%" (
    set "abort_reason=Could not create the destination directory."
    exit /b 1
)
mkdir "%staging_dir%" >nul 2>&1
if not exist "%staging_dir%\" (
    set "abort_reason=Could not create the staging folder in the temporary folder."
    exit /b 1
)
if not "%log_enabled%"=="1" (
    set "log_destination_text=none (ETA mode)"
    exit /b 0
)
(type nul >>"%log_staged_path%") 2>nul || (
    set "abort_reason=Could not create the working log in the temporary folder."
    exit /b 1
)
set "log_ready=1"
exit /b 0

:hash_this_script
rem The SHA-256 of this script file: shown in the header, and the value the
rem script copy placed by :stage_script_copy must match.
set "script_sha256="
call :get_sha256 script_path script_sha256
if not defined script_sha256 set "script_sha256=unknown"
exit /b 0

:write_header
rem Write the run header: the warnings first, then three sections:
rem environment, source, destination.
call :format_utc_offset local_utc_offset
call :describe_windows header_os
set "robocopy_path="
for /f "delims=" %%R in ('where robocopy.exe 2^>nul') do if not defined robocopy_path set "robocopy_path=%%R"
set "certutil_path="
for /f "delims=" %%C in ('where certutil.exe 2^>nul') do if not defined certutil_path set "certutil_path=%%C"
if not defined certutil_path set "certutil_path=not found"
set "header_script=%TOOL_NAME% %TOOL_VERSION%"
set "header_started=%start_utc_iso% (source: %start_utc_source%)"
set "header_utc_offset=%local_utc_offset% (robocopy's Started/Ended times are local; its file times are UTC)"
call :describe_user header_user
call :describe_host header_host
set "header_excluded=volume housekeeping at a drive root only (see Source and Destination)"
set "header_retries=%RETRY_COUNT% x %RETRY_WAIT_SECONDS% s"
if "%verification_enabled%"=="1" (set "header_verify=SHA-256 hash and metadata (size, last-modified time), every file") else set "header_verify=no"
set "header_hash_record=not used (no verification)"
if "%verification_enabled%"=="1" set "header_hash_record=none found in the source root: the source is hashed and becomes the reference record"
if defined source_record_name set "header_hash_record=%source_record_name% (oldest in the source; the destination is checked against it)"
set "warning_count=0"
if exist "%temp_warnings%" for /f "usebackq delims=" %%L in ("%temp_warnings%") do set /a "warning_count+=1"
set "msg================================================================================" & call :show_and_log msg
set "msg=Warnings (read before relying on this copy)" & call :show_and_log msg
if %warning_count% equ 0 (
    set "msg=  none"
    call :show_and_log msg
) else for /f "usebackq delims=" %%L in ("%temp_warnings%") do (
    set "msg=  %%L"
    call :show_and_log msg
)
set "msg=" & call :show_and_log msg
set "msg=Environment" & call :show_and_log msg
call :log_field "Script" header_script
call :log_field "Script path" script_path
call :log_field "Script SHA-256" script_sha256
call :log_field "Mode" header_mode
call :log_field "Started (UTC)" header_started
call :log_field "Local UTC offset" header_utc_offset
call :log_field "Time source" header_time_source
call :log_field "Last time sync" header_last_sync
call :log_field "Host" header_host
call :log_field "User" header_user
call :log_field "OS" header_os
call :log_field "Elevated" header_elevated
call :log_field "robocopy" robocopy_path
call :log_field "certutil" certutil_path
call :log_field "Sleep when idle" header_sleep
call :log_field "Excluded" header_excluded
call :log_field "Retries" header_retries
call :log_field "Progress" header_progress
call :log_field "Verify" header_verify
call :log_field "Writes" header_writes
set "msg=" & call :show_and_log msg
set "msg=Source" & call :show_and_log msg
call :log_field "Contents of" source_with_backslash
call :log_field "Chosen" source_chosen_how
call :log_field "Volume" header_source_volume
call :log_field "Hash record" header_hash_record
call :log_housekeeping source "Skipped at root"
set "msg=" & call :show_and_log msg
set "msg=Destination" & call :show_and_log msg
call :log_field "Copied into" destination_with_backslash
call :log_field "Was" destination_state_text
call :log_field "Volume" header_destination_volume
call :log_housekeeping destination "Left alone at root"
call :log_field "Log" log_destination_text
if "%log_enabled%"=="1" call :log_field "Log during run" log_staged_path
set "msg================================================================================" & call :show_and_log msg
exit /b 0

:run_copy_pass  passId
rem One robocopy pass as defined by the PASS_<passId>_* row in CONFIG.
setlocal EnableDelayedExpansion
set "label=!PASS_%~1_LABEL!"
set "threads=!PASS_%~1_THREADS!"
if /i "!threads!"=="auto" call :auto_thread_count threads
set "exclusion_args="
call :add_housekeeping_exclusions source
call :add_housekeeping_exclusions destination
set "msg=" & call :show_and_log msg
set "msg=--- Copy pass: !label!, threads: !threads! ---" & call :show_and_log msg
set "log_option="
if "!log_enabled!"=="1" set log_option=/log+:"!log_staged_path!"
robocopy "!source_path! " "!destination_path! " *.* !COPY_FLAGS! !PASS_%~1_FILTER! !PASS_%~1_FLAGS! /mt:!threads! /r:!RETRY_COUNT! /w:!RETRY_WAIT_SECONDS! !robocopy_progress_flags! !backup_flag! !exclusion_args! !log_option!
set "pass_exit_code=!errorlevel!"
call :report_robocopy_exit_code pass_exit_code
endlocal & set /a "copy_exit_codes|=%pass_exit_code%" & exit /b 0

:restore_destination_attributes
rem Undo container attributes (CONTAINER_ATTRIBUTES) that robocopy carried from
rem the source folder onto the destination folder itself (not its contents).
rem A destination drive root is left alone.
if "%destination_path:~-1%"=="\" exit /b 0
setlocal EnableDelayedExpansion
rem A FOR %%~a attribute string has one position per attribute, "-" if not
rem set. A destination that didn't exist before had none of them.
set "attributes_before=!destination_attributes_before!"
if not defined attributes_before set "attributes_before=-----------"
set "attributes_after_copy="
for %%A in ("!destination_path!") do set "attributes_after_copy=%%~aA"
set "attrib_switches="
set "cleared_names="
rem Each row of CONTAINER_ATTRIBUTES: %%I position, %%J attrib letter, %%K name.
for %%R in (%CONTAINER_ATTRIBUTES%) do for /f "tokens=1-3 delims=:" %%I in ("%%R") do (
    if /i "!attributes_after_copy:~%%I,1!"=="%%J" if "!attributes_before:~%%I,1!"=="-" (
        set "attrib_switches=!attrib_switches! -%%J"
        set "cleared_names=!cleared_names! %%K"
    )
)
set "msg=" & call :show_and_log msg
if not defined attrib_switches (
    set "msg=Destination folder attributes unchanged."
    call :show_and_log msg
    endlocal & exit /b 0
)
attrib !attrib_switches! "!destination_path!" >nul 2>&1
set "attributes_now="
for %%A in ("!destination_path!") do set "attributes_now=%%~aA"
set "msg=Destination folder: cleared!cleared_names! (carried over from the source folder)."
call :show_and_log msg
for %%R in (%CONTAINER_ATTRIBUTES%) do for /f "tokens=1-3 delims=:" %%I in ("%%R") do (
    if /i "!attributes_now:~%%I,1!"=="%%J" if "!attributes_before:~%%I,1!"=="-" (
        set "msg=[WARN] Could not clear %%K on the destination folder."
        call :show_and_log msg
        call :remember_problem msg
    )
)
endlocal & exit /b 0

:verify_copy
rem Check the copy: first the metadata (size and last-modified time), then the
rem SHA-256 of every file against the reference record. The reference record
rem is the oldest hash record found in the source or, if the source holds
rem none, this run's own record of the source, made now. So the source is
rem hashed once per evidence set, and every later copy is checked back to it.
set "msg=" & call :show_and_log msg
set "msg=--- Verification: metadata and SHA-256 hashes ---" & call :show_and_log msg
call :check_metadata
where /q certutil.exe || (
    set "msg=[FAIL] certutil.exe not found: verification could not run."
    call :show_and_log msg
    call :remember_problem msg
    set "hash_check_incomplete=1"
    exit /b 1
)
if not defined source_record_name (
    set "msg=" & call :show_and_log msg
    set "msg=--- Hashing the source (no hash record found in the source root): it becomes the reference record ---"
    call :show_and_log msg
    call :hash_folder source || set "hash_check_incomplete=1"
    call :write_hash_csv source
)
set "msg=" & call :show_and_log msg
set "msg=--- Hashing the destination ---" & call :show_and_log msg
call :hash_folder destination || set "hash_check_incomplete=1"
call :write_hash_csv destination
rem The reference record: the one found in the source, now read from its
rem copy in the destination; otherwise this run's own record of the source.
set "reference_name=robocopy_%run_utc_stamp%_hashes_source.csv"
set "reference_csv_path=%staged_hash_csv_source%"
if defined source_record_name set "reference_name=%source_record_name%"
if defined source_record_name set "reference_csv_path=%destination_with_backslash%%source_record_name%"
if not exist "%reference_csv_path%" (
    set "msg=[FAIL] The reference record %reference_name% was not found after the copy."
    call :show_and_log msg
    call :remember_problem msg
    set "hash_check_incomplete=1"
    exit /b 1
)
call :check_reference_seal
call :compare_with_reference
exit /b 0

:check_metadata
rem Compare size and last-modified time of every source file with its copy,
rem using robocopy's own comparison (see METADATA_FLAGS). Every file it lists
rem differs or is missing. Sets metadata_differ_count,
rem metadata_check_incomplete, metadata_time_precision, metadata_check_ran.
setlocal EnableDelayedExpansion
set "fft_flag="
set "time_precision=exact"
for %%F in (%COARSE_TIME_FILESYSTEMS%) do (
    if /i "!source_filesystem!"=="%%F" set "fft_flag=/fft"
    if /i "!destination_filesystem!"=="%%F" set "fft_flag=/fft"
)
if defined fft_flag set "time_precision=to 2 s, as FAT/exFAT is involved"
set "msg=" & call :show_and_log msg
set "msg=--- Metadata check: size and last-modified time, compared !time_precision! ---"
call :show_and_log msg
set "exclusion_args="
call :add_housekeeping_exclusions source
call :add_housekeeping_exclusions destination
robocopy "!source_path! " "!destination_path! " *.* !METADATA_FLAGS! !fft_flag! !backup_flag! !exclusion_args! >"!temp_metadata_list!" 2>&1
set "check_exit_code=!errorlevel!"
set "incomplete=0"
if !check_exit_code! geq 8 (
    set "msg=[FAIL] The metadata check could not compare every file (robocopy exit code !check_exit_code!)."
    call :show_and_log msg
    call :remember_problem msg
    set "incomplete=1"
)
endlocal & set "metadata_check_incomplete=%incomplete%" & set "metadata_time_precision=%time_precision%" & set "metadata_check_ran=1"
for /f "usebackq tokens=*" %%L in ("%temp_metadata_list%") do (
    set "listed_line=%%L"
    call :report_metadata_difference listed_line
)
exit /b 0

:report_metadata_difference  lineVar
rem One file listed by the metadata check: it differs from its source.
setlocal EnableDelayedExpansion
set "full_path=!%~1!"
call :relative_path full_path source_with_backslash file_relative_path || (
    set "msg=[FAIL] Unexpected line in the metadata check: !full_path!"
    call :show_and_log msg
    call :remember_problem msg
    endlocal & set /a "unexpected_listing_lines+=1" & exit /b 0
)
set "msg=[FAIL] METADATA differs (size or last-modified time), or not copied: !file_relative_path!"
call :show_and_log msg
call :remember_problem msg
endlocal & set /a "metadata_differ_count+=1" & exit /b 0

:hash_folder  side
rem List every file in the side's folder (with robocopy) and hash each one
rem into the side's rows. Exit 1 if the listing was incomplete.
set "hash_folder_listing_failed="
call :list_files %~1 temp_file_list || set "hash_folder_listing_failed=1"
rem Total for the progress counter: the listing read the same way as the
rem hashing loop below (FOR /F skips robocopy's blank lines, which a line
rem count would include), less the script copies left out of the source.
set "files_to_hash_count=0"
for /f "usebackq tokens=*" %%L in ("%temp_file_list%") do set /a "files_to_hash_count+=1"
if "%~1"=="source" for /f "eol=/ delims=" %%F in ('dir /b /a-d "%source_with_backslash%%SCRIPT_FILE_PREFIX%*%SCRIPT_FILE_EXT%" 2^>nul') do set /a "files_to_hash_count-=1"
for /f "usebackq tokens=*" %%L in ("%temp_file_list%") do (
    set "listed_line=%%L"
    call :hash_listed_file listed_line %~1 %files_to_hash_count%
)
if defined hash_folder_listing_failed exit /b 1
exit /b 0

:report_result
rem Work out the overall result from each check, write the summary and set
rem exit_code. The summary states what the result covers, so it can't be
rem misread later.
call :get_utc_now
set "end_utc_iso=%utc_iso%"
set /a "copy_failed_bits=copy_exit_codes & ROBOCOPY_FAIL_MASK"
set "copy_status=PASS"
if %copy_failed_bits% neq 0 set "copy_status=FAIL"
set "result_copy=%copy_status% (robocopy exit codes combined: %copy_exit_codes%)"
set "metadata_status=NOT RUN"
set "hash_status=NOT RUN"
set "result_metadata=NOT RUN: verification was not requested"
set "result_hash=NOT RUN: verification was not requested"
set "result_hash_detail="
set "result_reference=none"
if "%verification_enabled%"=="1" call :work_out_verification_status
rem The verdict: FAIL if the copy or any check failed (with verification on,
rem a check that didn't pass counts as failed); UNVERIFIED if the copy passed
rem but nothing was verified; otherwise PASS.
set "verdict=PASS"
if not "%copy_status%"=="PASS" set "verdict=FAIL"
if "%verification_enabled%"=="1" if not "%metadata_status%"=="PASS" set "verdict=FAIL"
if "%verification_enabled%"=="1" if not "%hash_status%"=="PASS" set "verdict=FAIL"
if not "%verification_enabled%"=="1" if "%verdict%"=="PASS" set "verdict=UNVERIFIED"
if "%verdict%"=="PASS" set "result_meaning=The copy completed, every file in the reference record is in the destination with the same SHA-256, and size and last-modified time match the source"
if "%verdict%"=="UNVERIFIED" set "result_meaning=The copy completed without errors, but was not verified (no SHA-256 or metadata check)"
if "%verdict%"=="FAIL" call :describe_failure
if "%verdict%"=="PASS" set "exit_code=%EXIT_CODE_PASS%"
if "%verdict%"=="FAIL" set "exit_code=%EXIT_CODE_FAIL%"
if "%verdict%"=="UNVERIFIED" set "exit_code=%EXIT_CODE_UNVERIFIED%"
set "result_overall=%verdict% (exit code %exit_code%)"
set "msg=" & call :show_and_log msg
set "msg================================================================================" & call :show_and_log msg
set "msg=Result" & call :show_and_log msg
call :log_field "Finished (UTC)" end_utc_iso
call :log_field "Script copy" result_script_copy
call :log_field "Reference record" result_reference
if defined reference_seal_result_text call :log_field_continued reference_seal_result_text
call :log_field "Log" log_destination_text
set "msg=" & call :show_and_log msg
rem The overall result, each check that feeds into it in the order they ran,
rem and what the result covers.
call :log_result_line "OVERALL RESULT" result_overall
call :log_check_line "Copy (robocopy)" result_copy
call :log_check_line "Metadata" result_metadata
call :log_check_line "Hash (SHA-256)" result_hash result_hash_detail
call :show_and_log result_meaning
set "msg================================================================================" & call :show_and_log msg
call :show_problems
exit /b 0

:describe_failure
rem The closing line of a FAIL summary: each failed check, in the order they
rem ran, then a pointer to the problems.
set "result_meaning="
if not "%copy_status%"=="PASS" call :add_failure_clause "The copy failed" "the copy failed"
if "%verification_enabled%"=="1" if not "%metadata_status%"=="PASS" call :add_failure_clause "The metadata check failed" "the metadata check failed"
if "%verification_enabled%"=="1" if not "%hash_status%"=="PASS" call :add_failure_clause "The SHA-256 verification failed" "the SHA-256 verification failed"
call :add_failure_clause "See the problems listed" "see the problems listed"
exit /b 0

:add_failure_clause  asFirstClause  asLaterClause
rem Append one clause to result_meaning: the first clause starts the
rem sentence; later ones follow "; ".
if defined result_meaning (set "result_meaning=%result_meaning%; %~2") else set "result_meaning=%~1"
exit /b 0

:abort
echo.
echo [FAIL] %abort_reason%
if defined log_ready (
    set "msg=[FAIL] Run aborted: %abort_reason%"
    call :show_and_log msg
)
call :publish_records
call :cleanup_temp
pause
exit /b %EXIT_CODE_FAIL%

rem --------------------------- Environment ------------------------------------

:check_environment
rem Run every check an analyst should know about before relying on the copy,
rem and collect the results as one list of warnings (:add_warning). The list
rem heads the log header and is repeated in the summary.
call :check_power
call :read_clock_status
call :describe_volume "%source_path:~0,2%" header_source_volume source_filesystem
call :describe_volume "%destination_path:~0,2%" header_destination_volume destination_filesystem
if "%utc_clock_failed%"=="1" (
    set "msg=No UTC time source worked: output names use a placeholder, and times are unknown."
    call :add_warning msg
)
if defined destination_filesystem if defined FILESYSTEM_WARNING_%destination_filesystem% call :warn_destination_filesystem
call :check_write_mode
call :check_recovered_fragments
call :find_drive_root_housekeeping source yes
call :find_drive_root_housekeeping destination yes
if "%verification_enabled%"=="1" if not defined source_record_name (
    set "msg=No hash record was found in the source root: the source is hashed now and becomes the reference record, so this copy is not checked against any earlier record."
    call :add_warning msg
)
if defined source_record_name call :check_reference_seal_present
if not "%destination_was_empty%"=="1" (
    set "msg=The destination was not empty (you chose to continue): robocopy overwrites same-named files that differ."
    call :add_warning msg
)
exit /b 0

:check_write_mode
rem Record whether every copy pass writes unbuffered (/j in PASS_<id>_FLAGS),
rem so that verification reads file contents back from the drive. Warn for
rem any pass that doesn't: its files may be verified from the Windows cache.
setlocal EnableDelayedExpansion
set "buffered_passes="
for %%P in (%COPY_PASSES%) do (
    set "flags= !PASS_%%P_FLAGS! "
    if "!flags: /j =!"=="!flags!" set "buffered_passes=!buffered_passes!, !PASS_%%P_LABEL!"
)
set "writes=unbuffered (robocopy /j), evidence and custody records: verification reads file contents from the drive"
if defined buffered_passes (
    set "writes=buffered for: !buffered_passes:~2!"
    set "msg=Copy pass without /j (!buffered_passes:~2!): its files may be verified from the Windows cache rather than read back from the drive."
    call :add_warning msg
)
endlocal & set "header_writes=%writes%"
exit /b 0

:check_recovered_fragments
rem Warn if the source or destination drive root holds folders of recovered
rem fragments (DRIVE_ROOT_RECOVERED_DIRS): the drive has had file-system
rem repairs.
for %%S in (source destination) do call :check_recovered_fragments_on %%S
exit /b 0

:check_recovered_fragments_on  side
rem Caller's scope: the :each_item callback adds to recovered_dirs_found.
set "recovered_dirs_found="
call :is_drive_root %~1_with_backslash || exit /b 0
if "%~1"=="source" (set "callback_drive_root=%source_with_backslash%") else set "callback_drive_root=%destination_with_backslash%"
call :each_item DRIVE_ROOT_RECOVERED_DIRS find_recovered_dirs
if not defined recovered_dirs_found exit /b 0
set "msg=The %~1 drive holds folders of fragments recovered by file-system repairs (%recovered_dirs_found%): the drive may have been damaged. They are copied as contents."
call :add_warning msg
exit /b 0

:find_recovered_dirs  pattern
rem :each_item callback: the folders matching one pattern at
rem callback_drive_root.
for /f "eol=/ delims=" %%F in ('dir /b /ad "%callback_drive_root%%~1" 2^>nul') do call :add_recovered_dir "%%F"
exit /b 0

:add_recovered_dir  name
if defined recovered_dirs_found (set "recovered_dirs_found=%recovered_dirs_found%, %~1") else set "recovered_dirs_found=%~1"
exit /b 0

:find_drive_root_housekeeping  side  recordItems
rem Find the housekeeping items present at the side's drive root, if its
rem folder is a drive root: folders matching DRIVE_ROOT_HOUSEKEEPING_DIRS and
rem files matching DRIVE_ROOT_HOUSEKEEPING_FILES. Sets housekeeping_item_count.
rem With recordItems=yes also writes them as D:"name" / F:"name" lines to
rem temp_housekeeping_<side>, which drive the exclusions
rem (:add_housekeeping_exclusions) and the log (:log_housekeeping).
rem Caller's scope: the :each_item callbacks add to the count and the list.
set "housekeeping_item_count=0"
set "housekeeping_list_file="
if "%~1"=="source" (set "callback_drive_root=%source_with_backslash%") else set "callback_drive_root=%destination_with_backslash%"
if /i "%~2"=="yes" if "%~1"=="source" set "housekeeping_list_file=%temp_housekeeping_source%"
if /i "%~2"=="yes" if "%~1"=="destination" set "housekeeping_list_file=%temp_housekeeping_destination%"
if defined housekeeping_list_file type nul >"%housekeeping_list_file%" 2>nul
call :is_drive_root %~1_with_backslash || exit /b 0
call :each_item DRIVE_ROOT_HOUSEKEEPING_DIRS find_housekeeping_dir
call :each_item DRIVE_ROOT_HOUSEKEEPING_FILES find_housekeeping_file
exit /b 0

:find_housekeeping_dir  pattern
rem :each_item callback: one folder pattern of DRIVE_ROOT_HOUSEKEEPING_DIRS at
rem callback_drive_root. An exact name is tested with IF EXIST (DIR on a
rem folder would list its contents); a pattern with * or ? is expanded with
rem DIR.
echo(%~1| findstr /r "[*?]" >nul && goto find_housekeeping_dir_wildcard
if exist "%callback_drive_root%%~1\" call :record_housekeeping_item D "%~1"
exit /b 0
:find_housekeeping_dir_wildcard
for /f "eol=/ delims=" %%F in ('dir /b /ad "%callback_drive_root%%~1" 2^>nul') do call :record_housekeeping_item D "%%F"
exit /b 0

:find_housekeeping_file  pattern
rem :each_item callback: one file pattern of DRIVE_ROOT_HOUSEKEEPING_FILES at
rem callback_drive_root.
for /f "eol=/ delims=" %%F in ('dir /b /a-d "%callback_drive_root%%~1" 2^>nul') do call :record_housekeeping_item F "%%F"
exit /b 0

:record_housekeeping_item  kind  name
rem Count one housekeeping item and, if recording, write it to the list.
set /a "housekeeping_item_count+=1"
if defined housekeeping_list_file >>"%housekeeping_list_file%" echo(%~1:"%~2"
exit /b 0

:log_housekeeping  side  label
rem Log "label : ..." for the housekeeping items skipped at the side's drive
rem root, one per line, or why there are none.
setlocal
set "text=n/a (not a drive root)"
call :is_drive_root %~1_with_backslash || (
    call :log_field "%~2" text
    endlocal & exit /b 0
)
if "%~1"=="source" (set "list_file=%temp_housekeeping_source%") else set "list_file=%temp_housekeeping_destination%"
set "item_count=0"
if exist "%list_file%" for /f "usebackq tokens=1* delims=:" %%A in ("%list_file%") do set /a "item_count+=1"
set "text=none present"
if %item_count% gtr 0 set "text=%item_count% item(s), excluded by exact path:"
call :log_field "%~2" text
if %item_count% equ 0 (endlocal & exit /b 0)
for /f "usebackq tokens=1* delims=:" %%A in ("%list_file%") do (
    set "item_name=%%~B"
    if "%%A"=="D" (set "item_kind=folder") else set "item_kind=file"
    call :log_housekeeping_line item_name item_kind
)
endlocal & exit /b 0

:log_housekeeping_line  nameVar  kindVar
setlocal EnableDelayedExpansion
set "msg=                      !%~1! (!%~2!)"
call :show_and_log msg
endlocal & exit /b 0

:add_warning  msgVar
rem Add "[WARN] <text>" to the warnings list (the first section of the log
rem header) and to the problems listed at the end of the run.
setlocal EnableDelayedExpansion
>>"!temp_warnings!" echo([WARN] !%~1!
>>"!temp_problems!" echo([WARN] !%~1!
endlocal & exit /b 0

:read_clock_status
rem Set header_time_source and header_last_sync from "w32tm /query /status",
rem and warn if the clock isn't synchronised. w32tm prints its lines in a
rem fixed order (1 leap indicator, ... 7 last successful sync time, 8
rem source), so lines are picked by position and work in any display
rem language. "Not synchronised": leap indicator 3, or a local or
rem free-running clock as the source.
set "header_time_source=unknown"
set "header_last_sync=unknown"
set "clock_unsynced_reason="
w32tm /query /status >"%temp_clock_status%" 2>&1
if errorlevel 1 (
    set "header_time_source=unavailable (time service off, or w32tm needs administrator)"
    set "msg=The clock's synchronisation could not be checked (w32tm failed): times in this record rely on this machine's clock."
    call :add_warning msg
    exit /b 0
)
set "clock_line_number=0"
for /f "usebackq delims=" %%L in ("%temp_clock_status%") do (
    set "clock_line=%%L"
    call :read_clock_line
)
if not defined clock_unsynced_reason findstr /i /c:"Local CMOS Clock" /c:"Free-running System Clock" "%temp_clock_status%" >nul 2>&1 && set "clock_unsynced_reason=w32tm reports a local clock as its source"
if defined clock_unsynced_reason (
    set "msg=The clock is not synchronised with a time source (%clock_unsynced_reason%): times in this record rely on this machine's own clock."
    call :add_warning msg
)
exit /b 0

:read_clock_line
rem Caller's scope (:read_clock_status): one line of w32tm output in
rem clock_line, numbered by clock_line_number. Keeps the value after
rem "label: ", without trailing spaces.
set /a "clock_line_number+=1"
set "clock_line_value=%clock_line:*: =%"
:read_clock_line_trim
if "%clock_line_value:~-1%"==" " (
    set "clock_line_value=%clock_line_value:~0,-1%"
    goto read_clock_line_trim
)
if %clock_line_number% equ 1 if "%clock_line_value:~0,1%"=="3" set "clock_unsynced_reason=w32tm reports leap indicator 3, not synchronised"
if %clock_line_number% equ 7 set "header_last_sync=%clock_line_value% (local time, as w32tm reports it)"
if %clock_line_number% equ 8 set "header_time_source=%clock_line_value%"
exit /b 0

:check_power
rem Warn if this machine may sleep or hibernate during the copy. Reads the
rem current power plan (SLEEP_SETTINGS, lid action). Pure batch can't read
rem whether the machine is on mains or battery right now, so the warnings
rem cover both. Sets header_sleep for the log header.
setlocal EnableDelayedExpansion
set "settings_readable=1"
set "sleep_seconds_mains=0"
set "sleep_seconds_battery=0"
for %%R in (%SLEEP_SETTINGS%) do for /f "tokens=1,2 delims=:" %%G in ("%%R") do (
    call :read_power_values %%G %%H setting
    if not defined setting_AC set "settings_readable="
    if defined setting_AC (
        if !setting_AC! gtr %SLEEP_NEVER_ABOVE_SECONDS% set "setting_AC=0"
        if !setting_DC! gtr %SLEEP_NEVER_ABOVE_SECONDS% set "setting_DC=0"
        if !setting_AC! gtr 0 if !sleep_seconds_mains! equ 0 set "sleep_seconds_mains=!setting_AC!"
        if !setting_AC! gtr 0 if !setting_AC! lss !sleep_seconds_mains! set "sleep_seconds_mains=!setting_AC!"
        if !setting_DC! gtr 0 if !sleep_seconds_battery! equ 0 set "sleep_seconds_battery=!setting_DC!"
        if !setting_DC! gtr 0 if !setting_DC! lss !sleep_seconds_battery! set "sleep_seconds_battery=!setting_DC!"
    )
)
rem Round seconds up to whole minutes without adding first (no 32-bit overflow).
set /a "minutes_mains=sleep_seconds_mains / 60, minutes_battery=sleep_seconds_battery / 60"
set /a "seconds_left_mains=sleep_seconds_mains %% 60, seconds_left_battery=sleep_seconds_battery %% 60"
if !seconds_left_mains! gtr 0 set /a "minutes_mains+=1"
if !seconds_left_battery! gtr 0 set /a "minutes_battery+=1"
set "sleep_text="
if not defined settings_readable set "sleep_text=unknown (power settings could not be read)"
if not defined sleep_text if !sleep_seconds_mains! equ 0 if !sleep_seconds_battery! equ 0 set "sleep_text=never, on mains or battery"
if not defined sleep_text if !sleep_seconds_mains! equ 0 set "sleep_text=never on mains; after !minutes_battery! min on battery"
if not defined sleep_text if !sleep_seconds_battery! equ 0 set "sleep_text=after !minutes_mains! min on mains; never on battery"
if not defined sleep_text set "sleep_text=after !minutes_mains! min on mains; after !minutes_battery! min on battery"
if not defined settings_readable (
    set "msg=The power settings could not be read: make sure this machine won't sleep or hibernate during the copy."
    call :add_warning msg
)
if defined settings_readable if !sleep_seconds_mains! gtr 0 (
    set "msg=This machine sleeps or hibernates after !minutes_mains! min idle, even on mains power: Windows may treat a long copy as idle and stop it part-way. Set sleep and hibernate to Never (Settings, System, Power)."
    call :add_warning msg
)
if defined settings_readable if !sleep_seconds_mains! equ 0 if !sleep_seconds_battery! gtr 0 (
    set "msg=On battery this machine sleeps after !minutes_battery! min idle: keep it plugged in for the whole copy."
    call :add_warning msg
)
call :read_power_values SUB_BUTTONS LIDACTION lid_action
set "lid_sleeps="
if defined lid_action_AC if !lid_action_AC! neq 0 set "lid_sleeps=1"
if defined lid_action_DC if !lid_action_DC! neq 0 set "lid_sleeps=1"
if defined lid_sleeps (
    set "msg=If this is a laptop, keep the lid open: closing it sleeps, hibernates or shuts it down."
    call :add_warning msg
)
endlocal & set "header_sleep=%sleep_text%"
exit /b 0

:read_power_values  subgroup  setting  prefix
rem Set <prefix>_AC and <prefix>_DC to the current power plan's values for a
rem setting. powercfg /q prints the setting's min, max and increment and then
rem the AC and DC values, all as 0x numbers, so the last two 0x values are AC
rem and DC in any display language. Both are cleared if it can't be read.
setlocal EnableDelayedExpansion
set "second_last_value="
set "last_value="
for /f "delims=" %%L in ('powercfg /q SCHEME_CURRENT %~1 %~2 2^>nul ^| find "0x"') do (
    set "line_last_token="
    for %%T in (%%L) do set "line_last_token=%%T"
    set "second_last_value=!last_value!"
    set "last_value=!line_last_token!"
)
set "ac_value="
set "dc_value="
if defined second_last_value set /a "ac_value=!second_last_value!, dc_value=!last_value!" 2>nul || (
    set "ac_value="
    set "dc_value="
)
endlocal & set "%~3_AC=%ac_value%" & set "%~3_DC=%dc_value%"
exit /b 0

:describe_windows  outVar
rem The OS as a person would name it: product, edition and release, e.g.
rem "Microsoft Windows 11 Pro 25H2", matching the form of WMI's Caption plus
rem release used by the PowerShell tools. "Microsoft " + registry ProductName
rem (corrected from "Windows 10" to "Windows 11" from build 22000, where the
rem registry still says 10) + DisplayVersion, or ReleaseId on older builds.
rem The build is read only for that correction, never shown.
setlocal EnableDelayedExpansion
set "registry_key=HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
for %%V in (ProductName DisplayVersion ReleaseId CurrentBuild) do (
    set "windows_%%V="
    for /f "tokens=2,*" %%A in ('reg query "!registry_key!" /v %%V 2^>nul ^| find /i "%%V"') do set "windows_%%V=%%B"
)
if not defined windows_ProductName (
    endlocal
    set "%~1=unknown (ProductName not readable)"
    exit /b 0
)
set "build=0"
set /a "build=windows_CurrentBuild" 2>nul
if !build! geq 22000 set "windows_ProductName=!windows_ProductName:Windows 10=Windows 11!"
set "release=!windows_DisplayVersion!"
if not defined release set "release=!windows_ReleaseId!"
set "text=Microsoft !windows_ProductName!"
if defined release set "text=!text! !release!"
endlocal & set "%~1=%text%"
exit /b 0

:describe_user  outVar
rem The account running the script, from its logon token ("whoami /user":
rem name and SID), not from environment variables, which can be changed in a
rem session. Falls back to USERDOMAIN\USERNAME, marked as such.
setlocal
set "user_name="
set "user_sid="
for /f "tokens=1,2 delims=," %%A in ('whoami /user /fo csv /nh 2^>nul') do (
    set "user_name=%%~A"
    set "user_sid=%%~B"
)
set "text=%USERDOMAIN%\%USERNAME% (from environment variables; whoami failed)"
if defined user_name set "text=%user_name% (SID %user_sid%)"
endlocal & set "%~1=%text%"
exit /b 0

:describe_host  outVar
rem The computer name from "hostname", falling back to COMPUTERNAME, marked.
setlocal
set "host_name="
for /f "delims=" %%H in ('hostname 2^>nul') do if not defined host_name set "host_name=%%H"
if not defined host_name set "host_name=%COMPUTERNAME% (from environment variables; hostname failed)"
endlocal & set "%~1=%host_name%"
exit /b 0

:describe_volume  drive  outVar  filesystemOutVar
rem Describe the volume of a drive ("C:") for the log: VOL's label line and
rem serial number (no admin needed), and the file system from
rem FILESYSTEM_METHODS. A network path (drive "\\") gets "n/a". Sets
rem filesystemOutVar to the file system name, or clears it if unknown.
setlocal
set "drive=%~1"
if not "%drive:~1,1%"==":" (
    endlocal
    set "%~2=n/a (network path)"
    set "%~3="
    exit /b 0
)
set "volume_label_line="
set "volume_serial=unknown"
for /f "tokens=*" %%L in ('vol %drive% 2^>nul') do if not defined volume_label_line set "volume_label_line=%%L"
for /f "skip=1 tokens=*" %%L in ('vol %drive% 2^>nul') do for %%T in (%%L) do set "volume_serial=%%T"
if not defined volume_label_line set "volume_label_line=%drive% (label unknown)"
set "filesystem_found="
for %%M in (%FILESYSTEM_METHODS%) do if not defined filesystem_found call :filesystem_from_%%M %drive%
set "filesystem_text=%filesystem_found%"
if not defined filesystem_found set "filesystem_text=file system unknown"
endlocal & set "%~2=%volume_label_line%; serial %volume_serial%; %filesystem_text%" & set "%~3=%filesystem_found%"
exit /b 0

:filesystem_from_fsutil  drive
rem Caller's scope (:describe_volume): set filesystem_found from
rem "fsutil fsinfo volumeinfo" (may need admin).
for /f "delims=" %%L in ('fsutil fsinfo volumeinfo %~1 2^>nul') do for %%T in (%%L) do for %%F in (%KNOWN_FILESYSTEMS%) do (
    if not defined filesystem_found if /i "%%~T"=="%%F" set "filesystem_found=%%F"
)
exit /b 0

:filesystem_from_chkntfs  drive
rem Caller's scope (:describe_volume): set filesystem_found from chkntfs
rem ("... file system is NTFS.").
for /f "delims=" %%L in ('chkntfs %~1 2^>nul') do for %%T in (%%L) do for %%F in (%KNOWN_FILESYSTEMS%) do (
    if not defined filesystem_found if /i "%%~T"=="%%F" set "filesystem_found=%%F"
    if not defined filesystem_found if /i "%%~T"=="%%F." set "filesystem_found=%%F"
)
exit /b 0

:warn_destination_filesystem
rem Warn about a destination file system listed in FILESYSTEM_WARNING_<name>.
rem A warning only: robocopy fails any file that doesn't fit.
setlocal EnableDelayedExpansion
set "msg=The destination file system is !destination_filesystem!: !FILESYSTEM_WARNING_%destination_filesystem%!"
call :add_warning msg
endlocal & exit /b 0

rem ------------------------- Custody records ---------------------------------

:publish_records
rem Put this run's custody records from the staging folder into the
rem destination with robocopy /j, so they go straight to the drive and never
rem overwrite a file there (/xc /xn /xo). Each one is then read back from the
rem destination and compared with its staged original by SHA-256. Only if all
rem match is the staging folder removed; otherwise it is kept and its path
rem shown, so no record is lost.
if not defined staging_dir exit /b 0
if not exist "%staging_dir%\" exit /b 0
setlocal
set "record_count=0"
set "records_matching=0"
for /f "eol=/ delims=" %%F in ('dir /b /a-d "%staging_dir%\" 2^>nul') do set /a "record_count+=1"
if %record_count% equ 0 goto publish_records_done
robocopy "%staging_dir% " "%destination_path% " *.* /j /xc /xn /xo /r:%RETRY_COUNT% /w:%RETRY_WAIT_SECONDS% /njh /njs /ndl /nfl /np >nul 2>&1
set "records_robocopy_exit_code=%errorlevel%"
for /f "eol=/ delims=" %%F in ('dir /b /a-d "%staging_dir%\" 2^>nul') do (
    set "record_name=%%F"
    call :check_record_in_destination record_name
)
if not %records_matching% equ %record_count% goto publish_records_failed
echo.
set "msg=Custody records written to the destination and read back: %records_matching% of %record_count% match."
call :show msg
if defined log_ready (
    set "msg=Log saved: %log_destination_path%"
    call :show msg
)
del /f /q "%staging_dir%\*" >nul 2>&1
:publish_records_done
rd "%staging_dir%" >nul 2>&1
endlocal & exit /b 0
:publish_records_failed
echo.
set "msg=[WARN] Only %records_matching% of %record_count% custody records reached the destination intact (robocopy exit code %records_robocopy_exit_code%). All of them are kept here:"
call :show msg
set "msg=       %staging_dir%"
call :show msg
endlocal & exit /b 1

:check_record_in_destination  nameVar
rem One staged record: add 1 to records_matching if the destination holds it
rem with the same SHA-256, else say so.
setlocal EnableDelayedExpansion
set "staged_path=!staging_dir!\!%~1!"
set "destination_copy_path=!destination_with_backslash!!%~1!"
set "staged_sha256="
set "destination_sha256="
call :get_sha256 staged_path staged_sha256
if exist "!destination_copy_path!" call :get_sha256 destination_copy_path destination_sha256
if defined staged_sha256 if /i "!staged_sha256!"=="!destination_sha256!" (endlocal & set /a "records_matching+=1" & exit /b 0)
set "msg=[WARN] Not in the destination, or it differs from the staged record: !%~1!"
call :show msg
endlocal & exit /b 0

:stage_script_copy
rem The script travels with the evidence. If the source root holds a copy of
rem it, that copy went across with the evidence. Otherwise add a copy of this
rem script to the custody records (staging folder), check it against the
rem Script SHA-256 in the header, and seal it with them. Never overwrites a
rem file in the destination.
set "script_copy_in_source="
for /f "eol=/ delims=" %%F in ('dir /b /a-d "%source_with_backslash%%SCRIPT_FILE_PREFIX%*%SCRIPT_FILE_EXT%" 2^>nul') do set "script_copy_in_source=1"
if defined script_copy_in_source (
    set "result_script_copy=not needed: the source holds a copy, copied with the evidence"
    exit /b 0
)
if exist "%destination_with_backslash%%script_file_name%" (
    set "result_script_copy=not placed: the destination already holds a file named %script_file_name%"
    set "msg=[WARN] The script was not copied to the destination: a file named %script_file_name% is already there."
    call :show_and_log msg
    call :remember_problem msg
    exit /b 0
)
set "script_copy_staged_path=%staging_dir%\%script_file_name%"
copy /b "%script_path%" "%script_copy_staged_path%" >nul 2>&1
set "script_copy_sha256="
if exist "%script_copy_staged_path%" call :get_sha256 script_copy_staged_path script_copy_sha256
if defined script_copy_sha256 if /i "%script_copy_sha256%"=="%script_sha256%" (
    set "result_script_copy=added to the custody records as %script_file_name%; its SHA-256 matches the Script SHA-256 above"
    set "staged_script_copy_path=%script_copy_staged_path%"
    exit /b 0
)
set "result_script_copy=FAILED: no verified copy of the script in the destination"
set "msg=[WARN] Could not place a verified copy of the script in the destination."
call :show_and_log msg
call :remember_problem msg
exit /b 0

:find_source_hash_record
rem Find the oldest source hash record in the source root
rem (robocopy_<UTC>_hashes_source.csv, oldest by name, as names start with the
rem UTC time; names without a timestamp are ignored). It is chosen from the
rem source, so an unrelated older record already in a non-empty destination
rem can't be picked, and read from the destination after the copy. Sets
rem source_record_name, or leaves it empty if the source holds none.
for /f "delims=" %%F in ('dir /b /a-d /on "%source_with_backslash%robocopy_*_hashes_source.csv" 2^>nul') do (
    if not defined source_record_name call :accept_if_timestamped_record "%%F"
)
exit /b 0

:accept_if_timestamped_record  fileName
rem Set source_record_name to the file name if it starts with a UTC time:
rem the character after "robocopy_" (position 9) is a digit.
set "candidate_record_name=%~1"
set "candidate_first_time_digit=%candidate_record_name:~9,1%"
if "%candidate_first_time_digit%" lss "0" exit /b 0
if "%candidate_first_time_digit%" gtr "9" exit /b 0
set "source_record_name=%candidate_record_name%"
exit /b 0

:find_reference_seal_name
rem Set reference_seal_name to the seal of the run that made the source's
rem hash record: robocopy_<UTC>.sha256, with the same UTC as the record.
set "record_utc_stamp=%source_record_name:robocopy_=%"
set "record_utc_stamp=%record_utc_stamp:_hashes_source.csv=%"
set "reference_seal_name=robocopy_%record_utc_stamp%.sha256"
exit /b 0

:check_reference_seal_present
rem Before the copy: warn up front if the source root holds no seal for the
rem source's hash record, so it can't be checked (see :check_reference_seal).
call :find_reference_seal_name
if exist "%source_with_backslash%%reference_seal_name%" exit /b 0
set "reference_seal_missing_warned=1"
set "msg=The reference record %source_record_name% has no seal in the source root (%reference_seal_name%), so it can't be checked for changes since it was made."
call :add_warning msg
exit /b 0

:check_reference_seal
rem A reference record carried with the evidence must not have changed since
rem its own run sealed it. Its seal (robocopy_<UTC>.sha256, same UTC as the
rem record) lists the record's SHA-256: they must match, or the hash
rem verification fails (reference_seal_failed). A missing seal (sets made
rem before 1.2.0) is a warning: the record can't be checked. The seal's own
rem SHA-256 is logged, to compare with the value recorded in the custody
rem notes for that run. A record made by this run is sealed at the end of
rem it: nothing to check.
if not defined source_record_name (
    set "reference_seal_result_text=made by this run; sealed at the end of it"
    exit /b 0
)
call :find_reference_seal_name
set "reference_seal_path=%destination_with_backslash%%reference_seal_name%"
set "msg=" & call :show_and_log msg
set "msg=--- Reference record vs its seal: %reference_seal_name% ---" & call :show_and_log msg
if not exist "%reference_seal_path%" (
    set "reference_seal_result_text=no seal found (%reference_seal_name%): can't be checked for changes since it was made"
    set "msg=[WARN] The reference record has no seal (%reference_seal_name%), so it can't be checked for changes since it was made."
    call :show_and_log msg
    if not defined reference_seal_missing_warned call :remember_problem msg
    exit /b 0
)
set "reference_seal_sha256="
call :get_sha256 reference_seal_path reference_seal_sha256
if not defined reference_seal_sha256 set "reference_seal_sha256=unknown"
set "reference_sha256_in_seal="
for /f "tokens=1" %%A in ('findstr /l /c:" *%reference_name%" "%reference_seal_path%" 2^>nul') do if not defined reference_sha256_in_seal set "reference_sha256_in_seal=%%A"
set "reference_sha256_now="
call :get_sha256 reference_csv_path reference_sha256_now
if not defined reference_sha256_in_seal (
    set "reference_seal_result_text=FAIL: its seal %reference_seal_name% (SHA-256 %reference_seal_sha256%) doesn't list it"
    set "msg=[FAIL] The seal %reference_seal_name% doesn't list the reference record, so it can't be shown to be unchanged."
    goto check_reference_seal_failed
)
if not defined reference_sha256_now (
    set "reference_seal_result_text=FAIL: the reference record couldn't be hashed"
    set "msg=[FAIL] The reference record couldn't be hashed to check it against its seal."
    goto check_reference_seal_failed
)
if /i not "%reference_sha256_now%"=="%reference_sha256_in_seal%" (
    set "reference_seal_result_text=FAIL: changed since it was sealed (seal %reference_seal_name%, SHA-256 %reference_seal_sha256%)"
    set "msg=[FAIL] The reference record has changed since it was sealed: its SHA-256 doesn't match %reference_seal_name%."
    goto check_reference_seal_failed
)
set "reference_seal_result_text=matches its seal %reference_seal_name% (seal SHA-256 %reference_seal_sha256%)"
set "msg=Reference record matches its seal. Seal SHA-256: %reference_seal_sha256%"
call :show_and_log msg
exit /b 0
:check_reference_seal_failed
call :show_and_log msg
call :remember_problem msg
set "reference_seal_failed=1"
exit /b 0

:compare_with_reference
rem Compare the destination with the reference record: every file in the
rem record must be in the destination with the same SHA-256. Both are written
rem as compare lines "relative path*SHA-256*REF" (from the reference record)
rem and "...*DST" (from the destination); * can't occur in Windows names.
rem Sorted ordinally (sort /L C), each path's two lines are adjacent, so one
rem pass pairs them up.
set "msg=" & call :show_and_log msg
set "msg=--- Destination vs reference record: %reference_name% ---"
call :show_and_log msg
for /f "usebackq skip=1 delims=" %%L in ("%reference_csv_path%") do (
    set "reference_row=%%L"
    call :add_reference_row reference_row
)
if not exist "%temp_compare_lines%" type nul >"%temp_compare_lines%"
sort /L C /O "%temp_compare_lines_sorted%" "%temp_compare_lines%"
set "previous_path="
set "previous_hash="
set "previous_tag="
for /f "usebackq eol=* delims=" %%L in ("%temp_compare_lines_sorted%") do (
    set "compare_line=%%L"
    call :pair_compare_line compare_line
)
call :settle_last_compare_line
exit /b 0

:add_reference_row  rowVar
rem Turn one row of the reference record ("relative path","SHA-256", maybe
rem with trailing spaces from 1.0.x) into a compare line "...*...*REF".
setlocal EnableDelayedExpansion
set "row=!%~1!"
:add_reference_row_trim
if "!row:~-1!"==" " (
    set "row=!row:~0,-1!"
    goto add_reference_row_trim
)
set "compare_entry=!row:","=*!"
set "compare_entry=!compare_entry:"=!"
rem A row without the "," separator has no "*" now ("!x:**=!" removes
rem everything up to the first "*", so it only equals x if there is none).
if "!compare_entry:**=!"=="!compare_entry!" (
    set "msg=[FAIL] Unreadable row in the reference record: !row!"
    call :show_and_log msg
    call :remember_problem msg
    endlocal & set /a "invalid_row_count+=1" & exit /b 0
)
>>"!temp_compare_lines!" echo(!compare_entry!*REF
endlocal & set /a "reference_row_count+=1" & exit /b 0

:pair_compare_line  lineVar
rem One sorted compare line ("relative path*SHA-256*REF" or "...*DST"). If it
rem has the same path as the previous line, the two are a pair: compare
rem their hashes. Otherwise the previous line had no partner: settle it alone
rem (:settle_unpaired_line), and keep this line as the new previous line.
rem Whatever was settled adds 1 to its counter (outcome_counter, a name from
rem :init_state).
setlocal EnableDelayedExpansion
set "line=!%~1!"
set "tag=!line:~-3!"
set "path_and_hash=!line:~0,-4!"
rem The hash is everything after the first "*" (paths can't contain "*").
set "hash=!path_and_hash:**=!"
call :strlen hash hash_length
set /a "cut_length=hash_length + 1"
for %%N in (!cut_length!) do set "file_path=!path_and_hash:~0,-%%N!"
set "outcome_counter="
set "keep_path=!file_path!"
set "keep_hash=!hash!"
set "keep_tag=!tag!"
if defined previous_path if "!previous_path!"=="!file_path!" (
    if "!tag!"=="REF" (
        set "reference_hash=!hash!"
        set "destination_hash=!previous_hash!"
    ) else (
        set "reference_hash=!previous_hash!"
        set "destination_hash=!hash!"
    )
    set "problem="
    if "!tag!"=="!previous_tag!" set "problem=listed twice" & set "outcome_counter=invalid_row_count"
    if not defined problem call :is_sha256 reference_hash || (set "problem=no valid hash in the reference record" & set "outcome_counter=invalid_row_count")
    if not defined problem if "!destination_hash!"=="UNREADABLE" set "problem=UNREADABLE in the destination" & set "outcome_counter=unreadable_count"
    if not defined problem if /i not "!reference_hash!"=="!destination_hash!" set "problem=DIFFERS from the reference record" & set "outcome_counter=differ_count"
    if defined problem (
        set "msg=[FAIL] !problem!: !file_path!"
        call :show_and_log msg
        call :remember_problem msg
    ) else set "outcome_counter=match_count"
    set "keep_path="
    set "keep_hash="
    set "keep_tag="
) else if defined previous_path call :settle_unpaired_line previous_path previous_tag
endlocal & set "previous_path=%keep_path%" & set "previous_hash=%keep_hash%" & set "previous_tag=%keep_tag%" & set "outcome_counter=%outcome_counter%"
if defined outcome_counter set /a "%outcome_counter%+=1"
exit /b 0

:settle_last_compare_line
rem Settle the last line if it had no partner.
if not defined previous_path exit /b 0
setlocal EnableDelayedExpansion
set "outcome_counter="
call :settle_unpaired_line previous_path previous_tag
endlocal & set "outcome_counter=%outcome_counter%"
if defined outcome_counter set /a "%outcome_counter%+=1"
exit /b 0

:settle_unpaired_line  pathVar  tagVar
rem A path found on one side only; sets outcome_counter. In the reference
rem record but not in the destination: missing (FAIL). In the destination but
rem not in the record: added since; a custody record of an earlier run
rem (robocopy_* in the root) or a script copy is expected, anything else is a
rem warning. Caller's scope, delayed expansion on.
if "!%~2!"=="REF" (
    set "msg=[FAIL] MISSING from the destination (in the reference record): !%~1!"
    call :show_and_log msg
    call :remember_problem msg
    set "outcome_counter=missing_count"
    exit /b 0
)
set "unpaired_path=!%~1!"
if "!unpaired_path:\=!"=="!unpaired_path!" if /i "!unpaired_path:~0,9!"=="robocopy_" (
    set "outcome_counter=added_record_count"
    exit /b 0
)
call :is_script_copy unpaired_path && (
    set "outcome_counter=added_record_count"
    exit /b 0
)
set "msg=[WARN] Not in the reference record (added since, so not verified against it): !unpaired_path!"
call :show_and_log msg
call :remember_problem msg
set "outcome_counter=added_other_count"
exit /b 0

:work_out_verification_status
rem Set metadata_status and hash_status (each PASS or FAIL) and the summary
rem lines for each. Anything that stopped a check from completing fails it.
rem The record the destination was compared with; if hashing stopped before
rem the comparison, the one found in the source (as in 1.5.0), else none.
set "result_reference=%reference_name%"
if not defined result_reference set "result_reference=%source_record_name%"
if not defined result_reference set "result_reference=none"
set /a "hash_problem_count=differ_count + missing_count + invalid_row_count + unreadable_count + unexpected_listing_lines + hash_check_incomplete + reference_seal_failed"
set "hash_status=PASS"
if %hash_problem_count% neq 0 set "hash_status=FAIL"
if %match_count% equ 0 set "hash_status=FAIL"
set "result_hash=%hash_status%: %match_count% of %reference_row_count% files in the reference record match the destination"
set "result_hash_detail=%differ_count% differ, %missing_count% missing, %unreadable_count% unreadable, %invalid_row_count% invalid in the record; added since: %added_record_count% custody record(s), %added_other_count% other file(s)"
if %hash_check_incomplete% neq 0 set "result_hash_detail=%result_hash_detail%; INCOMPLETE (see problems)"
if %unexpected_listing_lines% neq 0 set "result_hash_detail=%result_hash_detail%; %unexpected_listing_lines% unexpected listing line(s)"
if %reference_seal_failed% neq 0 set "result_hash_detail=%result_hash_detail%; the reference record failed its seal check"
if %hash_check_incomplete% equ 0 if %reference_row_count% equ 0 set "result_hash_detail=%result_hash_detail%; the reference record lists no files"
set "metadata_status=FAIL"
set "result_metadata=NOT RUN"
if defined metadata_check_ran set "metadata_status=PASS"
if defined metadata_check_ran set "result_metadata=PASS: size and last-modified time match for every file (compared %metadata_time_precision%)"
if %metadata_differ_count% neq 0 set "metadata_status=FAIL"
if %metadata_differ_count% neq 0 set "result_metadata=FAIL: %metadata_differ_count% file(s) differ in size or last-modified time, or were not copied"
if %metadata_check_incomplete% neq 0 set "metadata_status=FAIL"
if %metadata_check_incomplete% neq 0 set "result_metadata=FAIL: the comparison was incomplete"
exit /b 0

:is_sha256  hashVar
rem Exit 0 if the variable holds exactly 64 hex characters.
setlocal EnableDelayedExpansion
set "value=!%~1!"
if not defined value (endlocal & exit /b 1)
if not "!value:~64!"=="" (endlocal & exit /b 1)
if "!value:~63,1!"=="" (endlocal & exit /b 1)
for /f "delims=0123456789abcdefABCDEF" %%X in ("!value!") do (endlocal & exit /b 1)
endlocal & exit /b 0

:write_seal
rem Seal this run's custody records: write the SHA-256 of the log, hash CSVs
rem and script copy to robocopy_<UTC>.sha256 in the staging folder, then show
rem the seal's own SHA-256 for the user's chain-of-custody notes. With that
rem value recorded elsewhere, any later change to these records can be
rem detected. With neither a log nor hash CSVs there is no record to seal, so
rem a copy of the script alone isn't sealed either.
if not "%log_enabled%"=="1" if not "%verification_enabled%"=="1" exit /b 0
setlocal EnableDelayedExpansion
set "sealed_count=0"
for %%F in (log_staged_path staged_hash_csv_source staged_hash_csv_destination staged_script_copy_path) do (
    if defined %%F if exist "!%%F!" (
        set "record_path=!%%F!"
        set "record_sha256="
        call :get_sha256 record_path record_sha256
        for %%N in ("!record_path!") do set "record_name=%%~nxN"
        if defined record_sha256 (
            >>"!staged_seal_path!" echo(!record_sha256! *!record_name!
            set /a "sealed_count+=1"
        ) else (
            echo [WARN] Could not hash !record_name! for the seal.
        )
    )
)
if !sealed_count! equ 0 (endlocal & exit /b 0)
set "seal_sha256="
call :get_sha256 staged_seal_path seal_sha256
echo.
echo Custody records sealed in: !seal_file_name!
if defined seal_sha256 (
    echo   SHA-256: !seal_sha256!
    echo Record this value in your chain-of-custody notes: it shows whether this
    echo run's log and hash CSVs are later changed.
) else (
    echo [WARN] Could not hash the seal file.
)
endlocal & exit /b 0

rem ------------------------ Verification helpers ------------------------------

:list_files  side  outFileVar
rem Write every file in the side's folder to the out file as a full path, one
rem per line, using robocopy (sees Hidden/System files and long paths) and the
rem same drive-root exclusions as the copy. Exit 1 if robocopy reports a
rem failure.
setlocal EnableDelayedExpansion
set "exclusion_args="
call :add_housekeeping_exclusions %~1
robocopy "!%~1_with_backslash! " "!temp_path_prefix!_nonexistent" *.* !LIST_FLAGS! !backup_flag! !exclusion_args! >"!%~2!" 2>&1
set "list_exit_code=!errorlevel!"
if !list_exit_code! geq 8 (
    set "msg=[FAIL] Could not list every file under !%~1_with_backslash! (robocopy exit code !list_exit_code!)."
    call :show_and_log msg
    call :remember_problem msg
    endlocal & exit /b 1
)
endlocal & exit /b 0

:hash_listed_file  lineVar  side  total
rem Hash one listed file and record it as a "relative path","SHA-256" row for
rem the side's CSV; for the destination also as a compare line
rem "relative path*SHA-256*DST" for :compare_with_reference. total is only for
rem the progress counter. Script copies at the source root are left out
rem (custody records, not evidence).
setlocal EnableDelayedExpansion
set "full_path=!%~1!"
call :relative_path full_path %~2_with_backslash file_relative_path || (
    set "msg=[FAIL] Unexpected line while listing the %~2: !full_path!"
    call :show_and_log msg
    call :remember_problem msg
    endlocal & set /a "unexpected_listing_lines+=1" & exit /b 0
)
if "%~2"=="source" call :is_script_copy file_relative_path && (endlocal & exit /b 0)
set /a "sequence_number=hashed_count_%~2 + 1"
set "msg=[!sequence_number!/%~3] Hashing %~2: !file_relative_path!" & call :show msg
set "file_sha256="
call :get_sha256 full_path file_sha256
if not defined file_sha256 set "file_sha256=UNREADABLE"
>>"!temp_hash_rows_%~2!" echo("!file_relative_path!","!file_sha256!"
if "%~2"=="destination" >>"!temp_compare_lines!" echo(!file_relative_path!*!file_sha256!*DST
endlocal & set /a "hashed_count_%~2+=1" & exit /b 0

:write_hash_csv  side
rem Write the side's CSV (in the staging folder): header plus rows sorted by
rem relative path, so it doesn't depend on the order in which a file system
rem lists files.
setlocal EnableDelayedExpansion
>"!staged_hash_csv_%~1!" echo "File","SHA-256"
if exist "!temp_hash_rows_%~1!" sort "!temp_hash_rows_%~1!" >>"!staged_hash_csv_%~1!"
endlocal & exit /b 0

:get_sha256  pathVar  outVar
rem Set outVar to the file's SHA-256 (64 hex characters). Clear it if certutil
rem fails or prints anything else, so a failure can never look like a hash.
rem certutil can't hash empty files: a file of size 0 gets EMPTY_SHA256. The
rem size check is skipped for names containing "?" (a character the console
rem code page couldn't show), where FOR could match a different file.
setlocal EnableDelayedExpansion
set "file_path=!%~1!"
set "sha256="
for /f "skip=1 delims=" %%H in ('certutil -hashfile "!file_path!" SHA256 2^>nul') do if not defined sha256 set "sha256=%%H"
if defined sha256 set "sha256=!sha256: =!"
if defined sha256 if not "!sha256:~64!"=="" set "sha256="
if defined sha256 if "!sha256:~63,1!"=="" set "sha256="
if defined sha256 for /f "delims=0123456789abcdefABCDEF" %%X in ("!sha256!") do set "sha256="
if not defined sha256 if "!file_path:?=!"=="!file_path!" (
    set "size="
    for %%A in ("!file_path!") do set "size=%%~zA"
    if "!size!"=="0" set "sha256=!EMPTY_SHA256!"
)
endlocal & set "%~2=%sha256%"
exit /b 0

rem ---------------------------- Copy helpers ----------------------------------

:add_housekeeping_exclusions  side
rem Append "/xd" and "/xf" with the full paths of the housekeeping items
rem found at the side's drive root (temp_housekeeping_<side>) to
rem exclusion_args. Caller's scope; the caller must have delayed expansion
rem enabled. A name containing "!" can't be passed this way: that item is
rem then copied, never dropped.
set "housekeeping_exclusion_list=!temp_housekeeping_%~1!"
if not defined housekeeping_exclusion_list exit /b 0
if not exist "!housekeeping_exclusion_list!" exit /b 0
set "excluded_dirs="
set "excluded_files="
for /f "usebackq tokens=1* delims=:" %%A in ("!housekeeping_exclusion_list!") do (
    if "%%A"=="D" set "excluded_dirs=!excluded_dirs! "!%~1_with_backslash!%%~B""
    if "%%A"=="F" set "excluded_files=!excluded_files! "!%~1_with_backslash!%%~B""
)
if defined excluded_dirs set "exclusion_args=!exclusion_args! /xd!excluded_dirs!"
if defined excluded_files set "exclusion_args=!exclusion_args! /xf!excluded_files!"
exit /b 0

:auto_thread_count  outVar
rem Logical processors / THREAD_DIVISOR, kept within 1..THREAD_MAX.
setlocal
set "thread_count="
set /a "thread_count=NUMBER_OF_PROCESSORS / THREAD_DIVISOR" 2>nul
if not defined thread_count set "thread_count=1"
if %thread_count% lss 1 set "thread_count=1"
if %thread_count% gtr %THREAD_MAX% set "thread_count=%THREAD_MAX%"
endlocal & set "%~1=%thread_count%"
exit /b 0

:report_robocopy_exit_code  exitCodeVar
rem Explain each bit set in a robocopy exit code (see ROBOCOPY_EXIT_* in
rem CONFIG); anything but INFO goes on the problems list.
setlocal EnableDelayedExpansion
set /a "robocopy_exit_code=!%~1!"
set "msg=Robocopy exit code: !robocopy_exit_code!" & call :show_and_log msg
if !robocopy_exit_code! equ 0 (
    set "msg=  [INFO] No files were copied in this pass."
    call :show_and_log msg
)
for %%B in (%ROBOCOPY_EXIT_BITS%) do (
    set /a "bit_value=robocopy_exit_code & %%B"
    if !bit_value! neq 0 (
        set "msg=  [!ROBOCOPY_EXIT_%%B_SEVERITY!] !ROBOCOPY_EXIT_%%B_TEXT!"
        call :show_and_log msg
        if not "!ROBOCOPY_EXIT_%%B_SEVERITY!"=="INFO" call :remember_problem msg
    )
)
endlocal & exit /b 0

rem ------------------------------ Input --------------------------------------

:ask_progress_mode
rem /nonforensic only. Log mode and ETA mode are deliberately exclusive:
rem robocopy's progress output would make the log unreadable, so the user
rem picks one. ETA mode must be confirmed.
echo Would you prefer a log file, or ETA and percentage?
echo 1. Log file (but no ETA or percentage). Use this for evidence.
echo 2. ETA and percentage (no log file: for non-evidence copies only)
call :ask_choice progress_answer "1 2" || exit /b 1
if "%progress_answer%"=="1" (
    call :use_log_mode
    echo.
    exit /b 0
)
call :use_eta_mode
echo.
echo WARNING: ETA mode keeps no log file. This copy will leave no record and
echo cannot serve as chain of custody. Use it for non-evidence copies only.
echo 1. Continue without a log file
echo 2. Go back and choose again
call :ask_choice eta_confirm_answer "1 2" || exit /b 1
if "%eta_confirm_answer%"=="2" (
    echo.
    goto ask_progress_mode
)
echo.
exit /b 0

:ask_paths
rem Ask for the source and destination folders. Sets source_path,
rem source_with_backslash, source_chosen_how, destination_path,
rem destination_with_backslash, destination_was_empty and
rem destination_state_text.
echo The CONTENTS of the source folder are copied into the destination folder.
call :find_default_source
:ask_paths_source
echo.
call :ask_directory source "SOURCE folder" 1 1 || exit /b 1
set "source_chosen_how=entered at the prompt"
if defined default_source_taken set "source_chosen_how=the script's folder (the default, taken with Enter)"
:ask_paths_destination
echo.
call :ask_directory destination "DESTINATION folder" 0 0 || exit /b 1
call :paths_overlap && (
    echo Source and destination must not be the same, or inside each other.
    echo.
    goto ask_paths_source
)
set "destination_was_empty=1"
set "destination_state_text=empty"
call :destination_has_content || exit /b 0
echo.
echo The destination folder is not empty. Robocopy overwrites files there that
echo have the same name but a different size or timestamp.
echo 1. Continue with this destination
echo 2. Enter a different destination
call :ask_choice destination_answer "1 2" || exit /b 1
if "%destination_answer%"=="2" goto ask_paths_destination
set "destination_was_empty=0"
set "destination_state_text=NOT empty (user chose to continue)"
exit /b 0

:find_default_source
rem Offer the script's own folder as the default source when it holds
rem anything besides the script (evidence, logs and script kept together).
set "default_source_path="
set "normalise_path_input=%script_dir%"
call :normalise_path || exit /b 0
set "script_folder_entry_count=0"
for /f "eol=/ delims=" %%E in ('dir /b /a "%normalise_path_with_backslash%" 2^>nul') do set /a "script_folder_entry_count+=1"
if %script_folder_entry_count% gtr 1 set "default_source_path=%normalise_path_result%"
exit /b 0

:destination_has_content
rem Exit 0 if the destination folder exists and holds anything other than,
rem at a drive root, the items of DRIVE_ROOT_HOUSEKEEPING_DIRS/FILES.
if not exist "%destination_with_backslash%" exit /b 1
set "destination_entry_count=0"
for /f "eol=/ delims=" %%E in ('dir /b /a "%destination_with_backslash%" 2^>nul') do set /a "destination_entry_count+=1"
call :find_drive_root_housekeeping destination no
if %destination_entry_count% gtr %housekeeping_item_count% exit /b 0
exit /b 1

:ask_verification
rem /nonforensic only. Declining verification must be confirmed.
echo.
echo Once complete, compare the SHA-256 of every file?
echo 1. Compare SHA-256. Use this for evidence.
echo 2. Do not compare hashes (not for evidence)
call :ask_choice verification_answer "1 2" || exit /b 1
if "%verification_answer%"=="1" (
    set "verification_enabled=1"
    echo.
    exit /b 0
)
set "verification_enabled=0"
echo.
echo WARNING: without verification nothing is hashed and no hash record is
echo made, so this copy cannot show that the evidence is unchanged, and later
echo copies made from it can't be checked against a reference record.
echo 1. Continue without verification
echo 2. Go back and choose again
call :ask_choice verification_confirm_answer "1 2" || exit /b 1
if "%verification_confirm_answer%"=="2" goto ask_verification
echo.
exit /b 0

:ask_choice  outVar  validChoices
rem Read input until it is one of the space-separated validChoices. Exit 1
rem (with abort_reason) after MAX_PROMPT_ATTEMPTS invalid answers.
setlocal EnableDelayedExpansion
set "attempts=0"
:ask_choice_loop
set /a "attempts+=1"
if !attempts! gtr %MAX_PROMPT_ATTEMPTS% (
    endlocal
    set "abort_reason=No valid answer after %MAX_PROMPT_ATTEMPTS% attempts (no console input?)."
    exit /b 1
)
set "answer="
set /p "answer=> "
set "chosen="
if defined answer for %%C in (%~2) do if "!answer!"=="%%C" set "chosen=%%C"
if not defined chosen (
    echo Invalid input: enter one of %~2
    goto ask_choice_loop
)
endlocal & set "%~1=%chosen%"
exit /b 0

:ask_directory  side  prompt  mustExist  allowDefault
rem Prompt with "<prompt>: " for a directory until it is valid, and set
rem <side>_path and <side>_with_backslash. With allowDefault=1,
rem default_source_path is shown on the line above the prompt and an empty
rem answer takes it (sets default_source_taken). Anything that isn't a full
rem path is simply asked again. Exit 1 (with abort_reason) after
rem MAX_PROMPT_ATTEMPTS invalid answers.
set "directory_attempts=0"
set "default_source_taken="
:ask_directory_loop
set /a "directory_attempts+=1"
if %directory_attempts% gtr %MAX_PROMPT_ATTEMPTS% (
    set "abort_reason=No valid folder after %MAX_PROMPT_ATTEMPTS% attempts (no console input?)."
    exit /b 1
)
set "normalise_path_input="
set "default_source_taken="
if "%~4"=="1" if defined default_source_path (
    set "msg=Default (the script's folder): %default_source_path%"
    call :show msg
)
set /p "normalise_path_input=%~2: "
if not defined normalise_path_input if "%~4"=="1" if defined default_source_path (
    set "normalise_path_input=%default_source_path%"
    set "default_source_taken=1"
)
call :normalise_path
if errorlevel 1 goto ask_directory_loop
if exist "%normalise_path_result%" if not exist "%normalise_path_with_backslash%" (
    echo That is a file, not a directory.
    goto ask_directory_loop
)
if "%~3"=="1" if not exist "%normalise_path_with_backslash%" (
    echo Directory not found.
    if defined is_elevated if "%normalise_path_result:~1,1%"==":" (
        echo As administrator, drive letters mapped in your normal session are not
        echo visible. For a network share, enter its UNC path: \\server\share\...
    )
    goto ask_directory_loop
)
set "%~1_path=%normalise_path_result%"
set "%~1_with_backslash=%normalise_path_with_backslash%"
exit /b 0

:normalise_path
rem Caller's scope, fixed names: IN normalise_path_input. OUT
rem normalise_path_result (full path, no trailing backslash unless a drive
rem root) and normalise_path_with_backslash (the same with exactly one
rem trailing backslash). Exit 1 if empty or not a full path: relative paths
rem would resolve against the current directory, which is System32 when run
rem as administrator. Accepts quotes, forward slashes, "E:" for a drive root,
rem and any number of trailing backslashes, so every way of typing a folder
rem means its contents.
set "normalise_path_result="
set "normalise_path_with_backslash="
if not defined normalise_path_input exit /b 1
set "normalise_path_input=%normalise_path_input:"=%"
if not defined normalise_path_input exit /b 1
for /f "tokens=* delims= " %%A in ("%normalise_path_input%") do set "normalise_path_input=%%A"
if not defined normalise_path_input exit /b 1
set "normalise_path_input=%normalise_path_input:/=\%"
if "%normalise_path_input:~1%"==":" set "normalise_path_input=%normalise_path_input%\"
set "normalise_path_is_full="
if "%normalise_path_input:~1,2%"==":\" set "normalise_path_is_full=1"
if "%normalise_path_input:~0,2%"=="\\" set "normalise_path_is_full=1"
if not defined normalise_path_is_full exit /b 1
for %%A in ("%normalise_path_input%") do set "normalise_path_result=%%~fA"
if not defined normalise_path_result exit /b 1
:normalise_path_trim
if "%normalise_path_result:~-1%"=="\" if not "%normalise_path_result:~-2%"==":\" if not "%normalise_path_result%"=="\" (
    set "normalise_path_result=%normalise_path_result:~0,-1%"
    goto normalise_path_trim
)
set "normalise_path_with_backslash=%normalise_path_result%"
if not "%normalise_path_with_backslash:~-1%"=="\" set "normalise_path_with_backslash=%normalise_path_with_backslash%\"
exit /b 0

:paths_overlap
rem Exit 0 if source and destination are the same directory or one is inside
rem the other (case-insensitive). A mapped drive and its UNC path are not
rem recognised as the same place.
setlocal EnableDelayedExpansion
call :strlen source_with_backslash source_length
call :strlen destination_with_backslash destination_length
set "overlap_exit_code=1"
if !source_length! leq !destination_length! (
    for %%N in (!source_length!) do if /i "!destination_with_backslash:~0,%%N!"=="!source_with_backslash!" set "overlap_exit_code=0"
) else (
    for %%N in (!destination_length!) do if /i "!source_with_backslash:~0,%%N!"=="!destination_with_backslash!" set "overlap_exit_code=0"
)
endlocal & exit /b %overlap_exit_code%

rem ------------------------------- Time --------------------------------------

:get_utc_now
rem Set utc_digits (YYYYMMDDhhmmss), utc_compact (YYYYMMDDThhmmssZ), utc_iso
rem (YYYY-MM-DDThh:mm:ssZ) and utc_method, trying each of UTC_METHODS in turn.
rem If none works, use a placeholder and set utc_clock_failed: never local
rem time.
set "utc_digits="
set "utc_method="
for %%M in (%UTC_METHODS%) do if not defined utc_method (
    set "utc_digits="
    call :utc_from_%%M
    call :is_timestamp_digits utc_digits && set "utc_method=%%M"
)
if not defined utc_method (
    set "utc_compact=unknown-time-%RANDOM%"
    set "utc_iso=unknown"
    set "utc_method=none"
    set "utc_clock_failed=1"
    exit /b 1
)
set "utc_compact=%utc_digits:~0,8%T%utc_digits:~8,6%Z"
set "utc_iso=%utc_digits:~0,4%-%utc_digits:~4,2%-%utc_digits:~6,2%T%utc_digits:~8,2%:%utc_digits:~10,2%:%utc_digits:~12,2%Z"
exit /b 0

:utc_from_wmic
rem Fallback: WMI's Win32_UTCTime, which is already UTC. wmic is deprecated
rem and not installed by default from Windows 11 24H2. Sets utc_digits.
setlocal EnableDelayedExpansion
for %%F in (Year Month Day Hour Minute Second) do set "wmi_%%F="
for /f "tokens=1,2 delims==" %%A in ('wmic path Win32_UTCTime get Day^,Hour^,Minute^,Month^,Second^,Year /value 2^>nul') do for /f %%C in ("%%B") do set "wmi_%%A=%%C"
if not defined wmi_Year (endlocal & exit /b 1)
for %%F in (Month Day Hour Minute Second) do (
    set "wmi_%%F=0!wmi_%%F!"
    set "wmi_%%F=!wmi_%%F:~-2!"
)
set "digits=!wmi_Year!!wmi_Month!!wmi_Day!!wmi_Hour!!wmi_Minute!!wmi_Second!"
endlocal & set "utc_digits=%digits%"
exit /b 0

:utc_from_robocopy
rem Robocopy's error lines carry the local time as YYYY/MM/DD hh:mm:ss in every
rem locale; add the registry's ActiveTimeBias (which includes DST) for UTC.
rem The bias is read before and after the clock: if they differ, a DST change
rem happened in between and the reading is retried (up to 3 attempts). Sets
rem utc_digits.
setlocal EnableDelayedExpansion
set "attempt=0"
:utc_from_robocopy_retry
set /a "attempt+=1"
if !attempt! gtr 3 (endlocal & exit /b 1)
call :get_utc_bias_minutes bias_before || (endlocal & exit /b 1)
set "local_digits="
for /f "tokens=1,2" %%A in ('robocopy "|" . /njh /r:0 /w:0 2^>nul') do if not defined local_digits (
    set "robocopy_date=%%A"
    set "robocopy_time=%%B"
    if "!robocopy_date:~4,1!!robocopy_date:~7,1!!robocopy_time:~2,1!!robocopy_time:~5,1!"=="//::" set "local_digits=!robocopy_date:/=!!robocopy_time::=!"
)
if not defined local_digits (endlocal & exit /b 1)
call :get_utc_bias_minutes bias_after || (endlocal & exit /b 1)
if not "!bias_before!"=="!bias_after!" goto utc_from_robocopy_retry
call :is_timestamp_digits local_digits || (endlocal & exit /b 1)
call :add_minutes_to_digits local_digits !bias_before! utc_result
endlocal & set "utc_digits=%utc_result%"
exit /b 0

:get_utc_bias_minutes  outVar
rem Minutes to add to local time to get UTC (ActiveTimeBias, includes DST).
setlocal
set "bias="
for /f "tokens=3" %%V in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" /v ActiveTimeBias 2^>nul ^| find /i "ActiveTimeBias"') do set "bias=%%V"
if not defined bias (endlocal & exit /b 1)
set /a "bias=%bias%" 2>nul || (endlocal & exit /b 1)
endlocal & set "%~1=%bias%"
exit /b 0

:format_utc_offset  outVar
rem Local offset from UTC as +hh:mm / -hh:mm, or "unknown".
setlocal
call :get_utc_bias_minutes bias || (endlocal & set "%~1=unknown" & exit /b 1)
set /a "offset_minutes=-bias"
set "sign=+"
if %offset_minutes% lss 0 (
    set "sign=-"
    set /a "offset_minutes=-offset_minutes"
)
set /a "hours=offset_minutes / 60, minutes=offset_minutes %% 60"
if %hours% lss 10 set "hours=0%hours%"
if %minutes% lss 10 set "minutes=0%minutes%"
endlocal & set "%~1=%sign%%hours%:%minutes%"
exit /b 0

:add_minutes_to_digits  inVar  minutes  outVar
rem Add minutes (may be negative) to a YYYYMMDDhhmmss value, with correct
rem day, month, year and leap-year rollover. Converts to days since
rem 1970-01-01 and back with H. Hinnant's days_from_civil / civil_from_days;
rem the short names (y, mo, d, h, mi, s, era, yoe, doy, doe, mp, z) are the
rem published algorithm's, so it can be checked against the source.
setlocal EnableDelayedExpansion
set "timestamp=!%~1!"
set /a "y=1!timestamp:~0,4! - 10000, mo=1!timestamp:~4,2! - 100, d=1!timestamp:~6,2! - 100, h=1!timestamp:~8,2! - 100, mi=1!timestamp:~10,2! - 100"
set "s=!timestamp:~12,2!"
set /a "yy=y"
if !mo! leq 2 set /a "yy-=1"
if !mo! gtr 2 (set /a "mp=mo - 3") else set /a "mp=mo + 9"
set /a "era=yy / 400, yoe=yy - era * 400, doy=(153 * mp + 2) / 5 + d - 1"
set /a "doe=yoe * 365 + yoe / 4 - yoe / 100 + doy, days=era * 146097 + doe - 719468"
set /a "total=days * 1440 + h * 60 + mi + (%~2)"
set /a "days=total / 1440, mins=total %% 1440"
set /a "z=days + 719468, era=z / 146097, doe=z - era * 146097"
set /a "yoe=(doe - doe / 1460 + doe / 36524 - doe / 146096) / 365, y=yoe + era * 400"
set /a "doy=doe - (365 * yoe + yoe / 4 - yoe / 100), mp=(5 * doy + 2) / 153, d=doy - (153 * mp + 2) / 5 + 1"
if !mp! lss 10 (set /a "mo=mp + 3") else set /a "mo=mp - 9"
if !mo! leq 2 set /a "y+=1"
set /a "h=mins / 60, mi=mins %% 60"
for %%V in (mo d h mi) do (
    set "%%V=0!%%V!"
    set "%%V=!%%V:~-2!"
)
endlocal & set "%~3=%y%%mo%%d%%h%%mi%%s%"
exit /b 0

:is_timestamp_digits  valueVar
rem Exit 0 if the variable holds exactly 14 decimal digits.
setlocal EnableDelayedExpansion
set "value=!%~1!"
if not defined value (endlocal & exit /b 1)
if not "!value:~14!"=="" (endlocal & exit /b 1)
if "!value:~13,1!"=="" (endlocal & exit /b 1)
for /f "delims=0123456789" %%X in ("!value!") do (endlocal & exit /b 1)
endlocal & exit /b 0

rem ----------------------------- General -------------------------------------

:show  msgVar
rem Print a variable's value to the console only (not to the log).
setlocal EnableDelayedExpansion
echo(!%~1!
endlocal & exit /b 0

:show_and_log  msgVar
rem Print a variable's value to the console and, in log mode once the log
rem exists, append it to the log.
setlocal EnableDelayedExpansion
echo(!%~1!
if defined log_ready >>"!log_staged_path!" echo(!%~1!
endlocal & exit /b 0

:log_field  label  valueVar
rem Show and log "  label     : value", labels aligned under a section title.
setlocal EnableDelayedExpansion
set "padded_label=%~1                    "
set "msg=  !padded_label:~0,18!: !%~2!"
call :show_and_log msg
endlocal & exit /b 0

:log_field_continued  valueVar
rem Show and log a continuation line, aligned with the values of :log_field.
setlocal EnableDelayedExpansion
set "msg=                      !%~1!"
call :show_and_log msg
endlocal & exit /b 0

:log_result_line  label  valueVar
rem Show and log "  label   : value" for the overall result, whose value sits
rem four columns right of :log_field's to line up with :log_check_line.
setlocal EnableDelayedExpansion
set "padded_label=%~1                         "
set "msg=  !padded_label:~0,22!: !%~2!"
call :show_and_log msg
endlocal & exit /b 0

:log_check_line  label  valueVar  [detailVar]
rem Show and log one check under the overall result as
rem "    |-label : value", and detailVar (if given and set) on the next line,
rem aligned with the value.
setlocal EnableDelayedExpansion
set "padded_label=%~1                         "
set "msg=    |-!padded_label:~0,18!: !%~2!"
call :show_and_log msg
if "%~3"=="" (endlocal & exit /b 0)
if not defined %~3 (endlocal & exit /b 0)
set "msg=                          !%~3!"
call :show_and_log msg
endlocal & exit /b 0

:remember_problem  msgVar
rem Add a line to the problems listed at the end of the run.
setlocal EnableDelayedExpansion
>>"!temp_problems!" echo(!%~1!
endlocal & exit /b 0

:show_problems
rem List the remembered problems on the console at the end of the run (in
rem log mode each is also in the log, where it was found).
setlocal EnableDelayedExpansion
if not exist "!temp_problems!" (endlocal & exit /b 0)
echo.
echo Problems found during this run:
type "!temp_problems!"
endlocal & exit /b 0

:relative_path  fullVar  baseVar  outVar
rem Set outVar to fullVar without the baseVar prefix; exit 1 if fullVar does
rem not start with it. Caller's scope; the caller must have delayed expansion
rem on.
call :strlen %~2 relative_path_base_length
set "relative_path_prefix="
set "%~3="
for %%N in (!relative_path_base_length!) do (
    set "relative_path_prefix=!%~1:~0,%%N!"
    set "%~3=!%~1:~%%N!"
)
if /i not "!relative_path_prefix!"=="!%~2!" exit /b 1
if not defined %~3 exit /b 1
exit /b 0

:is_script_copy  relativePathVar
rem Exit 0 if the relative path is a root-level copy of this script:
rem SCRIPT_FILE_PREFIX ... SCRIPT_FILE_EXT, case-insensitive.
setlocal EnableDelayedExpansion
set "root_file_name=!%~1!"
if not "!root_file_name:\=!"=="!root_file_name!" (endlocal & exit /b 1)
call :strlen SCRIPT_FILE_PREFIX prefix_length
call :strlen SCRIPT_FILE_EXT extension_length
for %%P in (!prefix_length!) do if /i not "!root_file_name:~0,%%P!"=="!SCRIPT_FILE_PREFIX!" (endlocal & exit /b 1)
for %%E in (!extension_length!) do if /i not "!root_file_name:~-%%E!"=="!SCRIPT_FILE_EXT!" (endlocal & exit /b 1)
endlocal & exit /b 0

:is_drive_root  pathVar
rem Exit 0 if the path (in its with-backslash form) is a drive root: "X:\".
setlocal EnableDelayedExpansion
set "value=!%~1!"
if not "!value:~3!"=="" (endlocal & exit /b 1)
if not "!value:~1,2!"==":\" (endlocal & exit /b 1)
endlocal & exit /b 0

:each_item  listVar  callback
rem Call :<callback> "<item>" for each "|"-separated item of the list
rem variable. Splitting with FOR /F keeps * and ? intact (a plain FOR would
rem treat them as a file search). Caller's scope, so the callback's
rem variables persist; items are CONFIG values, safe to pass to CALL.
setlocal EnableDelayedExpansion
set "list=!%~1!"
endlocal & set "each_item_rest=%list%"
:each_item_loop
if not defined each_item_rest exit /b 0
set "each_item_current="
for /f "tokens=1* delims=|" %%A in ("%each_item_rest%") do (
    set "each_item_current=%%A"
    set "each_item_rest=%%B"
)
if not defined each_item_current set "each_item_rest="
if defined each_item_current call :%~2 "%each_item_current%"
goto each_item_loop

:strlen  textVar  outVar
rem Length of a variable's value.
setlocal EnableDelayedExpansion
set "text=!%~1!#"
set "length=0"
for %%P in (4096 2048 1024 512 256 128 64 32 16 8 4 2 1) do if not "!text:~%%P,1!"=="" (
    set /a "length+=%%P"
    set "text=!text:~%%P!"
)
endlocal & set "%~2=%length%"
exit /b 0

:cleanup_temp
rem Delete this run's temporary files; a failed delete never stops the run.
setlocal EnableDelayedExpansion
for %%T in (temp_file_list temp_metadata_list temp_hash_rows_source temp_hash_rows_destination temp_compare_lines temp_compare_lines_sorted temp_problems temp_warnings temp_clock_status temp_housekeeping_source temp_housekeeping_destination) do (
    if defined %%T if exist "!%%T!" del /f /q "!%%T!" >nul 2>&1
)
rem The staging folder goes only if empty: if it still holds records,
rem :publish_records has said where it is.
if defined staging_dir if exist "!staging_dir!\" rd "!staging_dir!" >nul 2>&1
endlocal & exit /b 0
