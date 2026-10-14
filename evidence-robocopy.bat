:: SPDX-License-Identifier: 0BSD
@echo off
rem ===========================================================================
rem evidence-robocopy - copy evidence between drives with robocopy (E01/EWF
rem image sets first and foremost, and loose files), verify every file by
rem SHA-256 against a reference record, and leave chain-of-custody records.
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
rem Conventions for contributors:
rem  - Delayed expansion is OFF in the main flow. Paths may contain ! % ^ & ( )
rem    so they are only ever expanded as !var! inside helpers that enable
rem    delayed expansion, or as "%var%" inside quotes in the main flow. Never
rem    pass a path to CALL as a value: pass the variable's NAME instead.
rem  - Never return a path from a SETLOCAL helper with "endlocal & set": into a
rem    delayed-expansion caller that mangles "!". Such helpers run in the
rem    caller's scope instead (they are marked "caller's scope").
rem  - Output goes through :say (console) or :emit (console and log):
rem        set "msg=Some text" & call :emit msg
rem  - Lists of similar items are tables in CONFIG: add a row, not code.
rem ===========================================================================
setlocal EnableExtensions DisableDelayedExpansion

rem ============================== CONFIG =====================================

set "SCRIPT_NAME=evidence-robocopy"
set "SCRIPT_VERSION=1.4.0"

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

rem Volume housekeeping skipped only when the source or destination IS a
rem drive root (E:\): what Windows, macOS and Linux leave on a drive they are
rem plugged into, not evidence. Anywhere else (inside a folder, or any UNC
rem path, which can't be told apart from a folder) these names are contents
rem and are copied: wrongly copying them fails visibly, wrongly skipping them
rem would silently leave evidence out. Before copying, each drive root is
rem checked and only the items actually present are excluded, by exact path,
rem and listed in the log. Items are separated by "|" (invalid in Windows
rem names; a plain FOR would treat * and ? as a file search), * and ? are
rem allowed. One row per origin: add a row, not code.
rem Folders:
rem   Windows: recycle bins (Vista+, 2000/XP/2003 NTFS, 9x/ME FAT), system data
set "EXCLUDED_ROOT_DIRS=$RECYCLE.BIN|RECYCLER|RECYCLED|System Volume Information"
rem   macOS: trash, Spotlight index, file-system events, temp, version store
set "EXCLUDED_ROOT_DIRS=%EXCLUDED_ROOT_DIRS%|.Trashes|.Spotlight-V100|.fseventsd|.TemporaryItems|.DocumentRevisions-V100"
rem   Linux desktops: trash on removable media, one per user (.Trash-<uid>)
set "EXCLUDED_ROOT_DIRS=%EXCLUDED_ROOT_DIRS%|.Trash-*"
rem Files:
rem   macOS: Finder data, AppleDouble files, volume icon, Time Machine and
rem   Spotlight markers
set "EXCLUDED_ROOT_FILES=.DS_Store|._*|.apdisk|.VolumeIcon.icns|.com.apple.timemachine.donotpresent|.metadata_never_index*"
rem   Windows: thumbnail cache
set "EXCLUDED_ROOT_FILES=%EXCLUDED_ROOT_FILES%|Thumbs.db"
rem   Linux desktops: GNOME volume info, KDE folder settings
set "EXCLUDED_ROOT_FILES=%EXCLUDED_ROOT_FILES%|.xdg-volume-info|.directory"

rem Folders of recovered fragments at a drive root ("|"-separated, * and ?
rem allowed):
rem chkdsk (FOUND.000, ...) and Android (LOST.DIR). They are copied as
rem contents, never skipped (they may hold pieces of evidence files), but
rem their presence means the drive has had file-system repairs: a warning.
set "RECOVERED_ROOT_DIRS=FOUND.???|LOST.DIR"

rem Copy passes, run in the order listed in COPY_PASSES. Fields per pass <id>:
rem   PASS_<id>_LABEL    text shown in the console and log
rem   PASS_<id>_FILTER   robocopy file-size filter
rem   PASS_<id>_THREADS  /mt thread count, or "auto" (see THREAD_DIVISOR)
rem   PASS_<id>_FLAGS    extra robocopy flags for this pass only
set "COPY_PASSES=large small"
set "PASS_large_LABEL=Large files (%LARGE_FILE_MIB% MiB and over)"
set "PASS_large_FILTER=/min:%LARGE_FILE_BYTES%"
set "PASS_large_THREADS=1"
set "PASS_large_FLAGS=/j"
set "PASS_small_LABEL=Small files (under %LARGE_FILE_MIB% MiB)"
set "PASS_small_FILTER=/max:%SMALL_FILE_MAX_BYTES%"
set "PASS_small_THREADS=auto"
set "PASS_small_FLAGS="

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
set "META_FLAGS=/l /e /xj /xx /njh /njs /ndl /nc /ns /fp /r:0 /w:0"
rem File systems with coarse timestamps: if the source or destination is one,
rem times are compared to 2 s (/fft) instead of exactly.
set "COARSE_TIME_FILESYSTEMS=FAT FAT32 exFAT"

rem Robocopy exit code bits, checked highest first. Fields per bit <n>:
rem   RC_<n>_SEVERITY  FAIL (copy failed), WARN or INFO
rem   RC_<n>_TEXT      explanation written to the console and log
set "RC_BITS=16 8 4 2 1"
set "RC_16_SEVERITY=FAIL"
set "RC_16_TEXT=Fatal error: nothing was copied (bad usage, or no access to source or destination)."
set "RC_8_SEVERITY=FAIL"
set "RC_8_TEXT=Some files or directories could not be copied (see ERROR lines above)."
set "RC_4_SEVERITY=FAIL"
set "RC_4_TEXT=Mismatched files or directories (a file and a directory share a name): those items were not copied."
set "RC_2_SEVERITY=WARN"
set "RC_2_TEXT=Extra files or directories in the destination that are not in the source."
set "RC_1_SEVERITY=INFO"
set "RC_1_TEXT=Files were copied."
rem Bits whose severity is FAIL, as a mask for the verdict (16 + 8 + 4).
set "RC_FAIL_MASK=28"

rem Source and destination folders are containers, not evidence: their own
rem attributes are never carried across. Robocopy copies the source folder's
rem attributes onto the destination folder; these are cleared again unless
rem the destination folder already had them. With Read-only or System set,
rem Explorer applies a copied desktop.ini, so the destination would show the
rem source folder's name and icon (e.g. Downloads). Fields per row, separated
rem by ":": position in a FOR %%~a attribute string, attrib letter, name.
set "CONTAINER_ATTRS=1:r:Read-only 3:h:Hidden 4:s:System"

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
rem :admin_check_<name>), tried in turn until one succeeds. Pure batch and
rem built-in tools only. The robocopy clock works on every Windows version
rem with robocopy (Vista and later); wmic is deprecated and absent by default
rem from Windows 11 24H2.
set "UTC_METHODS=robocopy wmic"
set "ADMIN_CHECKS=fsutil net"

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
rem file system, tried in order (each is an :fs_from_<name> helper).
set "KNOWN_FILESYSTEMS=NTFS ReFS exFAT FAT32 FAT UDF CDFS"
set "FS_METHODS=fsutil chkntfs"

rem Destination file systems that get a warning (FS_WARN_<name>=reason).
set "FS_WARN_FAT32=FAT32 can't hold files of 4 GiB or more, and keeps timestamps to 2 s only."
set "FS_WARN_FAT=FAT can't hold files of 2 GiB or more, and keeps timestamps to 2 s only."

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
call :detect_admin
call :ask_progress_mode || goto :abort
call :ask_paths || goto :abort
call :ask_verify || goto :abort
call :init_run || goto :abort
call :check_environment
call :write_header
for %%P in (%COPY_PASSES%) do call :run_copy_pass %%P
call :restore_destination_attributes
if "%verify%"=="1" call :verify_copy
call :place_script_copy
call :finish
call :publish_log
call :write_seal
call :cleanup_temp
pause
exit /b %exit_code%

rem ============================ FUNCTIONS ====================================

rem --------------------------- Run steps -------------------------------------

:show_help
echo %SCRIPT_NAME% %SCRIPT_VERSION%
echo.
echo Copies the CONTENTS of a source folder (e.g. an E01/EWF evidence set) into a
echo destination folder with robocopy, keeping data, attributes and timestamps,
echo then optionally compares the SHA-256 of every file. The two folders are
echo containers, not evidence: their own attributes are not carried across.
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
echo.
echo Exit codes: %EXIT_CODE_PASS% PASS, %EXIT_CODE_FAIL% FAIL, %EXIT_CODE_UNVERIFIED% UNVERIFIED (copied, not verified).
exit /b 0

:init_state
rem Counters and flags used across the run.
for %%V in (copy_rc n_anomalies verify_incomplete n_hashed_source n_hashed_destination m_differ m_incomplete) do set "%%V=0"
for %%V in (c_ok c_changed c_missing c_invalid c_unreadable c_records c_added c_rows) do set "%%V=0"
set "log_ready="
set "timestamp_warning=0"
set "n_warnings=0"
set "meta_mode=exact"
set "meta_ran="
set "exit_code=%EXIT_CODE_FAIL%"
set "v_script_copy=not attempted"
set "script_copy_file="
exit /b 0

:parse_args  arg1  arg2
rem Forensic mode unless /nonforensic is given. Anything else (an unknown
rem option, a folder dropped on the script, a second argument) stops the run,
rem so a typo can't silently fall back to a different mode than intended.
set "mode=forensic"
if /i "%~1"=="/nonforensic" set "mode=nonforensic"
if "%mode%"=="forensic" if not "%~1"=="" (
    set "abort_reason=Unknown option. Run with /? for the options."
    exit /b 1
)
if not "%~2"=="" (
    set "abort_reason=Too many options. Run with /? for the options."
    exit /b 1
)
if "%mode%"=="forensic" (
    set "mode_text=forensic (default): log file and SHA-256 verification"
) else (
    set "mode_text=non-forensic (/nonforensic): log and verification chosen at the prompts"
)
exit /b 0

:show_banner
echo Script: %SCRIPT_NAME%
echo Version: %SCRIPT_VERSION%
echo Author: outis
echo Licence: 0BSD
echo.
echo Tip: disable AV real-time scanning when copying many small files.
echo Tip: don't click inside this window while it runs: a QuickEdit selection
echo      pauses the copy until you press Esc.
echo.
exit /b 0

:check_robocopy
where /q robocopy.exe && exit /b 0
set "abort_reason=robocopy.exe was not found."
exit /b 1

:detect_admin
rem Elevated if any check in ADMIN_CHECKS succeeds; unknown counts as not
rem elevated.
set "is_admin="
set "admin_method=none"
for %%M in (%ADMIN_CHECKS%) do if not defined is_admin call :admin_check_%%M && (
    set "is_admin=1"
    set "admin_method=%%M"
)
if defined is_admin (
    set "backup_flag=/b"
    set "elevated_text=yes (detected by %admin_method%), backup mode /b"
    echo You are running as Administrator. Backup mode lets robocopy read files
    echo regardless of their permissions, but may be slower.
) else (
    set "backup_flag="
    set "elevated_text=no"
    echo You are not running as Administrator. Files your account can't read
    echo will fail to copy.
)
echo.
exit /b 0

:admin_check_fsutil
fsutil dirty query %SystemDrive% >nul 2>&1
exit /b %errorlevel%

:admin_check_net
net session >nul 2>&1
exit /b %errorlevel%

:ask_progress_mode
rem Log mode and ETA mode are deliberately exclusive: robocopy's progress
rem output would make the log unreadable, so the user picks one. Forensic
rem mode (the default) always keeps the log and doesn't ask.
if not "%mode%"=="nonforensic" (
    set "use_log=1"
    set "progress_flags=/np /tee"
    set "progress_text=log file (/np /tee)"
    exit /b 0
)
echo Would you prefer a log file, or ETA and percentage?
echo 1. Log file (but no ETA or percentage). Use this for evidence.
echo 2. ETA and percentage (no log file: for non-evidence copies only)
call :ask_choice progress_mode "1 2" || exit /b 1
if "%progress_mode%"=="1" (
    set "use_log=1"
    set "progress_flags=/np /tee"
    set "progress_text=log file (/np /tee)"
) else (
    set "use_log=0"
    set "progress_flags=/eta"
    set "progress_text=ETA and percentage, no log file (/eta): not a custody record"
)
if "%use_log%"=="0" (
    echo.
    echo WARNING: ETA mode keeps no log file. This copy will leave no record and
    echo cannot serve as chain of custody. Use it for non-evidence copies only.
    echo 1. Continue without a log file
    echo 2. Go back and choose again
)
if "%use_log%"=="0" call :ask_choice eta_confirm "1 2" || exit /b 1
if "%use_log%"=="0" if "%eta_confirm%"=="2" (
    echo.
    goto ask_progress_mode
)
echo.
exit /b 0

:ask_paths
echo The CONTENTS of the source folder are copied into the destination folder.
call :find_default_source
:ask_paths_loop
echo.
call :ask_directory source "SOURCE folder" 1 1 || exit /b 1
set "source_how=entered at the prompt"
if defined dir_used_default set "source_how=the script's folder (the default, taken with Enter)"
:ask_paths_destination
echo.
call :ask_directory destination "DESTINATION folder" 0 0 || exit /b 1
call :paths_overlap && (
    echo Source and destination must not be the same, or inside each other.
    echo.
    goto ask_paths_loop
)
set "dest_state=empty"
call :destination_has_content || exit /b 0
echo.
echo The destination folder is not empty. Robocopy overwrites files there that
echo have the same name but a different size or timestamp.
echo 1. Continue with this destination
echo 2. Enter a different destination
call :ask_choice dest_choice "1 2" || exit /b 1
if "%dest_choice%"=="2" goto ask_paths_destination
set "dest_state=NOT empty (user chose to continue)"
exit /b 0

:find_default_source
rem Offer the script's own folder as the default source when it holds
rem anything besides the script (evidence, logs and script kept together).
set "default_source="
set "path_in=%script_dir%"
call :normalise_path || exit /b 0
set "fd_n=0"
for /f "eol=/ delims=" %%E in ('dir /b /a "%path_cmp%" 2^>nul') do set /a "fd_n+=1"
if %fd_n% gtr 1 set "default_source=%path_out%"
exit /b 0

:destination_has_content
rem Exit 0 if the destination folder exists and holds anything other than,
rem at a drive root, the housekeeping items of EXCLUDED_ROOT_DIRS/FILES.
if not exist "%destination_cmp%" exit /b 1
set "dh_total=0"
for /f "eol=/ delims=" %%E in ('dir /b /a "%destination_cmp%" 2^>nul') do set /a "dh_total+=1"
call :find_root_baggage destination dh_baggage 0
if %dh_total% gtr %dh_baggage% exit /b 0
exit /b 1

:ask_verify
rem Forensic mode (the default) always verifies and doesn't ask.
if not "%mode%"=="nonforensic" (
    set "verify=1"
    exit /b 0
)
echo.
echo Once complete, compare the SHA-256 of every file?
echo 1. Compare SHA-256. Use this for evidence.
echo 2. Do not compare hashes (not for evidence)
call :ask_choice verify_choice "1 2" || exit /b 1
if "%verify_choice%"=="1" (set "verify=1") else set "verify=0"
if "%verify%"=="0" (
    echo.
    echo WARNING: without verification nothing is hashed and no hash record is
    echo made, so this copy cannot show that the evidence is unchanged, and later
    echo copies made from it can't be checked against a reference record.
    echo 1. Continue without verification
    echo 2. Go back and choose again
)
if "%verify%"=="0" call :ask_choice verify_confirm "1 2" || exit /b 1
if "%verify%"=="0" if "%verify_confirm%"=="2" goto ask_verify
echo.
exit /b 0

:init_run
rem Fix the run timestamp and output paths, create the destination and, in
rem log mode, the working log. The log is written in TEMP while the run is in
rem progress and moved to the destination at the end: inside the destination,
rem robocopy would count it as an extra file (exit bit 2) on every run.
call :get_utc_now
set "start_iso=%utc_iso%"
set "start_method=%utc_method%"
set "run_ts=%utc_compact%"
set "log_name=robocopy_%run_ts%.log"
set "log_file=%destination_cmp%%log_name%"
set "csv_source=%destination_cmp%robocopy_%run_ts%_hashes_source.csv"
set "csv_destination=%destination_cmp%robocopy_%run_ts%_hashes_destination.csv"
rem Working folder for temporary files and the log during the run, in order:
rem TEMP, TMP, LOCALAPPDATA\Temp. Never the destination: files there would be
rem hashed as evidence.
set "work_dir="
if defined TEMP if exist "%TEMP%\" set "work_dir=%TEMP%"
if not defined work_dir if defined TMP if exist "%TMP%\" set "work_dir=%TMP%"
if not defined work_dir if defined LOCALAPPDATA if exist "%LOCALAPPDATA%\Temp\" set "work_dir=%LOCALAPPDATA%\Temp"
if not defined work_dir (
    set "abort_reason=No temporary folder found (TEMP, TMP or LOCALAPPDATA\Temp)."
    exit /b 1
)
set "temp_prefix=%work_dir%\%SCRIPT_NAME%_%run_ts%_%RANDOM%"
set "tmp_list=%temp_prefix%_list.tmp"
set "tmp_rows_source=%temp_prefix%_source.tmp"
set "tmp_rows_destination=%temp_prefix%_destination.tmp"
set "tmp_problems=%temp_prefix%_problems.tmp"
set "tmp_merge=%temp_prefix%_merge.tmp"
set "tmp_merge_sorted=%temp_prefix%_merge_sorted.tmp"
set "tmp_clock=%temp_prefix%_clock.tmp"
set "tmp_warnings=%temp_prefix%_warnings.tmp"
set "tmp_baggage_source=%temp_prefix%_baggage_source.tmp"
set "tmp_baggage_destination=%temp_prefix%_baggage_destination.tmp"
set "seal_name=robocopy_%run_ts%.sha256"
set "seal_file=%destination_cmp%%seal_name%"
set "reference_name="
set "reference_csv="
if "%verify%"=="1" call :find_reference_csv
set "log_work=%temp_prefix%_%log_name%"
set "dest_attrs_before="
if exist "%destination_cmp%" for %%A in ("%destination%") do set "dest_attrs_before=%%~aA"
if not exist "%destination_cmp%" mkdir "%destination%" >nul 2>&1
if not exist "%destination_cmp%" (
    set "abort_reason=Could not create the destination directory."
    exit /b 1
)
if not "%use_log%"=="1" (
    set "log_file=none (ETA mode)"
    exit /b 0
)
(type nul >>"%log_work%") 2>nul || (
    set "abort_reason=Could not create the working log in the temporary folder."
    exit /b 1
)
set "log_ready=1"
exit /b 0

:write_header
rem Write the run header in three sections: environment, source, destination.
call :format_utc_offset utc_offset
call :describe_windows windows_version
set "robocopy_path="
for /f "delims=" %%R in ('where robocopy.exe 2^>nul') do if not defined robocopy_path set "robocopy_path=%%R"
set "certutil_path="
for /f "delims=" %%C in ('where certutil.exe 2^>nul') do if not defined certutil_path set "certutil_path=%%C"
if not defined certutil_path set "certutil_path=not found"
set "script_sha256="
call :get_sha256 script_path script_sha256
if not defined script_sha256 set "script_sha256=unknown"
set "v_script=%SCRIPT_NAME% %SCRIPT_VERSION%"
set "v_started=%start_iso% (source: %start_method%)"
set "v_offset=%utc_offset% (robocopy's Started/Ended times are local; its file times are UTC)"
set "v_user=%USERDOMAIN%\%USERNAME%"
set "v_excluded=volume housekeeping at a drive root only (see Source and Destination)"
set "v_retries=%RETRY_COUNT% x %RETRY_WAIT_SECONDS% s"
if "%verify%"=="1" (set "v_verify=SHA-256 hash and metadata (size, last-modified time), every file") else set "v_verify=no"
set "v_reference=not used (no verification)"
if "%verify%"=="1" set "v_reference=none found in the source root: the source is hashed and becomes the reference record"
if defined reference_name set "v_reference=%reference_name% (oldest in the source; the destination is checked against it)"
set "msg================================================================================" & call :emit msg
set "msg=Warnings (read before relying on this copy)" & call :emit msg
if %n_warnings% equ 0 (
    set "msg=  none"
    call :emit msg
) else for /f "usebackq delims=" %%L in ("%tmp_warnings%") do (
    set "msg=  %%L"
    call :emit msg
)
set "msg=" & call :emit msg
set "msg=Environment" & call :emit msg
call :emit_kv "Script" v_script
call :emit_kv "Script path" script_path
call :emit_kv "Script SHA-256" script_sha256
call :emit_kv "Mode" mode_text
call :emit_kv "Started (UTC)" v_started
call :emit_kv "Local UTC offset" v_offset
call :emit_kv "Time source" v_time_source
call :emit_kv "Last time sync" v_last_sync
call :emit_kv "Host" COMPUTERNAME
call :emit_kv "User" v_user
call :emit_kv "OS" windows_version
call :emit_kv "Elevated" elevated_text
call :emit_kv "robocopy" robocopy_path
call :emit_kv "certutil" certutil_path
call :emit_kv "Sleep when idle" sleep_text
call :emit_kv "Excluded" v_excluded
call :emit_kv "Retries" v_retries
call :emit_kv "Progress" progress_text
call :emit_kv "Verify" v_verify
set "msg=" & call :emit msg
set "msg=Source" & call :emit msg
call :emit_kv "Contents of" source_cmp
call :emit_kv "Chosen" source_how
call :emit_kv "Volume" v_src_volume
call :emit_kv "Hash record" v_reference
call :emit_baggage source "Skipped at root"
set "msg=" & call :emit msg
set "msg=Destination" & call :emit msg
call :emit_kv "Copied into" destination_cmp
call :emit_kv "Was" dest_state
call :emit_kv "Volume" v_dst_volume
call :emit_baggage destination "Left alone at root"
call :emit_kv "Log" log_file
if "%use_log%"=="1" call :emit_kv "Log during run" log_work
set "msg================================================================================" & call :emit msg
exit /b 0

:run_copy_pass  passId
rem One robocopy pass as defined by the PASS_<passId>_* row in CONFIG.
setlocal EnableDelayedExpansion
set "label=!PASS_%~1_LABEL!"
set "threads=!PASS_%~1_THREADS!"
if /i "!threads!"=="auto" call :auto_thread_count threads
set "excl_args="
call :add_root_exclusions source
call :add_root_exclusions destination
set "msg=" & call :emit msg
set "msg=--- Copy pass: !label!, threads: !threads! ---" & call :emit msg
set "log_args="
if "!use_log!"=="1" set log_args=/log+:"!log_work!"
robocopy "!source! " "!destination! " *.* !COPY_FLAGS! !PASS_%~1_FILTER! !PASS_%~1_FLAGS! /mt:!threads! /r:!RETRY_COUNT! /w:!RETRY_WAIT_SECONDS! !progress_flags! !backup_flag! !excl_args! !log_args!
set "rc=!errorlevel!"
call :report_robocopy_rc rc
endlocal & set /a "copy_rc|=%rc%" & exit /b 0

:restore_destination_attributes
rem Undo container attributes (CONTAINER_ATTRS) that robocopy carried from the
rem source folder onto the destination folder itself (not its contents). A
rem destination drive root is left alone.
if "%destination:~-1%"=="\" exit /b 0
setlocal EnableDelayedExpansion
set "before=!dest_attrs_before!"
if not defined before set "before=-----------"
set "after="
for %%A in ("!destination!") do set "after=%%~aA"
set "clear="
set "cleared="
for %%R in (%CONTAINER_ATTRS%) do for /f "tokens=1-3 delims=:" %%I in ("%%R") do (
    if /i "!after:~%%I,1!"=="%%J" if "!before:~%%I,1!"=="-" (
        set "clear=!clear! -%%J"
        set "cleared=!cleared! %%K"
    )
)
set "msg=" & call :emit msg
if not defined clear (
    set "msg=Destination folder attributes unchanged."
    call :emit msg
    endlocal & exit /b 0
)
attrib !clear! "!destination!" >nul 2>&1
set "now="
for %%A in ("!destination!") do set "now=%%~aA"
set "msg=Destination folder: cleared!cleared! (carried over from the source folder)."
call :emit msg
for %%R in (%CONTAINER_ATTRS%) do for /f "tokens=1-3 delims=:" %%I in ("%%R") do (
    if /i "!now:~%%I,1!"=="%%J" if "!before:~%%I,1!"=="-" (
        set "msg=[WARN] Could not clear %%K on the destination folder."
        call :emit msg
        call :add_problem msg
    )
)
endlocal & exit /b 0

:verify_copy
rem Hash the destination and compare it with the reference record: the oldest
rem source hash record from the source, or if the source holds none, this
rem run's own record of the source, made now. So the source is hashed
rem once per evidence set, and every later copy is checked back to it.
set "msg=" & call :emit msg
set "msg=--- Verification: metadata and SHA-256 hashes ---" & call :emit msg
call :check_metadata
where /q certutil.exe || (
    set "msg=[FAIL] certutil.exe not found: verification could not run."
    call :emit msg
    call :add_problem msg
    set "verify_incomplete=1"
    exit /b 1
)
if not defined reference_name (
    set "msg=" & call :emit msg
    set "msg=--- Hashing the source (no hash record found in the source root): it becomes the reference record ---"
    call :emit msg
    call :hash_tree source_cmp source || set "verify_incomplete=1"
    call :write_hash_csv source
    set "reference_name=robocopy_%run_ts%_hashes_source.csv"
)
set "msg=" & call :emit msg
set "msg=--- Hashing the destination ---" & call :emit msg
call :hash_tree destination_cmp destination || set "verify_incomplete=1"
call :write_hash_csv destination
set "reference_csv=%destination_cmp%%reference_name%"
if not exist "%reference_csv%" (
    set "msg=[FAIL] The reference record %reference_name% is not in the destination."
    call :emit msg
    call :add_problem msg
    set "verify_incomplete=1"
    exit /b 1
)
call :compare_with_reference
exit /b 0

:check_metadata
rem Compare size and last-modified time of every source file with its copy,
rem using robocopy's own comparison (see META_FLAGS). Any file listed differs
rem or is missing. Sets m_differ and m_incomplete; v_meta for the summary.
setlocal EnableDelayedExpansion
set "fft="
set "time_mode=exact"
for %%F in (%COARSE_TIME_FILESYSTEMS%) do (
    if /i "!src_fs!"=="%%F" set "fft=/fft"
    if /i "!dst_fs!"=="%%F" set "fft=/fft"
)
if defined fft set "time_mode=to 2 s, as FAT/exFAT is involved"
set "msg=" & call :emit msg
set "msg=--- Metadata check: size and last-modified time, compared !time_mode! ---"
call :emit msg
set "excl_args="
call :add_root_exclusions source
call :add_root_exclusions destination
robocopy "!source! " "!destination! " *.* !META_FLAGS! !fft! !backup_flag! !excl_args! >"!tmp_list!" 2>&1
set "rc=!errorlevel!"
set "incomplete=0"
if !rc! geq 8 (
    set "msg=[FAIL] The metadata check could not compare every file (robocopy exit code !rc!)."
    call :emit msg
    call :add_problem msg
    set "incomplete=1"
)
endlocal & set "m_incomplete=%incomplete%" & set "meta_mode=%time_mode%" & set "meta_ran=1"
for /f "usebackq tokens=*" %%L in ("%tmp_list%") do (
    set "entry=%%L"
    call :metadata_entry
)
exit /b 0

:metadata_entry
rem One file listed by the metadata check (in "entry"): it differs.
setlocal EnableDelayedExpansion
set "full=!entry!"
call :relative_path full source_cmp rel || (
    set "msg=[FAIL] Unexpected line in the metadata check: !full!"
    call :emit msg
    call :add_problem msg
    endlocal & set /a "n_anomalies+=1" & exit /b 0
)
set "msg=[FAIL] METADATA differs (size or last-modified time), or not copied: !rel!"
call :emit msg
call :add_problem msg
endlocal & set /a "m_differ+=1" & exit /b 0

:hash_tree  rootVar  side
rem List every file under the root (with robocopy) and hash each one into the
rem side's rows. Exit 1 if the listing was incomplete.
set "ht_failed="
call :list_files %~1 tmp_list || set "ht_failed=1"
set "n_listed=?"
for /f %%N in ('find /c /v "" ^<"%tmp_list%" 2^>nul') do set "n_listed=%%N"
rem The listing includes this run's own outputs already in the destination
rem (the source CSV, when the source had none); they are skipped, so leave
rem them out of the total shown in the progress counter.
if "%~2"=="destination" for %%O in (log_file csv_source csv_destination seal_file) do call :discount_output %%O
if "%~2"=="source" if not "%n_listed%"=="?" for /f "eol=/ delims=" %%F in ('dir /b /a-d "%source_cmp%%SCRIPT_FILE_PREFIX%*%SCRIPT_FILE_EXT%" 2^>nul') do set /a "n_listed-=1"
for /f "usebackq tokens=*" %%L in ("%tmp_list%") do (
    set "entry=%%L"
    call :hash_listed_entry %~1 %~2
)
if defined ht_failed exit /b 1
exit /b 0

:discount_output  pathVar
rem Lower n_listed by one if this run's output file exists (see :hash_tree).
setlocal EnableDelayedExpansion
if "!n_listed!"=="?" (endlocal & exit /b 0)
if not exist "!%~1!" (endlocal & exit /b 0)
endlocal & set /a "n_listed-=1"
exit /b 0

:finish
rem Work out the result, print the summary and set exit_code. The result
rem states what it covers, so it can't be misread later.
call :get_utc_now
set "end_iso=%utc_iso%"
set /a "copy_failed=copy_rc & RC_FAIL_MASK"
if %copy_failed% neq 0 (set "copy_status=FAILED") else set "copy_status=OK"
set "v_copy=%copy_status% (robocopy exit codes combined: %copy_rc%)"
set "verify_status=NOT RUN"
set "hash_status=NOT RUN"
set "meta_status=NOT RUN"
set "v_verify=NOT RUN: verification was not requested"
set "v_verify_detail="
set "v_ref_used=none"
set "v_meta=NOT RUN: verification was not requested"
if "%verify%"=="1" call :verification_status
set "verdict=PASS"
if "%verify_status%"=="FAIL" set "verdict=FAIL"
if "%copy_status%"=="FAILED" set "verdict=FAIL"
if "%verify_status%"=="NOT RUN" if "%verdict%"=="PASS" set "verdict=UNVERIFIED"
if "%verdict%"=="PASS" set "v_result=PASS - the copy completed, every file in the reference record is in the destination with the same SHA-256, and size and last-modified time match the source"
if "%verdict%"=="UNVERIFIED" set "v_result=UNVERIFIED - the copy completed without errors, but was not verified (no SHA-256 or metadata check)"
if "%verdict%"=="FAIL" set "v_result=FAIL - "
if "%verdict%"=="FAIL" if "%copy_status%"=="FAILED" set "v_result=%v_result%the copy failed; "
if "%verdict%"=="FAIL" if not "%hash_status%"=="PASS" if not "%hash_status%"=="NOT RUN" set "v_result=%v_result%the SHA-256 verification failed; "
if "%verdict%"=="FAIL" if "%verify_status%"=="FAIL" if not "%meta_status%"=="PASS" set "v_result=%v_result%the metadata check failed; "
if "%verdict%"=="FAIL" set "v_result=%v_result%see the problems listed"
if "%verdict%"=="PASS" set "exit_code=%EXIT_CODE_PASS%"
if "%verdict%"=="FAIL" set "exit_code=%EXIT_CODE_FAIL%"
if "%verdict%"=="UNVERIFIED" set "exit_code=%EXIT_CODE_UNVERIFIED%"
set "msg=" & call :emit msg
set "msg================================================================================" & call :emit msg
set "msg=Result" & call :emit msg
call :emit_kv "Finished (UTC)" end_iso
set "msg=" & call :emit msg
call :emit_kv "Copy (robocopy)" v_copy
call :emit_kv "Hash (SHA-256)" v_verify
if defined v_verify_detail call :emit_more v_verify_detail
call :emit_kv "Metadata" v_meta
set "msg=" & call :emit msg
call :emit_kv "Reference record" v_ref_used
call :emit_kv "Script copy" v_script_copy
set "msg=" & call :emit msg
call :emit_kv "OVERALL RESULT" v_result
call :emit_kv "Exit code" exit_code
call :emit_kv "Log" log_file
set "msg================================================================================" & call :emit msg
call :show_problems
exit /b 0

:abort
echo.
echo [FAIL] %abort_reason%
if defined log_ready (
    set "msg=[FAIL] Run aborted: %abort_reason%"
    call :emit msg
)
call :publish_log
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
call :describe_volume "%source:~0,2%" v_src_volume src_fs
call :describe_volume "%destination:~0,2%" v_dst_volume dst_fs
if "%timestamp_warning%"=="1" (
    set "msg=No UTC time source worked: output names use a placeholder, and times are unknown."
    call :add_warning msg
)
if defined dst_fs if defined FS_WARN_%dst_fs% call :warn_destination_fs
call :check_recovered_dirs
call :find_root_baggage source n_baggage_src 1
call :find_root_baggage destination n_baggage_dst 1
if "%verify%"=="1" if not defined reference_name (
    set "msg=No hash record was found in the source root: the source is hashed now and becomes the reference record, so this copy is not checked against any earlier record."
    call :add_warning msg
)
if not "%dest_state%"=="empty" (
    set "msg=The destination was not empty (you chose to continue): robocopy overwrites same-named files that differ."
    call :add_warning msg
)
exit /b 0

:check_recovered_dirs
rem Warn if the source or destination drive root holds folders of recovered
rem fragments (RECOVERED_ROOT_DIRS): the drive has had file-system repairs.
for %%R in (source destination) do call :check_recovered_side %%R
exit /b 0

:check_recovered_side  side
set "rc_hits="
call :is_drive_root %~1_cmp || exit /b 0
if "%~1"=="source" (set "fb_root=%source_cmp%") else set "fb_root=%destination_cmp%"
call :each_item RECOVERED_ROOT_DIRS find_recovered
if not defined rc_hits exit /b 0
set "msg=The %~1 drive holds folders of fragments recovered by file-system repairs (%rc_hits%): the drive may have been damaged. They are copied as contents."
call :add_warning msg
exit /b 0

:find_recovered  pattern
for /f "eol=/ delims=" %%F in ('dir /b /ad "%fb_root%%~1" 2^>nul') do call :add_recovered_hit "%%F"
exit /b 0

:add_recovered_hit  name
if defined rc_hits (set "rc_hits=%rc_hits%, %~1") else set "rc_hits=%~1"
exit /b 0

:find_root_baggage  side  countVar  write
rem Find the housekeeping items present at the side's root, if it is a drive
rem root: folders matching EXCLUDED_ROOT_DIRS and files matching
rem EXCLUDED_ROOT_FILES. Sets countVar; with write=1 also records them as
rem D:"name" / F:"name" lines in tmp_baggage_<side>, which drive the
rem exclusions (:add_root_exclusions) and the log (:emit_baggage).
set "fb_n=0"
set "fb_file="
if "%~1"=="source" (set "fb_root=%source_cmp%") else set "fb_root=%destination_cmp%"
if "%~3"=="1" if "%~1"=="source" set "fb_file=%tmp_baggage_source%"
if "%~3"=="1" if "%~1"=="destination" set "fb_file=%tmp_baggage_destination%"
if defined fb_file type nul >"%fb_file%" 2>nul
call :is_drive_root %~1_cmp || (
    set "%~2=0"
    exit /b 0
)
call :each_item EXCLUDED_ROOT_DIRS find_root_dir
call :each_item EXCLUDED_ROOT_FILES find_root_file
set "%~2=%fb_n%"
exit /b 0

:find_root_dir  pattern
rem One folder pattern of EXCLUDED_ROOT_DIRS (see :find_root_baggage). An
rem exact name is tested with IF EXIST (DIR on a folder lists its contents);
rem a pattern with * or ? is expanded with DIR.
echo(%~1| findstr /r "[*?]" >nul && goto find_root_dir_wild
if exist "%fb_root%%~1\" call :record_baggage D "%~1"
exit /b 0
:find_root_dir_wild
for /f "eol=/ delims=" %%F in ('dir /b /ad "%fb_root%%~1" 2^>nul') do call :record_baggage D "%%F"
exit /b 0

:find_root_file  pattern
rem One file pattern of EXCLUDED_ROOT_FILES (see :find_root_baggage).
for /f "eol=/ delims=" %%F in ('dir /b /a-d "%fb_root%%~1" 2^>nul') do call :record_baggage F "%%F"
exit /b 0

:record_baggage  kind  name
rem Count one housekeeping item and, if recording, write it (see above).
set /a "fb_n+=1"
if defined fb_file >>"%fb_file%" echo(%~1:"%~2"
exit /b 0

:emit_baggage  side  label
rem Emit "label : ..." for the housekeeping items skipped at the side's
rem root, one per line, or why there are none.
set "eb_text=n/a (not a drive root)"
call :is_drive_root %~1_cmp || (
    call :emit_kv "%~2" eb_text
    exit /b 0
)
if "%~1"=="source" (set "eb_file=%tmp_baggage_source%") else set "eb_file=%tmp_baggage_destination%"
set "eb_n=0"
if exist "%eb_file%" for /f "usebackq tokens=1* delims=:" %%A in ("%eb_file%") do set /a "eb_n+=1"
set "eb_text=none present"
if %eb_n% gtr 0 set "eb_text=%eb_n% item(s), excluded by exact path:"
call :emit_kv "%~2" eb_text
if %eb_n% equ 0 exit /b 0
for /f "usebackq tokens=1* delims=:" %%A in ("%eb_file%") do (
    set "eb_name=%%~B"
    if "%%A"=="D" (set "eb_kind=folder") else set "eb_kind=file"
    call :emit_baggage_line
)
exit /b 0

:emit_baggage_line
set "msg=                      %eb_name% (%eb_kind%)"
call :emit msg
exit /b 0

:add_warning  msgVar
rem Add "[WARN] <text>" to the warnings list and to the end-of-run problems.
setlocal EnableDelayedExpansion
>>"!tmp_warnings!" echo([WARN] !%~1!
>>"!tmp_problems!" echo([WARN] !%~1!
endlocal & set /a "n_warnings+=1"
exit /b 0

:read_clock_status
rem Set v_time_source and v_last_sync from "w32tm /query /status", and warn
rem if the clock isn't synchronised. w32tm prints its lines in a fixed order
rem (1 leap indicator, ... 7 last successful sync time, 8 source), so lines
rem are picked by position and work in any display language. The "not
rem synchronised" test: leap indicator 3, or a local/free-running clock source.
set "v_time_source=unknown"
set "v_last_sync=unknown"
set "clock_unsynced="
w32tm /query /status >"%tmp_clock%" 2>&1
if errorlevel 1 (
    set "v_time_source=unavailable (time service off, or w32tm needs administrator)"
    set "msg=The clock's synchronisation could not be checked (w32tm failed): times in this record rely on this machine's clock."
    call :add_warning msg
    exit /b 0
)
set "cl_n=0"
for /f "usebackq delims=" %%L in ("%tmp_clock%") do (
    set "cl_line=%%L"
    call :read_clock_line
)
if not defined clock_unsynced findstr /i /c:"Local CMOS Clock" /c:"Free-running System Clock" "%tmp_clock%" >nul 2>&1 && set "clock_unsynced=w32tm reports a local clock as its source"
if defined clock_unsynced (
    set "msg=The clock is not synchronised with a time source (%clock_unsynced%): times in this record rely on this machine's own clock."
    call :add_warning msg
)
exit /b 0

:read_clock_line
rem One line of w32tm output (in cl_line): keep the value after "label: ".
set /a "cl_n+=1"
set "cl_v=%cl_line:*: =%"
:read_clock_line_trim
if "%cl_v:~-1%"==" " (
    set "cl_v=%cl_v:~0,-1%"
    goto read_clock_line_trim
)
if %cl_n% equ 1 if "%cl_v:~0,1%"=="3" set "clock_unsynced=w32tm reports leap indicator 3, not synchronised"
if %cl_n% equ 7 set "v_last_sync=%cl_v% (local time, as w32tm reports it)"
if %cl_n% equ 8 set "v_time_source=%cl_v%"
exit /b 0

:check_power
rem Warn if this machine may sleep or hibernate during the copy. Reads the
rem current power plan (SLEEP_SETTINGS, lid action). Pure batch can't read
rem whether the machine is on mains or battery right now, so the warnings
rem cover both. Sets sleep_text for the log header.
setlocal EnableDelayedExpansion
set "known=1"
set "ac=0"
set "dc=0"
for %%R in (%SLEEP_SETTINGS%) do for /f "tokens=1,2 delims=:" %%G in ("%%R") do (
    call :read_power_values %%G %%H pw
    if not defined pw_AC set "known="
    if defined pw_AC (
        if !pw_AC! gtr %SLEEP_NEVER_ABOVE_SECONDS% set "pw_AC=0"
        if !pw_DC! gtr %SLEEP_NEVER_ABOVE_SECONDS% set "pw_DC=0"
        if !pw_AC! gtr 0 if !ac! equ 0 set "ac=!pw_AC!"
        if !pw_AC! gtr 0 if !pw_AC! lss !ac! set "ac=!pw_AC!"
        if !pw_DC! gtr 0 if !dc! equ 0 set "dc=!pw_DC!"
        if !pw_DC! gtr 0 if !pw_DC! lss !dc! set "dc=!pw_DC!"
    )
)
rem Round seconds up to whole minutes without adding first (no 32-bit overflow).
set /a "ac_min=ac / 60, dc_min=dc / 60, ac_rem=ac %% 60, dc_rem=dc %% 60"
if !ac_rem! gtr 0 set /a "ac_min+=1"
if !dc_rem! gtr 0 set /a "dc_min+=1"
set "sleep_text="
if not defined known set "sleep_text=unknown (power settings could not be read)"
if not defined sleep_text if !ac! equ 0 if !dc! equ 0 set "sleep_text=never, on mains or battery"
if not defined sleep_text if !ac! equ 0 set "sleep_text=never on mains; after !dc_min! min on battery"
if not defined sleep_text if !dc! equ 0 set "sleep_text=after !ac_min! min on mains; never on battery"
if not defined sleep_text set "sleep_text=after !ac_min! min on mains; after !dc_min! min on battery"
if not defined known (
    set "msg=The power settings could not be read: make sure this machine won't sleep or hibernate during the copy."
    call :add_warning msg
)
if defined known if !ac! gtr 0 (
    set "msg=This machine sleeps or hibernates after !ac_min! min idle, even on mains power: Windows may treat a long copy as idle and stop it part-way. Set sleep and hibernate to Never (Settings, System, Power)."
    call :add_warning msg
)
if defined known if !ac! equ 0 if !dc! gtr 0 (
    set "msg=On battery this machine sleeps after !dc_min! min idle: keep it plugged in for the whole copy."
    call :add_warning msg
)
call :read_power_values SUB_BUTTONS LIDACTION lid
set "lid_sleeps="
if defined lid_AC if !lid_AC! neq 0 set "lid_sleeps=1"
if defined lid_DC if !lid_DC! neq 0 set "lid_sleeps=1"
if defined lid_sleeps (
    set "msg=If this is a laptop, keep the lid open: closing it sleeps, hibernates or shuts it down."
    call :add_warning msg
)
endlocal & set "sleep_text=%sleep_text%" & set "n_warnings=%n_warnings%"
exit /b 0

:read_power_values  subgroup  setting  prefix
rem Set <prefix>_AC and <prefix>_DC to the current power plan's values for a
rem setting. powercfg /q prints the setting's min, max and increment and then
rem the AC and DC values, all as 0x numbers, so the last two 0x values are AC
rem and DC in any display language. Both stay undefined if it can't be read.
rem Caller's scope; the caller must have delayed expansion enabled.
set "%~3_AC="
set "%~3_DC="
set "pv_prev="
set "pv_last="
for /f "delims=" %%L in ('powercfg /q SCHEME_CURRENT %~1 %~2 2^>nul ^| find "0x"') do (
    set "pv_tok="
    for %%T in (%%L) do set "pv_tok=%%T"
    set "pv_prev=!pv_last!"
    set "pv_last=!pv_tok!"
)
if not defined pv_prev exit /b 1
set /a "%~3_AC=!pv_prev!, %~3_DC=!pv_last!" 2>nul || (
    set "%~3_AC="
    set "%~3_DC="
    exit /b 1
)
exit /b 0

:describe_windows  outVar
rem The OS as a person would name it: product, edition and release, e.g.
rem "Microsoft Windows 11 Pro 25H2", matching the form of WMI's Caption plus
rem release used by the PowerShell tools. "Microsoft " + registry ProductName
rem (corrected from "Windows 10" to "Windows 11" from build 22000, where the
rem registry still says 10) + DisplayVersion, or ReleaseId on older builds.
rem The build is read only for that correction, never shown.
setlocal EnableDelayedExpansion
set "cv=HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
for %%V in (ProductName DisplayVersion ReleaseId CurrentBuild) do (
    set "w_%%V="
    for /f "tokens=2,*" %%A in ('reg query "!cv!" /v %%V 2^>nul ^| find /i "%%V"') do set "w_%%V=%%B"
)
if not defined w_ProductName (
    endlocal
    set "%~1=unknown (ProductName not readable)"
    exit /b 0
)
set "build=0"
set /a "build=w_CurrentBuild" 2>nul
if !build! geq 22000 set "w_ProductName=!w_ProductName:Windows 10=Windows 11!"
set "release=!w_DisplayVersion!"
if not defined release set "release=!w_ReleaseId!"
set "text=Microsoft !w_ProductName!"
if defined release set "text=!text! !release!"
endlocal & set "%~1=%text%"
exit /b 0

:describe_volume  drive  outVar  fsOutVar
rem Describe the volume of a drive ("C:") for the log: VOL's label line and
rem serial number (no admin needed), and the file system from FS_METHODS.
rem A network path (drive "\\") gets "n/a". Sets fsOutVar to the file system
rem name, or clears it if unknown.
setlocal
set "drv=%~1"
if not "%drv:~1,1%"==":" (
    endlocal
    set "%~2=n/a (network path)"
    set "%~3="
    exit /b 0
)
set "vol_label="
set "vol_serial=unknown"
for /f "tokens=*" %%L in ('vol %drv% 2^>nul') do if not defined vol_label set "vol_label=%%L"
for /f "skip=1 tokens=*" %%L in ('vol %drv% 2^>nul') do for %%T in (%%L) do set "vol_serial=%%T"
if not defined vol_label set "vol_label=%drv% (label unknown)"
set "fs="
for %%M in (%FS_METHODS%) do if not defined fs call :fs_from_%%M %drv%
set "fs_text=%fs%"
if not defined fs set "fs_text=file system unknown"
endlocal & set "%~2=%vol_label%; serial %vol_serial%; %fs_text%" & set "%~3=%fs%"
exit /b 0

:fs_from_fsutil  drive
rem Caller's scope: set fs from "fsutil fsinfo volumeinfo" (may need admin).
for /f "delims=" %%L in ('fsutil fsinfo volumeinfo %~1 2^>nul') do for %%T in (%%L) do for %%F in (%KNOWN_FILESYSTEMS%) do (
    if not defined fs if /i "%%~T"=="%%F" set "fs=%%F"
)
exit /b 0

:fs_from_chkntfs  drive
rem Caller's scope: set fs from chkntfs ("... file system is NTFS.").
for /f "delims=" %%L in ('chkntfs %~1 2^>nul') do for %%T in (%%L) do for %%F in (%KNOWN_FILESYSTEMS%) do (
    if not defined fs if /i "%%~T"=="%%F" set "fs=%%F"
    if not defined fs if /i "%%~T"=="%%F." set "fs=%%F"
)
exit /b 0

:warn_destination_fs
rem Warn about a destination file system listed in FS_WARN_<name>. A warning
rem only: robocopy fails any file that doesn't fit.
setlocal EnableDelayedExpansion
set "msg=The destination file system is !dst_fs!: !FS_WARN_%dst_fs%!"
call :add_warning msg
endlocal & set /a "n_warnings+=1" & exit /b 0

rem ----------------------------- Log -----------------------------------------

:publish_log
rem Move the working log from TEMP to the destination. If that fails, say
rem where the log is so it isn't lost.
if not defined log_ready exit /b 0
setlocal EnableDelayedExpansion
move /y "!log_work!" "!log_file!" >nul 2>&1
if exist "!log_file!" if not exist "!log_work!" (
    echo Log saved: !log_file!
    endlocal & exit /b 0
)
echo [WARN] Could not move the log to the destination. It is here:
echo        !log_work!
endlocal & exit /b 1

rem ---------------------- Chain of custody helpers ---------------------------

:place_script_copy
rem The script travels with the evidence. If the source root holds a copy of
rem it, that copy went across with the evidence. Otherwise put a copy of this
rem script beside the logs in the destination, check it against the Script
rem SHA-256 in the header, and seal it with the logs. Never overwrites a file.
set "sc_has="
for /f "eol=/ delims=" %%F in ('dir /b /a-d "%source_cmp%%SCRIPT_FILE_PREFIX%*%SCRIPT_FILE_EXT%" 2^>nul') do set "sc_has=1"
if defined sc_has (
    set "v_script_copy=not needed: the source holds a copy, copied with the evidence"
    exit /b 0
)
set "sc_target=%destination_cmp%%script_file_name%"
if exist "%sc_target%" (
    set "v_script_copy=not placed: the destination already holds a file named %script_file_name%"
    set "msg=[WARN] The script was not copied to the destination: a file named %script_file_name% is already there."
    call :emit msg
    call :add_problem msg
    exit /b 0
)
copy /b "%script_path%" "%sc_target%" >nul 2>&1
set "sc_hash="
if exist "%sc_target%" call :get_sha256 sc_target sc_hash
if defined sc_hash if /i "%sc_hash%"=="%script_sha256%" (
    set "v_script_copy=placed in the destination as %script_file_name%; its SHA-256 matches the Script SHA-256 above"
    set "script_copy_file=%sc_target%"
    exit /b 0
)
set "v_script_copy=FAILED: no verified copy of the script in the destination"
set "msg=[WARN] Could not place a verified copy of the script in the destination."
call :emit msg
call :add_problem msg
exit /b 0

:find_reference_csv
rem Find the reference record: the oldest source hash record in the source
rem root (robocopy_<UTC>_hashes_source.csv, oldest by name, as names start
rem with the UTC time; names without a timestamp are ignored). It is chosen
rem from the source, so an unrelated older record already in a non-empty
rem destination can't be picked, and read from the destination after the
rem copy. Sets reference_name, or leaves it empty if the source holds none.
for /f "delims=" %%F in ('dir /b /a-d /on "%source_cmp%robocopy_*_hashes_source.csv" 2^>nul') do (
    if not defined reference_name call :consider_reference "%%F"
)
exit /b 0

:consider_reference  fileName
set "cr_name=%~1"
set "cr_char=%cr_name:~9,1%"
if "%cr_char%" lss "0" exit /b 0
if "%cr_char%" gtr "9" exit /b 0
set "reference_name=%cr_name%"
exit /b 0

:compare_with_reference
rem Compare the destination with the reference record: every file in the
rem record must be in the destination with the same SHA-256. Both lists are
rem written as "relpath*hash*tag" (* can't occur in Windows names), sorted
rem ordinally (sort /L C) so each path's two lines are adjacent, then paired
rem up in one pass.
set "msg=" & call :emit msg
set "msg=--- Destination vs reference record: %reference_name% ---"
call :emit msg
for /f "usebackq skip=1 delims=" %%L in ("%reference_csv%") do (
    set "ln=%%L"
    call :add_reference_row
)
if not exist "%tmp_merge%" type nul >"%tmp_merge%"
sort /L C /O "%tmp_merge_sorted%" "%tmp_merge%"
set "prev_rel="
set "prev_hash="
set "prev_tag="
for /f "usebackq eol=* delims=" %%L in ("%tmp_merge_sorted%") do (
    set "ln=%%L"
    call :compare_line
)
call :compare_flush
exit /b 0

:add_reference_row
rem Turn one row of the reference record ("rel","hash", maybe with trailing
rem spaces from 1.0.x) into a merge line "rel*hash*R".
setlocal EnableDelayedExpansion
set "row=!ln!"
:add_reference_row_trim
if "!row:~-1!"==" " (
    set "row=!row:~0,-1!"
    goto add_reference_row_trim
)
set "x=!row:","=*!"
set "x=!x:"=!"
if "!x:**=!"=="!x!" (
    set "msg=[FAIL] Unreadable row in the reference record: !row!"
    call :emit msg
    call :add_problem msg
    endlocal & set /a "c_invalid+=1" & exit /b 0
)
>>"!tmp_merge!" echo(!x!*R
endlocal & set /a "c_rows+=1" & exit /b 0

:compare_line
rem Process one sorted merge line (in "ln"): pair it with the previous line
rem if both are the same path, otherwise settle the previous line alone.
setlocal EnableDelayedExpansion
for %%V in (d_ok d_changed d_missing d_invalid d_unreadable d_records d_added) do set "%%V=0"
set "cur=!ln!"
set "tag=!cur:~-1!"
set "rest=!cur:~0,-2!"
set "hash=!rest:**=!"
call :strlen hash hash_len
set /a "cut=hash_len + 1"
for %%N in (!cut!) do set "rel=!rest:~0,-%%N!"
set "new_rel=!rel!"
set "new_hash=!hash!"
set "new_tag=!tag!"
if defined prev_rel if "!prev_rel!"=="!rel!" (
    if "!tag!"=="R" (
        set "ref_hash=!hash!"
        set "now_hash=!prev_hash!"
    ) else (
        set "ref_hash=!prev_hash!"
        set "now_hash=!hash!"
    )
    set "c_status="
    set "c_counter="
    if "!tag!"=="!prev_tag!" set "c_status=listed twice" & set "c_counter=d_invalid"
    if not defined c_status call :is_sha256 ref_hash || (set "c_status=no valid hash in the reference record" & set "c_counter=d_invalid")
    if not defined c_status if "!now_hash!"=="UNREADABLE" set "c_status=UNREADABLE in the destination" & set "c_counter=d_unreadable"
    if not defined c_status if /i not "!ref_hash!"=="!now_hash!" set "c_status=DIFFERS from the reference record" & set "c_counter=d_changed"
    if defined c_status (
        set "msg=[FAIL] !c_status!: !rel!"
        call :emit msg
        call :add_problem msg
        set "!c_counter!=1"
    ) else set "d_ok=1"
    set "new_rel="
    set "new_hash="
    set "new_tag="
) else if defined prev_rel call :compare_single prev_rel prev_tag
endlocal & set "prev_rel=%new_rel%" & set "prev_hash=%new_hash%" & set "prev_tag=%new_tag%" & set /a "c_ok+=%d_ok%, c_changed+=%d_changed%, c_missing+=%d_missing%, c_invalid+=%d_invalid%, c_unreadable+=%d_unreadable%, c_records+=%d_records%, c_added+=%d_added%"
exit /b 0

:compare_flush
rem Settle the last unpaired merge line, if any.
if not defined prev_rel exit /b 0
setlocal EnableDelayedExpansion
for %%V in (d_missing d_records d_added) do set "%%V=0"
call :compare_single prev_rel prev_tag
endlocal & set /a "c_missing+=%d_missing%, c_records+=%d_records%, c_added+=%d_added%"
exit /b 0

:compare_single  relVar  tagVar
rem A path found on one side only. In the reference record but not in the
rem destination: missing (FAIL). In the destination but not in the record:
rem added since; a custody record of an earlier run (robocopy_* in the root)
rem is expected, anything else is a warning. Caller's scope, delayed on.
if "!%~2!"=="R" (
    set "msg=[FAIL] MISSING from the destination (in the reference record): !%~1!"
    call :emit msg
    call :add_problem msg
    set "d_missing=1"
    exit /b 0
)
set "cs_rel=!%~1!"
if "!cs_rel:\=!"=="!cs_rel!" if /i "!cs_rel:~0,9!"=="robocopy_" (
    set "d_records=1"
    exit /b 0
)
call :is_script_copy cs_rel && (
    set "d_records=1"
    exit /b 0
)
set "msg=[WARN] Not in the reference record (added since, so not verified against it): !cs_rel!"
call :emit msg
call :add_problem msg
set "d_added=1"
exit /b 0

:verification_status
rem Set hash_status and meta_status (each PASS, FAIL or NOT RUN), verify_status
rem (PASS only if both pass), and the summary lines for each.
set "v_ref_used=%reference_name%"
if not defined v_ref_used set "v_ref_used=none"
set /a "hash_bad=c_changed + c_missing + c_invalid + c_unreadable + n_anomalies + verify_incomplete"
set "hash_status=PASS"
if %hash_bad% neq 0 set "hash_status=FAIL"
if %c_ok% equ 0 set "hash_status=FAIL"
set "v_verify=%hash_status%: %c_ok% of %c_rows% files in the reference record match the destination"
set "v_verify_detail=%c_changed% differ, %c_missing% missing, %c_unreadable% unreadable, %c_invalid% invalid in the record; added since: %c_records% custody record(s), %c_added% other file(s)"
if %verify_incomplete% neq 0 set "v_verify_detail=%v_verify_detail%; INCOMPLETE (see problems)"
if %n_anomalies% neq 0 set "v_verify_detail=%v_verify_detail%; %n_anomalies% unexpected listing line(s)"
set "meta_status=NOT RUN"
set "v_meta=NOT RUN"
if defined meta_ran set "meta_status=PASS"
if defined meta_ran set "v_meta=PASS: size and last-modified time match for every file (compared %meta_mode%)"
if %m_differ% neq 0 set "meta_status=FAIL"
if %m_differ% neq 0 set "v_meta=FAIL: %m_differ% file(s) differ in size or last-modified time, or were not copied"
if %m_incomplete% neq 0 set "meta_status=FAIL"
if %m_incomplete% neq 0 set "v_meta=FAIL: the comparison was incomplete"
set "verify_status=PASS"
if not "%hash_status%"=="PASS" set "verify_status=FAIL"
if not "%meta_status%"=="PASS" set "verify_status=FAIL"
exit /b 0

:is_sha256  hashVar
rem Exit 0 if the variable holds exactly 64 hex characters.
setlocal EnableDelayedExpansion
set "h=!%~1!"
if not defined h (endlocal & exit /b 1)
if not "!h:~64!"=="" (endlocal & exit /b 1)
if "!h:~63,1!"=="" (endlocal & exit /b 1)
for /f "delims=0123456789abcdefABCDEF" %%X in ("!h!") do (endlocal & exit /b 1)
endlocal & exit /b 0

:write_seal
rem Seal this run's custody records: write the SHA-256 of the log and hash
rem CSVs to robocopy_<UTC>.sha256 in the destination, then show the seal's
rem own SHA-256 for the user's chain-of-custody notes. With that value
rem recorded elsewhere, any later change to these records can be detected.
rem With neither a log nor hash CSVs there is no record to seal, so a copy of
rem the script alone isn't sealed either.
if not "%use_log%"=="1" if not "%verify%"=="1" exit /b 0
setlocal EnableDelayedExpansion
set "sealed=0"
for %%F in (log_file csv_source csv_destination script_copy_file) do (
    if exist "!%%F!" (
        set "sf=!%%F!"
        call :get_sha256 sf sh
        for %%N in ("!sf!") do set "sn=%%~nxN"
        if defined sh (
            >>"!seal_file!" echo(!sh! *!sn!
            set /a "sealed+=1"
        ) else (
            echo [WARN] Could not hash !sn! for the seal.
        )
    )
)
if !sealed! equ 0 (endlocal & exit /b 0)
set "seal_hash="
call :get_sha256 seal_file seal_hash
echo.
echo Custody records sealed in: !seal_name!
if defined seal_hash (
    echo   SHA-256: !seal_hash!
    echo Record this value in your chain-of-custody notes: it shows whether this
    echo run's log and hash CSVs are later changed.
) else (
    echo [WARN] Could not hash the seal file.
)
endlocal & exit /b 0

rem ------------------------ Verification helpers ------------------------------

:list_files  rootVar  outFileVar
rem Write every file under the root to the out file as a full path, one per
rem line, using robocopy (sees Hidden/System files and long paths) and the
rem same root exclusions as the copy. Exit 1 if robocopy reports a failure.
setlocal EnableDelayedExpansion
set "excl_args="
set "side=%~1"
call :add_root_exclusions !side:_cmp=!
robocopy "!%~1! " "!temp_prefix!_nonexistent" *.* !LIST_FLAGS! !backup_flag! !excl_args! >"!%~2!" 2>&1
set "rc=!errorlevel!"
if !rc! geq 8 (
    set "msg=[FAIL] Could not list every file under !%~1! (robocopy exit code !rc!)."
    call :emit msg
    call :add_problem msg
    endlocal & exit /b 1
)
endlocal & exit /b 0

:hash_listed_entry  rootVar  side
rem Hash one listed file (in "entry") and record it as a "rel","hash" row for
rem the side's CSV; for the destination also as a "rel*hash*C" line for the
rem comparison with the reference record. This run's own outputs are skipped.
setlocal EnableDelayedExpansion
set "full=!entry!"
call :relative_path full %~1 rel || (
    set "msg=[FAIL] Unexpected line while listing the %~2: !full!"
    call :emit msg
    call :add_problem msg
    endlocal & set /a "n_anomalies+=1" & exit /b 0
)
for %%O in (log_file csv_source csv_destination seal_file) do if /i "!full!"=="!%%O!" (endlocal & exit /b 0)
if "%~2"=="source" call :is_script_copy rel && (endlocal & exit /b 0)
set /a "seq=n_hashed_%~2 + 1"
set "msg=[!seq!/!n_listed!] Hashing %~2: !rel!" & call :say msg
call :get_sha256 full h
if not defined h set "h=UNREADABLE"
>>"!tmp_rows_%~2!" echo("!rel!","!h!"
if "%~2"=="destination" >>"!tmp_merge!" echo(!rel!*!h!*C
endlocal & set /a "n_hashed_%~2+=1" & exit /b 0

:write_hash_csv  side
rem Write the side's CSV: header plus rows sorted by relative path, so it
rem doesn't depend on the order in which a file system lists files.
setlocal EnableDelayedExpansion
>"!csv_%~1!" echo "File","SHA-256"
if exist "!tmp_rows_%~1!" sort "!tmp_rows_%~1!" >>"!csv_%~1!"
endlocal & exit /b 0

:get_sha256  pathVar  outVar
rem Set outVar to the file's SHA-256 (64 hex characters). Clear it if certutil
rem fails or prints anything else, so a failure can never look like a hash.
rem certutil can't hash empty files: a file of size 0 gets EMPTY_SHA256. The
rem size check is skipped for names containing "?" (a character the console
rem code page couldn't show), where FOR could match a different file.
setlocal EnableDelayedExpansion
set "p=!%~1!"
set "h="
for /f "skip=1 delims=" %%H in ('certutil -hashfile "!p!" SHA256 2^>nul') do if not defined h set "h=%%H"
if defined h set "h=!h: =!"
if defined h if not "!h:~64!"=="" set "h="
if defined h if "!h:~63,1!"=="" set "h="
if defined h for /f "delims=0123456789abcdefABCDEF" %%X in ("!h!") do set "h="
if not defined h if "!p:?=!"=="!p!" (
    set "size="
    for %%A in ("!p!") do set "size=%%~zA"
    if "!size!"=="0" set "h=!EMPTY_SHA256!"
)
endlocal & set "%~2=%h%"
exit /b 0

rem ---------------------------- Copy helpers ----------------------------------

:add_root_exclusions  side
rem Append "/xd" and "/xf" with the full paths of the housekeeping items
rem found at the side's root (tmp_baggage_<side>) to excl_args. Caller's
rem scope; the caller must have delayed expansion enabled. A name containing
rem "!" can't be passed this way: that item is then copied, never dropped.
set "ar_file=!tmp_baggage_%~1!"
if not defined ar_file exit /b 0
if not exist "!ar_file!" exit /b 0
set "ar_xd="
set "ar_xf="
for /f "usebackq tokens=1* delims=:" %%A in ("!ar_file!") do (
    if "%%A"=="D" set "ar_xd=!ar_xd! "!%~1_cmp!%%~B""
    if "%%A"=="F" set "ar_xf=!ar_xf! "!%~1_cmp!%%~B""
)
if defined ar_xd set "excl_args=!excl_args! /xd!ar_xd!"
if defined ar_xf set "excl_args=!excl_args! /xf!ar_xf!"
exit /b 0

:auto_thread_count  outVar
rem Logical processors / THREAD_DIVISOR, kept within 1..THREAD_MAX.
setlocal
set "n="
set /a "n=NUMBER_OF_PROCESSORS / THREAD_DIVISOR" 2>nul
if not defined n set "n=1"
if %n% lss 1 set "n=1"
if %n% gtr %THREAD_MAX% set "n=%THREAD_MAX%"
endlocal & set "%~1=%n%"
exit /b 0

:report_robocopy_rc  rcVar
rem Explain each bit set in a robocopy exit code (see the RC_* table).
setlocal EnableDelayedExpansion
set /a "rc=!%~1!"
set "msg=Robocopy exit code: !rc!" & call :emit msg
if !rc! equ 0 (
    set "msg=  [INFO] No files were copied in this pass."
    call :emit msg
)
for %%B in (%RC_BITS%) do (
    set /a "bit=rc & %%B"
    if !bit! neq 0 (
        set "msg=  [!RC_%%B_SEVERITY!] !RC_%%B_TEXT!"
        call :emit msg
        if not "!RC_%%B_SEVERITY!"=="INFO" call :add_problem msg
    )
)
endlocal & exit /b 0

rem ------------------------------ Input --------------------------------------

:ask_choice  outVar  validChoices
rem Read input until it is one of the space-separated validChoices. Exit 1
rem (with abort_reason) after MAX_PROMPT_ATTEMPTS invalid answers.
setlocal EnableDelayedExpansion
set "tries=0"
:ask_choice_loop
set /a "tries+=1"
if !tries! gtr %MAX_PROMPT_ATTEMPTS% (
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

:ask_directory  outVar  prompt  mustExist  allowDefault
rem Prompt with "<prompt>: " for a directory until it is valid. Sets outVar
rem (full path) and outVar_cmp (full path with a trailing backslash). With
rem allowDefault=1, default_source is shown on the line above the prompt and
rem an empty answer takes it (sets dir_used_default). Anything that isn't a
rem full path is simply asked again. Exit 1 (with abort_reason) after
rem MAX_PROMPT_ATTEMPTS invalid answers.
set "dir_tries=0"
set "dir_used_default="
:ask_directory_loop
set /a "dir_tries+=1"
if %dir_tries% gtr %MAX_PROMPT_ATTEMPTS% (
    set "abort_reason=No valid folder after %MAX_PROMPT_ATTEMPTS% attempts (no console input?)."
    exit /b 1
)
set "path_in="
set "dir_used_default="
if "%~4"=="1" if defined default_source (
    set "msg=Default (the script's folder): %default_source%"
    call :say msg
)
set /p "path_in=%~2: "
if not defined path_in if "%~4"=="1" if defined default_source (
    set "path_in=%default_source%"
    set "dir_used_default=1"
)
call :normalise_path
if errorlevel 1 goto ask_directory_loop
if exist "%path_out%" if not exist "%path_cmp%" (
    echo That is a file, not a directory.
    goto ask_directory_loop
)
if "%~3"=="1" if not exist "%path_cmp%" (
    echo Directory not found.
    if defined is_admin if "%path_out:~1,1%"==":" (
        echo As administrator, drive letters mapped in your normal session are not
        echo visible. For a network share, enter its UNC path: \\server\share\...
    )
    goto ask_directory_loop
)
set "%~1=%path_out%"
set "%~1_cmp=%path_cmp%"
exit /b 0

:normalise_path
rem IN: path_in. OUT: path_out (full path, no trailing backslash unless a drive
rem root) and path_cmp (path_out with exactly one trailing backslash). Exit 1
rem if empty or not a full path: relative paths would resolve against the
rem current directory, which is System32 when run as administrator.
rem Accepts quotes, forward slashes, "E:" for a drive root, and any number of
rem trailing backslashes, so every way of typing a folder means its contents.
set "path_out="
set "path_cmp="
if not defined path_in exit /b 1
set "path_in=%path_in:"=%"
if not defined path_in exit /b 1
for /f "tokens=* delims= " %%A in ("%path_in%") do set "path_in=%%A"
if not defined path_in exit /b 1
set "path_in=%path_in:/=\%"
if "%path_in:~1%"==":" set "path_in=%path_in%\"
set "path_ok="
if "%path_in:~1,2%"==":\" set "path_ok=1"
if "%path_in:~0,2%"=="\\" set "path_ok=1"
if not defined path_ok exit /b 1
for %%A in ("%path_in%") do set "path_out=%%~fA"
if not defined path_out exit /b 1
:normalise_path_trim
if "%path_out:~-1%"=="\" if not "%path_out:~-2%"==":\" if not "%path_out%"=="\" (
    set "path_out=%path_out:~0,-1%"
    goto normalise_path_trim
)
set "path_cmp=%path_out%"
if not "%path_cmp:~-1%"=="\" set "path_cmp=%path_cmp%\"
exit /b 0

:paths_overlap
rem Exit 0 if source and destination are the same directory or one is inside
rem the other (case-insensitive). A mapped drive and its UNC path are not
rem recognised as the same place.
setlocal EnableDelayedExpansion
call :strlen source_cmp len_s
call :strlen destination_cmp len_d
set "overlap=1"
if !len_s! leq !len_d! (
    for %%N in (!len_s!) do if /i "!destination_cmp:~0,%%N!"=="!source_cmp!" set "overlap=0"
) else (
    for %%N in (!len_d!) do if /i "!source_cmp:~0,%%N!"=="!destination_cmp!" set "overlap=0"
)
endlocal & exit /b %overlap%

rem ------------------------------- Time --------------------------------------

:get_utc_now
rem Set utc_digits (YYYYMMDDhhmmss), utc_compact (YYYYMMDDThhmmssZ), utc_iso
rem (YYYY-MM-DDThh:mm:ssZ) and utc_method, trying each of UTC_METHODS in turn.
rem If none works, use a placeholder and flag a warning: never local time.
set "utc_digits="
set "utc_method="
for %%M in (%UTC_METHODS%) do if not defined utc_method (
    set "utc_digits="
    call :utc_from_%%M
    call :is_timestamp_digits && set "utc_method=%%M"
)
if not defined utc_method (
    set "utc_compact=unknown-time-%RANDOM%"
    set "utc_iso=unknown"
    set "utc_method=none"
    set "timestamp_warning=1"
    exit /b 1
)
set "utc_compact=%utc_digits:~0,8%T%utc_digits:~8,6%Z"
set "utc_iso=%utc_digits:~0,4%-%utc_digits:~4,2%-%utc_digits:~6,2%T%utc_digits:~8,2%:%utc_digits:~10,2%:%utc_digits:~12,2%Z"
exit /b 0

:utc_from_wmic
rem Fallback: WMI's Win32_UTCTime. wmic is deprecated and not installed by
rem default from Windows 11 24H2.
setlocal EnableDelayedExpansion
for %%F in (Year Month Day Hour Minute Second) do set "w_%%F="
for /f "tokens=1,2 delims==" %%A in ('wmic path Win32_UTCTime get Day^,Hour^,Minute^,Month^,Second^,Year /value 2^>nul') do for /f %%C in ("%%B") do set "w_%%A=%%C"
if not defined w_Year (endlocal & exit /b 1)
for %%F in (Month Day Hour Minute Second) do (
    set "w_%%F=0!w_%%F!"
    set "w_%%F=!w_%%F:~-2!"
)
set "t=!w_Year!!w_Month!!w_Day!!w_Hour!!w_Minute!!w_Second!"
endlocal & set "utc_digits=%t%"
exit /b 0

:utc_from_robocopy
rem Robocopy's error lines carry the local time as YYYY/MM/DD hh:mm:ss in every
rem locale; add the registry's ActiveTimeBias (which includes DST) for UTC.
rem The bias is read before and after the clock: if they differ, a DST change
rem happened in between and the reading is retried (up to 3 attempts).
setlocal EnableDelayedExpansion
set "attempt=0"
:utc_from_robocopy_retry
set /a "attempt+=1"
if !attempt! gtr 3 (endlocal & exit /b 1)
call :get_utc_bias_minutes bias || (endlocal & exit /b 1)
set "local="
for /f "tokens=1,2" %%A in ('robocopy "|" . /njh /r:0 /w:0 2^>nul') do if not defined local (
    set "rd=%%A"
    set "rt=%%B"
    if "!rd:~4,1!!rd:~7,1!!rt:~2,1!!rt:~5,1!"=="//::" set "local=!rd:/=!!rt::=!"
)
if not defined local (endlocal & exit /b 1)
call :get_utc_bias_minutes bias_after || (endlocal & exit /b 1)
if not "!bias!"=="!bias_after!" goto utc_from_robocopy_retry
set "utc_digits=!local!"
call :is_timestamp_digits || (endlocal & exit /b 1)
call :add_minutes_to_digits local !bias! result
endlocal & set "utc_digits=%result%"
exit /b 0

:get_utc_bias_minutes  outVar
rem Minutes to add to local time to get UTC (ActiveTimeBias, includes DST).
setlocal
set "b="
for /f "tokens=3" %%V in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" /v ActiveTimeBias 2^>nul ^| find /i "ActiveTimeBias"') do set "b=%%V"
if not defined b (endlocal & exit /b 1)
set /a "b=%b%" 2>nul || (endlocal & exit /b 1)
endlocal & set "%~1=%b%"
exit /b 0

:format_utc_offset  outVar
rem Local offset from UTC as +hh:mm / -hh:mm, or "unknown".
setlocal
call :get_utc_bias_minutes bias || (endlocal & set "%~1=unknown" & exit /b 1)
set /a "off=-bias"
set "sign=+"
if %off% lss 0 (
    set "sign=-"
    set /a "off=-off"
)
set /a "hh=off / 60, mm=off %% 60"
if %hh% lss 10 set "hh=0%hh%"
if %mm% lss 10 set "mm=0%mm%"
endlocal & set "%~1=%sign%%hh%:%mm%"
exit /b 0

:add_minutes_to_digits  inVar  minutes  outVar
rem Add minutes (may be negative) to a YYYYMMDDhhmmss value, with correct
rem day, month, year and leap-year rollover. Converts to days since
rem 1970-01-01 and back (H. Hinnant's days_from_civil / civil_from_days).
setlocal EnableDelayedExpansion
set "t=!%~1!"
set /a "y=1!t:~0,4! - 10000, mo=1!t:~4,2! - 100, d=1!t:~6,2! - 100, h=1!t:~8,2! - 100, mi=1!t:~10,2! - 100"
set "s=!t:~12,2!"
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

:is_timestamp_digits
rem Exit 0 if utc_digits is exactly 14 decimal digits.
setlocal EnableDelayedExpansion
set "t=!utc_digits!"
if not defined t (endlocal & exit /b 1)
if not "!t:~14!"=="" (endlocal & exit /b 1)
if "!t:~13,1!"=="" (endlocal & exit /b 1)
for /f "delims=0123456789" %%X in ("!t!") do (endlocal & exit /b 1)
endlocal & exit /b 0

rem ----------------------------- General -------------------------------------

:say  msgVar
rem Print a variable's value to the console.
setlocal EnableDelayedExpansion
echo(!%~1!
endlocal & exit /b 0

:emit  msgVar
rem Print a variable's value to the console and, in log mode once the log
rem exists, append it to the log.
setlocal EnableDelayedExpansion
echo(!%~1!
if defined log_ready >>"!log_work!" echo(!%~1!
endlocal & exit /b 0

:emit_kv  label  valueVar
rem Emit "  label     : value" with the labels aligned under a section title.
setlocal EnableDelayedExpansion
set "kv_label=%~1                    "
set "msg=  !kv_label:~0,18!: !%~2!"
call :emit msg
endlocal & exit /b 0

:emit_more  valueVar
rem Emit a continuation line, aligned with the values of :emit_kv.
setlocal EnableDelayedExpansion
set "msg=                      !%~1!"
call :emit msg
endlocal & exit /b 0

:add_problem  msgVar
rem Remember a problem line for the end-of-run summary.
setlocal EnableDelayedExpansion
>>"!tmp_problems!" echo(!%~1!
endlocal & exit /b 0

:show_problems
rem List remembered problems on the console (in log mode they are also in
rem the log).
setlocal EnableDelayedExpansion
if not exist "!tmp_problems!" (endlocal & exit /b 0)
echo.
echo Problems found during this run:
type "!tmp_problems!"
endlocal & exit /b 0

:relative_path  fullVar  rootVar  outVar
rem Set outVar to fullVar without the rootVar prefix; exit 1 if fullVar does not
rem start with it. Caller's scope; the caller must have delayed expansion on.
call :strlen %~2 rp_len
set "rp_prefix="
set "%~3="
for %%N in (!rp_len!) do (
    set "rp_prefix=!%~1:~0,%%N!"
    set "%~3=!%~1:~%%N!"
)
if /i not "!rp_prefix!"=="!%~2!" exit /b 1
if not defined %~3 exit /b 1
exit /b 0

:is_script_copy  relVar
rem Exit 0 if the relative path is a root-level copy of this script:
rem SCRIPT_FILE_PREFIX ... SCRIPT_FILE_EXT, case-insensitive.
setlocal EnableDelayedExpansion
set "r=!%~1!"
if not "!r:\=!"=="!r!" (endlocal & exit /b 1)
call :strlen SCRIPT_FILE_PREFIX pl
call :strlen SCRIPT_FILE_EXT el
for %%P in (!pl!) do if /i not "!r:~0,%%P!"=="!SCRIPT_FILE_PREFIX!" (endlocal & exit /b 1)
for %%E in (!el!) do if /i not "!r:~-%%E!"=="!SCRIPT_FILE_EXT!" (endlocal & exit /b 1)
endlocal & exit /b 0

:is_drive_root  pathVar
rem Exit 0 if the path (in its trailing-backslash form) is a drive root: "X:\".
setlocal EnableDelayedExpansion
set "r=!%~1!"
if not "!r:~3!"=="" (endlocal & exit /b 1)
if not "!r:~1,2!"==":\" (endlocal & exit /b 1)
endlocal & exit /b 0

:each_item  listVar  callback
rem Call :<callback> "<item>" for each "|"-separated item of the list
rem variable. Splitting with FOR /F keeps * and ? intact (a plain FOR would
rem treat them as a file search). Caller's scope, so the callback's
rem variables persist; items are CONFIG values, safe to pass to CALL.
set "ei_rest=%~1"
call set "ei_rest=%%%ei_rest%%%"
:each_item_loop
if not defined ei_rest exit /b 0
set "ei_item="
for /f "tokens=1* delims=|" %%A in ("%ei_rest%") do (
    set "ei_item=%%A"
    set "ei_rest=%%B"
)
if not defined ei_item set "ei_rest="
if defined ei_item call :%~2 "%ei_item%"
goto each_item_loop

:strlen  stringVar  outVar
rem Length of a variable's value.
setlocal EnableDelayedExpansion
set "s=!%~1!#"
set "len=0"
for %%P in (4096 2048 1024 512 256 128 64 32 16 8 4 2 1) do if not "!s:~%%P,1!"=="" (
    set /a "len+=%%P"
    set "s=!s:~%%P!"
)
endlocal & set "%~2=%len%"
exit /b 0

:cleanup_temp
rem Delete this run's temporary files; a failed delete never stops the run.
setlocal EnableDelayedExpansion
for %%T in (tmp_list tmp_rows_source tmp_rows_destination tmp_problems tmp_merge tmp_merge_sorted tmp_clock tmp_warnings tmp_baggage_source tmp_baggage_destination) do (
    if defined %%T if exist "!%%T!" del /f /q "!%%T!" >nul 2>&1
)
endlocal & exit /b 0
