:: SPDX-License-Identifier: 0BSD
@echo off
rem ===========================================================================
rem evidence-robocopy - copy digital evidence between drives with robocopy,
rem verify every file by SHA-256 against a reference record and by size and
rem last-modified time, and keep a sealed record of every copy with the
rem evidence.
rem
rem Usage:   evidence-robocopy.bat       forensic mode (default): log, SHA-256
rem                                      verification and run records; asks
rem                                      only for source and destination
rem          evidence-robocopy.bat /nonforensic
rem                                      plain copy utility: ETA progress, no
rem                                      log or records, optional verification
rem          evidence-robocopy.bat /?    show help
rem          Run as administrator for backup mode (/b).
rem Exit:    0 PASS, 1 FAIL, 2 UNVERIFIED (see EXIT_CODE_* in CONFIG)
rem Changes: see CHANGELOG.md. Licence: 0BSD, see LICENSE.
rem
rem Terms (README, log and code use them the same way):
rem  - Set directory: holds exactly one evidence directory and the custody
rem    files.
rem  - Evidence directory: the directory of evidence; nothing else is ever
rem    written into it.
rem  - Custody files: the script, the history (HISTORY_FILE_NAME) and the
rem    records directory (RECORDS_DIR_NAME), beside the evidence directory.
rem  - Run record: one run's directory in the records directory, sealed.
rem  - source / destination: the two directories robocopy copies between (in a
rem    forensic run, the evidence directories); source_set / destination_set:
rem    the set directories around them.
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
rem  - Splitting a history row is the one place delayed expansion is turned
rem    off inside a loop (:split_history_line): it is enabled only to change
rem    the separators, and the FOR /F that sets the fields runs after
rem    ENDLOCAL, so "!" in paths survives.
rem  - Per-directory variables are named <key>_path (no trailing backslash) and
rem    <key>_with_backslash (exactly one), e.g. source_set_with_backslash.
rem  - "Drive root" is the top of a volume (E:\), always written in full.
rem  - Output goes through :show (console only) or :show_and_log (console and,
rem    in a forensic run, the log):
rem        set "msg=Some text" & call :show_and_log msg
rem  - Lists of similar items are tables in CONFIG: add a row, not code.
rem  - Records are UTF-8 with CRLF line endings; every CSV cell is quoted.
rem ===========================================================================
setlocal EnableExtensions DisableDelayedExpansion

rem ============================== CONFIG =====================================

rem Version: plain MAJOR.MINOR.PATCH only (the script check compares them).
set "TOOL_NAME=evidence-robocopy"
set "TOOL_VERSION=2.1.0"

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

rem Volume housekeeping skipped only when a directory IS a drive root (E:\):
rem what Windows, macOS and Linux leave on a drive they are plugged into, not
rem evidence. Anywhere else (inside a directory, or any UNC path, which can't be
rem told apart from a directory) these names are contents and are copied:
rem wrongly copying them fails visibly, wrongly skipping them would silently
rem leave evidence out. Before copying, the drive root is checked and only the
rem items actually present are excluded, by exact path, and listed in the log.
rem Items are separated by "|" (invalid in Windows names; a plain FOR would
rem treat * and ? as a file search), * and ? are allowed. One row per origin:
rem add a row, not code. Directories:
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
rem   Linux desktops: GNOME volume info, KDE directory settings
set "DRIVE_ROOT_HOUSEKEEPING_FILES=%DRIVE_ROOT_HOUSEKEEPING_FILES%|.xdg-volume-info|.directory"

rem Directories of recovered fragments at a drive root ("|"-separated, * and ?
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
rem headers, sizes or classes). Files and subdirectories keep their data,
rem attributes and timestamps (DAT), so anything hidden in the evidence stays
rem hidden; owner and ACLs are not copied. /bytes logs exact sizes. /e
rem includes empty directories. /xj doesn't follow junctions: only what is
rem physically inside the source is copied, and junction loops (e.g.
rem "Application Data" in a user profile) can't recurse forever.
set "COPY_FLAGS=/e /xj /v /x /ts /fp /bytes /dcopy:DAT /copy:DAT"
set "LIST_FLAGS=/l /e /xj /njh /njs /ndl /nc /ns /fp /r:0 /w:0"

rem Post-copy metadata check: robocopy in list-only mode, source against
rem destination, lists only files it would copy, i.e. whose size or
rem last-modified time differ (or that are missing). /xx leaves out files that
rem exist only in the destination. No /v or class column, so nothing
rem localised is parsed. Attributes and creation time are copied but not
rem compared: exFAT can't hold every NTFS attribute.
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

rem The evidence directory in the destination is a new directory with the
rem source's name; its contents are the evidence. Robocopy copies the source
rem directory's attributes onto it; these are cleared again unless the directory
rem already had them. Fields per row, separated by ":": position in a FOR %%~a
rem attribute string, attrib letter, name.
set "CONTAINER_ATTRIBUTES=1:r:Read-only 3:h:Hidden 4:s:System"

rem Custody files beside the evidence directory (see Terms above):
rem   SCRIPT_FILE_PREFIX*SCRIPT_FILE_EXT  copies of this script (any version)
rem   HISTORY_FILE_NAME   the history: one row per run, newest last; a quick
rem                       overview, rebuilt by every run and checked against
rem                       the sealed run records
rem   RECORDS_DIR_NAME    one sealed run record per run: <run UTC>\, its files
rem                       named RECORD_FILE_PREFIX<run UTC>...
rem   PARTIAL_RUN_SUFFIX  a run record still being written back; a leftover
rem                       one means the write-back was interrupted
rem Set directories and the records directory may also hold names in
rem IGNORED_CUSTODY_FILES (left by browsing with Explorer or a Mac): they are
rem not copied, hashed or counted. Inside the evidence directory they are
rem evidence. Items: exact names, or a prefix ending in "*".
set "SCRIPT_FILE_PREFIX=evidence-robocopy"
set "SCRIPT_FILE_EXT=.bat"
set "HISTORY_FILE_NAME=evidence-robocopy-history.csv"
set "RECORDS_DIR_NAME=evidence-robocopy-records"
set "RECORD_FILE_PREFIX=evidence-robocopy_"
set "PARTIAL_RUN_SUFFIX=.partial"
set "IGNORED_CUSTODY_FILES=.DS_Store|._*|.apdisk|desktop.ini|Thumbs.db|.directory"

rem History columns, fixed for all of 2.x: the run records check compares
rem history lines byte for byte, so later 2.x versions add information as
rem new files in the run record, never as columns. Cells never contain '"'
rem or "|". The newest row's Seal SHA-256 is "see <its seal file>" in its
rem sealed copy: a seal can't contain its own hash. The next run fills it in.
set "HISTORY_HEADER="Run (UTC)","Result","Source directory","Source volume serial","Source volume","Destination set directory","Destination volume serial","Destination volume","Evidence files","Host","User","Script","Seal SHA-256""

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
call :switch_console_to_utf8
call :check_script_path || goto :abort
call :read_carriage_return
call :show_banner
call :check_robocopy || goto :abort
call :detect_elevation
if "%run_mode%"=="nonforensic" goto :main_nonforensic

rem --- Forensic run (the default): log, verification and run records -------
call :use_log_mode
call :ask_source_set || goto :abort
call :ask_destination_set || goto :abort
call :init_run || goto :abort
call :hash_this_script
call :read_history || goto :abort
call :check_environment
call :check_script_against_previous_run
call :check_location_against_previous_run
call :choose_script_copy
call :precheck_run_records
call :write_header
call :log_pre_copy_findings
for %%P in (%COPY_PASSES%) do call :run_copy_pass %%P
call :find_skipped_links
call :copy_custody_files
call :restore_destination_attributes
call :verify_copy
call :stage_script_copy
call :report_result
call :write_history
call :write_seal
call :publish_records
call :cleanup_temp
call :restore_console_code_page
pause
exit /b %exit_code%

rem --- Non-forensic run (/nonforensic): a plain copy utility ---------------
rem No log and no records; it doesn't know about custody files or histories
rem (they are copied like any other file). Verification, if chosen, is shown
rem on screen only.
:main_nonforensic
call :confirm_nonforensic || goto :abort
call :ask_plain_paths || goto :abort
call :ask_verification || goto :abort
call :init_plain_run || goto :abort
call :hash_this_script
call :check_environment
call :write_header
for %%P in (%COPY_PASSES%) do call :run_copy_pass %%P
call :find_skipped_links
call :restore_destination_attributes
if "%verification_enabled%"=="1" call :verify_plain_copy
call :report_result
call :cleanup_temp
call :restore_console_code_page
pause
exit /b %exit_code%

rem ============================ FUNCTIONS ====================================

rem --------------------------- Run steps -------------------------------------

:show_help
echo %TOOL_NAME% %TOOL_VERSION%
echo.
echo Forensic mode (default): copies an evidence directory, under its own name,
echo into a set directory in the destination, beside the custody files (this
echo script, %HISTORY_FILE_NAME%, %RECORDS_DIR_NAME%\).
echo A log is kept, every file is verified by SHA-256 against the reference
echo record (the set's first hash record) and by size and last-modified time,
echo and every earlier run record must still match its seal and the history.
echo Each run adds its record in %RECORDS_DIR_NAME%\^<run UTC^>\ and a row
echo to the history. Nothing is ever written to the source.
echo.
echo Source: Enter takes the script's own directory as the set directory
echo (S1). A typed directory is a set directory if it holds the custody files
echo (S2), the set's evidence directory if its parent does (S3), or raw
echo evidence (S4, a first copy).
echo Destination: an existing directory. The set directory is, by the first
echo rule that fits: the directory, if it holds custody files (D1); its
echo parent, if the directory has the evidence directory's name and the
echo parent holds custody files or nothing else (D2); the directory, if it is
echo empty or holds only a directory with the evidence directory's name (D3);
echo otherwise a directory in it named after the set (D4). A set directory
echo holding custody files is a rerun or update (confirmed); otherwise it must
echo hold nothing but an empty evidence directory. Nothing is written into
echo another set.
echo.
echo /nonforensic: a plain copy utility for non-evidence copies: copies the
echo source directory's contents into the destination with ETA progress, no log
echo and no records; optional SHA-256 verification, shown on screen only.
echo.
echo Records are UTF-8 with CRLF line endings. Files are written unbuffered
echo (robocopy /j), so verification reads them back from the drive.
echo Run as administrator to use backup mode (/b).
echo.
echo Exit codes: %EXIT_CODE_PASS% PASS, %EXIT_CODE_FAIL% FAIL, %EXIT_CODE_UNVERIFIED% UNVERIFIED (copied, not verified).
exit /b 0

:init_state
rem Counters and flags used across the run, all given a starting value here.
rem   copy_exit_codes            robocopy exit codes of all passes, OR-ed
rem   hashed_count_<side>        files hashed in the source / destination, and
rem                              custody files hashed in the destination
rem   unexpected_listing_lines   listing lines that weren't a path in the
rem                              directory
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
rem   added_file_count           evidence files added since the reference record
rem   reference_seal_failed      1 if the reference record's run record fails
rem                              its checks
rem   run_records_checked        defined once the run records were checked
rem   run_record_count           run records checked
rem   run_record_file_match_count  files in them that match their seal
rem   run_record_problem_count   run record problems (see :check_run_records)
rem   utc_clock_failed           1 if no UTC_METHODS worked (see :get_utc_now)
for %%V in (copy_exit_codes hashed_count_source hashed_count_destination hashed_count_custody unexpected_listing_lines hash_check_incomplete) do set "%%V=0"
for %%V in (metadata_differ_count metadata_check_incomplete reference_row_count match_count differ_count missing_count) do set "%%V=0"
for %%V in (unreadable_count invalid_row_count added_file_count reference_seal_failed utc_clock_failed) do set "%%V=0"
for %%V in (run_record_count run_record_file_match_count run_record_problem_count history_row_count) do set "%%V=0"
set "run_records_checked="
set "metadata_check_ran="
set "metadata_time_precision=exact"
set "log_ready="
set "exit_code=%EXIT_CODE_FAIL%"
set "result_script_copy=not attempted"
set "staging_dir="
set "staging_dir_missing="
set "seal_incomplete="
set "original_code_page="
set "history_base_path="
set "history_base_side="
set "history_base_missing="
set "reference_run="
set "reference_name="
set "reference_csv_path="
set "reference_seal_result_text="
set "previous_run="
set "script_status=NONE"
set "result_script=NONE: no earlier run in the history"
set "script_failure_message="
set "verification_enabled="
exit /b 0

:parse_args  arg1  arg2
rem Forensic mode unless /nonforensic is given. Anything else (an unknown
rem option, a directory dropped on the script, a second argument) stops the run,
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
    set "header_mode=forensic (default): log, SHA-256 verification and run records"
) else (
    set "header_mode=non-forensic (/nonforensic): plain copy, no log or records; not for evidence"
)
exit /b 0

:switch_console_to_utf8
rem Every record is UTF-8: switch the console to code page 65001 for the run.
rem :restore_console_code_page switches back on every exit. If the switch
rem can't be confirmed, the header says which code page was used and
rem :check_environment warns.
call :read_console_code_page original_code_page
chcp 65001 >nul 2>&1 <nul
call :read_console_code_page console_code_page
set "header_encoding=UTF-8 (code page 65001)"
if not "%console_code_page%"=="65001" set "header_encoding=code page %console_code_page% (the switch to UTF-8 failed)"
exit /b 0

:read_console_code_page  outVar
rem The active console code page: the last number in chcp's output, in any
rem display language (e.g. "Active code page: 850." gives 850).
setlocal EnableDelayedExpansion
set "number="
for /f "tokens=*" %%L in ('chcp 2^>nul ^<nul') do for %%T in (%%L) do set "number=%%T"
if defined number set "number=!number:.=!"
if not defined number set "number=unknown"
endlocal & set "%~1=%number%"
exit /b 0

:restore_console_code_page
rem Switch the console back to the code page it had before the run.
if not defined original_code_page exit /b 0
if "%original_code_page%"=="unknown" exit /b 0
chcp %original_code_page% >nul 2>&1 <nul
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
echo Check: a copy of this script that travelled with evidence should match
echo        the published release (its SHA-256 is in the log header).
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
fsutil dirty query %SystemDrive% >nul 2>&1 <nul
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

:confirm_nonforensic
rem /nonforensic is for non-evidence copies; choosing it must be confirmed.
echo NON-FORENSIC MODE: a plain copy with ETA progress. No log and no records
echo are kept, and custody files and histories are copied like any other file:
echo not for evidence.
echo 1. Continue with a non-forensic copy
echo 2. Stop
call :ask_choice nonforensic_answer "1 2" || exit /b 1
if "%nonforensic_answer%"=="2" (
    set "abort_reason=Stopped at the user's choice."
    exit /b 1
)
call :use_eta_mode
echo.
exit /b 0

:use_eta_mode
rem Show ETA and percentage (/eta) and keep no log file: not a custody record.
set "log_enabled=0"
set "robocopy_progress_flags=/eta"
set "header_progress=ETA and percentage, no log file (/eta): not a custody record"
exit /b 0

rem -- Set and evidence directories --------------------------------------------

:ask_source_set
rem Ask for the source and work out the set (rules S1-S4; README, "Set and
rem evidence directories"). Sets source_path / source_with_backslash (the
rem evidence directory robocopy copies from), source_set_path /
rem source_set_with_backslash (empty for raw evidence), evidence_directory_name,
rem set_directory_name and source_set_rule.
echo The evidence directory is copied, under its own name, into a set directory.
call :find_default_source_set
set "source_set_rejected_answers=0"
:ask_source_set_again
echo.
call :ask_directory source_given "SOURCE directory" 1 1 || exit /b 1
call :identify_source_set && exit /b 0
call :show identify_problem
call :count_rejected_answer source_set_rejected_answers "source directory" || exit /b 1
goto ask_source_set_again

:find_default_source_set
rem S1: offer the script's own directory for Enter when it is a set directory
rem with exactly one evidence directory and nothing unexpected.
set "default_source_path="
set "normalise_path_input=%script_dir%"
call :normalise_path || exit /b 0
set "inspect_directory_with_backslash=%normalise_path_with_backslash%"
call :inspect_set_directory
if not "%inspect_evidence_count%"=="1" exit /b 0
if not "%inspect_unexpected_count%"=="0" exit /b 0
set "default_source_path=%normalise_path_result%"
exit /b 0

:identify_source_set
rem Caller's scope. Apply rules S1-S4 to source_given_path (typed, or the
rem script's directory taken with Enter). On a problem, set identify_problem
rem and exit 1.
set "identify_problem="
set "source_set_path="
set "source_set_with_backslash="
set "given_holds_custody_files="
call :holds_custody_files source_given_with_backslash && set "given_holds_custody_files=1"
set "normalise_path_input=%source_given_path%\.."
set "source_parent_path="
call :normalise_path
if not errorlevel 1 if /i not "%normalise_path_result%"=="%source_given_path%" set "source_parent_path=%normalise_path_result%"
set "source_parent_with_backslash="
if defined source_parent_path set "source_parent_with_backslash=%normalise_path_with_backslash%"
set "parent_holds_custody_files="
if defined source_parent_path call :holds_custody_files source_parent_with_backslash && set "parent_holds_custody_files=1"
if defined given_holds_custody_files if defined parent_holds_custody_files (
    set "identify_problem=Both this directory and the directory above it hold custody files: type the set directory itself."
    exit /b 1
)
if defined given_holds_custody_files goto identify_source_set_rule_s2
if defined parent_holds_custody_files goto identify_source_set_rule_s3
rem S4: no custody files here or above: raw evidence, a first copy.
set "source_path=%source_given_path%"
set "source_with_backslash=%source_given_with_backslash%"
call :name_directory_for_copy source_path evidence_directory_name
set "set_directory_name=%evidence_directory_name%"
set "source_set_rule=S4: raw evidence (no custody files here or in the directory above): a first copy"
exit /b 0
:identify_source_set_rule_s2
rem S1/S2: the directory holds the custody files: it is the set directory.
set "source_set_path=%source_given_path%"
set "source_set_with_backslash=%source_given_with_backslash%"
set "inspect_directory_with_backslash=%source_set_with_backslash%"
call :inspect_set_directory
call :check_set_directory_contents source || exit /b 1
set "evidence_directory_name=%inspect_evidence_name%"
rem The evidence directory's name is found, not typed, so the prompt's check
rem for "%" doesn't cover it (review, 2026-10-16): same rule, same reason.
call :path_has_percent evidence_directory_name && (
    set "identify_problem=The set's evidence directory name contains %%, which can't be handled safely yet: rename it or choose another set."
    exit /b 1
)
set "source_path=%source_set_with_backslash%%evidence_directory_name%"
set "source_with_backslash=%source_path%\"
call :name_directory_for_copy source_set_path set_directory_name
set "source_set_rule=S2: the directory holds the custody files: it is the set directory"
if defined default_source_taken set "source_set_rule=S1: the script's directory (Enter): it is the set directory"
exit /b 0
:identify_source_set_rule_s3
rem S3: the directory above holds the custody files: this is its evidence
rem directory.
set "source_set_path=%source_parent_path%"
set "source_set_with_backslash=%source_parent_with_backslash%"
set "inspect_directory_with_backslash=%source_set_with_backslash%"
call :inspect_set_directory
call :check_set_directory_contents source || exit /b 1
for %%A in ("%source_given_path%") do set "source_given_name=%%~nxA"
if /i not "%inspect_evidence_name%"=="%source_given_name%" (
    set "identify_problem=The directory above holds custody files, but its evidence directory is %inspect_evidence_name%, not this one."
    exit /b 1
)
set "evidence_directory_name=%inspect_evidence_name%"
set "source_path=%source_given_path%"
set "source_with_backslash=%source_given_with_backslash%"
call :name_directory_for_copy source_set_path set_directory_name
set "source_set_rule=S3: the directory above holds the custody files: this is its evidence directory"
exit /b 0

:check_set_directory_contents  role
rem Caller's scope, after :inspect_set_directory. A set directory must hold
rem exactly one evidence directory and nothing unexpected; set identify_problem
rem and exit 1 if not. role: source or destination, for the message.
if not "%inspect_unexpected_count%"=="0" (
    set "identify_problem=The %~1 set directory holds something other than one evidence directory and the custody files, e.g. %inspect_unexpected_name%."
    exit /b 1
)
if "%inspect_evidence_count%"=="1" exit /b 0
if "%inspect_evidence_count%"=="0" if "%~1"=="destination" exit /b 0
if "%inspect_evidence_count%"=="0" (
    set "identify_problem=The %~1 set directory holds custody files but no evidence directory."
    exit /b 1
)
set "identify_problem=The %~1 set directory holds more than one directory besides the custody files (one is %inspect_evidence_name%): one evidence directory per set."
exit /b 1

:ask_destination_set
rem Ask for an existing destination and work out the set directory (rules D1-D4;
rem README, "Set and evidence directories"). Sets destination_set_path /
rem destination_set_with_backslash, destination_path /
rem destination_with_backslash (the evidence directory in it),
rem destination_set_rule, destination_state_text and destination_was_empty.
set "destination_set_rejected_answers=0"
:ask_destination_set_again
echo.
call :ask_directory destination_given "DESTINATION directory" 1 0 || exit /b 1
call :identify_destination_set || (
    call :show identify_problem
    call :count_rejected_answer destination_set_rejected_answers "destination directory" || exit /b 1
    goto ask_destination_set_again
)
set "overlap_first_with_backslash=%source_with_backslash%"
if defined source_set_with_backslash set "overlap_first_with_backslash=%source_set_with_backslash%"
set "overlap_second_with_backslash=%destination_set_with_backslash%"
call :paths_overlap && (
    echo Source and destination must not be the same, or inside each other.
    call :count_rejected_answer destination_set_rejected_answers "destination directory" || exit /b 1
    goto ask_destination_set_again
)
if "%destination_was_empty%"=="1" exit /b 0
echo.
echo The destination already holds this set (a rerun or an update): files
echo that differ are copied again, and every file is verified.
echo 1. Continue with this destination
echo 2. Enter a different destination
call :ask_choice destination_answer "1 2" || exit /b 1
if "%destination_answer%"=="2" goto ask_destination_set_again
exit /b 0

:identify_destination_set
rem Caller's scope. Work out the destination set from destination_given_path
rem (an existing directory) in two stages (README, "Set and evidence
rem directories"):
rem   1. Layout: rules D1-D4, the first that fits, say which directory is the
rem      set directory. The evidence directory's name (evidence_directory_name)
rem      is looked for before the destination's contents.
rem   2. State, the same for every rule (:check_destination_set_state): an
rem      existing set (rerun or update) or a new one, and is that valid?
rem Junk names (IGNORED_CUSTODY_FILES, and at a drive root the housekeeping
rem tables) never count as content. On a problem, set identify_problem
rem (naming its rule) and exit 1.
set "identify_problem="
set "destination_parent_path="
set "destination_parent_with_backslash="
set "normalise_path_input=%destination_given_path%\.."
call :normalise_path
if not errorlevel 1 if /i not "%normalise_path_result%"=="%destination_given_path%" set "destination_parent_path=%normalise_path_result%"
if defined destination_parent_path set "destination_parent_with_backslash=%normalise_path_with_backslash%"
set "destination_given_name="
for %%A in ("%destination_given_path%") do set "destination_given_name=%%~nxA"
set "destination_given_is_evidence_name="
if /i "%destination_given_name%"=="%evidence_directory_name%" set "destination_given_is_evidence_name=1"
set "destination_parent_holds_custody_files="
if defined destination_parent_path call :holds_custody_files destination_parent_with_backslash && set "destination_parent_holds_custody_files=1"
set "destination_candidate_path=%destination_given_path%"
set "destination_candidate_with_backslash=%destination_given_with_backslash%"

rem D1: the destination holds custody files: it is the set directory.
set "destination_layout_rule_id=D1"
set "destination_layout_rule=D1: the directory holds custody files: it is the set directory"
call :holds_custody_files destination_candidate_with_backslash && goto identify_destination_set_state

rem Names are compared exactly, ignoring case only (as Windows file systems do):
rem no partial or pattern matching. D2: the destination has the evidence
rem directory's name, and the directory above holds custody files or nothing
rem else: it is the evidence directory, and the directory above is the set
rem directory. Any other directory inside a set is another set's: stop.
set "destination_layout_rule_id=D2"
set "destination_layout_rule=D2: the directory has the evidence directory's name: it is the evidence directory, and the directory above is the set directory"
if defined destination_parent_holds_custody_files if not defined destination_given_is_evidence_name (
    set "identify_problem=D2: the directory above holds custody files, so this directory is inside a set, but its name isn't the evidence directory's (%evidence_directory_name%): nothing is written into another set."
    exit /b 1
)
if not defined destination_given_is_evidence_name goto identify_destination_set_check_d3
if not defined destination_parent_path goto identify_destination_set_check_d3
if defined destination_parent_holds_custody_files goto identify_destination_set_rule_d2
set "inspect_directory_with_backslash=%destination_parent_with_backslash%"
call :inspect_set_directory
if "%inspect_evidence_count%%inspect_unexpected_count%"=="10" goto identify_destination_set_rule_d2

rem D3: the destination is empty, or holds only a directory with the evidence
rem directory's name (not itself a set directory): it is the set directory.
:identify_destination_set_check_d3
set "destination_layout_rule_id=D3"
set "destination_layout_rule=D3: the directory is empty or holds only a directory with the evidence directory's name: it is the set directory"
set "inspect_directory_with_backslash=%destination_candidate_with_backslash%"
call :inspect_set_directory
if "%inspect_evidence_count%%inspect_unexpected_count%"=="00" goto identify_destination_set_state
set "destination_child_with_backslash=%destination_candidate_with_backslash%%evidence_directory_name%\"
if "%inspect_evidence_count%%inspect_unexpected_count%"=="10" if /i "%inspect_evidence_name%"=="%evidence_directory_name%" (
    call :holds_custody_files destination_child_with_backslash || goto identify_destination_set_state
)

rem D4: anything else: the set directory is a directory in it named after the
rem set (set_directory_name), made if it isn't there; it must hold this set or
rem be empty.
set "destination_layout_rule_id=D4"
set "destination_layout_rule=D4: the directory holds other things: the set directory is a directory in it named after the set"
set "destination_candidate_path=%destination_given_with_backslash%%set_directory_name%"
set "destination_candidate_with_backslash=%destination_candidate_path%\"
goto identify_destination_set_state

:identify_destination_set_rule_d2
set "destination_candidate_path=%destination_parent_path%"
set "destination_candidate_with_backslash=%destination_parent_with_backslash%"

:identify_destination_set_state
call :check_destination_set_state || exit /b 1
exit /b 0

:check_destination_set_state
rem Caller's scope (:identify_destination_set, stage 2), for the set directory
rem in destination_candidate_path, whichever rule found it:
rem   holds custody files: an existing set; it must be a valid set directory
rem     whose evidence directory (if any) has this evidence directory's name. A
rem     rerun or update, confirmed before copying.
rem   otherwise: a new set; it may hold nothing but an empty directory named
rem     like the evidence directory (junk names aside).
rem On a problem, set identify_problem (naming the layout rule) and exit 1.
call :is_directory destination_candidate_with_backslash || goto check_destination_set_state_new
call :holds_custody_files destination_candidate_with_backslash || goto check_destination_set_state_new_existing
set "inspect_directory_with_backslash=%destination_candidate_with_backslash%"
call :inspect_set_directory
call :check_set_directory_contents destination || goto check_destination_set_state_invalid_set
if "%inspect_evidence_count%"=="1" if /i not "%inspect_evidence_name%"=="%evidence_directory_name%" (
    set "identify_problem=%destination_layout_rule_id%: the set directory %destination_candidate_path% holds a different evidence directory, %inspect_evidence_name%: sets are never mixed."
    exit /b 1
)
call :set_destination_set 0
exit /b 0
:check_destination_set_state_invalid_set
set "identify_problem=%destination_layout_rule_id%: %identify_problem%"
exit /b 1
:check_destination_set_state_new_existing
set "inspect_directory_with_backslash=%destination_candidate_with_backslash%"
call :inspect_set_directory
if "%inspect_evidence_count%%inspect_unexpected_count%"=="00" goto check_destination_set_state_new
if "%inspect_evidence_count%%inspect_unexpected_count%"=="10" if /i "%inspect_evidence_name%"=="%evidence_directory_name%" goto check_destination_set_state_new_evidence
set "unexpected_example_name=%inspect_unexpected_name%"
if not defined unexpected_example_name set "unexpected_example_name=%inspect_evidence_name%"
set "identify_problem=%destination_layout_rule_id%: %destination_candidate_path% holds something other than this set (e.g. %unexpected_example_name%): nothing is copied into it."
exit /b 1
:check_destination_set_state_new_evidence
set "inspect_directory_with_backslash=%destination_candidate_with_backslash%%evidence_directory_name%\"
call :inspect_set_directory
if "%inspect_evidence_count%%inspect_unexpected_count%"=="00" goto check_destination_set_state_new
set "identify_problem=%destination_layout_rule_id%: the directory %destination_candidate_with_backslash%%evidence_directory_name% isn't empty and isn't part of a set: nothing is copied into it."
exit /b 1
:check_destination_set_state_new
call :set_destination_set 1
exit /b 0

:set_destination_set  wasEmpty
rem Caller's scope (:check_destination_set_state): the destination set
rem directory is destination_candidate_path, found by destination_layout_rule;
rem the evidence directory goes inside it. wasEmpty: 1 for a new set, 0 for an
rem existing one.
set "destination_set_path=%destination_candidate_path%"
set "destination_set_with_backslash=%destination_candidate_with_backslash%"
set "destination_path=%destination_set_with_backslash%%evidence_directory_name%"
set "destination_with_backslash=%destination_path%\"
set "destination_set_rule=%destination_layout_rule%"
set "destination_was_empty=%~1"
set "destination_state_text=new set (empty, or only an empty evidence directory)"
if "%~1"=="0" set "destination_state_text=holds this set already (rerun or update; user chose to continue)"
exit /b 0

:holds_custody_files  directoryWithBackslashVar
rem Exit 0 if the directory holds a custody file: the history, the records
rem directory, or a copy of the script.
setlocal EnableDelayedExpansion
set "directory=!%~1!"
if exist "!directory!!HISTORY_FILE_NAME!" (endlocal & exit /b 0)
set "custody_records_directory=!directory!!RECORDS_DIR_NAME!"
call :is_directory custody_records_directory && (endlocal & exit /b 0)
if exist "!directory!!SCRIPT_FILE_PREFIX!*!SCRIPT_FILE_EXT!" (endlocal & exit /b 0)
endlocal & exit /b 1

:inspect_set_directory
rem Caller's scope, fixed names. IN inspect_directory_with_backslash. OUT
rem inspect_evidence_count directories other than the records directory
rem (inspect_evidence_name: the last one found) and inspect_unexpected_count
rem files that are neither custody files nor ignored names
rem (inspect_unexpected_name: the last one). Ignored: IGNORED_CUSTODY_FILES,
rem and at a drive root also DRIVE_ROOT_HOUSEKEEPING_DIRS and _FILES.
set "inspect_evidence_count=0"
set "inspect_evidence_name="
set "inspect_unexpected_count=0"
set "inspect_unexpected_name="
set "inspect_directory_is_drive_root="
call :is_drive_root inspect_directory_with_backslash && set "inspect_directory_is_drive_root=1"
for /f "eol=/ delims=" %%E in ('dir /b /a "%inspect_directory_with_backslash%" 2^>nul') do (
    set "inspect_entry_name=%%E"
    call :inspect_set_directory_entry
)
exit /b 0

:inspect_set_directory_entry
rem Caller's scope (:inspect_set_directory): one entry, in inspect_entry_name.
set "inspect_entry_path=%inspect_directory_with_backslash%%inspect_entry_name%"
call :is_directory inspect_entry_path && goto inspect_set_directory_entry_directory
call :is_custody_file_name inspect_entry_name && exit /b 0
call :name_matches_list inspect_entry_name IGNORED_CUSTODY_FILES && exit /b 0
if defined inspect_directory_is_drive_root call :name_matches_list inspect_entry_name DRIVE_ROOT_HOUSEKEEPING_FILES && exit /b 0
set /a "inspect_unexpected_count+=1"
set "inspect_unexpected_name=%inspect_entry_name%"
exit /b 0
:inspect_set_directory_entry_directory
if /i "%inspect_entry_name%"=="%RECORDS_DIR_NAME%" exit /b 0
if defined inspect_directory_is_drive_root call :name_matches_list inspect_entry_name DRIVE_ROOT_HOUSEKEEPING_DIRS && exit /b 0
set /a "inspect_evidence_count+=1"
set "inspect_evidence_name=%inspect_entry_name%"
exit /b 0

:is_custody_file_name  nameVar
rem Exit 0 if the name is a custody file kept at a set directory's top level:
rem the history, or a script copy (SCRIPT_FILE_PREFIX ... SCRIPT_FILE_EXT),
rem case-insensitive.
setlocal EnableDelayedExpansion
set "name=!%~1!"
if /i "!name!"=="!HISTORY_FILE_NAME!" (endlocal & exit /b 0)
call :strlen SCRIPT_FILE_PREFIX prefix_length
call :strlen SCRIPT_FILE_EXT extension_length
for %%P in (!prefix_length!) do if /i not "!name:~0,%%P!"=="!SCRIPT_FILE_PREFIX!" (endlocal & exit /b 1)
for %%E in (!extension_length!) do if /i not "!name:~-%%E!"=="!SCRIPT_FILE_EXT!" (endlocal & exit /b 1)
endlocal & exit /b 0

:name_matches_list  nameVar  listVar
rem Exit 0 if the name matches an item of the "|"-separated list: an exact
rem name, or a prefix ending in "*" (case-insensitive).
setlocal EnableDelayedExpansion
set "name=!%~1!"
set "remaining=!%~2!"
:name_matches_list_next
if not defined remaining (endlocal & exit /b 1)
set "pattern="
for /f "tokens=1* delims=|" %%A in ("!remaining!") do (
    set "pattern=%%A"
    set "remaining=%%B"
)
if not defined pattern (endlocal & exit /b 1)
if not "!pattern:~-1!"=="*" (
    if /i "!name!"=="!pattern!" (endlocal & exit /b 0)
    goto name_matches_list_next
)
set "prefix=!pattern:~0,-1!"
call :strlen prefix prefix_length
for %%N in (!prefix_length!) do if /i "!name:~0,%%N!"=="!prefix!" (endlocal & exit /b 0)
goto name_matches_list_next

:name_directory_for_copy  pathVar  outVar
rem The name a copied directory takes: its own name, or for a drive root its
rem volume label (first line of "fsutil fsinfo volumeinfo", in any display
rem language), or the volume serial if there is no label ("Volume_<serial>").
rem The name is read with delayed expansion off: a FOR value assigned while
rem it is on loses any "!" ("Ev!dence" would become "Evdence"; review,
rem 2026-10-16). The results go back through two ENDLOCALs to a caller
rem whose delayed expansion is off, so "!" survives.
setlocal DisableDelayedExpansion
call :copy_variable %~1 directory
for %%A in ("%directory%") do set "name=%%~nxA"
setlocal EnableDelayedExpansion
if not "!directory:~3!"=="" (endlocal & endlocal & set "%~2=%name%" & exit /b 0)
if not "!directory:~1,2!"==":\" (endlocal & endlocal & set "%~2=%name%" & exit /b 0)
set "label="
set "label_read="
rem The drive ("E:") in its own variable: inside a FOR /F command a comma,
rem as in !directory:~0,2!, is a separator and would break the command.
set "volume_drive=!directory:~0,2!"
fsutil fsinfo volumeinfo !volume_drive! >nul 2>&1 <nul || set "label_read=1"
for /f "tokens=1* delims=:" %%A in ('fsutil fsinfo volumeinfo !volume_drive! 2^>nul ^<nul') do if not defined label_read (
    set "label_read=1"
    set "label=%%B"
)
if defined label set "label=!label:~1!"
rem A label containing "%" would make a path the prompts refuse (see
rem :path_has_percent): use the serial instead.
if defined label if not "!label:%%=!"=="!label!" set "label="
if defined label (endlocal & endlocal & set "%~2=%label%" & exit /b 0)
set "serial=unknown"
for /f "skip=1 tokens=*" %%L in ('vol !volume_drive! 2^>nul') do for %%T in (%%L) do set "serial=%%T"
endlocal & endlocal & set "%~2=Volume_%serial%"
exit /b 0

:ask_plain_paths
rem /nonforensic: ask for the source and destination directories; the source's
rem contents are copied into the destination. No default source.
echo The CONTENTS of the source directory are copied into the destination
echo directory.
set "plain_paths_rejected_answers=0"
:ask_plain_paths_source
echo.
call :ask_directory source "SOURCE directory" 1 0 || exit /b 1
:ask_plain_paths_destination
echo.
call :ask_directory destination "DESTINATION directory" 1 0 || exit /b 1
set "overlap_first_with_backslash=%source_with_backslash%"
set "overlap_second_with_backslash=%destination_with_backslash%"
call :paths_overlap && (
    echo Source and destination must not be the same, or inside each other.
    call :count_rejected_answer plain_paths_rejected_answers "source and destination" || exit /b 1
    goto ask_plain_paths_source
)
set "destination_was_empty=1"
set "destination_state_text=empty"
call :destination_has_content || exit /b 0
echo.
echo The destination directory is not empty. Robocopy overwrites files there
echo that have the same name but a different size or timestamp.
echo 1. Continue with this destination
echo 2. Enter a different destination
call :ask_choice destination_answer "1 2" || exit /b 1
if "%destination_answer%"=="2" goto ask_plain_paths_destination
set "destination_was_empty=0"
set "destination_state_text=NOT empty (user chose to continue)"
exit /b 0

:destination_has_content
rem /nonforensic: exit 0 if the destination directory exists and holds anything
rem other than, at a drive root, the items of DRIVE_ROOT_HOUSEKEEPING_DIRS and
rem _FILES.
call :is_directory destination_with_backslash || exit /b 1
set "destination_entry_count=0"
for /f "eol=/ delims=" %%E in ('dir /b /a "%destination_with_backslash%" 2^>nul') do set /a "destination_entry_count+=1"
call :find_drive_root_housekeeping destination no
if %destination_entry_count% gtr %housekeeping_item_count% exit /b 0
exit /b 1

:ask_verification
rem /nonforensic: verify or not. Not for evidence either way, so declining
rem needs no further confirmation.
echo.
echo Once complete, compare the SHA-256 of every file with its source?
echo 1. Compare SHA-256 (result on screen only)
echo 2. Do not compare
call :ask_choice verification_answer "1 2" || exit /b 1
if "%verification_answer%"=="1" (set "verification_enabled=1") else set "verification_enabled=0"
echo.
exit /b 0

rem -- Run setup --------------------------------------------------------------

:init_run
rem Forensic run. Fix the run's UTC timestamp and output paths, and create
rem the destination set directory, the staging directories and the working log.
rem This run's record (log, hash CSVs, history, seal) and a script copy are
rem written to the staging directory in TEMP and put into the destination at
rem the end (:publish_records). A forensic run needs a UTC time: its record
rem is named after it.
call :get_utc_now
if "%utc_clock_failed%"=="1" (
    set "abort_reason=No UTC time source worked (robocopy's clock and wmic both failed): a forensic run can't name or date its record. Fix the clock source and run again."
    exit /b 1
)
set "start_utc_iso=%utc_iso%"
set "start_utc_source=%utc_method%"
set "run_utc_stamp=%utc_compact%"
set "record_file_stem=%RECORD_FILE_PREFIX%%run_utc_stamp%"
set "log_file_name=%record_file_stem%.log"
set "seal_file_name=%record_file_stem%.sha256"
set "pending_seal_text=see %seal_file_name%"
set "destination_records_root=%destination_set_with_backslash%%RECORDS_DIR_NAME%"
set "destination_run_dir=%destination_records_root%\%run_utc_stamp%"
set "destination_partial_run_dir=%destination_run_dir%%PARTIAL_RUN_SUFFIX%"
set "log_destination_path=%destination_run_dir%\%log_file_name%"
set "log_destination_text=%log_destination_path%"
call :choose_temp_dir || exit /b 1
call :set_temp_file_names
rem Staging: records\ goes to this run's record in the records directory, root\
rem to the destination set directory (script copy, history). See
rem :publish_records.
set "staging_dir=%temp_path_prefix%_staging"
set "staged_records_dir=%staging_dir%\records"
set "staged_root_dir=%staging_dir%\root"
set "log_staged_path=%staged_records_dir%\%log_file_name%"
set "staged_hash_csv_source=%staged_records_dir%\%record_file_stem%_hashes_source.csv"
set "staged_hash_csv_destination=%staged_records_dir%\%record_file_stem%_hashes_destination.csv"
set "staged_hash_csv_custody=%staged_records_dir%\%record_file_stem%_hashes_custody.csv"
set "staged_history_path=%staged_records_dir%\%record_file_stem%_history.csv"
set "staged_outside_history_path=%staged_records_dir%\%record_file_stem%_runs_outside_history.csv"
set "staged_seal_path=%staged_records_dir%\%seal_file_name%"
set "staged_root_history_path=%staged_root_dir%\%HISTORY_FILE_NAME%"
call :is_directory destination_set_with_backslash || mkdir "%destination_set_path%" >nul 2>&1
call :is_directory destination_set_with_backslash || (
    set "abort_reason=Could not create the destination set directory."
    exit /b 1
)
set "destination_attributes_before="
call :is_directory destination_with_backslash && for %%A in ("%destination_path%") do set "destination_attributes_before=%%~aA"
mkdir "%staged_records_dir%" >nul 2>&1
mkdir "%staged_root_dir%" >nul 2>&1
call :is_directory staged_records_dir || set "staging_dir_missing=1"
call :is_directory staged_root_dir || set "staging_dir_missing=1"
if defined staging_dir_missing (
    set "abort_reason=Could not create the staging directory in the temporary directory."
    exit /b 1
)
(type nul >>"%log_staged_path%") 2>nul || (
    set "abort_reason=Could not create the working log in the temporary directory."
    exit /b 1
)
set "log_ready=1"
exit /b 0

:init_plain_run
rem Non-forensic run: no record, so a UTC time is welcome but not required.
rem Verification works in TEMP and writes nothing beside the copy.
call :get_utc_now
set "start_utc_iso=%utc_iso%"
set "start_utc_source=%utc_method%"
set "run_utc_stamp=%utc_compact%"
set "log_destination_text=none (non-forensic run)"
call :choose_temp_dir || exit /b 1
call :set_temp_file_names
set "plain_hash_csv_source=%temp_path_prefix%_hashes_source.csv"
set "plain_hash_csv_destination=%temp_path_prefix%_hashes_destination.csv"
set "staged_hash_csv_source=%plain_hash_csv_source%"
set "staged_hash_csv_destination=%plain_hash_csv_destination%"
set "destination_attributes_before="
call :is_directory destination_with_backslash && for %%A in ("%destination_path%") do set "destination_attributes_before=%%~aA"
call :is_directory destination_with_backslash || mkdir "%destination_path%" >nul 2>&1
call :is_directory destination_with_backslash || (
    set "abort_reason=Could not create the destination directory."
    exit /b 1
)
exit /b 0

:choose_temp_dir
rem Temporary directory for working files and the staging directory, in order:
rem TEMP, TMP, LOCALAPPDATA\Temp. Never the destination: files there would be
rem hashed as evidence.
set "temp_dir="
set "local_app_data_temp="
if defined LOCALAPPDATA set "local_app_data_temp=%LOCALAPPDATA%\Temp"
if defined TEMP call :is_directory TEMP && set "temp_dir=%TEMP%"
if not defined temp_dir if defined TMP call :is_directory TMP && set "temp_dir=%TMP%"
if not defined temp_dir if defined local_app_data_temp call :is_directory local_app_data_temp && set "temp_dir=%local_app_data_temp%"
if not defined temp_dir (
    set "abort_reason=No temporary directory found (TEMP, TMP or LOCALAPPDATA\Temp)."
    exit /b 1
)
set "temp_path_prefix=%temp_dir%\%TOOL_NAME%_%run_utc_stamp%_%RANDOM%"
exit /b 0

:set_temp_file_names
rem Working files in TEMP, all deleted by :cleanup_temp.
set "temp_file_list=%temp_path_prefix%_list.tmp"
set "temp_metadata_list=%temp_path_prefix%_metadata.tmp"
set "temp_robocopy_unicode_output=%temp_path_prefix%_robocopy_unicode.tmp"
set "temp_certutil_output=%temp_path_prefix%_certutil.tmp"
set "temp_hash_rows_source=%temp_path_prefix%_source.tmp"
set "temp_hash_rows_destination=%temp_path_prefix%_destination.tmp"
set "temp_hash_rows_custody=%temp_path_prefix%_custody.tmp"
set "temp_custody_list=%temp_path_prefix%_custody_list.tmp"
set "temp_compare_lines=%temp_path_prefix%_compare.tmp"
set "temp_compare_lines_sorted=%temp_path_prefix%_compare_sorted.tmp"
set "temp_summary_warnings=%temp_path_prefix%_summary_warnings.tmp"
set "temp_summary_failures=%temp_path_prefix%_summary_failures.tmp"
set "temp_warnings=%temp_path_prefix%_warnings.tmp"
set "temp_clock_status=%temp_path_prefix%_clock.tmp"
set "temp_housekeeping_source=%temp_path_prefix%_housekeeping_source.tmp"
set "temp_housekeeping_destination=%temp_path_prefix%_housekeeping_destination.tmp"
set "temp_history_runs=%temp_path_prefix%_history_runs.tmp"
set "temp_history_lines=%temp_path_prefix%_history_lines.tmp"
set "temp_history_filled=%temp_path_prefix%_history_filled.tmp"
set "temp_outside_history=%temp_path_prefix%_outside_history.tmp"
set "temp_partial_warned=%temp_path_prefix%_partial_warned.tmp"
set "temp_predating_records=%temp_path_prefix%_predating_records.tmp"
set "temp_sealed_history_source=%temp_path_prefix%_sealed_history_source.tmp"
set "temp_sealed_history_destination=%temp_path_prefix%_sealed_history_destination.tmp"
exit /b 0

:hash_this_script
rem The SHA-256 of this script file: shown in the header, and the value the
rem script copy placed by :stage_script_copy must match. Hashed before
rem :choose_script_copy, which compares it with the destination's copy.
set "script_sha256="
call :get_sha256 script_path script_sha256
if not defined script_sha256 set "script_sha256=unknown"
exit /b 0

rem -- History ----------------------------------------------------------------

:read_history
rem The set's history (README, "History and run records"). For the source
rem set, and for the destination set on a rerun or update,
rem :resolve_set_history picks the history the run records support: the
rem history beside the evidence, or else the newest sealed history.
rem :check_run_records checks it against the run records after the copy.
rem Sets history_base_path (the history this run continues: the source
rem set's, or on a rerun or update the destination set's if it continues the
rem source's), history_base_side, history_base_set_with_backslash (the set
rem directory holding it), history_row_count, reference_run (row 1),
rem previous_run_* (the newest row) and source_last_* (the source history's
rem newest row, for the location check). A source set with run records but
rem no usable history sets history_base_missing: the Run records check fails
rem and the history starts again with this run, never silently.
set "source_history_path="
set "source_history_origin=none"
set "source_history_problem="
set "source_history_sealed_run="
set "source_history_superseded="
if defined source_set_path call :resolve_set_history source
if "%source_history_origin%"=="missing" set "history_base_missing=1"
call :resolve_set_history destination
call :continue_destination_history_instead && goto read_history_base_chosen
set "history_base_path=%source_history_path%"
set "history_base_side=source"
set "history_base_set_with_backslash=%source_set_with_backslash%"
if not defined history_base_missing if defined destination_history_path call :choose_history_base || exit /b 1
:read_history_base_chosen
if defined history_base_path call :count_history_rows history_base_path history_row_count
if %history_row_count% gtr 0 call :read_history_row history_base_path 2 reference
if %history_row_count% gtr 0 call :is_run_directory_name reference_run || set "reference_run="
if defined reference_run set "reference_name=%RECORD_FILE_PREFIX%%reference_run%_hashes_source.csv"
set /a "history_newest_line=history_row_count + 1"
if %history_row_count% gtr 0 call :read_history_row history_base_path %history_newest_line% previous
if %history_row_count% gtr 0 call :is_run_directory_name previous_run || set "previous_run="
set "source_last_run="
set "source_history_row_count=0"
if defined source_history_path call :count_history_rows source_history_path source_history_row_count
set /a "source_history_newest_line=source_history_row_count + 1"
if %source_history_row_count% gtr 0 call :read_history_row source_history_path %source_history_newest_line% source_last
set /a "this_run_number=history_row_count + 1"
call :describe_history_for_header
exit /b 0

:continue_destination_history_instead
rem Caller's scope (:read_history). On a rerun or update the source's history
rem may be unusable (missing, or matching no run records) while the
rem destination set's history matches its own run records. Then this run
rem continues the destination's history and reports the source's problem as
rem a Run records failure, instead of restarting the history and listing the
rem destination's good run records as outside it (owner, 2026-10-16, after
rem the review). Exit 0 if that applies, with the history base set.
if not "%source_history_origin%"=="missing" if not "%source_history_origin%"=="unverified" exit /b 1
if not "%destination_history_origin%"=="beside" if not "%destination_history_origin%"=="sealed" exit /b 1
set "history_base_missing="
set "source_history_superseded=1"
set "history_base_path=%destination_history_path%"
set "history_base_side=destination"
set "history_base_set_with_backslash=%destination_set_with_backslash%"
exit /b 0

:choose_history_base
rem Caller's scope (:read_history). The destination set already holds a
rem history (a rerun or an update). If it continues the source's history
rem (or the source has none), it is the starting point; if the source's
rem continues it, the source's is. Otherwise they are different lines of
rem copies, and sets are never mixed: stop before copying.
if not defined source_history_path (
    set "history_base_path=%destination_history_path%"
    set "history_base_side=destination"
    set "history_base_set_with_backslash=%destination_set_with_backslash%"
    exit /b 0
)
call :history_starts_with destination_history_path source_history_path && (
    set "history_base_path=%destination_history_path%"
    set "history_base_side=destination"
    set "history_base_set_with_backslash=%destination_set_with_backslash%"
    exit /b 0
)
call :history_starts_with source_history_path destination_history_path && exit /b 0
set "abort_reason=The destination set's history and the source set's history are different lines of copies (neither continues the other): sets are never mixed. Run again with another destination."
exit /b 1

:resolve_set_history  side
rem Caller's scope, before the copy. Which history a set continues from
rem (README, "History and run records"), for side source or destination
rem (<side>_set_with_backslash). The history beside the evidence first; if
rem it is missing, unreadable or doesn't match the sealed run records, the
rem newest sealed history instead, if that matches them, and the history
rem beside the evidence is disregarded. Sets:
rem   <side>_history_path        the history to continue from, or empty
rem   <side>_history_origin      none (no history, no run records), beside
rem                              (the history beside the evidence matches the
rem                              run records), sealed (it didn't; the newest
rem                              sealed history, which does, is used),
rem                              unverified (neither matches: continued from
rem                              the history beside the evidence as found) or
rem                              missing (run records but no usable history:
rem                              the history restarts)
rem   <side>_history_problem     why the history beside the evidence wasn't
rem                              used (origins sealed, unverified, missing)
rem   <side>_history_sealed_run  the run whose sealed history is used (sealed)
set "%~1_history_path="
set "%~1_history_origin=none"
set "%~1_history_problem="
set "%~1_history_sealed_run="
call :copy_variable %~1_set_with_backslash resolve_set_with_backslash
set "resolve_beside_path=%resolve_set_with_backslash%%HISTORY_FILE_NAME%"
set "resolve_records_root=%resolve_set_with_backslash%%RECORDS_DIR_NAME%"
set "resolve_records_present="
call :records_directory_holds_records resolve_records_root && set "resolve_records_present=1"
if not exist "%resolve_beside_path%" if not defined resolve_records_present exit /b 0
if exist "%resolve_beside_path%" call :history_matches_records resolve_beside_path resolve_records_root && (
    set "%~1_history_path=%resolve_beside_path%"
    set "%~1_history_origin=beside"
    exit /b 0
)
set "%~1_history_problem=the history beside the evidence (%HISTORY_FILE_NAME%) doesn't match the sealed run records"
if not exist "%resolve_beside_path%" set "%~1_history_problem=there is no history beside the evidence (%HISTORY_FILE_NAME%), though there are run records"
call :find_newest_sealed_history %~1 && goto resolve_set_history_sealed
if not exist "%resolve_beside_path%" (
    set "%~1_history_origin=missing"
    exit /b 0
)
set "%~1_history_path=%resolve_beside_path%"
set "%~1_history_origin=unverified"
exit /b 0
:resolve_set_history_sealed
call :copy_variable temp_sealed_history_%~1 %~1_history_path
set "%~1_history_origin=sealed"
set "%~1_history_sealed_run=%head_run%"
exit /b 0

:records_directory_holds_records  recordsRootVar
rem Exit 0 if the records directory holds anything besides leftover
rem <run>.partial directories (interrupted write-backs: outside the history,
rem a warning) and junk names (IGNORED_CUSTODY_FILES): a run record, or
rem anything else the Run records check must account for. A records
rem directory holding only .partial directories means no earlier runs.
setlocal DisableDelayedExpansion
call :copy_variable %~1 records_root
call :is_directory records_root || (endlocal & exit /b 1)
set "holds_records="
for /f "eol=/ delims=" %%E in ('dir /b /a "%records_root%\" 2^>nul') do if not defined holds_records (
    set "records_entry=%%E"
    call :records_entry_counts && set "holds_records=1"
)
if defined holds_records (endlocal & exit /b 0)
endlocal & exit /b 1

:records_entry_counts
rem Caller's scope (:records_directory_holds_records): exit 0 if the entry in
rem records_entry counts as a record: a directory other than a <run>.partial,
rem or a file other than a junk name.
set "records_entry_path=%records_root%\%records_entry%"
call :is_directory records_entry_path || goto records_entry_counts_file
call :is_partial_run_directory records_entry && exit /b 1
exit /b 0
:records_entry_counts_file
call :name_matches_list records_entry IGNORED_CUSTODY_FILES && exit /b 1
exit /b 0

:find_newest_sealed_history  side
rem Caller's scope (:resolve_set_history). The newest sealed history: that of
rem the run record with the latest run UTC (its name) in resolve_records_root,
rem taken as it is. Times are the lab's responsibility: no other run record
rem is tried, so a wrong clock or a missing sealed history stays visible.
rem Its own pending seal text is filled in with its seal's SHA-256, into
rem temp_sealed_history_<side> (sets head_run); exit 0 only if that history
rem matches the run records.
set "head_run="
for /f "eol=/ delims=" %%R in ('dir /b /ad /on "%resolve_records_root%\" 2^>nul') do (
    set "head_candidate_run=%%R"
    call :is_run_directory_name head_candidate_run && set "head_run=%%R"
)
if not defined head_run exit /b 1
call :copy_variable temp_sealed_history_%~1 head_filled_path
set "head_sealed_path=%resolve_records_root%\%head_run%\%RECORD_FILE_PREFIX%%head_run%_history.csv"
set "head_seal_path=%resolve_records_root%\%head_run%\%RECORD_FILE_PREFIX%%head_run%.sha256"
if not exist "%head_sealed_path%" exit /b 1
set "head_seal_sha256="
if exist "%head_seal_path%" call :get_sha256 head_seal_path head_seal_sha256
if not defined head_seal_sha256 exit /b 1
set "head_pending_text=see %RECORD_FILE_PREFIX%%head_run%.sha256"
call :write_history_with_seal head_sealed_path head_pending_text head_seal_sha256 head_filled_path
call :history_matches_records head_filled_path resolve_records_root || exit /b 1
exit /b 0

:history_matches_records  historyVar  recordsRootVar
rem Quiet check before the copy: exit 0 if a history and the run records
rem agree as the Run records check requires after it. Every row names a run
rem record that exists, whose seal has the row's Seal SHA-256 and whose
rem sealed history is the history up to that row; every run record is in
rem the history, a .partial directory, or listed outside it by a history
rem restart. The files inside each run record are checked against their
rem seals after the copy (:check_run_records).
setlocal EnableDelayedExpansion
set "matches_history=!%~1!"
set "matches_records_root=!%~2!"
setlocal DisableDelayedExpansion
set "matches_problem="
set "matches_rows=0"
type nul >"%temp_history_runs%"
type nul >"%temp_outside_history%"
for /f "tokens=1* delims=:" %%A in ('findstr /n "^" "%matches_history%" 2^>nul') do if %%A gtr 1 if not defined matches_problem (
    set "history_row_line=%%B"
    call :split_history_line row
    call :history_row_matches_record
)
if %matches_rows% equ 0 set "matches_problem=1"
if not defined matches_problem for /f "eol=/ delims=" %%R in ('dir /b /ad "%matches_records_root%\" 2^>nul') do (
    set "record_directory_name=%%R"
    call :record_directory_in_history
)
if defined matches_problem (endlocal & endlocal & exit /b 1)
endlocal & endlocal & exit /b 0

:history_row_matches_record
rem Caller's scope (:history_matches_records): one history row, in row_*.
set /a "matches_rows+=1"
call :is_run_directory_name row_run || (set "matches_problem=1" & exit /b 0)
call :append_line_to_file row_run temp_history_runs
set "matches_row_dir=%matches_records_root%\%row_run%"
call :is_directory matches_row_dir || (set "matches_problem=1" & exit /b 0)
call :collect_outside_history matches_row_dir row_run
set "matches_seal_path=%matches_row_dir%\%RECORD_FILE_PREFIX%%row_run%.sha256"
set "matches_seal_sha256="
if exist "%matches_seal_path%" call :get_sha256 matches_seal_path matches_seal_sha256
if not defined matches_seal_sha256 (set "matches_problem=1" & exit /b 0)
if /i not "%matches_seal_sha256%"=="%row_seal%" (set "matches_problem=1" & exit /b 0)
set "matches_sealed_history=%matches_row_dir%\%RECORD_FILE_PREFIX%%row_run%_history.csv"
if not exist "%matches_sealed_history%" (set "matches_problem=1" & exit /b 0)
set "matches_pending_text=see %RECORD_FILE_PREFIX%%row_run%.sha256"
call :write_history_with_seal matches_sealed_history matches_pending_text row_seal temp_history_filled
call :history_starts_with matches_history temp_history_filled || set "matches_problem=1"
exit /b 0

:record_directory_in_history
rem Caller's scope (:history_matches_records): one directory in the records
rem directory, in record_directory_name.
if defined matches_problem exit /b 0
call :is_partial_run_directory record_directory_name && exit /b 0
findstr /x /l /c:"%record_directory_name%" "%temp_history_runs%" >nul 2>&1 && exit /b 0
call :find_outside_history && exit /b 0
set "matches_problem=1"
exit /b 0

:report_history_set_aside  side  when
rem The history beside the evidence of side (source or destination) wasn't
rem used (:resolve_set_history). when=before: a warning up front; after: a
rem Run records failure.
call :copy_variable %~1_history_origin set_aside_origin
call :copy_variable %~1_history_problem set_aside_problem
call :copy_variable %~1_history_sealed_run set_aside_run
set "set_aside_text="
if "%set_aside_origin%"=="sealed" set "set_aside_text=Run records: in the %~1 set, %set_aside_problem%. This run continues from the newest sealed history instead (run %set_aside_run%), which matches the run records, and writes the destination a complete history built from it."
if "%set_aside_origin%"=="unverified" set "set_aside_text=Run records: in the %~1 set, %set_aside_problem%, and no sealed history does either: this run continues from it as found."
if "%~1"=="source" if defined source_history_superseded set "set_aside_text=Run records: in the source set, %set_aside_problem%, and no sealed history there does either. This rerun continues from the destination set's history instead, which matches its run records."
if not defined set_aside_text exit /b 0
if "%~2"=="before" (
    set "msg=%set_aside_text% The Run records check fails."
    call :add_warning msg
    exit /b 0
)
set "msg=[FAIL] %set_aside_text%"
call :show_and_log msg
call :remember_problem msg
set /a "run_record_problem_count+=1"
exit /b 0

:count_history_rows  fileVar  outVar
rem The number of runs in a history: its lines, less the header.
setlocal EnableDelayedExpansion
set "file=!%~1!"
set "lines=0"
for /f %%N in ('find /c /v "" ^< "!file!" 2^>nul') do set "lines=%%N"
set /a "rows=lines - 1"
if !rows! lss 0 set "rows=0"
endlocal & set "%~2=%rows%"
exit /b 0

:read_history_row  fileVar  lineNumber  prefix
rem Caller's scope, delayed expansion off. Set <prefix>_run, _result,
rem _source, _source_serial, _source_volume_label_and_filesystem,
rem _destination, _destination_serial,
rem _destination_volume_label_and_filesystem, _evidence_files, _host, _user,
rem _script and _seal (the 13 history columns) from line <lineNumber> of the
rem history (line 1 is the header). Exit 1, with them all cleared, if there
rem is no such line.
for %%F in (run result source source_serial source_volume_label_and_filesystem destination destination_serial destination_volume_label_and_filesystem evidence_files host user script seal) do set "%~3_%%F="
call :copy_variable %~1 read_history_row_file
set "history_row_line="
for /f "tokens=1* delims=:" %%A in ('findstr /n "^" "%read_history_row_file%" 2^>nul') do if "%%A"=="%~2" set "history_row_line=%%B"
if not defined history_row_line exit /b 1
call :split_history_line %~3
exit /b %errorlevel%

:split_history_line  prefix
rem Caller's scope (IN history_row_line; the caller's delayed expansion is
rem off). Split a history row into its 13 cells, keeping empty ones. The
rem '","' separators become "|" (cells never contain '"' or "|": see
rem :append_history_row), and each cell is cut off up to the next "|".
rem Delayed expansion is on only inside this helper; the cells come back on
rem one "endlocal & set" line, expanded before ENDLOCAL and assigned after
rem it, so "!" in paths survives. Exit 1 if there is no row.
rem History content is data, never code: the cells come back through "%...%"
rem on a command line, so any '"' left after the separators (cells never
rem contain one; a history edited by hand or by a spreadsheet, or a crafted
rem one, might) is removed here. Otherwise a cell could close the quotes and
rem run a command (review, 2026-10-16). Such a row no longer matches its
rem sealed copy, so the Run records check still fails on it.
if not defined history_row_line exit /b 1
setlocal EnableDelayedExpansion
set "remaining=!history_row_line:","=|!"
set "remaining=!remaining:~1,-1!|"
set "remaining=!remaining:"=!"
for %%C in (1 2 3 4 5 6 7 8 9 10 11 12 13) do (
    set "cell_%%C="
    if defined remaining (
        set "after_cell=!remaining:*|=!"
        call :strlen remaining remaining_length
        call :strlen after_cell after_length
        set /a "cell_length=remaining_length - after_length - 1"
        for %%L in (!cell_length!) do set "cell_%%C=!remaining:~0,%%L!"
        set "remaining=!after_cell!"
    )
)
endlocal & set "%~1_run=%cell_1%" & set "%~1_result=%cell_2%" & set "%~1_source=%cell_3%" & set "%~1_source_serial=%cell_4%" & set "%~1_source_volume_label_and_filesystem=%cell_5%" & set "%~1_destination=%cell_6%" & set "%~1_destination_serial=%cell_7%" & set "%~1_destination_volume_label_and_filesystem=%cell_8%" & set "%~1_evidence_files=%cell_9%" & set "%~1_host=%cell_10%" & set "%~1_user=%cell_11%" & set "%~1_script=%cell_12%" & set "%~1_seal=%cell_13%"
exit /b 0

:history_starts_with  longFileVar  shortFileVar
rem Exit 0 if the long history's first lines are exactly the short history
rem (byte for byte, as fc /b compares them).
setlocal EnableDelayedExpansion
set "long_file=!%~1!"
set "short_file=!%~2!"
setlocal DisableDelayedExpansion
set "short_lines=0"
for /f %%N in ('find /c /v "" ^< "%short_file%" 2^>nul') do set "short_lines=%%N"
type nul >"%temp_history_lines%"
for /f "tokens=1* delims=:" %%A in ('findstr /n "^" "%long_file%" 2^>nul') do if %%A leq %short_lines% >>"%temp_history_lines%" echo(%%B
fc /b "%short_file%" "%temp_history_lines%" >nul 2>&1
set "starts_with_exit_code=%errorlevel%"
endlocal & endlocal & exit /b %starts_with_exit_code%

:describe_history_for_header
rem Header lines for the reference record, the history and the previous run.
set "header_reference_record=none found in the source: the source is hashed now and becomes the reference record"
if defined history_base_missing set "header_reference_record=none: the source set holds run records but no history (see Warnings): the source is hashed now"
if defined reference_run set "header_reference_record=%RECORDS_DIR_NAME%\%reference_run%\%reference_name% (row 1 of the history)"
set "header_history=no earlier runs found in the source; this is run 1"
if %history_row_count% gtr 0 set "header_history=%history_row_count% earlier run(s); this is run %this_run_number%"
if "%history_base_side%"=="destination" set "header_history=%header_history% (continuing the destination set's history: a rerun or update)"
call :copy_variable %history_base_side%_history_origin header_history_origin
call :copy_variable %history_base_side%_history_sealed_run header_history_sealed_run
if "%header_history_origin%"=="sealed" set "header_history=%header_history%; taken from the newest sealed history (run %header_history_sealed_run%), not the history beside the evidence (see Warnings)"
set "header_previous_run=none"
if defined previous_run set "header_previous_run=%previous_run% (%previous_result%, host %previous_host%, seal SHA-256 %previous_seal%)"
exit /b 0

rem -- Checks before the copy -------------------------------------------------

:check_script_against_previous_run
rem Compare this script with the previous run's (README, "Script check"):
rem the version from the newest row of the previous run's sealed history,
rem the SHA-256 from its sealed log header. The script never vouches for
rem itself: a difference is flagged for the analyst to verify both scripts
rem against the published release. Newer version: WARN. Older version, or
rem the same version with a different SHA-256: FAIL. A previous run whose
rem sealed history is missing or holds no MAJOR.MINOR.PATCH version: FAIL
rem (a damaged record). No previous run: nothing to compare.
if not defined previous_run exit /b 0
set "previous_run_dir=%history_base_set_with_backslash%%RECORDS_DIR_NAME%\%previous_run%"
set "previous_sealed_history=%previous_run_dir%\%RECORD_FILE_PREFIX%%previous_run%_history.csv"
set "previous_sealed_newest_script="
if exist "%previous_sealed_history%" call :count_history_rows previous_sealed_history previous_sealed_row_count
if exist "%previous_sealed_history%" set /a "previous_sealed_newest_line=previous_sealed_row_count + 1"
if exist "%previous_sealed_history%" call :read_history_row previous_sealed_history %previous_sealed_newest_line% previous_sealed_newest
if not defined previous_sealed_newest_script (
    call :fail_script_check "the previous run's sealed history is missing or unreadable, so this script can't be compared with the one it used"
    exit /b 0
)
call :last_word previous_sealed_newest_script previous_script_version
call :parse_version previous_script_version previous_version || (
    call :fail_script_check "the previous run's script version (%previous_script_version%) is not a MAJOR.MINOR.PATCH version"
    exit /b 0
)
call :parse_version TOOL_VERSION this_version
call :compare_versions this_version previous_version version_order
if "%version_order%"=="older" (
    call :fail_script_check "this run's script (version %TOOL_VERSION%) is older than the previous run's (version %previous_script_version%)"
    exit /b 0
)
if "%version_order%"=="newer" (
    set "msg=Script: this run's script (version %TOOL_VERSION%) is newer than the previous run's (version %previous_script_version%)."
    call :add_warning msg
    set "script_status=PASS"
    set "result_script=PASS: version %TOOL_VERSION%, newer than the previous run's %previous_script_version% (see warnings)"
    exit /b 0
)
set "previous_log=%previous_run_dir%\%RECORD_FILE_PREFIX%%previous_run%.log"
set "previous_script_sha256="
if exist "%previous_log%" for /f "tokens=1* delims=:" %%A in ('findstr /b /c:"  Script SHA-256      : " "%previous_log%" 2^>nul') do set "previous_script_sha256=%%B"
call :clean_sha256_from_record previous_script_sha256
if not exist "%previous_log%" (
    set "msg=Script: the SHA-256 can't be compared: the previous run's record has no log."
    call :add_warning msg
    set "script_status=PASS"
    set "result_script=PASS: same version as the previous run (%TOOL_VERSION%); SHA-256 not compared (see warnings)"
    exit /b 0
)
if not defined previous_script_sha256 (
    call :fail_script_check "this run's script is version %TOOL_VERSION%, as the previous run's was, but the previous run's log holds no valid Script SHA-256 to compare it with"
    exit /b 0
)
if /i not "%previous_script_sha256%"=="%script_sha256%" (
    call :fail_script_check "this run's script is version %TOOL_VERSION%, as the previous run's was, but its SHA-256 differs"
    exit /b 0
)
set "script_status=PASS"
set "result_script=PASS: same version (%TOOL_VERSION%) and SHA-256 as the previous run's script"
exit /b 0

:clean_sha256_from_record  valueVar
rem A SHA-256 read from a record: spaces and quotes removed, and cleared
rem unless 64 hex characters remain, so record content can't reach a command
rem line and a malformed value never counts as a hash.
setlocal EnableDelayedExpansion
set "value=!%~1!"
if defined value set "value=!value: =!"
if defined value set "value=!value:"=!"
call :is_sha256 value || set "value="
endlocal & set "%~1=%value%"
exit /b 0

:last_word  textVar  outVar
rem Set outVar to the text after the last space of textVar (all of it if it
rem has none), without putting the text on a command line: it comes from a
rem record. The result is checked by the caller (e.g. :parse_version).
setlocal EnableDelayedExpansion
set "word=!%~1!"
:last_word_next
if defined word if not "!word: =!"=="!word!" (
    set "word=!word:* =!"
    goto last_word_next
)
endlocal & set "%~2=%word%"
exit /b 0

:fail_script_check  reason
rem Record a failed script check; it is shown after the header and listed
rem with the failures.
set "script_status=FAIL"
set "result_script=FAIL: %~1"
set "script_failure_message=[FAIL] Script: %~1. Verify both against the published release before relying on either copy."
exit /b 0

:parse_version  versionVar  outPrefix
rem Split a plain MAJOR.MINOR.PATCH version into <outPrefix>_major, _minor
rem and _patch; exit 1 if it isn't one (three parts, digits only, no leading
rem zeros).
setlocal EnableDelayedExpansion
set "version=!%~1!"
set "major="
set "minor="
set "patch="
set "extra="
for /f "tokens=1-4 delims=." %%A in ("!version!") do (
    set "major=%%A"
    set "minor=%%B"
    set "patch=%%C"
    set "extra=%%D"
)
if defined extra (endlocal & exit /b 1)
if "!version:..=!" neq "!version!" (endlocal & exit /b 1)
for %%P in (major minor patch) do (
    if not defined %%P (endlocal & exit /b 1)
    for /f "delims=0123456789" %%X in ("!%%P!") do (endlocal & exit /b 1)
    set "part=!%%P!"
    if not "!part:~1!"=="" if "!part:~0,1!"=="0" (endlocal & exit /b 1)
)
endlocal & set "%~2_major=%major%" & set "%~2_minor=%minor%" & set "%~2_patch=%patch%"
exit /b 0

:compare_versions  firstPrefix  secondPrefix  outVar
rem Set outVar to older, same or newer: the first version against the
rem second (each from :parse_version).
setlocal EnableDelayedExpansion
set "order=same"
for %%P in (major minor patch) do if "!order!"=="same" (
    if !%~1_%%P! lss !%~2_%%P! set "order=older"
    if !%~1_%%P! gtr !%~2_%%P! set "order=newer"
)
endlocal & set "%~3=%order%"
exit /b 0

:check_location_against_previous_run
rem Flag a set that reached this source by other means since the run that
rem made it (README, "Location check"): its volume serial and its path,
rem ignoring the drive letter and case, are compared with that run's
rem destination (the newest row of the source's history). Warnings only;
rem a different drive letter alone isn't flagged. A source set with run
rem records whose history gives no newest row can't be checked: a warning
rem says so (owner, 2026-10-16, after test round 7).
if not defined source_set_path exit /b 0
if not defined source_last_run if not "%source_history_origin%"=="none" (
    set "msg=Location: not checked: the source set's history can't be used, so where the run that made the set copied it isn't known."
    call :add_warning msg
)
if not defined source_last_run exit /b 0
rem A serial that couldn't be read ("unknown") is not compared: it would
rem raise a false warning, or hide a real move.
set "serials_comparable=1"
if "%source_last_destination_serial%"=="n/a" set "serials_comparable="
if "%source_volume_serial%"=="n/a" set "serials_comparable="
if "%source_last_destination_serial%"=="unknown" set "serials_comparable="
if "%source_volume_serial%"=="unknown" set "serials_comparable="
if "%source_volume_serial%"=="unknown" (
    set "msg=Location: the source volume's serial couldn't be read, so it isn't compared with where the run that made the set (%source_last_run%) copied it."
    call :add_warning msg
)
if defined serials_comparable if /i not "%source_last_destination_serial%"=="%source_volume_serial%" (
    set "msg=Location: the source set is on volume serial %source_volume_serial%, but the run that made it (%source_last_run%) copied it to volume serial %source_last_destination_serial%: it reached this volume by other means since."
    call :add_warning msg
)
set "location_now=%source_set_path%"
if "%location_now:~1,1%"==":" set "location_now=%location_now:~2%"
set "location_then=%source_last_destination%"
if "%location_then:~1,1%"==":" set "location_then=%location_then:~2%"
if /i not "%location_now%"=="%location_then%" (
    set "msg=Location: the source set directory is %source_set_path%, but the run that made it (%source_last_run%) copied it to %source_last_destination% (drive letters aside): it was moved or copied by other means since."
    call :add_warning msg
)
exit /b 0

:precheck_run_records
rem Before the copy, warn up front about run records that will fail the Run
rem records check after it: no history beside the evidence although there
rem are run records, runs the history lists without a run record, and run
rem records the history doesn't list (other than those a history restart
rem listed). Leftover <run>.partial directories (an interrupted write-back) are
rem warned about here too, as is a history beside the evidence that was set
rem aside (:resolve_set_history).
call :report_history_set_aside source before
call :report_history_set_aside destination before
call :precheck_partial_directories source
call :precheck_partial_directories destination
if defined history_base_missing (
    set "msg=Run records: the source set holds run records but no history file (%HISTORY_FILE_NAME%): the Run records check fails, and the history starts again with this run."
    call :add_warning msg
    exit /b 0
)
if not defined history_base_path exit /b 0
set "precheck_records_root=%history_base_set_with_backslash%%RECORDS_DIR_NAME%"
type nul >"%temp_history_runs%"
type nul >"%temp_outside_history%"
for /f "tokens=1* delims=:" %%A in ('findstr /n "^" "%history_base_path%" 2^>nul') do if %%A gtr 1 (
    set "history_row_line=%%B"
    call :split_history_line row
    call :precheck_history_row
)
for /f "eol=/ delims=" %%R in ('dir /b /ad "%precheck_records_root%\" 2^>nul') do (
    set "record_directory_name=%%R"
    call :precheck_record_directory
)
exit /b 0

:precheck_partial_directories  side
rem Caller's scope (:precheck_run_records): warn up front about leftover
rem <run>.partial directories (interrupted write-backs) in the side's
rem records directory, whether or not the set has a history (a set holding
rem only a .partial has no earlier runs). Each name is warned about once
rem (temp_partial_warned), also by :check_run_records after the copy.
call :copy_variable %~1_set_with_backslash precheck_partial_set
if not defined precheck_partial_set exit /b 0
for /f "eol=/ delims=" %%R in ('dir /b /ad "%precheck_partial_set%%RECORDS_DIR_NAME%\" 2^>nul') do (
    set "record_directory_name=%%R"
    call :precheck_partial_directory
)
exit /b 0

:precheck_partial_directory
rem Caller's scope (:precheck_partial_directories): one directory, in
rem record_directory_name.
call :is_partial_run_directory record_directory_name || exit /b 0
findstr /x /l /c:"%record_directory_name%" "%temp_partial_warned%" >nul 2>&1 && exit /b 0
set "msg=Run records: %record_directory_name% is an interrupted write-back (a run record never completed); it is outside the history."
call :add_warning msg
>>"%temp_partial_warned%" echo(%record_directory_name%
exit /b 0

:precheck_history_row
rem Caller's scope (:precheck_run_records): one history row, in row_*.
call :append_line_to_file row_run temp_history_runs
set "precheck_row_dir=%precheck_records_root%\%row_run%"
call :is_directory precheck_row_dir || goto precheck_history_row_missing
call :collect_outside_history precheck_row_dir row_run
exit /b 0
:precheck_history_row_missing
set "msg=Run records: run %row_run%, listed in the history, has no run record in the source set: the Run records check will fail."
call :add_warning msg
exit /b 0

:precheck_record_directory
rem Caller's scope (:precheck_run_records): one directory in the records
rem directory, in record_directory_name.
rem Leftover .partial directories were warned about already
rem (:precheck_partial_directories).
call :is_partial_run_directory record_directory_name && exit /b 0
findstr /x /l /c:"%record_directory_name%" "%temp_history_runs%" >nul 2>&1 && exit /b 0
call :find_outside_history && exit /b 0
set "msg=Run records: %record_directory_name% in the records directory is not in the history: the Run records check will fail."
call :add_warning msg
exit /b 0

:is_partial_run_directory  nameVar
rem Exit 0 if the directory name ends in PARTIAL_RUN_SUFFIX.
setlocal EnableDelayedExpansion
set "name=!%~1!"
call :strlen PARTIAL_RUN_SUFFIX suffix_length
for %%N in (!suffix_length!) do if /i "!name:~-%%N!"=="!PARTIAL_RUN_SUFFIX!" (endlocal & exit /b 0)
endlocal & exit /b 1

:log_pre_copy_findings
rem After the header: the script check's result, and its failure if any.
set "msg=" & call :show_and_log msg
set "msg=--- Script check against the previous run ---" & call :show_and_log msg
call :log_field "Script" result_script
if not defined script_failure_message exit /b 0
call :show_and_log script_failure_message
call :remember_problem script_failure_message
exit /b 0

:copy_variable  fromVar  toVar
rem Copy a variable's value by name into the caller, whose delayed expansion
rem must be off (so "!" and "%" in paths come through unchanged).
setlocal EnableDelayedExpansion
set "value=!%~1!"
endlocal & set "%~2=%value%"
exit /b 0

rem -- Header and environment -------------------------------------------------

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
set "header_utc_offset=%local_utc_offset% (robocopy's Started/Ended and ERROR times are local; its file times are UTC)"
call :describe_user header_user
call :describe_host header_host
set "header_excluded=volume housekeeping at a drive root only (see Source)"
set "header_retries=%RETRY_COUNT% x %RETRY_WAIT_SECONDS% s"
set "header_verify=no (not for evidence)"
if "%verification_enabled%"=="1" set "header_verify=SHA-256 hash and metadata (size, last-modified time), every file, on screen only"
if "%run_mode%"=="forensic" set "header_verify=SHA-256 hash and metadata (size, last-modified time), every file; run records against the history and their seals"
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
call :log_field "Encoding" header_encoding
call :log_field "Elevated" header_elevated
call :log_field "robocopy" robocopy_path
call :log_field "certutil" certutil_path
call :log_field "Sleep when idle" header_sleep
call :log_field "Excluded" header_excluded
call :log_field "Retries" header_retries
call :log_field "Progress" header_progress
call :log_field "Verify" header_verify
call :log_field "Writes" header_writes
if "%run_mode%"=="forensic" (call :write_header_sets) else call :write_header_plain_directories
set "msg================================================================================" & call :show_and_log msg
exit /b 0

:write_header_sets
rem Forensic run: the source and destination sections, set by set.
set "header_source_set=none: raw evidence (a first copy)"
if defined source_set_path set "header_source_set=%source_set_with_backslash%"
set "header_records=%destination_run_dir%\"
set "msg=" & call :show_and_log msg
set "msg=Source" & call :show_and_log msg
call :log_field "Set directory" header_source_set
call :log_field "Evidence directory" source_with_backslash
call :log_field "Chosen" source_set_rule
call :log_field "Volume" header_source_volume
call :log_housekeeping source "Skipped at root"
call :log_field "Reference record" header_reference_record
call :log_field "History" header_history
call :log_field "Previous run" header_previous_run
set "msg=" & call :show_and_log msg
set "msg=Destination" & call :show_and_log msg
call :log_field "Set directory" destination_set_with_backslash
call :log_field "Evidence directory" destination_with_backslash
call :log_field "Chosen" destination_set_rule
call :log_field "Was" destination_state_text
call :log_field "Volume" header_destination_volume
call :log_field "Run record" header_records
call :log_field "Log" log_destination_text
call :log_field "Log during run" log_staged_path
exit /b 0

:write_header_plain_directories
rem Non-forensic run: the two directories robocopy copies between.
set "msg=" & call :show_and_log msg
set "msg=Source" & call :show_and_log msg
call :log_field "Contents of" source_with_backslash
call :log_field "Volume" header_source_volume
call :log_housekeeping source "Skipped at root"
set "msg=" & call :show_and_log msg
set "msg=Destination" & call :show_and_log msg
call :log_field "Copied into" destination_with_backslash
call :log_field "Was" destination_state_text
call :log_field "Volume" header_destination_volume
call :log_housekeeping destination "Left alone at root"
exit /b 0

:check_environment
rem Run every check an analyst should know about before relying on the copy,
rem and collect the results as one list of warnings (:add_warning). The list
rem heads the log header and is repeated in the summary.
call :check_power
call :read_clock_status
set "destination_volume_directory=%destination_path%"
if "%run_mode%"=="forensic" set "destination_volume_directory=%destination_set_path%"
call :describe_volume "%source_path:~0,2%" header_source_volume source_filesystem source_volume_serial source_volume_label_and_filesystem
call :describe_volume "%destination_volume_directory:~0,2%" header_destination_volume destination_filesystem destination_volume_serial destination_volume_label_and_filesystem
if not "%console_code_page%"=="65001" (
    set "msg=The console couldn't be switched to UTF-8: text in this record is in code page %console_code_page% (see Encoding)."
    call :add_warning msg
)
if "%utc_clock_failed%"=="1" (
    set "msg=No UTC time source worked: times are unknown."
    call :add_warning msg
)
if defined destination_filesystem if defined FILESYSTEM_WARNING_%destination_filesystem% call :warn_destination_filesystem
call :check_write_mode
call :check_recovered_fragments
call :find_drive_root_housekeeping source yes
call :find_drive_root_housekeeping destination yes
if "%run_mode%"=="forensic" if not defined history_base_path if not defined history_base_missing (
    set "msg=No history or reference record was found in the source: the source is hashed now and becomes the reference record, so this copy is not checked against any earlier record."
    call :add_warning msg
)
rem A forensic rerun or update was confirmed at the prompt, and the header
rem says so ("Was"): no warning (owner, 2026-10-16). In /nonforensic the
rem destination was any non-empty directory.
if "%run_mode%"=="nonforensic" if not "%destination_was_empty%"=="1" (
    set "msg=The destination was not empty (you chose to continue): robocopy overwrites same-named files that differ."
    call :add_warning msg
)
exit /b 0

:check_recovered_fragments
rem Warn if the source's or the destination's drive root holds directories of
rem recovered fragments (DRIVE_ROOT_RECOVERED_DIRS): the drive has had
rem file-system repairs.
call :check_recovered_fragments_on source source
if "%run_mode%"=="forensic" (call :check_recovered_fragments_on destination_set destination) else call :check_recovered_fragments_on destination destination
exit /b 0

:check_recovered_fragments_on  directoryKey  label
rem Caller's scope: the :each_item callback adds to recovered_dirs_found.
set "recovered_dirs_found="
call :is_drive_root %~1_with_backslash || exit /b 0
if "%~1"=="source" set "callback_drive_root=%source_with_backslash%"
if "%~1"=="destination" set "callback_drive_root=%destination_with_backslash%"
if "%~1"=="destination_set" set "callback_drive_root=%destination_set_with_backslash%"
call :each_item DRIVE_ROOT_RECOVERED_DIRS find_recovered_dirs
if not defined recovered_dirs_found exit /b 0
set "msg=The %~2 drive holds directories of fragments recovered by file-system repairs (%recovered_dirs_found%): the drive may have been damaged. They are copied as contents."
call :add_warning msg
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
if "%run_mode%"=="nonforensic" set "writes=unbuffered (robocopy /j): verification reads file contents from the drive"
if defined buffered_passes (
    set "writes=buffered for: !buffered_passes:~2!"
    set "msg=Copy pass without /j (!buffered_passes:~2!): its files may be verified from the Windows cache rather than read back from the drive."
    call :add_warning msg
)
endlocal & set "header_writes=%writes%"
exit /b 0

:find_skipped_links
rem After the copy passes. Links in the source (the L attribute: junctions
rem and symbolic links, which robocopy doesn't follow or copy with /xj) that
rem are not in the destination: each is a warning, since what it points to
rem is not part of this copy. Other reparse points that robocopy did copy
rem (e.g. cloud placeholder files) are left alone: only the outcome counts. A
rem link inside a link that wasn't copied isn't listed again: DIR /S looks
rem inside links, and lists what is inside one after other links, not
rem straight after it (test round 7), so each link's directories are checked.
for /f "eol=/ delims=" %%L in ('dir /s /b /a:l "%source_with_backslash%" 2^>nul') do (
    set "skipped_link_path=%%L"
    call :report_skipped_link
)
exit /b 0

:report_skipped_link
rem Caller's scope (:find_skipped_links): one link, in skipped_link_path.
call :link_was_copied skipped_link_path && exit /b 0
call :is_inside_skipped_link skipped_link_path && exit /b 0
set "msg=Not copied: %skipped_link_path% is a link (a junction or symbolic link), which robocopy doesn't follow (/xj): what it points to is not part of this copy."
call :add_warning msg
set "msg=[WARN] %msg%"
call :show_and_log msg
exit /b 0

:link_was_copied  linkPathVar
rem Exit 0 if the link's place in the destination exists (it was copied).
setlocal EnableDelayedExpansion
call :relative_path %~1 source_with_backslash link_relative_path || (endlocal & exit /b 1)
if exist "!destination_with_backslash!!link_relative_path!" (endlocal & exit /b 0)
endlocal & exit /b 1

:is_inside_skipped_link  linkPathVar
rem Exit 0 if one of the directories between the source and the link is
rem itself a link that wasn't copied (reported already, or inside one that
rem was). Walks up from the link's directory to the source.
setlocal DisableDelayedExpansion
call :copy_variable %~1 enclosing_path
:is_inside_skipped_link_up
set "previous_enclosing_path=%enclosing_path%"
for %%A in ("%enclosing_path%\..") do set "enclosing_path=%%~fA"
if "%enclosing_path:~-1%"=="\" set "enclosing_path=%enclosing_path:~0,-1%"
if /i "%enclosing_path%"=="%previous_enclosing_path%" (endlocal & exit /b 1)
if /i "%enclosing_path%\"=="%source_with_backslash%" (endlocal & exit /b 1)
set "enclosing_with_backslash=%enclosing_path%\"
call :path_is_under enclosing_with_backslash source_with_backslash || (endlocal & exit /b 1)
set "enclosing_attributes="
for %%A in ("%enclosing_path%") do set "enclosing_attributes=%%~aA"
if not "%enclosing_attributes:~8,1%"=="l" goto is_inside_skipped_link_up
call :link_was_copied enclosing_path && goto is_inside_skipped_link_up
endlocal & exit /b 0

:path_is_under  pathVar  prefixVar
rem Exit 0 if the path starts with the prefix (a directory path ending in
rem "\"), ignoring case.
setlocal EnableDelayedExpansion
call :relative_path %~1 %~2 path_is_under_rest || (endlocal & exit /b 1)
endlocal & exit /b 0

:find_recovered_dirs  pattern
rem :each_item callback: the directories matching one pattern at
rem callback_drive_root.
for /f "eol=/ delims=" %%F in ('dir /b /ad "%callback_drive_root%%~1" 2^>nul') do call :add_recovered_dir "%%F"
exit /b 0

:add_recovered_dir  name
if defined recovered_dirs_found (set "recovered_dirs_found=%recovered_dirs_found%, %~1") else set "recovered_dirs_found=%~1"
exit /b 0

:find_drive_root_housekeeping  side  recordItems
rem Find the housekeeping items present at the side's drive root, if its
rem directory is a drive root: directories matching DRIVE_ROOT_HOUSEKEEPING_DIRS
rem and files matching DRIVE_ROOT_HOUSEKEEPING_FILES. Sets
rem housekeeping_item_count. With recordItems=yes also writes them as D:"name" /
rem F:"name" lines to temp_housekeeping_<side>, which drive the exclusions
rem (:add_housekeeping_exclusions) and the log (:log_housekeeping). Caller's
rem scope: the :each_item callbacks add to the count and the list.
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
rem :each_item callback: one directory pattern of DRIVE_ROOT_HOUSEKEEPING_DIRS
rem at callback_drive_root. An exact name is tested with IF EXIST (DIR on a
rem directory would list its contents); a pattern with * or ? is expanded with
rem DIR.
echo(%~1| findstr /r "[*?]" >nul && goto find_housekeeping_dir_wildcard
set "housekeeping_dir_path=%callback_drive_root%%~1"
call :is_directory housekeeping_dir_path && call :record_housekeeping_item D "%~1"
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
rem root, one per line, or why there are none (side: source or
rem destination, the directories robocopy copies between).
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
    if "%%A"=="D" (set "item_kind=directory") else set "item_kind=file"
    call :log_housekeeping_line item_name item_kind
)
endlocal & exit /b 0

:log_housekeeping_line  nameVar  kindVar
setlocal EnableDelayedExpansion
set "msg=                        !%~1! (!%~2!)"
call :show_and_log msg
endlocal & exit /b 0

:add_warning  msgVar
rem Add "[WARN] <text>" to the warnings list (the first section of the log
rem header) and to the warnings repeated in the summary.
setlocal EnableDelayedExpansion
>>"!temp_warnings!" echo([WARN] !%~1!
>>"!temp_summary_warnings!" echo([WARN] !%~1!
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

:describe_volume  drive  outVar  filesystemOutVar  serialOutVar  labelAndFilesystemOutVar
rem Describe the volume of a drive ("C:") for the log: VOL's label line and
rem serial number (no admin needed), and the file system from
rem FILESYSTEM_METHODS. A network path (drive "\\") gets "n/a". Sets
rem filesystemOutVar to the file system name, or clears it if unknown,
rem serialOutVar to the volume serial ("n/a" for a network path, "unknown"
rem if it can't be read), and labelAndFilesystemOutVar to the description
rem without the serial (the history has the serial in a column of its own).
setlocal
set "drive=%~1"
if not "%drive:~1,1%"==":" (
    endlocal
    set "%~2=n/a (network path)"
    set "%~3="
    set "%~4=n/a"
    set "%~5=n/a (network path)"
    exit /b 0
)
set "volume_label_line="
set "volume_serial=unknown"
for /f "tokens=*" %%L in ('vol %drive% 2^>nul') do if not defined volume_label_line set "volume_label_line=%%L"
for /f "skip=1 tokens=*" %%L in ('vol %drive% 2^>nul') do for %%T in (%%L) do set "volume_serial=%%T"
if not defined volume_label_line set "volume_label_line=%drive% (label unknown)"
if "%volume_label_line:~-1%"=="." set "volume_label_line=%volume_label_line:~0,-1%"
set "filesystem_found="
for %%M in (%FILESYSTEM_METHODS%) do if not defined filesystem_found call :filesystem_from_%%M %drive%
set "filesystem_text=%filesystem_found%"
if not defined filesystem_found set "filesystem_text=file system unknown"
endlocal & set "%~2=%volume_label_line%; serial %volume_serial%; %filesystem_text%" & set "%~3=%filesystem_found%" & set "%~4=%volume_serial%" & set "%~5=%volume_label_line%; %filesystem_text%"
exit /b 0

:filesystem_from_fsutil  drive
rem Caller's scope (:describe_volume): set filesystem_found from
rem "fsutil fsinfo volumeinfo" (may need admin).
for /f "delims=" %%L in ('fsutil fsinfo volumeinfo %~1 2^>nul ^<nul') do for %%T in (%%L) do for %%F in (%KNOWN_FILESYSTEMS%) do (
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

rem -- Copy -------------------------------------------------------------------

:run_copy_pass  passId
rem One robocopy pass as defined by the PASS_<passId>_* row in CONFIG.
setlocal EnableDelayedExpansion
set "label=!PASS_%~1_LABEL!"
set "threads=!PASS_%~1_THREADS!"
if /i "!threads!"=="auto" call :auto_thread_count threads
set "excluded_dirs="
set "excluded_files="
call :add_housekeeping_exclusions source
call :add_housekeeping_exclusions destination
call :build_exclusion_args
set "msg=" & call :show_and_log msg
set "msg=--- Copy pass: !label!, threads: !threads! ---" & call :show_and_log msg
set "log_option="
if "!log_enabled!"=="1" set log_option=/unilog:"!temp_robocopy_unicode_output!"
robocopy "!source_path! " "!destination_path! " *.* !COPY_FLAGS! !PASS_%~1_FILTER! !PASS_%~1_FLAGS! /mt:!threads! /r:!RETRY_COUNT! /w:!RETRY_WAIT_SECONDS! !robocopy_progress_flags! !backup_flag! !exclusion_args! !log_option!
set "pass_exit_code=!errorlevel!"
if "!log_enabled!"=="1" call :save_robocopy_unicode_output log_staged_path append
call :report_robocopy_exit_code pass_exit_code
endlocal & set /a "copy_exit_codes|=%pass_exit_code%" & exit /b 0

:copy_custody_files
rem Forensic run: copy the source set's custody files in a pass of their
rem own, into the destination set: the run records (without
rem IGNORED_CUSTODY_FILES) and script copies. The copy with this script's name
rem goes only if :choose_script_copy chose it (newer than this script), and
rem then replaces any copy there. The history beside the evidence
rem isn't copied: this run writes a new one (:publish_records). Raw evidence
rem (a first copy) has none. Same copy flags as the evidence passes,
rem unbuffered.
setlocal EnableDelayedExpansion
set "msg=" & call :show_and_log msg
set "msg=--- Copy pass: Custody records (not evidence) ---" & call :show_and_log msg
if not defined source_set_path (
    set "msg=No custody files to copy: raw evidence (a first copy)."
    call :show_and_log msg
    endlocal & exit /b 0
)
set "log_option="
if "!log_enabled!"=="1" set log_option=/unilog:"!temp_robocopy_unicode_output!"
call :ignored_names_as_robocopy_arguments ignored_arguments
set "custody_exit_codes=0"
set "custody_found="
set "source_records_directory=!source_set_with_backslash!!RECORDS_DIR_NAME!"
call :is_directory source_records_directory && (
    set "custody_found=1"
    robocopy "!source_set_with_backslash!!RECORDS_DIR_NAME! " "!destination_set_with_backslash!!RECORDS_DIR_NAME! " *.* !COPY_FLAGS! /xf !ignored_arguments! /j /mt:1 /r:!RETRY_COUNT! /w:!RETRY_WAIT_SECONDS! !robocopy_progress_flags! !backup_flag! !log_option!
    set "pass_exit_code=!errorlevel!"
    if "!log_enabled!"=="1" call :save_robocopy_unicode_output log_staged_path append
    call :report_robocopy_exit_code pass_exit_code custody
    set /a "custody_exit_codes|=pass_exit_code"
)
if exist "!source_set_with_backslash!!SCRIPT_FILE_PREFIX!*!SCRIPT_FILE_EXT!" (
    set "custody_found=1"
    robocopy "!source_set_path! " "!destination_set_path! " "!SCRIPT_FILE_PREFIX!*!SCRIPT_FILE_EXT!" /xf "!script_file_name!" !COPY_FLAGS! /lev:1 /j /mt:1 /r:!RETRY_COUNT! /w:!RETRY_WAIT_SECONDS! !robocopy_progress_flags! !backup_flag! !log_option!
    set "pass_exit_code=!errorlevel!"
    if "!log_enabled!"=="1" call :save_robocopy_unicode_output log_staged_path append
    call :report_robocopy_exit_code pass_exit_code custody
    set /a "custody_exit_codes|=pass_exit_code"
)
if "!script_copy_route!"=="source" (
    robocopy "!source_set_path! " "!destination_set_path! " "!script_file_name!" !COPY_FLAGS! /is /it /lev:1 /j /mt:1 /r:!RETRY_COUNT! /w:!RETRY_WAIT_SECONDS! !robocopy_progress_flags! !backup_flag! !log_option!
    set "pass_exit_code=!errorlevel!"
    if "!log_enabled!"=="1" call :save_robocopy_unicode_output log_staged_path append
    call :report_robocopy_exit_code pass_exit_code custody
    set /a "custody_exit_codes|=pass_exit_code"
)
if not defined custody_found (
    set "msg=No run records or script copies in the source set."
    call :show_and_log msg
)
endlocal & set /a "copy_exit_codes|=%custody_exit_codes%" & exit /b 0

:ignored_names_as_robocopy_arguments  outVar
rem IGNORED_CUSTODY_FILES as robocopy /xf arguments: each item quoted.
setlocal EnableDelayedExpansion
set "arguments="
set "remaining=!IGNORED_CUSTODY_FILES!"
:ignored_names_as_robocopy_arguments_next
if not defined remaining (endlocal & set "%~1=%arguments%" & exit /b 0)
set "item="
for /f "tokens=1* delims=|" %%A in ("!remaining!") do (
    set "item=%%A"
    set "remaining=%%B"
)
if defined item set "arguments=!arguments! "!item!""
if not defined item set "remaining="
goto ignored_names_as_robocopy_arguments_next

:restore_destination_attributes
rem Undo container attributes (CONTAINER_ATTRIBUTES) that robocopy carried from
rem the source directory onto the destination directory itself (not its
rem contents). A destination drive root is left alone.
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
    set "msg=Destination directory attributes unchanged."
    call :show_and_log msg
    endlocal & exit /b 0
)
attrib !attrib_switches! "!destination_path!" >nul 2>&1
set "attributes_now="
for %%A in ("!destination_path!") do set "attributes_now=%%~aA"
set "msg=Destination directory: cleared!cleared_names! (carried over from the source directory)."
call :show_and_log msg
for %%R in (%CONTAINER_ATTRIBUTES%) do for /f "tokens=1-3 delims=:" %%I in ("%%R") do (
    if /i "!attributes_now:~%%I,1!"=="%%J" if "!attributes_before:~%%I,1!"=="-" (
        set "msg=[WARN] Could not clear %%K on the destination directory."
        call :show_and_log msg
        call :remember_problem msg
    )
)
endlocal & exit /b 0

rem -- Verification -----------------------------------------------------------

:verify_copy
rem Forensic run. Check the copy: first the metadata (size and last-modified
rem time), then the SHA-256 of every evidence file against the reference
rem record, then the run records against the history and their seals. The
rem reference record is row 1's source hash record or, if the source has no
rem history, this run's own record of the source, made now. So the source is
rem hashed once per set, and every later copy is checked back to it.
set "msg=" & call :show_and_log msg
set "msg=--- Verification: metadata, SHA-256 hashes and run records ---" & call :show_and_log msg
call :check_metadata
where /q certutil.exe || (
    set "msg=[FAIL] certutil.exe not found: verification could not run."
    call :show_and_log msg
    call :remember_problem msg
    set "hash_check_incomplete=1"
    exit /b 1
)
if not defined reference_run (
    set "msg=" & call :show_and_log msg
    set "msg=--- Hashing the source (no reference record in the source's history): it becomes the reference record ---"
    call :show_and_log msg
    call :hash_directory source || set "hash_check_incomplete=1"
    call :write_hash_csv source
)
set "msg=" & call :show_and_log msg
set "msg=--- Hashing the destination ---" & call :show_and_log msg
call :hash_directory destination || set "hash_check_incomplete=1"
call :write_hash_csv destination
set "msg=" & call :show_and_log msg
set "msg=--- Hashing the custody files in the destination set (not evidence) ---" & call :show_and_log msg
call :hash_custody_files
call :write_hash_csv custody
rem The reference record: row 1's, read from its copy in the destination;
rem otherwise this run's own record of the source.
set "reference_name=%record_file_stem%_hashes_source.csv"
set "reference_csv_path=%staged_hash_csv_source%"
set "reference_seal_result_text=made by this run; sealed at the end of it"
if defined reference_run set "reference_name=%RECORD_FILE_PREFIX%%reference_run%_hashes_source.csv"
if defined reference_run set "reference_csv_path=%destination_set_with_backslash%%RECORDS_DIR_NAME%\%reference_run%\%RECORD_FILE_PREFIX%%reference_run%_hashes_source.csv"
if defined reference_run set "reference_seal_result_text="
call :check_run_records
if not exist "%reference_csv_path%" (
    set "msg=[FAIL] The reference record %reference_name% was not found after the copy."
    call :show_and_log msg
    call :remember_problem msg
    set "hash_check_incomplete=1"
    exit /b 1
)
call :compare_with_reference
exit /b 0

:verify_plain_copy
rem Non-forensic run: hash every source file and its copy and compare them,
rem with the metadata check. Working files stay in TEMP; nothing is written
rem beside the copy, and the result is shown on screen only.
set "msg=" & call :show msg
set "msg=--- Verification: metadata and SHA-256 hashes (on screen only) ---" & call :show msg
call :check_metadata
where /q certutil.exe || (
    set "msg=[FAIL] certutil.exe not found: verification could not run."
    call :show msg
    call :remember_problem msg
    set "hash_check_incomplete=1"
    exit /b 1
)
set "msg=" & call :show msg
set "msg=--- Hashing the source ---" & call :show msg
call :hash_directory source || set "hash_check_incomplete=1"
call :write_hash_csv source
set "msg=" & call :show msg
set "msg=--- Hashing the destination ---" & call :show msg
call :hash_directory destination || set "hash_check_incomplete=1"
call :write_hash_csv destination
set "reference_csv_path=%staged_hash_csv_source%"
call :compare_with_reference
exit /b 0

:hash_custody_files
rem Forensic run. Hash the custody files in the destination set as they are
rem before this run's record is added: the run records, script copies and
rem the history file. Ignored names (IGNORED_CUSTODY_FILES) are left out.
rem They have a progress counter of their own and are never counted as
rem evidence.
type nul >"%temp_custody_list%"
for /f "eol=/ delims=" %%F in ('dir /b /s /a-d "%destination_set_with_backslash%%RECORDS_DIR_NAME%\" 2^>nul') do (
    set "custody_file_path=%%F"
    for %%N in ("%%F") do set "custody_file_name=%%~nxN"
    call :list_custody_file
)
for /f "eol=/ delims=" %%F in ('dir /b /a-d "%destination_set_with_backslash%" 2^>nul') do (
    set "custody_file_name=%%F"
    call :list_top_level_custody_file
)
set "custody_files_count=0"
for /f "usebackq tokens=*" %%L in ("%temp_custody_list%") do set /a "custody_files_count+=1"
if %custody_files_count% equ 0 (
    set "msg=No custody files in the destination set yet."
    call :show_and_log msg
)
for /f "usebackq tokens=*" %%L in ("%temp_custody_list%") do (
    set "listed_line=%%L"
    call :hash_listed_file listed_line custody %custody_files_count%
)
exit /b 0

:list_custody_file
rem Caller's scope (:hash_custody_files): a file in the records directory, in
rem custody_file_path and custody_file_name; ignored names are left out.
call :name_matches_list custody_file_name IGNORED_CUSTODY_FILES && exit /b 0
call :append_line_to_file custody_file_path temp_custody_list
exit /b 0

:list_top_level_custody_file
rem Caller's scope (:hash_custody_files): a file at the destination set's top
rem level, in custody_file_name: listed if it is a custody file.
call :is_custody_file_name custody_file_name || exit /b 0
set "custody_file_path=%destination_set_with_backslash%%custody_file_name%"
call :append_line_to_file custody_file_path temp_custody_list
exit /b 0

:append_line_to_file  textVar  fileVar
rem Append a variable's value as a line to a file.
setlocal EnableDelayedExpansion
>>"!%~2!" echo(!%~1!
endlocal & exit /b 0

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
rem A network share may store coarser times than the file system it copies
rem from; robocopy's documentation recommends /fft for shares (owner,
rem 2026-10-16, after the reviews).
if not defined fft_flag if "!source_path:~0,2!"=="\\" set "time_precision=to 2 s, as a network share is involved"
if not defined fft_flag if "!destination_path:~0,2!"=="\\" set "time_precision=to 2 s, as a network share is involved"
if not defined fft_flag if "!source_path:~0,2!"=="\\" set "fft_flag=/fft"
if not defined fft_flag if "!destination_path:~0,2!"=="\\" set "fft_flag=/fft"
set "msg=" & call :show_and_log msg
set "msg=--- Metadata check: size and last-modified time, compared !time_precision! ---"
call :show_and_log msg
set "excluded_dirs="
set "excluded_files="
call :add_housekeeping_exclusions source
call :add_housekeeping_exclusions destination
call :build_exclusion_args
robocopy "!source_path! " "!destination_path! " *.* !METADATA_FLAGS! !fft_flag! !backup_flag! !exclusion_args! /unilog:"!temp_robocopy_unicode_output!"
set "check_exit_code=!errorlevel!"
call :save_robocopy_unicode_output temp_metadata_list new
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

:hash_directory  side
rem List every evidence file in the side's directory (with robocopy) and hash
rem each one into the side's rows. Exit 1 if the listing was incomplete.
set "hash_directory_listing_failed="
call :list_files %~1 temp_file_list || set "hash_directory_listing_failed=1"
rem Total for the progress counter: the listing read the same way as the
rem hashing loop below (FOR /F skips robocopy's blank lines, which a line
rem count would include).
set "files_to_hash_count=0"
for /f "usebackq tokens=*" %%L in ("%temp_file_list%") do set /a "files_to_hash_count+=1"
for /f "usebackq tokens=*" %%L in ("%temp_file_list%") do (
    set "listed_line=%%L"
    call :hash_listed_file listed_line %~1 %files_to_hash_count%
)
if defined hash_directory_listing_failed exit /b 1
exit /b 0

:list_files  side  outFileVar
rem Write every file in the side's directory to the out file as a full path,
rem one per line, using robocopy (sees Hidden/System files and long paths)
rem and the same drive-root exclusions as the copy. Exit 1 if robocopy
rem reports a failure.
setlocal EnableDelayedExpansion
set "excluded_dirs="
set "excluded_files="
call :add_housekeeping_exclusions %~1
call :build_exclusion_args
robocopy "!%~1_with_backslash! " "!temp_path_prefix!_nonexistent" *.* !LIST_FLAGS! !backup_flag! !exclusion_args! /unilog:"!temp_robocopy_unicode_output!"
set "list_exit_code=!errorlevel!"
call :save_robocopy_unicode_output %~2 new
if !list_exit_code! geq 8 (
    set "msg=[FAIL] Could not list every file under !%~1_with_backslash! (robocopy exit code !list_exit_code!)."
    call :show_and_log msg
    call :remember_problem msg
    endlocal & exit /b 1
)
endlocal & exit /b 0

:hash_listed_file  lineVar  side  total
rem Hash one listed file and record it as a "relative path","SHA-256" row for
rem the side's CSV. side: source, destination, or custody (custody files in
rem the destination set). For the destination also as a compare line
rem "relative path*SHA-256*DST" for :compare_with_reference. total is only for
rem the progress counter.
setlocal EnableDelayedExpansion
set "base_var=%~2_with_backslash"
if "%~2"=="custody" set "base_var=destination_set_with_backslash"
set "item_label=%~2"
if "%~2"=="custody" set "item_label=custody record"
set "full_path=!%~1!"
call :relative_path full_path !base_var! file_relative_path || (
    set "msg=[FAIL] Unexpected line while listing the %~2: !full_path!"
    call :show_and_log msg
    call :remember_problem msg
    endlocal & set /a "unexpected_listing_lines+=1" & exit /b 0
)
set /a "sequence_number=hashed_count_%~2 + 1"
set "msg=[!sequence_number!/%~3] Hashing !item_label!: !file_relative_path!" & call :show msg
set "file_sha256="
call :get_sha256 full_path file_sha256
if not defined file_sha256 set "file_sha256=UNREADABLE"
>>"!temp_hash_rows_%~2!" echo("!file_relative_path!","!file_sha256!"
if "%~2"=="destination" >>"!temp_compare_lines!" echo(!file_relative_path!*!file_sha256!*DST
endlocal & set /a "hashed_count_%~2+=1" & exit /b 0

:write_hash_csv  side
rem Write the side's CSV (in the staging directory; side: source, destination or
rem custody): header plus rows sorted by
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
rem certutil runs here, not inside a FOR /F command: FOR /F runs its
rem command in a child cmd, which would expand %NAME% in a file name (e.g.
rem "x %OS% y.txt" -> "x Windows_NT y.txt") and hash another file (test
rem runner round 6). Its output goes to temp_certutil_output and is read
rem from there.
setlocal EnableDelayedExpansion
set "file_path=!%~1!"
set "sha256="
del "!temp_certutil_output!" >nul 2>&1
rem certutil gets the extended-length form (\\?\, \\?\UNC\ for shares): Windows
rem then takes the name as it is, instead of normalising it (a trailing dot or
rem space dropped, so "report." would be hashed as "report"; reserved names
rem such as "nul"), and paths over 260 characters can be read (review,
rem 2026-10-16). The form isn't normalised either, so a path holding "\\",
rem "\.\" or "\..\" keeps the plain form.
set "hash_path=\\?\!file_path!"
if "!file_path:~0,2!"=="\\" set "hash_path=\\?\UNC\!file_path:~2!"
set "path_after_start=!file_path:~2!"
if not "!path_after_start!"=="!path_after_start:\\=!" set "hash_path=!file_path!"
if not "!file_path!"=="!file_path:\.\=!" set "hash_path=!file_path!"
if not "!file_path!"=="!file_path:\..\=!" set "hash_path=!file_path!"
certutil -hashfile "!hash_path!" SHA256 >"!temp_certutil_output!" 2>nul
if exist "!temp_certutil_output!" for /f "usebackq skip=1 delims=" %%H in ("!temp_certutil_output!") do if not defined sha256 set "sha256=%%H"
del "!temp_certutil_output!" >nul 2>&1
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

:compare_with_reference
rem Compare the destination with the reference record: every file in the
rem record must be in the destination with the same SHA-256. Both are written
rem as compare lines "relative path*SHA-256*REF" (from the reference record)
rem and "...*DST" (from the destination); * can't occur in Windows names.
rem Sorted ordinally (sort /L C), each path's two lines are adjacent, so one
rem pass pairs them up. In /nonforensic the reference is this run's hashes of
rem the source, which are in no record: the messages say "the source".
set "compare_reference_label=reference record"
if "%run_mode%"=="nonforensic" set "compare_reference_label=source"
set "msg=" & call :show_and_log msg
set "msg=--- Destination vs reference record: %reference_name% ---"
if "%run_mode%"=="nonforensic" set "msg=--- Destination vs source ---"
call :show_and_log msg
for /f "usebackq skip=1 delims=" %%L in ("%reference_csv_path%") do (
    set "reference_row=%%L"
    call :add_reference_row reference_row
)
if not exist "%temp_compare_lines%" type nul >"%temp_compare_lines%"
sort /L C /O "%temp_compare_lines_sorted%" "%temp_compare_lines%"
set "compare_line_count=0"
for /f %%N in ('find /c /v "" ^< "%temp_compare_lines_sorted%"') do set "compare_line_count=%%N"
set "msg=Pairing %compare_line_count% entries (%compare_reference_label% and destination) ..."
call :show msg
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
    if "!tag!"=="!previous_tag!" set "problem=Listed twice in the reference record" & set "outcome_counter=invalid_row_count"
    if not defined problem call :is_sha256 reference_hash || (set "problem=No valid hash in the reference record" & set "outcome_counter=invalid_row_count")
    if not defined problem if "!destination_hash!"=="UNREADABLE" set "problem=UNREADABLE in the destination" & set "outcome_counter=unreadable_count"
    if not defined problem if /i not "!reference_hash!"=="!destination_hash!" set "problem=DIFFERS from the !compare_reference_label!" & set "outcome_counter=differ_count"
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
rem not in the record: added since. In a forensic run that is a FAIL (owner,
rem 2026-10-16, after the reviews): inside the evidence directory a file the
rem reference record doesn't list is unexplained. In /nonforensic it is a file
rem that was already in the destination: a warning. Custody files never get
rem here; they are hashed separately. Caller's scope, delayed expansion on.
if "!%~2!"=="REF" (
    set "msg=[FAIL] MISSING from the destination (in the !compare_reference_label!): !%~1!"
    call :show_and_log msg
    call :remember_problem msg
    set "outcome_counter=missing_count"
    exit /b 0
)
set "unpaired_path=!%~1!"
set "msg=[FAIL] Not in the reference record (added since, so not verified against it): !unpaired_path!"
if "!run_mode!"=="nonforensic" set "msg=[WARN] Not in the source (already in the destination, not verified): !unpaired_path!"
call :show_and_log msg
call :remember_problem msg
set "outcome_counter=added_file_count"
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

rem -- Run records ------------------------------------------------------------

:check_run_records
rem Forensic run, after the copy: the run records in the destination set
rem against the history this run continues (README, "History and run
rem records"). Each of these fails the Run records check (counted in
rem run_record_problem_count): run records but no history beside the
rem evidence; a run the history lists that has no run record; a run record
rem the history doesn't list; a run record's seal whose SHA-256 isn't the
rem history's Seal SHA-256; a run record whose own sealed history doesn't
rem match the history; a run record failing its seal (:check_run_record).
rem A leftover <run>.partial directory (an interrupted write-back) is a warning
rem and outside the history.
set "run_records_root=%destination_set_with_backslash%%RECORDS_DIR_NAME%"
set "run_records_root_found="
call :is_directory run_records_root && set "run_records_root_found=1"
if not defined run_records_root_found if not defined history_base_path if not defined history_base_missing exit /b 0
set "run_records_checked=1"
set "msg=" & call :show_and_log msg
set "msg=--- Run records against the history and their seals ---" & call :show_and_log msg
call :report_history_set_aside source after
call :report_history_set_aside destination after
if defined history_base_missing (
    set "msg=[FAIL] Run records: the set holds run records but no history file (%HISTORY_FILE_NAME%) beside the evidence, so they can't be checked against it."
    call :show_and_log msg
    call :remember_problem msg
    set /a "run_record_problem_count+=1"
)
type nul >"%temp_history_runs%"
type nul >"%temp_outside_history%"
if defined history_base_path for /f "tokens=1* delims=:" %%A in ('findstr /n "^" "%history_base_path%" 2^>nul') do if %%A gtr 1 (
    set "history_row_line=%%B"
    set "history_line_number=%%A"
    call :split_history_line row
    call :check_history_row
)
for /f "eol=/ delims=" %%F in ('dir /b /a-d "%run_records_root%\" 2^>nul') do (
    set "stray_name=%%F"
    call :report_stray_record_file
)
type nul >"%temp_predating_records%"
for /f "eol=/ delims=" %%R in ('dir /b /ad /on "%run_records_root%\" 2^>nul') do (
    set "record_directory_name=%%R"
    call :check_record_directory_listed
)
call :report_predating_records
exit /b 0

:report_predating_records
rem One warning for all run records that predate a restarted history and
rem whose seal files still have the SHA-256 listed for them (owner,
rem 2026-10-16: one line per copy, not one per record).
setlocal EnableDelayedExpansion
set "predating_count=0"
set "predating_names="
for /f "usebackq delims=" %%P in ("!temp_predating_records!") do (
    set /a "predating_count+=1"
    set "predating_names=!predating_names!, %%P"
)
if !predating_count! equ 0 (endlocal & exit /b 0)
set "msg=Run records: !predating_count! run record(s) predate the history (listed as outside it when it was restarted): !predating_names:~2!. Each one's seal file still has the SHA-256 listed for it; its files are checked against that seal separately."
call :add_warning msg
endlocal & exit /b 0

:check_history_row
rem Caller's scope (:check_run_records): one row of the history (row_*, on
rem line history_line_number). Its run record must exist and pass its seal,
rem its seal's SHA-256 must be the row's Seal SHA-256, and its own sealed
rem history must be the history up to this row (with this row's pending
rem seal text, the only difference).
call :append_line_to_file row_run temp_history_runs
set "row_run_dir=%run_records_root%\%row_run%"
rem Row 1 is line 2 of the file (line 1 is the header).
set /a "history_row_number=history_line_number - 1"
call :is_directory row_run_dir || (
    set "msg=[FAIL] Run records: run %row_run% (row %history_row_number% of the history) has no run record."
    call :show_and_log msg
    call :remember_problem msg
    set /a "run_record_problem_count+=1"
    exit /b 0
)
call :check_run_record row_run row_run_dir
call :collect_outside_history row_run_dir row_run
set "row_seal_path=%row_run_dir%\%RECORD_FILE_PREFIX%%row_run%.sha256"
set "row_seal_sha256="
if exist "%row_seal_path%" call :get_sha256 row_seal_path row_seal_sha256
if exist "%row_seal_path%" if /i not "%row_seal_sha256%"=="%row_seal%" (
    set "msg=[FAIL] Run records: run %row_run%'s seal doesn't have the SHA-256 the history records for it."
    call :show_and_log msg
    call :remember_problem msg
    set /a "run_record_problem_count+=1"
)
set "row_sealed_history=%row_run_dir%\%RECORD_FILE_PREFIX%%row_run%_history.csv"
if not exist "%row_sealed_history%" exit /b 0
set "row_pending_text=see %RECORD_FILE_PREFIX%%row_run%.sha256"
call :write_history_with_seal row_sealed_history row_pending_text row_seal temp_history_filled
call :history_starts_with history_base_path temp_history_filled && exit /b 0
set "msg=[FAIL] Run records: run %row_run%'s sealed history doesn't match the history beside the evidence up to that run."
call :show_and_log msg
call :remember_problem msg
set /a "run_record_problem_count+=1"
exit /b 0

:report_stray_record_file
rem Caller's scope (:check_run_records): a file directly in the records
rem directory, in stray_name, outside any run record: no seal covers it.
rem Ignored names are left alone.
call :name_matches_list stray_name IGNORED_CUSTODY_FILES && exit /b 0
set "msg=[FAIL] Run records: %stray_name% is in the records directory but not in a run record, so no seal covers it."
call :show_and_log msg
call :remember_problem msg
set /a "run_record_problem_count+=1"
exit /b 0

:check_record_directory_listed
rem Caller's scope (:check_run_records): a directory in the records directory,
rem in record_directory_name. A leftover <run>.partial is a warning. Any other
rem directory must be a run the history lists, or a run record a history restart
rem listed as outside the history it restarted (a warning, if it still matches
rem the seal SHA-256 listed for it). When this run restarts the history itself,
rem each run record found is checked against its own seal and listed
rem (:list_run_outside_history).
call :is_partial_run_directory record_directory_name && goto check_record_directory_listed_partial
findstr /x /l /c:"%record_directory_name%" "%temp_history_runs%" >nul 2>&1 && exit /b 0
set "record_directory_dir=%run_records_root%\%record_directory_name%"
if defined history_base_missing (
    call :check_run_record record_directory_name record_directory_dir
    call :list_run_outside_history
    exit /b 0
)
call :find_outside_history && goto check_record_directory_listed_outside
set "msg=[FAIL] Run records: %record_directory_name% in the records directory is not in the history."
call :show_and_log msg
call :remember_problem msg
set /a "run_record_problem_count+=1"
exit /b 0
:check_record_directory_listed_partial
rem A leftover .partial: a warning, once (the check before the copy may have
rem listed it already); here it is also logged with the run records.
set "msg=Run records: %record_directory_name% is an interrupted write-back (a run record never completed); it is outside the history."
set "tagged_msg=[WARN] %msg%"
call :show_and_log tagged_msg
findstr /x /l /c:"%record_directory_name%" "%temp_partial_warned%" >nul 2>&1 && exit /b 0
call :add_warning msg
exit /b 0
:check_record_directory_listed_outside
call :check_run_record record_directory_name record_directory_dir
set "record_directory_seal=%record_directory_dir%\%RECORD_FILE_PREFIX%%record_directory_name%.sha256"
set "record_directory_seal_sha256="
if exist "%record_directory_seal%" call :get_sha256 record_directory_seal record_directory_seal_sha256
rem Listed with no seal ("none") and still without one: unchanged since the
rem restart; the missing seal itself is a failure of :check_run_record.
if "%outside_seal_sha256%"=="none" if not defined record_directory_seal_sha256 (
    set "msg=Run records: %record_directory_name% predates the history: run %outside_listed_by% found it outside the history it restarted, without a seal, and it still has none."
    call :add_warning msg
    exit /b 0
)
if /i not "%record_directory_seal_sha256%"=="%outside_seal_sha256%" (
    set "msg=[FAIL] Run records: %record_directory_name%, listed by run %outside_listed_by% as outside the history it restarted, has changed since: its seal's SHA-256 isn't the one listed."
    call :show_and_log msg
    call :remember_problem msg
    set /a "run_record_problem_count+=1"
    exit /b 0
)
rem Listed for one warning after all run records are checked
rem (:report_predating_records), not one warning each.
call :append_line_to_file record_directory_name temp_predating_records
exit /b 0

:list_run_outside_history
rem Caller's scope (:check_record_directory_listed, history restart): add the
rem run record in record_directory_name, with its seal's SHA-256, to this
rem run's sealed list of run records outside the restarted history
rem (<stem>_runs_outside_history.csv), so later copies can tell them apart
rem from run records added since.
set "record_directory_seal=%record_directory_dir%\%RECORD_FILE_PREFIX%%record_directory_name%.sha256"
set "record_directory_seal_sha256="
if exist "%record_directory_seal%" call :get_sha256 record_directory_seal record_directory_seal_sha256
if not defined record_directory_seal_sha256 set "record_directory_seal_sha256=none"
if not exist "%staged_outside_history_path%" >"%staged_outside_history_path%" echo "Run record","Seal SHA-256"
>>"%staged_outside_history_path%" echo "%record_directory_name%","%record_directory_seal_sha256%"
exit /b 0

:collect_outside_history  runDirVar  runVar
rem If this run record holds a history restart's list of run records outside
rem the history (<stem>_runs_outside_history.csv), add its rows to
rem temp_outside_history as "run*seal SHA-256*listing run" lines.
setlocal EnableDelayedExpansion
set "list_file=!%~1!\!RECORD_FILE_PREFIX!!%~2!_runs_outside_history.csv"
if not exist "!list_file!" (endlocal & exit /b 0)
for /f "usebackq skip=1 delims=" %%L in ("!list_file!") do (
    set "line=%%L"
    set "line=!line:","=*!"
    set "line=!line:"=!"
    >>"!temp_outside_history!" echo(!line!*!%~2!
)
endlocal & exit /b 0

:find_outside_history
rem Caller's scope (IN record_directory_name). If a history restart listed this
rem run record as outside its history, set outside_seal_sha256 and
rem outside_listed_by and exit 0; otherwise exit 1.
set "outside_seal_sha256="
set "outside_listed_by="
if not exist "%temp_outside_history%" exit /b 1
for /f "tokens=1-3 delims=*" %%A in ('findstr /b /l /c:"%record_directory_name%*" "%temp_outside_history%" 2^>nul') do if not defined outside_listed_by (
    set "outside_seal_sha256=%%B"
    set "outside_listed_by=%%C"
)
if defined outside_listed_by exit /b 0
exit /b 1

:check_run_record  runVar  runDirVar
rem One run record: its seal, every file the seal lists, and every file in
rem the directory (subdirectories must have every file listed too: later 2.x
rem versions may add them). If it is the reference record's run, also sets
rem reference_seal_failed and the summary text.
setlocal EnableDelayedExpansion
set "run=!%~1!"
set "run_dir=!%~2!"
set "seal_name=!RECORD_FILE_PREFIX!!run!.sha256"
set "seal_path=!run_dir!\!seal_name!"
set "problems=0"
set "matches=0"
set "seal_sha256=none"
if not exist "!seal_path!" (
    set "msg=[FAIL] Run record !run!: no seal (!seal_name!), so its files can't be shown unchanged."
    call :show_and_log msg
    call :remember_problem msg
    set /a "problems+=1"
    goto check_run_record_done
)
call :get_sha256 seal_path seal_sha256
if not defined seal_sha256 set "seal_sha256=unknown"
for /f "usebackq tokens=1,*" %%A in ("!seal_path!") do (
    set "listed_sha256=%%A"
    set "listed_name=%%B"
    call :check_sealed_file run run_dir listed_name listed_sha256
)
call :check_run_record_files run run_dir seal_path
set "msg=Run record !run!: !matches! file(s) match its seal, !problems! problem(s). Seal SHA-256: !seal_sha256!"
call :show_and_log msg
:check_run_record_done
set "reference_text="
set "reference_failed=0"
if "!run!"=="!reference_run!" (
    set "reference_text=matches its seal !seal_name! (seal SHA-256 !seal_sha256!)"
    if !problems! gtr 0 set "reference_text=FAIL: its run record fails its seal check (!seal_name!, seal SHA-256 !seal_sha256!)"
    if !problems! gtr 0 set "reference_failed=1"
)
endlocal & set /a "run_record_count+=1, run_record_file_match_count+=%matches%, run_record_problem_count+=%problems%, reference_seal_failed|=%reference_failed%" & if not "%reference_text%"=="" set "reference_seal_result_text=%reference_text%"
exit /b 0

:check_run_record_files  runVar  runDirVar  sealPathVar
rem Caller's scope (:check_run_record, delayed expansion on): every file in
rem the run record must be listed in its seal (:check_file_listed_in_seal).
rem The listing runs with delayed expansion off, so a "!" in the path (e.g.
rem in the destination's name) survives the FOR value; when it was on, the
rem "!" was lost, the path couldn't be compared and an unlisted file went
rem unreported (review, 2026-10-16). Problems found are added to the
rem caller's problems count.
setlocal DisableDelayedExpansion
call :copy_variable %~2 record_files_dir
set "problems=0"
for /f "eol=/ delims=" %%F in ('dir /b /s /a-d "%record_files_dir%\" 2^>nul') do (
    set "directory_file_path=%%F"
    call :check_file_listed_in_seal %~1 %~2 %~3 directory_file_path
)
endlocal & set /a "problems+=%problems%"
exit /b 0

:check_sealed_file  runVar  runDirVar  nameVar  sha256Var
rem One "SHA-256 *name" line of a seal: the file must exist in the run record
rem with that SHA-256. Counts into the caller's matches or problems.
setlocal EnableDelayedExpansion
set "sealed_name=!%~3!"
if "!sealed_name:~0,1!"=="*" set "sealed_name=!sealed_name:~1!"
set "sealed_path=!%~2!\!sealed_name!"
set "current_sha256="
if exist "!sealed_path!" call :get_sha256 sealed_path current_sha256
if not exist "!sealed_path!" (
    set "msg=[FAIL] Run record !%~1!: !sealed_name! is listed in its seal but missing."
    goto check_sealed_file_failed
)
if /i not "!current_sha256!"=="!%~4!" (
    set "msg=[FAIL] Run record !%~1!: !sealed_name! has changed since it was sealed."
    goto check_sealed_file_failed
)
endlocal & set /a "matches+=1" & exit /b 0
:check_sealed_file_failed
call :show_and_log msg
call :remember_problem msg
endlocal & set /a "problems+=1" & exit /b 0

:check_file_listed_in_seal  runVar  runDirVar  sealPathVar  filePathVar
rem A file in a run record must be the seal itself, an ignored name, or
rem listed in the seal (by its path inside the run record).
setlocal EnableDelayedExpansion
set "file_path=!%~4!"
for %%N in ("!file_path!") do set "file_name=%%~nxN"
set "run_dir_with_backslash=!%~2!\"
call :relative_path file_path run_dir_with_backslash name_in_record || goto check_file_listed_in_seal_unresolved
if /i "!name_in_record!"=="!RECORD_FILE_PREFIX!!%~1!.sha256" (endlocal & exit /b 0)
call :name_matches_list file_name IGNORED_CUSTODY_FILES && (endlocal & exit /b 0)
findstr /l /e /c:" *!name_in_record!" "!%~3!" >nul 2>&1 && (endlocal & exit /b 0)
set "msg=[FAIL] Run record !%~1!: !name_in_record! is not listed in its seal."
call :show_and_log msg
call :remember_problem msg
endlocal & set /a "problems+=1" & exit /b 0
:check_file_listed_in_seal_unresolved
rem A file found in the run record whose place in it can't be worked out is
rem never taken as listed: unknown is not passed.
set "msg=[FAIL] Run record !%~1!: !file_path! is in the run record, but its path inside it couldn't be worked out, so it can't be checked against the seal."
call :show_and_log msg
call :remember_problem msg
endlocal & set /a "problems+=1" & exit /b 0

:write_history_with_seal  sourceFileVar  pendingTextVar  sealVar  outFileVar
rem Write a copy of a history with the pending seal text (only ever in its
rem newest row) replaced by that seal's SHA-256.
setlocal EnableDelayedExpansion
set "history_source_file=!%~1!"
set "history_pending_text=!%~2!"
set "history_seal_sha256=!%~3!"
set "history_out_file=!%~4!"
setlocal DisableDelayedExpansion
type nul >"%history_out_file%"
for /f "tokens=1* delims=:" %%A in ('findstr /n "^" "%history_source_file%" 2^>nul') do (
    set "history_line=%%B"
    call :append_history_line_with_seal
)
endlocal & endlocal & exit /b 0

:append_history_line_with_seal
rem (:write_history_with_seal) one line, in history_line, with the pending
rem seal text replaced, appended to history_out_file.
setlocal EnableDelayedExpansion
if not defined history_line (
    >>"!history_out_file!" echo(
    endlocal & exit /b 0
)
for /f "delims=" %%P in ("!history_pending_text!") do set "history_line=!history_line:%%P=%history_seal_sha256%!"
>>"!history_out_file!" echo(!history_line!
endlocal & exit /b 0

:is_run_directory_name  nameVar
rem Exit 0 if the name is a run's UTC time as used for run directories:
rem YYYYMMDDThhmmssZ.
setlocal EnableDelayedExpansion
set "value=!%~1!"
if not "!value:~16!"=="" (endlocal & exit /b 1)
if not "!value:~8,1!"=="T" (endlocal & exit /b 1)
if not "!value:~15,1!"=="Z" (endlocal & exit /b 1)
set "date_and_time_digits=!value:~0,8!!value:~9,6!"
call :is_timestamp_digits date_and_time_digits || (endlocal & exit /b 1)
endlocal & exit /b 0

rem -- Result -----------------------------------------------------------------

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
set "run_records_status=NOT RUN"
set "result_metadata=NOT RUN: verification was not requested"
set "result_hash=NOT RUN: verification was not requested"
set "result_hash_detail="
set "result_run_records=NOT RUN"
set "result_reference=none"
set "verification_ran="
if "%verification_enabled%"=="1" set "verification_ran=1"
if "%run_mode%"=="forensic" set "verification_ran=1"
if defined verification_ran call :work_out_verification_status
rem The verdict: FAIL if the copy or any check failed (with verification on,
rem a check that didn't pass counts as failed; run records and the script
rem may also be NONE, with nothing earlier to check); UNVERIFIED if the copy
rem passed but nothing was verified (non-forensic only); otherwise PASS.
set "verdict=PASS"
if not "%copy_status%"=="PASS" set "verdict=FAIL"
if defined verification_ran if not "%metadata_status%"=="PASS" set "verdict=FAIL"
if defined verification_ran if not "%hash_status%"=="PASS" set "verdict=FAIL"
if "%run_records_status%"=="FAIL" set "verdict=FAIL"
if "%script_status%"=="FAIL" set "verdict=FAIL"
if not defined verification_ran if "%verdict%"=="PASS" set "verdict=UNVERIFIED"
call :describe_meaning
if "%verdict%"=="PASS" set "exit_code=%EXIT_CODE_PASS%"
if "%verdict%"=="FAIL" set "exit_code=%EXIT_CODE_FAIL%"
if "%verdict%"=="UNVERIFIED" set "exit_code=%EXIT_CODE_UNVERIFIED%"
set "result_overall=%verdict% (exit code %exit_code%)"
set "result_history=run %this_run_number% (%history_row_count% earlier run(s) in the history)"
set "msg=" & call :show_and_log msg
set "msg================================================================================" & call :show_and_log msg
set "msg=Result" & call :show_and_log msg
call :log_field "Finished (UTC)" end_utc_iso
if "%run_mode%"=="forensic" call :log_result_records
set "msg=" & call :show_and_log msg
call :log_summary_list "Warnings (did not fail the run)" warnings
set "msg=" & call :show_and_log msg
rem The overall result, each check that feeds into it in the order they ran,
rem and what the result covers.
call :log_result_line "OVERALL RESULT" result_overall
call :log_check_line "Copy (robocopy)" result_copy
call :log_check_line "Metadata" result_metadata
call :log_check_line "Hash (SHA-256)" result_hash result_hash_detail
if "%run_mode%"=="forensic" call :log_check_line "Run records" result_run_records
if "%run_mode%"=="forensic" call :log_check_line "Script" result_script
call :show_and_log result_meaning
set "msg=" & call :show_and_log msg
call :log_summary_list "Failures" failures
set "msg================================================================================" & call :show_and_log msg
exit /b 0

:log_result_records
rem Forensic run: the record lines of the summary.
call :log_field "Script copy" result_script_copy
call :log_field "Reference record" result_reference
if defined reference_seal_result_text call :log_field_continued reference_seal_result_text
call :log_field "History" result_history
call :log_field "Log" log_destination_text
exit /b 0

:describe_meaning
rem The closing line of the summary: what the result covers.
if "%verdict%"=="FAIL" (
    call :describe_failure
    exit /b 0
)
if "%verdict%"=="UNVERIFIED" (
    set "result_meaning=The copy completed without errors, but was not verified (no SHA-256 or metadata check)"
    exit /b 0
)
if "%run_mode%"=="nonforensic" (
    set "result_meaning=The copy completed, every source file is in the destination with the same SHA-256, and size and last-modified time match the source"
    exit /b 0
)
set "result_meaning=The copy completed, every file in the reference record is in the destination with the same SHA-256, and size and last-modified time match the source"
if "%run_records_status%"=="PASS" set "result_meaning=%result_meaning%; every earlier run record matches its seal and the history"
exit /b 0

:describe_failure
rem The closing line of a FAIL summary: each failed check, in the order they
rem ran, then a pointer to the failures listed below the result.
set "result_meaning="
if not "%copy_status%"=="PASS" call :add_failure_clause "The copy failed" "the copy failed"
if defined verification_ran if not "%metadata_status%"=="PASS" call :add_failure_clause "The metadata check failed" "the metadata check failed"
if defined verification_ran if not "%hash_status%"=="PASS" call :add_failure_clause "The SHA-256 verification failed" "the SHA-256 verification failed"
if "%run_records_status%"=="FAIL" call :add_failure_clause "The run records check failed" "the run records check failed"
if "%script_status%"=="FAIL" call :add_failure_clause "The script check failed" "the script check failed"
call :add_failure_clause "See the failures listed below" "see the failures listed below"
exit /b 0

:work_out_verification_status
rem Set metadata_status, hash_status (each PASS or FAIL), run_records_status
rem (PASS, FAIL or NONE; forensic only) and the summary lines for each.
rem Anything that stopped a check from completing fails it.
rem The record the destination was compared with; if hashing stopped before
rem the comparison, the one named by the history, else none.
set "result_reference=%reference_name%"
if not defined result_reference set "result_reference=none"
rem Every row of the reference record must be accounted for (matched, or a
rem listed problem); otherwise a counting slip could hide a file (review,
rem 2026-10-16).
set /a "accounted_row_count=match_count + differ_count + missing_count + invalid_row_count + unreadable_count"
set "unaccounted_rows=0"
if %hash_check_incomplete% equ 0 if %accounted_row_count% neq %reference_row_count% call :report_unaccounted_rows
set /a "hash_problem_count=differ_count + missing_count + invalid_row_count + unreadable_count + unexpected_listing_lines + hash_check_incomplete + reference_seal_failed + unaccounted_rows"
if "%run_mode%"=="forensic" set /a "hash_problem_count+=added_file_count"
set "hash_status=PASS"
if %hash_problem_count% neq 0 set "hash_status=FAIL"
if %match_count% equ 0 set "hash_status=FAIL"
set "reference_label=files in the reference record"
if "%run_mode%"=="nonforensic" set "reference_label=source files"
set "result_hash=%hash_status%: %match_count% of %reference_row_count% %reference_label% match the destination"
set "result_hash_detail=%differ_count% differ, %missing_count% missing, %unreadable_count% unreadable, %invalid_row_count% invalid in the record; added since: %added_file_count% file(s)"
if "%run_mode%"=="nonforensic" set "result_hash_detail=%differ_count% differ, %missing_count% missing, %unreadable_count% unreadable"
if %hash_check_incomplete% neq 0 set "result_hash_detail=%result_hash_detail%; INCOMPLETE (see failures)"
if %unexpected_listing_lines% neq 0 set "result_hash_detail=%result_hash_detail%; %unexpected_listing_lines% unexpected listing line(s)"
rem Files added since the reference fail a forensic run even when every file
rem in the record matches: say so first.
if "%run_mode%"=="forensic" if %added_file_count% gtr 0 set "result_hash=%hash_status%: %added_file_count% file(s) in the destination aren't in the reference record (added since); %match_count% of %reference_row_count% %reference_label% match the destination"
rem A reference whose run record fails its checks can't be relied on, even
rem if every file matches it: say so first, so the status can't be misread.
if %reference_seal_failed% neq 0 set "result_hash=%hash_status%: the reference record's run record failed its checks, so the reference can't be relied on; %match_count% of %reference_row_count% %reference_label% match it"
if "%run_mode%"=="forensic" if %hash_check_incomplete% equ 0 if %reference_row_count% equ 0 set "result_hash_detail=%result_hash_detail%; the reference record lists no files"
if "%run_mode%"=="nonforensic" if %hash_check_incomplete% equ 0 if %reference_row_count% equ 0 set "result_hash_detail=%result_hash_detail%; the source holds no files"
if %hash_check_incomplete% equ 0 if %reference_row_count% equ 0 call :report_nothing_to_verify
set "metadata_status=FAIL"
set "result_metadata=NOT RUN"
if defined metadata_check_ran set "metadata_status=PASS"
if defined metadata_check_ran set "result_metadata=PASS: size and last-modified time match for every file (compared %metadata_time_precision%)"
if defined metadata_check_ran if %hashed_count_destination% equ 0 set "result_metadata=PASS: no differences, but there were no files to compare"
if %metadata_differ_count% neq 0 set "metadata_status=FAIL"
if %metadata_differ_count% neq 0 set "result_metadata=FAIL: %metadata_differ_count% file(s) differ in size or last-modified time, or were not copied"
if %metadata_check_incomplete% neq 0 set "metadata_status=FAIL"
if %metadata_check_incomplete% neq 0 set "result_metadata=FAIL: the comparison was incomplete"
if not "%run_mode%"=="forensic" exit /b 0
rem Run records: NONE if the set has no earlier runs (a first copy); FAIL if
rem there are some but the check didn't run, or found any problem.
set "run_records_status=NONE"
set "result_run_records=NONE: no earlier runs found in the source"
if %history_row_count% gtr 0 if not defined run_records_checked set "run_records_status=FAIL" & set "result_run_records=FAIL: not checked (verification stopped before the run records check)"
if defined run_records_checked set "run_records_status=PASS" & set "result_run_records=PASS: %run_record_count% run record(s) match their seals and the history (%run_record_file_match_count% sealed file(s))"
if defined run_records_checked if %run_record_count% equ 0 if %run_record_problem_count% equ 0 set "run_records_status=NONE" & set "result_run_records=NONE: no earlier runs found in the source"
if %run_record_problem_count% neq 0 set "run_records_status=FAIL" & set "result_run_records=FAIL: %run_record_problem_count% problem(s) in the run records (see failures)"
exit /b 0

:report_unaccounted_rows
rem Caller's scope (:work_out_verification_status): not every row of the
rem reference record was matched or reported.
set "unaccounted_rows=1"
set "msg=[FAIL] The reference record lists %reference_row_count% file(s), but only %accounted_row_count% were matched or reported: the comparison can't be relied on."
call :remember_problem msg
exit /b 0

:report_nothing_to_verify
rem The reference record (or, in /nonforensic, the source) lists no files, so
rem nothing was verified: list that with the failures, as the reason the
rem Hash (SHA-256) check fails.
set "msg=[FAIL] Nothing was verified: the reference record lists no files."
if "%run_mode%"=="nonforensic" set "msg=[FAIL] Nothing was verified: the source holds no files."
call :remember_problem msg
exit /b 0

:add_failure_clause  asFirstClause  asLaterClause
rem Append one clause to result_meaning: the first clause starts the
rem sentence; later ones follow "; ".
if defined result_meaning (set "result_meaning=%result_meaning%; %~2") else set "result_meaning=%~1"
exit /b 0

rem -- Custody records --------------------------------------------------------

:choose_script_copy
rem Forensic run, before the copy. Decide once where the destination set's
rem file with this script's name (script_file_name) comes from. It arrives by
rem one route only, never copied and then overwritten (owner's rule):
rem   source       the source set's copy declares a newer version than this
rem                script: the custody pass carries it (:copy_custody_files)
rem   this_script  otherwise: this script is placed (:stage_script_copy) and
rem                the custody pass leaves the source set's copy out
rem   none         the destination set already holds the chosen file (same
rem                SHA-256), or a newer version than it: left as it is
rem An unreadable or non-semver version never counts as newer. Script copies
rem with other names are carried by the custody pass as they are.
set "script_copy_route=this_script"
set "script_copy_replaces="
set "chosen_copy_path=%script_path%"
set "chosen_copy_version=%TOOL_VERSION%"
set "result_script_copy=placed in the destination set directory as %script_file_name%"
set "source_copy_path="
set "source_copy_version="
if defined source_set_path set "source_copy_path=%source_set_with_backslash%%script_file_name%"
if defined source_copy_path if exist "%source_copy_path%" call :read_script_version source_copy_path source_copy_version
if defined source_copy_version call :version_is_newer source_copy_version TOOL_VERSION && (
    set "script_copy_route=source"
    set "chosen_copy_path=%source_copy_path%"
    set "chosen_copy_version=%source_copy_version%"
    set "result_script_copy=carried from the source set: its %script_file_name% (version %source_copy_version%) is newer than this script (version %TOOL_VERSION%)"
)
set "destination_copy_path=%destination_set_with_backslash%%script_file_name%"
if not exist "%destination_copy_path%" exit /b 0
set "destination_copy_version="
call :read_script_version destination_copy_path destination_copy_version
call :version_is_newer destination_copy_version chosen_copy_version && (
    set "script_copy_route=none"
    set "result_script_copy=not placed: the copy already beside the evidence is newer (version %destination_copy_version%), so it is left as it is"
    exit /b 0
)
call :files_have_same_sha256 chosen_copy_path destination_copy_path && (
    set "script_copy_route=none"
    set "result_script_copy=not needed: the destination set directory already holds this file as %script_file_name% (same SHA-256)"
    exit /b 0
)
if "%script_copy_route%"=="this_script" set "script_copy_replaces=1"
set "destination_copy_version_text=version unknown"
if defined destination_copy_version set "destination_copy_version_text=version %destination_copy_version%"
set "result_script_copy=%result_script_copy%, replacing the copy there (%destination_copy_version_text%, a different SHA-256)"
exit /b 0

:stage_script_copy
rem Forensic run, if :choose_script_copy chose this script: stage it for the
rem destination set directory and check the staged copy against the Script
rem SHA-256 in the header, which the sealed log records (:publish_records
rem puts it in place).
if not "%script_copy_route%"=="this_script" exit /b 0
set "script_copy_staged_path=%staged_root_dir%\%script_file_name%"
copy /b "%script_path%" "%script_copy_staged_path%" >nul 2>&1
set "script_copy_sha256="
if exist "%script_copy_staged_path%" call :get_sha256 script_copy_staged_path script_copy_sha256
if not defined script_copy_sha256 goto stage_script_copy_failed
if /i not "%script_copy_sha256%"=="%script_sha256%" goto stage_script_copy_failed
set "result_script_copy=%result_script_copy%; its SHA-256 matches the Script SHA-256 above"
exit /b 0
:stage_script_copy_failed
set "script_copy_replaces="
set "result_script_copy=FAILED: no verified copy of the script in the destination set directory"
set "msg=[WARN] Could not place a verified copy of the script in the destination set directory."
call :show_and_log msg
call :remember_problem msg
exit /b 0

:version_is_newer  versionVar  thanVar
rem Caller's scope. Exit 0 only if versionVar holds a MAJOR.MINOR.PATCH
rem version newer than the one in thanVar; an unreadable or non-semver
rem version on either side doesn't count as newer.
call :parse_version %~1 candidate_version || exit /b 1
call :parse_version %~2 baseline_version || exit /b 1
call :compare_versions baseline_version candidate_version candidate_version_order
if "%candidate_version_order%"=="older" exit /b 0
exit /b 1

:files_have_same_sha256  firstPathVar  secondPathVar
rem Exit 0 if both files can be hashed and have the same SHA-256.
setlocal
set "first_sha256="
set "second_sha256="
call :get_sha256 %~1 first_sha256
call :get_sha256 %~2 second_sha256
if not defined first_sha256 (endlocal & exit /b 1)
if /i "%first_sha256%"=="%second_sha256%" (endlocal & exit /b 0)
endlocal & exit /b 1

:read_script_version  fileVar  outVar
rem The version a copy of this script declares: its TOOL_VERSION line (2.x),
rem or SCRIPT_VERSION (1.x). The file is only read, never run. Clears outVar
rem if neither is found.
setlocal EnableDelayedExpansion
set "file=!%~1!"
set "version="
for %%N in (TOOL_VERSION SCRIPT_VERSION) do if not defined version (
    for /f "tokens=2 delims==" %%V in ('findstr /b /r /c:"set .%%N=" "!file!" 2^>nul') do if not defined version set "version=%%V"
)
if defined version set "version=!version:"=!"
endlocal & set "%~2=%version%"
exit /b 0

:write_history
rem Forensic run. This run's history, sealed in its run record: the history
rem it continues, unchanged, with this run's row added; or, if it continues
rem none, the header and this run's row. The new row's Seal SHA-256 is
rem pending_seal_text ("see <its seal file>"): the next run fills it in.
set "history_continues="
if defined history_base_path if exist "%history_base_path%" set "history_continues=1"
if defined history_continues copy /b "%history_base_path%" "%staged_history_path%" >nul 2>&1
if not defined history_continues call :append_line_to_file HISTORY_HEADER staged_history_path
set "history_source_set=%source_path%"
if defined source_set_path set "history_source_set=%source_set_path%"
call :append_history_row
exit /b 0

:append_history_row
rem (:write_history) Append this run's row to staged_history_path.
setlocal EnableDelayedExpansion
rem Cells never contain '"' or "|" (the history's parser relies on it):
rem any in a value (e.g. a localised volume line) become "'" and "/".
for %%V in (history_source_set source_volume_serial source_volume_label_and_filesystem destination_set_path destination_volume_serial destination_volume_label_and_filesystem header_host header_user) do (
    set "cell=!%%V!"
    if defined cell set "cell=!cell:"='!"
    if defined cell set "cell=!cell:|=/!"
    set "clean_%%V=!cell!"
)
set "row="!run_utc_stamp!","!verdict!","!clean_history_source_set!","!clean_source_volume_serial!","!clean_source_volume_label_and_filesystem!","!clean_destination_set_path!","!clean_destination_volume_serial!","!clean_destination_volume_label_and_filesystem!","!match_count!","!clean_header_host!","!clean_header_user!","!TOOL_NAME! !TOOL_VERSION!","!pending_seal_text!""
>>"!staged_history_path!" echo(!row!
endlocal & exit /b 0

:write_seal
rem Forensic run. Seal this run's record: write the SHA-256 of the log,
rem hash CSVs and history to <stem>.sha256 beside them in the run record
rem (staged), then show the seal's own SHA-256 for the user's
rem chain-of-custody notes. With that value recorded elsewhere, any later
rem change to the record can be detected. A script copy isn't listed: the
rem sealed log records the script's SHA-256, which the copy was checked
rem against. Sets run_seal_sha256, and seal_incomplete=1 if any record file
rem or the seal itself couldn't be hashed: :publish_records then writes
rem nothing and the run fails (owner, 2026-10-16), since a run record whose
rem seal doesn't cover it would fail every later copy.
setlocal EnableDelayedExpansion
set "sealed_count=0"
set "seal_expected_count=0"
for %%F in (log_staged_path staged_hash_csv_source staged_hash_csv_destination staged_hash_csv_custody staged_history_path staged_outside_history_path) do (
    if defined %%F if exist "!%%F!" (
        set /a "seal_expected_count+=1"
        set "record_path=!%%F!"
        set "record_sha256="
        call :get_sha256 record_path record_sha256
        for %%N in ("!record_path!") do set "record_name=%%~nxN"
        if defined record_sha256 (
            >>"!staged_seal_path!" echo(!record_sha256! *!record_name!
            set /a "sealed_count+=1"
        ) else (
            echo [FAIL] Could not hash !record_name! for the seal.
        )
    )
)
set "incomplete="
if !sealed_count! neq !seal_expected_count! set "incomplete=1"
if !sealed_count! equ 0 (endlocal & set "seal_incomplete=1" & exit /b 0)
set "seal_sha256="
call :get_sha256 staged_seal_path seal_sha256
if not defined seal_sha256 set "incomplete=1"
echo.
echo Run record sealed in: !seal_file_name!
if defined seal_sha256 (
    echo   SHA-256: !seal_sha256!
    echo Record this value in your chain-of-custody notes: it shows whether this
    echo run's record is later changed.
) else (
    echo [FAIL] Could not hash the seal file.
)
endlocal & set "run_seal_sha256=%seal_sha256%" & set "seal_incomplete=%incomplete%"
exit /b 0

:publish_records
rem Forensic run. Put this run's staged files into the destination with
rem robocopy /j, so they go straight to the drive: the run record into
rem <run UTC>.partial, read back and only then renamed to <run UTC>, so an
rem interrupted write-back is never mistaken for a run record; then a script
rem copy into the destination set directory; then the history beside the
rem evidence: this run's, with every row's seal filled in, if the run record
rem is in place, otherwise the history this run continued, so the
rem destination's history still matches its run records. Nothing is
rem overwritten (/xc /xn /xo) except that history and a script copy this
rem run replaces (:choose_script_copy). Each file is read back and compared with
rem its staged original by SHA-256. Only if all match and the run record is
rem in place is the staging directory removed; otherwise it is kept and its
rem path shown, so no record is lost, and the exit code becomes FAIL.
if not defined staging_dir exit /b 0
call :is_directory staging_dir || exit /b 0
if defined seal_incomplete goto publish_records_seal_incomplete
setlocal
set "record_count=0"
set "records_matching=0"
set "records_robocopy_exit_codes=0"
set "run_record_in_place="
call :publish_staged_directory records
if %records_matching% equ %record_count% if %record_count% gtr 0 ren "%destination_partial_run_dir%" "%run_utc_stamp%" >nul 2>&1 && set "run_record_in_place=1"
if %record_count% gtr 0 if not defined run_record_in_place call :report_run_record_not_completed
call :publish_staged_directory root
if defined run_record_in_place if defined run_seal_sha256 call :publish_root_history new
if not defined run_record_in_place if defined history_base_path call :publish_root_history continued
if %record_count% equ 0 goto publish_records_done
if not %records_matching% equ %record_count% goto publish_records_failed
if not defined run_record_in_place goto publish_records_failed
echo.
set "msg=Custody files written to the destination and read back: %records_matching% of %record_count% match."
call :show msg
if defined log_ready (
    set "msg=Log saved: %log_destination_path%"
    call :show msg
)
del /f /q "%staged_records_dir%\*" >nul 2>&1
del /f /q "%staged_root_dir%\*" >nul 2>&1
:publish_records_done
rd "%staged_records_dir%" >nul 2>&1
rd "%staged_root_dir%" >nul 2>&1
rd "%staging_dir%" >nul 2>&1
endlocal & exit /b 0
:publish_records_failed
echo.
set "msg=[WARN] Only %records_matching% of %record_count% custody files reached the destination intact (robocopy exit codes combined: %records_robocopy_exit_codes%). All of them are kept here:"
call :show msg
set "msg=       %staging_dir%"
call :show msg
set "msg=[FAIL] This run's record wasn't completed in the destination. The log and summary were sealed before the write-back; because the record is missing, the exit code is FAIL (%EXIT_CODE_FAIL%)."
call :show msg
endlocal & set "exit_code=%EXIT_CODE_FAIL%" & exit /b 1

:report_run_record_not_completed
rem Caller's scope (:publish_records): the run record couldn't be put in
rem place. Say what the destination holds of it: a .partial directory,
rem nothing at all, or, if the destination can't be reached (e.g. the drive
rem was removed), that this can't be told.
set "msg=[WARN] The run record could not be written to the destination (nothing of it is there) and is not added to the history."
call :is_directory destination_set_with_backslash || set "msg=[WARN] The run record could not be written: the destination set directory can't be reached, so whether any of the run record is there can't be told. It is not added to the history; a later copy warns about any %run_utc_stamp%%PARTIAL_RUN_SUFFIX% left there."
call :is_directory destination_partial_run_dir && set "msg=[WARN] The run record was not completed in the destination: it is left as %run_utc_stamp%%PARTIAL_RUN_SUFFIX% and is not added to the history."
call :show msg
exit /b 0

:publish_records_seal_incomplete
rem The seal doesn't cover the whole run record (:write_seal): none of this
rem run's record is written to the destination, the staging directory is
rem kept, and the run fails. As when the write-back fails, the history this
rem run continued is written beside the evidence, unchanged, so it matches the
rem run records the custody pass copied there (owner, 2026-10-16, after test
rem round 7: without it, the next copy failed for a missing history).
setlocal
set "record_count=0"
set "records_matching=0"
set "records_robocopy_exit_codes=0"
set "continued_history_text="
if defined history_base_path call :publish_root_history continued
if defined history_base_path set "continued_history_text= The history this run continued was written beside the evidence, unchanged."
if defined history_base_path if not %records_matching% equ %record_count% set "continued_history_text= The history this run continued couldn't be written beside the evidence intact (see above)."
echo.
set "msg=[FAIL] This run's record couldn't be sealed completely, so none of it was written to the destination.%continued_history_text% The log and summary were written before the seal; the exit code is FAIL (%EXIT_CODE_FAIL%). Everything is kept here:"
call :show msg
set "msg=       %staging_dir%"
call :show msg
endlocal & set "exit_code=%EXIT_CODE_FAIL%" & exit /b 1

:publish_staged_directory  where
rem Caller's scope (:publish_records). where: records (staged_records_dir to
rem this run's <run UTC>.partial directory) or root (staged_root_dir to the
rem destination set directory; the history is published separately). Nothing
rem is overwritten, except a script copy this run replaces
rem (:choose_script_copy).
rem Copies the staged files, then checks each one in the destination.
if "%~1"=="records" (set "publish_from=%staged_records_dir%") else set "publish_from=%staged_root_dir%"
if "%~1"=="records" (set "publish_to=%destination_partial_run_dir%") else set "publish_to=%destination_set_path%"
if "%~1"=="records" (set "publish_to_with_backslash=%destination_partial_run_dir%\") else set "publish_to_with_backslash=%destination_set_with_backslash%"
set "publish_count=0"
for /f "eol=/ delims=" %%F in ('dir /b /a-d "%publish_from%\" 2^>nul') do if /i not "%%F"=="%HISTORY_FILE_NAME%" set /a "publish_count+=1"
if %publish_count% equ 0 exit /b 0
set /a "record_count+=publish_count"
set "publish_overwrite_flags=/xc /xn /xo"
if "%~1"=="root" if defined script_copy_replaces set "publish_overwrite_flags=/is /it"
robocopy "%publish_from% " "%publish_to% " *.* /xf "%HISTORY_FILE_NAME%" /j %publish_overwrite_flags% /r:%RETRY_COUNT% /w:%RETRY_WAIT_SECONDS% /njh /njs /ndl /nfl /np >nul 2>&1
set /a "records_robocopy_exit_codes|=%errorlevel%"
for /f "eol=/ delims=" %%F in ('dir /b /a-d "%publish_from%\" 2^>nul') do if /i not "%%F"=="%HISTORY_FILE_NAME%" (
    set "record_name=%%F"
    call :check_record_in_destination record_name publish_from publish_to_with_backslash
)
exit /b 0

:publish_root_history  which
rem Caller's scope (:publish_records). The history beside the evidence: with
rem which=new, this run's sealed history with its own seal filled in, so
rem every row is complete; with which=continued (this run's record couldn't
rem be completed), the history this run continued, unchanged, so the
rem destination's history still matches the run records copied there. A
rem quick overview, never relied on: each run checks it against the sealed
rem run records. It replaces the one already there (/is /it).
if "%~1"=="new" call :write_history_with_seal staged_history_path pending_seal_text run_seal_sha256 staged_root_history_path
if "%~1"=="continued" copy /b "%history_base_path%" "%staged_root_history_path%" >nul 2>&1
set /a "record_count+=1"
robocopy "%staged_root_dir% " "%destination_set_path% " "%HISTORY_FILE_NAME%" /is /it /j /r:%RETRY_COUNT% /w:%RETRY_WAIT_SECONDS% /njh /njs /ndl /nfl /np >nul 2>&1
set /a "records_robocopy_exit_codes|=%errorlevel%"
set "record_name=%HISTORY_FILE_NAME%"
set "publish_from=%staged_root_dir%"
set "publish_to_with_backslash=%destination_set_with_backslash%"
call :check_record_in_destination record_name publish_from publish_to_with_backslash
exit /b 0

:check_record_in_destination  nameVar  stagedDirVar  destinationPrefixVar
rem One staged file: add 1 to records_matching if the destination holds it
rem with the same SHA-256, else say so.
setlocal EnableDelayedExpansion
set "staged_path=!%~2!\!%~1!"
set "destination_copy_path=!%~3!!%~1!"
set "staged_sha256="
set "destination_sha256="
call :get_sha256 staged_path staged_sha256
if exist "!destination_copy_path!" call :get_sha256 destination_copy_path destination_sha256
if defined staged_sha256 if /i "!staged_sha256!"=="!destination_sha256!" (endlocal & set /a "records_matching+=1" & exit /b 0)
set "msg=[WARN] Not in the destination, or it differs from the staged record: !%~1!"
call :is_directory destination_set_with_backslash || set "msg=[WARN] Couldn't be read back (the destination set directory can't be reached): !%~1!"
call :show msg
endlocal & exit /b 0

rem -- Copy helpers -----------------------------------------------------------

:add_housekeeping_exclusions  side
rem Add the full paths of the housekeeping items found at the side's drive
rem root (temp_housekeeping_<side>) to excluded_dirs and excluded_files (see
rem :build_exclusion_args). Caller's scope; the caller must have delayed
rem expansion enabled. A name containing "!" can't be passed this way: that
rem item is then copied, never dropped.
set "housekeeping_exclusion_list=!temp_housekeeping_%~1!"
if not defined housekeeping_exclusion_list exit /b 0
if not exist "!housekeeping_exclusion_list!" exit /b 0
for /f "usebackq tokens=1* delims=:" %%A in ("!housekeeping_exclusion_list!") do (
    if "%%A"=="D" set "excluded_dirs=!excluded_dirs! "!%~1_with_backslash!%%~B""
    if "%%A"=="F" set "excluded_files=!excluded_files! "!%~1_with_backslash!%%~B""
)
exit /b 0

:build_exclusion_args
rem Set exclusion_args to one /xd and one /xf with everything collected in
rem excluded_dirs and excluded_files. Caller's scope, delayed expansion on.
set "exclusion_args="
if defined excluded_dirs set "exclusion_args=/xd!excluded_dirs!"
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

:save_robocopy_unicode_output  outFileVar  mode
rem Robocopy writes its own console and /log output in the system's OEM code
rem page, whatever the console's (test 18: "u-umlaut" came out as one OEM
rem byte inside the UTF-8 log, and a listing read under code page 65001
rem turned it into U+FFFD, so no destination path matched). So every
rem robocopy output the script keeps or reads is written as UTF-16 (/unilog)
rem to temp_robocopy_unicode_output and converted here by TYPE, which writes
rem it in the console's code page: UTF-8 during a run. Robocopy also ends
rem its ERROR message lines with CR CR LF, so each line is rewritten with one
rem trailing CR removed and the records keep CRLF line endings (test runner
rem round 2, P1: otherwise byte-identical to TYPE's output, including empty
rem lines, tabs, leading ";" or ":", and ! % ^ &). Delayed expansion is on
rem per line only, so "!" in the text survives. mode: new (replace the out
rem file) or append.
setlocal DisableDelayedExpansion
call :copy_variable %~1 robocopy_output_file
if not "%~2"=="append" type nul >"%robocopy_output_file%" 2>nul
(for /f "delims=" %%L in ('type "%temp_robocopy_unicode_output%" 2^>nul ^| findstr /n "^"') do (
    set "robocopy_output_line=%%L"
    setlocal EnableDelayedExpansion
    set "robocopy_output_line=!robocopy_output_line:*:=!"
    if defined robocopy_output_line if "!robocopy_output_line:~-1!"=="!carriage_return!" set "robocopy_output_line=!robocopy_output_line:~0,-1!"
    echo(!robocopy_output_line!
    endlocal
)) >>"%robocopy_output_file%"
del "%temp_robocopy_unicode_output%" >nul 2>&1
endlocal & exit /b 0

:check_script_path
rem The script's own path goes on child command lines too (e.g.
rem :read_carriage_return), so it may not contain "%" either (see
rem :path_has_percent).
call :path_has_percent script_path || exit /b 0
set "abort_reason=The script's own path contains %%, which can't be handled safely yet: move or rename it."
exit /b 1

:read_carriage_return
rem Set carriage_return to the CR character, for :save_robocopy_unicode_output
rem (COPY /Z prints its progress with a CR; the standard pure-batch way).
set "carriage_return="
for /f %%C in ('copy /z "%script_path%" nul') do set "carriage_return=%%C"
exit /b 0

:report_robocopy_exit_code  exitCodeVar  [custody]
rem Explain each bit set in a robocopy exit code (see ROBOCOPY_EXIT_* in
rem CONFIG); anything but INFO is listed in the summary (:remember_problem).
rem With "custody" (a custody pass), extras (bit 2) are expected on a rerun
rem or update: the destination set holds its own run records and history,
rem which the source set doesn't; the Run records check verifies them all,
rem so they are reported as INFO.
setlocal EnableDelayedExpansion
set /a "robocopy_exit_code=!%~1!"
set "msg=Robocopy exit code: !robocopy_exit_code!" & call :show_and_log msg
if !robocopy_exit_code! equ 0 (
    set "msg=  [INFO] No files were copied in this pass."
    call :show_and_log msg
)
for %%B in (%ROBOCOPY_EXIT_BITS%) do (
    set /a "bit_value=robocopy_exit_code & %%B"
    set "severity=!ROBOCOPY_EXIT_%%B_SEVERITY!"
    set "text=!ROBOCOPY_EXIT_%%B_TEXT!"
    if "%~2"=="custody" if %%B equ 2 (
        set "severity=INFO"
        set "text=Items in the destination set that the source set doesn't hold, left as they are (such as its own run records and history, or files at a drive root): run records among them are checked by the Run records check below."
    )
    if !bit_value! neq 0 (
        set "msg=  [!severity!] !text!"
        call :show_and_log msg
        if not "!severity!"=="INFO" call :remember_problem msg
    )
)
endlocal & exit /b 0

rem -- Input ------------------------------------------------------------------

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
    set "abort_reason=No valid directory after %MAX_PROMPT_ATTEMPTS% attempts (no console input?)."
    exit /b 1
)
set "normalise_path_input="
set "default_source_taken="
if "%~4"=="1" if defined default_source_path (
    set "msg=Default (the script's directory): %default_source_path%"
    call :show msg
)
set /p "normalise_path_input=%~2: "
if not defined normalise_path_input if "%~4"=="1" if defined default_source_path (
    set "normalise_path_input=%default_source_path%"
    set "default_source_taken=1"
)
call :normalise_path
if errorlevel 1 goto ask_directory_loop
call :path_has_percent normalise_path_result && (
    echo Paths containing %% can't be handled safely yet: rename the directory or choose another.
    goto ask_directory_loop
)
set "answer_is_directory="
call :is_directory normalise_path_result && set "answer_is_directory=1"
if exist "%normalise_path_result%" if not defined answer_is_directory (
    echo That is a file, not a directory.
    goto ask_directory_loop
)
if "%~3"=="1" if not defined answer_is_directory (
    echo Directory not found.
    if defined is_elevated if "%normalise_path_result:~1,1%"==":" if not exist "%normalise_path_result:~0,2%\" (
        echo As administrator, drive letters mapped in your normal session are not
        echo visible. For a network share, enter its UNC path: \\server\share\...
    )
    goto ask_directory_loop
)
set "%~1_path=%normalise_path_result%"
set "%~1_with_backslash=%normalise_path_with_backslash%"
exit /b 0

:count_rejected_answer  counterVar  what
rem Count an answer that :ask_directory accepted but the caller then rejected
rem (a set rule, or source and destination overlapping). Exit 1 (with
rem abort_reason) after MAX_PROMPT_ATTEMPTS of them: :ask_directory's own count
rem starts again on every call, and with S1 an empty answer takes the default
rem each time, so a closed or redirected console would otherwise loop forever
rem (test round 7).
set /a "%~1+=1"
setlocal EnableDelayedExpansion
if !%~1! lss %MAX_PROMPT_ATTEMPTS% (endlocal & exit /b 0)
endlocal
set "abort_reason=No usable %~2 after %MAX_PROMPT_ATTEMPTS% attempts (no console input?)."
exit /b 1

:path_has_percent  pathVar
rem Exit 0 if the path contains "%". Many FOR /F commands put directory paths
rem on a child command line, where %NAME% would be expanded, so such paths
rem are refused at the prompt for now (owner, 2026-10-16). Evidence file
rem names inside the directories are safe: hashing doesn't use a child
rem command line (:get_sha256).
setlocal EnableDelayedExpansion
set "path_to_check=!%~1!"
if "!path_to_check:%%=!"=="!path_to_check!" (endlocal & exit /b 1)
endlocal & exit /b 0

:normalise_path
rem Caller's scope, fixed names: IN normalise_path_input. OUT
rem normalise_path_result (full path, no trailing backslash unless a drive
rem root) and normalise_path_with_backslash (the same with exactly one
rem trailing backslash). Exit 1 if empty or not a full path: relative paths
rem would resolve against the current directory, which is System32 when run
rem as administrator. Accepts quotes, forward slashes, "E:" for a drive root,
rem and any number of trailing backslashes, so every way of typing a directory
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
rem Exit 0 if two directories are the same or one is inside the other
rem (case-insensitive). IN overlap_first_with_backslash and
rem overlap_second_with_backslash. A mapped drive and its UNC path are not
rem recognised as the same place.
setlocal EnableDelayedExpansion
call :strlen overlap_first_with_backslash first_length
call :strlen overlap_second_with_backslash second_length
set "overlap_exit_code=1"
if !first_length! leq !second_length! (
    for %%N in (!first_length!) do if /i "!overlap_second_with_backslash:~0,%%N!"=="!overlap_first_with_backslash!" set "overlap_exit_code=0"
) else (
    for %%N in (!second_length!) do if /i "!overlap_first_with_backslash:~0,%%N!"=="!overlap_second_with_backslash!" set "overlap_exit_code=0"
)
endlocal & exit /b %overlap_exit_code%

rem -- Time -------------------------------------------------------------------

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

rem -- General ----------------------------------------------------------------

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
set "padded_label=%~1                      "
set "msg=  !padded_label:~0,20!: !%~2!"
call :show_and_log msg
endlocal & exit /b 0

:log_field_continued  valueVar
rem Show and log a continuation line, aligned with the values of :log_field.
setlocal EnableDelayedExpansion
set "msg=                        !%~1!"
call :show_and_log msg
endlocal & exit /b 0

:log_result_line  label  valueVar
rem Show and log "  label   : value" for the overall result, whose value sits
rem four columns right of :log_field's to line up with :log_check_line.
setlocal EnableDelayedExpansion
set "padded_label=%~1                           "
set "msg=  !padded_label:~0,24!: !%~2!"
call :show_and_log msg
endlocal & exit /b 0

:log_check_line  label  valueVar  [detailVar]
rem Show and log one check under the overall result as
rem "    |-label : value", and detailVar (if given and set) on the next line,
rem aligned with the value.
setlocal EnableDelayedExpansion
set "padded_label=%~1                           "
set "msg=    |-!padded_label:~0,20!: !%~2!"
call :show_and_log msg
if "%~3"=="" (endlocal & exit /b 0)
if not defined %~3 (endlocal & exit /b 0)
set "msg=                            !%~3!"
call :show_and_log msg
endlocal & exit /b 0

:remember_problem  msgVar
rem Remember a [FAIL] or [WARN] line for the summary: [FAIL] lines (anything
rem that fails the run) go to the failures listed below the result, all others
rem to the warnings listed above it. Leading spaces are dropped.
setlocal EnableDelayedExpansion
set "line=!%~1!"
:remember_problem_trim
if "!line:~0,1!"==" " (
    set "line=!line:~1!"
    goto remember_problem_trim
)
if "!line:[FAIL]=!"=="!line!" (
    >>"!temp_summary_warnings!" echo(!line!
) else (
    >>"!temp_summary_failures!" echo(!line!
)
endlocal & exit /b 0

:log_summary_list  title  kind
rem Show and log a titled list for the summary, one item per line, or
rem "none". kind is "warnings" or "failures".
setlocal DisableDelayedExpansion
if "%~2"=="failures" (set "list_path=%temp_summary_failures%") else set "list_path=%temp_summary_warnings%"
set "msg=  %~1"
call :show_and_log msg
set "item_count=0"
if exist "%list_path%" for /f "usebackq delims=" %%L in ("%list_path%") do (
    set "msg=    %%L"
    call :show_and_log msg
    set /a "item_count+=1"
)
if %item_count% equ 0 (
    set "msg=    none"
    call :show_and_log msg
)
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

:is_directory  pathVar
rem Exit 0 if the path (with or without a trailing backslash) is an existing
rem directory. Every directory test goes through here: IF EXIST "<path>\"
rem alone is also true for a file on a network path (UNC or a mapped drive;
rem test round 7). So where the path's attributes can be read they must include
rem d; where none can be read (e.g. a share's root), IF EXIST decides.
setlocal EnableDelayedExpansion
set "directory_to_test=!%~1!"
if not defined directory_to_test (endlocal & exit /b 1)
if "!directory_to_test:~-1!"=="\" set "directory_to_test=!directory_to_test:~0,-1!"
if not exist "!directory_to_test!\" (endlocal & exit /b 1)
set "directory_attributes="
for %%A in ("!directory_to_test!") do set "directory_attributes=%%~aA"
if not defined directory_attributes (endlocal & exit /b 0)
if "!directory_attributes:~0,1!"=="d" (endlocal & exit /b 0)
endlocal & exit /b 1

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
for %%T in (temp_file_list temp_metadata_list temp_robocopy_unicode_output temp_certutil_output temp_hash_rows_source temp_hash_rows_destination temp_hash_rows_custody temp_custody_list temp_compare_lines temp_compare_lines_sorted temp_summary_warnings temp_summary_failures temp_warnings temp_clock_status temp_housekeeping_source temp_housekeeping_destination temp_history_runs temp_history_lines temp_history_filled temp_outside_history temp_partial_warned temp_predating_records temp_sealed_history_source temp_sealed_history_destination plain_hash_csv_source plain_hash_csv_destination) do (
    if defined %%T if exist "!%%T!" del /f /q "!%%T!" >nul 2>&1
)
rem The staging directories go only if empty: if they still hold records,
rem :publish_records has said where they are.
if defined staging_dir (
    rd "!staged_records_dir!" >nul 2>&1
    rd "!staged_root_dir!" >nul 2>&1
    rd "!staging_dir!" >nul 2>&1
)
endlocal & exit /b 0

:abort
rem Stop before anything is copied. No run record is written: an aborted run
rem leaves nothing in the destination. Its log, if one was started, stays in
rem TEMP and its path is shown.
echo.
echo [FAIL] %abort_reason%
if defined log_ready (
    set "msg=[FAIL] Run aborted: %abort_reason%"
    call :show_and_log msg
    set "msg=The log of this aborted run is kept here: %log_staged_path%"
    call :show msg
)
call :cleanup_temp
call :restore_console_code_page
pause
exit /b %EXIT_CODE_FAIL%
