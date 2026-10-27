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
rem          EVIDENCE_ROBOCOPY_PLAIN=1   plain console output instead of the
rem                                      live display; NO_COLOR=1 no colour
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
set "TOOL_VERSION=2.8.2"

rem Robocopy retries for each file that fails (count, seconds between tries).
rem Fail fast on purpose: one short retry covers transient faults (network
rem blip, AV holding a file), while a real problem fails within seconds per
rem file instead of retrying for hours and looking like progress.
set "RETRY_COUNT=1"
set "RETRY_WAIT_SECONDS=2"

rem certutil can fail to read a file once (seen once in about 180,000 hashes,
rem with real-time antivirus scanning on; workshop, 2026-10-18): a file it
rem can't read is hashed again after this many seconds before it is recorded
rem UNREADABLE, and the retry is noted in the log. A file that fails twice is
rem UNREADABLE (:get_sha256).
set "HASH_RETRY_WAIT_SECONDS=2"

rem The longest full path (drive letter to file name, as the source or the
rem destination lists it) of a file this script hashes and compares. A
rem longer one is refused by name: robocopy copies it, the run fails. cmd
rem sets the ceiling (round 12.7): it skips a FOR /F iteration whose
rem expanded command would pass 8,191 characters without a word (a path of
rem 8,200 characters was left out of both hash records and the run PASSed),
rem a percent-expanded line that long ends the script, and sort writes
rem nothing for a record of 4,096 characters or more (its default). 4,000
rem keeps every line a path goes on well inside those limits, and no
rem mainstream system makes such paths (Linux stops at 4,096 bytes, macOS at
rem 1,024).
set "MAX_FILE_PATH_LENGTH=4000"
rem How much of a refused path its failure line shows: the whole can't
rem always be read (above), and the output wrapper spends about 10 ms per
rem character of an unbreakable word.
set "PATH_EXCERPT_LENGTH=200"

rem Microsoft Defender's real-time protection, read only for a warning,
rem given only when it is known to be on (owner, 2026-10-20;
rem :check_realtime_scanning; best efforts; owner: "if real time protection
rem is occurring, we want to know"). Taken as on when its engine runs (the
rem service DEFENDER_SERVICE in sc's state 4, a number in any language, or
rem else the process DEFENDER_ENGINE_PROCESS in tasklist's list: the signal
rem AveYo's ToggleDefender uses), unless a row of DEFENDER_OFF_VALUES reads
rem 0x1. The rows are the settings that turn it off (AveYo's
rem ToggleDefender sets DisableAntiSpyware, DisableAntiVirus and
rem PassiveMode; the registry and Group Policy methods
rem DisableRealtimeMonitoring and DisableOnAccessProtection). With Tamper
rem Protection on, Defender ignores the Policies keys, so a policy row
rem counts only when DEFENDER_TAMPER_VALUE in DEFENDER_TAMPER_KEY reads one
rem of DEFENDER_TAMPER_OFF_DATA (4: off; 5: on). Fields:
rem   DEFENDER_OFF_<row>_KEY     the registry key
rem   DEFENDER_OFF_<row>_VALUE   the value that turns protection off at 0x1
rem   DEFENDER_OFF_<row>_POLICY  yes for a Policies key
rem A value that can't be read turns nothing off: the engine running with
rem nothing readable saying it's off gives the warning.
set "DEFENDER_SERVICE=WinDefend"
set "DEFENDER_ENGINE_PROCESS=MsMpEng.exe"
set "DEFENDER_TAMPER_KEY=HKLM\SOFTWARE\Microsoft\Windows Defender\Features"
set "DEFENDER_TAMPER_VALUE=TamperProtection"
set "DEFENDER_TAMPER_OFF_DATA=0x4 0x0"
set "DEFENDER_OFF_VALUES=realtime realtime_policy realtime_policy_root on_access_policy antivirus antivirus_policy antispyware antispyware_policy passive passive_policy"
set "DEFENDER_OFF_realtime_KEY=HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"
set "DEFENDER_OFF_realtime_POLICY=no"
set "DEFENDER_OFF_realtime_VALUE=DisableRealtimeMonitoring"
set "DEFENDER_OFF_realtime_policy_KEY=HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
set "DEFENDER_OFF_realtime_policy_POLICY=yes"
set "DEFENDER_OFF_realtime_policy_VALUE=DisableRealtimeMonitoring"
set "DEFENDER_OFF_realtime_policy_root_KEY=HKLM\SOFTWARE\Policies\Microsoft\Windows Defender"
set "DEFENDER_OFF_realtime_policy_root_POLICY=yes"
set "DEFENDER_OFF_realtime_policy_root_VALUE=DisableRealtimeMonitoring"
set "DEFENDER_OFF_on_access_policy_KEY=HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
set "DEFENDER_OFF_on_access_policy_POLICY=yes"
set "DEFENDER_OFF_on_access_policy_VALUE=DisableOnAccessProtection"
set "DEFENDER_OFF_antivirus_KEY=HKLM\SOFTWARE\Microsoft\Windows Defender"
set "DEFENDER_OFF_antivirus_POLICY=no"
set "DEFENDER_OFF_antivirus_VALUE=DisableAntiVirus"
set "DEFENDER_OFF_antivirus_policy_KEY=HKLM\SOFTWARE\Policies\Microsoft\Windows Defender"
set "DEFENDER_OFF_antivirus_policy_POLICY=yes"
set "DEFENDER_OFF_antivirus_policy_VALUE=DisableAntiVirus"
set "DEFENDER_OFF_antispyware_KEY=HKLM\SOFTWARE\Microsoft\Windows Defender"
set "DEFENDER_OFF_antispyware_POLICY=no"
set "DEFENDER_OFF_antispyware_VALUE=DisableAntiSpyware"
set "DEFENDER_OFF_antispyware_policy_KEY=HKLM\SOFTWARE\Policies\Microsoft\Windows Defender"
set "DEFENDER_OFF_antispyware_policy_POLICY=yes"
set "DEFENDER_OFF_antispyware_policy_VALUE=DisableAntiSpyware"
set "DEFENDER_OFF_passive_KEY=HKLM\SOFTWARE\Microsoft\Windows Defender"
set "DEFENDER_OFF_passive_POLICY=no"
set "DEFENDER_OFF_passive_VALUE=PassiveMode"
set "DEFENDER_OFF_passive_policy_KEY=HKLM\SOFTWARE\Policies\Microsoft\Windows Defender"
set "DEFENDER_OFF_passive_policy_POLICY=yes"
set "DEFENDER_OFF_passive_policy_VALUE=PassiveMode"

rem The update check (:check_latest_release; owner, 2026-10-20): every run
rem asks GitHub, once, which release of this script is the latest, with
rem curl.exe (built into Windows since 10 1803): a header-only request to
rem UPDATE_LATEST_URL, answered with a redirect to .../tag/v<version>. A
rem newer release is a warning; the check never updates anything. /update
rem (:prepare_update) downloads UPDATE_ASSET_NAME and its SHA-256 file
rem UPDATE_HASH_ASSET_NAME from UPDATE_DOWNLOAD_URL/<tag>/ and replaces this
rem file with the download once it is checked. Best efforts: no answer
rem within UPDATE_CHECK_MAX_SECONDS, or any failure, is a warning and the
rem run goes on; no proxy handling.
set "UPDATE_LATEST_URL=https://github.com/rbqbjyur/evidence-robocopy/releases/latest"
set "UPDATE_DOWNLOAD_URL=https://github.com/rbqbjyur/evidence-robocopy/releases/download"
set "UPDATE_ASSET_NAME=evidence-robocopy.bat"
set "UPDATE_HASH_ASSET_NAME=evidence-robocopy.bat.sha256"
set "UPDATE_CHECK_MAX_SECONDS=3"
set "UPDATE_DOWNLOAD_MAX_SECONDS=60"
rem The update check runs in the background while the prompts are answered
rem (2.8.0; :start_latest_release_check): how long the run waits for its
rem answer when the header is written, if it isn't in yet (curl itself gives
rem up after UPDATE_CHECK_MAX_SECONDS).
set "UPDATE_CHECK_WAIT_SECONDS=5"

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
rem   PASS_<id>_PROGRESS the live display's copy bar: by bytes (each file's
rem                      size from the listing made before the pass, in MB;
rem                      for a pass of few, large files) or by files
rem   PASS_<id>_PERCENTAGES  yes: while the live display is on, the pass runs
rem                      without /np, so robocopy's percentage within each
rem                      file is shown live; those percentages are left out
rem                      of the log (:save_robocopy_unicode_output), which
rem                      then reads as with /np. no: /np as always.
rem Every pass uses /j (unbuffered I/O): file contents don't pass through
rem Windows' file cache, so verification can't be served from it, unless
rem the pass runs in backup mode (/b, every elevated run), which leaves
rem the written files in that cache whatever /j says (round 15.1: the
rem destination hash read 384 MiB from it in 0.6 s, 16 s from the
rem medium); the header's Writes field says which (:check_write_mode).
rem The run record's own write-back (:publish_records) copies with /j and
rem never /b. What the drive's own cache does is another matter (README,
rem "What it does not do"). A pass without /j is named in a warning
rem (:check_write_mode). Before the passes, each pass's files are listed
rem (:count_copy_pass_files); a pass with no file in its class is skipped,
rem except the last pass, which always runs so that robocopy creates the
rem directories (/e) whatever the passes hold.
set "COPY_PASSES=large small"
set "PASS_large_LABEL=Large files (%LARGE_FILE_MIB% MiB and over)"
set "PASS_large_FILTER=/min:%LARGE_FILE_BYTES%"
set "PASS_large_THREADS=1"
set "PASS_large_FLAGS=/j"
set "PASS_large_PROGRESS=bytes"
set "PASS_large_PERCENTAGES=yes"
set "PASS_small_LABEL=Small files (under %LARGE_FILE_MIB% MiB)"
set "PASS_small_FILTER=/max:%SMALL_FILE_MAX_BYTES%"
set "PASS_small_THREADS=auto"
set "PASS_small_FLAGS=/j"
set "PASS_small_PROGRESS=files"
set "PASS_small_PERCENTAGES=no"

rem Robocopy flags used by every copy pass (COPY_FLAGS), and by the file
rem listing that drives verification (LIST_FLAGS: list only, full paths, no
rem headers, sizes or classes). Files and subdirectories keep their data,
rem attributes and timestamps (DAT), so anything hidden in the evidence stays
rem hidden; owner and ACLs are not copied. /bytes logs exact sizes. /e
rem includes empty directories. /xj doesn't follow junctions: only what is
rem physically inside the source is copied, and junction loops (e.g.
rem "Application Data" in a user profile) can't recurse forever.
set "COPY_FLAGS=/e /xj /v /x /ts /fp /bytes /dcopy:DAT /copy:DAT"
rem Every listing carries each file's exact size before its path (/bytes; the
rem loops that read a listing split it off): the Hash bars count bytes.
set "LIST_FLAGS=/l /e /xj /njh /njs /ndl /nc /fp /bytes /r:0 /w:0"
rem The Hash bars' progress (owner, 2026-10-20: by bytes, not files): each
rem file counts its size in units of 10^HASH_PROGRESS_UNIT_DIGITS bytes (5:
rem 100 KB; set /a is 32-bit, so 100 KB units reach 214 TB) plus
rem HASH_WEIGHT_PER_FILE_UNITS for the fixed cost of hashing a file (about
rem 33 ms on the test machine, worth some 30 MB of hashing: a bar by bytes
rem alone would stand still through thousands of small files).
set "HASH_PROGRESS_UNIT_DIGITS=5"
set "HASH_WEIGHT_PER_FILE_UNITS=300"
rem The listing made before the copy passes (:count_copy_pass_files), the
rem source against the destination as it is, so it names the files each
rem pass will copy (2.8.0; before, against an empty directory: every file):
rem as LIST_FLAGS with each file's exact size, and robocopy's job summary
rem kept (no /njs), whose Bytes row gives the bytes still to copy
rem (:check_destination_free_space).
set "COPY_COUNT_FLAGS=/l /e /xj /njh /ndl /nc /fp /bytes /r:0 /w:0"
rem The walk of the source that finds its links after the copy
rem (:find_skipped_links): list only, /xj so a link is listed and never
rem followed, /v so the links /xj skips are listed too, directories listed
rem (no /ndl), no class column (localised).
set "LINK_LIST_FLAGS=/l /e /xj /v /njh /njs /nc /fp /bytes /r:0 /w:0"
rem The list-only robocopy that decides about a directory DIR found
rem nothing in (:confirm_directory_readable): the directory and one level
rem below (/e /lev:2: a subdirectory counts in the Dirs row, a file in
rem either level in the Files row), no file or directory lines, the job
rem summary kept (no /njs) with its counts as plain numbers (/bytes).
set "DIRECTORY_PROBE_FLAGS=/l /e /lev:2 /nfl /ndl /njh /nc /np /bytes /r:0 /w:0"

rem Post-copy metadata check: robocopy in list-only mode, source against
rem destination, lists only files it would copy, i.e. whose size or
rem last-modified time differ (or that are missing). /xx leaves out files that
rem exist only in the destination. No /v or class column, so nothing
rem localised is parsed. Attributes and creation time are copied but not
rem compared: exFAT can't hold every NTFS attribute.
set "METADATA_FLAGS=/l /e /xj /xx /njh /njs /ndl /nc /fp /bytes /r:0 /w:0"
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
rem Robocopy's own exit codes use the five bits above (0 to 31). Anything
rem else (negative, or higher) means robocopy was stopped or failed: after
rem Ctrl+C it is -1073741510 (0xC000013A). Its bits then mean nothing, and
rem the copy or listing it ran fails (:is_robocopy_exit_code_in_range).
set "ROBOCOPY_EXIT_CODE_HIGHEST=31"

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

rem The files of a run record, checked before it is sealed (:write_seal,
rem 2.8.0; the GPT 6.1 review's finding 7): one row per file, named
rem RECORD_FILE_PREFIX<run UTC> plus its suffix. Each must be in staging with
rem at least one line when its WHEN holds for the run, and a file in staging
rem that no row names (junk names and the seal aside) is as wrong: the seal
rem wouldn't list it, and the next run would fail the record on it. Either
rem makes the seal incomplete: the record isn't written, staging is kept,
rem FAIL. Until 2.8.0 the seal covered whatever was in staging, so a record
rem file never written went unnoticed by the run that should have written
rem it.
rem   RECORD_FILE_<name>_SUFFIX  the file's name after the run UTC
rem   RECORD_FILE_<name>_VAR     the variable holding its staged path
rem   RECORD_FILE_<name>_WHEN    when it must be there (:record_file_required;
rem                              a value not listed here counts as always):
rem                              always; no_reference (a first copy or a
rem                              history restart: the source is hashed into
rem                              it); relocation (/relocate, or relocate
rem                              typed at the destination prompt); optional
rem                              (a restart's list of the run records found
rem                              outside the new history: written only when
rem                              one is found, sealed when present)
set "RECORD_FILES=log hashes_source hashes_destination hashes_custody history outside_history relocation"
set "RECORD_FILE_log_SUFFIX=.log"
set "RECORD_FILE_log_VAR=log_staged_path"
set "RECORD_FILE_log_WHEN=always"
set "RECORD_FILE_hashes_source_SUFFIX=_hashes_source.csv"
set "RECORD_FILE_hashes_source_VAR=staged_hash_csv_source"
set "RECORD_FILE_hashes_source_WHEN=no_reference"
set "RECORD_FILE_hashes_destination_SUFFIX=_hashes_destination.csv"
set "RECORD_FILE_hashes_destination_VAR=staged_hash_csv_destination"
set "RECORD_FILE_hashes_destination_WHEN=always"
set "RECORD_FILE_hashes_custody_SUFFIX=_hashes_custody.csv"
set "RECORD_FILE_hashes_custody_VAR=staged_hash_csv_custody"
set "RECORD_FILE_hashes_custody_WHEN=always"
set "RECORD_FILE_history_SUFFIX=_history.csv"
set "RECORD_FILE_history_VAR=staged_history_path"
set "RECORD_FILE_history_WHEN=always"
set "RECORD_FILE_outside_history_SUFFIX=_runs_outside_history.csv"
set "RECORD_FILE_outside_history_VAR=staged_outside_history_path"
set "RECORD_FILE_outside_history_WHEN=optional"
set "RECORD_FILE_relocation_SUFFIX=_relocation.txt"
set "RECORD_FILE_relocation_VAR=staged_relocation_path"
set "RECORD_FILE_relocation_WHEN=relocation"

rem History columns, fixed for all of 2.x: the run records check compares
rem history lines byte for byte, so later 2.x versions add information as
rem new files in the run record, never as columns. Cells never contain '"'
rem or "|". The newest row's Seal SHA-256 is "see <its seal file>" in its
rem sealed copy: a seal can't contain its own hash. The next run fills it in.
set "HISTORY_HEADER="Run (UTC)","Result","Source directory","Source volume serial","Source volume","Destination set directory","Destination volume serial","Destination volume","Evidence files","Host","User","Script","Seal SHA-256""

rem SHA-256 of zero bytes. certutil -hashfile fails on empty files, so a file
rem that certutil can't hash but whose size is 0 gets this value.
set "EMPTY_SHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

rem External programs (2.8.0; owner, 2026-10-24, from the GPT 6.1 review's
rem finding 8): every program this script runs, each by its full path under
rem the Windows directory (%SystemRoot%), never by its bare name. cmd looks
rem for a bare name in the current directory before PATH, so a robocopy.bat
rem beside a double-clicked script, or a certutil.exe on a writable PATH
rem entry, would run instead of Windows' own. :resolve_system_tools, the
rem first thing MAIN does, sets tool_<name> for each row to the file's
rem path, or to nothing when the file isn't there. Every call site writes
rem "%tool_<name>%": a path under %SystemRoot% holds no "!" or "%", so the
rem percent form is used whatever the expansion state. A FOR /F command
rem starts with its redirections, ('2^>nul ^<nul "%tool_x%" args'): cmd /c
rem strips the first and the last quote of a command line that starts with
rem one (unless there are exactly two), which would break the path's own
rem quotes; one that starts with a redirection is left as it is, and the
rem escaping is as with a bare name. Not one more pair of quotes round the
rem command: that inverts the parent cmd's quote state, so 2^>nul reached
rem the program as text (round 14.7). Child cmd instances are started as
rem "%ComSpec%". One row per program:
rem   SYSTEM_TOOL_<name>_FILE      the file, relative to %SystemRoot%
rem   SYSTEM_TOOL_<name>_REQUIRED  1: nothing works without it, so a run
rem                                stops before anything is written when it
rem                                is missing; 0: the check that uses it
rem                                reports it absent or falls back, as it
rem                                did when the program failed
set "SYSTEM_TOOLS=robocopy certutil findstr find sort fc more mode attrib chcp ping reg tasklist whoami hostname sc fsutil chkntfs w32tm powercfg curl wmic net"
set "SYSTEM_TOOL_robocopy_FILE=System32\robocopy.exe"
set "SYSTEM_TOOL_robocopy_REQUIRED=1"
set "SYSTEM_TOOL_certutil_FILE=System32\certutil.exe"
set "SYSTEM_TOOL_certutil_REQUIRED=1"
set "SYSTEM_TOOL_findstr_FILE=System32\findstr.exe"
set "SYSTEM_TOOL_findstr_REQUIRED=1"
set "SYSTEM_TOOL_find_FILE=System32\find.exe"
set "SYSTEM_TOOL_find_REQUIRED=1"
set "SYSTEM_TOOL_sort_FILE=System32\sort.exe"
set "SYSTEM_TOOL_sort_REQUIRED=1"
set "SYSTEM_TOOL_fc_FILE=System32\fc.exe"
set "SYSTEM_TOOL_fc_REQUIRED=1"
set "SYSTEM_TOOL_more_FILE=System32\more.com"
set "SYSTEM_TOOL_more_REQUIRED=1"
set "SYSTEM_TOOL_mode_FILE=System32\mode.com"
set "SYSTEM_TOOL_mode_REQUIRED=1"
set "SYSTEM_TOOL_attrib_FILE=System32\attrib.exe"
set "SYSTEM_TOOL_attrib_REQUIRED=1"
set "SYSTEM_TOOL_chcp_FILE=System32\chcp.com"
set "SYSTEM_TOOL_chcp_REQUIRED=1"
set "SYSTEM_TOOL_ping_FILE=System32\ping.exe"
set "SYSTEM_TOOL_ping_REQUIRED=1"
set "SYSTEM_TOOL_reg_FILE=System32\reg.exe"
set "SYSTEM_TOOL_reg_REQUIRED=1"
set "SYSTEM_TOOL_tasklist_FILE=System32\tasklist.exe"
set "SYSTEM_TOOL_tasklist_REQUIRED=0"
set "SYSTEM_TOOL_whoami_FILE=System32\whoami.exe"
set "SYSTEM_TOOL_whoami_REQUIRED=0"
set "SYSTEM_TOOL_hostname_FILE=System32\hostname.exe"
set "SYSTEM_TOOL_hostname_REQUIRED=0"
set "SYSTEM_TOOL_sc_FILE=System32\sc.exe"
set "SYSTEM_TOOL_sc_REQUIRED=0"
set "SYSTEM_TOOL_fsutil_FILE=System32\fsutil.exe"
set "SYSTEM_TOOL_fsutil_REQUIRED=0"
set "SYSTEM_TOOL_chkntfs_FILE=System32\chkntfs.exe"
set "SYSTEM_TOOL_chkntfs_REQUIRED=0"
set "SYSTEM_TOOL_w32tm_FILE=System32\w32tm.exe"
set "SYSTEM_TOOL_w32tm_REQUIRED=0"
set "SYSTEM_TOOL_powercfg_FILE=System32\powercfg.exe"
set "SYSTEM_TOOL_powercfg_REQUIRED=0"
set "SYSTEM_TOOL_curl_FILE=System32\curl.exe"
set "SYSTEM_TOOL_curl_REQUIRED=0"
set "SYSTEM_TOOL_wmic_FILE=System32\wbem\wmic.exe"
set "SYSTEM_TOOL_wmic_REQUIRED=0"
set "SYSTEM_TOOL_net_FILE=System32\net.exe"
set "SYSTEM_TOOL_net_REQUIRED=0"

rem Ordered fallbacks: each name is a helper (:utc_from_<name> or
rem :elevation_check_<name>), tried in turn until one succeeds. Pure batch and
rem built-in tools only. The robocopy clock works on every Windows version
rem with robocopy (Vista and later); wmic is deprecated and absent by default
rem from Windows 11 24H2.
set "UTC_METHODS=robocopy wmic"
set "ELEVATION_CHECKS=fsutil net"

rem The clock check (:read_clock_status): a run warns when the time service's
rem last synchronisation is older than this, or isn't known. A PC clock
rem typically drifts 1-2 s a day; Windows re-syncs a standalone PC every few
rem hours while it is online (owner, 2026-10-19: 7 days).
set "CLOCK_SYNC_MAX_AGE_HOURS=168"

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
rem Destination file systems with a file-size limit (2.8.0; owner): the
rem first size that doesn't fit, in bytes, and that size as words. A copy
rem run with a source file of that size or more stops before copying
rem (:check_destination_free_space): the copy would fail part-way.
rem FILESYSTEM_FILE_LIMIT_<fs> and FILESYSTEM_FILE_LIMIT_<fs>_TEXT.
set "FILESYSTEM_FILE_LIMIT_FAT32=4294967296"
set "FILESYSTEM_FILE_LIMIT_FAT32_TEXT=4 GiB"
set "FILESYSTEM_FILE_LIMIT_FAT=2147483648"
set "FILESYSTEM_FILE_LIMIT_FAT_TEXT=2 GiB"
rem Free space before the copy (2.8.0; owner): the bytes the passes will
rem copy, plus one part in 10^FREE_SPACE_MARGIN_DROP_DIGITS of them (2: one
rem hundredth) and FREE_SPACE_MARGIN_MB for the run record and the file
rem system's slack, must be free on the destination volume, or the run
rem stops before copying. The numbers are digit strings, added and compared
rem as such (:add_decimal_strings, :compare_decimal_strings): cmd's
rem arithmetic is 32-bit.
set "FREE_SPACE_MARGIN_DROP_DIGITS=2"
set "FREE_SPACE_MARGIN_MB=64"

rem Invalid answers allowed per prompt before the run aborts. Stops an endless
rem loop when there is no console input (e.g. input redirected or closed).
set "MAX_PROMPT_ATTEMPTS=10"

rem Final verdicts and their exit codes.
set "EXIT_CODE_PASS=0"
set "EXIT_CODE_FAIL=1"
set "EXIT_CODE_UNVERIFIED=2"

rem Output layout (shared rules: 80-character output, scannable output).
rem Every line the script writes itself keeps to OUTPUT_WIDTH characters,
rem broken at spaces with a hanging indent (:emit_wrapped); a line of exactly
rem 80 makes some 80-column consoles add an empty line, hence 79. A word
rem longer than the room left (a SHA-256, a path) stays whole. Sections open
rem with a blank line, RULE_LIGHT and a title (:write_section_heading); the
rem header and the result block sit between RULE_HEAVY lines. BLANKS is a
rem run of spaces to cut indents from.
set "OUTPUT_WIDTH=79"
rem Loops over the parts of a value (the leading or trailing spaces of a
rem line, the lines a text wraps into, the items of a "|"-separated CONFIG
rem list, the names in a path, the words in a record's cell) are bounded
rem FOR /L loops, never a goto loop: a backward goto scans the whole file
rem for its label, about 10 ms per iteration (workshop, 2026-10-20: a
rem 3,000-character word took 34 s to wrap). Each bound is far above any
rem real count; past it, what is left is taken as one piece.
set "OUTPUT_MAX_INDENT=32"
set "OUTPUT_MAX_WRAPPED_LINES=120"
set "CONFIG_LIST_MAX_ITEMS=64"
set "PATH_MAX_DEPTH=256"
set "RECORD_CELL_MAX_WORDS=64"
rem The live display's Source and Destination columns side by side (owner,
rem 2026-10-20), source left, destination right, the same field on the
rem same row, when the window is at least this many columns wide
rem (:dashboard_build_header_sections); narrower, one below the other as
rem the log always has them (the log keeps one column, for grepping; since
rem 2.8.0 the header is in the log alone where the display runs). Each
rem side's labels are HEADER_PAIR_LABEL_WIDTH wide.
set "HEADER_SIDE_BY_SIDE_MIN_COLUMNS=100"
set "HEADER_PAIR_LABEL_WIDTH=9"
rem The History row (2.8.0; owner, 2026-10-24): the runs of the history
rem this run continues, oldest first, then "current"; at most this many
rem runs, the newest, "....." standing for the ones left out
rem (:build_run_history_items, :write_run_history_rows,
rem :dashboard_emit_run_history_line). Nine runs and "current" fill one
rem line of a maximised Windows Terminal on 1920 x 1080 at 100 %.
set "HISTORY_RUNS_MAX=9"
set "RULE_HEAVY================================================================================"
set "RULE_LIGHT=-------------------------------------------------------------------------------"
set "BLANKS=                                                                                "

rem Console colours (ANSI SGR codes; :init_console_colour): on the console
rem only, never in the log or any record, and the words PASS, WARN and FAIL
rem are always written as well. COLOUR_<what>=code; verdicts are bold too.
set "COLOUR_PASS=32"
set "COLOUR_WARN=33"
set "COLOUR_FAIL=31"
set "COLOUR_INFO=36"
set "COLOUR_BOLD=1"

rem Live display on the console (:init_dashboard and the :dashboard_*
rem helpers, at the end of the file): drawn on the console's alternate
rem screen while a forensic run works (2.6.0), on a console that takes VT
rem sequences, and laid out for the window as it is at every redraw. From
rem the bottom up (owner, 2026-10-21): the progress block always; its
rem Failures and Warnings lists; above it, with rows to spare, the header's
rem Source and Destination sections, then the environment in cells across
rem the screen; the lists grow with what is left. Console only: nothing of
rem it reaches the log or any record, and it reads the run's counters
rem without changing them. The environment variable
rem EVIDENCE_ROBOCOPY_PLAIN, set to anything, asks for the plain output
rem instead (output that is captured, or a console without VT sequences),
rem as NO_COLOR asks for no colour.
rem   DASHBOARD_REDRAW_CENTISECONDS  in the script's own loops (hashing, the
rem                                  compare, the run records): at most one
rem                                  redraw per this; 5 s is the shortest
rem                                  interval that cost no more than a
rem                                  longer one (workshop, 2026-10-18). The
rem                                  default: /redraw <seconds> sets a
rem                                  run's (redraw_interval_centiseconds,
rem                                  :init_dashboard)
rem   DASHBOARD_TICK_EVERY_ITEMS     the loops read the clock every this many
rem                                  items (:dashboard_tick)
rem   DASHBOARD_TICK_EVERY_CONTENT_UNITS  the hash loop also reads it once
rem                                  this much file content has been hashed
rem                                  since it last did, in the Hash bars'
rem                                  units (HASH_PROGRESS_UNIT_DIGITS: 1000
rem                                  is 100 MB) without the per-file share
rem                                  (2.8.1: a few large files, an E01
rem                                  set's segments, never reached 25)
rem   DASHBOARD_POLL_SECONDS         how often the display helper reads the
rem                                  copy's progress from robocopy's log;
rem                                  the default, /redraw sets a run's
rem                                  (copy_progress_poll_seconds)
rem   DASHBOARD_REDRAW_MAX_SECONDS   the most /redraw accepts (1 to this)
rem   DASHBOARD_HELPER_WAIT_SECONDS  longest wait for the helper to see the
rem                                  copy start, or to end
rem   DASHBOARD_BYTES_TABLE_MAX_FILES  a bytes pass with more files than this
rem                                  is shown by files (its per-file table
rem                                  would be too large for the environment)
rem   DASHBOARD_BAR_WIDTH            columns inside a bar's [ ] in an
rem                                  80-column window; BAR_FULL and BAR_EMPTY
rem                                  are that many # and . (a wider window
rem                                  widens the bar with it: the strings are
rem                                  repeated at the start, :init_dashboard)
rem   DASHBOARD_ESTIMATE_AFTER_SECONDS, _PERMILLE  a bar's time left is shown
rem                                  once its stage has run this long and is
rem                                  this far through (thousandths); before,
rem                                  "estimating"
rem   DASHBOARD_BLOCK_FIXED_LINES    the progress block's lines besides its
rem                                  lists: a rule, the title, the six stage
rem                                  rows, two detail lines under Copy and
rem                                  one under Hash, a blank line, a rule
rem                                  (the lists' headings come on top: two
rem                                  one above the other, one side by side)
rem   DASHBOARD_LIST_ROWS_MIN        rows the Failures and Warnings lists get
rem                                  before the header's sections are given
rem                                  room (shared, one above the other; each,
rem                                  side by side)
rem   DASHBOARD_LIST_ROWS_MAX        the most rows the lists take (and the
rem                                  most lines of each list kept for them)
rem   DASHBOARD_LISTS_SIDE_BY_SIDE_MIN_COLUMNS  from this width the Failures
rem                                  list is on the left and the Warnings
rem                                  list on the right, each the full
rem                                  height (owner, 2026-10-21: 160, where
rem                                  each has the summary's 79 columns)
rem   DASHBOARD_MIN_WINDOW_ROWS, _COLUMNS  the smallest window the display
rem                                  draws in (the block with its lists at
rem                                  their minimum, 80 columns: 2.4.0's
rem                                  size); a smaller one shows one line
rem                                  asking for a larger window until it
rem                                  gets one (owner, 2026-10-21: the
rem                                  display always starts; the window's
rem                                  size is read at every redraw)
rem   DASHBOARD_CELL_WIDTH           an environment cell's least columns
rem                                  ("Label: value"); wider when the longest
rem                                  cell needs it, so no value is cut while
rem                                  the window holds one cell; widened to
rem                                  share its row; as many cells across as
rem                                  the window takes
rem   DASHBOARD_ENVIRONMENT_FIELDS   the environment cells, in order;
rem                                  DASHBOARD_FIELD_<field>_LABEL its label,
rem                                  _VAR the variable with its short value
rem                                  (written for the cell; the header and
rem                                  the log hold the full text)
rem   DASHBOARD_HIGHLIGHTS           values the display colours (2.7.0,
rem                                  owner): items "<raised>:<shown>:<kind>";
rem                                  <raised> a variable defined when the run
rem                                  raised the [WARN] or [INFO] the value is
rem                                  about (set where the warning is added),
rem                                  <shown> the variable whose value an
rem                                  environment cell (DASHBOARD_FIELD_<f>_VAR)
rem                                  or a side-by-side Source/Destination
rem                                  field shows, <kind> warn (COLOUR_WARN)
rem                                  or info (COLOUR_INFO), as the tag. The
rem                                  label stays plain; console only, and
rem                                  not where the fields are one below the
rem                                  other (under 100 columns). Add a row for
rem                                  a new warning about a shown value.
rem   DASHBOARD_STAGES               the result block's checks, in its order;
rem                                  DASHBOARD_STAGE_<stage>_LABEL its label
set "DASHBOARD_REDRAW_CENTISECONDS=500"
set "DASHBOARD_TICK_EVERY_ITEMS=25"
set "DASHBOARD_TICK_EVERY_CONTENT_UNITS=1000"
set "DASHBOARD_POLL_SECONDS=5"
set "DASHBOARD_REDRAW_MAX_SECONDS=60"
set "DASHBOARD_HELPER_WAIT_SECONDS=10"
set "DASHBOARD_BYTES_TABLE_MAX_FILES=1000"
set "DASHBOARD_BAR_WIDTH=34"
set "DASHBOARD_BAR_FULL=##################################"
set "DASHBOARD_BAR_EMPTY=.................................."
set "DASHBOARD_ESTIMATE_AFTER_SECONDS=60"
set "DASHBOARD_ESTIMATE_AFTER_PERMILLE=10"
set "DASHBOARD_BLOCK_FIXED_LINES=14"
set "DASHBOARD_LIST_ROWS_MIN=6"
set "DASHBOARD_LIST_ROWS_MAX=20"
set "DASHBOARD_LISTS_SIDE_BY_SIDE_MIN_COLUMNS=160"
set /a "DASHBOARD_MIN_WINDOW_ROWS=DASHBOARD_BLOCK_FIXED_LINES + 2 + DASHBOARD_LIST_ROWS_MIN + 2"
set /a "DASHBOARD_MIN_WINDOW_COLUMNS=OUTPUT_WIDTH + 1"
set "DASHBOARD_CELL_WIDTH=40"
set "DASHBOARD_ENVIRONMENT_FIELDS=script started host user os elevated clock sync release mode sleep"
set "DASHBOARD_HIGHLIGHTS=elevation_noted:elevated_summary:info clock_warned:time_source_summary:warn clock_warned:last_sync_summary:warn latest_release_warning:latest_release_summary:warn power_warned:sleep_summary:warn filesystem_warned_source:header_source_volume:warn filesystem_warned_destination:header_destination_volume:warn location_serial_warned:header_source_volume:warn location_path_warned:header_source_set:warn reference_missing_warned:header_reference_record:warn destination_not_empty_warned:destination_state_text:warn recovered_warned_source:pair_source_root_text:warn"
set "DASHBOARD_FIELD_script_LABEL=Script"
set "DASHBOARD_FIELD_script_VAR=header_script"
set "DASHBOARD_FIELD_started_LABEL=Started (UTC)"
set "DASHBOARD_FIELD_started_VAR=start_utc_iso"
set "DASHBOARD_FIELD_host_LABEL=Host"
set "DASHBOARD_FIELD_host_VAR=header_host"
set "DASHBOARD_FIELD_user_LABEL=User"
set "DASHBOARD_FIELD_user_VAR=header_user_name"
set "DASHBOARD_FIELD_os_LABEL=OS"
set "DASHBOARD_FIELD_os_VAR=header_os"
set "DASHBOARD_FIELD_elevated_LABEL=Elevated"
set "DASHBOARD_FIELD_elevated_VAR=elevated_summary"
set "DASHBOARD_FIELD_clock_LABEL=Time source"
set "DASHBOARD_FIELD_clock_VAR=time_source_summary"
set "DASHBOARD_FIELD_sync_LABEL=Last sync"
set "DASHBOARD_FIELD_sync_VAR=last_sync_summary"
set "DASHBOARD_FIELD_release_LABEL=Latest release"
set "DASHBOARD_FIELD_release_VAR=latest_release_summary"
set "DASHBOARD_FIELD_mode_LABEL=Mode"
set "DASHBOARD_FIELD_mode_VAR=mode_summary"
set "DASHBOARD_FIELD_sleep_LABEL=Sleep"
set "DASHBOARD_FIELD_sleep_VAR=sleep_summary"
set "DASHBOARD_STAGES=result script copy metadata run_records hash record_written"
set "DASHBOARD_STAGE_result_LABEL=RESULT"
set "DASHBOARD_STAGE_script_LABEL=Script"
set "DASHBOARD_STAGE_copy_LABEL=Copy"
set "DASHBOARD_STAGE_metadata_LABEL=Metadata"
set "DASHBOARD_STAGE_run_records_LABEL=Run records"
set "DASHBOARD_STAGE_hash_LABEL=Hash (SHA-256)"
set "DASHBOARD_STAGE_record_written_LABEL=Record written"
rem   DASHBOARD_STAGE_<stage>_DETAILS  the variables of the detail lines shown
rem                                  under a stage's row (empty: none); they
rem                                  go when the stage has its result
set "DASHBOARD_STAGE_copy_DETAILS=dashboard_copy_detail dashboard_copy_error_text"
set "DASHBOARD_STAGE_hash_DETAILS=dashboard_hash_detail"

rem =============================== MAIN ======================================

if "%~1"=="/?" goto :show_help
set "script_path=%~f0"
set "script_file_name=%~nx0"
set "script_dir=%~dp0"

rem The display helper: this script started again by :dashboard_copy_begin,
rem in the same console and with the run's variables, to paint the live
rem display while robocopy copies (:dashboard_helper_main). It is told apart
rem by a variable set for the moment it starts, holding this run's own
rem temporary path, which nothing else can hold.
if defined evidence_robocopy_display_helper if "%evidence_robocopy_display_helper%"=="%temp_path_prefix%" goto :dashboard_helper_main
rem The display watchdog (2.6.0): this script started again by
rem :dashboard_start, told apart the same way, to switch the console back
rem from its alternate screen if the run dies there (:dashboard_watchdog_main).
if defined evidence_robocopy_display_watchdog if "%evidence_robocopy_display_watchdog%"=="%temp_path_prefix%" goto :dashboard_watchdog_main
rem The update check (2.8.0): this script started again by
rem :start_latest_release_check, told apart the same way (by this run's
rem answer file), to ask github.com while the prompts are answered
rem (:update_check_main).
if defined evidence_robocopy_update_check if "%evidence_robocopy_update_check%"=="%temp_update_check%" goto :update_check_main

call :init_state
call :resolve_system_tools || goto :abort
call :init_console_vt
call :init_console_colour
rem The arguments are parsed without CALL (2.6.0): CALL expands a "%" in
rem an argument a second time and doubles each "^" (workshop 2.6.0: a path
rem with %OS% in it arrived as Windows_NT); :parse_args is entered with
rem goto and comes back to :main_after_parse_args, or goes to :abort.
goto parse_args
:main_after_parse_args
call :init_dashboard
call :switch_console_to_utf8
call :init_listing_file || goto :abort
call :read_carriage_return
call :show_banner
call :detect_elevation
rem The update check (2.8.0): in line for /update, which needs the answer
rem before the prompts; skipped with /no-update-check; otherwise in the
rem background, its answer read before the header (:check_environment).
if defined argument_no_update_check (call :skip_latest_release_check) else if defined update_requested (call :check_latest_release) else call :start_latest_release_check
if defined update_requested call :prepare_update
if defined update_ready call :compose_update_arguments
rem /update, once :prepare_update has checked the download (update_ready): the
rem replacement and the start of the new file, here in MAIN and inside one
rem parenthesised block, which cmd parses whole before the copy runs. After
rem the copy the next line read from this file would come from the new one
rem at this file's byte offset, and an "exit /b" inside a called helper
rem would only return here (workshop, 2026-10-20: both seen); in MAIN
rem "exit /b" ends this script. Nothing in the block calls a label (it would
rem be looked for in the new file): the code page goes back inline, the scope
rem is closed (the new run starts in the environment this one started in,
rem plus update_script_path, the path carried across the endlocal with
rem delayed expansion off, so a "!" in it survives), a scope with delayed
rem expansion is opened for the exit code (setlocal resets ERRORLEVEL, so
rem it comes before the child), and this script ends with the new run's
rem exit code. The child cmd is given the variable's name, not the path
rem ("%%" in this file is one "%" on the child's command line): a child cmd
rem expands %NAME% in its command line, so a path holding "%" would be
rem changed; the variable's value is expanded once, by the child, as it is.
rem No CALL: CALL would expand the path a second time (round 13: "%OS%" in
rem it became "Windows_NT", "The system cannot find the path specified.").
rem The mode and options this run was given follow the path the same way
rem (update_arguments, :compose_update_arguments; 2.7.0), so the updated
rem script runs what this one was asked for; /v:off keeps a "!" in a path
rem as it is in the child. update_arguments is carried across the endlocal
rem without quotes round the assignment, so each path in it stays inside
rem its own quotes (:compose_update_arguments says why). A run given
rem nothing but /update has no words to pass, and a child cmd keeps an
rem undefined %NAME% on its command line as that text (round 15: the
rem updated script was given the argument "%update_arguments%" and
rem refused it as an unknown option; 2.7.0 as released does the same),
rem so the child's line is one of two: with the words, or the path alone.
rem This run's working files (the update check's answer among them:
rem round 14.8 found it left in TEMP) go first, before the copy, where a
rem label may still be called.
if defined update_ready (
    call :cleanup_temp
    copy /y "%update_download_path%" "%script_path%" >nul 2>&1 || goto update_replace_failed
    del /q "%update_dir%\*" >nul 2>&1
    rd "%update_dir%" >nul 2>&1
    if not "%original_code_page%"=="unknown" "%tool_chcp%" %original_code_page% >nul 2>&1 <nul
    endlocal & set "update_script_path=%script_path%" & set update_arguments=%update_arguments%
    setlocal EnableDelayedExpansion
    if defined update_arguments (
        "%ComSpec%" /d /v:off /c ""%%update_script_path%%" %%update_arguments%%"
    ) else (
        "%ComSpec%" /d /v:off /c ""%%update_script_path%%""
    )
    exit /b !errorlevel!
)
if "%run_mode%"=="nonforensic" goto :main_nonforensic
:main_after_update

rem --- Forensic run (the default): log, verification and run records -------
rem A copy run; or, by run_kind (2.5.0), a check (/check: the set given is
rem verified in place and the check recorded in it, nothing copied) or a
rem relocation (/relocate: the set moved within its volume, then verified at
rem its new place and the move recorded in it). The checks before the copy
rem read the set where it is; a relocation moves it after them, in place of
rem the copy (:relocate_set), and the verification reads the moved set.
call :use_log_mode
call :ask_source_set || goto :abort
if "%run_kind%"=="copy" call :ask_destination_set || goto :abort
if "%run_kind%"=="check" call :confirm_check_in_place || goto :abort
if "%run_kind%"=="relocate" if not defined relocation_chosen_at_destination call :ask_relocation_target || goto :abort
call :init_run || goto :abort
call :hash_this_script
call :read_history || goto :abort
if not "%run_kind%"=="copy" call :require_reference_record || goto :abort
call :check_environment
call :check_script_against_previous_run
call :check_location_against_previous_run
call :choose_script_copy
call :precheck_run_records
if "%run_kind%"=="relocate" call :relocate_set || goto :abort
if "%run_kind%"=="copy" call :prepare_copy_passes || goto :abort
rem The live display takes over from here (2.8.0; owner, 2026-10-24: it
rem stands in for the console output): it starts before the header, so
rem the header and the summary reach the log alone (:emit_line), and
rem draws its first frame once the header's variables are set. Without
rem the display (the plain output) these calls do nothing and the output
rem is as before.
call :dashboard_start
call :write_header
call :log_pre_copy_findings
call :dashboard_redraw
rem The work, the record and the display's last frame with its pause,
rem with the display's watch lock held open on handle 8 for their whole
rem duration (2.6.0; 2.8.0 through the pause): the watchdog switches the
rem console back when the lock opens without the end marker
rem (:dashboard_watchdog_main). Then the normal screen, with a
rem scrollback, gets the result block and the closing lines.
(call :run_recorded_work) 8>"%temp_dashboard_watch_lock%"
call :write_result_block console
call :show_closing_lines
call :cleanup_temp
call :restore_console_code_page
if not defined argument_nopause if not defined dashboard_paused pause
exit /b %exit_code%

rem --- The copy step of a forensic run, by kind ----------------------------
:copy_evidence
rem A copy run: the passes, with the display's lock file held open on
rem handle 9 for their whole duration: the display helper ends when it is
rem released (:dashboard_helper_main). Without the live display the file is
rem only made, and deleted with the other working files. Then the links
rem the passes left behind, the custody files, the Copy check's result and
rem the destination directory's attributes.
call :dashboard_copy_begin
(for %%P in (%COPY_PASSES%) do call :run_copy_pass %%P) 9>"%temp_dashboard_lock%"
call :dashboard_copy_end
call :find_skipped_links
call :copy_custody_files
call :work_out_copy_status
call :dashboard_stage_result copy result_copy
call :restore_destination_attributes
exit /b 0

:skip_copy
rem A check or a relocation: nothing is copied; the Copy row says so (NONE)
rem and the verification follows on the set as it is.
call :work_out_copy_status
call :dashboard_stage_result copy result_copy
exit /b 0

rem --- The work under the live display ---------------------------------------
:run_verified_work
rem The copy (or not, by kind), the verification, the result and the
rem display's end, called by MAIN with the watch lock held (2.6.0):
rem :dashboard_finish writes the end marker before the lock is released, so
rem the watchdog stays quiet at a normal end.
if "%run_kind%"=="copy" (call :copy_evidence) else call :skip_copy
call :verify_copy
call :stage_script_copy
call :work_out_result
call :dashboard_finish
exit /b 0

:run_recorded_work
rem Everything under the watch lock (2.8.0): the work, then the summary
rem (the log's copy of the result block), the history, the seal, the
rem record's write-back, the final verdict, and the display's last frame,
rem which waits at the pause before the console leaves it
rem (:dashboard_finish_run; nothing without the display). Called by MAIN.
call :run_verified_work
call :write_summary
call :write_history
call :write_seal
call :publish_records
call :work_out_final_result
call :dashboard_finish_run
exit /b 0

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
call :prepare_copy_passes || goto :abort
rem The live display from before the header to after the pause, as a
rem forensic run's (MAIN above; 2.8.0): a non-forensic run has no log, so
rem the header is the display's alone, and the summary is printed on the
rem normal screen once the console is back on it.
call :dashboard_start
call :write_header
call :dashboard_redraw
rem The work under the live display (2.7.0), with the display's watch lock
rem held open on handle 8 for its whole duration, as a forensic run's
rem (MAIN above): the watchdog switches the console back when the lock
rem opens without the end marker.
(call :run_plain_recorded_work) 8>"%temp_dashboard_watch_lock%"
call :write_summary
call :cleanup_temp
call :restore_console_code_page
if not defined argument_nopause if not defined dashboard_paused pause
exit /b %exit_code%

:run_plain_work
rem The non-forensic run's work under the live display (2.7.0), called by
rem MAIN with the watch lock held: the copy passes with the display's lock
rem on handle 9 (the display helper ends when it opens; :copy_evidence is
rem the model), the links left behind, the Copy row's result, the
rem destination directory's attributes, the verification when it was
rem chosen, the result and the display's end.
call :dashboard_copy_begin
(for %%P in (%COPY_PASSES%) do call :run_copy_pass %%P) 9>"%temp_dashboard_lock%"
call :dashboard_copy_end
call :find_skipped_links
call :work_out_copy_status
call :dashboard_stage_result copy result_copy
call :restore_destination_attributes
if "%verification_enabled%"=="1" call :verify_plain_copy
call :work_out_result
call :dashboard_finish
exit /b 0

:run_plain_recorded_work
rem A non-forensic run's work and the display's last frame with its pause
rem (2.8.0), under the watch lock; called by MAIN.
call :run_plain_work
call :dashboard_finish_run
exit /b 0

rem ============================ FUNCTIONS ====================================

rem --------------------------- Run steps -------------------------------------

:show_help
echo %TOOL_NAME% %TOOL_VERSION%
echo.
echo Forensic mode (default): copies an evidence directory, under its own name,
echo   into a set directory in the destination, beside the custody files (this
echo   script, %HISTORY_FILE_NAME%, %RECORDS_DIR_NAME%\).
echo A log is kept, every file is verified by SHA-256 against the reference
echo   record (the set's first hash record) and by size and last-modified time,
echo   and every earlier run record must still match its seal and the history.
echo Each run adds its record in %RECORDS_DIR_NAME%\^<run UTC^>\ and a row
echo   to the history. Nothing is ever written to the source.
echo.
echo Source: Enter takes the script's own directory as the set directory
echo   (S1). A typed directory is a set directory if it holds the custody
echo   files (S2), the set's evidence directory if its parent does (S3), or
echo   raw evidence (S4, a first copy).
echo Destination: an existing directory. The set directory is, by the first
echo   rule that fits: the directory, if it holds custody files (D1); its
echo   parent, if the directory has the evidence directory's name and the
echo   parent holds custody files or nothing else (D2); the directory, if it
echo   is empty or holds only a directory with the evidence directory's name
echo   (D3); otherwise a directory in it named after the set (D4). A set
echo   directory holding custody files is a rerun or update (confirmed);
echo   otherwise it must hold nothing but an empty evidence directory. Nothing
echo   is written into another set.
echo.
echo /check: verifies a set in place, without copying: the SOURCE prompt only
echo   (a set directory, or its evidence directory); every file against the
echo   reference record, the run records against their seals and the history;
echo   a run record and a history row are written into the set (confirmed).
echo /relocate: moves a set to a new location on the same volume (a rename,
echo   nothing copied), confirmed; then verifies it there as /check does and
echo   records the move in its run record, so later copies don't warn that it
echo   was moved by other means.
echo /nonforensic: a plain copy utility for non-evidence copies: copies the
echo   source directory's contents into the destination with its progress on
echo   screen (the live display, or robocopy's ETA with the plain output), no
echo   log and no records; optional SHA-256 verification, shown on screen only.
echo /update: asks GitHub for the latest release and, if it is newer, replaces
echo   this file with it (the download checked against the release's SHA-256
echo   file), then starts the updated script with the mode and options this
echo   run was given (none: a forensic copy); with nothing to update, this
echo   script carries on with them.
echo Every run asks GitHub (github.com) once which release is the latest and
echo   warns when this script is older or newer than it, or when it can't tell;
echo   it never updates itself.
echo.
echo Options, in any order with the modes above:
echo   /source "<path>"       answers the SOURCE prompt
echo   /destination "<path>"  answers the DESTINATION prompt (a relocation's
echo                          new location); not with /check
echo   /yes-to-all            answers every question below with the answer shown,
echo                          whatever comes up; give it only when you know which
echo                          questions this run will ask. It never moves a set.
echo                            a destination that holds the set: 1 (continue)
echo                            /check: 1 (verify and record)
echo                            /relocate: 1 (move)
echo                            copy or relocate (below): copy
echo                            /nonforensic: 1 (continue), 1 (compare), and
echo                              1 (continue) when the destination isn't empty
echo   /nopause               no "Press any key" at the end; the exit code is the
echo                          result
echo   /redraw ^<seconds^>      the live display's redraw interval, 1 to %DASHBOARD_REDRAW_MAX_SECONDS%
echo                          (default %DASHBOARD_POLL_SECONDS%): the loops redraw at most this often
echo                          and the copy's progress is read this often. Cost on
echo                          10,000 small files: 1 s +16 %%, 5 s +9 %%, 10 s the
echo                          same as 5 s. No effect with the plain output.
echo   /no-update-check       no request to github.com for the latest release
echo                          (the header says so); not with /update
echo   A refused path stops the run before anything is written (exit 1). A
echo   question without /yes-to-all is asked at the console as usual. Quote
echo   each path. The shell expands a %%name%% of a defined variable in it
echo   before this script runs; from another batch file start this one
echo   without CALL, which doubles each ^^ and expands %%%% again. The log's
echo   header says whether questions were answered by /yes-to-all.
echo In a copy run, when the new destination set is on the source set's volume,
echo   the run asks whether to copy the set or to move it there (Enter or copy;
echo   or the word relocate, which does what /relocate does).
echo.
echo Records are UTF-8 with CRLF line endings. Files are written unbuffered
echo   (robocopy /j). Not elevated, nothing copied is in Windows' file cache
echo   when verified. Elevated, backup mode (/b) leaves the evidence and
echo   custody files it copies in that cache, so they may be verified from
echo   it; the run's own record is not in it either way.
echo Run as administrator to use backup mode (/b).
echo A run shows its progress in a live display on the console
echo   (Windows 10 or later, not the legacy console), drawn on the console's
echo   second screen and laid out for the window at each redraw: make the
echo   window larger at any time. The progress block (the RESULT, each
echo   check's status or bar, the file in hand, the last failures and
echo   warnings) always; above it, with room, the Source and Destination
echo   columns with the History row (the set's runs, then this one), then
echo   the environment. Under %DASHBOARD_MIN_WINDOW_COLUMNS% x %DASHBOARD_MIN_WINDOW_ROWS% it shows one line asking for a
echo   larger window. The display stands in for the console output: the
echo   header and the summary go to the log; at the end it shows the result,
echo   the seal's SHA-256 and the log's location and waits at the pause, and
echo   the normal screen then gets the result block and those lines. Set
echo   EVIDENCE_ROBOCOPY_PLAIN=1 for the plain output instead (the header,
echo   robocopy's lines, a line per hashed file, the summary), e.g. when the
echo   output is captured. From %HEADER_SIDE_BY_SIDE_MIN_COLUMNS% columns the display's Source and
echo   Destination columns sit side by side.
echo.
echo Exit codes:
echo   %EXIT_CODE_PASS% PASS
echo   %EXIT_CODE_FAIL% FAIL
echo   %EXIT_CODE_UNVERIFIED% UNVERIFIED (copied, not verified)
exit /b 0

:init_state
rem Counters and flags used across the run, all given a starting value here.
rem   copy_exit_codes            robocopy exit codes of all passes, OR-ed
rem   copy_files_<column>        robocopy's Files row over the evidence
rem                              passes (copied, skipped, failed, mismatch,
rem                              extras: :add_pass_summary_counts),
rem                              copy_files_total the largest Total of a
rem                              pass, copy_passes_counted the passes with
rem                              a summary, and copy_counts_missing 1 when
rem                              a pass ran without a readable summary
rem   hashed_count_<side>        files hashed in the source / destination, and
rem                              custody files hashed in the destination
rem   hashed_units_<side>        the same in the Hash bars' units (bytes in
rem                              100 KB units plus a share per file:
rem                              HASH_WEIGHT_PER_FILE_UNITS), against
rem                              listing_units_total, the listing's
rem   unexpected_listing_lines   listing lines that weren't a path in the
rem                              directory
rem   hash_check_incomplete      1 if a listing, certutil or the reference
rem                              record was unavailable
rem   path_too_long_<side>_count  listed files of the source / destination
rem                              not hashed: their path is over
rem                              MAX_FILE_PATH_LENGTH, or cmd couldn't carry
rem                              their listing line (:hash_listed_files). Per
rem                              side: one file over the limit on both sides
rem                              is refused twice (round 12.8)
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
rem   run_records_warned         defined once a warning about the run records
rem                              was raised (before the copy, or a .partial
rem                              found after it): a clean check after the
rem                              copy then reads WARN, not PASS
rem   run_record_count           run records checked
rem   run_record_file_match_count  files in them that match their seal
rem   run_record_problem_count   run record problems (see :check_run_records)
rem   utc_clock_failed           1 if no UTC_METHODS worked (see :get_utc_now)
rem   compare_lines_done         compare lines paired so far (the live
rem                              display's compare bar)
rem   copy_pass_last             the last pass in COPY_PASSES (never skipped)
rem   copy_log_incomplete        1 if a line of robocopy's output couldn't be
rem                              written into the log
rem                              (:report_dropped_robocopy_lines)
rem   robocopy_output_lines_written, _total  the lines the last
rem                              :save_robocopy_unicode_output wrote, of
rem                              those robocopy's output held
rem   header_written             defined once the log header is complete
for %%V in (copy_exit_codes hashed_count_source hashed_count_destination hashed_count_custody unexpected_listing_lines hash_check_incomplete) do set "%%V=0"
for %%V in (copy_files_copied copy_files_skipped copy_files_failed copy_files_mismatch copy_files_extras copy_files_total copy_passes_counted copy_counts_missing) do set "%%V=0"
for %%V in (hashed_units_source hashed_units_destination hashed_units_custody listing_units_total) do set "%%V=0"
for %%V in (metadata_differ_count metadata_check_incomplete reference_row_count match_count differ_count missing_count) do set "%%V=0"
for %%V in (unreadable_count invalid_row_count added_file_count reference_seal_failed utc_clock_failed) do set "%%V=0"
for %%V in (run_record_count run_record_file_match_count run_record_problem_count history_row_count) do set "%%V=0"
for %%V in (path_too_long_source_count path_too_long_destination_count copy_log_incomplete robocopy_output_lines_written robocopy_output_lines_total) do set "%%V=0"
set "run_records_checked="
set "run_records_warned="
rem The display's highlights (DASHBOARD_HIGHLIGHTS): defined where the
rem [WARN] or [INFO] they stand for is raised.
for %%V in (elevation_noted clock_warned power_warned filesystem_warned_source filesystem_warned_destination location_serial_warned location_path_warned reference_missing_warned destination_not_empty_warned recovered_warned_source) do set "%%V="
set "metadata_check_ran="
set "metadata_time_precision=exact"
set "compare_lines_done=0"
set "copy_pass_last="
for %%P in (%COPY_PASSES%) do set "copy_pass_last=%%P"
set "header_written="
set "log_ready="
set "log_sealed="
set "exit_code=%EXIT_CODE_FAIL%"
set "result_script_copy=not attempted"
set "staging_dir="
set "staging_dir_missing="
set "staged_relocation_path="
set "seal_incomplete="
set "original_code_page="
set "history_base_path="
set "history_base_side="
set "history_base_missing="
set "history_base_sha256="
set "history_staging_problem="
set "reference_run="
set "reference_name="
set "reference_csv_path="
set "reference_seal_result_text="
set "reference_seal_sha256_text="
set "previous_run="
set "script_status=NONE"
set "result_script=NONE: no earlier run in the history"
set "script_failure_message="
set "verification_enabled="
set "result_hash_detail_count=0"
set "result_record_written=FAIL: the record's write-back did not run"
set "final_result_overall="
set "log_published="
set "record_kept_in_staging="
set "run_seal_sha256="
exit /b 0

:resolve_system_tools
rem Caller's scope (MAIN, right after :init_state, before any program
rem runs). Each row of SYSTEM_TOOLS (CONFIG, "External programs") into
rem tool_<name>: the file's full path under %SystemRoot%, or empty when it
rem isn't there. A required program missing stops the run (abort_reason,
rem exit 1) before the console is switched or anything is written.
set "system_tools_missing="
for %%T in (%SYSTEM_TOOLS%) do call :resolve_system_tool %%T
if not defined system_tools_missing exit /b 0
set "abort_reason=Not found in the Windows directory (%SystemRoot%):%system_tools_missing%. This script runs only Windows' own copies of the programs it uses, by their full paths; nothing is copied or written without them."
exit /b 1

:resolve_system_tool  name
rem Caller's scope (:resolve_system_tools): one row.
call :copy_variable SYSTEM_TOOL_%~1_FILE resolve_tool_file
call :copy_variable SYSTEM_TOOL_%~1_REQUIRED resolve_tool_required
set "tool_%~1=%SystemRoot%\%resolve_tool_file%"
if exist "%SystemRoot%\%resolve_tool_file%" exit /b 0
set "tool_%~1="
if "%resolve_tool_required%"=="1" set "system_tools_missing=%system_tools_missing% %resolve_tool_file%"
exit /b 0

:init_console_vt
rem Does the console take VT sequences (colour, the live display)? Windows
rem 10 or later (by version number) and not the legacy console (HKCU\Console
rem ForceV2 = 0). Sets console_vt and escape_character; the escape
rem character is made here, at run time, so the file itself stays plain
rem ASCII.
set "console_vt="
set "escape_character="
rem Registry values are read as :describe_windows reads them (the line that
rem names the value, then its data).
set "windows_major_version=0"
for /f "tokens=2,*" %%A in ('2^>nul ^<nul "%tool_reg%" query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v CurrentMajorVersionNumber ^| "%tool_find%" /i "CurrentMajorVersionNumber"') do set /a "windows_major_version=%%B" 2>nul
if %windows_major_version% lss 10 exit /b 0
set "legacy_console="
for /f "tokens=2,*" %%A in ('2^>nul ^<nul "%tool_reg%" query "HKCU\Console" /v ForceV2 ^| "%tool_find%" /i "ForceV2"') do if /i "%%B"=="0x0" set "legacy_console=1"
if defined legacy_console exit /b 0
for /f %%E in ('echo prompt $E^| "%ComSpec%" /d 2^>nul') do set "escape_character=%%E"
if not defined escape_character exit /b 0
if not "%escape_character:~1%"=="" (set "escape_character=" & exit /b 0)
set "console_vt=1"
exit /b 0

:init_console_colour
rem Colour on the console only where it takes VT sequences (console_vt,
rem :init_console_vt) and not when NO_COLOR is set (the common way to ask
rem for none). Sets console_colour and the coloured status words
rem :colour_for_console puts in.
set "console_colour="
if defined NO_COLOR exit /b 0
if not defined console_vt exit /b 0
set "colour_end=%escape_character%[0m"
set "coloured_pass=%escape_character%[%COLOUR_PASS%mPASS%colour_end%"
set "coloured_fail=%escape_character%[%COLOUR_FAIL%mFAIL%colour_end%"
set "coloured_not_run=%escape_character%[%COLOUR_WARN%mNOT RUN%colour_end%"
set "coloured_warn=%escape_character%[%COLOUR_WARN%mWARN%colour_end%"
set "coloured_warn_tag=%escape_character%[%COLOUR_WARN%m[WARN]%colour_end%"
set "coloured_info_tag=%escape_character%[%COLOUR_INFO%m[INFO]%colour_end%"
set "coloured_fail_tag=%escape_character%[%COLOUR_FAIL%m[FAIL]%colour_end%"
set "coloured_run_failed_start=%escape_character%[%COLOUR_FAIL%m"
set "coloured_verdict_pass=%escape_character%[%COLOUR_BOLD%;%COLOUR_PASS%mPASS%colour_end%"
set "coloured_verdict_fail=%escape_character%[%COLOUR_BOLD%;%COLOUR_FAIL%mFAIL%colour_end%"
set "coloured_verdict_unverified=%escape_character%[%COLOUR_BOLD%;%COLOUR_WARN%mUNVERIFIED%colour_end%"
set "console_colour=1"
exit /b 0

:parse_args  [options...]
rem Entered with goto from MAIN, never CALL (2.6.0: CALL expands a "%" in
rem an argument a second time and doubles each "^"), and leaves with goto
rem :main_after_parse_args, or goto :abort. Forensic mode unless
rem /nonforensic is given. A forensic run's kind (run_kind, 2.5.0): copy
rem (the default), check (/check: a set verified in place, no copy) or
rem relocate (/relocate: a set moved within its volume, then verified in
rem place); run_kind_switch is the option's text for messages ("/check"),
rem empty for a copy. The options that answer prompts (2.6.0, owner):
rem /source "<path>" and /destination "<path>" answer the directory prompts
rem (the path as %~1 and the others give it: the caller's shell has already
rem expanded a %name% of a defined variable in it, nothing here expands it
rem again); /yes-to-all answers every question that has numbered choices
rem with its first choice and the copy-or-relocate question with copy (the
rem help lists them; it never chooses to move a set: that takes the word
rem relocate, typed or as the option), each answer echoed as a typed one is
rem and the header's Confirmations field saying so; /nopause leaves out
rem the pause at the end. A question with no option answering it is asked
rem at the console as always. Options in any order, each a word of its
rem own; a repeated option, an option without its value, an unknown option
rem (a directory dropped on the script too), two modes, or /check with
rem /destination stop the run before anything is written, so a typo can't
rem silently fall back to a different mode than intended. /update (2.7.0)
rem goes with any mode and option: the updated script is started with the
rem same ones (:compose_update_arguments), and with nothing to update this
rem script carries on in that mode. /redraw <seconds> (2.7.0) sets the
rem live display's redraw interval (:check_redraw_argument). A path is
rem handled on a plain line, never inside a parenthesised block: a ")" in
rem it would close the block. shift /1 keeps %0 (this script's own path)
rem as it is.
set "run_mode=forensic"
set "run_kind=copy"
set "run_kind_switch="
set "update_requested="
set "argument_source="
set "argument_destination="
set "argument_yes_to_all="
set "argument_nopause="
set "argument_redraw_text="
set "argument_redraw_seconds="
set "relocation_chosen_at_destination="
set "relocation_how_text=/relocate"
set "argument_no_update_check="
set "argument_count=0"
set "argument_mode_count=0"
:parse_args_next
if "%~1"=="" goto parse_args_done
set /a "argument_count+=1"
if /i "%~1"=="/nonforensic" (set "run_mode=nonforensic" & set /a "argument_mode_count+=1" & goto parse_args_shift)
if /i "%~1"=="/update" (set "update_requested=1" & goto parse_args_shift)
if /i "%~1"=="/check" (set "run_kind=check" & set /a "argument_mode_count+=1" & goto parse_args_shift)
if /i "%~1"=="/relocate" (set "run_kind=relocate" & set /a "argument_mode_count+=1" & goto parse_args_shift)
if /i "%~1"=="/yes-to-all" (set "argument_yes_to_all=1" & goto parse_args_shift)
if /i "%~1"=="/nopause" (set "argument_nopause=1" & goto parse_args_shift)
if /i "%~1"=="/no-update-check" (set "argument_no_update_check=1" & goto parse_args_shift)
if /i "%~1"=="/redraw" goto parse_args_redraw
if /i "%~1"=="/source" goto parse_args_source
if /i "%~1"=="/destination" goto parse_args_destination
set "abort_reason=Unknown option: %~1. Run with /? for the options."
goto :abort
:parse_args_source
if defined argument_source (set "abort_reason=/source was given twice." & goto :abort)
if "%~2"=="" (set "abort_reason=/source needs a path after it (quoted)." & goto :abort)
set "argument_source=%~2"
shift /1
goto parse_args_shift
:parse_args_destination
if defined argument_destination (set "abort_reason=/destination was given twice." & goto :abort)
if "%~2"=="" (set "abort_reason=/destination needs a path after it (quoted)." & goto :abort)
set "argument_destination=%~2"
shift /1
goto parse_args_shift
:parse_args_redraw
if defined argument_redraw_text (set "abort_reason=/redraw was given twice." & goto :abort)
if "%~2"=="" (set "abort_reason=/redraw needs a number of seconds after it (1 to %DASHBOARD_REDRAW_MAX_SECONDS%)." & goto :abort)
set "argument_redraw_text=%~2"
shift /1
goto parse_args_shift
:parse_args_shift
shift /1
goto parse_args_next
:parse_args_done
if not "%run_kind%"=="copy" set "run_kind_switch=/%run_kind%"
if %argument_mode_count% gtr 1 (set "abort_reason=Only one of /nonforensic, /check and /relocate can be given." & goto :abort)
if defined update_requested if defined argument_no_update_check (set "abort_reason=/update and /no-update-check can't be given together." & goto :abort)
if "%run_kind%"=="check" if defined argument_destination (set "abort_reason=/check takes no /destination: the set is verified in place." & goto :abort)
if defined argument_redraw_text call :check_redraw_argument || goto :abort
set "header_confirmations=asked at the console"
if defined argument_yes_to_all set "header_confirmations=/yes-to-all: every question answered with its first choice (copy at the copy-or-relocate question)"
if "%run_mode%"=="forensic" (
    set "header_mode=forensic (default): log, SHA-256 verification and run records"
    set "mode_summary=forensic"
) else (
    set "header_mode=non-forensic (/nonforensic): plain copy, no log or records; not for evidence"
    set "mode_summary=non-forensic: not for evidence"
)
if "%run_kind%"=="check" set "header_mode=forensic check (/check): no copy; the set verified in place, with a run record"
if "%run_kind%"=="check" set "mode_summary=check (/check): no copy"
if "%run_kind%"=="relocate" set "header_mode=relocation (/relocate): the set moved within its volume, then verified in place, with a run record"
if "%run_kind%"=="relocate" set "mode_summary=relocation (/relocate)"
goto main_after_parse_args

:check_redraw_argument
rem /redraw's value (argument_redraw_text, as typed): a whole number of
rem seconds from 1 to DASHBOARD_REDRAW_MAX_SECONDS, into
rem argument_redraw_seconds; anything else is refused (exit 1, the reason
rem in abort_reason). Digits only, at most two, no leading zero (set /a
rem would read one as octal), then the range.
set "argument_redraw_seconds="
set "abort_reason=/redraw takes a whole number of seconds, 1 to %DASHBOARD_REDRAW_MAX_SECONDS%; given: %argument_redraw_text%"
setlocal
set "redraw_digits_only=1"
for /f "delims=0123456789" %%X in ("%argument_redraw_text%") do set "redraw_digits_only="
if not defined redraw_digits_only (endlocal & exit /b 1)
if not "%argument_redraw_text:~2%"=="" (endlocal & exit /b 1)
if "%argument_redraw_text:~0,1%"=="0" (endlocal & exit /b 1)
set /a "redraw_seconds=argument_redraw_text"
if %redraw_seconds% lss 1 (endlocal & exit /b 1)
if %redraw_seconds% gtr %DASHBOARD_REDRAW_MAX_SECONDS% (endlocal & exit /b 1)
endlocal & set "argument_redraw_seconds=%redraw_seconds%" & set "abort_reason="
exit /b 0

:compose_update_arguments
rem /update's hand-over (MAIN, 2.7.0): the mode and the options this run
rem was given, as the words of the updated script's command line, into
rem update_arguments: /nonforensic, /check or /relocate; /yes-to-all,
rem /nopause, /redraw <n>; /source "<path>" and /destination "<path>" as
rem given. Rebuilt from what the parser kept, never from the raw command
rem line; delayed expansion is off here, so "!" in a path survives; a "%"
rem in a path is not expanded again (a variable's value is taken as it
rem is). Each path sits inside its own quotes on every line that parses
rem it, so "&", "^" and ")" in it are text: the two path lines below, and
rem MAIN's carry across the endlocal, set the variable WITHOUT quotes
rem round the whole assignment (the readable "set "var=... "path""" form
rem would end its quoting at the path's first quote and leave the path
rem bare: round 14.4, a "&" ran the rest of the name as a command and a
rem "^" was dropped); each line ends at the path's closing quote, so no
rem trailing space is taken. /update itself is left out: the updated
rem script runs the mode, not another update.
set "update_arguments="
if "%run_mode%"=="nonforensic" set "update_arguments=%update_arguments% /nonforensic"
if not "%run_kind%"=="copy" set "update_arguments=%update_arguments% %run_kind_switch%"
if defined argument_yes_to_all set "update_arguments=%update_arguments% /yes-to-all"
if defined argument_nopause set "update_arguments=%update_arguments% /nopause"
if defined argument_redraw_seconds set "update_arguments=%update_arguments% /redraw %argument_redraw_seconds%"
if defined argument_source set update_arguments=%update_arguments% /source "%argument_source%"
if defined argument_destination set update_arguments=%update_arguments% /destination "%argument_destination%"
exit /b 0

:switch_console_to_utf8
rem Every record is UTF-8: switch the console to code page 65001 for the run.
rem :restore_console_code_page switches back on every exit. If the switch
rem can't be confirmed, the header says which code page was used and
rem :check_environment warns.
call :read_console_code_page original_code_page
"%tool_chcp%" 65001 >nul 2>&1 <nul
call :read_console_code_page console_code_page
set "header_encoding=UTF-8 (code page 65001)"
if not "%console_code_page%"=="65001" set "header_encoding=code page %console_code_page% (the switch to UTF-8 failed)"
exit /b 0

:read_console_code_page  outVar
rem The active console code page: the last number in chcp's output, in any
rem display language (e.g. "Active code page: 850." gives 850).
setlocal EnableDelayedExpansion
set "number="
for /f "tokens=*" %%L in ('2^>nul ^<nul "%tool_chcp%"') do for %%T in (%%L) do set "number=%%T"
if defined number set "number=!number:.=!"
if not defined number set "number=unknown"
endlocal & set "%~1=%number%"
exit /b 0

:restore_console_code_page
rem Switch the console back to the code page it had before the run.
if not defined original_code_page exit /b 0
if "%original_code_page%"=="unknown" exit /b 0
"%tool_chcp%" %original_code_page% >nul 2>&1 <nul
exit /b 0

:show_banner
echo Script: %TOOL_NAME%
echo Version: %TOOL_VERSION%
echo Author: outis
echo Licence: 0BSD
echo.
echo Tip: don't click inside this window while it runs: a QuickEdit selection
echo       pauses the copy until you press Esc.
echo.
exit /b 0

:check_realtime_scanning
rem A warning when Microsoft Defender's real-time protection is known to be
rem on (owner, 2026-10-20: a [WARN] up front, so it is in the header's
rem Warnings and the live display's list from the start). Best efforts: a
rem state that can't be read, or another antivirus, gives no warning.
call :read_defender_realtime_protection
if not defined defender_realtime_protection_on exit /b 0
set "msg=Microsoft Defender's real-time protection is on: it scans each file as it is written, which slows copies of many small files, and a file it quarantines fails verification as MISSING."
call :add_warning msg
exit /b 0

:read_defender_realtime_protection
rem Define defender_realtime_protection_on when Microsoft Defender's
rem real-time protection is taken as on (DEFENDER_* in CONFIG): its engine
rem running (the service, or else the process), and no row of
rem DEFENDER_OFF_VALUES reading 0x1 (a Policies row only while Tamper
rem Protection reads off). Read only; nothing is changed.
set "defender_realtime_protection_on="
setlocal EnableDelayedExpansion
set "engine_running="
if defined tool_sc for /f "tokens=2 delims=:" %%S in ('2^>nul ^<nul "%tool_sc%" query "!DEFENDER_SERVICE!"') do for /f "tokens=1" %%N in ("%%S") do if "%%N"=="4" set "engine_running=1"
rem Percent form on purpose: each side of a pipe runs in a new cmd without
rem delayed expansion (a CONFIG constant, no path).
if not defined engine_running "%tool_tasklist%" /fi "imagename eq %DEFENDER_ENGINE_PROCESS%" /fo csv /nh 2>nul <nul | "%tool_find%" /i "%DEFENDER_ENGINE_PROCESS%" >nul 2>&1 && set "engine_running=1"
if not defined engine_running (endlocal & exit /b 0)
set "tamper_protection_off="
for /f "tokens=3" %%V in ('2^>nul ^<nul "%tool_reg%" query "!DEFENDER_TAMPER_KEY!" /v "!DEFENDER_TAMPER_VALUE!"') do for %%D in (%DEFENDER_TAMPER_OFF_DATA%) do if /i "%%V"=="%%D" set "tamper_protection_off=1"
set "turned_off="
for %%R in (%DEFENDER_OFF_VALUES%) do (
    set "off_key=!DEFENDER_OFF_%%R_KEY!"
    set "off_value=!DEFENDER_OFF_%%R_VALUE!"
    set "off_row_counts=1"
    if /i "!DEFENDER_OFF_%%R_POLICY!"=="yes" if not defined tamper_protection_off set "off_row_counts="
    if defined off_row_counts for /f "tokens=3" %%V in ('2^>nul ^<nul "%tool_reg%" query "!off_key!" /v "!off_value!"') do if /i "%%V"=="0x1" set "turned_off=1"
)
if defined turned_off (endlocal & exit /b 0)
endlocal & set "defender_realtime_protection_on=1"
exit /b 0

:check_latest_release
rem Ask GitHub which release of this script is the latest (owner,
rem 2026-10-20: every run; never an automatic update): one header-only
rem request to UPDATE_LATEST_URL with curl.exe, which answers with a
rem redirect to the release's tag page (.../tag/v<version>); nothing is
rem downloaded and the API's rate limit doesn't apply. Best efforts within
rem UPDATE_CHECK_MAX_SECONDS: no curl.exe, no answer in time, or another
rem answer, and the run goes on with "not checked". Sets
rem latest_release_version and latest_release_tag (empty unless a version
rem was read), latest_release_order (the latest against this script: newer,
rem same or older), latest_release_text (the header's "Latest release"
rem field) and latest_release_warning (shown here at once, before the
rem prompts, and added to the warnings by :check_environment). curl's
rem output goes to a file and is read from there (nothing from the network
rem goes on a command line); the tag is used only once :parse_version has
rem accepted it as MAJOR.MINOR.PATCH. Since 2.8.0 this in-line check runs
rem only for /update, which needs the answer before the prompts; every
rem other run asks in the background (:start_latest_release_check) and
rem reads the answer before the header (:finish_latest_release_check), or
rem skips it (/no-update-check, :skip_latest_release_check). The answer is
rem read by :read_latest_release_answer in every case.
call :init_latest_release_texts || goto check_latest_release_done
"%tool_curl%" -s -S -I -o nul -w "%%{http_code} %%{redirect_url}" --connect-timeout %UPDATE_CHECK_MAX_SECONDS% --max-time %UPDATE_CHECK_MAX_SECONDS% "%UPDATE_LATEST_URL%" >"%temp_update_check%" 2>nul
set "latest_release_curl_exit=%errorlevel%"
call :read_latest_release_answer
:check_latest_release_done
if not defined latest_release_warning exit /b 0
set "msg=[WARN] %latest_release_warning%"
call :show msg
echo.
exit /b 0

:init_latest_release_texts
rem The update check's texts as "not checked", until an answer is read;
rem exit 1, the texts saying why, when curl.exe isn't there (no request is
rem made).
set "latest_release_version="
set "latest_release_tag="
set "latest_release_order="
set "latest_release_warning="
set "latest_release_text=not checked"
set "latest_release_summary=not checked"
set "latest_release_check_started="
if defined tool_curl exit /b 0
set "latest_release_text=not checked: curl.exe is not on this machine"
set "latest_release_warning=Update check: curl.exe is not on this machine, so whether a newer release of this script exists isn't known. The latest release is at %UPDATE_LATEST_URL%."
exit /b 1

:start_latest_release_check
rem The update check in the background (2.8.0; owner: no start-up delay,
rem the warning when the answer is known): a second instance of this script
rem (:update_check_main, told apart by evidence_robocopy_update_check
rem holding this run's answer file, which nothing else can hold; the script
rem named to the child cmd by variable, as the display helper is) asks
rem github.com while the prompts are answered. :finish_latest_release_check
rem reads the answer before the header is written. The texts start as "not
rem checked", in case the answer never comes.
call :init_latest_release_texts || exit /b 0
del "%temp_update_check%" "%temp_update_check_done%" >nul 2>&1
set "evidence_robocopy_update_check=%temp_update_check%"
set "evidence_robocopy_update_check_script=%script_path%"
start "" /b "%ComSpec%" /d /v:off /c ""%%evidence_robocopy_update_check_script%%""
set "evidence_robocopy_update_check="
set "evidence_robocopy_update_check_script="
set "latest_release_check_started=1"
exit /b 0

:skip_latest_release_check
rem /no-update-check (2.8.0; owner): no request to github.com; the header
rem says so, with no warning.
call :init_latest_release_texts
set "latest_release_warning="
set "latest_release_text=not checked (/no-update-check)"
set "latest_release_summary=not checked (/no-update-check)"
exit /b 0

:finish_latest_release_check
rem Caller's scope (:check_environment, before the header is written). The
rem background check's answer (:update_check_main), waited for up to
rem UPDATE_CHECK_WAIT_SECONDS if it isn't in yet (curl gives up after
rem UPDATE_CHECK_MAX_SECONDS), read as the in-line check reads it; with no
rem answer by then, "not checked" and its warning. Nothing to do when the
rem check ran in line (/update) or was skipped (/no-update-check).
if not defined latest_release_check_started exit /b 0
set "latest_release_check_started="
for /l %%W in (1,1,%UPDATE_CHECK_WAIT_SECONDS%) do if not exist "%temp_update_check_done%" "%tool_ping%" -n 2 127.0.0.1 >nul
set "latest_release_curl_exit="
if exist "%temp_update_check_done%" for /f "usebackq" %%E in ("%temp_update_check_done%") do set "latest_release_curl_exit=%%E"
if defined latest_release_curl_exit call :read_latest_release_answer & exit /b 0
set "latest_release_text=not checked: github.com didn't answer within %UPDATE_CHECK_WAIT_SECONDS% s"
set "latest_release_warning=Update check: github.com didn't answer within %UPDATE_CHECK_WAIT_SECONDS% s (offline, a proxy, or a slow link), so whether a newer release of this script exists isn't known."
exit /b 0

:read_latest_release_answer
rem The update check's answer: github.com's reply in temp_update_check
rem ("<HTTP code> <redirect URL>", curl's -w output) and curl's exit code in
rem latest_release_curl_exit, into the latest_release_* texts (the comment
rem of :check_latest_release). Nothing from the network goes on a command
rem line; the tag is used only once :parse_version has accepted it.
set "latest_release_http_code="
set "latest_release_location="
if exist "%temp_update_check%" for /f "usebackq tokens=1,*" %%A in ("%temp_update_check%") do (
    set "latest_release_http_code=%%A"
    set "latest_release_location=%%B"
)
if not "%latest_release_curl_exit%"=="0" (
    set "latest_release_text=not checked: github.com didn't answer within %UPDATE_CHECK_MAX_SECONDS% s (curl exit code %latest_release_curl_exit%)"
    set "latest_release_warning=Update check: github.com couldn't be reached within %UPDATE_CHECK_MAX_SECONDS% s (curl exit code %latest_release_curl_exit%: offline, a proxy, or a slow link), so whether a newer release of this script exists isn't known."
    exit /b 0
)
rem The tag is the last part of the redirect's URL ("v2.4.0").
if "%latest_release_http_code%"=="302" if defined latest_release_location for %%P in ("%latest_release_location%") do set "latest_release_tag=%%~nxP"
if defined latest_release_tag if "%latest_release_tag:~0,1%"=="v" set "latest_release_version=%latest_release_tag:~1%"
if defined latest_release_version call :parse_version latest_release_version latest_release || set "latest_release_version="
if not defined latest_release_version (
    set "latest_release_tag="
    set "latest_release_text=not checked: github.com's answer named no release (HTTP %latest_release_http_code%)"
    set "latest_release_warning=Update check: github.com answered, but not with a release (HTTP %latest_release_http_code%: a captive portal or a proxy page?), so whether a newer release of this script exists isn't known."
    exit /b 0
)
call :parse_version TOOL_VERSION this_version
call :compare_versions latest_release this_version latest_release_order
set "latest_release_text=%latest_release_version%: this script is the latest release"
set "latest_release_summary=%latest_release_version% (this script)"
if "%latest_release_order%"=="newer" (
    set "latest_release_text=%latest_release_version%, newer than this script (see Warnings)"
    set "latest_release_summary=%latest_release_version% (newer than this)"
    set "latest_release_warning=A newer release of this script is published: version %latest_release_version% (this is %TOOL_VERSION%). Run it with /update to replace this file with the latest release, or download it from %UPDATE_LATEST_URL%."
)
if "%latest_release_order%"=="older" (
    set "latest_release_text=%latest_release_version%; this script (%TOOL_VERSION%) is newer: not a published release"
    set "latest_release_summary=%latest_release_version% (this is newer)"
    set "latest_release_warning=This script's version (%TOOL_VERSION%) is newer than the latest published release (%latest_release_version%): it is not a published release."
)
exit /b 0

:prepare_update
rem /update (owner, 2026-10-20): prepare to replace this script's file with
rem the latest release when :check_latest_release found a newer one, then
rem start the new file in this console with no arguments (a normal run) and
rem end with its exit code. Otherwise say so and return: the run goes on
rem with this script. Nothing of it reaches a record (records are for the
rem evidence). The release's script and its SHA-256 file
rem (UPDATE_HASH_ASSET_NAME, published with every release from 2.4.0 on)
rem are downloaded into a directory of their own in TEMP; the download
rem replaces this file only when its SHA-256 is the published one and its
rem version line reads the release's version. The replacement and the
rem start of the new file are MAIN's (see there, "update_ready"): this
rem helper only prepares and checks. The hashing and reading helpers write
rem their working files under the run's temporary names, which :init_run
rem sets later: for this step they go into the update directory.
set "update_ready="
rem The section opens as every section does, less its empty line: the
rem elevation notice and the update check's [WARN] before it each end with
rem one (round 12.12: two empty lines).
set "section_line=%RULE_LIGHT%"
call :emit_line section_line console
set "heading=Update: replacing this script with the latest release"
call :emit_free_text heading console
if not defined latest_release_version (
    set "msg=[WARN] Update: the latest release couldn't be determined (see above), so nothing is replaced. Carrying on with this script (version %TOOL_VERSION%)."
    call :show msg
    echo.
    exit /b 0
)
if not "%latest_release_order%"=="newer" (
    set "msg=Nothing to update: this script (version %TOOL_VERSION%) is the latest release. Carrying on."
    if "%latest_release_order%"=="older" set "msg=Nothing to update: this script (version %TOOL_VERSION%) is newer than the latest release (%latest_release_version%). Carrying on."
    call :show msg
    echo.
    exit /b 0
)
call :choose_temp_dir || (
    set "update_problem=no temporary directory (TEMP, TMP or LOCALAPPDATA\Temp) for the download"
    goto update_failed
)
set "update_dir=%temp_dir%\%TOOL_NAME%_update_%RANDOM%"
set "update_download_path=%update_dir%\%UPDATE_ASSET_NAME%"
set "update_hash_path=%update_dir%\%UPDATE_HASH_ASSET_NAME%"
mkdir "%update_dir%" >nul 2>&1
call :is_directory update_dir || (
    set "update_problem=a directory for the download couldn't be made in TEMP"
    goto update_failed
)
set "temp_certutil_output=%update_dir%\certutil.tmp"
set "temp_custody_copy=%update_dir%\custody_copy.tmp"
set "temp_record_match=%update_dir%\record_match.tmp"
set "msg=Latest release: %latest_release_version% (this script is %TOOL_VERSION%). Downloading it from %UPDATE_DOWNLOAD_URL%/%latest_release_tag%/ ..."
call :show msg
"%tool_curl%" -s -S -L -f -o "%update_download_path%" --connect-timeout %UPDATE_CHECK_MAX_SECONDS% --max-time %UPDATE_DOWNLOAD_MAX_SECONDS% "%UPDATE_DOWNLOAD_URL%/%latest_release_tag%/%UPDATE_ASSET_NAME%" 2>nul
set "update_curl_exit=%errorlevel%"
if not "%update_curl_exit%"=="0" (
    set "update_problem=the download of %UPDATE_ASSET_NAME% failed (curl exit code %update_curl_exit%)"
    goto update_failed
)
"%tool_curl%" -s -S -L -f -o "%update_hash_path%" --connect-timeout %UPDATE_CHECK_MAX_SECONDS% --max-time %UPDATE_DOWNLOAD_MAX_SECONDS% "%UPDATE_DOWNLOAD_URL%/%latest_release_tag%/%UPDATE_HASH_ASSET_NAME%" 2>nul
set "update_curl_exit=%errorlevel%"
if not "%update_curl_exit%"=="0" (
    set "update_problem=the release's SHA-256 file (%UPDATE_HASH_ASSET_NAME%) couldn't be downloaded, so the download can't be checked (curl exit code %update_curl_exit%)"
    goto update_failed
)
rem The published SHA-256: the first word of the file, as sha256sum writes
rem it ("<sha256> *<name>"); record content is data (:clean_sha256_from_record).
set "update_published_sha256="
for /f "usebackq tokens=1" %%H in ("%update_hash_path%") do if not defined update_published_sha256 set "update_published_sha256=%%H"
call :clean_sha256_from_record update_published_sha256
if not defined update_published_sha256 (
    set "update_problem=%UPDATE_HASH_ASSET_NAME% doesn't hold a SHA-256"
    goto update_failed
)
set "update_download_sha256="
call :get_sha256 update_download_path update_download_sha256
if /i not "%update_download_sha256%"=="%update_published_sha256%" (
    set "update_problem=the download's SHA-256 (%update_download_sha256%) isn't the published one (%update_published_sha256%)"
    goto update_failed
)
set "update_download_version="
call :read_script_version update_download_path update_download_version
if not "%update_download_version%"=="%latest_release_version%" (
    set "update_problem=the download's version line reads %update_download_version%, not %latest_release_version%"
    goto update_failed
)
set "msg=Downloaded and checked: its SHA-256 is the published one (%update_published_sha256%) and its version line reads %latest_release_version%."
call :show msg
set "msg=Replacing %script_path% and starting the updated script with this run's mode and options; its output follows."
call :show msg
echo.
set "update_ready=1"
exit /b 0
:update_replace_failed
rem Reached from MAIN's block when the copy failed (the file is unchanged):
rem the warning, then the normal run from where MAIN left off.
set "update_problem=this script's file (%script_path%) couldn't be replaced: read-only, open in another program, or no permission to write it"
call :report_update_failure
if "%run_mode%"=="nonforensic" goto :main_nonforensic
goto main_after_update
:update_failed
call :report_update_failure
exit /b 0

:report_update_failure
rem The [WARN] for an update that didn't happen (update_problem); what was
rem downloaded is left in the update directory, when there is one.
set "msg=[WARN] Update: %update_problem%. Nothing was replaced; carrying on with this script (version %TOOL_VERSION%)."
if defined update_dir if exist "%update_dir%\" set "msg=%msg% What was downloaded is kept in %update_dir%."
call :show msg
echo.
exit /b 0

:detect_elevation
rem Elevated if any check in ELEVATION_CHECKS succeeds; unknown counts as not
rem elevated. An elevated run uses robocopy's backup mode (/b).
set "is_elevated="
set "elevation_detected_by=none"
for %%M in (%ELEVATION_CHECKS%) do if not defined is_elevated call :elevation_check_%%M && (
    set "is_elevated=1"
    set "elevation_detected_by=%%M"
)
rem The notice is an [INFO] line (owner, 2026-10-20: the analyst should be
rem aware; neither state is preferred), its tag coloured on the console.
if defined is_elevated (
    set "backup_flag=/b"
    set "header_elevated=yes (detected by %elevation_detected_by%), backup mode /b"
    set "elevated_summary=yes (backup mode /b)"
    set "msg=[INFO] Running as administrator: backup mode (/b) lets robocopy read files regardless of their permissions, but may be slower."
) else (
    set "backup_flag="
    set "header_elevated=no"
    set "elevated_summary=no"
    set "msg=[INFO] Not running as administrator: files your account can't read will fail to copy."
)
set "elevation_noted=1"
call :show msg
echo.
exit /b 0

:elevation_check_fsutil
"%tool_fsutil%" dirty query %SystemDrive% >nul 2>&1 <nul
exit /b %errorlevel%

:elevation_check_net
"%tool_net%" session >nul 2>&1
exit /b %errorlevel%

:use_log_mode
rem Keep a log file. /np /tee: no progress figures, output to console and log.
rem With the live display (dashboard_mode live, :init_dashboard) robocopy's
rem console output goes to nul: robocopy_console_redirection holds that
rem redirection, put on every robocopy line as
rem %robocopy_console_redirection%: the percent form, because a redirection
rem is parsed after percent expansion and before delayed expansion; empty,
rem it is nothing. /tee stays, so robocopy writes its log as in a plain run
rem (without /tee it wrote " Retrying..." where a plain run's log didn't:
rem round 12.2). A pass marked PASS_<id>_PERCENTAGES=yes then runs without
rem /np (:run_copy_pass): robocopy's percentage within each of its files is
rem shown live and left out of the log (:save_robocopy_unicode_output).
set "log_enabled=1"
set "robocopy_progress_flags=/np /tee"
set "robocopy_console_redirection="
set "header_progress=log file (/np /tee)"
if not "%dashboard_mode%"=="live" exit /b 0
set "robocopy_console_redirection=>nul"
set "header_progress=log file (/np /tee, the console copy discarded); a live display on the console (redrawn every %redraw_interval_seconds% s), not in the log"
call :describe_percentage_passes
if defined percentage_pass_labels set "header_progress=%header_progress%; %percentage_pass_labels% copied without /np: the percentage within each file shown live, left out of the log"
exit /b 0

:describe_percentage_passes
rem The labels of the passes marked PASS_<id>_PERCENTAGES=yes, comma
rem separated, into percentage_pass_labels (empty if none).
setlocal EnableDelayedExpansion
set "labels="
for %%P in (%COPY_PASSES%) do if /i "!PASS_%%P_PERCENTAGES!"=="yes" set "labels=!labels!, !PASS_%%P_LABEL!"
if defined labels set "labels=!labels:~2!"
endlocal & set "percentage_pass_labels=%labels%"
exit /b 0

:confirm_nonforensic
rem /nonforensic is for non-evidence copies; choosing it must be confirmed.
echo NON-FORENSIC MODE: a plain copy with its progress on screen. No log and
echo   no records are kept, and custody files and histories are copied like
echo   any other file: not for evidence.
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
rem Non-forensic run: no log file is kept (not a custody record). With the
rem plain output robocopy shows its ETA and percentage (/eta) on the
rem console. With the live display (2.7.0) robocopy writes its output to
rem the run's temporary file in TEMP instead (/unilog, as a forensic run's
rem passes do: :run_copy_pass), which the display helper reads for the
rem copy's progress and :cleanup_temp deletes at the end (the watchdog
rem after a Ctrl+C); its console output goes to nul (it would paint over
rem the display) and /np leaves out the percentages the display shows
rem itself (a pass marked PASS_<id>_PERCENTAGES runs without it, as in a
rem forensic run). Nothing of it is kept.
set "log_enabled=0"
set "robocopy_progress_flags=/eta"
set "robocopy_console_redirection="
set "header_progress=ETA and percentage, no log file (/eta): not a custody record"
if not "%dashboard_mode%"=="live" exit /b 0
set "robocopy_progress_flags=/np"
set "robocopy_console_redirection=>nul"
set "header_progress=a live display on the console (redrawn every %redraw_interval_seconds% s), its copy progress read from a temporary file in TEMP that is deleted at the end; no log file: not a custody record"
call :describe_percentage_passes
if defined percentage_pass_labels set "header_progress=%header_progress%; %percentage_pass_labels% copied without /np: the percentage within each file shown live"
exit /b 0

rem -- Set and evidence directories --------------------------------------------

:ask_source_set
rem Ask for the source and work out the set (rules S1-S4; README, "Set and
rem evidence directories"). Sets source_path / source_with_backslash (the
rem evidence directory robocopy copies from), source_set_path /
rem source_set_with_backslash (empty for raw evidence), evidence_directory_name,
rem set_directory_name and source_set_rule.
call :find_default_source_set
set "source_set_rejected_answers=0"
rem The first prompt follows the elevation notice's blank line; a retry
rem gets one of its own after the refusal (round 12.10: two blank lines
rem once the line between them had gone).
goto ask_source_set_prompt
:ask_source_set_again
echo.
:ask_source_set_prompt
call :ask_directory source_given "SOURCE directory" 1 1 || exit /b 1
call :identify_source_set && call :accept_source_for_run_kind && exit /b 0
call :show identify_problem
if defined argument_source (set "abort_reason=The source given on the command line was refused (see above)." & exit /b 1)
call :count_rejected_answer source_set_rejected_answers "source directory" || exit /b 1
goto ask_source_set_again

:accept_source_for_run_kind
rem Caller's scope (:ask_source_set), after the set rules accepted the
rem answer: a check or a relocation takes a set (S1, S2 or S3), never raw
rem evidence (nothing to verify against; a first copy makes the record); a
rem relocation never takes the set this script runs from (cmd reads this
rem file as it goes: moving the set would move the file being read). Sets
rem identify_problem and exits 1 otherwise.
if "%run_kind%"=="copy" exit /b 0
if not defined source_set_path (
    set "identify_problem=%run_kind_switch% takes a set (its set directory, or its evidence directory): this is raw evidence (no custody files here or in the directory above), with no record to verify against. A first copy makes one."
    exit /b 1
)
if not "%run_kind%"=="relocate" exit /b 0
call :script_is_inside_set || exit /b 0
set "identify_problem=/relocate can't move the set this script runs from (%script_dir%): run a copy of the script from somewhere else."
exit /b 1

:script_is_inside_set
rem Exit 0 if this script's directory is the source set directory or inside
rem it (the paths compared by prefix, ignoring case).
setlocal EnableDelayedExpansion
set "script_dir_test=!script_dir!"
call :strlen source_set_with_backslash set_length
for %%N in (!set_length!) do if /i "!script_dir_test:~0,%%N!"=="!source_set_with_backslash!" (endlocal & exit /b 0)
endlocal & exit /b 1

:confirm_check_in_place
rem /check, once the set is known: a check writes a run record and a
rem history row into the set it checks (owner, 2026-10-20: an unrecorded
rem verification has no custody value), the one thing a forensic run ever
rem writes into the set it was given; confirmed before anything else. The
rem set then stands in for the destination (:take_set_as_destination).
echo.
set "msg=This verifies the set in place: %source_set_path%" & call :show msg
echo A run record is added and the history updated; the evidence and the
echo   earlier records are left as they are, and nothing is copied.
echo 1. Verify it and record the check
echo 2. Stop
call :ask_choice check_answer "1 2" || exit /b 1
if "%check_answer%"=="2" (
    set "abort_reason=Stopped at the user's choice."
    exit /b 1
)
call :take_set_as_destination
exit /b 0

:take_set_as_destination
rem Caller's scope (/check): the set at source_set_path is where this run's
rem record goes, so the destination's names point at it and the
rem verification, the run record and the history are written as for a copy
rem into this set (:verify_copy and :publish_records read the destination's
rem names). A relocation points them at the set's new location instead
rem (:ask_relocation_target).
set "destination_set_path=%source_set_path%"
set "destination_set_with_backslash=%source_set_with_backslash%"
set "destination_path=%source_path%"
set "destination_with_backslash=%source_with_backslash%"
set "destination_set_rule=the set itself, verified in place (%run_kind_switch%)"
set "destination_was_empty=0"
set "destination_state_text=this set, verified in place: nothing copied (%run_kind_switch%)"
exit /b 0

:ask_relocation_target
rem /relocate, once the set is known: where to move it (a full path that
rem doesn't exist yet, in a directory that does, on the set's own volume:
rem a move within a volume is a rename, instant and done or not; across
rem volumes it would be a copy, which is what a copy run is for),
rem confirmed. Sets relocate_from_path / _with_backslash (the set's path
rem now) and relocate_target_path / _with_backslash, and points the
rem destination's names at the new location: the run record goes into the
rem moved set (:init_run names it; the move itself comes after the checks
rem that read the set where it is: :relocate_set).
set "relocate_from_path=%source_set_path%"
set "relocate_from_with_backslash=%source_set_with_backslash%"
set "relocate_rejected_answers=0"
:ask_relocation_target_again
echo.
call :ask_directory relocate_target "NEW LOCATION of the set (a full path)" 0 0 || exit /b 1
call :check_relocation_target || (
    call :show identify_problem
    if defined argument_destination set "abort_reason=The new location given on the command line was refused (see above)." & if defined argument_destination exit /b 1
    call :count_rejected_answer relocate_rejected_answers "new location" || exit /b 1
    goto ask_relocation_target_again
)
echo.
set "msg=This moves the set %relocate_from_path% to %relocate_target_path%. The set is then verified at its new location, and the move is recorded in it."
call :show msg
echo 1. Move it
echo 2. Stop
call :ask_choice relocate_answer "1 2" || exit /b 1
if "%relocate_answer%"=="2" (
    set "abort_reason=Stopped at the user's choice."
    exit /b 1
)
set "destination_set_path=%relocate_target_path%"
set "destination_set_with_backslash=%relocate_target_with_backslash%"
set "destination_path=%relocate_target_with_backslash%%evidence_directory_name%"
set "destination_with_backslash=%destination_path%\"
set "destination_set_rule=the set's new location (/relocate)"
set "destination_was_empty=0"
set "destination_state_text=the set's new location: moved here by this run from %relocate_from_path% (/relocate)"
exit /b 0

:check_relocation_target
rem Caller's scope (:ask_relocation_target), for relocate_target_path: it
rem must not exist, its directory must, it must not be inside the set (nor
rem the set inside it), and it must be on the set's volume (the volume
rem serial of both; a network path's can't be read, so a set on one isn't
rem moved by this script). Sets identify_problem and exits 1 otherwise;
rem relocate_from_serial is kept for the record of the move.
set "identify_problem="
if exist "%relocate_target_path%" (
    set "identify_problem=The new location already exists: give a path that doesn't exist yet (the set is moved there, under that name)."
    exit /b 1
)
set "normalise_path_input=%relocate_target_path%\.."
call :normalise_path || (
    set "identify_problem=The new location's directory couldn't be worked out."
    exit /b 1
)
set "relocate_target_parent_path=%normalise_path_result%"
set "relocate_target_parent_with_backslash=%normalise_path_with_backslash%"
call :is_directory relocate_target_parent_with_backslash || (
    set "identify_problem=The new location's directory doesn't exist: %relocate_target_parent_path%"
    exit /b 1
)
set "overlap_first_with_backslash=%relocate_from_with_backslash%"
set "overlap_second_with_backslash=%relocate_target_with_backslash%"
call :paths_overlap && (
    set "identify_problem=The new location is inside the set, or the set would be inside it: a set can't be moved into itself."
    exit /b 1
)
call :describe_volume "%relocate_from_path:~0,2%" relocate_from_volume_text relocate_from_filesystem relocate_from_serial relocate_from_volume_label_and_filesystem
call :describe_volume "%relocate_target_path:~0,2%" relocate_target_volume_text relocate_target_filesystem relocate_target_serial relocate_target_volume_label_and_filesystem
if "%relocate_from_serial%"=="n/a" (
    set "identify_problem=The set is on a network path, whose volume can't be read: /relocate moves a set within one volume only."
    exit /b 1
)
if "%relocate_target_serial%"=="n/a" (
    set "identify_problem=The new location is on a network path, whose volume can't be read: /relocate moves a set within one volume only."
    exit /b 1
)
if "%relocate_from_serial%"=="unknown" (
    set "identify_problem=The set's volume serial couldn't be read, so the move can't be confirmed to stay on one volume."
    exit /b 1
)
if /i not "%relocate_from_serial%"=="%relocate_target_serial%" (
    set "identify_problem=The new location is on another volume (serial %relocate_target_serial%; the set's is %relocate_from_serial%): /relocate moves a set within one volume only. To put a set on another volume, copy it there."
    exit /b 1
)
exit /b 0

:require_reference_record
rem A check or a relocation, once the history is read: the set must name a
rem reference record (row 1 of a usable history) to verify against; without
rem one the set's own files would be hashed as the reference and the
rem verification would pass vacuously (unknown is not passed). A set with
rem run records but no usable history has none either. Before a relocation
rem moves anything: the set stays where it is.
if defined reference_run exit /b 0
set "abort_reason=The set has no reference record to verify against (no usable history naming its first run's hash record), so %run_kind_switch% can't verify it. A first copy of the evidence makes a reference record."
if "%run_kind%"=="relocate" set "abort_reason=%abort_reason% The set wasn't moved."
exit /b 1

:relocate_set
rem /relocate, after every check that reads the set at its old path: move
rem the set, one rename within its volume (done or not), then point the run
rem at its new path: the source names (the set is this run's source too)
rem and the history this run continues; the destination names already name
rem the new location. A move that fails leaves the set where it was, and
rem the run stops with the reason; a state the move shouldn't leave (both
rem paths present, or neither) stops it too, for the user to look at before
rem anything else. The move is recorded in the run record
rem (:write_relocation_record), sealed with it.
set "msg=Moving %relocate_from_path% to %relocate_target_path% ..."
call :show msg
move "%relocate_from_path%" "%relocate_target_path%" >nul 2>&1
set "relocate_move_exit_code=%errorlevel%"
set "relocate_old_present="
set "relocate_new_present="
call :is_directory relocate_from_with_backslash && set "relocate_old_present=1"
call :is_directory relocate_target_with_backslash && set "relocate_new_present=1"
if defined relocate_old_present if not defined relocate_new_present (
    set "abort_reason=The set couldn't be moved (move's exit code %relocate_move_exit_code%: a file in it may be open, or the new location may not be writable). Nothing was changed: the set is still at %relocate_from_path%."
    exit /b 1
)
if defined relocate_old_present if defined relocate_new_present (
    set "abort_reason=After the move both %relocate_from_path% and %relocate_target_path% exist: check both before doing anything else. Nothing of this run is recorded."
    exit /b 1
)
if not defined relocate_new_present (
    set "abort_reason=After the move neither %relocate_from_path% nor %relocate_target_path% holds the set: check the volume before doing anything else. Nothing of this run is recorded."
    exit /b 1
)
set "msg=Moved. The set is verified at its new location below."
call :show msg
for %%V in (source_set_path source_set_with_backslash source_path source_with_backslash history_base_path history_base_set_with_backslash source_history_path) do call :repoint_relocated_path %%V
call :write_relocation_record
exit /b 0

:repoint_relocated_path  pathVar
rem (:relocate_set) If the variable holds the set's old path, or a path
rem inside it, replace that part with the new location. Delayed expansion
rem off at the hand-back, so "!" and "%" in the path survive.
setlocal EnableDelayedExpansion
set "value=!%~1!"
set "value_with_backslash=!value!\"
set "repointed="
if /i "!value_with_backslash!"=="!relocate_from_with_backslash!" set "repointed=!relocate_target_path!"
if /i "!value!"=="!relocate_from_with_backslash!" set "repointed=!relocate_target_with_backslash!"
if not defined repointed call :relative_path value relocate_from_with_backslash value_rest && set "repointed=!relocate_target_with_backslash!!value_rest!"
if not defined repointed (endlocal & exit /b 0)
endlocal & set "%~1=%repointed%"
exit /b 0

:write_relocation_record
rem /relocate, after the move: the record of it, a file of its own in this
rem run's record (staged_relocation_path, sealed with the others: a later
rem 2.x adds information as new files in the run record, contract), saying
rem what was moved, from where to where, when, by whom and on what. The
rem history row has the old path as the source and the new as the
rem destination; this file says the row records a move, not a copy. Each
rem line through :append_line_to_file (a path may hold "!" or "&").
set "staged_relocation_path=%staged_records_dir%\%record_file_stem%_relocation.txt"
call :describe_user relocation_user
call :describe_host relocation_host
type nul >"%staged_relocation_path%"
set "relocation_line=Relocation: the set was moved within its volume, not copied (%relocation_how_text%)."
call :append_line_to_file relocation_line staged_relocation_path
set "relocation_line=  Moved by      : %TOOL_NAME% %TOOL_VERSION%"
call :append_line_to_file relocation_line staged_relocation_path
set "relocation_line=  From          : %relocate_from_path%"
call :append_line_to_file relocation_line staged_relocation_path
set "relocation_line=  To            : %relocate_target_path%"
call :append_line_to_file relocation_line staged_relocation_path
set "relocation_line=  When (UTC)    : %start_utc_iso%"
call :append_line_to_file relocation_line staged_relocation_path
set "relocation_line=  By            : %relocation_user%"
call :append_line_to_file relocation_line staged_relocation_path
set "relocation_line=  On            : %relocation_host%"
call :append_line_to_file relocation_line staged_relocation_path
set "relocation_line=  Volume serial : %relocate_from_serial%"
call :append_line_to_file relocation_line staged_relocation_path
exit /b 0

:find_default_source_set
rem S1: offer the script's own directory for Enter when it is a set directory
rem with exactly one evidence directory and nothing unexpected.
set "default_source_path="
set "normalise_path_input=%script_dir%"
call :normalise_path || exit /b 0
set "inspect_directory_with_backslash=%normalise_path_with_backslash%"
call :inspect_set_directory
if defined inspect_unreadable exit /b 0
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
rem and exit 1 if not. role: source or destination, for the message. A
rem directory that couldn't be listed is refused first: nothing is known
rem about what it holds.
if defined inspect_unreadable call :refuse_unlistable_directory "The %~1 set directory" || exit /b 1
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
    if defined argument_destination set "abort_reason=The destination given on the command line was refused (see above)." & if defined argument_destination exit /b 1
    call :count_rejected_answer destination_set_rejected_answers "destination directory" || exit /b 1
    goto ask_destination_set_again
)
set "overlap_first_with_backslash=%source_with_backslash%"
if defined source_set_with_backslash set "overlap_first_with_backslash=%source_set_with_backslash%"
set "overlap_second_with_backslash=%destination_set_with_backslash%"
call :paths_overlap && (
    echo Source and destination must not be the same, or inside each other.
    if defined argument_destination set "abort_reason=The source and the destination given on the command line are the same, or inside each other." & if defined argument_destination exit /b 1
    call :count_rejected_answer destination_set_rejected_answers "destination directory" || exit /b 1
    goto ask_destination_set_again
)
if "%destination_was_empty%"=="1" (
    call :offer_relocation_instead_of_copy || exit /b 1
    exit /b 0
)
echo.
echo The destination already holds this set (a rerun or an update): files
echo   that differ are copied again, and every file is verified.
echo 1. Continue with this destination
echo 2. Enter a different destination
call :ask_choice destination_answer "1 2" || exit /b 1
rem Answer 2 with the destination given on the command line would ask the
rem same destination again: the run stops instead.
if "%destination_answer%"=="2" if defined argument_destination (
    set "abort_reason=Stopped at the user's choice: the destination given on the command line was not accepted."
    exit /b 1
)
if "%destination_answer%"=="2" goto ask_destination_set_again
exit /b 0

:offer_relocation_instead_of_copy
rem Caller's scope (:ask_destination_set), once a new destination set is
rem settled (2.6.0, owner): when the source is a set (S2 or S3; not S1 and
rem not the set this script runs from: cmd reads this file as it goes) and
rem the new set would be on the same volume (the volume serials match; a
rem network path has none), the set can be moved there instead of copied.
rem Asked once: Enter or "copy" keeps the copy (so an answer file that ends
rem here keeps working: set /p at the end of input leaves the answer
rem empty; /yes-to-all takes copy too); the word "relocate", typed in full,
rem turns this run into a relocation and is its confirmation (the owner:
rem the word, typed or as the /relocate option, leaves no doubt of the
rem intention). Its target is the set directory the copy would have used:
rem D4's (made by the copy, so it doesn't exist yet) or, where the directory
rem given is empty or holds only an empty evidence-named directory (D3), or
rem is itself an empty evidence-named directory in an otherwise empty one
rem (D2), those empty directories are removed and the set moved to the set
rem directory's name: the same paths a copy accepts. Then checked as
rem /relocate checks a target. A drive root as the set directory is never
rem asked (it can't be removed). Exit 1 (with abort_reason) when the
rem answers run out, the directory can't be removed or the target is
rem refused.
if not "%run_kind%"=="copy" exit /b 0
if not defined source_set_path exit /b 0
if defined default_source_taken exit /b 0
call :script_is_inside_set && exit /b 0
if not "%source_set_path:~1,1%"==":" exit /b 0
if not "%destination_set_path:~1,1%"==":" exit /b 0
call :is_drive_root destination_set_with_backslash && exit /b 0
call :describe_volume "%source_set_path:~0,2%" offer_source_volume_text offer_source_filesystem offer_source_serial offer_source_label_and_filesystem
call :describe_volume "%destination_set_path:~0,2%" offer_destination_volume_text offer_destination_filesystem offer_destination_serial offer_destination_label_and_filesystem
if "%offer_source_serial%"=="n/a" exit /b 0
if "%offer_source_serial%"=="unknown" exit /b 0
if /i not "%offer_source_serial%"=="%offer_destination_serial%" exit /b 0
echo.
set "msg=The destination is on the source set's volume (%offer_source_label_and_filesystem%; serial %offer_source_serial%): the set can be copied there, or moved there without copying (a relocation, recorded as /relocate records it, so later copies don't warn that it was moved)."
call :show msg
echo Press Enter (or type copy) to copy; type relocate to move it.
if defined argument_yes_to_all (
    echo ^> copy ^(answered by /yes-to-all^)
    exit /b 0
)
set "offer_relocation_attempts=0"
:offer_relocation_ask
set /a "offer_relocation_attempts+=1"
if %offer_relocation_attempts% gtr %MAX_PROMPT_ATTEMPTS% (
    set "abort_reason=No valid answer after %MAX_PROMPT_ATTEMPTS% attempts (no console input?)."
    exit /b 1
)
set "offer_relocation_answer="
set /p "offer_relocation_answer=> "
if not defined offer_relocation_answer exit /b 0
if /i "%offer_relocation_answer%"=="copy" exit /b 0
if /i "%offer_relocation_answer%"=="relocate" goto offer_relocation_move
echo Invalid input: press Enter, or enter copy or relocate
goto offer_relocation_ask
:offer_relocation_move
rem The empty directories (an empty evidence-named one inside, then the
rem set directory itself: D2 and D3; D4's doesn't exist yet) are removed
rem with rd, which fails on anything else.
if exist "%destination_set_with_backslash%%evidence_directory_name%\" rd "%destination_set_with_backslash%%evidence_directory_name%" >nul 2>&1
if exist "%destination_set_with_backslash%" rd "%destination_set_path%" >nul 2>&1
if exist "%destination_set_with_backslash%" (
    set "abort_reason=The destination directory %destination_set_path% couldn't be removed to make room for the move (it holds something, or it is in use). The set wasn't moved and nothing was copied: check the directory before trying again."
    exit /b 1
)
set "relocate_from_path=%source_set_path%"
set "relocate_from_with_backslash=%source_set_with_backslash%"
set "relocate_target_path=%destination_set_path%"
set "relocate_target_with_backslash=%destination_set_with_backslash%"
call :check_relocation_target || (
    call :show identify_problem
    set "abort_reason=The set can't be moved there (see above): nothing was changed."
    exit /b 1
)
set "run_kind=relocate"
set "run_kind_switch=/relocate"
set "relocation_chosen_at_destination=1"
set "relocation_how_text=relocate, typed at the destination prompt of a copy run"
set "header_mode=relocation (chosen at the destination prompt): the set moved within its volume, then verified in place, with a run record"
set "mode_summary=relocation (chosen at the prompt)"
set "destination_set_rule=the set's new location (a relocation chosen at the destination prompt; the copy's %destination_layout_rule_id% set directory)"
set "destination_state_text=the set's new location: moved here by this run from %relocate_from_path% (relocation chosen at the destination prompt)"
set "msg=The set will be moved to %relocate_target_path% and verified there; the move is recorded in it."
call :show msg
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
if defined inspect_unreadable call :refuse_unlistable_directory "D2: the directory above" || exit /b 1
if "%inspect_evidence_count%%inspect_unexpected_count%"=="10" goto identify_destination_set_rule_d2

rem D3: the destination is empty, or holds only a directory with the evidence
rem directory's name (not itself a set directory): it is the set directory.
:identify_destination_set_check_d3
set "destination_layout_rule_id=D3"
set "destination_layout_rule=D3: the directory is empty or holds only a directory with the evidence directory's name: it is the set directory"
set "inspect_directory_with_backslash=%destination_candidate_with_backslash%"
call :inspect_set_directory
if defined inspect_unreadable call :refuse_unlistable_directory "D3: the directory" || exit /b 1
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
if defined inspect_unreadable call :refuse_unlistable_directory "%destination_layout_rule_id%: the directory" || exit /b 1
if "%inspect_evidence_count%%inspect_unexpected_count%"=="00" goto check_destination_set_state_new
if "%inspect_evidence_count%%inspect_unexpected_count%"=="10" if /i "%inspect_evidence_name%"=="%evidence_directory_name%" goto check_destination_set_state_new_evidence
set "unexpected_example_name=%inspect_unexpected_name%"
if not defined unexpected_example_name set "unexpected_example_name=%inspect_evidence_name%"
set "identify_problem=%destination_layout_rule_id%: %destination_candidate_path% holds something other than this set (e.g. %unexpected_example_name%): nothing is copied into it."
exit /b 1
:check_destination_set_state_new_evidence
set "inspect_directory_with_backslash=%destination_candidate_with_backslash%%evidence_directory_name%\"
call :inspect_set_directory
if defined inspect_unreadable call :refuse_unlistable_directory "%destination_layout_rule_id%: the directory" || exit /b 1
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
rem inspect_unreadable is 1 when the directory couldn't be listed: the
rem counts then say nothing, and every caller refuses the directory
rem (:refuse_unlistable_directory) or, for the Enter default, offers none.
set "inspect_evidence_count=0"
set "inspect_evidence_name="
set "inspect_unexpected_count=0"
set "inspect_unexpected_name="
set "inspect_unreadable="
set "inspect_directory_is_drive_root="
call :is_drive_root inspect_directory_with_backslash && set "inspect_directory_is_drive_root=1"
call :list_directory "/b /a" inspect_directory_with_backslash temp_directory_listing || set "inspect_unreadable=1"
if defined inspect_unreadable exit /b 0
for /f "usebackq eol=/ delims=" %%E in ("%temp_directory_listing%") do (
    set "inspect_entry_name=%%E"
    call :inspect_set_directory_entry
)
exit /b 0

:refuse_unlistable_directory  leadText
rem Caller's scope (the set rules, after :inspect_set_directory left
rem inspect_unreadable set): identify_problem names the directory, led by
rem leadText (the rule, as the other refusals name it), and exit 1: the
rem prompt asks again, or a path given on the command line stops the run.
set "identify_problem=%~1 (%inspect_directory_with_backslash%) couldn't be listed (access denied, missing, or the device isn't readable), so what it holds can't be told: it is refused."
exit /b 1

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
rem name, or a prefix ending in "*" (case-insensitive). The items are CONFIG
rem values (safe in FOR values with delayed expansion on); the name is read
rem with !var! only. A FOR /L over the items, never a goto (section 6 of
rem the conventions); a prefix's length is measured here rather than by
rem :strlen, which sits far below this per-item helper.
setlocal EnableDelayedExpansion
set "name=!%~1!"
set "remaining=!%~2!"
set "matched="
for /l %%I in (1,1,%CONFIG_LIST_MAX_ITEMS%) do if not defined matched if defined remaining (
    set "pattern="
    for /f "tokens=1* delims=|" %%A in ("!remaining!") do (
        set "pattern=%%A"
        set "remaining=%%B"
    )
    if defined pattern call :name_matches_pattern
)
if defined matched (endlocal & exit /b 0)
endlocal & exit /b 1

:name_matches_pattern
rem Caller's scope (:name_matches_list, delayed expansion on): set matched
rem if the name matches the pattern (an exact name, or a prefix before "*").
if not "!pattern:~-1!"=="*" (
    if /i "!name!"=="!pattern!" set "matched=1"
    exit /b 0
)
set "prefix=!pattern:~0,-1!"
set "prefix_measure=!prefix!#"
set "prefix_length=0"
for %%P in (256 128 64 32 16 8 4 2 1) do if not "!prefix_measure:~%%P,1!"=="" (
    set /a "prefix_length+=%%P"
    set "prefix_measure=!prefix_measure:~%%P!"
)
for %%N in (!prefix_length!) do if /i "!name:~0,%%N!"=="!prefix!" set "matched=1"
exit /b 0

:name_directory_for_copy  pathVar  outVar
rem The name a copied directory takes: its own name, or for a drive root its
rem volume label (first line of "fsutil fsinfo volumeinfo", in any display
rem language), or the volume serial if there is no label ("Volume_<serial>").
rem The name is read with delayed expansion off: a FOR value assigned while
rem it is on loses any "!" ("Ev!dence" would become "Evdence"; review,
rem 2026-10-16). The results go back through the ENDLOCALs to a caller
rem whose delayed expansion is off, so "!" survives.
setlocal DisableDelayedExpansion
call :copy_variable %~1 directory
for %%A in ("%directory%") do set "name=%%~nxA"
setlocal EnableDelayedExpansion
if not "!directory:~3!"=="" (endlocal & endlocal & set "%~2=%name%" & exit /b 0)
if not "!directory:~1,2!"==":\" (endlocal & endlocal & set "%~2=%name%" & exit /b 0)
endlocal
rem A drive root. Its label is read with delayed expansion off as well: a
rem volume label may hold "!" (static check, 2026-10-16). The drive ("E:") is
rem in its own variable, as a comma inside a FOR /F command is a separator.
set "volume_drive=%directory:~0,2%"
set "label="
set "label_read="
"%tool_fsutil%" fsinfo volumeinfo %volume_drive% >nul 2>&1 <nul || set "label_read=1"
if defined tool_fsutil for /f "tokens=1* delims=:" %%A in ('2^>nul ^<nul "%tool_fsutil%" fsinfo volumeinfo %volume_drive%') do if not defined label_read (
    set "label_read=1"
    set "label=%%B"
)
if defined label set "label=%label:~1%"
if defined label (endlocal & set "%~2=%label%" & exit /b 0)
set "serial=unknown"
for /f "skip=1 tokens=*" %%L in ('vol %volume_drive% 2^>nul') do for %%T in (%%L) do set "serial=%%T"
endlocal & set "%~2=Volume_%serial%"
exit /b 0

:ask_plain_paths
rem /nonforensic: ask for the source and destination directories; the source's
rem contents are copied into the destination. No default source.
echo The CONTENTS of the source directory are copied into the destination
echo   directory.
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
set "destination_content_unreadable="
call :destination_has_content || exit /b 0
if defined destination_content_unreadable (
    echo The destination directory couldn't be listed ^(access denied, or the
    echo   device isn't readable^), so it can't be told whether it is empty: it
    echo   is refused.
    if defined argument_destination set "abort_reason=The destination given on the command line couldn't be listed (access denied, or the device isn't readable)." & if defined argument_destination exit /b 1
    call :count_rejected_answer plain_paths_rejected_answers "destination directory" || exit /b 1
    goto ask_plain_paths_destination
)
echo.
echo The destination directory is not empty. Robocopy overwrites files there
echo   that have the same name but a different size or timestamp.
echo 1. Continue with this destination
echo 2. Enter a different destination
call :ask_choice destination_answer "1 2" || exit /b 1
if "%destination_answer%"=="2" if defined argument_destination (
    set "abort_reason=Stopped at the user's choice: the destination given on the command line was not accepted."
    exit /b 1
)
if "%destination_answer%"=="2" goto ask_plain_paths_destination
set "destination_was_empty=0"
set "destination_state_text=NOT empty (user chose to continue)"
exit /b 0

:destination_has_content
rem /nonforensic: exit 0 if the destination directory exists and holds anything
rem other than, at a drive root, the items of DRIVE_ROOT_HOUSEKEEPING_DIRS and
rem _FILES. A directory that couldn't be listed sets
rem destination_content_unreadable (cleared by the caller) and exits 0: the
rem caller refuses it rather than ask whether to continue into it.
call :is_directory destination_with_backslash || exit /b 1
set "destination_entry_count=0"
call :list_directory "/b /a" destination_with_backslash temp_directory_listing || (set "destination_content_unreadable=1" & exit /b 0)
for /f "usebackq eol=/ delims=" %%E in ("%temp_directory_listing%") do set /a "destination_entry_count+=1"
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
if "%run_kind%"=="copy" call :make_destination_set_directory || exit /b 1
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

:make_destination_set_directory
rem (:init_run, a copy run) The destination set directory, made if it
rem isn't there. A check's is the set itself; a relocation's is made by
rem the move (:relocate_set): making it first would put the moved set
rem inside it.
call :is_directory destination_set_with_backslash || mkdir "%destination_set_path%" >nul 2>&1
call :is_directory destination_set_with_backslash && exit /b 0
set "abort_reason=Could not create the destination set directory."
exit /b 1

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
set "temp_custody_copy=%temp_path_prefix%_custody_copy.tmp"
set "temp_custody_copy_second=%temp_path_prefix%_custody_copy_second.tmp"
set "temp_listing_numbered=%temp_path_prefix%_listing_numbered.tmp"
set "temp_listing_line=%temp_path_prefix%_listing_line.tmp"
set "temp_robocopy_unicode_output=%temp_path_prefix%_robocopy_unicode.tmp"
set "temp_robocopy_summary=%temp_path_prefix%_robocopy_summary.tmp"
set "temp_robocopy_summary_tail=%temp_path_prefix%_robocopy_summary_tail.tmp"
set "temp_free_space=%temp_path_prefix%_free_space.tmp"
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
set "temp_count=%temp_path_prefix%_count.tmp"
set "temp_dashboard_pass=%temp_path_prefix%_dashboard_pass.tmp"
set "temp_dashboard_lock=%temp_path_prefix%_dashboard.lock"
set "temp_dashboard_helper_done=%temp_path_prefix%_dashboard_helper_done.tmp"
set "temp_dashboard_lists=%temp_path_prefix%_dashboard_lists.tmp"
set "temp_dashboard_count=%temp_path_prefix%_dashboard_count.tmp"
set "temp_dashboard_list_tail=%temp_path_prefix%_dashboard_list_tail.tmp"
set "temp_dashboard_copy_tail=%temp_path_prefix%_dashboard_copy_tail.tmp"
set "temp_dashboard_started_lines=%temp_path_prefix%_dashboard_started_lines.tmp"
set "temp_dashboard_error_lines=%temp_path_prefix%_dashboard_error_lines.tmp"
set "temp_dashboard_size=%temp_path_prefix%_dashboard_size.tmp"
set "temp_dashboard_environment=%temp_path_prefix%_dashboard_environment.tmp"
set "temp_dashboard_header_sections=%temp_path_prefix%_dashboard_header_sections.tmp"
set "temp_dashboard_header_sections_raw=%temp_path_prefix%_dashboard_header_sections_raw.tmp"
set "temp_dashboard_watch_lock=%temp_path_prefix%_dashboard_watch.lock"
set "temp_dashboard_watch_end=%temp_path_prefix%_dashboard_watch_end.tmp"
set "temp_dashboard_watch_done=%temp_path_prefix%_dashboard_watch_done.tmp"
set "temp_dashboard_closing=%temp_path_prefix%_dashboard_closing.tmp"
set "temp_dashboard_closing_raw=%temp_path_prefix%_dashboard_closing_raw.tmp"
set "temp_copy_pass_listing=%temp_path_prefix%_copy_pass_listing.tmp"
rem The FOR /F rework's files (2.5.0): every listing or search a loop reads
rem goes to a file first and is read from there (:list_directory), so no
rem path, record value or TEMP path goes on a child cmd's command line. One
rem file per loop that can run inside another: the records directory's
rem listing (temp_directory_listing, the prompt-time listings too: set by
rem :init_listing_file) holds a run record's file listing
rem (temp_record_files_listing) inside it; the history's numbered lines
rem (temp_history_numbered) hold a sealed history's (the _second) inside.
set "temp_record_files_listing=%temp_path_prefix%_record_files_listing.tmp"
set "temp_history_numbered=%temp_path_prefix%_history_numbered.tmp"
set "temp_history_numbered_second=%temp_path_prefix%_history_numbered_second.tmp"
set "temp_record_match=%temp_path_prefix%_record_match.tmp"
set "temp_record_files_expected=%temp_path_prefix%_record_files_expected.tmp"
set "temp_robocopy_numbered=%temp_path_prefix%_robocopy_numbered.tmp"
set "temp_link_listing=%temp_path_prefix%_link_listing.tmp"
set "temp_summary_warnings_wrapped=%temp_path_prefix%_summary_warnings_wrapped.tmp"
set "temp_summary_failures_wrapped=%temp_path_prefix%_summary_failures_wrapped.tmp"
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
rem A check's destination is the set itself (resolved once, as the
rem source); a relocation's doesn't exist yet: neither has a history of
rem its own to choose from.
if "%run_kind%"=="copy" (call :resolve_set_history destination) else call :clear_destination_history
call :continue_destination_history_instead && goto read_history_base_chosen
set "history_base_path=%source_history_path%"
set "history_base_side=source"
set "history_base_set_with_backslash=%source_set_with_backslash%"
if not defined history_base_missing if defined destination_history_path call :choose_history_base || exit /b 1
:read_history_base_chosen
rem The history continued is copied into this run's record at the end
rem (:write_history); its SHA-256 now pins what was checked (2.8.2).
if defined history_base_path call :get_sha256 history_base_path history_base_sha256
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

:clear_destination_history
rem Caller's scope (:read_history): the destination's history variables as
rem :resolve_set_history leaves them for a set with no history and no run
rem records.
set "destination_history_path="
set "destination_history_origin=none"
set "destination_history_problem="
set "destination_history_sealed_run="
set "destination_records_unreadable="
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
rem   <side>_records_unreadable  1 when the records directory couldn't be
rem                              listed: no history can be matched to its
rem                              run records (origin missing or unverified),
rem                              and :report_history_set_aside says so
set "%~1_history_path="
set "%~1_history_origin=none"
set "%~1_history_problem="
set "%~1_history_sealed_run="
set "%~1_records_unreadable="
call :copy_variable %~1_set_with_backslash resolve_set_with_backslash
set "resolve_beside_path=%resolve_set_with_backslash%%HISTORY_FILE_NAME%"
set "resolve_records_root=%resolve_set_with_backslash%%RECORDS_DIR_NAME%"
set "resolve_records_present="
set "records_root_unreadable="
call :records_directory_holds_records resolve_records_root && set "resolve_records_present=1"
if defined records_root_unreadable set "%~1_records_unreadable=1"
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
rem directory holding only .partial directories means no earlier runs. One
rem that couldn't be listed counts as holding records (unknown is not
rem nothing) and sets records_root_unreadable, which the caller
rem (:resolve_set_history) clears first and reports.
setlocal DisableDelayedExpansion
call :copy_variable %~1 records_root
call :is_directory records_root || (endlocal & exit /b 1)
set "holds_records="
set "records_root_with_backslash=%records_root%\"
call :list_directory "/b /a" records_root_with_backslash temp_directory_listing || (endlocal & set "records_root_unreadable=1" & exit /b 0)
for /f "usebackq eol=/ delims=" %%E in ("%temp_directory_listing%") do if not defined holds_records (
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
set "resolve_records_root_with_backslash=%resolve_records_root%\"
call :list_directory "/b /ad /on" resolve_records_root_with_backslash temp_directory_listing || exit /b 1
for /f "usebackq eol=/ delims=" %%R in ("%temp_directory_listing%") do (
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
call :write_history_with_seal head_sealed_path head_pending_text head_seal_sha256 head_filled_path || exit /b 1
call :history_matches_records head_filled_path resolve_records_root || exit /b 1
exit /b 0

:history_matches_records  historyVar  recordsRootVar
rem Before the copy, to choose which history to continue (:resolve_set_history,
rem :find_newest_sealed_history): exit 0 if the history and the run records
rem agree in their structure (:check_history_against_records, quiet).
setlocal DisableDelayedExpansion
call :check_history_against_records quiet %~1 %~2
set "history_matches_exit_code=%errorlevel%"
endlocal & exit /b %history_matches_exit_code%

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
if defined %~1_records_unreadable set "set_aside_text=Run records: in the %~1 set, the records directory (%RECORDS_DIR_NAME%) couldn't be listed (access denied, or the device isn't readable): its run records can't be checked, and no history can be matched to them."
if not defined set_aside_text exit /b 0
if "%~2"=="before" (
    set "msg=%set_aside_text% The Run records check will fail."
    call :add_warning msg
    set "run_records_warned=1"
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
set "lines=0"
call :copy_for_reading %~1 temp_custody_copy || (endlocal & set "%~2=0" & exit /b 1)
"%tool_find%" /c /v "" <"!temp_custody_copy!" >"!temp_count!" 2>nul
for /f "usebackq" %%N in ("!temp_count!") do set "lines=%%N"
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
rem is no such line, or the history couldn't be read.
for %%F in (run result source source_serial source_volume_label_and_filesystem destination destination_serial destination_volume_label_and_filesystem evidence_files host user script seal) do set "%~3_%%F="
call :copy_variable %~1 read_history_row_file
set "history_row_line="
call :copy_for_reading read_history_row_file temp_custody_copy || exit /b 1
"%tool_findstr%" /n "^" "%temp_custody_copy%" >"%temp_history_numbered%" 2>nul
for /f "usebackq tokens=1* delims=:" %%A in ("%temp_history_numbered%") do if "%%A"=="%~2" set "history_row_line=%%B"
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
rem (byte for byte, as fc /b compares them); exit 1 if either couldn't be
rem read (two empty copies would otherwise match).
setlocal EnableDelayedExpansion
set "long_file=!%~1!"
set "short_file=!%~2!"
setlocal DisableDelayedExpansion
call :copy_for_reading short_file temp_custody_copy_second || (endlocal & endlocal & exit /b 1)
call :copy_for_reading long_file temp_custody_copy || (endlocal & endlocal & exit /b 1)
set "short_lines=0"
"%tool_find%" /c /v "" <"%temp_custody_copy_second%" >"%temp_count%" 2>nul
for /f "usebackq" %%N in ("%temp_count%") do set "short_lines=%%N"
type nul >"%temp_history_lines%"
"%tool_findstr%" /n "^" "%temp_custody_copy%" >"%temp_history_numbered_second%" 2>nul
for /f "usebackq tokens=1* delims=:" %%A in ("%temp_history_numbered_second%") do if %%A leq %short_lines% >>"%temp_history_lines%" echo(%%B
"%tool_fc%" /b "%temp_custody_copy_second%" "%temp_history_lines%" >nul 2>&1
set "starts_with_exit_code=%errorlevel%"
endlocal & endlocal & exit /b %starts_with_exit_code%

:describe_history_for_header
rem Header lines for the reference record, the history and the previous run.
set "header_reference_record=none found in the source: the source is hashed now and becomes the reference record"
if defined history_base_missing set "header_reference_record=none: the source set holds run records but no history (see Warnings): the source is hashed now"
if defined history_base_missing if defined source_records_unreadable set "header_reference_record=none usable: the source set's records directory couldn't be listed (see Warnings): the source is hashed now"
if defined reference_run set "header_reference_record=%RECORDS_DIR_NAME%\%reference_run%\%reference_name% (row 1 of the history)"
set "header_history=no earlier runs found in the source; this is run 1"
if %history_row_count% gtr 0 set "header_history=%history_row_count% earlier run(s); this is run %this_run_number%"
if "%history_base_side%"=="destination" set "header_history=%header_history% (continuing the destination set's history: a rerun or update)"
call :copy_variable %history_base_side%_history_origin header_history_origin
call :copy_variable %history_base_side%_history_sealed_run header_history_sealed_run
if "%header_history_origin%"=="sealed" set "header_history=%header_history%; taken from the newest sealed history (run %header_history_sealed_run%), not the history beside the evidence (see Warnings)"
set "header_previous_run=none"
set "header_previous_run_seal="
if defined previous_run set "header_previous_run=%previous_run% (%previous_result%, host %previous_host%)"
if defined previous_run set "header_previous_run_seal=seal SHA-256: %previous_seal%"
exit /b 0

rem -- Checks before the copy -------------------------------------------------

:check_script_against_previous_run
rem Compare this script with the previous run's (README, "Script check"):
rem the version from the newest row of the previous run's sealed history,
rem the SHA-256 from its sealed log header. The script never vouches for
rem itself: a difference is flagged for the analyst to verify both scripts
rem against the published release. Newer version: WARN (the status too:
rem owner, 2026-10-20). Older version, or the same version with a different
rem SHA-256: FAIL. The same version with no log to take the SHA-256 from:
rem WARN. A previous run whose sealed history is missing or holds no
rem MAJOR.MINOR.PATCH version: FAIL (a damaged record). No previous run:
rem nothing to compare.
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
    set "script_status=WARN"
    set "result_script=WARN: version %TOOL_VERSION%, newer than the previous run's %previous_script_version% (see Warnings)"
    exit /b 0
)
set "previous_log=%previous_run_dir%\%RECORD_FILE_PREFIX%%previous_run%.log"
set "previous_script_sha256="
set "previous_log_unreadable="
call :copy_for_reading previous_log temp_custody_copy || set "previous_log_unreadable=1"
"%tool_findstr%" /b /c:"  Script SHA-256      : " "%temp_custody_copy%" >"%temp_record_match%" 2>nul
for /f "usebackq tokens=1* delims=:" %%A in ("%temp_record_match%") do set "previous_script_sha256=%%B"
call :clean_sha256_from_record previous_script_sha256
if not exist "%previous_log%" (
    set "msg=Script: the SHA-256 can't be compared: the previous run's record has no log."
    call :add_warning msg
    set "script_status=WARN"
    set "result_script=WARN: same version as the previous run (%TOOL_VERSION%); SHA-256 not compared: its record has no log (see Warnings)"
    exit /b 0
)
if defined previous_log_unreadable (
    call :fail_script_check "this run's script is version %TOOL_VERSION%, as the previous run's was, but the previous run's log couldn't be read (access denied, empty, or the device isn't readable), so its Script SHA-256 can't be compared"
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
for /l %%I in (1,1,%RECORD_CELL_MAX_WORDS%) do if defined word if not "!word: =!"=="!word!" set "word=!word:* =!"
endlocal & set "%~2=%word%"
exit /b 0

:fail_script_check  reason
rem Record a failed script check; it is shown after the header and listed
rem with the failures.
set "script_status=FAIL"
set "result_script=FAIL: %~1 (see Script above, and Failures)"
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
rem says so (owner, 2026-10-16, after test round 7). A relocation runs this
rem before its move, on the set where it is: a set moved by hand before is
rem still flagged, and the new location goes into this run's row.
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
    set "location_serial_warned=1"
)
if defined serials_comparable if /i not "%source_last_destination_serial%"=="%source_volume_serial%" (
    set "msg=Location: the source set is on volume serial %source_volume_serial%, but the run that made it (%source_last_run%) copied it to volume serial %source_last_destination_serial%: it reached this volume by other means since."
    call :add_warning msg
    set "location_serial_warned=1"
)
set "location_now=%source_set_path%"
if "%location_now:~1,1%"==":" set "location_now=%location_now:~2%"
set "location_then=%source_last_destination%"
if "%location_then:~1,1%"==":" set "location_then=%location_then:~2%"
if /i not "%location_now%"=="%location_then%" (
    set "msg=Location: the source set directory is %source_set_path%, but the run that made it (%source_last_run%) copied it to %source_last_destination% (drive letters aside): it was moved or copied by other means since."
    call :add_warning msg
    set "location_path_warned=1"
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
rem Not when the records directory couldn't be listed: that warning (above,
rem :report_history_set_aside) is the one report for it (round 14.7).
if defined history_base_missing if not defined source_records_unreadable (
    set "msg=Run records: the source set holds run records but no history file (%HISTORY_FILE_NAME%): the Run records check will fail, and the history starts again with this run."
    call :add_warning msg
    set "run_records_warned=1"
)
rem The full check of the earlier runs, before the copy (owner, 2026-10-16):
rem the history this run continues against the run records of the set that
rem holds it, every run record against its seal; each problem is a warning
rem here, and the check of their copies after the copy decides the result.
set "precheck_history=%history_base_path%"
set "precheck_records_root=%history_base_set_with_backslash%%RECORDS_DIR_NAME%"
if defined history_base_missing set "precheck_history="
if defined history_base_missing set "precheck_records_root=%source_set_with_backslash%%RECORDS_DIR_NAME%"
if not defined history_base_missing if not defined history_base_path exit /b 0
call :check_history_against_records warn precheck_history precheck_records_root
exit /b 0

:precheck_partial_directories  side
rem Caller's scope (:precheck_run_records): warn up front about leftover
rem <run>.partial directories (interrupted write-backs) in the side's
rem records directory, whether or not the set has a history (a set holding
rem only a .partial has no earlier runs). Each name is warned about once
rem (temp_partial_warned), also by :check_run_records after the copy.
call :copy_variable %~1_set_with_backslash precheck_partial_set
if not defined precheck_partial_set exit /b 0
set "precheck_partial_records_root=%precheck_partial_set%%RECORDS_DIR_NAME%\"
rem A records directory that couldn't be listed is reported by
rem :resolve_set_history's report and the history checker, not here.
call :list_directory "/b /ad" precheck_partial_records_root temp_directory_listing || exit /b 0
for /f "usebackq eol=/ delims=" %%R in ("%temp_directory_listing%") do (
    set "record_directory_name=%%R"
    call :precheck_partial_directory
)
exit /b 0

:precheck_partial_directory
rem Caller's scope (:precheck_partial_directories): one directory, in
rem record_directory_name.
call :is_partial_run_directory record_directory_name || exit /b 0
"%tool_findstr%" /x /l /c:"%record_directory_name%" "%temp_partial_warned%" >nul 2>&1 && exit /b 0
set "msg=Run records: %record_directory_name% is an interrupted write-back (a run record never completed); it is outside the history."
call :add_warning msg
set "run_records_warned=1"
>>"%temp_partial_warned%" echo(%record_directory_name%
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
rem With the live display they go to the log only: the display's Script row
rem and its Failures list show them on the console a line later (owner,
rem 2026-10-20: the same check shown twice, apart from the others).
set "pre_copy_findings_target=both"
if "%dashboard_mode%"=="live" set "pre_copy_findings_target=log"
set "heading=Script: checked against the previous run"
call :write_section_heading heading %pre_copy_findings_target%
call :log_field "Script" result_script %pre_copy_findings_target%
if not defined script_failure_message exit /b 0
call :emit_free_text script_failure_message %pre_copy_findings_target%
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
rem environment, source, destination, and a forensic run's History row
rem (its items built here first, 2.8.0). With the live display on, every
rem line goes to the log alone (:emit_line); the display draws its own
rem columns from the same variables.
if "%run_mode%"=="forensic" call :build_run_history_items
call :format_utc_offset local_utc_offset
call :describe_windows header_os
set "robocopy_path=%tool_robocopy%"
set "certutil_path=%tool_certutil%"
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
set "msg=  Findings made after the copy (such as links not copied) are in the summary." & call :show_and_log msg
set "msg=" & call :show_and_log msg
set "msg=Environment" & call :show_and_log msg
call :log_field "Script" header_script
call :log_field "Script path" script_path
call :log_field "Script SHA-256" script_sha256
call :log_field "Latest release" latest_release_text
call :log_field "Mode" header_mode
call :log_field "Confirmations" header_confirmations
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
set "header_written=1"
exit /b 0

:write_abort_header
rem A forensic run aborted after its log was started but before its header
rem (:abort): write what is known at that point, to the log only, so the
rem kept log says what ran, where and when. The console keeps its one
rem result block.
set "abort_header_script=%TOOL_NAME% %TOOL_VERSION%"
set "abort_header_started=%start_utc_iso% (source: %start_utc_source%)"
call :describe_user abort_header_user
call :describe_host abort_header_host
set "msg=Environment (the run was aborted before its header was complete)"
call :emit_free_text msg log
call :log_field "Script" abort_header_script log
call :log_field "Script path" script_path log
if defined script_sha256 call :log_field "Script SHA-256" script_sha256 log
call :log_field "Started (UTC)" abort_header_started log
call :log_field "Host" abort_header_host log
call :log_field "User" abort_header_user log
if defined source_path call :log_field "Source" source_path log
if defined source_set_path call :log_field "Source set" source_set_path log
if defined destination_path call :log_field "Destination" destination_path log
if defined destination_set_path call :log_field "Destination set" destination_set_path log
set "msg=" & call :emit_free_text msg log
exit /b 0

:write_header_sets
rem Forensic run: the source and destination sections, set by set, one
rem below the other (the log always, and the plain output; with the live
rem display on they reach the log alone, and the display draws its own
rem columns, side by side from HEADER_SIDE_BY_SIDE_MIN_COLUMNS:
rem :dashboard_build_header_sections), then the History row.
set "header_source_set=none: raw evidence (a first copy)"
if defined source_set_path set "header_source_set=%source_set_with_backslash%"
set "header_source_evidence=%source_with_backslash%"
rem A relocation's source is the set where it was (the checks before the
rem move read it there); the Destination section has its new location.
if "%run_kind%"=="relocate" set "header_source_set=%relocate_from_with_backslash% (before this run's move)"
if "%run_kind%"=="relocate" set "header_source_evidence=%relocate_from_with_backslash%%evidence_directory_name%\ (before this run's move)"
set "header_records=%destination_run_dir%\"
call :write_header_set_fields both
exit /b 0

:write_header_set_fields  target
rem The Source and Destination sections as fields, one below the other, to
rem the console, the log or both.
set "msg=" & call :emit_free_text msg %~1
set "msg=Source" & call :emit_free_text msg %~1
call :log_field "Set directory" header_source_set %~1
call :log_field "Evidence directory" header_source_evidence %~1
call :log_field "Chosen" source_set_rule %~1
call :log_field "Volume" header_source_volume %~1
call :log_housekeeping source "Skipped at root" %~1
call :log_field "Reference record" header_reference_record %~1
call :log_field "History" header_history %~1
call :log_field "Previous run" header_previous_run %~1
if defined header_previous_run_seal call :log_field_continued header_previous_run_seal %~1
set "msg=" & call :emit_free_text msg %~1
set "msg=Destination" & call :emit_free_text msg %~1
call :log_field "Set directory" destination_set_with_backslash %~1
call :log_field "Evidence directory" destination_with_backslash %~1
call :log_field "Chosen" destination_set_rule %~1
call :log_field "Was" destination_state_text %~1
call :log_field "Volume" header_destination_volume %~1
call :log_field "Run record" header_records %~1
call :log_field "Log" log_destination_text %~1
call :log_field "Log during run" log_staged_path %~1
set "msg=" & call :emit_free_text msg %~1
call :write_run_history_rows %~1
exit /b 0

:describe_housekeeping_for_pair  side  outVar
rem One line for the side-by-side header: the housekeeping items skipped at
rem the side's drive root, as a count (the log lists each one).
setlocal
set "text=n/a (not a drive root)"
call :is_drive_root %~1_with_backslash || (endlocal & set "%~2=%text%" & exit /b 0)
if "%~1"=="source" (set "list_file=%temp_housekeeping_source%") else set "list_file=%temp_housekeeping_destination%"
set "item_count=0"
if exist "%list_file%" for /f "usebackq tokens=1* delims=:" %%A in ("%list_file%") do set /a "item_count+=1"
set "text=none present"
if %item_count% gtr 0 set "text=%item_count% item(s), excluded by exact path (listed in the log)"
endlocal & set "%~2=%text%"
exit /b 0

:build_run_history_items
rem Forensic run (2.8.0; owner, 2026-10-24): the runs of the history this
rem run continues, oldest first, for the History row (:write_run_history_rows,
rem :dashboard_emit_run_history_line): run_history_count items, each
rem run_history_<n>_text (the row's run cell as the history holds it:
rem record content, printed and never run) and run_history_<n>_failed (1
rem unless its Result cell is PASS). A /check's row (its Source directory
rem and Destination set directory the same set) is left out unless it
rem failed (owner: a check moves nothing, but a failed one found the
rem evidence or its records changed). run_history_current_text is this
rem run's item: "current"; none for a /check, which shows the runs alone;
rem "current (first copy)" with no history to continue; with run records
rem but no usable history, or a history that couldn't be read, a note
rem pointing at the Warnings. Delayed expansion is off (the caller's): the
rem rows are read as :check_history_row reads them.
set "run_history_count=0"
set "run_history_current_text=current"
if "%run_kind%"=="check" set "run_history_current_text="
if not defined history_base_path (
    if "%run_kind%"=="copy" set "run_history_current_text=current (first copy)"
    if defined history_base_missing set "run_history_current_text=current (no usable history: see Warnings)"
    exit /b 0
)
call :copy_for_reading history_base_path temp_custody_copy || (
    set "run_history_current_text=%run_history_current_text% (the history couldn't be read: see Warnings)"
    exit /b 0
)
"%tool_findstr%" /n "^" "%temp_custody_copy%" >"%temp_history_numbered%" 2>nul
for /f "usebackq tokens=1* delims=:" %%A in ("%temp_history_numbered%") do if %%A gtr 1 (
    set "history_row_line=%%B"
    call :add_run_history_item
)
exit /b 0

:add_run_history_item
rem Caller's scope (:build_run_history_items): one row of the history, in
rem history_row_line, added as an item unless it is a /check's row that
rem passed. The cells are compared inside quotes and assigned inside
rem quotes: record content is data (section 6 of the conventions).
call :split_history_line item || exit /b 0
set "item_failed=1"
if /i "%item_result%"=="PASS" set "item_failed="
set "item_is_check="
if /i "%item_source%"=="%item_destination%" set "item_is_check=1"
if defined item_is_check if not defined item_failed exit /b 0
set /a "run_history_count+=1"
set "run_history_%run_history_count%_text=%item_run%"
set "run_history_%run_history_count%_failed=%item_failed%"
exit /b 0

:write_run_history_rows  target
rem The History row (2.8.0; owner, 2026-10-24) as the log and the plain
rem output have it, and the display when its sections are one column:
rem one run per line, the runs of the history this run continues oldest
rem first (:build_run_history_items), then this run as "current"; the
rem field layout, each later line's run under the first and a "v" under
rem the colon for the arrow. At most HISTORY_RUNS_MAX runs, the newest,
rem a line "....." first standing for the ones left out. On a console a
rem run whose Result isn't PASS is red, and "current" once this run has
rem failed (run_history_current_failed, set for the display's last
rem frame); the log never carries colour, so a line's log copy and
rem console copy are written apart (:emit_line writes one text). target:
rem console, log, both, or file (the display's static lines, coloured as
rem the console's).
setlocal EnableDelayedExpansion
set "rows_target=%~1"
set "rows_first=1"
set "rows_lead_text="
if !run_history_count! gtr %HISTORY_RUNS_MAX% set /a "rows_first=run_history_count - HISTORY_RUNS_MAX + 1"
if !run_history_count! gtr %HISTORY_RUNS_MAX% set "rows_lead_text=....."
set "rows_line_number=0"
if defined rows_lead_text (
    set "rows_item_text=!rows_lead_text!"
    set "rows_item_failed="
    call :write_run_history_item
)
for /l %%I in (!rows_first!,1,!run_history_count!) do (
    set "rows_item_text=!run_history_%%I_text!"
    set "rows_item_failed=!run_history_%%I_failed!"
    call :write_run_history_item
)
if defined run_history_current_text (
    set "rows_item_text=!run_history_current_text!"
    set "rows_item_failed=!run_history_current_failed!"
    call :write_run_history_item
)
endlocal & exit /b 0

:write_run_history_item
rem Caller's scope, delayed expansion on (:write_run_history_rows): one
rem line of the row: the first with the label ("  History" padded to the
rem field layout's 20, the value at column 25), each later one with the
rem "v" at column 23, under the colon, and its run at column 25.
set /a "rows_line_number+=1"
set "rows_label=  History             : "
if !rows_line_number! gtr 1 set "rows_label=!BLANKS:~0,22!v "
set "rows_plain=!rows_label!!rows_item_text!"
set "rows_shown=!rows_plain!"
if defined rows_item_failed if defined console_colour set "rows_shown=!rows_label!!coloured_run_failed_start!!rows_item_text!!colour_end!"
if "!rows_target!"=="log" call :emit_line rows_plain log
if "!rows_target!"=="console" call :emit_line rows_shown console
if "!rows_target!"=="file" call :emit_line rows_shown file
if "!rows_target!"=="both" (
    call :emit_line rows_plain log
    call :emit_line rows_shown console
)
exit /b 0

:wrap_field_into_column  label  valueVar  outPrefix
rem Caller's scope, delayed expansion on (:dashboard_emit_field_pair): the field
rem "  label    : value" wrapped within the pair's column into
rem <outPrefix>_1.. (<outPrefix>_count lines): the value from the first
rem line's value column, continuations one column right of it; a break at
rem the last space or after the last backslash that fits (a path breaks
rem between its names); failing those, after the last "_", "." or "-"
rem that fits (a name longer than the column breaks between its parts:
rem round 12.13), a "." only when five or more characters follow it (round
rem 12.15: "evidence-robocopy_<UTC>." left "log" alone on a row); else
rem after the last character that fits (a part longer than the column is
rem cut here, on the console only; the log holds it whole). A FOR /L,
rem never a goto, per piece.
set "wrap_label=%~1!BLANKS!"
set "wrap_prefix=  !wrap_label:~0,%HEADER_PAIR_LABEL_WIDTH%!: "
set "wrap_text=!%~2!"
set "%~3_count=0"
set "wrap_room=!pair_value_width!"
for /l %%S in (1,1,200) do if defined wrap_text (
    for %%W in (!wrap_room!) do (
        set "wrap_piece=!wrap_text:~0,%%W!"
        set "wrap_rest=!wrap_text:~%%W!"
    )
    if defined wrap_rest (
        set "wrap_break_at="
        for /l %%I in (!wrap_room!,-1,1) do if not defined wrap_break_at (
            set "wrap_head=!wrap_text:~0,%%I!"
            if "!wrap_text:~%%I,1!"==" " set "wrap_break_at=%%I"
            if "!wrap_head:~-1!"=="\" set "wrap_break_at=%%I"
        )
        if not defined wrap_break_at for /l %%I in (!wrap_room!,-1,1) do if not defined wrap_break_at (
            set "wrap_head=!wrap_text:~0,%%I!"
            for %%C in (_ -) do if "!wrap_head:~-1!"=="%%C" set "wrap_break_at=%%I"
            if "!wrap_head:~-1!"=="." if not "!wrap_text:~%%I,5!"=="!wrap_text:~%%I,4!" set "wrap_break_at=%%I"
        )
        if defined wrap_break_at for %%B in (!wrap_break_at!) do (
            set "wrap_piece=!wrap_text:~0,%%B!"
            set "wrap_rest=!wrap_text:~%%B!"
        )
    )
    for /l %%T in (1,1,4) do if "!wrap_rest:~0,1!"==" " set "wrap_rest=!wrap_rest:~1!"
    set /a "%~3_count+=1"
    for %%N in (!%~3_count!) do set "%~3_%%N=!wrap_prefix!!wrap_piece!"
    set "wrap_text=!wrap_rest!"
    set "wrap_prefix=!BLANKS:~0,%HEADER_PAIR_LABEL_WIDTH%!     "
    set /a "wrap_room=pair_value_width - 1"
)
exit /b 0

:write_header_plain_directories  [target]
rem Non-forensic run: the two directories robocopy copies between. target:
rem console, log or both (the default); the display's columns take them
rem as a file (:dashboard_emit_fields).
setlocal
set "plain_directories_target=%~1"
if not defined plain_directories_target set "plain_directories_target=both"
set "msg=" & call :emit_free_text msg %plain_directories_target%
set "msg=Source" & call :emit_free_text msg %plain_directories_target%
call :log_field "Contents of" source_with_backslash %plain_directories_target%
call :log_field "Volume" header_source_volume %plain_directories_target%
call :log_housekeeping source "Skipped at root" %plain_directories_target%
set "msg=" & call :emit_free_text msg %plain_directories_target%
set "msg=Destination" & call :emit_free_text msg %plain_directories_target%
call :log_field "Copied into" destination_with_backslash %plain_directories_target%
call :log_field "Was" destination_state_text %plain_directories_target%
call :log_field "Volume" header_destination_volume %plain_directories_target%
call :log_housekeeping destination "Left alone at root" %plain_directories_target%
endlocal & exit /b 0

:check_environment
rem Run every check an analyst should know about before relying on the copy,
rem and collect the results as one list of warnings (:add_warning). The list
rem heads the log header and is repeated in the summary.
call :check_power
call :read_clock_status
call :check_realtime_scanning
call :finish_latest_release_check
if defined latest_release_warning call :add_warning latest_release_warning
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
    set "clock_warned=1"
    call :add_warning msg
)
if defined destination_filesystem if defined FILESYSTEM_WARNING_%destination_filesystem% call :warn_destination_filesystem
if not defined source_filesystem if not "%source_volume_serial%"=="n/a" call :warn_unknown_filesystem source "%source_path:~0,2%"
if not defined destination_filesystem if not "%destination_volume_serial%"=="n/a" call :warn_unknown_filesystem destination "%destination_volume_directory:~0,2%"
call :check_write_mode
call :check_recovered_fragments
call :find_drive_root_housekeeping source yes
call :find_drive_root_housekeeping destination yes
if "%run_mode%"=="forensic" if not defined history_base_path if not defined history_base_missing (
    set "msg=No history or reference record was found in the source: the source is hashed now and becomes the reference record, so this copy is not checked against any earlier record."
    call :add_warning msg
    set "reference_missing_warned=1"
)
rem A forensic rerun or update was confirmed at the prompt, and the header
rem says so ("Was"): no warning (owner, 2026-10-16). In /nonforensic the
rem destination was any non-empty directory.
if "%run_mode%"=="nonforensic" if not "%destination_was_empty%"=="1" (
    set "msg=The destination was not empty (you chose to continue): robocopy overwrites same-named files that differ."
    call :add_warning msg
    set "destination_not_empty_warned=1"
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
if "%~2"=="source" set "recovered_warned_source=1"
exit /b 0

:check_write_mode
rem Record whether every copy pass writes unbuffered (/j in PASS_<id>_FLAGS),
rem so that verification can't be served from Windows' file cache, and
rem whether backup mode (/b, backup_flag: an elevated run) undoes that for
rem the evidence and custody files it copies (round 15.1: /b leaves the
rem written files in the cache; /j alone keeps them out). The run record's
rem own write-back never uses /b, so it is read back from the medium
rem either way. Warn for any pass that doesn't use /j.
setlocal EnableDelayedExpansion
set "buffered_passes="
for %%P in (%COPY_PASSES%) do (
    set "flags= !PASS_%%P_FLAGS! "
    if "!flags: /j =!"=="!flags!" set "buffered_passes=!buffered_passes!, !PASS_%%P_LABEL!"
)
set "writes=unbuffered (robocopy /j), evidence and custody records: not in Windows' file cache when verified"
if defined backup_flag set "writes=unbuffered (robocopy /j); the evidence and custody records, copied in backup mode (/b), may be in Windows' file cache when verified; this run's record is not"
if "%run_mode%"=="nonforensic" set "writes=unbuffered (robocopy /j): not in Windows' file cache when verified"
if "%run_mode%"=="nonforensic" if defined backup_flag set "writes=unbuffered (robocopy /j) in backup mode (/b): may be in Windows' file cache when verified"
if not "%run_kind%"=="copy" set "writes=the run record only, unbuffered (robocopy /j): nothing copied (%run_kind_switch%)"
if not "%run_kind%"=="copy" set "buffered_passes="
if defined buffered_passes (
    set "writes=buffered for: !buffered_passes:~2!"
    set "msg=Copy pass without /j (!buffered_passes:~2!): its files may be verified from the Windows cache rather than read back from the drive."
    call :add_warning msg
)
endlocal & set "header_writes=%writes%"
exit /b 0

:find_skipped_links
rem After the copy passes. Links in the source (junctions and symbolic
rem links: the L attribute), which robocopy doesn't follow or copy (/xj),
rem that are not in the destination: each is a warning, since what it
rem points to is not part of this copy. Other reparse points that robocopy
rem did copy (e.g. cloud placeholder files) are left alone: only the
rem outcome counts. The source is walked by robocopy itself
rem (LINK_LIST_FLAGS): a link is listed once and never followed, so a loop
rem of junctions ends at once and nothing inside a skipped link is listed
rem (round 12.2's probe; before 2.5.0, DIR /S walked into every link: a
rem junction back to its parent was walked to the path-length limit, round
rem 7). The listing is read numbered, as every listing (section 6), and
rem each line's attributes are read in-process (FOR %%~a: an "l" at
rem position 9 is a link) with delayed expansion off, so "!" and "%" in a
rem path stay and no path goes on a child command line. A walk robocopy
rem couldn't complete, and lines cmd couldn't carry (over about 8,000
rem characters), give one warning each: a link there, if any, isn't
rem listed. Links are findings, not a check: a warning never changes the
rem verdict.
setlocal EnableDelayedExpansion
set "excluded_dirs="
set "excluded_files="
call :add_housekeeping_exclusions source
call :build_exclusion_args
"%tool_robocopy%" "!source_with_backslash! " "!temp_path_prefix!_nonexistent" *.* !LINK_LIST_FLAGS! !backup_flag! !exclusion_args! /unilog:"!temp_robocopy_unicode_output!" >nul 2>&1
set "link_list_exit_code=!errorlevel!"
call :save_robocopy_unicode_output temp_link_listing new
set "link_listing_incomplete="
if !link_list_exit_code! geq 8 set "link_listing_incomplete=1"
call :is_robocopy_exit_code_in_range link_list_exit_code || set "link_listing_incomplete=1"
if not "!robocopy_output_lines_written!"=="!robocopy_output_lines_total!" set "link_listing_incomplete=1"
endlocal & set "link_listing_incomplete=%link_listing_incomplete%"
if defined link_listing_incomplete (
    set "msg=Links in the source couldn't all be looked for: robocopy's walk of the source didn't complete, or a line of it couldn't be read. A link it holds, if any, isn't listed here."
    call :add_warning msg
)
call :number_listing temp_link_listing
set "link_lines_handled=0"
for /f "usebackq tokens=1* delims=:" %%A in ("%temp_listing_numbered%") do (
    set "link_candidate_path="
    for /f "tokens=1*" %%S in ("%%B") do set "link_candidate_path=%%T"
    call :check_listed_link
)
if %link_lines_handled% neq %listing_line_count% (
    set "msg=Links in the source: %link_lines_handled% of the %listing_line_count% lines of robocopy's walk could be read (cmd can't carry a line over 8000 characters). A link on one of the others, if any, isn't listed here."
    call :add_warning msg
)
exit /b 0

:check_listed_link
rem Caller's scope (:find_skipped_links, delayed expansion off): one line
rem of robocopy's walk, in link_candidate_path (a file, or a directory with
rem its trailing backslash; empty for a line that names no path). A link
rem (the L attribute) that isn't in the destination is reported. The source
rem directory's own line is passed over: its contents were copied whatever
rem it is.
set /a "link_lines_handled+=1"
if not defined link_candidate_path exit /b 0
if /i "%link_candidate_path%"=="%source_with_backslash%" exit /b 0
if "%link_candidate_path:~-1%"=="\" set "link_candidate_path=%link_candidate_path:~0,-1%"
set "link_candidate_attributes="
for %%A in ("%link_candidate_path%") do set "link_candidate_attributes=%%~aA"
if not defined link_candidate_attributes exit /b 0
if not "%link_candidate_attributes:~8,1%"=="l" exit /b 0
set "skipped_link_path=%link_candidate_path%"
call :report_skipped_link
exit /b 0

:report_skipped_link
rem Caller's scope (:check_listed_link): one link, in skipped_link_path.
call :link_was_copied skipped_link_path && exit /b 0
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

:find_recovered_dirs  pattern
rem :each_item callback: the directories matching one pattern at
rem callback_drive_root. Each name goes to its helper by variable (a CALL
rem argument is expanded a second time, so a "%" in a name would change).
set "callback_pattern_path=%callback_drive_root%%~1"
call :list_directory "/b /ad" callback_pattern_path temp_directory_listing callback_drive_root || (call :warn_drive_root_unlistable & exit /b 0)
for /f "usebackq eol=/ delims=" %%F in ("%temp_directory_listing%") do (
    set "callback_found_name=%%F"
    call :add_recovered_dir callback_found_name
)
exit /b 0

:add_recovered_dir  nameVar
setlocal EnableDelayedExpansion
if defined recovered_dirs_found (set "found=!recovered_dirs_found!, !%~1!") else set "found=!%~1!"
endlocal & set "recovered_dirs_found=%found%"
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
echo(%~1| "%tool_findstr%" /r "[*?]" >nul && goto find_housekeeping_dir_wildcard
set "housekeeping_dir_path=%callback_drive_root%%~1"
set "callback_found_name=%~1"
call :is_directory housekeeping_dir_path && call :record_housekeeping_item D callback_found_name
exit /b 0
:find_housekeeping_dir_wildcard
set "callback_pattern_path=%callback_drive_root%%~1"
call :list_directory "/b /ad" callback_pattern_path temp_directory_listing callback_drive_root || (call :warn_drive_root_unlistable & exit /b 0)
for /f "usebackq eol=/ delims=" %%F in ("%temp_directory_listing%") do (
    set "callback_found_name=%%F"
    call :record_housekeeping_item D callback_found_name
)
exit /b 0

:find_housekeeping_file  pattern
rem :each_item callback: one file pattern of DRIVE_ROOT_HOUSEKEEPING_FILES at
rem callback_drive_root.
set "callback_pattern_path=%callback_drive_root%%~1"
call :list_directory "/b /a-d" callback_pattern_path temp_directory_listing callback_drive_root || (call :warn_drive_root_unlistable & exit /b 0)
for /f "usebackq eol=/ delims=" %%F in ("%temp_directory_listing%") do (
    set "callback_found_name=%%F"
    call :record_housekeeping_item F callback_found_name
)
exit /b 0

:warn_drive_root_unlistable
rem Caller's scope (the drive-root callbacks above): the drive root in
rem callback_drive_root couldn't be listed, so its housekeeping items and
rem recovered-fragment directories, if any, weren't found and none is
rem excluded from the copy. One warning per root (:add_warning lists a text
rem once); the copy or the listing of that root then fails on its own.
set "msg=The drive root %callback_drive_root% couldn't be listed (access denied, or the device isn't readable): its housekeeping items, if any, weren't found, so none is excluded from the copy."
call :add_warning msg
exit /b 0

:record_housekeeping_item  kind  nameVar
rem Count one housekeeping item and, if recording, write it to the list
rem (the name by variable: delayed expansion is off, so "!" and "%" in it
rem come through).
set /a "housekeeping_item_count+=1"
if defined housekeeping_list_file call :append_housekeeping_line %~1 %~2
exit /b 0

:append_housekeeping_line  kind  nameVar
setlocal EnableDelayedExpansion
>>"!housekeeping_list_file!" echo(%~1:"!%~2!"
endlocal & exit /b 0

:log_housekeeping  side  label  [target]
rem Log "label : ..." for the housekeeping items skipped at the side's drive
rem root, one per line, or why there are none (side: source or
rem destination, the directories robocopy copies between). target: console,
rem log or both (the default).
setlocal
set "housekeeping_target=%~3"
if not defined housekeeping_target set "housekeeping_target=both"
set "text=n/a (not a drive root)"
call :is_drive_root %~1_with_backslash || (
    call :log_field "%~2" text %housekeeping_target%
    endlocal & exit /b 0
)
if "%~1"=="source" (set "list_file=%temp_housekeeping_source%") else set "list_file=%temp_housekeeping_destination%"
set "item_count=0"
if exist "%list_file%" for /f "usebackq tokens=1* delims=:" %%A in ("%list_file%") do set /a "item_count+=1"
set "text=none present"
if %item_count% gtr 0 set "text=%item_count% item(s), excluded by exact path:"
call :log_field "%~2" text %housekeeping_target%
if %item_count% equ 0 (endlocal & exit /b 0)
for /f "usebackq tokens=1* delims=:" %%A in ("%list_file%") do (
    set "item_name=%%~B"
    if "%%A"=="D" (set "item_kind=directory") else set "item_kind=file"
    call :log_housekeeping_line item_name item_kind %housekeeping_target%
)
endlocal & exit /b 0

:log_housekeeping_line  nameVar  kindVar  target
setlocal EnableDelayedExpansion
set "msg=                        !%~1! (!%~2!)"
call :emit_free_text msg %~3
endlocal & exit /b 0

:add_warning  msgVar
rem Add "[WARN] <text>" to the warnings list (the first section of the log
rem header) and to the warnings repeated in the summary, unless the same
rem warning is listed already (the history checks before and after the copy
rem can find the same thing). The list is read with delayed expansion off,
rem so a "!" in a listed warning survives the comparison.
setlocal DisableDelayedExpansion
call :copy_variable %~1 warning_text
set "warning_already_listed="
if exist "%temp_warnings%" for /f "usebackq delims=" %%L in ("%temp_warnings%") do (
    set "listed_warning=%%L"
    call :is_same_warning && set "warning_already_listed=1"
)
if defined warning_already_listed (endlocal & exit /b 0)
setlocal EnableDelayedExpansion
>>"!temp_warnings!" echo([WARN] !warning_text!
set "tagged_warning=[WARN] !warning_text!"
call :keep_summary_line tagged_warning warnings
endlocal & endlocal & exit /b 0

:is_same_warning
rem Caller's scope (:add_warning): exit 0 if listed_warning is "[WARN] "
rem followed by warning_text.
setlocal EnableDelayedExpansion
if "!listed_warning!"=="[WARN] !warning_text!" (endlocal & exit /b 0)
endlocal & exit /b 1

:read_clock_status
rem Set header_time_source and header_last_sync from "w32tm /query /status
rem /verbose", and warn unless the time service synchronised the clock no
rem longer than CLOCK_SYNC_MAX_AGE_HOURS ago. w32tm prints its lines in a
rem fixed order (1 leap indicator, ... 6 reference id, 7 last successful
rem sync time, 8 source; the verbose part ends with the time since the last
rem good sync, in seconds), so lines are picked by position and work in any
rem display language. The time service keeps no record of a sync from
rem before it last started (it starts and stops on demand): until its first
rem sync it reports leap indicator 3 and reference id 0x00000000, and its
rem "time since" then counts from some other moment (owner's machine,
rem 2026-10-19), so the age is only read once it has synchronised. Such a
rem state is reported as what it is: no record of a sync, so the clock's
rem accuracy can't be confirmed (round 12.3: "not synchronised" a while
rem after the owner had synced the clock).
set "header_time_source=unknown"
set "header_last_sync=unknown"
set "time_source_summary=unknown"
set "last_sync_summary=unknown"
set "clock_unsynced_reason="
"%tool_w32tm%" /query /status /verbose >"%temp_clock_status%" 2>&1
if errorlevel 1 (
    set "header_time_source=unavailable (time service off, or w32tm needs administrator)"
    set "time_source_summary=unavailable"
    set "msg=The clock's synchronisation could not be checked (w32tm failed): times in this record rely on this machine's clock."
    call :add_warning msg
    set "clock_warned=1"
    exit /b 0
)
set "clock_line_number=0"
set "clock_leap_indicator="
set "clock_reference_id="
set "clock_last_sync_text=unknown"
set "clock_seconds_since_sync="
for /f "usebackq delims=" %%L in ("%temp_clock_status%") do (
    set "clock_line=%%L"
    call :read_clock_line
)
call :work_out_clock_sync_age
rem Kept from earlier versions as an extra catch (English output only): a
rem local or free-running clock named as the source.
if not defined clock_unsynced_reason "%tool_findstr%" /i /c:"Local CMOS Clock" /c:"Free-running System Clock" "%temp_clock_status%" >nul 2>&1 && set "clock_unsynced_reason=w32tm reports a local clock as its source"
if defined clock_unsynced_reason (
    set "msg=The clock's accuracy can't be confirmed (%clock_unsynced_reason%): times in this record rely on this machine's own clock."
    call :add_warning msg
    set "clock_warned=1"
)
exit /b 0

:read_clock_line
rem Caller's scope (:read_clock_status): one line of w32tm output in
rem clock_line, numbered by clock_line_number (FOR /F skips the empty line
rem in the middle, so the numbers are of the lines with text). Keeps the
rem value after "label: ", without trailing spaces; the last line's value
rem is the time since the last good sync.
set /a "clock_line_number+=1"
set "clock_line_value=%clock_line:*: =%"
setlocal EnableDelayedExpansion
for /l %%I in (1,1,%OUTPUT_MAX_INDENT%) do if "!clock_line_value:~-1!"==" " set "clock_line_value=!clock_line_value:~0,-1!"
endlocal & set "clock_line_value=%clock_line_value%"
if %clock_line_number% equ 1 set "clock_leap_indicator=%clock_line_value:~0,1%"
if %clock_line_number% equ 6 set "clock_reference_id=%clock_line_value:~0,10%"
if %clock_line_number% equ 7 set "clock_last_sync_text=%clock_line_value%"
if %clock_line_number% equ 8 set "header_time_source=%clock_line_value%"
if %clock_line_number% equ 8 set "time_source_summary=%clock_line_value%"
if %clock_line_number% gtr 9 set "clock_seconds_since_sync=%clock_line_value%"
exit /b 0

:work_out_clock_sync_age
rem Caller's scope (:read_clock_status): from the values :read_clock_line
rem kept, header_last_sync and clock_unsynced_reason (empty when the last
rem sync is known and recent enough). The time since the last good sync
rem ("7.8546526s": digits, a decimal part, "s") is read as whole seconds;
rem a last line of any other form, or more than nine digits, and the age is
rem not known (never taken as recent).
if "%clock_reference_id%"=="0x00000000" (
    set "header_last_sync=none since the time service started (w32tm: %clock_last_sync_text%)"
    set "last_sync_summary=none since service start"
    set "clock_unsynced_reason=the time service has no record of a synchronisation since it started"
    exit /b 0
)
rem 0x4C4F434C is "LOCL": the machine's own clock as the reference.
if "%clock_reference_id%"=="0x4C4F434C" (
    set "header_last_sync=%clock_last_sync_text% (local time, as w32tm reports it)"
    set "last_sync_summary=local clock"
    set "clock_unsynced_reason=w32tm reports the local clock as its reference"
    exit /b 0
)
if "%clock_leap_indicator%"=="3" (
    set "header_last_sync=%clock_last_sync_text% (local time, as w32tm reports it)"
    set "last_sync_summary=not synchronised"
    set "clock_unsynced_reason=w32tm reports leap indicator 3, not synchronised"
    exit /b 0
)
set "clock_sync_age_seconds="
if defined clock_seconds_since_sync if "%clock_seconds_since_sync:~-1%"=="s" for /f "delims=.,s" %%S in ("%clock_seconds_since_sync%") do set "clock_sync_age_seconds=%%S"
if defined clock_sync_age_seconds for /f "delims=0123456789" %%X in ("%clock_sync_age_seconds%") do set "clock_sync_age_seconds="
if defined clock_sync_age_seconds if not "%clock_sync_age_seconds:~9%"=="" set "clock_sync_age_seconds="
if not defined clock_sync_age_seconds (
    set "header_last_sync=%clock_last_sync_text% (local time, as w32tm reports it); the time since can't be read"
    set "last_sync_summary=time since unknown"
    set "clock_unsynced_reason=the time since the last synchronisation can't be read"
    exit /b 0
)
call :describe_duration clock_sync_age_seconds clock_sync_age_text
set "header_last_sync=%clock_last_sync_text% (local time, as w32tm reports it), %clock_sync_age_text% ago"
set "last_sync_summary=%clock_sync_age_text% ago"
set /a "clock_sync_max_age_seconds=CLOCK_SYNC_MAX_AGE_HOURS * 3600"
if %clock_sync_age_seconds% gtr %clock_sync_max_age_seconds% set "clock_unsynced_reason=the last synchronisation was %clock_sync_age_text% ago, more than %CLOCK_SYNC_MAX_AGE_HOURS% hours"
exit /b 0

:describe_duration  secondsVar  outVar
rem A count of seconds as words for a header or warning: "n s" under a
rem minute, "n min" under two hours, "n h" under two days, else "n days".
setlocal EnableDelayedExpansion
set /a "seconds=!%~1!"
set "unit=s"
set /a "amount=seconds"
if !seconds! geq 60 (
    set "unit=min"
    set /a "amount=seconds / 60"
)
if !seconds! geq 7200 (
    set "unit=h"
    set /a "amount=seconds / 3600"
)
if !seconds! geq 172800 (
    set "unit=days"
    set /a "amount=seconds / 86400"
)
set "text=!amount! !unit!"
endlocal & set "%~2=%text%"
exit /b 0

:check_power
rem Warn if this machine may sleep or hibernate during the copy. Reads the
rem current power plan (SLEEP_SETTINGS, lid action). Pure batch can't read
rem whether the machine is on mains or battery right now, so the warnings
rem cover both. Sets header_sleep for the log header.
setlocal EnableDelayedExpansion
set "power_warned="
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
set "sleep_summary="
if not defined settings_readable set "sleep_text=unknown (power settings could not be read)" & set "sleep_summary=unknown"
if not defined sleep_text if !sleep_seconds_mains! equ 0 if !sleep_seconds_battery! equ 0 set "sleep_text=never, on mains or battery" & set "sleep_summary=never"
if not defined sleep_text if !sleep_seconds_mains! equ 0 set "sleep_text=never on mains; after !minutes_battery! min on battery" & set "sleep_summary=mains never, battery !minutes_battery! min"
if not defined sleep_text if !sleep_seconds_battery! equ 0 set "sleep_text=after !minutes_mains! min on mains; never on battery" & set "sleep_summary=mains !minutes_mains! min, battery never"
if not defined sleep_text set "sleep_text=after !minutes_mains! min on mains; after !minutes_battery! min on battery" & set "sleep_summary=mains !minutes_mains! min, battery !minutes_battery! min"
if not defined settings_readable (
    set "msg=The power settings could not be read: make sure this machine won't sleep or hibernate during the copy."
    call :add_warning msg
    set "power_warned=1"
)
if defined settings_readable if !sleep_seconds_mains! gtr 0 (
    set "msg=This machine sleeps or hibernates after !minutes_mains! min idle, even on mains power: Windows may treat a long copy as idle and stop it part-way. Set sleep and hibernate to Never (Settings, System, Power)."
    call :add_warning msg
    set "power_warned=1"
)
if defined settings_readable if !sleep_seconds_mains! equ 0 if !sleep_seconds_battery! gtr 0 (
    set "msg=On battery this machine sleeps after !minutes_battery! min idle: keep it plugged in for the whole copy."
    call :add_warning msg
    set "power_warned=1"
)
call :read_power_values SUB_BUTTONS LIDACTION lid_action
set "lid_sleeps="
if defined lid_action_AC if !lid_action_AC! neq 0 set "lid_sleeps=1"
if defined lid_action_DC if !lid_action_DC! neq 0 set "lid_sleeps=1"
if defined lid_sleeps (
    set "msg=If this is a laptop, keep the lid open: closing it sleeps, hibernates or shuts it down."
    call :add_warning msg
    set "power_warned=1"
)
endlocal & set "header_sleep=%sleep_text%" & set "sleep_summary=%sleep_summary%" & set "power_warned=%power_warned%"
exit /b 0

:read_power_values  subgroup  setting  prefix
rem Set <prefix>_AC and <prefix>_DC to the current power plan's values for a
rem setting. powercfg /q prints the setting's min, max and increment and then
rem the AC and DC values, all as 0x numbers, so the last two 0x values are AC
rem and DC in any display language. Both are cleared if it can't be read.
setlocal EnableDelayedExpansion
set "second_last_value="
set "last_value="
if defined tool_powercfg for /f "delims=" %%L in ('2^>nul "%tool_powercfg%" /q SCHEME_CURRENT %~1 %~2 ^| "%tool_find%" "0x"') do (
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
    for /f "tokens=2,*" %%A in ('2^>nul "%tool_reg%" query "!registry_key!" /v %%V ^| "%tool_find%" /i "%%V"') do set "windows_%%V=%%B"
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
rem session. Falls back to USERDOMAIN\USERNAME, marked as such. <outVar>_name
rem gets the name alone (the display's environment cell).
setlocal
set "user_name="
set "user_sid="
if defined tool_whoami for /f "tokens=1,2 delims=," %%A in ('2^>nul "%tool_whoami%" /user /fo csv /nh') do (
    set "user_name=%%~A"
    set "user_sid=%%~B"
)
set "text=%USERDOMAIN%\%USERNAME% (from environment variables; whoami failed)"
set "name_only=%USERDOMAIN%\%USERNAME% (environment variables)"
if defined user_name set "text=%user_name% (SID %user_sid%)"
if defined user_name set "name_only=%user_name%"
endlocal & set "%~1=%text%" & set "%~1_name=%name_only%"
exit /b 0

:describe_host  outVar
rem The computer name from "hostname", falling back to COMPUTERNAME, marked.
setlocal
set "host_name="
if defined tool_hostname for /f "delims=" %%H in ('2^>nul "%tool_hostname%"') do if not defined host_name set "host_name=%%H"
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
if defined tool_fsutil for /f "delims=" %%L in ('2^>nul ^<nul "%tool_fsutil%" fsinfo volumeinfo %~1') do for %%T in (%%L) do for %%F in (%KNOWN_FILESYSTEMS%) do (
    if not defined filesystem_found if /i "%%~T"=="%%F" set "filesystem_found=%%F"
)
exit /b 0

:filesystem_from_chkntfs  drive
rem Caller's scope (:describe_volume): set filesystem_found from chkntfs
rem ("... file system is NTFS.").
if defined tool_chkntfs for /f "delims=" %%L in ('2^>nul "%tool_chkntfs%" %~1') do for %%T in (%%L) do for %%F in (%KNOWN_FILESYSTEMS%) do (
    if not defined filesystem_found if /i "%%~T"=="%%F" set "filesystem_found=%%F"
    if not defined filesystem_found if /i "%%~T"=="%%F." set "filesystem_found=%%F"
)
exit /b 0

:warn_unknown_filesystem  side  drive
rem No method in FILESYSTEM_METHODS could read the side's file system (not
rem elevated, fsutil and chkntfs can't read the system volume; test round
rem 8). Times are then compared exactly unless the other side needs /fft, so
rem a FAT or exFAT volume could fail the metadata check: the warning says why
rem in advance. The verdict is unaffected.
set "msg=The %~1 volume's file system (%~2) couldn't be read"
if not defined is_elevated set "msg=%msg% (not elevated: fsutil and chkntfs can't read some volumes, such as the system volume)"
set "msg=%msg%: if it is FAT or exFAT, last-modified times compared exactly can differ by up to 2 s and fail the metadata check."
call :add_warning msg
set "filesystem_warned_%~1=1"
exit /b 0

:warn_destination_filesystem
rem Warn about a destination file system listed in FILESYSTEM_WARNING_<name>.
rem A warning only: robocopy fails any file that doesn't fit.
setlocal EnableDelayedExpansion
set "msg=The destination file system is !destination_filesystem!: !FILESYSTEM_WARNING_%destination_filesystem%!"
call :add_warning msg
endlocal & set "filesystem_warned_destination=1" & exit /b 0

rem -- Copy -------------------------------------------------------------------

:count_copy_pass_files  passId
rem Before the header (:prepare_copy_passes), one pass: a list-only robocopy
rem of the source against the destination as it is, with the pass's filter
rem and the drive-root exclusions, no job header, so the files the pass will
rem copy are known (2.8.0; before, against an empty directory, so every
rem file of the class): their count (the lines naming the source directory,
rem one per file) into copy_pass_<pass>_total, and the bytes they hold
rem (the Copied column of the summary's Bytes row, :read_robocopy_summary)
rem into copy_pass_<pass>_bytes, for :check_destination_free_space; both
rem "unknown" when the listing failed (robocopy exit 8 or more; the pass
rem then runs whatever it holds). The count lets :run_copy_pass skip a pass
rem with nothing to copy in its class (a pass over 100,000 small files that
rem copies none of them costs about a millisecond per file: workshop,
rem 2026-10-18) and gives the live display its total. With the live
rem display, for a pass whose
rem PASS_<id>_PROGRESS is bytes, each file's size in MB (its last six digits
rem dropped: set /a is 32-bit) and path are kept in listing order, which is
rem the order robocopy /mt:1 copies them in, as copy_pass_<pass>_file_<n>_name,
rem _name_length and _cumulative_mb, and copy_pass_<pass>_progress says
rem bytes; a pass of
rem more than DASHBOARD_BYTES_TABLE_MAX_FILES files is shown by files. The
rem listing is read with delayed expansion off, so "!" in a path survives.
rem Caller's scope.
setlocal EnableDelayedExpansion
set "excluded_dirs="
set "excluded_files="
call :add_housekeeping_exclusions source
call :add_housekeeping_exclusions destination
call :build_exclusion_args
"%tool_robocopy%" "!source_path! " "!destination_path! " *.* !COPY_COUNT_FLAGS! !PASS_%~1_FILTER! !backup_flag! !exclusion_args! /unilog:"!temp_robocopy_unicode_output!" >nul 2>&1
set "list_exit_code=!errorlevel!"
endlocal & set "count_copy_pass_files_exit_code=%list_exit_code%"
set "copy_pass_%~1_total=unknown"
set "copy_pass_%~1_bytes=unknown"
set "copy_pass_%~1_progress=files"
if %count_copy_pass_files_exit_code% geq 8 goto count_copy_pass_files_done
call :is_robocopy_exit_code_in_range count_copy_pass_files_exit_code || goto count_copy_pass_files_done
"%tool_find%" /c /i "%source_with_backslash%" <"%temp_robocopy_unicode_output%" >"%temp_count%" 2>nul
for /f "usebackq" %%N in ("%temp_count%") do set "copy_pass_%~1_total=%%N"
type "%temp_robocopy_unicode_output%" >"%temp_copy_pass_listing%" 2>nul
call :read_robocopy_summary temp_copy_pass_listing && call :keep_copy_pass_bytes %~1
if not "%dashboard_mode%"=="live" goto count_copy_pass_files_done
call :copy_variable PASS_%~1_PROGRESS count_copy_pass_files_progress
if /i not "%count_copy_pass_files_progress%"=="bytes" goto count_copy_pass_files_done
call :copy_variable copy_pass_%~1_total count_copy_pass_files_total
if "%count_copy_pass_files_total%"=="unknown" goto count_copy_pass_files_done
if %count_copy_pass_files_total% gtr %DASHBOARD_BYTES_TABLE_MAX_FILES% goto count_copy_pass_files_done
set "copy_pass_%~1_progress=bytes"
set "count_copy_pass_files_index=0"
set "count_copy_pass_files_cumulative_mb=0"
for /f "usebackq tokens=1*" %%S in ("%temp_copy_pass_listing%") do if not "%%T"=="" (
    set "count_copy_pass_files_size=%%S"
    set "count_copy_pass_files_path=%%T"
    call :keep_copy_pass_listed_file %~1
)
rem A line cmd couldn't carry (a path over about 8,000 characters: section
rem 6 of the conventions) leaves the table short: the pass is then shown by
rem files.
if not "%count_copy_pass_files_index%"=="%count_copy_pass_files_total%" set "copy_pass_%~1_progress=files"
:count_copy_pass_files_done
del "%temp_robocopy_unicode_output%" >nul 2>&1
del "%temp_copy_pass_listing%" >nul 2>&1
exit /b 0

:keep_copy_pass_bytes  passId
rem Caller's scope (:count_copy_pass_files): the bytes the pass will copy,
rem from the summary :read_robocopy_summary just read.
set "copy_pass_%~1_bytes=%robocopy_summary_bytes_copied%"
exit /b 0

:prepare_copy_passes
rem Before the header (MAIN, a copy run; 2.8.0): each pass's files and bytes
rem still to copy (:count_copy_pass_files), then the destination volume's
rem free space against them, and on a file system with a file-size limit
rem the source's largest files against it (:check_destination_free_space):
rem exit 1 with abort_reason when the copy can't fit, so the run stops
rem before the header and before anything is copied; a finding that is only
rem a warning goes into the header's Warnings. Until 2.8.0 the passes were
rem counted at the copy step, under the live display.
for %%P in (%COPY_PASSES%) do call :count_copy_pass_files %%P
call :check_destination_free_space || exit /b 1
exit /b 0

:check_destination_free_space
rem Caller's scope (:prepare_copy_passes). The bytes the passes will copy
rem (copy_pass_<pass>_bytes, added as digit strings), plus one part in
rem 10^FREE_SPACE_MARGIN_DROP_DIGITS of them and FREE_SPACE_MARGIN_MB for
rem the run record and the file system's slack, against the destination
rem volume's free bytes (:read_free_bytes). Too little: exit 1 with
rem abort_reason naming both numbers; nothing has been copied. Free space
rem or the bytes to copy that can't be read: a warning, and the copy goes on
rem (robocopy's ERROR 112 fails the run if the volume fills). Then, when
rem the destination's file system has a file-size limit
rem (FILESYSTEM_FILE_LIMIT_<fs>), the source is listed for files of that
rem size or more (:find_files_over_limit): any makes the run stop too, the
rem first named, since the copy would fail part-way (owner, 2026-10-24).
set "bytes_to_copy=0"
set "bytes_to_copy_known=1"
for %%P in (%COPY_PASSES%) do call :add_pass_bytes_to_copy %%P
if not defined bytes_to_copy_known (
    set "msg=Free space: the bytes to copy couldn't be read from a pass's listing, so the destination's free space isn't compared with them (robocopy's ERROR 112 fails the run if the volume fills)."
    call :add_warning msg
    goto check_destination_free_space_limit
)
set "bytes_margin=%bytes_to_copy%"
call :drop_last_digits bytes_margin %FREE_SPACE_MARGIN_DROP_DIGITS%
set /a "bytes_margin_fixed=FREE_SPACE_MARGIN_MB * 1048576"
call :add_decimal_strings bytes_margin bytes_margin_fixed bytes_margin
call :add_decimal_strings bytes_to_copy bytes_margin bytes_required
call :read_free_bytes destination_volume_directory bytes_free
if "%bytes_free%"=="unknown" (
    set "msg=Free space: the destination volume's free space couldn't be read (fsutil volume diskfree and dir both failed), so it isn't compared with the bytes to copy (robocopy's ERROR 112 fails the run if the volume fills)."
    call :add_warning msg
    goto check_destination_free_space_limit
)
call :compare_decimal_strings bytes_free bytes_required free_space_order
if not "%free_space_order%"=="less" goto check_destination_free_space_limit
call :format_decimal_string bytes_required bytes_required_text
call :format_decimal_string bytes_to_copy bytes_to_copy_text
call :format_decimal_string bytes_margin bytes_margin_text
call :format_decimal_string bytes_free bytes_free_text
set "abort_reason=Not enough free space on the destination volume: %bytes_required_text% bytes needed (%bytes_to_copy_text% to copy, plus a margin of %bytes_margin_text% for the run record and the file system), %bytes_free_text% bytes free. Nothing was copied."
exit /b 1
:check_destination_free_space_limit
if not defined destination_filesystem exit /b 0
if not defined FILESYSTEM_FILE_LIMIT_%destination_filesystem% exit /b 0
call :copy_variable FILESYSTEM_FILE_LIMIT_%destination_filesystem% filesystem_file_limit
call :copy_variable FILESYSTEM_FILE_LIMIT_%destination_filesystem%_TEXT filesystem_file_limit_text
call :find_files_over_limit filesystem_file_limit
if "%over_limit_count%"=="unknown" (
    set "msg=The destination's file system is %destination_filesystem%, which can't hold a file of %filesystem_file_limit_text% or more, and the source couldn't be listed for such files: if it holds one, the copy fails on it."
    call :add_warning msg
    exit /b 0
)
if %over_limit_count% equ 0 exit /b 0
call :format_decimal_string over_limit_example_size over_limit_example_size_text
set "abort_reason=The destination's file system is %destination_filesystem%, which can't hold a file of %filesystem_file_limit_text% or more, and the source has %over_limit_count% such file(s), e.g. %over_limit_example_path% (%over_limit_example_size_text% bytes): the copy would fail part-way. Choose a destination with another file system. Nothing was copied."
exit /b 1

:add_pass_bytes_to_copy  passId
rem Caller's scope (:check_destination_free_space): one pass's bytes into
rem bytes_to_copy; a pass whose listing failed clears bytes_to_copy_known.
call :copy_variable copy_pass_%~1_bytes pass_bytes_to_copy
if "%pass_bytes_to_copy%"=="unknown" (set "bytes_to_copy_known=" & exit /b 0)
call :add_decimal_strings bytes_to_copy pass_bytes_to_copy bytes_to_copy
exit /b 0

:find_files_over_limit  limitVar
rem Caller's scope (:check_destination_free_space): the source's files of
rem the limit's size or more (a list-only robocopy with /min, the same
rem exclusions as the passes): their count into over_limit_count ("unknown"
rem when the listing failed) and the first one's size and path into
rem over_limit_example_size and _path. The listing is read with delayed
rem expansion off, so "!" in a path survives.
setlocal EnableDelayedExpansion
set "excluded_dirs="
set "excluded_files="
call :add_housekeeping_exclusions source
call :add_housekeeping_exclusions destination
call :build_exclusion_args
"%tool_robocopy%" "!source_path! " "!destination_path! " *.* !COPY_COUNT_FLAGS! /min:!%~1! !backup_flag! !exclusion_args! /unilog:"!temp_robocopy_unicode_output!" >nul 2>&1
set "list_exit_code=!errorlevel!"
endlocal & set "over_limit_exit_code=%list_exit_code%"
set "over_limit_count=unknown"
set "over_limit_example_size="
set "over_limit_example_path="
if %over_limit_exit_code% geq 8 goto find_files_over_limit_done
call :is_robocopy_exit_code_in_range over_limit_exit_code || goto find_files_over_limit_done
"%tool_find%" /c /i "%source_with_backslash%" <"%temp_robocopy_unicode_output%" >"%temp_count%" 2>nul
for /f "usebackq" %%N in ("%temp_count%") do set "over_limit_count=%%N"
if "%over_limit_count%"=="0" goto find_files_over_limit_done
type "%temp_robocopy_unicode_output%" >"%temp_copy_pass_listing%" 2>nul
for /f "usebackq tokens=1*" %%S in ("%temp_copy_pass_listing%") do if not defined over_limit_example_path if not "%%T"=="" (
    set "over_limit_example_size=%%S"
    set "over_limit_example_path=%%T"
)
:find_files_over_limit_done
del "%temp_robocopy_unicode_output%" >nul 2>&1
del "%temp_copy_pass_listing%" >nul 2>&1
exit /b 0

:read_free_bytes  directoryVar  outVar
rem The free bytes of the volume holding the directory, as a digit string,
rem or "unknown": from "fsutil volume diskfree <drive>:" (the number after
rem the first line's colon; the labels are localised, so the line is taken
rem by position), else from DIR's last line (the third word from its end:
rem "<n> Dir(s)  <bytes> bytes free" in any language), which also serves a
rem network path. Thousands separators are removed and only digits are
rem taken (:digits_only): nothing read is run. Delayed expansion is off, so
rem the path stays as it is.
setlocal DisableDelayedExpansion
call :copy_variable %~1 free_space_directory
set "free_bytes_text="
set "free_space_drive=%free_space_directory:~0,2%"
if defined tool_fsutil if "%free_space_drive:~1,1%"==":" (
    "%tool_fsutil%" volume diskfree %free_space_drive% >"%temp_free_space%" 2>nul <nul
    for /f "usebackq tokens=2 delims=:" %%A in ("%temp_free_space%") do if not defined free_bytes_text for /f "tokens=1" %%B in ("%%A") do set "free_bytes_text=%%B"
)
call :digits_only free_bytes_text
if not defined free_bytes_text (
    if "%free_space_directory:~-1%"=="\" set "free_space_directory=%free_space_directory:~0,-1%"
    set "free_bytes_last_line="
    dir "%free_space_directory%\" >"%temp_free_space%" 2>nul
    for /f "usebackq tokens=*" %%L in ("%temp_free_space%") do set "free_bytes_last_line=%%L"
    call :third_word_from_end free_bytes_last_line free_bytes_text
    call :digits_only free_bytes_text
)
if not defined free_bytes_text set "free_bytes_text=unknown"
endlocal & set "%~2=%free_bytes_text%"
exit /b 0

:digits_only  textVar
rem Caller's scope: the variable's thousands separators ("," and ".") and
rem spaces removed; cleared unless what is left is one or more digits.
setlocal EnableDelayedExpansion
set "digits=!%~1!"
if defined digits set "digits=!digits:,=!"
if defined digits set "digits=!digits:.=!"
if defined digits set "digits=!digits: =!"
set "digits_bad="
if not defined digits set "digits_bad=1"
if defined digits for /f "delims=0123456789" %%X in ("!digits!") do set "digits_bad=1"
if defined digits_bad set "digits="
endlocal & set "%~1=%digits%"
exit /b 0

:third_word_from_end  lineVar  outVar
rem The third word from the end of a line (DIR's "<bytes> bytes free"), by
rem a bounded walk over its words (RECORD_CELL_MAX_WORDS; section 6 of the
rem conventions: no goto loop), or empty.
setlocal EnableDelayedExpansion
set "rest=!%~1!"
set "w1="
set "w2="
set "w3="
for /l %%I in (1,1,%RECORD_CELL_MAX_WORDS%) do if defined rest (
    for /f "tokens=1*" %%A in ("!rest!") do (
        set "w1=!w2!"
        set "w2=!w3!"
        set "w3=%%A"
        set "rest=%%B"
    )
)
endlocal & set "%~2=%w1%"
exit /b 0

:keep_copy_pass_listed_file  passId
rem Caller's scope (:count_copy_pass_files, delayed expansion off): one
rem listed file, in count_copy_pass_files_size and _path, as the next entry
rem of the pass's table. The listing ends with robocopy's job summary (its
rem rows have a second token too): once as many files as the listing
rem counted are in the table, the rest of the lines are the summary.
if %count_copy_pass_files_index% geq %count_copy_pass_files_total% exit /b 0
set /a "count_copy_pass_files_index+=1"
set "count_copy_pass_files_mb=%count_copy_pass_files_size:~0,-6%"
if not defined count_copy_pass_files_mb set "count_copy_pass_files_mb=0"
set /a "count_copy_pass_files_cumulative_mb+=count_copy_pass_files_mb"
call :strlen count_copy_pass_files_path count_copy_pass_files_path_length
for %%N in (%count_copy_pass_files_index%) do set "copy_pass_%~1_file_%%N_name=%count_copy_pass_files_path%"
for %%N in (%count_copy_pass_files_index%) do set "copy_pass_%~1_file_%%N_name_length=%count_copy_pass_files_path_length%"
for %%N in (%count_copy_pass_files_index%) do set "copy_pass_%~1_file_%%N_cumulative_mb=%count_copy_pass_files_cumulative_mb%"
exit /b 0

:run_copy_pass  passId
rem One robocopy pass as defined by the PASS_<passId>_* row in CONFIG. A pass
rem whose listing (:count_copy_pass_files) found no file in its class is
rem skipped, unless it is the last pass: that one always runs, so that
rem robocopy creates the directories (/e) whatever the passes hold. With the
rem live display, the pass's state goes to temp_dashboard_pass for the
rem display helper, and a pass marked PASS_<id>_PERCENTAGES=yes runs without
rem /np (its percentages are left out of the log).
setlocal EnableDelayedExpansion
set "label=!PASS_%~1_LABEL!"
set "threads=!PASS_%~1_THREADS!"
if /i "!threads!"=="auto" call :auto_thread_count threads
set "heading=Copy: !label!, threads: !threads!" & call :write_section_heading heading both
if "!copy_pass_%~1_total!"=="0" if not "%~1"=="!copy_pass_last!" (
    set "msg=No files in this pass (none of this size in the source): skipped."
    call :show_and_log msg
    endlocal & exit /b 0
)
set "excluded_dirs="
set "excluded_files="
call :add_housekeeping_exclusions source
call :add_housekeeping_exclusions destination
call :build_exclusion_args
set "pass_progress_flags=!robocopy_progress_flags!"
set "pass_percentages=no"
if defined dashboard_active if /i "!PASS_%~1_PERCENTAGES!"=="yes" (
    set "pass_progress_flags=!robocopy_progress_flags:/np=!"
    set "pass_percentages=yes"
)
rem The pass's state for the display helper. The block form puts cmd's own
rem message for a failed redirection (the helper reading the file at that
rem moment) under the 2>nul too: a message would move the block down.
if defined dashboard_active call :dashboard_read_clock pass_started_clock
if defined dashboard_active (> "!temp_dashboard_pass!" echo %~1 running !pass_started_clock!) 2>nul
set "log_option="
if "!log_enabled!"=="1" set log_option=/unilog:"!temp_robocopy_unicode_output!"
rem A non-forensic run with the display (2.7.0): the same file, for the
rem display helper alone; nothing of it is kept (:use_eta_mode).
if defined dashboard_active set log_option=/unilog:"!temp_robocopy_unicode_output!"
"%tool_robocopy%" "!source_path! " "!destination_path! " *.* !COPY_FLAGS! !PASS_%~1_FILTER! !PASS_%~1_FLAGS! /mt:!threads! /r:!RETRY_COUNT! /w:!RETRY_WAIT_SECONDS! !pass_progress_flags! !backup_flag! !exclusion_args! !log_option! %robocopy_console_redirection%
set "pass_exit_code=!errorlevel!"
if defined dashboard_active (> "!temp_dashboard_pass!" echo %~1 copied) 2>nul
call :add_pass_summary_counts
if "!log_enabled!"=="1" call :save_robocopy_unicode_output log_staged_path append !pass_percentages! pass_exit_code
call :report_dropped_robocopy_lines
call :report_robocopy_exit_code pass_exit_code
endlocal & set /a "copy_exit_codes|=%pass_exit_code%" & set "copy_log_incomplete=%copy_log_incomplete%" & set "copy_files_copied=%copy_files_copied%" & set "copy_files_skipped=%copy_files_skipped%" & set "copy_files_failed=%copy_files_failed%" & set "copy_files_mismatch=%copy_files_mismatch%" & set "copy_files_extras=%copy_files_extras%" & set "copy_files_total=%copy_files_total%" & set "copy_passes_counted=%copy_passes_counted%" & set "copy_counts_missing=%copy_counts_missing%" & exit /b 0

:add_pass_summary_counts
rem Caller's scope (:run_copy_pass, after robocopy and before its output is
rem converted into the log and deleted): the pass's Files row (robocopy's
rem job summary, :read_robocopy_summary) added to the copy_files_<column>
rem counters for the Copy row's words (:describe_copy_counts, 2.8.0).
rem Every pass lists every file: the ones its size filter leaves out are
rem its Skipped (round 14.8: "48 files copied, 48 files already there"),
rem so the largest Total and the number of passes are kept, and
rem :describe_copy_counts takes the files of the other passes off the
rem skipped count. A
rem pass without a readable summary (no output file: a non-forensic run
rem without the display; or robocopy stopped) sets copy_counts_missing, and
rem the Copy row keeps the exit codes alone.
if not defined log_option (set "copy_counts_missing=1" & exit /b 0)
type "!temp_robocopy_unicode_output!" >"!temp_robocopy_summary!" 2>nul
call :read_robocopy_summary temp_robocopy_summary || (set "copy_counts_missing=1" & exit /b 0)
set /a "copy_files_copied+=robocopy_summary_files_copied, copy_files_skipped+=robocopy_summary_files_skipped, copy_files_failed+=robocopy_summary_files_failed, copy_files_mismatch+=robocopy_summary_files_mismatch, copy_files_extras+=robocopy_summary_files_extras, copy_passes_counted+=1"
if %robocopy_summary_files_total% gtr %copy_files_total% set "copy_files_total=%robocopy_summary_files_total%"
exit /b 0

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
set "heading=Copy: custody records (not evidence)" & call :write_section_heading heading both
set "msg=running: custody records (not evidence)" & call :dashboard_stage copy msg
if not defined source_set_path (
    set "msg=No custody files to copy: raw evidence (a first copy)."
    call :show_and_log msg
    endlocal & exit /b 0
)
set "log_option="
if "!log_enabled!"=="1" set log_option=/unilog:"!temp_robocopy_unicode_output!"
call :ignored_names_as_robocopy_arguments ignored_arguments
set "custody_exit_codes=0"
set "custody_extras_explained="
set "custody_found="
set "source_records_directory=!source_set_with_backslash!!RECORDS_DIR_NAME!"
call :is_directory source_records_directory && (
    set "custody_found=1"
    "%tool_robocopy%" "!source_set_with_backslash!!RECORDS_DIR_NAME! " "!destination_set_with_backslash!!RECORDS_DIR_NAME! " *.* !COPY_FLAGS! /xf !ignored_arguments! /j /mt:1 /r:!RETRY_COUNT! /w:!RETRY_WAIT_SECONDS! !robocopy_progress_flags! !backup_flag! !log_option! %robocopy_console_redirection%
    set "pass_exit_code=!errorlevel!"
    if "!log_enabled!"=="1" call :save_robocopy_unicode_output log_staged_path append no pass_exit_code
    call :report_dropped_robocopy_lines
    call :report_robocopy_exit_code pass_exit_code custody
    set /a "custody_exit_codes|=pass_exit_code"
)
if exist "!source_set_with_backslash!!SCRIPT_FILE_PREFIX!*!SCRIPT_FILE_EXT!" (
    set "custody_found=1"
    "%tool_robocopy%" "!source_set_path! " "!destination_set_path! " "!SCRIPT_FILE_PREFIX!*!SCRIPT_FILE_EXT!" /xf "!script_file_name!" !COPY_FLAGS! /lev:1 /j /mt:1 /r:!RETRY_COUNT! /w:!RETRY_WAIT_SECONDS! !robocopy_progress_flags! !backup_flag! !log_option! %robocopy_console_redirection%
    set "pass_exit_code=!errorlevel!"
    if "!log_enabled!"=="1" call :save_robocopy_unicode_output log_staged_path append no pass_exit_code
    call :report_dropped_robocopy_lines
    call :report_robocopy_exit_code pass_exit_code custody
    set /a "custody_exit_codes|=pass_exit_code"
)
if "!script_copy_route!"=="source" (
    "%tool_robocopy%" "!source_set_path! " "!destination_set_path! " "!script_file_name!" !COPY_FLAGS! /is /it /lev:1 /j /mt:1 /r:!RETRY_COUNT! /w:!RETRY_WAIT_SECONDS! !robocopy_progress_flags! !backup_flag! !log_option! %robocopy_console_redirection%
    set "pass_exit_code=!errorlevel!"
    if "!log_enabled!"=="1" call :save_robocopy_unicode_output log_staged_path append no pass_exit_code
    call :report_dropped_robocopy_lines
    call :report_robocopy_exit_code pass_exit_code custody
    set /a "custody_exit_codes|=pass_exit_code"
)
if not defined custody_found (
    set "msg=No run records or script copies in the source set."
    call :show_and_log msg
)
endlocal & set "copy_log_incomplete=%copy_log_incomplete%" & set /a "copy_exit_codes|=%custody_exit_codes%" & exit /b 0

:ignored_names_as_robocopy_arguments  outVar
rem IGNORED_CUSTODY_FILES as robocopy /xf arguments: each item quoted.
setlocal EnableDelayedExpansion
set "arguments="
set "remaining=!IGNORED_CUSTODY_FILES!"
for /l %%I in (1,1,%CONFIG_LIST_MAX_ITEMS%) do if defined remaining (
    set "item="
    for /f "tokens=1* delims=|" %%A in ("!remaining!") do (
        set "item=%%A"
        set "remaining=%%B"
    )
    if defined item set "arguments=!arguments! "!item!""
    if not defined item set "remaining="
)
endlocal & set "%~1=%arguments%"
exit /b 0

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
"%tool_attrib%" !attrib_switches! "!destination_path!" >nul 2>&1
set "attributes_now="
for %%A in ("!destination_path!") do set "attributes_now=%%~aA"
rem Each attribute is reported as the directory now has it: cleared, or a
rem warning that it couldn't be (round 12.10: attrib doesn't reach a
rem directory past 260 characters, and the log said "cleared" before the
rem warning that it wasn't).
set "cleared_names="
set "not_cleared_names="
for %%R in (%CONTAINER_ATTRIBUTES%) do for /f "tokens=1-3 delims=:" %%I in ("%%R") do (
    if /i "!attributes_after_copy:~%%I,1!"=="%%J" if "!attributes_before:~%%I,1!"=="-" (
        if /i "!attributes_now:~%%I,1!"=="%%J" (
            set "not_cleared_names=!not_cleared_names! %%K"
        ) else set "cleared_names=!cleared_names! %%K"
    )
)
if defined cleared_names (
    set "msg=Destination directory: cleared!cleared_names! (carried over from the source directory)."
    call :show_and_log msg
)
for %%K in (!not_cleared_names!) do (
    set "msg=[WARN] Could not clear %%K on the destination directory."
    call :show_and_log msg
    call :remember_problem msg
)
endlocal & exit /b 0

rem -- Verification -----------------------------------------------------------

:verify_copy
rem Forensic run. Check the copy, in the result block's order (owner,
rem 2026-10-18): first the metadata (size and last-modified time); then the
rem run records against the history and their seals, after hashing the
rem custody files; then the SHA-256 of every evidence file against the
rem reference record. The reference record is row 1's source hash record or,
rem if the source has no history, this run's own record of the source, made
rem now. So the source is hashed once per set, and every later copy is
rem checked back to it. The run records come before the compare: the compare
rem relies on the reference record having passed its seal. A check or a
rem relocation has no copy to compare sizes and times with: its Metadata
rem row is NONE (:skip_metadata_check); the rest is the same, on the set.
if "%run_kind%"=="copy" (call :check_metadata) else call :skip_metadata_check
set "heading=Run records: hashing the custody files in the destination set (not evidence)"
call :write_section_heading heading both
call :dashboard_stage_bar run_records hashed_count_custody custody_files_count
call :hash_custody_files
call :write_hash_csv custody || set /a "run_record_problem_count+=1"
rem The reference record: row 1's, read from its copy in the destination;
rem otherwise this run's own record of the source.
set "reference_name=%record_file_stem%_hashes_source.csv"
set "reference_csv_path=%staged_hash_csv_source%"
set "reference_seal_result_text=made by this run; sealed at the end of it"
if defined reference_run set "reference_name=%RECORD_FILE_PREFIX%%reference_run%_hashes_source.csv"
if defined reference_run set "reference_csv_path=%destination_set_with_backslash%%RECORDS_DIR_NAME%\%reference_run%\%RECORD_FILE_PREFIX%%reference_run%_hashes_source.csv"
if defined reference_run set "reference_seal_result_text="
call :dashboard_stage_bar run_records run_record_count history_row_count
call :check_run_records
call :work_out_run_records_status
call :dashboard_stage run_records result_run_records
if not defined reference_run (
    set "heading=Hash (SHA-256): hashing the source, which becomes the reference record (none in the source's history)"
    call :write_section_heading heading both
    set "dashboard_hash_detail=hashing the source, which becomes the reference record"
    call :dashboard_stage_bar hash hashed_units_source listing_units_total
    call :hash_directory source || set "hash_check_incomplete=1"
    call :write_hash_csv source || set "hash_check_incomplete=1"
)
set "heading=Hash (SHA-256): hashing the destination"
call :write_section_heading heading both
set "dashboard_hash_detail=hashing the destination"
call :dashboard_stage_bar hash hashed_units_destination listing_units_total
call :hash_directory destination || set "hash_check_incomplete=1"
call :write_hash_csv destination || set "hash_check_incomplete=1"
if not exist "%reference_csv_path%" (
    set "msg=[FAIL] The reference record %reference_name% was not found after the copy."
    call :show_and_log msg
    call :remember_problem msg
    set "hash_check_incomplete=1"
    exit /b 1
)
set "compare_lines_done=0"
set "dashboard_hash_detail=comparing the destination with the reference record"
call :dashboard_stage_bar hash compare_lines_done compare_line_count
call :compare_with_reference
exit /b 0

:skip_metadata_check
rem A check or a relocation: nothing was copied, so there is no source to
rem compare sizes and times with; the Metadata row says so (NONE, never a
rem PASS: nothing was compared).
set "heading=Metadata: no copy to compare with (%run_kind_switch%)"
call :write_section_heading heading both
call :work_out_metadata_status
call :show_and_log result_metadata
call :dashboard_stage metadata result_metadata
exit /b 0

:verify_plain_copy
rem Non-forensic run: hash every source file and its copy and compare them,
rem with the metadata check. Working files stay in TEMP; nothing is written
rem beside the copy, and the result is shown on screen only.
call :check_metadata
set "heading=Hash (SHA-256): hashing the source" & call :write_section_heading heading console
set "dashboard_hash_detail=hashing the source"
call :dashboard_stage_bar hash hashed_units_source listing_units_total
call :hash_directory source || set "hash_check_incomplete=1"
call :write_hash_csv source || set "hash_check_incomplete=1"
set "heading=Hash (SHA-256): hashing the destination" & call :write_section_heading heading console
set "dashboard_hash_detail=hashing the destination"
call :dashboard_stage_bar hash hashed_units_destination listing_units_total
call :hash_directory destination || set "hash_check_incomplete=1"
call :write_hash_csv destination || set "hash_check_incomplete=1"
set "reference_csv_path=%staged_hash_csv_source%"
set "compare_lines_done=0"
set "dashboard_hash_detail=comparing the destination with the source's hashes"
call :dashboard_stage_bar hash compare_lines_done compare_line_count
call :compare_with_reference
exit /b 0

:hash_custody_files
rem Forensic run. Hash the custody files in the destination set as they are
rem before this run's record is added: the run records, script copies and
rem the history file. Ignored names (IGNORED_CUSTODY_FILES) are left out.
rem They have a progress counter of their own and are never counted as
rem evidence.
type nul >"%temp_custody_list%"
set "custody_records_root=%destination_set_with_backslash%%RECORDS_DIR_NAME%\"
rem A first copy's destination has no records directory yet: this run makes
rem it when its record is written, so none is "no run records there yet".
rem One that is there and can't be listed is a Run records failure.
set "custody_records_root_present="
call :is_directory custody_records_root && set "custody_records_root_present=1"
type nul >"%temp_directory_listing%"
if defined custody_records_root_present call :list_directory "/b /s /a-d" custody_records_root temp_directory_listing || call :report_custody_listing_failed custody_records_root
for /f "usebackq eol=/ delims=" %%F in ("%temp_directory_listing%") do (
    set "custody_file_path=%%F"
    for %%N in ("%%F") do set "custody_file_name=%%~nxN"
    call :list_custody_file
)
call :list_directory "/b /a-d" destination_set_with_backslash temp_directory_listing || call :report_custody_listing_failed destination_set_with_backslash
for /f "usebackq eol=/ delims=" %%F in ("%temp_directory_listing%") do (
    set "custody_file_name=%%F"
    call :list_top_level_custody_file
)
rem Hashed as the evidence is (:hash_listed_files); a file refused for its
rem path's length, or a listing not read in full, is a Run records problem.
set "listing_refusal_label=Not hashed (custody record)"
call :hash_listed_files temp_custody_list custody custody_files_count || set /a "run_record_problem_count+=1"
set /a "run_record_problem_count+=listing_refused_count"
if %custody_files_count% equ 0 (
    set "msg=No custody files in the destination set yet."
    call :show_and_log msg
)
exit /b 0

:list_custody_file
rem Caller's scope (:hash_custody_files): a file in the records directory, in
rem custody_file_path and custody_file_name; ignored names are left out.
call :name_matches_list custody_file_name IGNORED_CUSTODY_FILES && exit /b 0
call :append_sized_line_to_file custody_file_path temp_custody_list
exit /b 0

:report_custody_listing_failed  directoryVar
rem Caller's scope (:hash_custody_files): a directory of custody files
rem couldn't be listed, so the files in it weren't hashed; a Run records
rem failure, by directory.
setlocal EnableDelayedExpansion
set "msg=[FAIL] Custody files in !%~1! couldn't be listed (access denied, missing, or the device isn't readable): they were not hashed."
call :show_and_log msg
call :remember_problem msg
endlocal & set /a "run_record_problem_count+=1"
exit /b 0

:list_top_level_custody_file
rem Caller's scope (:hash_custody_files): a file at the destination set's top
rem level, in custody_file_name: listed if it is a custody file.
call :is_custody_file_name custody_file_name || exit /b 0
set "custody_file_path=%destination_set_with_backslash%%custody_file_name%"
call :append_sized_line_to_file custody_file_path temp_custody_list
exit /b 0

:append_sized_line_to_file  pathVar  fileVar
rem Append a file's path as a listing line ("<size> <path>": robocopy writes
rem a tab between the two with /bytes, and the loops that read a listing
rem split at either, so every listing has the same shape; the script holds
rem no tab). The size from FOR's %%~z (a custody file's path is under cmd's
rem limits).
setlocal EnableDelayedExpansion
set "sized_file_size=0"
for %%A in ("!%~1!") do set "sized_file_size=%%~zA"
>>"!%~2!" echo(!sized_file_size! !%~1!
endlocal & exit /b 0

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
set "heading=Metadata: size and last-modified time, compared !time_precision!"
call :write_section_heading heading both
set "msg=running: robocopy list-only, source against destination" & call :dashboard_stage metadata msg
set "excluded_dirs="
set "excluded_files="
call :add_housekeeping_exclusions source
call :add_housekeeping_exclusions destination
call :build_exclusion_args
"%tool_robocopy%" "!source_path! " "!destination_path! " *.* !METADATA_FLAGS! !fft_flag! !backup_flag! !exclusion_args! /unilog:"!temp_robocopy_unicode_output!" %robocopy_console_redirection%
set "check_exit_code=!errorlevel!"
call :save_robocopy_unicode_output temp_metadata_list new
set "incomplete=0"
set "listing_failed="
if !check_exit_code! geq 8 set "listing_failed=1"
call :is_robocopy_exit_code_in_range check_exit_code || set "listing_failed=1"
if defined listing_failed (
    set "msg=[FAIL] The metadata check could not compare every file (robocopy exit code !check_exit_code!)."
    call :show_and_log msg
    call :remember_problem msg
    set "incomplete=1"
)
if not "!robocopy_output_lines_written!"=="!robocopy_output_lines_total!" (
    set "msg=[FAIL] The metadata check could not compare every file: only !robocopy_output_lines_written! of the !robocopy_output_lines_total! lines of robocopy's listing could be read (cmd can't carry a line over 8000 characters)."
    call :show_and_log msg
    call :remember_problem msg
    set "incomplete=1"
)
rem The Metadata row's text, set above for the live display, is carried out
rem too: the differences are listed after the endlocal, and the row read
rem "waiting" while they were (round 12.3). Without the display it is
rem undefined and stays so.
endlocal & set "metadata_check_incomplete=%incomplete%" & set "metadata_time_precision=%time_precision%" & set "metadata_check_ran=1" & set "dashboard_metadata_text=%dashboard_metadata_text%"
rem The files listed, read as :hash_listed_files reads a listing: numbered,
rem so a line cmd couldn't carry is seen and refused by name, each line
rem trimmed by a FOR /F of its own, and the lines counted against the files
rem reported or refused. A refused file counts as a difference: robocopy
rem listed it.
set "listing_refusal_label=METADATA differs (size or last-modified time), or not copied"
call :number_listing temp_metadata_list
set "metadata_listed_count=0"
for /f "usebackq tokens=*" %%L in ("%temp_metadata_list%") do set /a "metadata_listed_count+=1"
set "metadata_differ_before=%metadata_differ_count%"
set "metadata_unexpected_before=%unexpected_listing_lines%"
for /f "usebackq tokens=1* delims=:" %%A in ("%temp_listing_numbered%") do (
    set "listed_line_number=%%A"
    set "listed_line="
    for /f "tokens=1*" %%S in ("%%B") do set "listed_line=%%T"
    call :report_metadata_difference listed_line
)
call :check_listing_tail
set /a "metadata_differ_count+=listing_refused_count"
set /a "metadata_listed_accounted=metadata_differ_count - metadata_differ_before + unexpected_listing_lines - metadata_unexpected_before"
if %metadata_listed_accounted% neq %metadata_listed_count% (
    call :report_unaccounted_listing_lines metadata_listed_accounted metadata_listed_count "files the metadata check listed"
    set "metadata_check_incomplete=1"
)
rem For the live display: the block's PASS text depends on the file count,
rem which the hashing gives later, so a PASS shows what is known now.
call :work_out_metadata_status
set "msg=%result_metadata%"
if "%metadata_status%"=="PASS" set "msg=PASS: no size or last-modified time differences listed"
call :dashboard_stage metadata msg
exit /b 0

:report_metadata_difference  lineVar
rem One file listed by the metadata check: it differs from its source. The
rem numbered listing's bookkeeping, in the caller's scope (:check_metadata's
rem loop, as :hash_listed_file's): IN listed_line_number, this line's
rem number, and listing_last_line_number, the last line's; the lines between
rem them were skipped by cmd (a path too long to carry) and are refused by
rem name (:refuse_skipped_listing_lines). An empty line (robocopy's) only
rem moves the bookkeeping on. A path over MAX_FILE_PATH_LENGTH is refused by
rem name too (:report_too_long_path) and counted in listing_refused_count.
rem With the live display, the tick redraws it now and then, so a long list
rem of differences shows as a growing Failures count (round 12.2: 3,376
rem lines took about 4 minutes with nothing changing on the screen).
setlocal EnableDelayedExpansion
set /a "listing_gap=listed_line_number - listing_last_line_number - 1"
if !listing_gap! gtr 0 call :refuse_skipped_listing_lines
set "full_path=!%~1!"
if not defined full_path goto report_metadata_difference_skipped
if not "!full_path:~%MAX_FILE_PATH_LENGTH%,1!"=="" (
    call :report_too_long_path full_path
    set /a "listing_refused_count+=1"
    goto report_metadata_difference_skipped
)
if defined dashboard_active (
    set /a "dashboard_tick_count+=1"
    if !dashboard_tick_count! geq %DASHBOARD_TICK_EVERY_ITEMS% call :dashboard_tick
)
call :relative_path full_path source_with_backslash file_relative_path || (
    set "msg=[FAIL] Unexpected line in the metadata check: !full_path!"
    call :show_and_log msg
    call :remember_problem msg
    endlocal & set /a "unexpected_listing_lines+=1" & set "dashboard_tick_count=%dashboard_tick_count%" & set "dashboard_last_redraw=%dashboard_last_redraw%" & set "listing_last_line_number=%listed_line_number%" & set "listing_refused_count=%listing_refused_count%" & exit /b 0
)
set "msg=[FAIL] METADATA differs (size or last-modified time), or not copied: !file_relative_path!"
call :show_and_log msg
call :remember_problem msg
endlocal & set /a "metadata_differ_count+=1" & set "dashboard_tick_count=%dashboard_tick_count%" & set "dashboard_last_redraw=%dashboard_last_redraw%" & set "listing_last_line_number=%listed_line_number%" & set "listing_refused_count=%listing_refused_count%" & exit /b 0
:report_metadata_difference_skipped
endlocal & set "listing_last_line_number=%listed_line_number%" & set "listing_refused_count=%listing_refused_count%" & exit /b 0

:hash_directory  side
rem List every evidence file in the side's directory (with robocopy) and hash
rem each one into the side's rows (:hash_listed_files). Exit 1 if the
rem listing was incomplete or couldn't be read in full. Files refused for
rem their path's length count against the Hash check
rem (path_too_long_<side>_count).
set "hash_directory_listing_failed="
call :list_files %~1 temp_file_list || set "hash_directory_listing_failed=1"
set "listing_refusal_label=Not hashed (%~1)"
call :hash_listed_files temp_file_list %~1 files_to_hash_count || set "hash_directory_listing_failed=1"
set /a "path_too_long_%~1_count+=listing_refused_count"
if defined hash_directory_listing_failed exit /b 1
exit /b 0

:hash_listed_files  listingVar  side  totalVar
rem Caller's scope (delayed expansion off). Hash every file a listing names
rem (one full path per line, as robocopy writes it) into the side's rows
rem (:hash_listed_file); totalVar gets the count of files listed first (the
rem progress counter and the live display's total). cmd skips a FOR /F
rem iteration whose expanded command would pass 8,191 characters without a
rem word (round 12.7: a file whose path was 8,200 characters long was left
rem out of both hash records, and the run PASSed), so the listing is read
rem numbered (:number_listing): a line cmd couldn't carry shows as a gap in
rem the numbers and is refused by name (:hash_listed_file,
rem :check_listing_tail), as is a path over MAX_FILE_PATH_LENGTH. Each line
rem is trimmed of the tabs and spaces robocopy puts before the path by a
rem FOR /F of its own (tokens=*), the number having taken the first token.
rem Last, every file listed must have been hashed, reported or refused
rem (:report_unaccounted_listing_lines); exit 1 if not. Each line holds the
rem file's size before its path (LIST_FLAGS /bytes): the Hash bar's units
rem (HASH_PROGRESS_UNIT_DIGITS, HASH_WEIGHT_PER_FILE_UNITS) are added up
rem here into listing_units_total, the bar's total.
call :copy_variable %~1 hash_listing_path
set "%~3=0"
rem The files listed and the units they weigh (sizes are digits: delayed
rem expansion on is safe here).
setlocal EnableDelayedExpansion
set "listed_count=0"
set "listed_units=0"
for /f "usebackq tokens=1" %%S in ("!hash_listing_path!") do (
    set "listed_size=%%S"
    rem A first word that isn't a size (a line of robocopy's own, which
    rem fails the listing anyway) weighs the per-file share alone.
    for /f "delims=0123456789" %%X in ("!listed_size!") do set "listed_size="
    set "listed_file_units="
    if defined listed_size set "listed_file_units=!listed_size:~0,-%HASH_PROGRESS_UNIT_DIGITS%!"
    if not defined listed_file_units set "listed_file_units=0"
    set /a "listed_count+=1, listed_units+=listed_file_units + HASH_WEIGHT_PER_FILE_UNITS"
)
endlocal & set "%~3=%listed_count%" & set "listing_units_total=%listed_units%"
call :number_listing %~1
call :copy_variable hashed_count_%~2 hash_listing_hashed_before
set "hash_listing_unexpected_before=%unexpected_listing_lines%"
rem Each line: its number, then the size and the path split by a FOR /F of
rem its own (tokens=1*: the size, then the rest after the tab, the path).
for /f "usebackq tokens=1* delims=:" %%A in ("%temp_listing_numbered%") do (
    set "listed_line_number=%%A"
    set "listed_line="
    set "listed_size="
    for /f "tokens=1*" %%S in ("%%B") do (
        set "listed_size=%%S"
        set "listed_line=%%T"
    )
    call :hash_listed_file listed_line %~2 %~3
)
call :check_listing_tail
call :copy_variable %~3 hash_listing_total
set /a "hash_listing_accounted=hashed_count_%~2 - hash_listing_hashed_before + unexpected_listing_lines - hash_listing_unexpected_before + listing_refused_count"
if %hash_listing_accounted% equ %hash_listing_total% exit /b 0
set "hash_listing_what=files listed in the %~2"
if "%~2"=="custody" set "hash_listing_what=custody files listed"
call :report_unaccounted_listing_lines hash_listing_accounted hash_listing_total "%hash_listing_what%"
exit /b 1

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
"%tool_robocopy%" "!%~1_with_backslash! " "!temp_path_prefix!_nonexistent" *.* !LIST_FLAGS! !backup_flag! !exclusion_args! /unilog:"!temp_robocopy_unicode_output!" %robocopy_console_redirection%
set "list_exit_code=!errorlevel!"
call :save_robocopy_unicode_output %~2 new
set "listing_failed="
if !list_exit_code! geq 8 set "listing_failed=1"
call :is_robocopy_exit_code_in_range list_exit_code || set "listing_failed=1"
if defined listing_failed (
    set "msg=[FAIL] Could not list every file under !%~1_with_backslash! (robocopy exit code !list_exit_code!)."
    call :show_and_log msg
    call :remember_problem msg
    endlocal & exit /b 1
)
if not "!robocopy_output_lines_written!"=="!robocopy_output_lines_total!" (
    set "msg=[FAIL] Could not list every file under !%~1_with_backslash!: only !robocopy_output_lines_written! of the !robocopy_output_lines_total! lines of robocopy's listing could be read (cmd can't carry a line over 8000 characters)."
    call :show_and_log msg
    call :remember_problem msg
    endlocal & exit /b 1
)
endlocal & exit /b 0

:hash_listed_file  lineVar  side  totalVar
rem Hash one listed file and record it as a "relative path","SHA-256" row for
rem the side's CSV. side: source, destination, or custody (custody files in
rem the destination set). For the destination also as a compare line
rem "relative path*SHA-256*DST" for :compare_with_reference. totalVar names
rem the count of files listed, for the progress counter. The numbered
rem listing's bookkeeping, in the caller's scope (:hash_listed_files): IN
rem listed_line_number, this line's number, and listing_last_line_number,
rem the last line's; the lines between them were skipped by cmd (a path too
rem long to carry) and are refused by name (:refuse_skipped_listing_lines).
rem An empty line (robocopy's) only moves the bookkeeping on. A path over
rem MAX_FILE_PATH_LENGTH is refused by name too (:report_too_long_path) and
rem counted in listing_refused_count: no row, no compare line.
setlocal EnableDelayedExpansion
set /a "listing_gap=listed_line_number - listing_last_line_number - 1"
if !listing_gap! gtr 0 call :refuse_skipped_listing_lines
set "full_path=!%~1!"
if not defined full_path goto hash_listed_file_skipped
if not "!full_path:~%MAX_FILE_PATH_LENGTH%,1!"=="" (
    call :report_too_long_path full_path
    set /a "listing_refused_count+=1"
    goto hash_listed_file_skipped
)
set "base_var=%~2_with_backslash"
if "%~2"=="custody" set "base_var=destination_set_with_backslash"
set "item_label=%~2"
if "%~2"=="custody" set "item_label=custody record"
call :relative_path full_path !base_var! file_relative_path || (
    set "msg=[FAIL] Unexpected line while listing the %~2: !full_path!"
    call :show_and_log msg
    call :remember_problem msg
    endlocal & set /a "unexpected_listing_lines+=1" & set "listing_last_line_number=%listed_line_number%" & set "listing_refused_count=%listing_refused_count%" & exit /b 0
)
set /a "sequence_number=hashed_count_%~2 + 1"
rem The progress line, once per file: with the live display it is the Hash
rem detail line, shown at the next redraw (the tick's few lines are all
rem the loop carries per file: cmd parses a function's lines on every
rem call); otherwise it is written directly when it fits (going through
rem :show costs about 6 ms per file: test round 11), and a longer one goes
rem through :show to be wrapped. The tick comes every
rem DASHBOARD_TICK_EVERY_ITEMS files, or sooner once the files hashed
rem since the last one hold DASHBOARD_TICK_EVERY_CONTENT_UNITS of content
rem (2.8.1, round 15.3: four 128 MiB segments never reached 25 files, so
rem the Hash bar stood at 0 % until the stage was over).
set "msg=[!sequence_number!/!%~3!] Hashing !item_label!: !file_relative_path!"
if defined dashboard_active (
    set /a "dashboard_tick_count+=1"
    if !dashboard_tick_count! geq %DASHBOARD_TICK_EVERY_ITEMS% (
        call :dashboard_tick msg
    ) else if !dashboard_tick_content_units! geq %DASHBOARD_TICK_EVERY_CONTENT_UNITS% (
        call :dashboard_tick msg
    )
) else if "!msg:~%OUTPUT_WIDTH%!"=="" (
    echo(!msg!
) else (
    call :show msg
)
set "file_sha256="
call :get_sha256 full_path file_sha256 listed_size
if not defined file_sha256 set "file_sha256=UNREADABLE"
>>"!temp_hash_rows_%~2!" echo("!file_relative_path!","!file_sha256!"
if "%~2"=="destination" >>"!temp_compare_lines!" echo(!file_relative_path!*!file_sha256!*DST
rem The file's units for the Hash bar (listed_size: the caller's, from the
rem listing's size column): its content, which also counts towards the
rem next tick, then the per-file share, which doesn't.
set "file_units=!listed_size:~0,-%HASH_PROGRESS_UNIT_DIGITS%!"
if not defined file_units set "file_units=0"
set /a "dashboard_tick_content_units+=file_units"
set /a "file_units+=HASH_WEIGHT_PER_FILE_UNITS"
endlocal & set /a "hashed_count_%~2+=1, hashed_units_%~2+=%file_units%" & set "dashboard_tick_count=%dashboard_tick_count%" & set "dashboard_tick_content_units=%dashboard_tick_content_units%" & set "dashboard_last_redraw=%dashboard_last_redraw%" & set "listing_last_line_number=%listed_line_number%" & set "listing_refused_count=%listing_refused_count%" & exit /b 0
:hash_listed_file_skipped
endlocal & set "listing_last_line_number=%listed_line_number%" & set "listing_refused_count=%listing_refused_count%" & exit /b 0

:write_hash_csv  side
rem Write the side's CSV (in the staging directory; side: source, destination or
rem custody): header plus rows sorted by
rem relative path, so it doesn't depend on the order in which a file system
rem lists files. The rows are counted before and after the sort: sort
rem writes nothing at all when a record passes its limit (4,096 characters
rem by default; round 12.6: both hash records empty, the run failing
rem "Nothing was verified"), and a record short of its rows must fail by
rem name (exit 1).
setlocal EnableDelayedExpansion
>"!staged_hash_csv_%~1!" echo "File","SHA-256"
set "rows_to_sort=0"
set "rows_sorted=0"
if exist "!temp_hash_rows_%~1!" (
    "%tool_sort%" "!temp_hash_rows_%~1!" >>"!staged_hash_csv_%~1!"
    "%tool_find%" /c /v "" <"!temp_hash_rows_%~1!" >"!temp_count!" 2>nul
    for /f "usebackq" %%N in ("!temp_count!") do set "rows_to_sort=%%N"
    "%tool_find%" /c /v "" <"!staged_hash_csv_%~1!" >"!temp_count!" 2>nul
    for /f "usebackq" %%N in ("!temp_count!") do set /a "rows_sorted=%%N - 1"
)
if !rows_sorted! equ !rows_to_sort! (endlocal & exit /b 0)
set "msg=[FAIL] The %~1 hash record holds !rows_sorted! of its !rows_to_sort! rows: sorting them failed, so the record can't be relied on."
call :show_and_log msg
call :remember_problem msg
endlocal & exit /b 1

:get_sha256  pathVar  outVar  [sizeVar]
rem Set outVar to the file's SHA-256 (64 hex characters). Clear it if certutil
rem fails or prints anything else, so a failure can never look like a hash.
rem certutil can't hash empty files: a file of size 0 gets EMPTY_SHA256 once
rem it has been opened and read to its end with nothing in it (2.8.2, the
rem GPT 6.1 review of 2.8.1, finding 2: the size is the directory entry's,
rem so a file that couldn't be opened passed as hashed); find reads it
rem through the same path form certutil was given, and a file it can't
rem open is retried and UNREADABLE like any other. The size is sizeVar's
rem when the caller has one (the hash pass: robocopy's listing, which
rem names the file exactly; 2.8.2, round 15.6: FOR's %%~z on the plain
rem path gave no size for "nul" or a name ending in a space, so such a
rem zero-byte file was UNREADABLE, and a name ending in a dot took its
rem twin's size), else FOR's %%~z, skipped for names containing "?" (a
rem character the console code page couldn't show), where FOR could
rem match a different file.
rem certutil runs here, not inside a FOR /F command: FOR /F runs its
rem command in a child cmd, which would expand %NAME% in a file name (e.g.
rem "x %OS% y.txt" -> "x Windows_NT y.txt") and hash another file (test
rem runner round 6). Its output goes to temp_certutil_output and is read
rem from there. A file certutil couldn't read is tried once more after
rem HASH_RETRY_WAIT_SECONDS, and both attempts are noted in the log: one
rem failed read in about 180,000 was seen (workshop, 2026-10-18), and a
rem first copy records UNREADABLE in the set's reference record for good.
setlocal EnableDelayedExpansion
set "file_path=!%~1!"
set "sha256="
set "attempts_left=1"
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
:get_sha256_attempt
"%tool_certutil%" -hashfile "!hash_path!" SHA256 >"!temp_certutil_output!" 2>nul
if exist "!temp_certutil_output!" for /f "usebackq skip=1 delims=" %%H in ("!temp_certutil_output!") do if not defined sha256 set "sha256=%%H"
del "!temp_certutil_output!" >nul 2>&1
if defined sha256 set "sha256=!sha256: =!"
if defined sha256 if not "!sha256:~64!"=="" set "sha256="
if defined sha256 if "!sha256:~63,1!"=="" set "sha256="
if defined sha256 for /f "delims=0123456789abcdefABCDEF" %%X in ("!sha256!") do set "sha256="
if defined sha256 goto get_sha256_done
set "size=unknown"
if not "%~3"=="" if defined %~3 set "size=!%~3!"
if "!size!"=="unknown" if "!file_path:?=!"=="!file_path!" for %%A in ("!file_path!") do set "size=%%~zA"
if "!size!"=="0" (
    del "!temp_certutil_output!" >nul 2>&1
    ("%tool_find%" /c /v "" <"!hash_path!" >"!temp_certutil_output!") 2>nul
    if exist "!temp_certutil_output!" for /f "usebackq" %%N in ("!temp_certutil_output!") do if "%%N"=="0" set "sha256=!EMPTY_SHA256!"
    del "!temp_certutil_output!" >nul 2>&1
)
if defined sha256 goto get_sha256_done
set "attempt_problem=certutil could not read !file_path!"
if "!size!"=="0" set "attempt_problem=!file_path! is listed as 0 bytes but couldn't be opened and read"
if !attempts_left! equ 0 (
    set "msg=[INFO] !attempt_problem! at the second attempt either: recorded as UNREADABLE."
    call :show_and_log msg
    goto get_sha256_done
)
set /a "attempts_left-=1, retry_wait_pings=HASH_RETRY_WAIT_SECONDS + 1"
set "msg=[INFO] !attempt_problem! at the first attempt; trying again in !HASH_RETRY_WAIT_SECONDS! s."
call :show_and_log msg
"%tool_ping%" -n !retry_wait_pings! 127.0.0.1 >nul
goto get_sha256_attempt
:get_sha256_done
endlocal & set "%~2=%sha256%"
exit /b 0

rem :relative_path sits here, just below the per-file loop that calls it for
rem every file (:hash_listed_file), and :strlen below the compare loop
rem (:pair_compare_line calls it for every line; :relative_path then scans
rem a little further): cmd finds a label by scanning forward from the
rem caller and wrapping at the end of the file, about 5 ms for 2,000 lines
rem (workshop, 2026-10-18; round 12.2: :strlen here, above the compare,
rem cost the compare 20 ms per file). Pure moves; the code is unchanged.

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
set "heading=Hash (SHA-256): destination vs reference record %reference_name%"
if "%run_mode%"=="nonforensic" set "heading=Hash (SHA-256): destination vs source"
call :write_section_heading heading both
call :compare_identical_records && exit /b 0
for /f "usebackq skip=1 delims=" %%L in ("%reference_csv_path%") do (
    set "reference_row=%%L"
    call :add_reference_row reference_row
)
if not exist "%temp_compare_lines%" type nul >"%temp_compare_lines%"
"%tool_sort%" /L C /O "%temp_compare_lines_sorted%" "%temp_compare_lines%"
rem sort writes nothing for a record over its limit (:write_hash_csv): the
rem sorted lines are counted against the unsorted ones.
set "compare_lines_to_sort=0"
"%tool_find%" /c /v "" <"%temp_compare_lines%" >"%temp_count%" 2>nul
for /f "usebackq" %%N in ("%temp_count%") do set "compare_lines_to_sort=%%N"
set "compare_line_count=0"
"%tool_find%" /c /v "" <"%temp_compare_lines_sorted%" >"%temp_count%" 2>nul
for /f "usebackq" %%N in ("%temp_count%") do set "compare_line_count=%%N"
if %compare_line_count% neq %compare_lines_to_sort% call :report_compare_lines_lost compare_line_count compare_lines_to_sort
set "msg=Pairing %compare_line_count% entries (%compare_reference_label% and destination) ..."
call :show msg
set "previous_path="
set "previous_hash="
set "previous_tag="
for /f "usebackq eol=* delims=" %%L in ("%temp_compare_lines_sorted%") do (
    set "compare_line=%%L"
    set /a "compare_lines_done+=1"
    call :pair_compare_line compare_line
)
call :settle_last_compare_line
exit /b 0

:compare_identical_records
rem The compare's fast path (2.6.0, owner): exit 0, with every count set
rem as the pairing would set it, when the destination's hash record is the
rem reference record byte for byte. Why that is enough: the destination's
rem record was written by this run from its own listing, one row per file,
rem each hash certutil's (64 lower-case hex characters) or UNREADABLE,
rem sorted; byte equality means the reference lists the same paths, once
rem each, with the same hashes. Not taken (exit 1: the pairing runs, which
rem reports each row) when the records differ in any byte (another sort
rem order, trailing spaces, a BOM), when the reference holds an UNREADABLE
rem row, when it holds no rows, or when its run record failed its seal (the
rem Hash result then says the reference can't be relied on, with the
rem pairing's counts). Both records are copied into TEMP first: fc can't
rem open a path over 260 characters (:copy_for_reading); the copy's lines
rem are counted with find.
if %reference_seal_failed% neq 0 exit /b 1
call :copy_for_reading reference_csv_path temp_custody_copy || exit /b 1
call :copy_for_reading staged_hash_csv_destination temp_custody_copy_second || exit /b 1
"%tool_fc%" /b "%temp_custody_copy%" "%temp_custody_copy_second%" >nul 2>&1 || exit /b 1
"%tool_findstr%" /c:"UNREADABLE" "%temp_custody_copy%" >nul 2>&1 && exit /b 1
set "identical_record_lines=0"
"%tool_find%" /c /v "" <"%temp_custody_copy%" >"%temp_count%" 2>nul
for /f "usebackq" %%N in ("%temp_count%") do set "identical_record_lines=%%N"
set /a "identical_record_rows=identical_record_lines - 1"
if %identical_record_rows% leq 0 exit /b 1
set /a "reference_row_count=identical_record_rows, match_count=identical_record_rows, compare_line_count=identical_record_rows * 2"
set "compare_lines_done=%compare_line_count%"
set "msg=The destination's hash record is identical to the %compare_reference_label%'s, byte for byte (%identical_record_rows% rows): every file in it is in the destination with the same SHA-256. The row-by-row pairing was not needed."
call :show_and_log msg
exit /b 0

:add_reference_row  rowVar
rem Turn one row of the reference record ("relative path","SHA-256", maybe
rem with trailing spaces from 1.0.x) into a compare line "...*...*REF".
setlocal EnableDelayedExpansion
set "row=!%~1!"
for /l %%I in (1,1,%OUTPUT_MAX_INDENT%) do if "!row:~-1!"==" " set "row=!row:~0,-1!"
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
if defined dashboard_active (
    set /a "dashboard_tick_count+=1"
    if !dashboard_tick_count! geq %DASHBOARD_TICK_EVERY_ITEMS% call :dashboard_tick
)
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
endlocal & set "previous_path=%keep_path%" & set "previous_hash=%keep_hash%" & set "previous_tag=%keep_tag%" & set "outcome_counter=%outcome_counter%" & set "dashboard_tick_count=%dashboard_tick_count%" & set "dashboard_last_redraw=%dashboard_last_redraw%"
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
set "heading=Run records: against the history and their seals" & call :write_section_heading heading both
call :report_history_set_aside source after
call :report_history_set_aside destination after
rem (With the source's records directory unlistable, that is the one
rem failure reported, by :report_history_set_aside above.)
if defined history_base_missing if not defined source_records_unreadable (
    set "msg=[FAIL] Run records: the set holds run records but no history file (%HISTORY_FILE_NAME%) beside the evidence, so they can't be checked against it."
    call :show_and_log msg
    call :remember_problem msg
    set /a "run_record_problem_count+=1"
)
set "run_records_history=%history_base_path%"
if defined history_base_missing set "run_records_history="
call :check_history_against_records fail run_records_history run_records_root
exit /b 0

rem -- Listings read line by line ---------------------------------------------
rem cmd skips a FOR /F iteration whose expanded command would pass 8,191
rem characters without a word (round 12.7: a file whose full path was 8,200
rem characters long was left out of both hash records, and the run PASSed).
rem So every listing of paths (the evidence and custody files to hash, the
rem metadata check's differences) is read numbered: findstr /n, with the
rem file named, reads a line of any length, and a line cmd couldn't carry
rem shows as a gap in the numbers. The loop reading it keeps
rem listing_last_line_number (the last line handled) and
rem listing_refused_count (the lines refused by name) in the caller's
rem scope; its per-line helper refuses the gap before it, and a path over
rem MAX_FILE_PATH_LENGTH; :check_listing_tail refuses lines after the last
rem one handled. :hash_listed_files is the model.

:number_listing  listingVar
rem Caller's scope, delayed expansion off. Number the listing's lines into
rem temp_listing_numbered ("n:line") and count them into listing_line_count
rem (every line, empty ones too), and start the loop's bookkeeping.
call :copy_variable %~1 number_listing_path
type nul >"%temp_listing_numbered%"
if exist "%number_listing_path%" "%tool_findstr%" /n "^" "%number_listing_path%" >"%temp_listing_numbered%" 2>nul
set "listing_line_count=0"
"%tool_find%" /c /v "" <"%temp_listing_numbered%" >"%temp_count%" 2>nul
for /f "usebackq" %%N in ("%temp_count%") do set "listing_line_count=%%N"
set "listing_last_line_number=0"
set "listing_refused_count=0"
exit /b 0

:refuse_skipped_listing_lines
rem Caller's scope, delayed expansion on (:hash_listed_file,
rem :report_metadata_difference): the listing_gap lines between the last
rem line handled (listing_last_line_number) and this one
rem (listed_line_number) were skipped by cmd, each a path too long to
rem carry: refuse them by name and count them.
set /a "listing_gap_first=listing_last_line_number + 1, listing_gap_last=listed_line_number - 1"
call :report_unreadable_listing_lines listing_gap_first listing_gap_last
set /a "listing_refused_count+=listing_gap"
exit /b 0

:check_listing_tail
rem Caller's scope, after a loop over the numbered listing: the lines after
rem the last one handled were skipped by cmd, each a path too long to
rem carry: refuse them by name and count them.
if %listing_last_line_number% geq %listing_line_count% exit /b 0
set /a "listing_tail_first=listing_last_line_number + 1, listing_tail_count=listing_line_count - listing_last_line_number"
call :report_unreadable_listing_lines listing_tail_first listing_line_count
set /a "listing_refused_count+=listing_tail_count"
exit /b 0

:report_unreadable_listing_lines  firstVar  lastVar
rem Lines firstVar to lastVar of the numbered listing couldn't be carried by
rem cmd (over 8,000 characters each): one failure per line, under the
rem caller's listing_refusal_label, naming the path by its first
rem PATH_EXCERPT_LENGTH characters (:read_listing_line_start).
setlocal EnableDelayedExpansion
for /l %%N in (!%~1!,1,!%~2!) do (
    call :read_listing_line_start %%N listing_line_start
    set "msg=[FAIL] !listing_refusal_label!: path too long, over 8000 characters (the limit is !MAX_FILE_PATH_LENGTH!; the first !PATH_EXCERPT_LENGTH! shown): !listing_line_start:~0,%PATH_EXCERPT_LENGTH%!..."
    call :show_and_log msg
    call :remember_problem msg
)
endlocal & exit /b 0

:read_listing_line_start  lineNumber  outVar
rem The start of line lineNumber of the numbered listing (as much as SET /P
rem reads, about 1,000 characters), without its number and robocopy's
rem leading tabs and spaces, into outVar; empty if it can't be read. The
rem line is picked out by its number with findstr (the file named: any
rem length) into a file of its own and read from there, so the line itself
rem never goes on a command line, which is what it is too long for.
rem Delayed expansion off throughout, so a "!" in the path survives the
rem FOR values and the hand-back.
setlocal DisableDelayedExpansion
set "line_start="
"%tool_findstr%" /b /l /c:"%~1:" "%temp_listing_numbered%" >"%temp_listing_line%" 2>nul
set /p "line_start=" <"%temp_listing_line%"
if defined line_start for /f "tokens=1* delims=:" %%A in ("%line_start%") do set "line_start=%%B"
if defined line_start for /f "tokens=1*" %%S in ("%line_start%") do set "line_start=%%T"
endlocal & set "%~2=%line_start%"
exit /b 0

:report_too_long_path  pathVar
rem One failure for a listed file whose path is over MAX_FILE_PATH_LENGTH,
rem under the caller's listing_refusal_label, with the path's length and
rem its first PATH_EXCERPT_LENGTH characters.
setlocal EnableDelayedExpansion
set "too_long_path=!%~1!"
call :strlen too_long_path too_long_path_length
set "msg=[FAIL] !listing_refusal_label!: path too long, !too_long_path_length! characters (the limit is !MAX_FILE_PATH_LENGTH!; the first !PATH_EXCERPT_LENGTH! shown): !too_long_path:~0,%PATH_EXCERPT_LENGTH%!..."
call :show_and_log msg
call :remember_problem msg
endlocal & exit /b 0

:report_unaccounted_listing_lines  accountedVar  totalVar  whatText
rem Not every file a listing holds was handled by the loop that read it
rem (hashed or reported, or refused by name): the listing can't be relied
rem on. whatText names the files ("files listed in the source").
setlocal EnableDelayedExpansion
set "msg=[FAIL] Only !%~1! of the !%~2! %~3 were accounted for (handled, or refused by name): the listing could not be read in full."
call :show_and_log msg
call :remember_problem msg
endlocal & exit /b 0

:report_compare_lines_lost  sortedVar  totalVar
rem The compare lines came short out of sorting (:compare_with_reference):
rem the Hash check is incomplete.
setlocal EnableDelayedExpansion
set "msg=[FAIL] Only !%~1! of the !%~2! compare lines came through sorting: the comparison can't be relied on."
call :show_and_log msg
call :remember_problem msg
endlocal & set "hash_check_incomplete=1"
exit /b 0

:report_dropped_robocopy_lines
rem After :save_robocopy_unicode_output wrote robocopy's output into the
rem log: lines it couldn't carry (over 8,000 characters: cmd skips them
rem without a word) are missing from the log, which fails the Copy check
rem (copy_log_incomplete, carried out of the pass's scope by the caller).
if "%robocopy_output_lines_written%"=="%robocopy_output_lines_total%" exit /b 0
setlocal EnableDelayedExpansion
set "msg=[FAIL] Only !robocopy_output_lines_written! of the !robocopy_output_lines_total! lines of robocopy's output could be written into this log (cmd can't carry a line over 8000 characters): the output above is incomplete."
call :show_and_log msg
call :remember_problem msg
endlocal & set "copy_log_incomplete=1"
exit /b 0

:check_history_against_records  mode  historyVar  recordsRootVar
rem The one history checker (README, "History and run records"): a history
rem (none when the history restarts) against the records directory of the
rem set that holds it. Caller's scope (working names history_check_*);
rem the caller's delayed expansion is off. mode:
rem   quiet  before the copy, choosing which history to continue: rows,
rem          run record names, seals' SHA-256 and sealed histories only; no
rem          output; exit 1 if anything doesn't match.
rem   warn   before the copy, on the set holding the history this run
rem          continues (owner, 2026-10-16): everything, every run record
rem          against its seal too; each problem a header warning.
rem   fail   after the copy, on the destination set: everything; each
rem          problem fails the Run records check, and the run records'
rem          counts and the reference record's seal result are kept.
rem What is checked: every row names a run record (YYYYMMDDTHHMMSSZ) that
rem exists, whose seal has the row's Seal SHA-256 and whose own sealed
rem history is the history up to that row; every run record matches its seal
rem (warn, fail); no file lies loose in the records directory (warn, fail);
rem every directory there is a run the history lists, a leftover
rem <run>.partial (a warning), or a run record a history restart listed as
rem outside its history (a warning while its seal still has the SHA-256
rem listed for it). With no history (a restart), every run record found is
rem checked against its seal and, after the copy, listed as outside the new
rem history.
set "history_check_mode=%~1"
call :copy_variable %~2 history_check_history
call :copy_variable %~3 history_check_records_root
rem The set the records directory belongs to: the destination after the
rem copy, else the set holding the history this run continues (the source
rem when there is none). Its <side>_records_unreadable, set when the
rem directory couldn't be listed before the copy and reported by
rem :report_history_set_aside, keeps the finding below from naming the
rem directory a second time (round 14.8).
set "history_check_side=%history_base_side%"
if not defined history_check_side set "history_check_side=source"
if "%history_check_mode%"=="fail" set "history_check_side=destination"
set "history_check_problem="
set "history_check_rows=0"
type nul >"%temp_history_runs%"
type nul >"%temp_outside_history%"
type nul >"%temp_predating_records%"
set "history_check_history_unreadable="
if defined history_check_history (call :copy_for_reading history_check_history temp_custody_copy || set "history_check_history_unreadable=1")
if defined history_check_history_unreadable (
    set "finding=The history %history_check_history% couldn't be read (access denied, empty, missing, or the device isn't readable): the run records can't be checked against it."
    call :history_problem finding
)
if defined history_check_history "%tool_findstr%" /n "^" "%temp_custody_copy%" >"%temp_history_numbered%" 2>nul
if defined history_check_history for /f "usebackq tokens=1* delims=:" %%A in ("%temp_history_numbered%") do if %%A gtr 1 (
    set "history_row_line=%%B"
    set "history_line_number=%%A"
    call :check_history_row
)
if "%history_check_mode%"=="quiet" if %history_check_rows% equ 0 set "history_check_problem=1"
if "%history_check_mode%"=="quiet" if defined history_check_problem exit /b 1
set "history_check_records_root_with_backslash=%history_check_records_root%\"
rem A records directory that isn't there holds nothing to list: on a
rem destination whose custody pass failed it was never made (round 14.8),
rem and the rows above have already reported every run record they name
rem as missing.
call :is_directory history_check_records_root || goto check_history_against_records_no_directory
if not "%history_check_mode%"=="quiet" call :list_directory "/b /a-d" history_check_records_root_with_backslash temp_directory_listing || goto check_history_against_records_unlistable
if not "%history_check_mode%"=="quiet" for /f "usebackq eol=/ delims=" %%F in ("%temp_directory_listing%") do (
    set "stray_name=%%F"
    call :report_stray_record_file
)
call :list_directory "/b /ad /on" history_check_records_root_with_backslash temp_directory_listing || goto check_history_against_records_unlistable
for /f "usebackq eol=/ delims=" %%R in ("%temp_directory_listing%") do (
    set "record_directory_name=%%R"
    call :check_record_directory_listed
)
:check_history_against_records_no_directory
if not "%history_check_mode%"=="quiet" call :report_predating_records
if defined history_check_problem exit /b 1
exit /b 0
:check_history_against_records_unlistable
rem The records directory itself couldn't be listed, so no run record in it
rem can be checked: one problem (quiet mode rejects the history; fail mode
rem counts one failure). The rows were still checked by path above. When
rem :report_history_set_aside has already reported this directory for
rem its set, the problem is noted without a second message.
if defined %history_check_side%_records_unreadable (set "history_check_problem=1" & exit /b 1)
set "finding=The records directory %history_check_records_root% couldn't be listed (access denied, missing, or the device isn't readable): the run records in it can't be checked against the history or their seals."
call :history_problem finding
exit /b 1

:history_finding  textVar
rem Caller's scope (the history checker and the run record checks). One
rem problem, named as a sentence in textVar: in quiet mode only noted
rem (history_check_problem; inside a run record's check that note stays
rem there, which quiet mode never runs); in warn mode a header warning; in
rem fail mode a failure of the Run records check, shown, logged and listed.
rem The count of failures is kept by the caller.
set "history_check_problem=1"
if "%history_check_mode%"=="quiet" exit /b 0
setlocal EnableDelayedExpansion
if "!history_check_mode!"=="warn" (
    set "msg=!%~1! The Run records check will fail."
    call :add_warning msg
    endlocal & set "run_records_warned=1" & exit /b 0
)
set "msg=[FAIL] !%~1!"
call :show_and_log msg
call :remember_problem msg
endlocal & exit /b 0

:history_problem  textVar
rem Caller's scope (the history checker): a problem with the history or the
rem records directory itself (:history_finding), counted after the copy.
call :history_finding %~1
if "%history_check_mode%"=="fail" set /a "run_record_problem_count+=1"
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
endlocal & set "run_records_warned=1" & exit /b 0

:check_history_row
rem Caller's scope (:check_history_against_records): one row of the history,
rem in history_row_line (line history_line_number of the file). Its run
rem record must exist (and, in warn and fail modes, pass its seal), its
rem seal's SHA-256 must be the row's Seal SHA-256, and its own sealed history
rem must be the history up to this row (this row's pending seal text the
rem only difference). The row's run cell must be a run's UTC time before it
rem is used in a path (record content is data: test round 10).
set /a "history_check_rows+=1"
if "%history_check_mode%"=="quiet" if defined history_check_problem exit /b 0
call :split_history_line row
rem Row 1 is line 2 of the file (line 1 is the header).
set /a "history_row_number=history_line_number - 1"
set "finding=Run records: row %history_row_number% of the history doesn't name a run record (a run's UTC time, YYYYMMDDTHHMMSSZ)."
call :is_run_directory_name row_run || (
    call :history_problem finding
    exit /b 0
)
call :append_line_to_file row_run temp_history_runs
set "row_run_dir=%history_check_records_root%\%row_run%"
set "finding=Run records: run %row_run% (row %history_row_number% of the history) has no run record."
call :is_directory row_run_dir || (
    call :history_problem finding
    exit /b 0
)
if not "%history_check_mode%"=="quiet" call :check_run_record row_run row_run_dir
call :collect_outside_history row_run_dir row_run
set "row_seal_path=%row_run_dir%\%RECORD_FILE_PREFIX%%row_run%.sha256"
set "row_seal_sha256="
if exist "%row_seal_path%" call :get_sha256 row_seal_path row_seal_sha256
rem No seal at all is a failure of the run record's own check; when only
rem choosing a history (quiet), it means this history can't be shown to match.
if not exist "%row_seal_path%" if "%history_check_mode%"=="quiet" set "history_check_problem=1"
set "finding=Run records: run %row_run%'s seal doesn't have the SHA-256 the history records for it."
if exist "%row_seal_path%" if /i not "%row_seal_sha256%"=="%row_seal%" call :history_problem finding
set "row_sealed_history=%row_run_dir%\%RECORD_FILE_PREFIX%%row_run%_history.csv"
rem A missing sealed history is a file missing from a sealed run record,
rem which the run record's own check reports (warn, fail).
if not exist "%row_sealed_history%" if "%history_check_mode%"=="quiet" set "history_check_problem=1"
if not exist "%row_sealed_history%" exit /b 0
set "row_pending_text=see %RECORD_FILE_PREFIX%%row_run%.sha256"
call :write_history_with_seal row_sealed_history row_pending_text row_seal temp_history_filled
call :history_starts_with history_check_history temp_history_filled && exit /b 0
set "finding=Run records: run %row_run%'s sealed history doesn't match the history this run continues, up to that run."
call :history_problem finding
exit /b 0

:report_stray_record_file
rem Caller's scope (:check_history_against_records): a file directly in the
rem records directory, in stray_name, outside any run record: no seal covers
rem it. Ignored names are left alone.
call :name_matches_list stray_name IGNORED_CUSTODY_FILES && exit /b 0
set "finding=Run records: %stray_name% is in the records directory but not in a run record, so no seal covers it."
call :history_problem finding
exit /b 0

:check_record_directory_listed
rem Caller's scope (:check_history_against_records): a directory in the
rem records directory, in record_directory_name. A leftover <run>.partial is a
rem warning. Any other directory must be a run the history lists, or a run
rem record a history restart listed as outside the history it restarted (a
rem warning, if it still matches the seal SHA-256 listed for it). With no
rem history (this run restarts it), each run record found is checked against
rem its own seal and, after the copy, listed (:list_run_outside_history).
call :is_partial_run_directory record_directory_name && goto check_record_directory_listed_partial
"%tool_findstr%" /x /l /c:"%record_directory_name%" "%temp_history_runs%" >nul 2>&1 && exit /b 0
set "record_directory_dir=%history_check_records_root%\%record_directory_name%"
if not defined history_check_history goto check_record_directory_listed_restart
call :find_outside_history && goto check_record_directory_listed_outside
set "finding=Run records: %record_directory_name% in the records directory is not in the history."
call :history_problem finding
exit /b 0
:check_record_directory_listed_restart
if "%history_check_mode%"=="quiet" exit /b 0
call :check_run_record record_directory_name record_directory_dir
if "%history_check_mode%"=="fail" call :list_run_outside_history
exit /b 0
:check_record_directory_listed_partial
rem A leftover .partial: one warning (:add_warning lists it once, though
rem the checks before and after the copy both find it); after the copy it
rem is also logged with the run records.
if "%history_check_mode%"=="quiet" exit /b 0
set "msg=Run records: %record_directory_name% is an interrupted write-back (a run record never completed); it is outside the history."
set "run_records_warned=1"
set "tagged_msg=[WARN] %msg%"
if "%history_check_mode%"=="fail" call :show_and_log tagged_msg
call :add_warning msg
exit /b 0
:check_record_directory_listed_outside
if "%history_check_mode%"=="quiet" exit /b 0
call :check_run_record record_directory_name record_directory_dir
set "record_directory_seal=%record_directory_dir%\%RECORD_FILE_PREFIX%%record_directory_name%.sha256"
set "record_directory_seal_sha256="
if exist "%record_directory_seal%" call :get_sha256 record_directory_seal record_directory_seal_sha256
rem Listed with no seal ("none") and still without one: unchanged since the
rem restart; the missing seal itself is a failure of :check_run_record.
if "%outside_seal_sha256%"=="none" if not defined record_directory_seal_sha256 (
    set "msg=Run records: %record_directory_name% predates the history: run %outside_listed_by% found it outside the history it restarted, without a seal, and it still has none."
    call :add_warning msg
    set "run_records_warned=1"
    exit /b 0
)
set "finding=Run records: %record_directory_name%, listed by run %outside_listed_by% as outside the history it restarted, has changed since: its seal's SHA-256 isn't the one listed."
if /i not "%record_directory_seal_sha256%"=="%outside_seal_sha256%" (
    call :history_problem finding
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
"%tool_findstr%" /b /l /c:"%record_directory_name%*" "%temp_outside_history%" >"%temp_record_match%" 2>nul
for /f "usebackq tokens=1-3 delims=*" %%A in ("%temp_record_match%") do if not defined outside_listed_by (
    set "outside_seal_sha256=%%B"
    set "outside_listed_by=%%C"
)
if defined outside_listed_by exit /b 0
exit /b 1

:check_run_record  runVar  runDirVar
rem One run record: its seal, every file the seal lists, and every file in
rem the directory (subdirectories must have every file listed too: later 2.x
rem versions may add them). Problems go through :history_finding (a warning
rem before the copy, a failure after it). After the copy (fail mode) it also
rem logs the record's count line, adds to the run records' counts and, for
rem the reference record's run, sets reference_seal_failed and the summary
rem text.
setlocal EnableDelayedExpansion
set "run=!%~1!"
set "run_dir=!%~2!"
set "seal_name=!RECORD_FILE_PREFIX!!run!.sha256"
set "seal_path=!run_dir!\!seal_name!"
set "problems=0"
set "matches=0"
set "seal_sha256=none"
rem The directory first: IF EXIST finds a file through FindFirstFile, which
rem a directory that denies listing refuses even for a readable file, so a
rem denied record read "no seal" (round 14.7); the cause is named instead.
call :confirm_directory_readable run_dir || (
    set "finding=Run record !run!: its directory couldn't be listed (access denied, missing, or the device isn't readable), so its files can't be checked against its seal."
    call :history_finding finding
    set /a "problems+=1"
    goto check_run_record_done
)
if not exist "!seal_path!" (
    set "finding=Run record !run!: no seal (!seal_name!), so its files can't be shown unchanged."
    call :history_finding finding
    set /a "problems+=1"
    goto check_run_record_done
)
call :get_sha256 seal_path seal_sha256
if not defined seal_sha256 set "seal_sha256=unknown"
call :check_seal_lines run run_dir seal_path
call :check_run_record_files run run_dir seal_path
if "!history_check_mode!"=="fail" (
    set "msg=Run record !run!: !matches! file(s) match its seal, !problems! problem(s)."
    call :show_and_log msg
    set "msg=  Seal SHA-256: !seal_sha256!"
    call :show_and_log msg
    call :dashboard_tick
)
:check_run_record_done
if not "!history_check_mode!"=="fail" (endlocal & exit /b 0)
set "reference_text="
set "reference_hash_text="
set "reference_failed=0"
if "!run!"=="!reference_run!" (
    set "reference_text=matches its seal !seal_name!"
    if !problems! gtr 0 set "reference_text=FAIL: its run record fails its seal check (!seal_name!)"
    set "reference_hash_text=seal SHA-256: !seal_sha256!"
    if !problems! gtr 0 set "reference_failed=1"
)
endlocal & set /a "run_record_count+=1, run_record_file_match_count+=%matches%, run_record_problem_count+=%problems%, reference_seal_failed|=%reference_failed%" & set "dashboard_last_redraw=%dashboard_last_redraw%" & if not "%reference_text%"=="" set "reference_seal_result_text=%reference_text%" & set "reference_seal_sha256_text=%reference_hash_text%"
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
rem The directory's files are counted first: cmd skips a FOR /F iteration
rem whose expanded command would pass 8,191 characters without a word, so a
rem file with such a path would go unchecked (round 12.7's class of defect).
set "files_in_directory=0"
set "record_files_dir_with_backslash=%record_files_dir%\"
call :list_directory "/b /s /a-d" record_files_dir_with_backslash temp_record_files_listing || goto check_run_record_files_unlistable
"%tool_find%" /c /v "" <"%temp_record_files_listing%" >"%temp_count%" 2>nul
for /f "usebackq" %%N in ("%temp_count%") do set "files_in_directory=%%N"
set "files_checked=0"
for /f "usebackq eol=/ delims=" %%F in ("%temp_record_files_listing%") do (
    set /a "files_checked+=1"
    set "directory_file_path=%%F"
    call :check_file_listed_in_seal %~1 %~2 %~3 directory_file_path
)
if not "%files_checked%"=="%files_in_directory%" call :report_run_record_files_unread %~1 files_checked files_in_directory
endlocal & set /a "problems+=%problems%"
exit /b 0
:check_run_record_files_unlistable
rem The run record's directory couldn't be listed, so no file in it can be
rem checked against the seal (the seal's own lines were checked by the
rem caller): one problem, by run. Unknown is not passed: until 2.8.0 the
rem empty listing counted as zero files, all checked.
call :copy_variable %~1 record_files_run
set "finding=Run record %record_files_run%: its directory couldn't be listed (access denied, missing, or the device isn't readable), so its files can't be checked against its seal."
call :history_finding finding
endlocal & set /a "problems+=1"
exit /b 0

:report_run_record_files_unread  runVar  checkedVar  totalVar
rem Caller's scope (:check_run_record_files): not every file in the run
rem record's directory was read from its listing, so not every one was
rem checked against the seal. A finding, counted with the problems.
setlocal EnableDelayedExpansion
set "finding=Run record !%~1!: only !%~2! of the !%~3! files in its directory could be read from the listing (cmd can't carry a path over 8000 characters), so not every file was checked against its seal."
call :history_finding finding
endlocal & set /a "problems+=1"
exit /b 0

:check_seal_lines  runVar  runDirVar  sealPathVar
rem Every "SHA-256 *name" line of a run record's seal, through
rem :check_sealed_file. The seal is read from a copy (:copy_for_reading,
rem as every custody file read for a check is: round 14.8 found a bare
rem FOR /F here, which printed cmd's own message for an unreadable seal
rem and read it as no lines); a seal that couldn't be read is one problem
rem here, and every file of the record is then reported by
rem :check_file_listed_in_seal. The lines are read with delayed expansion
rem off, so a "!" in a listed name survives (section 6 of the
rem conventions); matches and problems, plain numbers, go back to the
rem caller (:check_run_record).
setlocal DisableDelayedExpansion
call :copy_for_reading %~3 temp_custody_copy || goto check_seal_lines_unreadable
for /f "usebackq tokens=1,*" %%A in ("%temp_custody_copy%") do (
    set "listed_sha256=%%A"
    set "listed_name=%%B"
    call :check_sealed_file %~1 %~2 listed_name listed_sha256
)
endlocal & set "matches=%matches%" & set "problems=%problems%"
exit /b 0
:check_seal_lines_unreadable
call :copy_variable %~1 seal_lines_run
set "finding=Run record %seal_lines_run%: its seal couldn't be read (access denied, empty, or the device isn't readable), so the files it lists can't be checked."
call :history_finding finding
endlocal & set "matches=%matches%" & set /a "problems=%problems%+1"
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
    set "finding=Run record !%~1!: !sealed_name! is listed in its seal but missing."
    goto check_sealed_file_failed
)
if /i not "!current_sha256!"=="!%~4!" (
    set "finding=Run record !%~1!: !sealed_name! has changed since it was sealed."
    goto check_sealed_file_failed
)
endlocal & set /a "matches+=1" & exit /b 0
:check_sealed_file_failed
call :history_finding finding
endlocal & set /a "problems+=1" & exit /b 0

:check_file_listed_in_seal  runVar  runDirVar  sealPathVar  filePathVar
rem A file in a run record must be the seal itself, an ignored name, or
rem listed in the seal (by its path inside the run record). The file's own
rem name is cut from its path with !var! operations, not taken from a FOR
rem value: with delayed expansion on, a FOR value loses its "!", and a file
rem planted as "!._x" or "desk!top.ini" would then match an ignored name and
rem go unchecked (static check, 2026-10-16).
setlocal EnableDelayedExpansion
set "file_path=!%~4!"
set "run_dir_with_backslash=!%~2!\"
call :relative_path file_path run_dir_with_backslash name_in_record || goto check_file_listed_in_seal_unresolved
set "file_name=!name_in_record!"
for /l %%I in (1,1,%PATH_MAX_DEPTH%) do if not "!file_name:\=!"=="!file_name!" set "file_name=!file_name:*\=!"
if /i "!name_in_record!"=="!RECORD_FILE_PREFIX!!%~1!.sha256" (endlocal & exit /b 0)
call :name_matches_list file_name IGNORED_CUSTODY_FILES && (endlocal & exit /b 0)
call :copy_for_reading %~3 temp_custody_copy || goto check_file_listed_in_seal_seal_unreadable
"%tool_findstr%" /l /e /c:" *!name_in_record!" "!temp_custody_copy!" >nul 2>&1 && (endlocal & exit /b 0)
set "finding=Run record !%~1!: !name_in_record! is not listed in its seal."
call :history_finding finding
endlocal & set /a "problems+=1" & exit /b 0
:check_file_listed_in_seal_seal_unreadable
rem The seal itself couldn't be read, so the file can't be shown listed in
rem it: unknown is not passed.
set "finding=Run record !%~1!: !name_in_record! can't be checked against the seal, which couldn't be read (access denied, empty, or the device isn't readable)."
call :history_finding finding
endlocal & set /a "problems+=1" & exit /b 0
:check_file_listed_in_seal_unresolved
rem A file found in the run record whose place in it can't be worked out is
rem never taken as listed: unknown is not passed.
set "finding=Run record !%~1!: !file_path! is in the run record, but its path inside it couldn't be worked out, so it can't be checked against the seal."
call :history_finding finding
endlocal & set /a "problems+=1" & exit /b 0

:copy_for_reading  pathVar  copyVar
rem Copy a custody file (a history, a seal, a log, a script copy) byte for
rem byte into the TEMP file copyVar names (temp_custody_copy, or
rem temp_custody_copy_second where two are read together), for findstr,
rem find or fc to read at once. cmd's own commands (copy, type, if exist,
rem FOR /F) open a path of any length; those tools, given the path, can't
rem open one over 260 characters (round 12.8, RECORD-DEEP: a set directory
rem path of about 240 characters made its history read as matching no run
rem record). The copy is emptied first. Exit 0 once the file has been
rem copied whole; exit 1, the copy empty, when the file is missing, is
rem zero bytes (no custody file is legitimately empty: every record has
rem at least a header line, a seal at least one line; COPY copies an
rem empty file and exits 0, round 14.8, so the size is tested), can't be
rem read or copied, or the copy can't be written. Until 2.8.0 every
rem case read as an empty file, so an unreadable seal, history or log
rem failed as "doesn't match" or went unreported (the GPT 6.1 review's
rem finding 3, 2026-10-24). A caller that gets exit 1 says the file
rem couldn't be read; it never takes the empty copy as the file's content.
setlocal EnableDelayedExpansion
set "copy_path=!%~2!"
(type nul >"!copy_path!") 2>nul || (endlocal & exit /b 1)
if not exist "!%~1!" (endlocal & exit /b 1)
for %%A in ("!%~1!") do if "%%~zA"=="0" (endlocal & exit /b 1)
copy /b /y "!%~1!" "!copy_path!" >nul 2>&1 || (endlocal & exit /b 1)
endlocal & exit /b 0

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
call :copy_for_reading history_source_file temp_custody_copy || (endlocal & endlocal & exit /b 1)
for /f "tokens=1* delims=:" %%A in ('2^>nul "%tool_findstr%" /n "^" "%temp_custody_copy%"') do (
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

:work_out_result
rem Work out the overall result from each check and set exit_code; the
rem summary (:write_summary) states what the result covers, so it can't be
rem misread later.
call :get_utc_now
set "end_utc_iso=%utc_iso%"
call :work_out_copy_status
set "metadata_status=NOT RUN"
set "hash_status=NOT RUN"
set "run_records_status=NOT RUN"
set "result_metadata=NOT RUN: verification was not requested"
set "result_hash=NOT RUN: verification was not requested"
set "result_hash_detail_count=0"
set "result_run_records=NOT RUN"
set "result_reference=none"
set "verification_ran="
if "%verification_enabled%"=="1" set "verification_ran=1"
if "%run_mode%"=="forensic" set "verification_ran=1"
if defined verification_ran call :work_out_verification_status
rem The verdict: FAIL if the copy or any check failed (with verification on,
rem a check that didn't pass counts as failed; run records and the script
rem may also be NONE, with nothing earlier to check; the copy and the
rem metadata check are NONE in a check or a relocation, which has no
rem copy); UNVERIFIED if the copy passed but nothing was verified
rem (non-forensic only); otherwise PASS.
set "verdict=PASS"
if not "%copy_status%"=="PASS" if not "%copy_status%"=="NONE" set "verdict=FAIL"
if defined verification_ran if not "%metadata_status%"=="PASS" if not "%metadata_status%"=="NONE" set "verdict=FAIL"
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
exit /b 0

:work_out_copy_status
rem copy_status (PASS or FAIL) and the Copy row's text from the robocopy
rem exit codes of every pass; also called when the copy finishes, for the
rem live display.
if not "%run_kind%"=="copy" (
    set "copy_status=NONE"
    set "result_copy=NONE: nothing copied: the set verified in place (%run_kind_switch%)"
    if "%run_kind%"=="relocate" set "result_copy=NONE: nothing copied: the set moved within its volume (/relocate)"
    exit /b 0
)
set /a "copy_failed_bits=copy_exit_codes & ROBOCOPY_FAIL_MASK"
set "copy_status=PASS"
if %copy_failed_bits% neq 0 set "copy_status=FAIL"
rem The codes are combined by OR, so one pass's abnormal code (negative, or
rem above robocopy's range) stays out of range in the combination.
call :is_robocopy_exit_code_in_range copy_exit_codes || set "copy_status=FAIL"
if %copy_log_incomplete% neq 0 set "copy_status=FAIL"
set "result_copy=%copy_status%: robocopy exit codes combined: %copy_exit_codes%"
call :describe_copy_counts copy_counts_text
if defined copy_counts_text set "result_copy=%copy_status%: %copy_counts_text% (robocopy exit codes combined: %copy_exit_codes%)"
if %copy_log_incomplete% neq 0 set "result_copy=%result_copy%, but its output in the log is incomplete"
if "%copy_status%"=="FAIL" set "result_copy=%result_copy% (see Copy above, and Failures)"
exit /b 0

:describe_copy_counts  outVar
rem The Copy row's words (2.8.0; owner) from robocopy's Files rows over the
rem evidence passes (copy_files_<column>, :add_pass_summary_counts): what
rem was copied, what was already there, what failed, what was mismatched or
rem extra; never "successful" (Copy is robocopy's report; verification is
rem the other rows). Empty when a pass ran without a readable summary: the
rem row then keeps the exit codes alone.
set "%~1="
if %copy_counts_missing% neq 0 exit /b 0
rem Already there: each pass counts the files of the other passes as
rem Skipped (its size filter leaves them out), so those come off the
rem skipped total: with every pass seeing the same files, (passes - 1)
rem times the Total. A count that comes out negative means the passes
rem didn't see the same files: the row then keeps the exit codes alone.
set /a "copy_files_already_there=copy_files_skipped - (copy_passes_counted - 1) * copy_files_total"
if %copy_files_already_there% lss 0 exit /b 0
call :count_with_noun copy_files_copied file copy_counts_copied_text
call :count_with_noun copy_files_already_there file copy_counts_skipped_text
call :count_with_noun copy_files_failed file copy_counts_failed_text
call :count_with_noun copy_files_mismatch file copy_counts_mismatch_text
call :count_with_noun copy_files_extras file copy_counts_extras_text
if %copy_files_copied% gtr 0 (set "copy_counts_words=%copy_counts_copied_text% copied") else set "copy_counts_words=nothing needed copying"
if %copy_files_already_there% gtr 0 set "copy_counts_words=%copy_counts_words%, %copy_counts_skipped_text% already there"
if %copy_files_failed% gtr 0 set "copy_counts_words=%copy_counts_words%, %copy_counts_failed_text% couldn't be copied"
if %copy_files_failed% equ 0 if %copy_files_copied% gtr 0 set "copy_counts_words=%copy_counts_words%, none failed"
if %copy_files_mismatch% gtr 0 set "copy_counts_words=%copy_counts_words%, %copy_counts_mismatch_text% mismatched (a file and a directory share a name)"
if %copy_files_extras% gtr 0 set "copy_counts_words=%copy_counts_words%, %copy_counts_extras_text% extra in the destination"
set "%~1=%copy_counts_words%"
exit /b 0

:count_with_noun  countVar  noun  outVar
rem "1 <noun>" or "<n> <noun>s".
call :copy_variable %~1 count_with_noun_value
if "%count_with_noun_value%"=="1" (set "%~3=1 %~2") else set "%~3=%count_with_noun_value% %~2s"
exit /b 0

:write_summary
rem The summary (shared rule: scannable output): its fields, the warnings,
rem the failures, the sentence saying what the result covers, and last the
rem result block. The checks in the block are in the order they ran (owner,
rem 2026-10-16 and 2026-10-18: the Script check before the copy; the copy;
rem then metadata, the run records, and last the SHA-256 hashing and
rem compare, which relies on the reference record having passed its seal).
rem In a forensic run the block goes into the log here, sealed with it; the
rem console gets it last, after the record's write-back (:write_result_block
rem console in MAIN).
set "heading=Summary" & call :write_section_heading heading both
call :log_field "Finished (UTC)" end_utc_iso
if "%run_mode%"=="forensic" call :log_result_records
set "msg=" & call :show_and_log msg
call :log_summary_list "Warnings (did not fail the run)" warnings
set "msg=" & call :show_and_log msg
call :log_summary_list "Failures" failures
set "msg=" & call :show_and_log msg
call :show_and_log result_meaning
if "%run_mode%"=="forensic" (call :write_result_block log) else call :write_result_block console
exit /b 0

:log_result_records
rem Forensic run: the record lines of the summary.
call :log_field "Script copy" result_script_copy
call :log_field "Reference record" result_reference
if defined reference_seal_result_text call :log_field_continued reference_seal_result_text
if defined reference_seal_sha256_text call :log_field_continued reference_seal_sha256_text
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
if "%run_kind%"=="check" set "result_meaning=The set was verified in place: every file in the reference record is in its evidence directory with the same SHA-256"
if "%run_kind%"=="relocate" set "result_meaning=The set was moved to %destination_set_path% and verified there: every file in the reference record is in its evidence directory with the same SHA-256"
if "%run_records_status%"=="PASS" set "result_meaning=%result_meaning%; every earlier run record matches its seal and the history"
exit /b 0

:describe_failure
rem The closing line of a FAIL summary: each failed check, in the order they
rem ran, then a pointer to the failures listed below the result.
set "result_meaning="
if "%script_status%"=="FAIL" call :add_failure_clause "The script check failed" "the script check failed"
if not "%copy_status%"=="PASS" if not "%copy_status%"=="NONE" call :add_failure_clause "The copy failed" "the copy failed"
if defined verification_ran if not "%metadata_status%"=="PASS" if not "%metadata_status%"=="NONE" call :add_failure_clause "The metadata check failed" "the metadata check failed"
if "%run_records_status%"=="FAIL" call :add_failure_clause "The run records check failed" "the run records check failed"
if defined verification_ran if not "%hash_status%"=="PASS" call :add_failure_clause "The SHA-256 verification failed" "the SHA-256 verification failed"
call :add_failure_clause "See the failures listed above" "see the failures listed above"
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
call :describe_paths_too_long
set /a "hash_problem_count=differ_count + missing_count + invalid_row_count + unreadable_count + unexpected_listing_lines + hash_check_incomplete + reference_seal_failed + unaccounted_rows + path_too_long_count"
if "%run_mode%"=="forensic" set /a "hash_problem_count+=added_file_count"
set "hash_status=PASS"
if %hash_problem_count% neq 0 set "hash_status=FAIL"
if %match_count% equ 0 set "hash_status=FAIL"
set "reference_label=files in the reference record"
if "%run_mode%"=="nonforensic" set "reference_label=source files"
set "result_hash=%hash_status%: %match_count% of %reference_row_count% %reference_label% match the destination"
rem The detail under the Hash check: one count per line (a list is laid
rem out, not wrapped).
set "result_hash_detail_count=0"
call :add_hash_detail "%differ_count% differ"
call :add_hash_detail "%missing_count% missing"
call :add_hash_detail "%unreadable_count% unreadable"
if "%run_mode%"=="forensic" call :add_hash_detail "%invalid_row_count% invalid in the record"
if "%run_mode%"=="forensic" call :add_hash_detail "added since: %added_file_count% file(s)"
if %hash_check_incomplete% neq 0 call :add_hash_detail "INCOMPLETE (see Failures)"
if %unexpected_listing_lines% neq 0 call :add_hash_detail "%unexpected_listing_lines% unexpected listing line(s)"
if %path_too_long_count% neq 0 call :add_hash_detail "paths too long: %path_too_long_detail_text%"
rem Files added since the reference fail a forensic run even when every file
rem in the record matches: say so first.
if "%run_mode%"=="forensic" if %added_file_count% gtr 0 set "result_hash=%hash_status%: %added_file_count% file(s) in the destination aren't in the reference record (added since); %match_count% of %reference_row_count% %reference_label% match the destination"
rem A file not hashed for its path's length fails the run whatever the rest
rem matched: say so first (MAX_FILE_PATH_LENGTH; the file is named in the
rem Hash section and Failures). The refusals are given per side, never as
rem a count of files: one file over the limit on both sides of a first copy
rem is refused twice (round 12.8).
if %path_too_long_count% gtr 0 set "result_hash=%hash_status%: not hashed, path too long: %path_too_long_text%; %match_count% of %reference_row_count% %reference_label% match the destination"
rem A reference whose run record fails its checks can't be relied on, even
rem if every file matches it: say so first, so the status can't be misread.
if %reference_seal_failed% neq 0 set "result_hash=%hash_status%: the reference record's run record failed its checks, so the reference can't be relied on; %match_count% of %reference_row_count% %reference_label% match it"
rem Nothing to verify: that is the reason, so it leads (the counts are 0).
if "%run_mode%"=="forensic" if %hash_check_incomplete% equ 0 if %reference_row_count% equ 0 set "result_hash=%hash_status%: nothing was verified: the reference record lists no files"
if "%run_mode%"=="nonforensic" if %hash_check_incomplete% equ 0 if %reference_row_count% equ 0 set "result_hash=%hash_status%: nothing was verified: the source holds no files"
rem The pointer names what explains the failure: an unreliable reference is
rem explained by the Run records check, a comparison problem by the Hash
rem section; both are in Failures.
set /a "comparison_problem_count=hash_problem_count - reference_seal_failed"
set "hash_pointer=see Hash (SHA-256) above, and Failures"
if %reference_seal_failed% neq 0 set "hash_pointer=see Run records above, and Failures"
if %reference_seal_failed% neq 0 if %comparison_problem_count% neq 0 set "hash_pointer=see Run records and Hash (SHA-256) above, and Failures"
if "%hash_status%"=="FAIL" set "result_hash=%result_hash% (%hash_pointer%)"
if %hash_check_incomplete% equ 0 if %reference_row_count% equ 0 call :report_nothing_to_verify
call :work_out_metadata_status
if not "%run_mode%"=="forensic" exit /b 0
call :work_out_run_records_status
exit /b 0

:work_out_metadata_status
rem metadata_status (PASS or FAIL) and the Metadata row's text from the
rem metadata check's counters; also called when that check finishes, for
rem the live display.
if not "%run_kind%"=="copy" (
    set "metadata_status=NONE"
    set "result_metadata=NONE: no copy to compare sizes and times with (%run_kind_switch%)"
    exit /b 0
)
set "metadata_status=FAIL"
set "result_metadata=NOT RUN"
if defined metadata_check_ran set "metadata_status=PASS"
if defined metadata_check_ran set "result_metadata=PASS: size and last-modified time match for every file (compared %metadata_time_precision%)"
if defined metadata_check_ran if %hashed_count_destination% equ 0 set "result_metadata=PASS: no differences, but there were no files to compare"
if %metadata_differ_count% neq 0 set "metadata_status=FAIL"
if %metadata_differ_count% neq 0 set "result_metadata=FAIL: %metadata_differ_count% file(s) differ in size or last-modified time, or were not copied (see Metadata above, and Failures)"
if %metadata_check_incomplete% neq 0 set "metadata_status=FAIL"
if %metadata_check_incomplete% neq 0 set "result_metadata=FAIL: the comparison was incomplete (see Metadata above, and Failures)"
exit /b 0

:work_out_run_records_status
rem run_records_status (PASS, WARN, FAIL or NONE) and the Run records row's
rem text: NONE if the set has no earlier runs (a first copy); FAIL if there
rem are some but the check didn't run, or found any problem; WARN if the
rem check after the copy found none but a warning about the records was
rem raised (run_records_warned; owner, 2026-10-20: the warning is inherited,
rem never a PASS beside it). Also called when that check finishes, for the
rem live display.
set "run_records_status=NONE"
set "result_run_records=NONE: no earlier runs found in the source"
if %history_row_count% gtr 0 if not defined run_records_checked set "run_records_status=FAIL" & set "result_run_records=FAIL: not checked (verification stopped before the run records check; see Failures)"
if defined run_records_checked set "run_records_status=PASS" & set "result_run_records=PASS: %run_record_count% run record(s) match their seals and the history (%run_record_file_match_count% sealed file(s))"
if defined run_records_checked if %run_record_count% equ 0 if %run_record_problem_count% equ 0 set "run_records_status=NONE" & set "result_run_records=NONE: no earlier runs found in the source"
if defined run_records_checked if defined run_records_warned if %run_record_count% gtr 0 if %run_record_problem_count% equ 0 set "run_records_status=WARN" & set "result_run_records=WARN: %run_record_count% run record(s) match their seals and the history (%run_record_file_match_count% sealed file(s)); warnings before the copy (see Warnings)"
if %run_record_problem_count% neq 0 set "run_records_status=FAIL" & set "result_run_records=FAIL: %run_record_problem_count% problem(s) in the run records (see Run records above, and Failures)"
exit /b 0

:describe_paths_too_long
rem Caller's scope (:work_out_result): path_too_long_count, the refusals for
rem a path's length on both sides together, and path_too_long_text, the
rem refusals by side ("1 in the source, 1 in the destination"; a side with
rem none is left out; "none" if neither has any), and
rem path_too_long_detail_text, the same for the Hash check's detail line,
rem short enough to stay on one line from column 29 ("1 source, 1
rem destination"; round 12.9: the longer form wrapped).
set /a "path_too_long_count=path_too_long_source_count + path_too_long_destination_count"
set "path_too_long_text="
set "path_too_long_detail_text="
if %path_too_long_source_count% gtr 0 set "path_too_long_text=%path_too_long_source_count% in the source"
if %path_too_long_source_count% gtr 0 set "path_too_long_detail_text=%path_too_long_source_count% source"
if %path_too_long_destination_count% gtr 0 if defined path_too_long_text set "path_too_long_text=%path_too_long_text%, "
if %path_too_long_destination_count% gtr 0 if defined path_too_long_detail_text set "path_too_long_detail_text=%path_too_long_detail_text%, "
if %path_too_long_destination_count% gtr 0 set "path_too_long_text=%path_too_long_text%%path_too_long_destination_count% in the destination"
if %path_too_long_destination_count% gtr 0 set "path_too_long_detail_text=%path_too_long_detail_text%%path_too_long_destination_count% destination"
if not defined path_too_long_text set "path_too_long_text=none"
if not defined path_too_long_detail_text set "path_too_long_detail_text=none"
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
if not "%run_kind%"=="copy" (
    set "script_copy_route=none"
    set "result_script_copy=not placed: nothing copied (%run_kind_switch%); the set's own script copies stay as they are"
    exit /b 0
)
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
set "result_script_copy=FAIL: no verified copy of the script in the destination set directory"
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
call :copy_for_reading file temp_custody_copy
for %%N in (TOOL_VERSION SCRIPT_VERSION) do if not defined version (
    "%tool_findstr%" /b /r /c:"set .%%N=" "!temp_custody_copy!" >"!temp_record_match!" 2>nul
    for /f "usebackq tokens=2 delims==" %%V in ("!temp_record_match!") do if not defined version set "version=%%V"
)
if defined version set "version=!version:"=!"
endlocal & set "%~2=%version%"
exit /b 0

:write_history
rem Forensic run. This run's history, sealed in its run record: the history
rem it continues, unchanged, with this run's row added; or, if it continues
rem none, the header and this run's row. The new row's Seal SHA-256 is
rem pending_seal_text ("see <its seal file>"): the next run fills it in.
rem The copy must have the SHA-256 the history had when it was chosen
rem (2.8.2, the GPT 6.1 review of 2.8.1, finding 1): a copy that failed
rem or was cut short, or a history changed during the run, would
rem otherwise be sealed as this run's history, without the rows before.
rem Then the seal is incomplete (history_staging_problem, :write_seal).
rem history_base_path is only ever set to a history that was there when
rem it was chosen: one gone since is a failed copy (2.8.2; before, the
rem run started a new history in silence).
set "history_continues="
if defined history_base_path set "history_continues=1"
if defined history_continues copy /b "%history_base_path%" "%staged_history_path%" >nul 2>&1
if defined history_continues call :history_copy_is_unchanged staged_history_path || set "history_staging_problem=1"
if not defined history_continues call :append_line_to_file HISTORY_HEADER staged_history_path
set "history_source_set=%source_path%"
if defined source_set_path set "history_source_set=%source_set_path%"
rem A relocation's row: where the set was as the source, its new location
rem as the destination (the Location check of later runs compares with the
rem destination); its run record's relocation file says it was a move.
if "%run_kind%"=="relocate" set "history_source_set=%relocate_from_path%"
call :append_history_row
exit /b 0

:history_copy_is_unchanged  copyPathVar
rem Exit 0 if the copy has the SHA-256 the history this run continues had
rem when it was chosen (history_base_sha256, :read_history), so it holds
rem exactly the history that was checked. A hash that couldn't be taken
rem at either point is exit 1: unknown is not unchanged. A copy that
rem isn't there (the history unreadable or gone) is exit 1 without a
rem hash: :get_sha256's retry would wait and write its notes for nothing
rem (2.8.2, round 15.6).
setlocal
call :copy_variable %~1 copy_path
if not exist "%copy_path%" (endlocal & exit /b 1)
set "copy_sha256="
call :get_sha256 %~1 copy_sha256
if not defined history_base_sha256 (endlocal & exit /b 1)
if /i "%copy_sha256%"=="%history_base_sha256%" (endlocal & exit /b 0)
endlocal & exit /b 1

:report_history_not_copied
rem (:write_seal, after its heading, when :write_history set
rem history_staging_problem) The history continued couldn't be copied
rem into the run record unchanged: a [FAIL] on the console in the Record
rem written section (the log is closed), and the seal is incomplete, so
rem the record isn't written.
set "msg=[FAIL] The history this run continues couldn't be copied into its run record unchanged (it couldn't be read, or it changed after it was checked before the copy): the record can't be sealed."
call :show_write_back_problem msg
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
rem or the seal itself couldn't be hashed, or (2.8.0, :check_record_files)
rem a file the run must have written is missing or empty, or staging holds
rem a file no row of RECORD_FILES names, or (2.8.2, :write_history) the
rem history continued wasn't copied unchanged: :publish_records then writes
rem nothing and the run fails (owner, 2026-10-16), since a run record whose
rem seal doesn't cover it would fail every later copy. Console only from
rem here: the log is complete and is being sealed.
set "heading=Record written: sealing this run's record and writing it to the destination"
call :write_section_heading heading console
rem From here the log is closed: nothing more is written into it, whatever
rem the target a later line asks for (:emit_line), so the seal covers it as
rem it stays.
set "log_sealed=1"
set "record_files_problem="
call :check_record_files
if defined history_staging_problem call :report_history_not_copied
setlocal EnableDelayedExpansion
set "sealed_count=0"
set "seal_expected_count=0"
for %%F in (log_staged_path staged_hash_csv_source staged_hash_csv_destination staged_hash_csv_custody staged_history_path staged_outside_history_path staged_relocation_path) do (
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
            set "msg=[FAIL] Could not hash !record_name! for the seal."
            call :show_write_back_problem msg
        )
    )
)
set "incomplete="
if !sealed_count! neq !seal_expected_count! set "incomplete=1"
if defined record_files_problem set "incomplete=1"
if defined history_staging_problem set "incomplete=1"
if !sealed_count! equ 0 (endlocal & set "seal_incomplete=1" & exit /b 0)
set "seal_sha256="
call :get_sha256 staged_seal_path seal_sha256
if not defined seal_sha256 set "incomplete=1"
if not defined seal_sha256 (
    set "msg=[FAIL] Could not hash the seal file."
    call :show_write_back_problem msg
)
endlocal & set "run_seal_sha256=%seal_sha256%" & set "seal_incomplete=%incomplete%"
exit /b 0

:check_record_files
rem Caller's scope (:write_seal, before the seal is written; the log is
rem closed). Every file this run's record must hold is in staging with at
rem least one line, and nothing else is there but the seal and junk names
rem (RECORD_FILES, CONFIG): a record file never written, or an extra file
rem the seal wouldn't list, would otherwise be found only by a later run
rem (the GPT 6.1 review's finding 7, 2026-10-24). Each problem is a [FAIL]
rem by name on the console (:show_write_back_problem) and sets
rem record_files_problem, so the seal is incomplete and the record isn't
rem written.
setlocal DisableDelayedExpansion
type nul >"%temp_record_files_expected%"
for %%R in (%RECORD_FILES%) do call :check_record_file %%R
set "staged_records_dir_with_backslash=%staged_records_dir%\"
call :list_directory "/b /a-d" staged_records_dir_with_backslash temp_directory_listing || call :report_record_files_unlistable
for /f "usebackq eol=/ delims=" %%F in ("%temp_directory_listing%") do (
    set "staged_file_name=%%F"
    call :check_staged_file_expected
)
endlocal & set "record_files_problem=%record_files_problem%"
exit /b 0

:check_record_file  name
rem Caller's scope (:check_record_files): one row of RECORD_FILES. Its
rem name goes to temp_record_files_expected (for the extra-file check);
rem when the row's WHEN holds for this run, the file must exist with at
rem least one line.
call :copy_variable RECORD_FILE_%~1_SUFFIX record_file_suffix
call :copy_variable RECORD_FILE_%~1_VAR record_file_var
call :copy_variable RECORD_FILE_%~1_WHEN record_file_when
set "record_file_name=%record_file_stem%%record_file_suffix%"
>>"%temp_record_files_expected%" echo(%record_file_name%
call :record_file_required %record_file_when% || exit /b 0
call :copy_variable %record_file_var% record_file_path
set "record_file_lines=0"
if defined record_file_path if exist "%record_file_path%" (
    "%tool_find%" /c /v "" <"%record_file_path%" >"%temp_count%" 2>nul
    for /f "usebackq" %%N in ("%temp_count%") do set "record_file_lines=%%N"
)
if %record_file_lines% gtr 0 exit /b 0
set "msg=[FAIL] The run record's %record_file_name% is missing or empty: it was never written, so the record can't be sealed."
call :show_write_back_problem msg
set "record_files_problem=1"
exit /b 0

:record_file_required  when
rem Exit 0 when a RECORD_FILE_<name>_WHEN value says the file must be in
rem this run's record; a value not known here counts as always (unknown is
rem not optional).
if "%~1"=="optional" exit /b 1
if "%~1"=="no_reference" if defined reference_run exit /b 1
if "%~1"=="relocation" if not "%run_kind%"=="relocate" exit /b 1
exit /b 0

:check_staged_file_expected
rem Caller's scope (:check_record_files): one file found in staging, in
rem staged_file_name: the seal itself, a junk name, or a name a row of
rem RECORD_FILES gives; anything else is a [FAIL].
if /i "%staged_file_name%"=="%record_file_stem%.sha256" exit /b 0
call :name_matches_list staged_file_name IGNORED_CUSTODY_FILES && exit /b 0
"%tool_findstr%" /x /i /l /c:"%staged_file_name%" "%temp_record_files_expected%" >nul 2>&1 && exit /b 0
set "msg=[FAIL] %staged_file_name% is in the staged run record but isn't a file this run writes: the record can't be sealed with it."
call :show_write_back_problem msg
set "record_files_problem=1"
exit /b 0

:report_record_files_unlistable
rem Caller's scope (:check_record_files): the staged run record couldn't be
rem listed, so it can't be checked before sealing.
set "msg=[FAIL] The staged run record (%staged_records_dir%) couldn't be listed (access denied, missing, or the device isn't readable), so it can't be checked before sealing."
call :show_write_back_problem msg
set "record_files_problem=1"
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
rem path shown, so no record is lost, and the exit code becomes FAIL. Sets
rem result_record_written, the "Record written" row of the console's result
rem block (it starts as a FAIL: unknown is not passed).
if not defined staging_dir exit /b 0
call :is_directory staging_dir || exit /b 0
if defined seal_incomplete goto publish_records_seal_incomplete
setlocal
set "record_written_text=FAIL: no record files were found to write (see Record written above)"
set "record_count=0"
set "records_matching=0"
set "records_robocopy_exit_codes=0"
set "run_record_in_place="
set "publish_listing_failed="
call :publish_staged_directory records
if %records_matching% equ %record_count% if %record_count% gtr 0 ren "%destination_partial_run_dir%" "%run_utc_stamp%" >nul 2>&1 && set "run_record_in_place=1"
if %record_count% gtr 0 if not defined run_record_in_place call :report_run_record_not_completed
call :publish_staged_directory root
if defined run_record_in_place if defined run_seal_sha256 call :publish_root_history new
if not defined run_record_in_place if defined history_base_path call :publish_root_history continued
if defined publish_listing_failed goto publish_records_failed
if %record_count% equ 0 goto publish_records_done
if not %records_matching% equ %record_count% goto publish_records_failed
if not defined run_record_in_place goto publish_records_failed
set "msg=Custody files written to the destination and read back: %records_matching% of %record_count% match."
call :show msg
set "record_written_text=PASS: %records_matching% of %record_count% custody files written and read back intact"
set "log_was_published="
if defined log_ready set "log_was_published=1"
del /f /q "%staged_records_dir%\*" >nul 2>&1
del /f /q "%staged_root_dir%\*" >nul 2>&1
:publish_records_done
rd "%staged_records_dir%" >nul 2>&1
rd "%staged_root_dir%" >nul 2>&1
rd "%staging_dir%" >nul 2>&1
endlocal & set "result_record_written=%record_written_text%" & set "log_published=%log_was_published%" & exit /b 0
:publish_records_failed
set "msg=[WARN] Only %records_matching% of %record_count% custody files reached the destination intact (robocopy exit codes combined: %records_robocopy_exit_codes%). All of them are kept here:"
call :show_write_back_problem msg
set "msg=       %staging_dir%"
call :show msg
set "msg=[FAIL] This run's record wasn't completed in the destination. The log and summary were sealed before the write-back; because the record is missing, the exit code is FAIL (%EXIT_CODE_FAIL%)."
call :show_write_back_problem msg
set "record_written_text=FAIL: only %records_matching% of %record_count% custody files reached the destination intact; all are kept in TEMP (see Record written above)"
endlocal & set "exit_code=%EXIT_CODE_FAIL%" & set "result_record_written=%record_written_text%" & set "record_kept_in_staging=1" & exit /b 1

:report_run_record_not_completed
rem Caller's scope (:publish_records): the run record couldn't be put in
rem place. Say what the destination holds of it: a .partial directory,
rem nothing at all, or, if the destination can't be reached (e.g. the drive
rem was removed), that this can't be told.
set "msg=[WARN] The run record could not be written to the destination (nothing of it is there) and is not added to the history."
call :is_directory destination_set_with_backslash || set "msg=[WARN] The run record could not be written: the destination set directory can't be reached, so whether any of the run record is there can't be told. It is not added to the history; a later copy warns about any %run_utc_stamp%%PARTIAL_RUN_SUFFIX% left there."
call :is_directory destination_partial_run_dir && set "msg=[WARN] The run record was not completed in the destination: it is left as %run_utc_stamp%%PARTIAL_RUN_SUFFIX% and is not added to the history."
call :show_write_back_problem msg
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
set "msg=[FAIL] This run's record couldn't be sealed completely, so none of it was written to the destination.%continued_history_text% The log and summary were written before the seal; the exit code is FAIL (%EXIT_CODE_FAIL%). Everything is kept here:"
call :show_write_back_problem msg
set "msg=       %staging_dir%"
call :show msg
set "record_written_text=FAIL: this run's record couldn't be sealed completely, so none of it was written (see Record written above)"
endlocal & set "exit_code=%EXIT_CODE_FAIL%" & set "result_record_written=%record_written_text%" & set "record_kept_in_staging=1" & exit /b 1

:work_out_final_result
rem Forensic run, after the write-back: the verdict the console shows last,
rem which also covers writing the record (the sealed log can't: shared rule).
rem A record that wasn't written in full makes the run FAIL.
set "final_verdict=%verdict%"
if not "%result_record_written:~0,4%"=="PASS" set "final_verdict=FAIL"
if "%final_verdict%"=="FAIL" set "exit_code=%EXIT_CODE_FAIL%"
set "final_result_overall=%final_verdict% (exit code %exit_code%)"
exit /b 0

:show_closing_lines  [target]
rem Forensic run, after the console's result block. With the record written:
rem the seal's SHA-256 for the custody notes, and the log's name, then its
rem directory on a line of its own (a full path would wrap on an 80-column
rem console). With the record kept in staging instead (a failed seal or
rem write-back): where it is and its seal's SHA-256, without asking for that
rem to be recorded as the set's. Otherwise nothing: the Record written row
rem says what happened. (Owner, 2026-10-17, both.) target: console (the
rem default: MAIN, on the normal screen) or file (the display's last frame
rem and the watchdog's end-state file, 2.8.0).
set "closing_target=%~1"
if not defined closing_target set "closing_target=console"
if defined record_kept_in_staging goto show_closing_lines_kept
if not "%result_record_written:~0,4%"=="PASS" exit /b 0
if not defined run_seal_sha256 goto show_closing_lines_log
set "msg=Run record sealed in: %seal_file_name%" & call :emit_free_text msg %closing_target%
set "msg=  SHA-256: %run_seal_sha256%" & call :emit_free_text msg %closing_target%
set "msg=Record this value in your chain-of-custody notes: it shows whether this run's record is later changed."
call :emit_free_text msg %closing_target%
:show_closing_lines_log
if not defined log_published exit /b 0
set "msg=Log: %log_file_name%" & call :emit_free_text msg %closing_target%
set "msg=  in %destination_run_dir%" & call :emit_free_text msg %closing_target%
exit /b 0
:show_closing_lines_kept
set "msg=Run record kept in TEMP, not in the destination (see Record written above)."
call :emit_free_text msg %closing_target%
if not defined run_seal_sha256 exit /b 0
set "msg=  Its seal: %seal_file_name%"
if defined seal_incomplete set "msg=  Its seal (incomplete): %seal_file_name%"
call :emit_free_text msg %closing_target%
set "msg=  SHA-256: %run_seal_sha256%" & call :emit_free_text msg %closing_target%
exit /b 0

:show_write_back_problem  msgVar
rem Forensic run, after the log is sealed: show a [WARN] or [FAIL] line of
rem the record's write-back and remember it (:remember_problem), so the
rem console's result block counts it. The sealed log's lists and block end
rem before the write-back and can't hold it (shared rule).
call :show %~1
call :remember_problem %~1
exit /b 0

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
set "publish_from_with_backslash=%publish_from%\"
call :list_directory "/b /a-d" publish_from_with_backslash temp_directory_listing || goto publish_staged_directory_unlistable
for /f "usebackq eol=/ delims=" %%F in ("%temp_directory_listing%") do if /i not "%%F"=="%HISTORY_FILE_NAME%" set /a "publish_count+=1"
if %publish_count% equ 0 exit /b 0
set /a "record_count+=publish_count"
set "publish_overwrite_flags=/xc /xn /xo"
if "%~1"=="root" if defined script_copy_replaces set "publish_overwrite_flags=/is /it"
"%tool_robocopy%" "%publish_from% " "%publish_to% " *.* /xf "%HISTORY_FILE_NAME%" /j %publish_overwrite_flags% /r:%RETRY_COUNT% /w:%RETRY_WAIT_SECONDS% /njh /njs /ndl /nfl /np >nul 2>&1
set /a "records_robocopy_exit_codes|=%errorlevel%"
for /f "usebackq eol=/ delims=" %%F in ("%temp_directory_listing%") do if /i not "%%F"=="%HISTORY_FILE_NAME%" (
    set "record_name=%%F"
    call :check_record_in_destination record_name publish_from publish_to_with_backslash
)
exit /b 0
:publish_staged_directory_unlistable
rem The staged files couldn't be listed (TEMP unreadable or gone), so none
rem was written from there, and the write-back fails (:publish_records).
set "msg=[FAIL] The staged files in %publish_from% couldn't be listed (access denied, missing, or the device isn't readable): they were not written to the destination."
call :show_write_back_problem msg
set "publish_listing_failed=1"
exit /b 0

:publish_root_history  which
rem Caller's scope (:publish_records). The history beside the evidence: with
rem which=new, this run's sealed history with its own seal filled in, so
rem every row is complete; with which=continued (this run's record couldn't
rem be completed), the history this run continued, unchanged, so the
rem destination's history still matches the run records copied there. A
rem quick overview, never relied on: each run checks it against the sealed
rem run records. It replaces the one already there (/is /it); a continued
rem history whose copy isn't the one checked before the copy (2.8.2) is
rem not written, and the destination's is left as it is.
if "%~1"=="new" call :write_history_with_seal staged_history_path pending_seal_text run_seal_sha256 staged_root_history_path
if "%~1"=="continued" copy /b "%history_base_path%" "%staged_root_history_path%" >nul 2>&1
if "%~1"=="continued" call :history_copy_is_unchanged staged_root_history_path || goto publish_root_history_not_copied
set /a "record_count+=1"
"%tool_robocopy%" "%staged_root_dir% " "%destination_set_path% " "%HISTORY_FILE_NAME%" /is /it /j /r:%RETRY_COUNT% /w:%RETRY_WAIT_SECONDS% /njh /njs /ndl /nfl /np >nul 2>&1
set /a "records_robocopy_exit_codes|=%errorlevel%"
set "record_name=%HISTORY_FILE_NAME%"
set "publish_from=%staged_root_dir%"
set "publish_to_with_backslash=%destination_set_with_backslash%"
call :check_record_in_destination record_name publish_from publish_to_with_backslash
exit /b 0
:publish_root_history_not_copied
rem Counted as a file not written: the write-back fails.
set /a "record_count+=1"
set "msg=[FAIL] The history this run continued couldn't be copied unchanged (it couldn't be read, or it changed after it was checked before the copy), so the history beside the evidence in the destination was not replaced."
call :show_write_back_problem msg
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
call :show_write_back_problem msg
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

:save_robocopy_unicode_output  outFileVar  mode  [percentages]  [exitCodeVar]
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
rem file) or append. percentages yes: the pass ran without /np, so each
rem of its file lines ends with robocopy's progress fragments (CR, a
rem percentage in three columns, "%", two spaces, repeated as the copy
rem went): every line is cut at its first CR, which no line of robocopy's
rem holds before its end otherwise, so the line reads as with /np, the
rem file's path intact. FOR /F can't take a CR as a delimiter (its options
rem take neither delayed expansion nor a FOR variable: round 12.2 cut every
rem line at the letters of "!carriage_return!"), so each CR is first turned
rem into "|", which no Windows path holds, and FOR /F cuts at the first
rem "|". The line goes into FOR /F behind a "#", taken off again after, so
rem a line that starts with a CR, or with FOR /F's end-of-line character
rem ";", is still cut and kept rather than skipped. The text before the
rem cut is assigned after ENDLOCAL, with delayed expansion off again, so a
rem "!" in the path survives, and the scope is reopened for the echo. The
rem output is
rem rewritten line by line only when it holds an ERROR line ("(0x", the
rem error code robocopy writes with every ERROR line, in any language) or
rem percentages: otherwise TYPE's output is appended as it is, the same
rem bytes without a FOR /F per line (about a millisecond each: 100 s for
rem 100,000 lines; workshop, 2026-10-18). exitCodeVar (a copy pass's exit
rem code): outside robocopy's own range (stopped, e.g. by Ctrl+C) the log
rem is rewritten too, so its last line, cut where robocopy stopped, gets a
rem line end, and the next line of the log starts on a line of its own
rem (round 12.4: "Robocopy exit code: ..." ran onto the last file's name).
rem The rewrite counts the lines it writes against the lines robocopy's
rem output holds (robocopy_output_lines_written, _total, for the caller):
rem cmd skips a FOR /F iteration whose expanded command would pass 8,191
rem characters without a word, so a line that long (a path over about
rem 8,100 characters) would be missing from the log or the listing.
setlocal DisableDelayedExpansion
call :copy_variable %~1 robocopy_output_file
set "lines_written=0"
set "lines_total=0"
if not "%~2"=="append" type nul >"%robocopy_output_file%" 2>nul
set "robocopy_output_rewrite="
if "%~3"=="yes" set "robocopy_output_rewrite=1"
if not "%~4"=="" call :is_robocopy_exit_code_in_range %~4 || set "robocopy_output_rewrite=1"
set "robocopy_output_error_lines="
"%tool_find%" /c "(0x" <"%temp_robocopy_unicode_output%" >"%temp_count%" 2>nul
for /f "usebackq" %%N in ("%temp_count%") do set "robocopy_output_error_lines=%%N"
if not "%robocopy_output_error_lines%"=="0" set "robocopy_output_rewrite=1"
if not defined robocopy_output_rewrite (
    type "%temp_robocopy_unicode_output%" >>"%robocopy_output_file%" 2>nul
    goto save_robocopy_unicode_output_done
)
type "%temp_robocopy_unicode_output%" 2>nul | "%tool_find%" /c /v "" >"%temp_count%"
for /f "usebackq" %%N in ("%temp_count%") do set "lines_total=%%N"
type "%temp_robocopy_unicode_output%" 2>nul | "%tool_findstr%" /n "^" >"%temp_robocopy_numbered%"
(for /f "usebackq delims=" %%L in ("%temp_robocopy_numbered%") do (
    set /a "lines_written+=1"
    set "robocopy_output_line=%%L"
    setlocal EnableDelayedExpansion
    set "robocopy_output_line=!robocopy_output_line:*:=!"
    if defined robocopy_output_line if "!robocopy_output_line:~-1!"=="!carriage_return!" set "robocopy_output_line=!robocopy_output_line:~0,-1!"
    if "%~3"=="yes" if defined robocopy_output_line for %%R in ("!carriage_return!") do set "robocopy_output_line=!robocopy_output_line:%%~R=|!"
    if "%~3"=="yes" for /f "delims=|" %%A in ("#!robocopy_output_line!") do (
        endlocal
        set "robocopy_output_line=%%A"
        setlocal EnableDelayedExpansion
        set "robocopy_output_line=!robocopy_output_line:~1!"
    )
    echo(!robocopy_output_line!
    endlocal
)) >>"%robocopy_output_file%"
:save_robocopy_unicode_output_done
del "%temp_robocopy_unicode_output%" >nul 2>&1
endlocal & set "robocopy_output_lines_written=%lines_written%" & set "robocopy_output_lines_total=%lines_total%" & exit /b 0

:read_robocopy_summary  outputVar  [countFileVar]  [tailFileVar]
rem Robocopy's job summary from its output (the /unilog file converted to
rem the console's code page by TYPE, or robocopy's plain output): of the
rem rows after the last dashed rule, the first three that end in six
rem numbers are Dirs, Files and Bytes, taken in that order since their
rem labels are localised, and each row's last six words as its Total,
rem Copied, Skipped, Mismatch, FAILED and Extras columns, in that order,
rem whatever the language. The rows go to robocopy_summary_dirs_<column>,
rem robocopy_summary_files_<column> and robocopy_summary_bytes_<column>
rem (plain numbers: every pass and listing runs with /bytes). Exit 1 if the
rem output has no summary or a row isn't six numbers: the caller then has no
rem counts. Only the tail after the rule is read line by line (more +n), so
rem a listing of 100,000 lines costs no FOR /F per line. The two working
rem files (the rule's line number, the tail) are temp_count and
rem temp_robocopy_summary_tail unless named: the directory probe runs
rem before :init_run makes those (:confirm_directory_readable).
setlocal DisableDelayedExpansion
call :copy_variable %~1 summary_source_file
set "summary_count_file=%temp_count%"
set "summary_tail_file=%temp_robocopy_summary_tail%"
if not "%~2"=="" call :copy_variable %~2 summary_count_file
if not "%~3"=="" call :copy_variable %~3 summary_tail_file
for %%C in (total copied skipped mismatch failed extras) do set "summary_dirs_%%C=" & set "summary_files_%%C=" & set "summary_bytes_%%C="
set "summary_rule_line="
if exist "%summary_source_file%" "%tool_findstr%" /n /b /c:"-----" "%summary_source_file%" >"%summary_count_file%" 2>nul
if exist "%summary_source_file%" for /f "usebackq tokens=1 delims=:" %%N in ("%summary_count_file%") do set "summary_rule_line=%%N"
if not defined summary_rule_line (endlocal & exit /b 1)
rem <nul: MORE with a file argument still reads the rest of a redirected
rem standard input (round 14.8: the answers waiting there were lost).
"%tool_more%" +%summary_rule_line% "%summary_source_file%" >"%summary_tail_file%" 2>nul <nul
set "summary_number_rows=0"
for /f "usebackq tokens=*" %%L in ("%summary_tail_file%") do (
    set "summary_line=%%L"
    call :read_robocopy_summary_row
)
if not defined summary_dirs_total (endlocal & exit /b 1)
if not defined summary_files_total (endlocal & exit /b 1)
if not defined summary_bytes_total (endlocal & exit /b 1)
endlocal & set "robocopy_summary_dirs_total=%summary_dirs_total%" & set "robocopy_summary_dirs_copied=%summary_dirs_copied%" & set "robocopy_summary_dirs_skipped=%summary_dirs_skipped%" & set "robocopy_summary_dirs_mismatch=%summary_dirs_mismatch%" & set "robocopy_summary_dirs_failed=%summary_dirs_failed%" & set "robocopy_summary_dirs_extras=%summary_dirs_extras%" & set "robocopy_summary_files_total=%summary_files_total%" & set "robocopy_summary_files_copied=%summary_files_copied%" & set "robocopy_summary_files_skipped=%summary_files_skipped%" & set "robocopy_summary_files_mismatch=%summary_files_mismatch%" & set "robocopy_summary_files_failed=%summary_files_failed%" & set "robocopy_summary_files_extras=%summary_files_extras%" & set "robocopy_summary_bytes_total=%summary_bytes_total%" & set "robocopy_summary_bytes_copied=%summary_bytes_copied%" & set "robocopy_summary_bytes_skipped=%summary_bytes_skipped%" & set "robocopy_summary_bytes_mismatch=%summary_bytes_mismatch%" & set "robocopy_summary_bytes_failed=%summary_bytes_failed%" & set "robocopy_summary_bytes_extras=%summary_bytes_extras%"
exit /b 0

:read_robocopy_summary_row
rem Caller's scope (:read_robocopy_summary): one line of the summary's tail,
rem in summary_line. Only a row whose last six words are each one or more
rem digits counts (summary_number_rows): the first is Dirs, the second
rem Files and the third Bytes, into summary_<row>_<column>; the
rem column headings above them and the Times row below aren't numbers in
rem any language (round 14.7: counting every line took the headings for
rem Dirs, so Files got the Dirs counts and Bytes the file counts). With no
rem such rows the values stay empty, and the caller reports no summary.
if %summary_number_rows% geq 3 exit /b 0
setlocal EnableDelayedExpansion
for %%C in (1 2 3 4 5 6) do set "column_%%C="
set "summary_words=!summary_line!"
for /l %%I in (1,1,%RECORD_CELL_MAX_WORDS%) do if defined summary_words (
    for /f "tokens=1*" %%A in ("!summary_words!") do (
        set "column_1=!column_2!"
        set "column_2=!column_3!"
        set "column_3=!column_4!"
        set "column_4=!column_5!"
        set "column_5=!column_6!"
        set "column_6=%%A"
        set "summary_words=%%B"
    )
)
set "columns_bad="
for %%C in (1 2 3 4 5 6) do (
    if not defined column_%%C set "columns_bad=1"
    if defined column_%%C for /f "delims=0123456789" %%X in ("!column_%%C!") do set "columns_bad=1"
)
if defined columns_bad (endlocal & exit /b 0)
set /a "number_row=summary_number_rows+1"
set "row_name=dirs"
if %number_row% equ 2 set "row_name=files"
if %number_row% equ 3 set "row_name=bytes"
endlocal & set "summary_number_rows=%number_row%" & set "summary_%row_name%_total=%column_1%" & set "summary_%row_name%_copied=%column_2%" & set "summary_%row_name%_skipped=%column_3%" & set "summary_%row_name%_mismatch=%column_4%" & set "summary_%row_name%_failed=%column_5%" & set "summary_%row_name%_extras=%column_6%"
exit /b 0

:read_carriage_return
rem Set carriage_return to the CR character, for :save_robocopy_unicode_output
rem (COPY /Z prints its progress with a CR; the standard pure-batch way).
rem The file copied to nul is cmd.exe's own (ComSpec, never a path with
rem "%" in it): this script's path would go on a child cmd's command line.
set "carriage_return="
for /f %%C in ('copy /z "%ComSpec%" nul') do set "carriage_return=%%C"
exit /b 0

:report_robocopy_exit_code  exitCodeVar  [custody]
rem Explain each bit set in a robocopy exit code (see ROBOCOPY_EXIT_* in
rem CONFIG); anything but INFO is listed in the summary (:remember_problem).
rem With "custody" (a custody pass), extras (bit 2) are expected on a rerun
rem or update: the destination set holds its own run records and history,
rem which the source set doesn't; the Run records check verifies them all,
rem so they are reported as INFO, in full for the first custody pass that
rem has them and as "see above" after that (custody_extras_explained, in the
rem custody passes' scope).
setlocal EnableDelayedExpansion
set /a "robocopy_exit_code=!%~1!"
set "extras_explained_after=!custody_extras_explained!"
set "msg=Robocopy exit code: !robocopy_exit_code!" & call :show_and_log msg
call :is_robocopy_exit_code_in_range robocopy_exit_code || (
    set "msg=  [FAIL] Robocopy ended abnormally (exit code !robocopy_exit_code!): it was stopped or failed, so its exit code says nothing about what it copied, and its log above may be incomplete."
    call :show_and_log msg
    call :remember_problem msg
    endlocal & exit /b 0
)
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
        if defined custody_extras_explained set "text=Items in the destination set that the source set doesn't hold, left as they are (see above)."
    )
    if !bit_value! neq 0 (
        set "msg=  [!severity!] !text!"
        call :show_and_log msg
        if not "!severity!"=="INFO" call :remember_problem msg
        if "%~2"=="custody" if %%B equ 2 set "extras_explained_after=1"
    )
)
if "%~2"=="custody" (endlocal & set "custody_extras_explained=%extras_explained_after%" & exit /b 0)
endlocal & exit /b 0

:is_robocopy_exit_code_in_range  exitCodeVar
rem Exit 0 if the exit code is one of robocopy's own (0 to
rem ROBOCOPY_EXIT_CODE_HIGHEST), 1 if robocopy was stopped or failed.
setlocal EnableDelayedExpansion
set /a "code=!%~1!"
if !code! lss 0 (endlocal & exit /b 1)
if !code! gtr %ROBOCOPY_EXIT_CODE_HIGHEST% (endlocal & exit /b 1)
endlocal & exit /b 0

:add_decimal_strings  aVar  bVar  outVar
rem The sum of two numbers held as digit strings (byte counts past cmd's
rem 32-bit arithmetic), digit by digit from the right with a carry, up to 24
rem digits each; leading zeros off the result.
setlocal EnableDelayedExpansion
set "pad=000000000000000000000000"
set "a=!pad!!%~1!"
set "b=!pad!!%~2!"
set "a=!a:~-24!"
set "b=!b:~-24!"
set "carry=0"
set "sum="
for /l %%P in (23,-1,0) do (
    set /a "digit=!a:~%%P,1! + !b:~%%P,1! + carry"
    set /a "carry=digit / 10, digit=digit %% 10"
    set "sum=!digit!!sum!"
)
if !carry! gtr 0 set "sum=!carry!!sum!"
for /l %%I in (1,1,24) do if "!sum:~0,1!"=="0" if not "!sum:~1!"=="" set "sum=!sum:~1!"
endlocal & set "%~3=%sum%"
exit /b 0

:compare_decimal_strings  aVar  bVar  outVar
rem a against b, both digit strings: less, equal or greater. Leading zeros
rem off, then the longer is the greater, and of two the same length the
rem lexically greater (a letter in front keeps IF from reading them as
rem numbers, which would overflow).
setlocal EnableDelayedExpansion
set "a=!%~1!"
set "b=!%~2!"
for /l %%I in (1,1,24) do (
    if "!a:~0,1!"=="0" if not "!a:~1!"=="" set "a=!a:~1!"
    if "!b:~0,1!"=="0" if not "!b:~1!"=="" set "b=!b:~1!"
)
call :strlen a a_length
call :strlen b b_length
set "order=equal"
if !a_length! lss !b_length! set "order=less"
if !a_length! gtr !b_length! set "order=greater"
if "!order!"=="equal" if "x!a!" lss "x!b!" set "order=less"
if "!order!"=="equal" if "x!a!" gtr "x!b!" set "order=greater"
endlocal & set "%~3=%order%"
exit /b 0

:drop_last_digits  digitsVar  count
rem The digit string with its last count digits dropped (a division by a
rem power of ten, rounded down), "0" when nothing is left.
setlocal EnableDelayedExpansion
set "digits=!%~1!"
for /l %%I in (1,1,%~2) do if defined digits if "!digits:~1!"=="" (set "digits=0") else set "digits=!digits:~0,-1!"
if not defined digits set "digits=0"
endlocal & set "%~1=%digits%"
exit /b 0

:format_decimal_string  digitsVar  outVar
rem A digit string for a message: thousands separated by commas and, from
rem a million up, the same in MB or GB to one decimal in brackets, e.g.
rem "12,345,678,901 (12.3 GB)".
setlocal EnableDelayedExpansion
set "digits=!%~1!"
set "rest=!digits!"
set "grouped="
for /l %%I in (1,1,8) do if defined rest (
    if "!rest:~-3!"=="!rest!" (set "grouped=!rest!!grouped!" & set "rest=") else (set "grouped=,!rest:~-3!!grouped!" & set "rest=!rest:~0,-3!")
)
call :strlen digits digits_length
set "unit_text="
if !digits_length! gtr 9 set "unit_text= (!digits:~0,-9!.!digits:~-9,1! GB)"
if !digits_length! leq 9 if !digits_length! gtr 6 set "unit_text= (!digits:~0,-6!.!digits:~-6,1! MB)"
endlocal & set "%~2=%grouped%%unit_text%"
exit /b 0

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
rem With /yes-to-all the first choice answers (2.6.0), echoed as a typed
rem answer would be; the console is asked otherwise, as always.
if defined argument_yes_to_all for %%C in (%~2) do if not defined answer set "answer=%%C"
if defined argument_yes_to_all echo ^> !answer! ^(answered by /yes-to-all^)
if not defined argument_yes_to_all set /p "answer=> "
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
rem path is refused and asked again. Any character Windows allows in a path
rem is taken as it is ("%" included, since 2.5.0: no path goes on a child
rem command line any more). Exit 1 (with abort_reason) after
rem MAX_PROMPT_ATTEMPTS invalid answers. The option that answers this
rem prompt (2.6.0): /source for the source prompts, /destination for the
rem destination prompts and a relocation's new location. Given, it is
rem taken once in place of the prompt and echoed as the prompt would have
rem shown it; a refusal then stops the run (no one to ask again).
set "directory_attempts=0"
set "default_source_taken="
set "directory_argument_name="
if /i "%~1"=="source_given" set "directory_argument_name=argument_source"
if /i "%~1"=="source" set "directory_argument_name=argument_source"
if /i "%~1"=="destination_given" set "directory_argument_name=argument_destination"
if /i "%~1"=="destination" set "directory_argument_name=argument_destination"
if /i "%~1"=="relocate_target" set "directory_argument_name=argument_destination"
if defined directory_argument_name if not defined %directory_argument_name% set "directory_argument_name="
:ask_directory_loop
set /a "directory_attempts+=1"
if %directory_attempts% gtr %MAX_PROMPT_ATTEMPTS% (
    set "abort_reason=No valid directory after %MAX_PROMPT_ATTEMPTS% attempts (no console input?)."
    exit /b 1
)
set "normalise_path_input="
set "default_source_taken="
if defined directory_argument_name goto ask_directory_from_argument
if "%~4"=="1" if defined default_source_path (
    set "msg=Default (the script's directory): %default_source_path%"
    call :show msg
)
set /p "normalise_path_input=%~2: "
if not defined normalise_path_input if "%~4"=="1" if defined default_source_path (
    set "normalise_path_input=%default_source_path%"
    set "default_source_taken=1"
)
goto ask_directory_check
:ask_directory_from_argument
call :copy_variable %directory_argument_name% normalise_path_input
set "msg=%~2 (from the command line): %normalise_path_input%"
call :show msg
:ask_directory_check
rem Every refusal says why and leaves a blank line before the prompt comes
rem again (owner, 2026-10-20); with the answer from the command line it
rem stops the run instead.
call :normalise_path
if errorlevel 1 (
    echo Enter a full path: a drive letter and directory, or a UNC path.
    echo.
    if defined directory_argument_name set "abort_reason=The %~2 given on the command line isn't a full path." & if defined directory_argument_name exit /b 1
    goto ask_directory_loop
)
set "answer_is_directory="
call :is_directory normalise_path_result && set "answer_is_directory=1"
if exist "%normalise_path_result%" if not defined answer_is_directory (
    echo That is a file, not a directory.
    echo.
    if defined directory_argument_name set "abort_reason=The %~2 given on the command line is a file, not a directory." & if defined directory_argument_name exit /b 1
    goto ask_directory_loop
)
if "%~3"=="1" if not defined answer_is_directory (
    echo Directory not found.
    if defined is_elevated if "%normalise_path_result:~1,1%"==":" if not exist "%normalise_path_result:~0,2%\" (
        echo As administrator, drive letters mapped in your normal session are not
        echo   visible. For a network share, enter its UNC path: \\server\share\...
    )
    echo.
    if defined directory_argument_name set "abort_reason=The %~2 given on the command line was not found." & if defined directory_argument_name exit /b 1
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
rem The trailing backslashes go in a bounded loop, with delayed expansion
rem on inside it only (the value is a typed path: read with !var!, handed
rem back with delayed expansion off, so "!" and "%" in it survive).
setlocal EnableDelayedExpansion
for /l %%I in (1,1,%OUTPUT_MAX_INDENT%) do if "!normalise_path_result:~-1!"=="\" if not "!normalise_path_result:~-2!"==":\" if not "!normalise_path_result!"=="\" set "normalise_path_result=!normalise_path_result:~0,-1!"
endlocal & set "normalise_path_result=%normalise_path_result%"
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
if defined tool_wmic for /f "tokens=1,2 delims==" %%A in ('2^>nul "%tool_wmic%" path Win32_UTCTime get Day^,Hour^,Minute^,Month^,Second^,Year /value') do for /f %%C in ("%%B") do set "wmi_%%A=%%C"
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
for /f "tokens=1,2" %%A in ('2^>nul "%tool_robocopy%" "|" . /njh /r:0 /w:0') do if not defined local_digits (
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
for /f "tokens=3" %%V in ('2^>nul "%tool_reg%" query "HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" /v ActiveTimeBias ^| "%tool_find%" /i "ActiveTimeBias"') do set "bias=%%V"
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
rem Print a variable's value to the console only (not to the log), as free
rem text within OUTPUT_WIDTH (:emit_free_text).
call :emit_free_text %~1 console
exit /b 0

:show_and_log  msgVar
rem Print a variable's value to the console and, in log mode once the log
rem exists, append it to the log; free text within OUTPUT_WIDTH.
call :emit_free_text %~1 both
exit /b 0

:log_field  label  valueVar  [target]
rem Show and log "  label     : value" (labels 20 wide, the value from
rem column 25); a long value continues from column 26 (:emit_wrapped), a
rem word that can't fit there (a SHA-256) from column 5. The value never
rem leaves the label's line: the Script check reads the
rem "  Script SHA-256      : " line of a sealed log (contract). target:
rem console, log or both (the default).
setlocal EnableDelayedExpansion
set "padded_label=%~1                      "
set "field_line=  !padded_label:~0,20!: !%~2!"
set "field_continuation=!BLANKS:~0,25!"
set "field_long_word_start=!BLANKS:~0,4!"
set "field_target=%~3"
if not defined field_target set "field_target=both"
call :emit_wrapped field_line 24 field_continuation !field_target! field_long_word_start
endlocal & exit /b 0

:log_field_continued  valueVar  [target]
rem Show and log a further line of a field, starting at the value column
rem (25); a long one continues from column 26, a word that can't fit there
rem from column 5. target: console, log or both (the default).
setlocal EnableDelayedExpansion
set "field_line=!BLANKS:~0,24!!%~1!"
set "field_continuation=!BLANKS:~0,25!"
set "field_long_word_start=!BLANKS:~0,4!"
set "field_target=%~2"
if not defined field_target set "field_target=both"
call :emit_wrapped field_line 24 field_continuation !field_target! field_long_word_start
endlocal & exit /b 0

:write_section_heading  titleVar  target
rem Open a section (shared rule: scannable output): an empty line, a light
rem rule, the title. Titles start with the name the result block points to
rem (Script, Copy, Metadata, Run records, Hash (SHA-256), Record written).
rem target: console, log or both (:emit_line).
setlocal
set "section_line="
call :emit_line section_line %~2
set "section_line=%RULE_LIGHT%"
call :emit_line section_line %~2
call :emit_free_text %~1 %~2
endlocal & exit /b 0

:emit_free_text  textVar  target
rem Write free text (a sentence, a list item, a tagged line) within
rem OUTPUT_WIDTH: a longer line continues two columns right of where its
rem text starts (its own leading spaces plus two), never at the left edge.
setlocal EnableDelayedExpansion
set "free_text=!%~1!"
if not defined free_text goto emit_free_text_as_is
if "!free_text:~%OUTPUT_WIDTH%!"=="" goto emit_free_text_as_is
set "free_text_indent=0"
set "free_text_indent_counted="
for /l %%I in (0,1,%OUTPUT_MAX_INDENT%) do if not defined free_text_indent_counted (
    if "!free_text:~%%I,1!"==" " (set /a "free_text_indent+=1") else set "free_text_indent_counted=1"
)
set /a "free_text_continuation_width=free_text_indent + 2"
for %%I in (!free_text_continuation_width!) do set "free_text_continuation=!BLANKS:~0,%%I!"
call :emit_wrapped free_text !free_text_indent! free_text_continuation %~2
endlocal & exit /b 0
:emit_free_text_as_is
call :emit_line free_text %~2
endlocal & exit /b 0

:emit_wrapped  textVar  valueColumn  continuationVar  target  [longWordStartVar]
rem Write one line of output within OUTPUT_WIDTH characters (shared rule:
rem 80-character output), broken at spaces. The value starts at character
rem valueColumn (counted from 0) and never leaves the first line, so a break
rem comes only at a space after its first character. Each further line
rem starts with continuationVar's text (the hanging indent). A word longer
rem than the room left (a SHA-256, a path) stays whole: if longWordStartVar
rem is given and the word fits within OUTPUT_WIDTH after its (shorter) text,
rem the line starts with that instead, so an 80-column console doesn't
rem split the word back to column 1; otherwise it runs past the width. The
rem lines come off the text in a FOR /L (OUTPUT_MAX_WRAPPED_LINES at most;
rem a text that would need more ends with the rest on one line), one
rem :emit_wrapped_line each; never a goto loop (section 6).
setlocal EnableDelayedExpansion
set "remaining=!%~1!"
set "line_kind=first"
if not defined remaining goto emit_wrapped_last
if "!remaining:~%OUTPUT_WIDTH%!"=="" goto emit_wrapped_last
set "continuation=!%~3!"
call :strlen continuation continuation_length
set "long_word_start="
if not "%~5"=="" set "long_word_start=!%~5!"
if defined long_word_start call :strlen long_word_start long_word_start_length
set /a "earliest_break=%~2 + 1"
set "wrapping_done="
for /l %%S in (1,1,%OUTPUT_MAX_WRAPPED_LINES%) do if not defined wrapping_done call :emit_wrapped_line %~4
if not defined remaining (endlocal & exit /b 0)
:emit_wrapped_last
call :emit_line remaining %~4 !line_kind!
endlocal & exit /b 0

:emit_wrapped_line  target
rem Caller's scope, delayed expansion on (:emit_wrapped): write the next
rem line of the text, broken at the last space that fits (or the first
rem after the width, for a word longer than the room), and put the hanging
rem indent before what is left. Sets wrapping_done when the rest fits on
rem one line (the caller writes it), when nothing is left, or when there is
rem no space to break at.
if "!remaining:~%OUTPUT_WIDTH%!"=="" (
    set "wrapping_done=1"
    exit /b 0
)
set "break_at="
for /l %%I in (%OUTPUT_WIDTH%,-1,!earliest_break!) do if not defined break_at if "!remaining:~%%I,1!"==" " set "break_at=%%I"
if not defined break_at call :find_next_space remaining %OUTPUT_WIDTH% break_at
if not defined break_at (
    set "wrapping_done=1"
    exit /b 0
)
for %%B in (!break_at!) do (
    set "wrapped_line=!remaining:~0,%%B!"
    set "remaining=!remaining:~%%B!"
)
for /l %%T in (1,1,%OUTPUT_MAX_INDENT%) do if "!remaining:~0,1!"==" " set "remaining=!remaining:~1!"
call :emit_line wrapped_line %~1 !line_kind!
set "line_kind=continuation"
if not defined remaining (
    set "wrapping_done=1"
    exit /b 0
)
set "line_start=!continuation!"
set "line_start_length=!continuation_length!"
if defined long_word_start call :first_word_fits_only_after remaining !continuation_length! !long_word_start_length! && (
    set "line_start=!long_word_start!"
    set "line_start_length=!long_word_start_length!"
)
set "remaining=!line_start!!remaining!"
set /a "earliest_break=line_start_length + 1"
exit /b 0

:first_word_fits_only_after  textVar  continuationLength  longWordStartLength
rem Exit 0 if the text's first word doesn't fit within OUTPUT_WIDTH after
rem continuationLength characters but does after longWordStartLength
rem (:emit_wrapped). The space added at the end ends a text of one word.
setlocal EnableDelayedExpansion
set "words=!%~1! "
set /a "room_after_continuation=OUTPUT_WIDTH - %~2, room_after_long_word_start=OUTPUT_WIDTH - %~3"
set "first_word_length="
for /l %%I in (0,1,!room_after_long_word_start!) do if not defined first_word_length if "!words:~%%I,1!"==" " set "first_word_length=%%I"
if not defined first_word_length (endlocal & exit /b 1)
if !first_word_length! leq !room_after_continuation! (endlocal & exit /b 1)
endlocal & exit /b 0

:find_next_space  textVar  fromIndex  outVar
rem Caller's scope, delayed expansion on (:emit_wrapped_line). Set outVar
rem to the index of the first space at or after fromIndex, or clear it if
rem there is none (a long unbreakable value is then written whole). A FOR
rem /L over the text's characters (round 12.7: as a goto loop, 89 s for an
rem 8,100-character path; the workshop measured 34 s to 40 ms).
set "%~3="
call :strlen %~1 find_next_space_length
for /l %%P in (%~2,1,!find_next_space_length!) do if not defined %~3 if "!%~1:~%%P,1!"==" " set "%~3=%%P"
exit /b 0

:emit_line  lineVar  target  [lineKind]
rem The one place a finished line is written. target: console, log or both.
rem The console copy gets colour when :init_console_colour turned it on; the
rem log copy never does (records are plain text, sealed, compared byte for
rem byte). Lines reach the log only once it exists (log_ready) and until
rem it is sealed (log_sealed, :write_seal): a line after the seal would
rem change a sealed file (round 13: the certutil retry's notes during the
rem write-back's read-back went into the kept log). lineKind
rem "continuation" (:emit_wrapped's further lines) is never coloured: a
rem status starts a text, and a further line may hold the rest of an
rem evidence name. While the live display is active (from before the
rem header to after the pause, 2.8.0), the console copy is left out: the
rem header and the summary then reach the log alone, the display shows
rem the run's progress, and [WARN] and [FAIL] lines reach it through the
rem summary's lists; the log copy is written as always.
rem target "file": the line goes to the file emit_line_file_path names and
rem nowhere else (the summary's lists are kept wrapped: :remember_problem).
setlocal EnableDelayedExpansion
set "line=!%~1!"
if "%~2"=="file" (
    >>"!emit_line_file_path!" echo(!%~1!
    endlocal & exit /b 0
)
if "%~2"=="log" goto emit_line_to_log
if defined dashboard_active goto emit_line_to_log
if defined line if defined console_colour if not "%~3"=="continuation" call :colour_for_console line
echo(!line!
:emit_line_to_log
if "%~2"=="console" (endlocal & exit /b 0)
if defined log_ready if not defined log_sealed >>"!log_staged_path!" echo(!%~1!
endlocal & exit /b 0

:colour_for_console  lineVar
rem Caller's scope, delayed expansion on (:emit_line). Colour the status
rem words of a console line (COLOUR_* in CONFIG): the verdict bold, PASS
rem green, WARN and NOT RUN yellow, FAIL red, an [INFO] tag cyan. The words
rem themselves stay. Only where the layout puts a status, so the same words
rem in an evidence name ("[FAIL] x.txt", "PASSPORT.pdf") stay plain: a
rem [FAIL], [WARN] or [INFO] tag starting the line (column 1, or 3 and 5
rem in the Warnings and Failures lists), the verdict of the RESULT line,
rem the status starting a
rem result block row's value (column 29), and a status and colon starting
rem a field's value at column 25, on the field's own line or a detail line
rem below it (the Script field; Script copy, or the Reference record's seal
rem result, when they fail). The colon keeps a value that only starts with
rem the word (a host name) plain: names can't hold one.
set "colour_line=!%~1!"
if "!colour_line:~0,6!"=="[FAIL]" set "%~1=%coloured_fail_tag%!colour_line:~6!"
if "!colour_line:~0,8!"=="  [FAIL]" set "%~1=  %coloured_fail_tag%!colour_line:~8!"
if "!colour_line:~0,10!"=="    [FAIL]" set "%~1=    %coloured_fail_tag%!colour_line:~10!"
if "!colour_line:~0,6!"=="[WARN]" set "%~1=%coloured_warn_tag%!colour_line:~6!"
if "!colour_line:~0,8!"=="  [WARN]" set "%~1=  %coloured_warn_tag%!colour_line:~8!"
if "!colour_line:~0,10!"=="    [WARN]" set "%~1=    %coloured_warn_tag%!colour_line:~10!"
if "!colour_line:~0,6!"=="[INFO]" set "%~1=%coloured_info_tag%!colour_line:~6!"
if "!colour_line:~0,8!"=="  [INFO]" set "%~1=  %coloured_info_tag%!colour_line:~8!"
if "!colour_line:~0,10!"=="    [INFO]" set "%~1=    %coloured_info_tag%!colour_line:~10!"
if "!colour_line:~0,10!"=="  RESULT: " (
    set "%~1=!%~1:RESULT: PASS=RESULT: %coloured_verdict_pass%!"
    set "%~1=!%~1:RESULT: FAIL=RESULT: %coloured_verdict_fail%!"
    set "%~1=!%~1:RESULT: UNVERIFIED=RESULT: %coloured_verdict_unverified%!"
)
if "!colour_line:~0,6!"=="    |-" if "!colour_line:~26,2!"==": " (
    if "!colour_line:~28,4!"=="PASS" set "%~1=!colour_line:~0,28!%coloured_pass%!colour_line:~32!"
    if "!colour_line:~28,4!"=="FAIL" set "%~1=!colour_line:~0,28!%coloured_fail%!colour_line:~32!"
    if "!colour_line:~28,4!"=="WARN" set "%~1=!colour_line:~0,28!%coloured_warn%!colour_line:~32!"
    if "!colour_line:~28,7!"=="NOT RUN" set "%~1=!colour_line:~0,28!%coloured_not_run%!colour_line:~35!"
)
set "colour_field_value_line="
if "!colour_line:~0,2!"=="  " if "!colour_line:~22,2!"==": " set "colour_field_value_line=1"
if "!colour_line:~0,24!"=="!BLANKS:~0,24!" set "colour_field_value_line=1"
if defined colour_field_value_line (
    if "!colour_line:~24,5!"=="PASS:" set "%~1=!colour_line:~0,24!%coloured_pass%!colour_line:~28!"
    if "!colour_line:~24,5!"=="FAIL:" set "%~1=!colour_line:~0,24!%coloured_fail%!colour_line:~28!"
    if "!colour_line:~24,5!"=="WARN:" set "%~1=!colour_line:~0,24!%coloured_warn%!colour_line:~28!"
    if "!colour_line:~24,8!"=="NOT RUN:" set "%~1=!colour_line:~0,24!%coloured_not_run%!colour_line:~31!"
)
exit /b 0

:write_result_block  target
rem The run's result block (shared rule: scannable output): between two
rem heavy rules, the verdict, then each check in the order it ran, and the
rem warning and failure counts; a check that didn't pass names the section
rem and list that explain it. A wrapped value keeps the tree's "|" in column
rem 5 and continues from column 30. target: log (the copy sealed with the
rem log), console (the last thing on screen; in a forensic run, after the
rem record's write-back, with a row for it and a verdict that includes it,
rem and counts that include its warnings and failures) or file (the
rem console's form into emit_line_file_path: the watchdog's end-state
rem file, 2.8.0).
setlocal
set "block_target=%~1"
set "block_overall=%result_overall%"
if not "%block_target%"=="log" if "%run_mode%"=="forensic" set "block_overall=%final_result_overall%"
set "block_line=" & call :emit_line block_line %block_target%
set "block_line=%RULE_HEAVY%" & call :emit_line block_line %block_target%
set "block_line=  RESULT: %block_overall%" & call :emit_line block_line %block_target%
if "%run_mode%"=="forensic" call :write_check_row "Script" result_script %block_target%
call :write_check_row "Copy" result_copy %block_target%
call :write_check_row "Metadata" result_metadata %block_target%
if "%run_mode%"=="forensic" call :write_check_row "Run records" result_run_records %block_target%
call :write_check_row "Hash (SHA-256)" result_hash %block_target% result_hash_detail
if not "%block_target%"=="log" if "%run_mode%"=="forensic" call :write_check_row "Record written" result_record_written %block_target%
set "block_line=" & call :emit_line block_line %block_target%
call :count_summary_list warnings block_warning_count
call :count_summary_list failures block_failure_count
set "block_warnings=%block_warning_count%"
set "block_failures=%block_failure_count%"
if %block_warning_count% equ 0 set "block_warnings=none"
if %block_failure_count% equ 0 set "block_failures=none"
rem Where the lists are: above the block in the log, the plain output and
rem a non-forensic run; in the log alone after a forensic run's display
rem (2.8.1, round 15.3: since 2.8.0 its summary goes to the log only, so
rem the normal screen and the watchdog's end-state file have none above).
set "block_lists_place=listed above"
if not "%block_target%"=="log" if "%run_mode%"=="forensic" if "%dashboard_mode%"=="live" set "block_lists_place=listed in the log"
set "block_line=  Warnings: %block_warnings%, Failures: %block_failures% (%block_lists_place%)"
if %block_warning_count% equ 0 if %block_failure_count% equ 0 set "block_line=  Warnings: none, Failures: none"
call :emit_line block_line %block_target%
set "block_line=%RULE_HEAVY%" & call :emit_line block_line %block_target%
endlocal & exit /b 0

:write_check_row  label  valueVar  target  [detailPrefix]
rem One check in the result block: "    |-label : value" (labels 20 wide, the
rem value from column 29), a long value continued from column 30 behind the
rem tree's "|", a word that can't fit there from column 9. With
rem detailPrefix, the lines <detailPrefix>_1 to _<detailPrefix>_count
rem follow, one item per line from column 29 (a list is laid out, not
rem wrapped).
setlocal EnableDelayedExpansion
set "padded_label=%~1                      "
set "row_line=    |-!padded_label:~0,20!: !%~2!"
set "row_continuation=    |!BLANKS:~0,24!"
set "row_long_word_start=    |!BLANKS:~0,3!"
call :emit_wrapped row_line 28 row_continuation %~3 row_long_word_start
if "%~4"=="" (endlocal & exit /b 0)
set "row_detail_count=!%~4_count!"
if not defined row_detail_count set "row_detail_count=0"
for /l %%D in (1,1,!row_detail_count!) do (
    set "row_line=    |!BLANKS:~0,23!!%~4_%%D!"
    call :emit_wrapped row_line 28 row_continuation %~3 row_long_word_start
)
endlocal & exit /b 0

:count_summary_list  kind  outVar
rem The number of lines in the summary's warnings or failures list; after
rem the write-back, with the write-back's (:show_write_back_problem).
setlocal
if "%~1"=="failures" (set "list_path=%temp_summary_failures%") else set "list_path=%temp_summary_warnings%"
set "list_count=0"
if exist "%list_path%" for /f "usebackq delims=" %%L in ("%list_path%") do set /a "list_count+=1"
endlocal & set "%~2=%list_count%"
exit /b 0

:add_hash_detail  text
rem Caller's scope (:work_out_verification_status): one more line of the
rem Hash check's detail list (result_hash_detail_<n>).
set /a "result_hash_detail_count+=1"
set "result_hash_detail_%result_hash_detail_count%=%~1"
exit /b 0

:remember_problem  msgVar
rem Remember a [FAIL] or [WARN] line for the summary: [FAIL] lines (anything
rem that fails the run) go to its Failures list, all others to its Warnings
rem list. Leading spaces are dropped. Each line is kept twice: as it is
rem (the lists' counts, the live display's last lines) and wrapped as the
rem summary lays it out (:keep_summary_line), so the summary replays the
rem lists from a file (:log_summary_list) rather than wrapping every line
rem again through four helpers (round 12.4: about 50,000 failures were still
rem being listed 56 minutes in).
setlocal EnableDelayedExpansion
set "line=!%~1!"
for /l %%T in (1,1,%OUTPUT_MAX_INDENT%) do if "!line:~0,1!"==" " set "line=!line:~1!"
set "list_kind=warnings"
if not "!line:[FAIL]=!"=="!line!" set "list_kind=failures"
call :keep_summary_line line !list_kind!
endlocal & exit /b 0

:keep_summary_line  lineVar  kind
rem Caller's scope, delayed expansion on (:remember_problem, :add_warning):
rem append the line to the summary's list of its kind (warnings or
rem failures) as it is, and to the list's wrapped file as the summary shows
rem it: four columns in, continued at six (:emit_free_text with the file
rem target), once the run's working files exist.
>>"!temp_summary_%~2!" echo(!%~1!
set "emit_line_file_path=!temp_summary_%~2_wrapped!"
if not defined emit_line_file_path exit /b 0
set "summary_wrapped_line=    !%~1!"
call :emit_free_text summary_wrapped_line file
exit /b 0

:log_summary_list  title  kind
rem Show and log a titled list for the summary, one item per line, or
rem "none". kind is "warnings" or "failures". The lines come wrapped from
rem the list's file (:keep_summary_line): the log takes the file in one
rem TYPE, the console a plain loop that colours the tag at column 5 ([WARN]
rem or [FAIL], as :colour_for_console colours it; a continuation line starts
rem with spaces and gets none), with delayed expansion off, so a "!" in an
rem evidence name stays. The lists are read as :emit_line writes them: not
rem to the console while the live display is active.
setlocal DisableDelayedExpansion
set "list_path=%temp_summary_warnings%"
set "wrapped_path=%temp_summary_warnings_wrapped%"
if "%~2"=="failures" set "list_path=%temp_summary_failures%"
if "%~2"=="failures" set "wrapped_path=%temp_summary_failures_wrapped%"
set "msg=  %~1"
call :show_and_log msg
set "item_count=0"
if exist "%list_path%" for /f "usebackq delims=" %%L in ("%list_path%") do set /a "item_count+=1"
if %item_count% equ 0 (
    set "msg=    none"
    call :show_and_log msg
    endlocal & exit /b 0
)
if defined log_ready if exist "%wrapped_path%" type "%wrapped_path%" >>"%log_staged_path%" 2>nul
if defined dashboard_active (endlocal & exit /b 0)
if exist "%wrapped_path%" for /f "usebackq delims=" %%L in ("%wrapped_path%") do (
    set "list_line=%%L"
    call :echo_list_line
)
endlocal & exit /b 0

:echo_list_line
rem Caller's scope (:log_summary_list): one wrapped list line, in
rem list_line, to the console, its tag coloured when colour is on.
setlocal EnableDelayedExpansion
set "line=!list_line!"
if defined console_colour (
    if "!line:~4,6!"=="[WARN]" set "line=    %coloured_warn_tag%!line:~10!"
    if "!line:~4,6!"=="[FAIL]" set "line=    %coloured_fail_tag%!line:~10!"
)
echo(!line!
endlocal & exit /b 0

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

:list_directory  switches  pathVar  outFileVar
rem Write DIR's listing of a directory to a file, for a FOR /F to read with
rem usebackq (the FOR /F rework, 2.5.0): DIR runs here, in this cmd, with
rem its output redirected, so the path is expanded once and "%" in it stays
rem text. In a FOR /F command it went to a child cmd, which expands %NAME%
rem in its command line (test runner round 6: "x %OS% y" became "x
rem Windows_NT y"), the reason paths with "%" were refused until 2.5.0.
rem Delayed expansion is off throughout, so "!" stays too. switches: DIR's
rem (e.g. "/b /a"); the path as the variable holds it (a trailing backslash
rem where the caller wants the directory's contents, or a wildcard in its
rem last part). Exit 0 once the directory is known to have been read; exit
rem 1, the file emptied, when the file couldn't be written or the directory
rem couldn't be listed (access denied, missing, a device gone). DIR's own
rem exit code is 1 for an empty directory and for one it can't read alike,
rem and its message goes to nul, so until 2.8.0 a directory that couldn't
rem be listed read as empty (the GPT 6.1 review's finding 3, 2026-10-24: a
rem run record directory that denied listing passed its seal check with an
rem unsealed file in it). :confirm_directory_readable decides, on
rem probeDirVar when given (the directory a wildcard path searches), else
rem on the path itself: DIR's own exit code, and a list-only robocopy
rem where DIR found nothing. It probes again after the listing (2.8.2, the
rem GPT 6.1 review of 2.8.1, finding 3), so a directory lost while DIR
rem listed it (a device gone, access removed) is exit 1 too, not a short
rem listing; DIR's exit code can't tell it (1 also when the switches
rem match nothing there, e.g. /a-d among directories). A caller that gets
rem exit 1 fails or refuses; it never reads the empty file as "nothing
rem there".
setlocal DisableDelayedExpansion
call :copy_variable %~2 list_directory_path
call :copy_variable %~3 list_directory_file
set "list_directory_probe=%list_directory_path%"
if not "%~4"=="" call :copy_variable %~4 list_directory_probe
(type nul >"%list_directory_file%") 2>nul || (endlocal & exit /b 1)
call :confirm_directory_readable list_directory_probe || (endlocal & exit /b 1)
dir %~1 "%list_directory_path%" >"%list_directory_file%" 2>nul
call :confirm_directory_readable list_directory_probe || ((type nul >"%list_directory_file%") 2>nul & endlocal & exit /b 1)
endlocal & exit /b 0

:confirm_directory_readable  directoryVar
rem Exit 0 once the directory is known to have been read by DIR, or known
rem to hold nothing; exit 1 otherwise. Two stages (round 14.7's probe):
rem 1. "dir /a /b" of the directory, its output to nul. Exit code 0 means
rem    DIR enumerated it (an empty directory counts: its "." and ".."
rem    entries are found, though /b doesn't print them), so the listing
rem    the caller makes next is what DIR could read. Exit code 1 means
rem    DIR found no entry at all: the directory is missing, denies
rem    listing, or is a drive root with nothing in it (roots have no "."
rem    entry). DIR never takes backup semantics, elevated or not.
rem 2. Then a list-only robocopy of the directory (DIRECTORY_PROBE_FLAGS:
rem    the directory and one level below, no file or directory lines,
rem    the job summary kept), without /b. A missing directory, a device
rem    that is gone, or a directory denied to a run that isn't elevated
rem    gives an "(0x" error line and exit code 16: exit 1. Otherwise the
rem    summary decides: Dirs 1 (the directory itself) and Files 0 means
rem    nothing is there, exit 0; anything more means robocopy reads what
rem    DIR can't (an elevated run: robocopy takes backup semantics
rem    itself, /b or not, while DIR never does; round 14.7, where the
rem    probe was robocopy alone and passed on every denied directory
rem    elevated), so exit 1: the caller reports a directory that can be
rem    copied but not checked. A summary that can't be read is exit 1.
rem Stage 2 runs only where DIR found nothing, so a run pays a robocopy
rem start (about 50 ms) for an empty drive root or a denied directory,
rem not per listing. The path goes to robocopy from this cmd, so "%" and
rem "!" in it stay (section 6 of the conventions); the trailing space
rem inside the quotes keeps a drive root's "\" from escaping them; the
rem destination named never exists (robocopy /l creates nothing). Output
rem to files of its own (temp_directory_probe and its _count and _tail
rem files, made before the prompts: the set rules list directories
rem before :init_run); a file that can't be written fails the probe, so a
rem failed redirection's exit code 1 can't pass as robocopy's.
setlocal EnableDelayedExpansion
set "probe_directory=!%~1!"
dir /a /b "!probe_directory!" >nul 2>nul && (endlocal & exit /b 0)
set "probe_passed="
(type nul >"!temp_directory_probe!") 2>nul || (endlocal & exit /b 1)
"%tool_robocopy%" "!probe_directory! " "!temp_directory_probe!_nonexistent" *.* !DIRECTORY_PROBE_FLAGS! >"!temp_directory_probe!" 2>&1
set "probe_exit_code=!errorlevel!"
if !probe_exit_code! lss 8 call :is_robocopy_exit_code_in_range probe_exit_code && set "probe_passed=1"
"%tool_findstr%" /l /c:"(0x" "!temp_directory_probe!" >nul 2>&1 && set "probe_passed="
if not defined probe_passed (endlocal & exit /b 1)
call :read_robocopy_summary temp_directory_probe temp_directory_probe_count temp_directory_probe_tail || (endlocal & exit /b 1)
if not "!robocopy_summary_dirs_total!"=="1" (endlocal & exit /b 1)
if not "!robocopy_summary_files_total!"=="0" (endlocal & exit /b 1)
endlocal & exit /b 0

:init_listing_file
rem The working file the directory listings go to (:list_directory), made
rem before the prompts: the set rules list directories to tell a set from
rem raw evidence. Without a temporary directory nothing can be listed
rem safely, so the run stops here (before 2.5.0 it stopped at :init_run,
rem after the prompts, for the same reason). Deleted with the run's other
rem working files (:cleanup_temp). The second file takes the output of the
rem list-only robocopy that confirms a directory was read
rem (:confirm_directory_readable); its _count and _tail files are the
rem summary reader's working files for it (:read_robocopy_summary).
call :choose_temp_dir || exit /b 1
set "temp_directory_listing=%temp_dir%\%TOOL_NAME%_listing_%RANDOM%.tmp"
set "temp_directory_probe=%temp_dir%\%TOOL_NAME%_probe_%RANDOM%.tmp"
set "temp_directory_probe_count=%temp_directory_probe%.count"
set "temp_directory_probe_tail=%temp_directory_probe%.tail"
set "temp_update_check=%temp_dir%\%TOOL_NAME%_update_check_%RANDOM%.tmp"
set "temp_update_check_done=%temp_update_check%.done"
exit /b 0

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
for /l %%I in (1,1,%CONFIG_LIST_MAX_ITEMS%) do if defined each_item_rest call :each_item_next %~2
exit /b 0

:each_item_next  callback
rem Caller's scope (:each_item, delayed expansion off): take the next item
rem off each_item_rest and call the callback with it (a CALL per item, with
rem the item read fresh by this line's own expansion).
set "each_item_current="
for /f "tokens=1* delims=|" %%A in ("%each_item_rest%") do (
    set "each_item_current=%%A"
    set "each_item_rest=%%B"
)
if not defined each_item_current set "each_item_rest="
if defined each_item_current call :%~1 "%each_item_current%"
exit /b 0

:cleanup_temp
rem Delete this run's temporary files; a failed delete never stops the run.
setlocal EnableDelayedExpansion
for %%T in (temp_file_list temp_metadata_list temp_custody_copy temp_custody_copy_second temp_listing_numbered temp_listing_line temp_robocopy_unicode_output temp_robocopy_summary temp_robocopy_summary_tail temp_free_space temp_update_check temp_update_check_done temp_certutil_output temp_hash_rows_source temp_hash_rows_destination temp_hash_rows_custody temp_custody_list temp_compare_lines temp_compare_lines_sorted temp_summary_warnings temp_summary_failures temp_warnings temp_clock_status temp_housekeeping_source temp_housekeeping_destination temp_history_runs temp_history_lines temp_history_filled temp_outside_history temp_partial_warned temp_predating_records temp_sealed_history_source temp_sealed_history_destination temp_count temp_dashboard_pass temp_dashboard_lock temp_dashboard_helper_done temp_dashboard_lists temp_dashboard_count temp_dashboard_list_tail temp_dashboard_copy_tail temp_dashboard_started_lines temp_dashboard_error_lines temp_dashboard_size temp_dashboard_environment temp_dashboard_header_sections temp_dashboard_header_sections_raw temp_dashboard_watch_lock temp_dashboard_watch_end temp_dashboard_watch_done temp_dashboard_closing temp_dashboard_closing_raw temp_copy_pass_listing temp_directory_listing temp_directory_probe temp_directory_probe_count temp_directory_probe_tail temp_record_files_listing temp_record_files_expected temp_history_numbered temp_history_numbered_second temp_record_match temp_robocopy_numbered temp_link_listing temp_summary_warnings_wrapped temp_summary_failures_wrapped plain_hash_csv_source plain_hash_csv_destination) do (
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
rem TEMP and its path is shown. The reason is shown once, in a result block
rem (shared rule: scannable output), in the log too if there is one; a log
rem stopped before its header gets the fields known so far
rem (:write_abort_header).
call :dashboard_stop
if defined log_ready if not defined header_written call :write_abort_header
set "abort_target=console"
if defined log_ready set "abort_target=both"
set "block_line=" & call :emit_line block_line %abort_target%
set "block_line=%RULE_HEAVY%" & call :emit_line block_line %abort_target%
set "block_line=  RESULT: FAIL (exit code %EXIT_CODE_FAIL%)" & call :emit_line block_line %abort_target%
call :write_check_row "Run aborted" abort_reason %abort_target%
set "block_line=%RULE_HEAVY%" & call :emit_line block_line %abort_target%
if defined log_ready (
    set "msg=The log of this aborted run is kept here: %log_staged_path%"
    call :show msg
)
call :cleanup_temp
call :restore_console_code_page
if not defined argument_nopause pause
exit /b %EXIT_CODE_FAIL%

rem -- Live display (the dashboard) -------------------------------------------
rem Console only; forensic runs, and non-forensic runs since 2.7.0 (the
rem same screen; the rows a non-forensic run has nothing for read NONE:
rem :dashboard_set_rows_without_records). From :dashboard_start (after
rem the header) to
rem :dashboard_finish (before the summary) the console is switched to its
rem alternate screen (2.6.0; the header stays on the normal screen, where
rem the summary follows it after the switch back) and the whole screen is
rem redrawn there for the window as it is: the progress block (the result
rem block's checks with a status or a bar, the item in hand, the last
rem failures and warnings; the summary lists them all), and above it, when
rem the window has the rows, the header's Source and Destination sections
rem and the environment (:dashboard_layout). While it is active, lines the
rem run writes to the console go to the log alone (:emit_line). The display
rem reads the run's counters and never changes a check, a record or the exit
rem code; a value it can't read shows as starting or unknown, never as done.
rem Mode (dashboard_mode): live where the console takes VT sequences
rem (:init_console_vt) and EVIDENCE_ROBOCOPY_PLAIN isn't set, off otherwise
rem (the plain output). A watchdog, a second instance of this script,
rem switches the console back if the run dies in the alternate screen
rem (:dashboard_watchdog_main). The section sits at the end of the file on
rem purpose: cmd finds a label by scanning forward from the caller and
rem wrapping, so helpers placed above the per-file loops would slow every
rem call those loops make (workshop, 2026-10-18); the loops call only
rem :dashboard_tick, every DASHBOARD_TICK_EVERY_ITEMS items (the hash
rem loop also every DASHBOARD_TICK_EVERY_CONTENT_UNITS of content).

:init_dashboard
rem Decide the mode and give every display variable its starting value.
set "dashboard_mode=off"
set "dashboard_active="
set "dashboard_last_redraw=0"
set "dashboard_tick_count=0"
set "dashboard_tick_content_units=0"
set "dashboard_copy_detail="
set "dashboard_copy_error_text="
set "dashboard_hash_detail="
for %%S in (%DASHBOARD_STAGES%) do set "dashboard_%%S_text=waiting"
for %%S in (%DASHBOARD_STAGES%) do set "dashboard_%%S_bar="
set "dashboard_result_text=pending"
set "dashboard_paused="
set "dashboard_final_frame="
set "dashboard_closing_lines=0"
set "run_history_current_failed="
set "console_window_rows=unknown"
set "console_window_columns=unknown"
set "dashboard_static_columns="
set "dashboard_environment_lines=0"
set "dashboard_header_sections_lines=0"
set "dashboard_stop_state_text="
set "dashboard_stop_record_text="
set "dashboard_title_text=Progress (the header and the summary are in the log)"
set "dashboard_lists_rest_text=all in the log"
if "%run_mode%"=="nonforensic" set "dashboard_title_text=Progress (console only; no log and no records: /nonforensic)"
if "%run_mode%"=="nonforensic" set "dashboard_lists_rest_text=all in the summary that follows"
rem The redraw interval (2.7.0): CONFIG's, or /redraw's for this run; the
rem loops' redraws (:dashboard_tick) and the copy helper's reads of
rem robocopy's log (:dashboard_helper_main) follow it; the header's
rem Progress field states it.
set "redraw_interval_centiseconds=%DASHBOARD_REDRAW_CENTISECONDS%"
set "copy_progress_poll_seconds=%DASHBOARD_POLL_SECONDS%"
if defined argument_redraw_seconds set /a "redraw_interval_centiseconds=argument_redraw_seconds * 100, copy_progress_poll_seconds=argument_redraw_seconds"
set /a "redraw_interval_seconds=redraw_interval_centiseconds / 100"
rem The bar and rule strings for the widest window (2.6.0: a bar and a rule
rem fill the row's width): the CONFIG strings doubled five and three times
rem (1,088 and 632 columns), cut to the width at each layout.
setlocal EnableDelayedExpansion
set "bar_full=%DASHBOARD_BAR_FULL%"
set "bar_empty=%DASHBOARD_BAR_EMPTY%"
set "rule=%RULE_LIGHT%"
for /l %%I in (1,1,5) do set "bar_full=!bar_full!!bar_full!" & set "bar_empty=!bar_empty!!bar_empty!"
for /l %%I in (1,1,3) do set "rule=!rule!!rule!"
endlocal & set "dashboard_bar_full_text=%bar_full%" & set "dashboard_bar_empty_text=%bar_empty%" & set "dashboard_rule_text=%rule%"
if not defined console_vt exit /b 0
if defined EVIDENCE_ROBOCOPY_PLAIN exit /b 0
rem The display lays itself out for the window at every redraw (2.6.0), in
rem the console's alternate screen, so no size keeps it off: a window
rem smaller than DASHBOARD_MIN_WINDOW_COLUMNS x _ROWS shows one line saying
rem so until it is made larger (:dashboard_layout).
set "dashboard_mode=live"
exit /b 0

:dashboard_start
rem Switch the console to its alternate screen (2.6.0: no scrollback to
rem re-wrap, so the display lays itself out for the window at every
rem redraw), hide the cursor, and start the watchdog that switches back if
rem the run dies (:dashboard_watchdog_main, a second instance of this
rem script started as the display helper is, with Ctrl+C ignored; what a
rem stop leaves, by kind, is worded here for it). Since 2.8.0 (owner,
rem 2026-10-24: the display stands in for the console output) this comes
rem before the header, which then reaches the log alone; MAIN draws the
rem first frame (:dashboard_redraw) once the header's variables are set:
rem the Script check's result, the run records as checked before the copy,
rem every other stage waiting, the RESULT pending.
if not "%dashboard_mode%"=="live" exit /b 0
set "dashboard_active=1"
set "dashboard_static_columns="
set "dashboard_stop_state_text=What was copied before the stop is in the destination, unverified: %destination_with_backslash%"
if "%run_kind%"=="check" set "dashboard_stop_state_text=Nothing in the set was changed."
if "%run_kind%"=="relocate" set "dashboard_stop_state_text=The set was moved to %relocate_target_path% before the stop and is unverified there."
set "dashboard_stop_record_text=No run record was written. %dashboard_stop_state_text% The log as far as it got is kept here: %log_staged_path%"
if "%run_mode%"=="nonforensic" set "dashboard_stop_record_text=%dashboard_stop_state_text% Nothing is kept (no log and no records: /nonforensic); the run's working files in TEMP are removed."
del "%temp_dashboard_watch_end%" >nul 2>&1
set "evidence_robocopy_display_watchdog=%temp_path_prefix%"
set "evidence_robocopy_display_watchdog_script=%script_path%"
start "" /b "%ComSpec%" /d /v:off /c ""%%evidence_robocopy_display_watchdog_script%%""
set "evidence_robocopy_display_watchdog="
set "evidence_robocopy_display_watchdog_script="
set "dashboard_script_text=%result_script%"
rem A check or a relocation copies nothing and compares no metadata: its
rem Copy and Metadata rows read NONE from the first frame (round 14: they
rem read "waiting" until the next).
if not "%run_kind%"=="copy" (
    call :work_out_copy_status
    call :work_out_metadata_status
)
if not "%run_kind%"=="copy" (
    set "dashboard_copy_text=%result_copy%"
    set "dashboard_metadata_text=%result_metadata%"
)
rem A non-forensic run (2.7.0) has no script check, no run records and no
rem record to write, and verifies only when asked: those rows say so from
rem the first frame.
if "%run_mode%"=="nonforensic" call :dashboard_set_rows_without_records
call :dashboard_set_highlights
<nul set /p "=%escape_character%[?1049h%escape_character%[?25l"
exit /b 0

:dashboard_set_highlights
rem (:dashboard_start) The values the display colours (DASHBOARD_HIGHLIGHTS,
rem 2.7.0): for each item whose raised variable is defined, the colour
rem sequence into dashboard_colour_<shown variable>, read by the cell and
rem column builders (:dashboard_build_environment,
rem :dashboard_emit_field_pair). None without colour (NO_COLOR, no VT).
rem Warnings are raised before the display starts (the header's Warnings),
rem so this runs once.
set "dashboard_colour_warn_start=%escape_character%[%COLOUR_WARN%m"
set "dashboard_colour_info_start=%escape_character%[%COLOUR_INFO%m"
if not defined console_colour exit /b 0
for %%H in (%DASHBOARD_HIGHLIGHTS%) do for /f "tokens=1-3 delims=:" %%A in ("%%H") do if defined %%A (
    if "%%C"=="warn" set "dashboard_colour_%%B=%escape_character%[%COLOUR_WARN%m"
    if "%%C"=="info" set "dashboard_colour_%%B=%escape_character%[%COLOUR_INFO%m"
)
exit /b 0

:dashboard_set_rows_without_records
rem (:dashboard_start, :dashboard_finish) A non-forensic run's rows that
rem have nothing to show (2.7.0): no script check (no earlier record to
rem check against), no run records, no record written; and the Metadata
rem and Hash rows as the result block words them when verification wasn't
rem chosen (:work_out_result: NOT RUN).
set "dashboard_script_text=NONE: nothing to check against (/nonforensic)"
set "dashboard_run_records_text=NONE: no run records (/nonforensic)"
set "dashboard_record_written_text=NONE: no record written (/nonforensic)"
if not "%verification_enabled%"=="1" set "dashboard_metadata_text=NOT RUN: verification was not requested"
if not "%verification_enabled%"=="1" set "dashboard_hash_text=NOT RUN: verification was not requested"
exit /b 0

:dashboard_stage  stage  textVar
rem Show a stage with a plain status (the variable's text: fixed words and
rem counts, never a path) and redraw.
if not defined dashboard_active exit /b 0
call :copy_variable %~2 dashboard_%~1_text
set "dashboard_%~1_bar="
call :dashboard_redraw
exit /b 0

:dashboard_stage_result  stage  textVar
rem Show a stage's result (the result block's text for it) and redraw; its
rem detail lines go (round 12.4: the copy's last progress stayed under
rem "Copy : PASS" to the end).
if not defined dashboard_active exit /b 0
call :dashboard_clear_details %~1
call :dashboard_stage %~1 %~2
exit /b 0

:dashboard_clear_details  stage
rem Clear the variables of a stage's detail lines (DASHBOARD_STAGE_<stage>_
rem DETAILS); the redraw shows them empty.
setlocal EnableDelayedExpansion
set "details=!DASHBOARD_STAGE_%~1_DETAILS!"
endlocal & set "dashboard_clear_details_names=%details%"
if defined dashboard_clear_details_names for %%D in (%dashboard_clear_details_names%) do set "%%D="
exit /b 0

:dashboard_stage_bar  stage  doneVar  totalVar
rem Show a stage as a bar: done of total, read from the named counters at
rem every redraw (a total not known yet shows as starting), with the time
rem since now.
if not defined dashboard_active exit /b 0
set "dashboard_%~1_bar=1"
set "dashboard_%~1_done_var=%~2"
set "dashboard_%~1_total_var=%~3"
call :dashboard_read_clock dashboard_%~1_started
call :dashboard_redraw
exit /b 0

:dashboard_finish
rem After every check (:work_out_result): each stage shows its result block
rem text, once more; the RESULT stays pending and Record written says the
rem record is being written, until :dashboard_finish_run after the
rem write-back (2.8.0; the display stays on through it).
if not defined dashboard_active exit /b 0
for %%S in (%DASHBOARD_STAGES%) do set "dashboard_%%S_bar="
set "dashboard_script_text=%result_script%"
set "dashboard_copy_text=%result_copy%"
set "dashboard_metadata_text=%result_metadata%"
set "dashboard_run_records_text=%result_run_records%"
set "dashboard_hash_text=%result_hash%"
set "dashboard_record_written_text=writing the record"
if "%run_mode%"=="nonforensic" call :dashboard_set_rows_without_records
for %%S in (%DASHBOARD_STAGES%) do call :dashboard_clear_details %%S
call :dashboard_redraw
exit /b 0

:dashboard_finish_run
rem The display's last frame (2.8.0; owner, 2026-10-24: the display stands
rem in for the console output), after the record's write-back: the RESULT
rem row gets the final verdict (the console block's; a non-forensic run's
rem the checks'), Record written its row, the lists' headings say how many
rem lines aren't shown, and a forensic run's closing lines (the seal's
rem SHA-256 and the log's location, :show_closing_lines) come under the
rem block (:dashboard_build_closing_lines); the History row's "current"
rem turns red when the run has failed (the static parts are rebuilt). The
rem frame stays on the alternate screen through the pause (none with
rem /nopause), so the analyst reads it there; then the console goes back to
rem the normal screen, where MAIN prints the result block and the closing
rem lines (that screen has a scrollback). Before the pause the plain text
rem of that end goes to temp_dashboard_watch_done for the watchdog: a
rem Ctrl+C at the pause then shows it on the normal screen rather than
rem "no run record was written", and the watchdog removes this run's
rem working files, which the pause would have left in TEMP.
if not defined dashboard_active exit /b 0
set "dashboard_result_text=%result_overall%"
if "%run_mode%"=="forensic" set "dashboard_result_text=%final_result_overall%"
if "%run_mode%"=="forensic" set "dashboard_record_written_text=%result_record_written%"
if "%run_mode%"=="nonforensic" call :dashboard_set_rows_without_records
set "run_history_current_failed="
if "%dashboard_result_text:~0,4%"=="FAIL" set "run_history_current_failed=1"
if defined run_history_current_failed set "dashboard_static_columns="
set "dashboard_final_frame=1"
set "dashboard_closing_lines=0"
type nul >"%temp_dashboard_closing%"
if "%run_mode%"=="forensic" call :dashboard_build_closing_lines
type nul >"%temp_dashboard_watch_done%"
set "emit_line_file_path=%temp_dashboard_watch_done%"
call :write_result_block file
if "%run_mode%"=="forensic" call :show_closing_lines file
set "emit_line_file_path="
call :dashboard_redraw
if not defined argument_nopause pause
if not defined argument_nopause set "dashboard_paused=1"
call :dashboard_leave_screen
exit /b 0

:dashboard_build_closing_lines
rem (:dashboard_finish_run) A forensic run's closing lines for the last
rem frame: a blank line, then :show_closing_lines' lines, written plain
rem into temp_dashboard_closing_raw and taken over into
rem temp_dashboard_closing erased-and-written and cut to the window's
rem width (:dashboard_keep_static_line, with the width read for this
rem frame); their count into dashboard_closing_lines, which the layout
rem takes from the lists' rows.
type nul >"%temp_dashboard_closing_raw%"
set "emit_line_file_path=%temp_dashboard_closing_raw%"
call :show_closing_lines file
set "emit_line_file_path="
set "dashboard_closing_columns=%console_window_columns%"
if "%dashboard_closing_columns%"=="unknown" set "dashboard_closing_columns=80"
set /a "dashboard_line_room_static=dashboard_closing_columns - 1, dashboard_cut_length_static=dashboard_closing_columns - 4"
set "dashboard_static_file=%temp_dashboard_closing%"
type nul >"%dashboard_static_file%"
setlocal DisableDelayedExpansion
set "dashboard_static_lines=0"
set "dashboard_static_line="
call :dashboard_keep_static_line
for /f "usebackq delims=" %%L in ("%temp_dashboard_closing_raw%") do (
    set "dashboard_static_line=%%L"
    call :dashboard_keep_static_line
)
endlocal & set "dashboard_closing_lines=%dashboard_static_lines%"
exit /b 0

:dashboard_stop
rem Stop the display where the run stops early (:abort): the console goes
rem back to the normal screen and the output continues after the header.
if not defined dashboard_active exit /b 0
call :dashboard_leave_screen
exit /b 0

:dashboard_leave_screen
rem Mark the display's normal end for the watchdog, show the cursor and
rem switch the console back to the normal screen, where the earlier output
rem is as it was (the switch back needs nothing more after a resize:
rem workshop, 2026-10-20).
> "%temp_dashboard_watch_end%" echo ended
<nul set /p "=%escape_character%[?25h%escape_character%[?1049l"
set "dashboard_active="
exit /b 0

:dashboard_tick  [detailVar]
rem Every DASHBOARD_TICK_EVERY_ITEMS items of a loop (:hash_listed_file,
rem :pair_compare_line; once per record in :check_run_record; in
rem :hash_listed_file also once DASHBOARD_TICK_EVERY_CONTENT_UNITS of
rem content have been hashed since the last tick): read the
rem clock and redraw when redraw_interval_centiseconds have passed since the
rem last redraw, with detailVar's text (the item in hand) as the Hash
rem detail. The loops keep two lines per item (a count and this call): cmd
rem parses a function's lines on every call, so a clock read inline would
rem cost 2-4 ms per item (workshop, 2026-10-18). Sets dashboard_tick_count,
rem dashboard_tick_content_units and dashboard_last_redraw in the caller,
rem whichever its delayed expansion state.
if not defined dashboard_active exit /b 0
setlocal EnableDelayedExpansion
set "dashboard_since=0"
set "dashboard_clock=!time: =0!"
for /f "tokens=1-4 delims=:.," %%A in ("!dashboard_clock!") do set /a "dashboard_since=((1%%A %% 100) * 60 + (1%%B %% 100)) * 6000 + (1%%C %% 100) * 100 + (1%%D %% 100) - dashboard_last_redraw" 2>nul
if !dashboard_since! lss 0 set /a "dashboard_since+=8640000"
if !dashboard_since! geq %redraw_interval_centiseconds% (
    if not "%~1"=="" set "dashboard_hash_detail=!%~1!"
    call :dashboard_redraw
)
endlocal & set "dashboard_tick_count=0" & set "dashboard_tick_content_units=0" & set "dashboard_last_redraw=%dashboard_last_redraw%" & set "dashboard_static_columns=%dashboard_static_columns%" & set "dashboard_environment_lines=%dashboard_environment_lines%" & set "dashboard_header_sections_lines=%dashboard_header_sections_lines%"
exit /b 0

:dashboard_read_clock  outVar
rem Centiseconds since midnight from %time%, for elapsed times and the
rem redraw interval (display only). The locale's separators may be any of
rem ":", "." and ","; a leading space becomes 0; each field is read as
rem 1<field> mod 100 so a leading 0 isn't read as octal. 0 when it can't be
rem parsed.
setlocal EnableDelayedExpansion
set "clock=!time: =0!"
set "centiseconds="
for /f "tokens=1-4 delims=:.," %%A in ("!clock!") do set /a "centiseconds=((1%%A %% 100) * 60 + (1%%B %% 100)) * 6000 + (1%%C %% 100) * 100 + (1%%D %% 100)" 2>nul
if not defined centiseconds set "centiseconds=0"
endlocal & set "%~1=%centiseconds%"
exit /b 0

:dashboard_bar_text  doneVar  totalVar  startedVar  outVar
rem "[####....]  nn %  h:mm left" from done of total, and the time left
rem estimated from the average rate since the started centiseconds (owner,
rem 2026-10-20: time left only, hours and minutes, from the average since
rem the start rather than the rate of the moment), taken against the
rem redraw's own clock reading (dashboard_redraw_clock; a day's wrap
rem allowed for). "estimating" until the stage has run
rem DASHBOARD_ESTIMATE_AFTER_SECONDS and is DASHBOARD_ESTIMATE_AFTER_PERMILLE
rem through; minutes rounded up; "starting" while the total isn't known
rem yet. Progress is taken in thousandths first, and the percentage and
rem the bar's fill from those, so no product passes set /a's 32 bits
rem (2,000,000 MB times 1,000 would; 2.6.0: a bar of a few hundred
rem columns, or a set of a few TB in 100 KB units, would have too). The
rem bar is dashboard_bar_columns columns, the layout's (:dashboard_layout).
rem Counts only: delayed expansion is on.
setlocal EnableDelayedExpansion
set "done=0"
set "total=0"
if defined %~1 set /a "done=!%~1!" 2>nul
if defined %~2 set /a "total=!%~2!" 2>nul
if !total! leq 0 (endlocal & set "%~4=starting" & exit /b 0)
if !done! gtr !total! set "done=!total!"
if !total! gtr 1000000 (set /a "permille=done / (total / 1000)") else set /a "permille=done * 1000 / total"
if !permille! gtr 1000 set "permille=1000"
set /a "percent=permille / 10, filled=permille * dashboard_bar_columns / 1000"
set /a "empty=dashboard_bar_columns - filled"
for %%F in (!filled!) do for %%E in (!empty!) do set "bar=[!dashboard_bar_full_text:~0,%%F!!dashboard_bar_empty_text:~0,%%E!]"
set "padded_percent=   !percent!"
set "padded_percent=!padded_percent:~-3!"
set "time_text=estimating"
set "elapsed=0"
if defined %~3 (
    set /a "elapsed=(dashboard_redraw_clock - !%~3!) / 100"
    if !elapsed! lss 0 set /a "elapsed+=86400"
)
if !elapsed! geq %DASHBOARD_ESTIMATE_AFTER_SECONDS% if !permille! geq %DASHBOARD_ESTIMATE_AFTER_PERMILLE% (
    set /a "remaining=elapsed * (1000 - permille) / permille"
    set /a "remaining_minutes=(remaining + 59) / 60"
    set /a "hours=remaining_minutes / 60, minutes=remaining_minutes %% 60"
    if !minutes! lss 10 set "minutes=0!minutes!"
    set "time_text=!hours!:!minutes! left"
)
endlocal & set "%~4=%bar% %padded_percent% %%  %time_text%"
exit /b 0

:dashboard_redraw
rem Redraw the whole alternate screen for the window as it is now (2.6.0):
rem its size read with "mode con" (8 ms; :dashboard_read_window_size), the
rem static parts rebuilt into their files when the width changed
rem (:dashboard_build_static), the parts that fit chosen from the bottom up
rem (:dashboard_layout), then the screen drawn from the top left
rem (:dashboard_draw_screen). Records the time, for the loops' ticks.
if not defined dashboard_active exit /b 0
call :dashboard_read_window_size
if not "%console_window_columns%"=="%dashboard_static_columns%" call :dashboard_build_static
call :dashboard_layout
call :dashboard_draw_screen
exit /b 0

:dashboard_draw_screen
rem (:dashboard_redraw) The screen's lines, written from the top left: the
rem environment cells and the header's Source and Destination sections when
rem the layout shows them (typed from their files), then the progress
rem block: a rule, the title, the stage rows with their detail lines, a
rem blank line, the Failures and Warnings lists (:dashboard_draw_lists), a
rem rule; then the rest of the screen erased. Every line erased and
rem rewritten (VT sequences, as the colour uses) and cut to the width so
rem the console never wraps one, its last three characters "..." so the
rem cut shows (round 12.9; the summary holds every line in full). A stage
rem row has the field layout (the status at column 25) and the list lines
rem the lists' ([WARN] at column 5): their colour is the same rule as
rem :colour_for_console's for those shapes, written here rather than
rem called, so a redraw doesn't pay the label search ten times. The lists'
rem counts and last lines come from the summary's list files through a
rem small cache (:dashboard_read_lists), with delayed expansion off, so "!"
rem in an evidence name survives.
setlocal DisableDelayedExpansion
call :dashboard_read_lists
call :dashboard_read_clock dashboard_redraw_clock
setlocal EnableDelayedExpansion
set "dashboard_erase=!escape_character![2K"
<nul set /p "=!escape_character![H"
rem The notice is the one line not cut to the window (it says what to do):
rem in a narrow window the console wraps it, so the screen is cleared from
rem the top first, or the wrapped rows would keep the last frame's text
rem (round 14). Only here: a full clear flashes, so a frame never starts
rem with one.
if defined dashboard_small_text (
    <nul set /p "=!escape_character![J"
    echo(!dashboard_small_text!
    goto dashboard_draw_screen_end
)
if defined dashboard_show_environment type "!temp_dashboard_environment!"
if defined dashboard_show_header_sections type "!temp_dashboard_header_sections!"
echo(!dashboard_erase!!dashboard_rule!
set "dashboard_line=!dashboard_title_text!"
if not "!dashboard_line:~%dashboard_line_room%!"=="" set "dashboard_line=!dashboard_line:~0,%dashboard_cut_length%!..."
echo(!dashboard_erase!!dashboard_line!
for %%S in (%DASHBOARD_STAGES%) do (
    set "dashboard_stage_text=!dashboard_%%S_text!"
    if defined dashboard_%%S_bar call :dashboard_bar_text !dashboard_%%S_done_var! !dashboard_%%S_total_var! dashboard_%%S_started dashboard_stage_text
    set "dashboard_padded_label=!DASHBOARD_STAGE_%%S_LABEL!                    "
    set "dashboard_line=  !dashboard_padded_label:~0,20!: !dashboard_stage_text!"
    if not "!dashboard_line:~%dashboard_line_room%!"=="" set "dashboard_line=!dashboard_line:~0,%dashboard_cut_length%!..."
    if defined console_colour (
        if "!dashboard_line:~24,5!"=="PASS:" set "dashboard_line=!dashboard_line:~0,24!%coloured_pass%!dashboard_line:~28!"
        if "!dashboard_line:~24,5!"=="FAIL:" set "dashboard_line=!dashboard_line:~0,24!%coloured_fail%!dashboard_line:~28!"
        if "!dashboard_line:~24,5!"=="WARN:" set "dashboard_line=!dashboard_line:~0,24!%coloured_warn%!dashboard_line:~28!"
    )
    rem The RESULT row (2.8.0): its verdict bold, as the result block's.
    if "%%S"=="result" if defined console_colour (
        if "!dashboard_line:~24,5!"=="PASS " set "dashboard_line=!dashboard_line:~0,24!%coloured_verdict_pass%!dashboard_line:~28!"
        if "!dashboard_line:~24,5!"=="FAIL " set "dashboard_line=!dashboard_line:~0,24!%coloured_verdict_fail%!dashboard_line:~28!"
        if "!dashboard_line:~24,11!"=="UNVERIFIED " set "dashboard_line=!dashboard_line:~0,24!%coloured_verdict_unverified%!dashboard_line:~34!"
    )
    echo(!dashboard_erase!!dashboard_line!
    set "dashboard_detail_lines=!DASHBOARD_STAGE_%%S_DETAILS!"
    if defined dashboard_detail_lines for %%D in (!dashboard_detail_lines!) do (
        set "dashboard_line=    !%%D!"
        if not "!dashboard_line:~%dashboard_line_room%!"=="" set "dashboard_line=!dashboard_line:~0,%dashboard_cut_length%!..."
        echo(!dashboard_erase!!dashboard_line!
    )
)
echo(!dashboard_erase!
call :dashboard_draw_lists
echo(!dashboard_erase!!dashboard_rule!
if !dashboard_closing_lines! gtr 0 type "!temp_dashboard_closing!"
:dashboard_draw_screen_end
<nul set /p "=!escape_character![J"
endlocal
endlocal & set "dashboard_last_redraw=%dashboard_redraw_clock%" & set "dashboard_tick_count=0" & set "dashboard_tick_content_units=0"
exit /b 0

:dashboard_draw_lists
rem (:dashboard_draw_screen, delayed expansion on) The Failures and Warnings
rem lists in the layout's rows (dashboard_list_rows), failures first
rem (owner, 2026-10-21: the display is live, a failure is what the analyst
rem may act on). Each list's last lines are held, up to
rem DASHBOARD_LIST_ROWS_MAX (dashboard_list_F1.., _W1..), the newest last.
rem Side by side (dashboard_lists_side_by_side): Failures on the left,
rem Warnings on the right, one heading row and then the rows, each list
rem the full height, its lines from the top under its heading and the
rem spare rows blank at the bottom (owner, 2026-10-21, round 14.3: before,
rem one line sat at the bottom of its column). One above the other: both
rem headings with their counts
rem always; everything when it fits; else two failure rows for each
rem warning row, the warnings keeping at least one line while there are
rem three rows or more (fewer: failures first), a list needing less than
rem its share giving the rest to the other; the spare rows blank at the
rem bottom. Lines cut with "..." to their column.
set "dashboard_failures_held=!dashboard_list_FC!"
set "dashboard_warnings_held=!dashboard_list_WC!"
if !dashboard_failures_held! gtr %DASHBOARD_LIST_ROWS_MAX% set "dashboard_failures_held=%DASHBOARD_LIST_ROWS_MAX%"
if !dashboard_warnings_held! gtr %DASHBOARD_LIST_ROWS_MAX% set "dashboard_warnings_held=%DASHBOARD_LIST_ROWS_MAX%"
if defined dashboard_lists_side_by_side goto dashboard_draw_lists_side_by_side
set /a "dashboard_failures_rows=dashboard_failures_held, dashboard_warnings_rows=dashboard_warnings_held, dashboard_lists_held=dashboard_failures_held + dashboard_warnings_held"
if !dashboard_lists_held! gtr !dashboard_list_rows! (
    set /a "dashboard_failures_rows=(2 * dashboard_list_rows + 2) / 3"
    if !dashboard_failures_rows! gtr !dashboard_failures_held! set "dashboard_failures_rows=!dashboard_failures_held!"
    set /a "dashboard_warnings_rows=dashboard_list_rows - dashboard_failures_rows"
    if !dashboard_warnings_rows! gtr !dashboard_warnings_held! set /a "dashboard_warnings_rows=dashboard_warnings_held, dashboard_failures_rows=dashboard_list_rows - dashboard_warnings_held"
)
set /a "dashboard_blank_rows=dashboard_list_rows - dashboard_failures_rows - dashboard_warnings_rows"
call :dashboard_list_heading Failures dashboard_list_FC dashboard_failures_rows
echo(!dashboard_erase!!dashboard_list_heading!
set /a "dashboard_list_first=dashboard_failures_held - dashboard_failures_rows"
for /l %%N in (1,1,!dashboard_failures_rows!) do (
    set /a "dashboard_list_slot=dashboard_list_first + %%N"
    for %%T in (!dashboard_list_slot!) do set "dashboard_line=    !dashboard_list_F%%T!"
    call :dashboard_echo_list_line
)
call :dashboard_list_heading Warnings dashboard_list_WC dashboard_warnings_rows
echo(!dashboard_erase!!dashboard_list_heading!
set /a "dashboard_list_first=dashboard_warnings_held - dashboard_warnings_rows"
for /l %%N in (1,1,!dashboard_warnings_rows!) do (
    set /a "dashboard_list_slot=dashboard_list_first + %%N"
    for %%T in (!dashboard_list_slot!) do set "dashboard_line=    !dashboard_list_W%%T!"
    call :dashboard_echo_list_line
)
for /l %%N in (1,1,!dashboard_blank_rows!) do echo(!dashboard_erase!
exit /b 0
:dashboard_draw_lists_side_by_side
set "dashboard_failures_shown=!dashboard_failures_held!"
set "dashboard_warnings_shown=!dashboard_warnings_held!"
if !dashboard_failures_shown! gtr !dashboard_list_rows! set "dashboard_failures_shown=!dashboard_list_rows!"
if !dashboard_warnings_shown! gtr !dashboard_list_rows! set "dashboard_warnings_shown=!dashboard_list_rows!"
call :dashboard_list_heading Failures dashboard_list_FC dashboard_failures_shown
set "dashboard_line=!dashboard_list_heading!!BLANKS!!BLANKS!!BLANKS!!BLANKS!!BLANKS!"
call :dashboard_list_heading Warnings dashboard_list_WC dashboard_warnings_shown
echo(!dashboard_erase!!dashboard_line:~0,%dashboard_list_column_width%! !dashboard_list_heading!
set /a "dashboard_failures_first=dashboard_failures_held - dashboard_list_rows, dashboard_warnings_first=dashboard_warnings_held - dashboard_list_rows"
if !dashboard_failures_first! lss 0 set "dashboard_failures_first=0"
if !dashboard_warnings_first! lss 0 set "dashboard_warnings_first=0"
for /l %%N in (1,1,!dashboard_list_rows!) do (
    set "dashboard_left="
    set "dashboard_right="
    set /a "dashboard_list_slot=dashboard_failures_first + %%N"
    if !dashboard_list_slot! leq !dashboard_failures_held! for %%T in (!dashboard_list_slot!) do set "dashboard_left=    !dashboard_list_F%%T!"
    set /a "dashboard_list_slot=dashboard_warnings_first + %%N"
    if !dashboard_list_slot! leq !dashboard_warnings_held! for %%T in (!dashboard_list_slot!) do set "dashboard_right=    !dashboard_list_W%%T!"
    call :dashboard_echo_list_pair
)
exit /b 0

:dashboard_list_heading  title  countVar  shownVar
rem (:dashboard_draw_lists) A list's heading into dashboard_list_heading:
rem "  Failures: n", and when fewer lines are shown than the list holds
rem (2.8.0; the owner: the rest is in the log), ", the last m shown (all
rem in the log)" or, for a non-forensic run, "(all in the summary that
rem follows)" (dashboard_lists_rest_text); ", none shown (...)" when
rem the last frame's closing lines leave the list no row (round 14.10
rem at 80 x 24). Counts only.
set "dashboard_list_heading=  %~1: !%~2!"
if !%~3! lss !%~2! set "dashboard_list_heading=  %~1: !%~2!, the last !%~3! shown (!dashboard_lists_rest_text!)"
if !%~3! equ 0 if !%~2! gtr 0 set "dashboard_list_heading=  %~1: !%~2!, none shown (!dashboard_lists_rest_text!)"
exit /b 0

:dashboard_echo_list_line
rem (:dashboard_draw_lists) dashboard_line, cut to the row and its tag
rem coloured, echoed.
if not "!dashboard_line:~%dashboard_line_room%!"=="" set "dashboard_line=!dashboard_line:~0,%dashboard_cut_length%!..."
if defined console_colour (
    if "!dashboard_line:~4,6!"=="[WARN]" set "dashboard_line=    %coloured_warn_tag%!dashboard_line:~10!"
    if "!dashboard_line:~4,6!"=="[FAIL]" set "dashboard_line=    %coloured_fail_tag%!dashboard_line:~10!"
)
echo(!dashboard_erase!!dashboard_line!
exit /b 0

:dashboard_echo_list_pair
rem (:dashboard_draw_lists, side by side) dashboard_left and _right, each
rem cut to its column (dashboard_list_column_width and
rem dashboard_list_right_width), the left padded to it, the tags coloured
rem after the padding (the colour's characters take no columns), echoed as
rem one row.
for %%W in (!dashboard_list_column_width!) do for %%C in (!dashboard_list_column_cut!) do (
    if defined dashboard_left if not "!dashboard_left:~%%W!"=="" set "dashboard_left=!dashboard_left:~0,%%C!..."
    set "dashboard_left=!dashboard_left!!BLANKS!!BLANKS!!BLANKS!!BLANKS!!BLANKS!"
    set "dashboard_left=!dashboard_left:~0,%%W!"
)
for %%W in (!dashboard_list_right_width!) do for %%C in (!dashboard_list_right_cut!) do (
    if defined dashboard_right if not "!dashboard_right:~%%W!"=="" set "dashboard_right=!dashboard_right:~0,%%C!..."
)
if defined console_colour (
    if "!dashboard_left:~4,6!"=="[FAIL]" set "dashboard_left=    %coloured_fail_tag%!dashboard_left:~10!"
    if "!dashboard_left:~4,6!"=="[WARN]" set "dashboard_left=    %coloured_warn_tag%!dashboard_left:~10!"
    if "!dashboard_right:~4,6!"=="[WARN]" set "dashboard_right=    %coloured_warn_tag%!dashboard_right:~10!"
    if "!dashboard_right:~4,6!"=="[FAIL]" set "dashboard_right=    %coloured_fail_tag%!dashboard_right:~10!"
)
echo(!dashboard_erase!!dashboard_left! !dashboard_right!
exit /b 0

:dashboard_read_window_size
rem The window's rows and columns while the display is in the alternate
rem screen, whose buffer is the window, so "mode con" reports it as it is
rem (until 2.8.0 a read at the start switched screens to get that, which
rem here would switch the display off): into console_window_rows and
rem _columns, "unknown" when unreadable. <nul: mode reads the console
rem input otherwise. The first two numbers after a colon are the rows,
rem then the columns (mode's lines come in a fixed order in any language);
rem read inline, with no call per line (a call from here scans most of the
rem file for its label: 120 ms a redraw, workshop 2.6.0).
set "console_window_rows=unknown"
set "console_window_columns=unknown"
"%tool_mode%" con >"%temp_dashboard_size%" 2>nul <nul
setlocal EnableDelayedExpansion
set "numbers_read=0"
set "rows=unknown"
set "columns=unknown"
for /f "usebackq tokens=2 delims=:" %%A in ("!temp_dashboard_size!") do for %%T in (%%A) do (
    set "word=%%T"
    if "!word!" neq "" if "!word:~0,1!" geq "0" if "!word:~0,1!" leq "9" (
        set /a "numbers_read+=1"
        if !numbers_read! equ 1 set "rows=%%T"
        if !numbers_read! equ 2 set "columns=%%T"
    )
)
endlocal & set "console_window_rows=%rows%" & set "console_window_columns=%columns%"
exit /b 0

:dashboard_layout
rem Caller's scope (:dashboard_redraw): which parts fit the window, from
rem the bottom up (owner, 2026-10-21): the progress block always, its lists
rem DASHBOARD_LIST_ROWS_MIN rows; above it the header's Source and
rem Destination sections when they fit in what is left (never taking rows
rem from the lists), then the environment cells; then the lists grow
rem towards DASHBOARD_LIST_ROWS_MAX with the rows left. A window smaller
rem than DASHBOARD_MIN_WINDOW_COLUMNS x _ROWS gets one line saying so
rem (dashboard_small_text), replaced by the display at the first redraw
rem with room. One row is always left free at the bottom, so the last
rem line's end never scrolls the screen. Sets dashboard_window_rows and
rem _columns (25 x 80 when the size can't be read), dashboard_line_room
rem (what a line may hold: one less than the width, so no line wraps),
rem dashboard_cut_length (where a longer line is cut before its "..."),
rem dashboard_rule and dashboard_bar_columns (the window's width: owner,
rem 2026-10-21), dashboard_lists_side_by_side with
rem dashboard_list_column_width and _cut (the left column) and
rem dashboard_list_right_width and _cut (the right column, one column
rem shorter at an odd width, so a row is never the window's full width:
rem round 14) (from DASHBOARD_LISTS_SIDE_BY_SIDE_MIN_COLUMNS),
rem dashboard_list_rows (less the last frame's closing lines,
rem dashboard_closing_lines, which come under the block: 2.8.0),
rem dashboard_show_header_sections, dashboard_show_environment.
set "dashboard_window_rows=%console_window_rows%"
set "dashboard_window_columns=%console_window_columns%"
if "%dashboard_window_rows%"=="unknown" set "dashboard_window_rows=25"
if "%dashboard_window_columns%"=="unknown" set "dashboard_window_columns=80"
set /a "dashboard_line_room=dashboard_window_columns - 1, dashboard_cut_length=dashboard_window_columns - 4"
set "dashboard_small_text="
set "dashboard_show_header_sections="
set "dashboard_show_environment="
set "dashboard_lists_side_by_side="
set "dashboard_list_rows=0"
rem The notice fits 80 columns (round 14.10: at the width it names, the
rem console split a longer one mid-word).
if %dashboard_window_rows% lss %DASHBOARD_MIN_WINDOW_ROWS% set "dashboard_small_text=The window is %dashboard_window_columns% x %dashboard_window_rows%; the live display needs %DASHBOARD_MIN_WINDOW_COLUMNS% x %DASHBOARD_MIN_WINDOW_ROWS% (the run goes on)."
if %dashboard_window_columns% lss %DASHBOARD_MIN_WINDOW_COLUMNS% set "dashboard_small_text=The window is %dashboard_window_columns% x %dashboard_window_rows%; the live display needs %DASHBOARD_MIN_WINDOW_COLUMNS% x %DASHBOARD_MIN_WINDOW_ROWS% (the run goes on)."
if defined dashboard_small_text exit /b 0
set /a "dashboard_bar_columns=dashboard_line_room - (OUTPUT_WIDTH - DASHBOARD_BAR_WIDTH)"
set "dashboard_rule=%dashboard_rule_text%"
setlocal EnableDelayedExpansion
for %%W in (!dashboard_line_room!) do set "dashboard_rule=!dashboard_rule:~0,%%W!"
endlocal & set "dashboard_rule=%dashboard_rule%"
set "dashboard_list_heading_rows=2"
if %dashboard_window_columns% geq %DASHBOARD_LISTS_SIDE_BY_SIDE_MIN_COLUMNS% (
    set "dashboard_lists_side_by_side=1"
    set "dashboard_list_heading_rows=1"
    set /a "dashboard_list_column_width=(dashboard_window_columns - 1) / 2, dashboard_list_column_cut=(dashboard_window_columns - 1) / 2 - 3"
    set /a "dashboard_list_right_width=dashboard_window_columns - 2 - (dashboard_window_columns - 1) / 2, dashboard_list_right_cut=dashboard_window_columns - 5 - (dashboard_window_columns - 1) / 2"
)
set /a "dashboard_rows_free=dashboard_window_rows - 1 - DASHBOARD_BLOCK_FIXED_LINES - dashboard_list_heading_rows - dashboard_closing_lines"
if %dashboard_rows_free% lss 0 set "dashboard_rows_free=0"
set "dashboard_list_rows=%dashboard_rows_free%"
if %dashboard_list_rows% gtr %DASHBOARD_LIST_ROWS_MIN% set "dashboard_list_rows=%DASHBOARD_LIST_ROWS_MIN%"
set /a "dashboard_rows_free-=dashboard_list_rows"
if %dashboard_rows_free% geq %dashboard_header_sections_lines% (
    set "dashboard_show_header_sections=1"
    set /a "dashboard_rows_free-=dashboard_header_sections_lines"
)
if defined dashboard_show_header_sections if %dashboard_rows_free% geq %dashboard_environment_lines% (
    set "dashboard_show_environment=1"
    set /a "dashboard_rows_free-=dashboard_environment_lines"
)
set /a "dashboard_list_rows+=dashboard_rows_free"
if %dashboard_list_rows% gtr %DASHBOARD_LIST_ROWS_MAX% set "dashboard_list_rows=%DASHBOARD_LIST_ROWS_MAX%"
exit /b 0

:dashboard_build_static
rem The static parts of the screen for the window's width, into their
rem files (one erased-and-written line each, typed at every redraw): the
rem environment cells (:dashboard_build_environment) and the header's
rem Source and Destination sections (:dashboard_build_header_sections),
rem each with a blank line below; their line counts into
rem dashboard_environment_lines and dashboard_header_sections_lines, the
rem width they were built for into dashboard_static_columns. Called by
rem :dashboard_redraw when the width changed (the first time too).
set "dashboard_static_columns=%console_window_columns%"
set "dashboard_build_columns=%console_window_columns%"
if "%dashboard_build_columns%"=="unknown" set "dashboard_build_columns=80"
if %dashboard_build_columns% lss %DASHBOARD_MIN_WINDOW_COLUMNS% set "dashboard_build_columns=%DASHBOARD_MIN_WINDOW_COLUMNS%"
set /a "dashboard_line_room_static=dashboard_build_columns - 1, dashboard_cut_length_static=dashboard_build_columns - 4"
set "dashboard_environment_lines=0"
set "dashboard_header_sections_lines=0"
call :dashboard_build_environment
call :dashboard_build_header_sections
exit /b 0

:dashboard_build_environment
rem Caller's scope (:dashboard_build_static): the environment, a title and
rem then "Label: value" cells, as many across as the width takes (one, as
rem wide as the window, when it takes fewer than two), the fields of
rem DASHBOARD_ENVIRONMENT_FIELDS in order, each with its short value
rem (written for the cell; the header and the log hold the full text);
rem then a blank line. A value DASHBOARD_HIGHLIGHTS names is coloured as
rem its tag (dashboard_colour_<var>, :dashboard_set_highlights), after the
rem cell is cut and padded, so the colour takes no columns (2.7.0). A cell
rem is DASHBOARD_CELL_WIDTH wide, or wider when
rem the longest "Label: value" needs it (owner, 2026-10-21: nothing cut,
rem round 14), so a value is cut with "..." only in a window too narrow
rem for one cell. A row is at most one column less than the window (two
rem columns of indent, the cells, and the column left free), so the
rem console never wraps it. Values are read by name only.
setlocal EnableDelayedExpansion
set "erase=!escape_character![2K"
set "longest_cell=0"
for %%F in (%DASHBOARD_ENVIRONMENT_FIELDS%) do (
    set "cell=!DASHBOARD_FIELD_%%F_LABEL!: "
    for %%V in (!DASHBOARD_FIELD_%%F_VAR!) do set "cell=!cell!!%%V!"
    set "cell_length=0"
    for /l %%I in (0,1,%OUTPUT_WIDTH%) do if not "!cell:~%%I,1!"=="" set /a "cell_length=%%I + 1"
    if !cell_length! gtr !longest_cell! set "longest_cell=!cell_length!"
)
set /a "least_cell_width=longest_cell + 1"
if !least_cell_width! lss %DASHBOARD_CELL_WIDTH% set "least_cell_width=%DASHBOARD_CELL_WIDTH%"
set /a "cells_per_row=(dashboard_build_columns - 3) / least_cell_width"
if !cells_per_row! lss 1 set "cells_per_row=1"
set /a "cell_width=(dashboard_build_columns - 3) / cells_per_row"
set /a "cell_room=cell_width - 1, cell_cut=cell_width - 4"
set "lines=1"
> "!temp_dashboard_environment!" echo(!erase!Environment
set "row_text=  "
set "cells_in_row=0"
for %%F in (%DASHBOARD_ENVIRONMENT_FIELDS%) do (
    set "cell=!DASHBOARD_FIELD_%%F_LABEL!: "
    for %%V in (!DASHBOARD_FIELD_%%F_VAR!) do set "cell=!cell!!%%V!"
    for %%W in (!cell_room!) do for %%C in (!cell_cut!) do (
        if not "!cell:~%%W!"=="" set "cell=!cell:~0,%%C!..."
        set "cell=!cell!!BLANKS!!BLANKS!!BLANKS!"
        set "cell=!cell:~0,%%W! "
    )
    for %%V in (!DASHBOARD_FIELD_%%F_VAR!) do if defined dashboard_colour_%%V (
        set "cell_prefix=!DASHBOARD_FIELD_%%F_LABEL!: "
        set "cell_prefix_length=0"
        for /l %%I in (0,1,%OUTPUT_WIDTH%) do if not "!cell_prefix:~%%I,1!"=="" set /a "cell_prefix_length=%%I + 1"
        for %%P in (!cell_prefix_length!) do set "cell=!cell:~0,%%P!!dashboard_colour_%%V!!cell:~%%P!!colour_end!"
    )
    set "row_text=!row_text!!cell!"
    set /a "cells_in_row+=1"
    if !cells_in_row! geq !cells_per_row! (
        >> "!temp_dashboard_environment!" echo(!erase!!row_text!
        set /a "lines+=1"
        set "row_text=  "
        set "cells_in_row=0"
    )
)
if !cells_in_row! gtr 0 (
    >> "!temp_dashboard_environment!" echo(!erase!!row_text!
    set /a "lines+=1"
)
>> "!temp_dashboard_environment!" echo(!erase!
set /a "lines+=1"
endlocal & set "dashboard_environment_lines=%lines%"
exit /b 0

:dashboard_build_header_sections
rem Caller's scope (:dashboard_build_static): the header's Source and
rem Destination sections for the width: side by side from
rem HEADER_SIDE_BY_SIDE_MIN_COLUMNS (the header's pairs,
rem :dashboard_emit_pairs), else one below the other (the header's fields,
rem wrapped within the window, :dashboard_emit_fields). The lines are
rem written plain into temp_dashboard_header_sections_raw through
rem :emit_line's file target, then taken over into
rem temp_dashboard_header_sections erased-and-written and cut to the width
rem (:dashboard_keep_static_line), read with delayed expansion off
rem whatever the caller's state (a redraw from :dashboard_tick has it on),
rem so "!" in a path survives.
type nul >"%temp_dashboard_header_sections_raw%"
set "emit_line_file_path=%temp_dashboard_header_sections_raw%"
if %dashboard_build_columns% geq %HEADER_SIDE_BY_SIDE_MIN_COLUMNS% (
    call :dashboard_emit_pairs
) else (
    call :dashboard_emit_fields
)
set "emit_line_file_path="
set "dashboard_static_file=%temp_dashboard_header_sections%"
type nul >"%dashboard_static_file%"
setlocal DisableDelayedExpansion
set "dashboard_static_lines=0"
for /f "usebackq delims=" %%L in ("%temp_dashboard_header_sections_raw%") do (
    set "dashboard_static_line=%%L"
    call :dashboard_keep_static_line
)
set "dashboard_static_line="
call :dashboard_keep_static_line
endlocal & set "dashboard_header_sections_lines=%dashboard_static_lines%"
exit /b 0

:dashboard_keep_static_line
rem (:dashboard_build_header_sections, :dashboard_build_closing_lines)
rem dashboard_static_line, erased-and-written and cut to the width,
rem appended to the file dashboard_static_file names; counted in
rem dashboard_static_lines. Its length is measured without the colour
rem sequences (the highlights', 2.7.0, and the History row's red, 2.8.0:
rem ESC can't be in a path, so only they hold one); a line too long is
rem cut from its plain text, so a cut line has no colour.
setlocal EnableDelayedExpansion
set "line=!dashboard_static_line!"
set "plain_line=!line!"
if defined plain_line if defined console_colour (
    set "plain_line=!plain_line:%dashboard_colour_warn_start%=!"
    set "plain_line=!plain_line:%dashboard_colour_info_start%=!"
    set "plain_line=!plain_line:%coloured_run_failed_start%=!"
    set "plain_line=!plain_line:%colour_end%=!"
)
for %%W in (!dashboard_line_room_static!) do for %%C in (!dashboard_cut_length_static!) do if defined plain_line if not "!plain_line:~%%W!"=="" set "line=!plain_line:~0,%%C!..."
>> "!dashboard_static_file!" echo(!escape_character![2K!line!
endlocal & set /a "dashboard_static_lines+=1"
exit /b 0

:dashboard_emit_pairs
rem (:dashboard_build_header_sections) The sections side by side (the
rem normal screen's header had the same form until 2.8.0), into the raw
rem file: the pair widths from the window's columns. A non-forensic run's
rem (2.7.0): the two directories robocopy copies between
rem (:write_header_plain_directories), its own three rows.
set "pair_source_root_text="
call :describe_housekeeping_for_pair source pair_source_root_text
call :dashboard_emit_pair_titles Source Destination
if "%run_mode%"=="nonforensic" (
    call :dashboard_emit_field_pair "Contents" source_with_backslash "Into" destination_with_backslash
    call :dashboard_emit_field_pair "Volume" header_source_volume "Volume" header_destination_volume
    call :dashboard_emit_field_pair "At root" pair_source_root_text "Was" destination_state_text
    exit /b 0
)
call :dashboard_emit_field_pair "Set dir" header_source_set "Set dir" destination_set_with_backslash
call :dashboard_emit_field_pair "Evidence" header_source_evidence "Evidence" destination_with_backslash
call :dashboard_emit_field_pair "Chosen" source_set_rule "Chosen" destination_set_rule
call :dashboard_emit_field_pair "Volume" header_source_volume "Volume" header_destination_volume
call :dashboard_emit_field_pair "At root" pair_source_root_text "Was" destination_state_text
call :dashboard_emit_field_pair "Reference" header_reference_record "Record" header_records
call :dashboard_emit_field_pair "History" header_history "Log" log_destination_text
call :dashboard_emit_field_pair "Previous" header_previous_run "Log (run)" log_staged_path
if defined header_previous_run_seal (
    set "msg=  Previous run's %header_previous_run_seal%"
    call :emit_line msg file
)
call :dashboard_emit_run_history_line
exit /b 0

:dashboard_emit_run_history_line
rem (:dashboard_emit_pairs) The History row on one line under the Source
rem and Destination columns (2.8.0; owner, 2026-10-24): "  History : ",
rem the runs of the history this run continues oldest first, joined by
rem " -> ", then "current" (:build_run_history_items has the items and the
rem words; a /check shows the runs alone). At most HISTORY_RUNS_MAX runs,
rem and within the window: as many of the newest as fit
rem dashboard_line_room_static, "..... -> " first when any is left out, so
rem the line is never cut at the right. It is measured plain; a run whose
rem Result isn't PASS, and "current" once this run has failed, are red
rem in the line written (:dashboard_compose_run_history_line). Into the
rem raw file, as the pairs.
setlocal EnableDelayedExpansion
set "wide_label=  History : "
set "wide_tail="
if defined run_history_current_text set "wide_tail= -> !run_history_current_text!"
set "wide_first=1"
if !run_history_count! gtr %HISTORY_RUNS_MAX% set /a "wide_first=run_history_count - HISTORY_RUNS_MAX + 1"
set "wide_fits="
for /l %%T in (1,1,%HISTORY_RUNS_MAX%) do if not defined wide_fits (
    call :dashboard_compose_run_history_line
    call :strlen wide_plain wide_length
    if !wide_length! leq !dashboard_line_room_static! (set "wide_fits=1") else set /a "wide_first+=1"
)
if not defined wide_fits call :dashboard_compose_run_history_line
call :emit_line wide_shown file
endlocal & exit /b 0

:dashboard_compose_run_history_line
rem Caller's scope, delayed expansion on (:dashboard_emit_run_history_line):
rem the line from item wide_first on, plain (wide_plain, to measure) and
rem as shown (wide_shown, the red where it applies). With every run left
rem out, "..... -> current".
set "wide_lead="
if !wide_first! gtr 1 set "wide_lead=..... -> "
set "wide_items_plain="
set "wide_items_shown="
for /l %%I in (!wide_first!,1,!run_history_count!) do (
    set "wide_item=!run_history_%%I_text!"
    set "wide_item_shown=!run_history_%%I_text!"
    if defined run_history_%%I_failed if defined console_colour set "wide_item_shown=!coloured_run_failed_start!!run_history_%%I_text!!colour_end!"
    if defined wide_items_plain (set "wide_items_plain=!wide_items_plain! -> !wide_item!") else set "wide_items_plain=!wide_item!"
    if defined wide_items_shown (set "wide_items_shown=!wide_items_shown! -> !wide_item_shown!") else set "wide_items_shown=!wide_item_shown!"
)
set "wide_tail_shown=!wide_tail!"
if defined run_history_current_failed if defined console_colour if defined run_history_current_text set "wide_tail_shown= -> !coloured_run_failed_start!!run_history_current_text!!colour_end!"
if defined wide_items_plain (
    set "wide_plain=!wide_label!!wide_lead!!wide_items_plain!!wide_tail!"
    set "wide_shown=!wide_label!!wide_lead!!wide_items_shown!!wide_tail_shown!"
) else (
    set "wide_plain=!wide_label!!wide_lead!!wide_tail:~4!"
    set "wide_shown=!wide_label!!wide_lead!!wide_tail_shown:~4!"
)
exit /b 0

:dashboard_emit_pair_titles  leftTitle  rightTitle
rem (:dashboard_emit_pairs) The two sections' titles on one row, the right
rem one at the right column's start, into the raw file, the
rem column width from dashboard_build_columns: (C - 2) / 2 a side, so a
rem row of the pairs (left, a space, right) is at most C - 1 columns at an
rem odd width too (round 14.3: at 209 the right column's full rows reached
rem the window's width and were cut; the normal screen's header keeps
rem (C - 1) / 2, which the console wraps rather than cuts).
setlocal EnableDelayedExpansion
set /a "pair_column_width=(dashboard_build_columns - 2) / 2"
set "pair_row=%~1!BLANKS!!BLANKS!!BLANKS!"
set "pair_row=!pair_row:~0,%pair_column_width%! %~2"
call :emit_line pair_row file
endlocal & exit /b 0

:dashboard_emit_field_pair  leftLabel  leftVar  rightLabel  rightVar
rem (:dashboard_emit_pairs) One row of fields, side by side, each wrapped
rem within its column (:wrap_field_into_column) and the two merged row by
rem row, the left padded to its column, into the raw file, the
rem column width from dashboard_build_columns ((C - 2) / 2 a side:
rem :dashboard_emit_pair_titles). A value DASHBOARD_HIGHLIGHTS names
rem (dashboard_colour_<var>) is coloured from its value column (the label,
rem HEADER_PAIR_LABEL_WIDTH, and four columns) to the side's end, after
rem the side is cut and padded, so the colour takes no columns (2.7.0);
rem :dashboard_keep_static_line measures the line without it.
setlocal EnableDelayedExpansion
set /a "pair_column_width=(dashboard_build_columns - 2) / 2, pair_value_width=(dashboard_build_columns - 2) / 2 - 4 - HEADER_PAIR_LABEL_WIDTH"
set /a "pair_value_start=4 + HEADER_PAIR_LABEL_WIDTH"
set "pair_left_colour=!dashboard_colour_%~2!"
set "pair_right_colour=!dashboard_colour_%~4!"
call :wrap_field_into_column "%~1" %~2 left
call :wrap_field_into_column "%~3" %~4 right
set "pair_rows=!left_count!"
if !right_count! gtr !pair_rows! set "pair_rows=!right_count!"
for /l %%R in (1,1,!pair_rows!) do (
    set "pair_left="
    set "pair_right="
    if %%R leq !left_count! set "pair_left=!left_%%R!"
    if %%R leq !right_count! set "pair_right=!right_%%R!"
    set "pair_left=!pair_left!!BLANKS!!BLANKS!!BLANKS!"
    set "pair_left=!pair_left:~0,%pair_column_width%!"
    if defined pair_left_colour set "pair_left=!pair_left:~0,%pair_value_start%!!pair_left_colour!!pair_left:~%pair_value_start%!!colour_end!"
    if defined pair_right_colour if defined pair_right set "pair_right=!pair_right:~0,%pair_value_start%!!pair_right_colour!!pair_right:~%pair_value_start%!!colour_end!"
    set "pair_row=!pair_left! !pair_right!"
    call :emit_line pair_row file
)
endlocal & exit /b 0

:dashboard_emit_fields
rem (:dashboard_build_header_sections) The sections one below the other,
rem the header's fields (:write_header_set_fields), wrapped within the
rem window: the width rule is OUTPUT_WIDTH, set for these lines alone to
rem the window's width when that is narrower (the scope ends with this
rem helper; the lines are in the raw file).
setlocal
if %dashboard_build_columns% leq %OUTPUT_WIDTH% set /a "OUTPUT_WIDTH=dashboard_build_columns - 1"
if "%run_mode%"=="forensic" (call :write_header_set_fields file) else call :write_header_plain_directories file
endlocal
exit /b 0

:update_check_main
rem The update check's own instance (2.8.0; MAIN: entered when
rem evidence_robocopy_update_check holds this run's answer file, set by
rem :start_latest_release_check for the moment it starts this second
rem instance): one header-only request to UPDATE_LATEST_URL with curl.exe,
rem its answer into temp_update_check and then curl's exit code into
rem temp_update_check_done, which tells the run the answer is in
rem (:finish_latest_release_check); then this instance ends. The run's
rem variables (the paths, tool_curl) came with the environment.
"%tool_curl%" -s -S -I -o nul -w "%%{http_code} %%{redirect_url}" --connect-timeout %UPDATE_CHECK_MAX_SECONDS% --max-time %UPDATE_CHECK_MAX_SECONDS% "%UPDATE_LATEST_URL%" >"%temp_update_check%" 2>nul
set "update_check_curl_exit=%errorlevel%"
>"%temp_update_check_done%" echo %update_check_curl_exit%
exit /b 0

:dashboard_watchdog_main
rem The display watchdog (MAIN: entered when evidence_robocopy_display_watchdog
rem holds this run's temporary path, set by :dashboard_start for the
rem moment it starts this second instance with "start /b", which has
rem Ctrl+C ignored). It waits for the watch lock the run holds open on
rem handle 8 around its work under the display (:run_verified_work), then
rem tests it every second (the display helper's test); when the lock opens
rem without the end marker :dashboard_leave_screen wrote, the run died in
rem the alternate screen (Ctrl+C answered with Y, a crash): it switches the
rem console back to the normal screen with the cursor shown, restores the
rem code page and says what the stop left (dashboard_stop_state_text, by
rem kind: the files copied so far, unverified; nothing changed in a checked
rem set; a moved set unverified at its new place) and what is kept
rem (dashboard_stop_record_text: a forensic run's log in TEMP; a
rem non-forensic run keeps nothing, and its working files are removed
rem here; a run stopped at its closing pause had finished, so its
rem working files are removed here too, as after any completed run:
rem round 14.10). Batch can't trap Ctrl+C; this needs no trap (workshop,
rem 2026-10-20). A killed process tree takes the watchdog with it: the
rem console then stays in the alternate screen until the window is closed
rem or the script runs again (a stated limitation). It writes nothing
rem else: no log (log_ready is cleared here, so :show can't reach it), no
rem record. By host (2.7.0, owner 2026-10-21, rounds 14.1-14.2): in
rem Windows Terminal (WT_SESSION is set in its tabs) the console goes back
rem to the normal screen, where the header is, and cmd's prompt works on;
rem the classic console (conhost) destroys the alternate screen on the
rem switch back while cmd's prompt read is pending there, and the window
rem then closed at the first key pressed (round 14.2: d2 and d5 closed, d4
rem kept it), so without WT_SESSION the console stays on the display's
rem screen, the cursor shown, and the [WARN] says where the header is (it
rem comes back when a run with the display next ends in that window). A
rem conhost started from a Windows Terminal tab inherits WT_SESSION and
rem gets the switch back (2.6.0's behaviour); either way the [WARN] is
rem shown and the code page restored. A script Windows opens in Windows
rem Terminal as the default terminal has no WT_SESSION (round 14.5): it
rem stays on the display's screen there too (the window is kept), so the
rem [WARN] for that branch names no console.
set "dashboard_active="
set "log_ready="
set "dashboard_watch_waits=0"
:dashboard_watchdog_wait
"%tool_ping%" -n 2 127.0.0.1 >nul
set /a "dashboard_watch_waits+=1"
if exist "%temp_dashboard_watch_lock%" goto dashboard_watchdog_loop
if %dashboard_watch_waits% gtr %DASHBOARD_HELPER_WAIT_SECONDS% exit /b 0
goto dashboard_watchdog_wait
:dashboard_watchdog_loop
"%tool_ping%" -n 2 127.0.0.1 >nul
if not exist "%temp_dashboard_watch_lock%" exit /b 0
((call ) 8>>"%temp_dashboard_watch_lock%") 2>nul || goto dashboard_watchdog_loop
if exist "%temp_dashboard_watch_end%" exit /b 0
if defined WT_SESSION (
    <nul set /p "=%escape_character%[?25h%escape_character%[?1049l"
    set "dashboard_stop_screen_text=The display was closed; the output before it is above."
) else (
    <nul set /p "=%escape_character%[?25h"
    set "dashboard_stop_screen_text=The display's last screen is left above; the output before it is on the normal screen, which comes back when a run with the live display next ends in this window. The prompt above this warning takes commands."
)
set "msg=" & call :show msg
set "msg=[WARN] The run stopped while its live display was on. %dashboard_stop_screen_text% %dashboard_stop_record_text%"
rem A stop at the closing pause (2.8.0): the run had finished and written
rem the plain text of its display's end (:dashboard_finish_run), which is
rem shown here instead, so the result and the seal are on the normal
rem screen as they would have been.
if exist "%temp_dashboard_watch_done%" set "msg=[WARN] The run was stopped at its closing pause, after it had finished (its working files in TEMP are removed). %dashboard_stop_screen_text% What its display showed last:"
call :show msg
if exist "%temp_dashboard_watch_done%" type "%temp_dashboard_watch_done%"
call :restore_console_code_page
rem A run stopped at its closing pause had finished: nothing of it is in
rem flight, so its working files go as a completed run's do (a staging
rem directory still holding a record that couldn't be written back
rem stays: :cleanup_temp removes only empty ones). Any other stop of a
rem non-forensic run waits for robocopy to let go of its output first.
if exist "%temp_dashboard_watch_done%" (
    call :cleanup_temp
) else if "%run_mode%"=="nonforensic" call :dashboard_remove_plain_working_files
exit /b 0

:dashboard_remove_plain_working_files
rem (:dashboard_watchdog_main) A non-forensic run keeps nothing: its
rem working files in TEMP (the robocopy output the display read, the hash
rem records of a verification) are removed once robocopy, which finishes
rem the files in flight after the Ctrl+C, has let go of its output file:
rem tried every second for DASHBOARD_HELPER_WAIT_SECONDS at most.
set "dashboard_remove_waits=0"
:dashboard_remove_plain_working_files_wait
"%tool_ping%" -n 2 127.0.0.1 >nul
call :cleanup_temp
if not exist "%temp_robocopy_unicode_output%" exit /b 0
set /a "dashboard_remove_waits+=1"
if %dashboard_remove_waits% lss %DASHBOARD_HELPER_WAIT_SECONDS% goto dashboard_remove_plain_working_files_wait
exit /b 0

:dashboard_read_lists
rem Caller's scope (:dashboard_draw_screen, delayed expansion off): the
rem counts and the last DASHBOARD_LIST_ROWS_MAX lines of the summary's
rem warnings and failures lists, into dashboard_list_WC and _FC, _W1.. and
rem _F1... The list files are read (:dashboard_refresh_lists: two "find /c"
rem and two "more +n", four process starts) only when one has changed size
rem since the last time, which is seen in-process (%%~z); what was read is
rem kept in temp_dashboard_lists, a file of three lines plus the lines
rem held, read in-process here at every redraw. (Reading the lists at
rem every redraw cost about 300 ms, a third of the hashing time at one
rem redraw a second: workshop, phase 3.)
for /l %%N in (1,1,%DASHBOARD_LIST_ROWS_MAX%) do set "dashboard_list_W%%N="
for /l %%N in (1,1,%DASHBOARD_LIST_ROWS_MAX%) do set "dashboard_list_F%%N="
set "dashboard_list_WC=0"
set "dashboard_list_FC=0"
set "dashboard_list_S="
set "dashboard_warnings_size=0"
set "dashboard_failures_size=0"
if exist "%temp_summary_warnings%" for %%A in ("%temp_summary_warnings%") do set "dashboard_warnings_size=%%~zA"
if exist "%temp_summary_failures%" for %%A in ("%temp_summary_failures%") do set "dashboard_failures_size=%%~zA"
set "dashboard_list_sizes=%dashboard_warnings_size% %dashboard_failures_size%"
if exist "%temp_dashboard_lists%" for /f "usebackq tokens=1* delims=:" %%A in ("%temp_dashboard_lists%") do set "dashboard_list_%%A=%%B"
if "%dashboard_list_S%"=="%dashboard_list_sizes%" exit /b 0
call :dashboard_refresh_lists
for /f "usebackq tokens=1* delims=:" %%A in ("%temp_dashboard_lists%") do set "dashboard_list_%%A=%%B"
exit /b 0

:dashboard_refresh_lists
rem Caller's scope (:dashboard_read_lists, delayed expansion off): the list
rem files read and the cache written, one "key:text" line each (S the
rem sizes, WC and FC the counts, W1.. and F1.. the lines, empty ones too). The
rem lines are written with delayed expansion on, so "&" or "|" in a name
rem can't be read as a command.
call :dashboard_count_list_lines warnings
call :dashboard_count_list_lines failures
call :dashboard_read_list_lines warnings
call :dashboard_read_list_lines failures
setlocal EnableDelayedExpansion
(
    echo(S:!dashboard_list_sizes!
    echo(WC:!dashboard_warnings_count!
    echo(FC:!dashboard_failures_count!
    for /l %%N in (1,1,%DASHBOARD_LIST_ROWS_MAX%) do echo(W%%N:!dashboard_warnings_line_%%N!
    for /l %%N in (1,1,%DASHBOARD_LIST_ROWS_MAX%) do echo(F%%N:!dashboard_failures_line_%%N!
) >"!temp_dashboard_lists!"
endlocal
exit /b 0

:dashboard_count_list_lines  kind
rem Caller's scope (:dashboard_refresh_lists, delayed expansion off): the
rem lines in the summary's warnings or failures list (temp_summary_<kind>),
rem into dashboard_<kind>_count; 0 without the file. Counted from the file:
rem a counter kept in a variable would be lost in the callers' setlocal
rem scopes.
set "dashboard_%~1_count=0"
set "dashboard_list_path=%temp_summary_warnings%"
if "%~1"=="failures" set "dashboard_list_path=%temp_summary_failures%"
if not exist "%dashboard_list_path%" exit /b 0
"%tool_find%" /c /v "" <"%dashboard_list_path%" >"%temp_dashboard_count%" 2>nul
for /f "usebackq" %%N in ("%temp_dashboard_count%") do set "dashboard_%~1_count=%%N"
exit /b 0

:dashboard_read_list_lines  kind
rem Caller's scope (:dashboard_refresh_lists, delayed expansion off): the last
rem DASHBOARD_LIST_ROWS_MAX lines of the summary's warnings or failures list
rem (temp_summary_<kind>) into dashboard_<kind>_line_1... The earlier
rem lines are skipped with "more +n" (cheap however long the list), its
rem output written to a file and read from there (no path on a child
rem command line), and the rest assigned with delayed expansion off, so "!"
rem and "%" in an evidence name come through as they are; none is ever run
rem or expanded.
for /l %%N in (1,1,%DASHBOARD_LIST_ROWS_MAX%) do set "dashboard_%~1_line_%%N="
set "dashboard_list_index=0"
set "dashboard_list_path=%temp_summary_warnings%"
if "%~1"=="failures" set "dashboard_list_path=%temp_summary_failures%"
if not exist "%dashboard_list_path%" exit /b 0
set /a "dashboard_list_skip=dashboard_%~1_count - DASHBOARD_LIST_ROWS_MAX"
if %dashboard_list_skip% lss 0 set "dashboard_list_skip=0"
"%tool_more%" +%dashboard_list_skip% "%dashboard_list_path%" >"%temp_dashboard_list_tail%" 2>nul <nul
for /f "usebackq delims=" %%L in ("%temp_dashboard_list_tail%") do (
    set "dashboard_list_line=%%L"
    call :dashboard_keep_list_line %~1
)
exit /b 0

:dashboard_keep_list_line  kind
rem Caller's scope (:dashboard_read_list_lines, delayed expansion off): the
rem line read, as the next of the kind's lines (1 to DASHBOARD_LIST_ROWS_MAX).
set /a "dashboard_list_index+=1"
for /l %%N in (1,1,%DASHBOARD_LIST_ROWS_MAX%) do if "%dashboard_list_index%"=="%%N" set "dashboard_%~1_line_%%N=%dashboard_list_line%"
exit /b 0

rem -- Live copy progress: the display helper ---------------------------------
rem While the copy passes run (robocopy, synchronous, as always: started in
rem the background it would ignore Ctrl+C and copy on after the script was
rem stopped), a second instance of this script, started by
rem :dashboard_copy_begin, paints the block: it reads how far robocopy is
rem from its own log, which is written as the copy goes, and ends when the
rem lock file the run holds open around the passes is released. Nothing of
rem this reaches the log or a record.

:dashboard_copy_begin
rem Forensic run with the live display, before the copy passes (MAIN):
rem starts the display helper (:dashboard_helper_main), which inherits the
rem run's variables as they are now, the pass listings
rem (:count_copy_pass_files) among them; which pass runs it reads from
rem temp_dashboard_pass, written by :run_copy_pass.
if not defined dashboard_active exit /b 0
set "copy_excluded_item_count=0"
if exist "%temp_housekeeping_source%" for /f "usebackq eol=| delims=" %%L in ("%temp_housekeeping_source%") do set /a "copy_excluded_item_count+=1"
rem The length of the source evidence directory's path, cut from a listed
rem file's to give its path within the directory (the copy's detail line).
call :strlen source_with_backslash dashboard_source_prefix_length
rem Every pass's files, for the count of a pass by files
rem (:dashboard_count_listed_files); a pass whose listing failed counts 0.
set "copy_files_all_passes=0"
for %%P in (%COPY_PASSES%) do call :dashboard_add_pass_total %%P
> "%temp_dashboard_pass%" echo none
del "%temp_dashboard_helper_done%" >nul 2>&1
set "msg=running" & call :dashboard_stage copy msg
rem The copy bar's start, inherited by the helper (its time read from it).
call :dashboard_read_clock dashboard_copy_started
rem The child cmd is given the script's path by variable name ("%%" here
rem is one "%" on its command line): a child cmd expands %NAME% in its
rem command line, so a path holding "%" would be changed; the variable's
rem value is expanded once, by the child, as it is. No CALL, which would
rem expand it a second time (round 13: the helper never started).
set "evidence_robocopy_display_helper=%temp_path_prefix%"
set "evidence_robocopy_display_helper_script=%script_path%"
start "" /b "%ComSpec%" /d /v:off /c ""%%evidence_robocopy_display_helper_script%%""
set "evidence_robocopy_display_helper="
set "evidence_robocopy_display_helper_script="
exit /b 0

:dashboard_add_pass_total  passId
rem Add a pass's file count (copy_pass_<pass>_total) to
rem copy_files_all_passes, unless its listing failed ("unknown").
call :copy_variable copy_pass_%~1_total dashboard_add_pass_total_value
if "%dashboard_add_pass_total_value%"=="unknown" exit /b 0
set /a "copy_files_all_passes+=dashboard_add_pass_total_value"
exit /b 0

:dashboard_copy_end
rem After the copy passes (MAIN): wait for the display helper to notice the
rem lock's release and end (its done marker: about a second;
rem DASHBOARD_HELPER_WAIT_SECONDS at most), so the two never paint at once.
rem The copy's detail lines were the helper's own: from here on the block
rem shows none under the Copy row, as the helper's last reading may be
rem seconds old and the custody pass has none (round 12.5: "File 3 of 3
rem (87 %)" under the custody pass's row when they were taken over).
if not defined dashboard_active exit /b 0
set "dashboard_copy_waits=0"
:dashboard_copy_end_wait
if exist "%temp_dashboard_helper_done%" goto dashboard_copy_end_done
set /a "dashboard_copy_waits+=1"
if %dashboard_copy_waits% gtr %DASHBOARD_HELPER_WAIT_SECONDS% goto dashboard_copy_end_done
"%tool_ping%" -n 2 127.0.0.1 >nul
goto dashboard_copy_end_wait
:dashboard_copy_end_done
del "%temp_dashboard_helper_done%" >nul 2>&1
exit /b 0

:dashboard_helper_main
rem The display helper (MAIN: entered when evidence_robocopy_display_helper
rem holds this run's temporary path, set by :dashboard_copy_begin for the
rem moment it starts this second instance), in the same console, while the
rem first instance runs robocopy. Every second it tests the lock file the
rem first instance holds open around the copy passes: once that can be
rem opened for writing, the passes are over (or the run died) and the
rem helper ends, leaving its done marker. Every copy_progress_poll_seconds
rem (CONFIG's DASHBOARD_POLL_SECONDS, or /redraw's) it reads the pass's
rem progress from robocopy's log and redraws the block. It
rem writes nothing else: no log, no record, no console line of its own; it
rem never reads input, changes the code page or pauses.
set "dashboard_helper_waits=0"
set "dashboard_helper_lock_seen="
:dashboard_helper_loop
"%tool_ping%" -n 2 127.0.0.1 >nul
set /a "dashboard_helper_waits+=1"
if exist "%temp_dashboard_lock%" set "dashboard_helper_lock_seen=1"
if not defined dashboard_helper_lock_seen if %dashboard_helper_waits% gtr %DASHBOARD_HELPER_WAIT_SECONDS% goto dashboard_helper_end
if not defined dashboard_helper_lock_seen goto dashboard_helper_loop
rem The lock test: a second write handle on a file the first instance holds
rem open on handle 9 fails with a sharing violation while its copy passes
rem run; "(call )" is a command that does nothing, so the test only opens
rem the file. cmd reports a failed redirection outside the command's own
rem 2>nul, so the test is wrapped in a block whose 2>nul takes the message
rem (round 12.2: once a second on the console, moving the block down).
((call ) 9>>"%temp_dashboard_lock%") 2>nul && goto dashboard_helper_end
set /a "dashboard_helper_poll=dashboard_helper_waits %% copy_progress_poll_seconds"
if %dashboard_helper_poll% neq 0 goto dashboard_helper_loop
call :dashboard_read_copy_progress
call :dashboard_redraw
goto dashboard_helper_loop
:dashboard_helper_end
> "%temp_dashboard_helper_done%" echo done
exit /b 0

:dashboard_read_copy_progress
rem Caller's scope (the display helper, delayed expansion off). Which pass
rem runs (temp_dashboard_pass: "<pass> running" or "<pass> copied") and how
rem far it is, from robocopy's log as it is written. Files done: a pass run
rem without /np (PASS_<id>_PERCENTAGES) by the files robocopy has started
rem (:dashboard_count_started_files), any other pass by the lines that name
rem the source (:dashboard_count_listed_files); never more than the pass's
rem total. A pass without /np also gives the percentage of the file in
rem progress (:dashboard_read_copy_percentage). ERROR lines (each holds
rem "(0x", in any language): counted, and the last one read only when there
rem is one. A count that can't be read leaves the display as it was. The
rem helper's counts go to its own file (temp_dashboard_count), never to the
rem one the first instance uses at the same time.
set "dashboard_copy_pass_line="
if exist "%temp_dashboard_pass%" set /p "dashboard_copy_pass_line=" <"%temp_dashboard_pass%"
if not defined dashboard_copy_pass_line exit /b 0
set "dashboard_copy_pass="
set "dashboard_copy_pass_state="
set "dashboard_copy_pass_started="
for /f "tokens=1-3" %%A in ("%dashboard_copy_pass_line%") do (
    set "dashboard_copy_pass=%%A"
    set "dashboard_copy_pass_state=%%B"
    set "dashboard_copy_pass_started=%%C"
)
rem The bar's time left is from the pass's own start (:run_copy_pass).
if defined dashboard_copy_pass_started set "dashboard_copy_started=%dashboard_copy_pass_started%"
if not defined dashboard_copy_pass exit /b 0
if "%dashboard_copy_pass%"=="none" exit /b 0
call :copy_variable PASS_%dashboard_copy_pass%_LABEL dashboard_copy_pass_label
call :copy_variable PASS_%dashboard_copy_pass%_PERCENTAGES dashboard_copy_pass_percentages
call :copy_variable copy_pass_%dashboard_copy_pass%_progress dashboard_copy_pass_progress
call :copy_variable copy_pass_%dashboard_copy_pass%_total dashboard_copy_total
if "%dashboard_copy_total%"=="unknown" exit /b 0
if "%dashboard_copy_total%"=="0" goto dashboard_read_copy_progress_none
if "%dashboard_copy_pass_state%"=="copied" goto dashboard_read_copy_progress_copied
if not exist "%temp_robocopy_unicode_output%" exit /b 0
set "dashboard_copy_error_lines="
"%tool_find%" /c "(0x" <"%temp_robocopy_unicode_output%" >"%temp_dashboard_count%" 2>nul
for /f "usebackq" %%N in ("%temp_dashboard_count%") do set "dashboard_copy_error_lines=%%N"
if not defined dashboard_copy_error_lines exit /b 0
set "dashboard_copy_files_done="
set "dashboard_copy_files_started="
if /i "%dashboard_copy_pass_percentages%"=="yes" (call :dashboard_count_started_files) else call :dashboard_count_listed_files
if not defined dashboard_copy_files_done exit /b 0
set "dashboard_copy_percent_of_file=0"
set "dashboard_copy_tail_in_progress="
if /i "%dashboard_copy_pass_percentages%"=="yes" call :dashboard_read_copy_percentage
rem A pass without /np whose log's last line holds no progress has no file
rem in progress (the last one finished, or one failed): every file started
rem is done (round 12.4: the detail read "File 3 of 3 (0 %)" at the end).
rem A bytes pass then finds the files done by name (:dashboard_find_files_done).
if /i "%dashboard_copy_pass_percentages%"=="yes" if not defined dashboard_copy_tail_in_progress set "dashboard_copy_files_done=%dashboard_copy_files_started%"
if /i "%dashboard_copy_pass_percentages%"=="yes" if "%dashboard_copy_pass_progress%"=="bytes" call :dashboard_find_files_done
if %dashboard_copy_files_done% lss 0 set "dashboard_copy_files_done=0"
if %dashboard_copy_files_done% gtr %dashboard_copy_total% set "dashboard_copy_files_done=%dashboard_copy_total%"
call :dashboard_read_copy_errors
set "dashboard_copy_bar=1"
set "dashboard_copy_done_var=dashboard_copy_done"
set "dashboard_copy_total_var=dashboard_copy_bar_total"
call :dashboard_copy_detail_text
exit /b 0
:dashboard_read_copy_progress_none
set "dashboard_copy_bar="
set "dashboard_copy_text=running: %dashboard_copy_pass_label%"
set "dashboard_copy_detail=no files in this pass"
exit /b 0
:dashboard_read_copy_progress_copied
rem The pass's files are copied; the run is writing robocopy's log into the
rem record.
set "dashboard_copy_done=%dashboard_copy_total%"
set "dashboard_copy_bar_total=%dashboard_copy_total%"
set "dashboard_copy_bar=1"
set "dashboard_copy_done_var=dashboard_copy_done"
set "dashboard_copy_total_var=dashboard_copy_bar_total"
set "dashboard_copy_detail=All %dashboard_copy_total% files of this pass copied; writing robocopy's log"
exit /b 0

:dashboard_count_started_files
rem Caller's scope (:dashboard_read_copy_progress), a pass run without /np:
rem robocopy starts each file's progress on that file's own line ("  0%  ",
rem then a fragment per step, each ending in "%" and two spaces), so the
rem lines holding "%  " are the files started; the last of them is in
rem progress, the others are done. Lines of files the pass's size filter
rem skips (/v lists them) carry no percentage, so they don't count (round
rem 12.2: counting every line that names the source ran a file ahead).
rem A path holding "%  " in a skipped line would count; display only.
set "dashboard_count_started_files_value="
"%tool_find%" /c "%%  " <"%temp_robocopy_unicode_output%" >"%temp_dashboard_count%" 2>nul
for /f "usebackq" %%N in ("%temp_dashboard_count%") do set "dashboard_count_started_files_value=%%N"
if not defined dashboard_count_started_files_value exit /b 0
set "dashboard_copy_files_started=%dashboard_count_started_files_value%"
set /a "dashboard_copy_files_done=dashboard_count_started_files_value - 1"
exit /b 0

:dashboard_count_listed_files
rem Caller's scope (:dashboard_read_copy_progress), a pass with /np: the
rem lines that name the source directory are the job header's Source line,
rem one per item excluded at the source's drive root
rem (copy_excluded_item_count), one per file the pass copies or finds the
rem same (written as its copy starts), one per ERROR, and one per file the
rem pass's size filter skips (/v lists them, wherever the walk meets them).
rem Files done = those lines, less the header's, the excluded items, the
rem errors, the one in progress and every file of the other passes
rem (copy_files_all_passes less this pass's total): an undercount until
rem the walk has met them all, never ahead.
set "dashboard_count_listed_files_value="
"%tool_find%" /c /i "%source_with_backslash%" <"%temp_robocopy_unicode_output%" >"%temp_dashboard_count%" 2>nul
for /f "usebackq" %%N in ("%temp_dashboard_count%") do set "dashboard_count_listed_files_value=%%N"
if not defined dashboard_count_listed_files_value exit /b 0
set /a "dashboard_copy_files_done=dashboard_count_listed_files_value - 1 - copy_excluded_item_count - dashboard_copy_error_lines - 1 - (copy_files_all_passes - dashboard_copy_total)"
exit /b 0

:dashboard_read_copy_percentage
rem Caller's scope (:dashboard_read_copy_progress, delayed expansion off):
rem robocopy's percentage of the file in progress, from the end of the log's
rem last line (its unterminated line, reached with "more +n", cheap however
rem long the log, written to a file and read from there), into
rem dashboard_copy_percent_of_file; 0 if none. The line itself is kept in
rem dashboard_copy_tail (empty if it couldn't be read).
set "dashboard_copy_tail="
set "dashboard_copy_lines_total="
"%tool_find%" /c /v "" <"%temp_robocopy_unicode_output%" >"%temp_dashboard_count%" 2>nul
for /f "usebackq" %%N in ("%temp_dashboard_count%") do set "dashboard_copy_lines_total=%%N"
if not defined dashboard_copy_lines_total exit /b 0
set /a "dashboard_copy_tail_skip=dashboard_copy_lines_total - 1"
if %dashboard_copy_tail_skip% lss 0 exit /b 0
"%tool_more%" +%dashboard_copy_tail_skip% "%temp_robocopy_unicode_output%" >"%temp_dashboard_copy_tail%" 2>nul <nul
for /f "usebackq delims=" %%L in ("%temp_dashboard_copy_tail%") do set "dashboard_copy_tail=%%L"
if not defined dashboard_copy_tail exit /b 0
call :dashboard_percentage_from_tail
exit /b 0

:dashboard_percentage_from_tail
rem Caller's scope: the percentage at the end of dashboard_copy_tail, the
rem last of robocopy's fragments (CR, the percentage right-aligned, "%",
rem two spaces: "<CR> 38%  ", or with a decimal, "<CR> 38.5%  "), whole
rem percent only, into dashboard_copy_percent_of_file; 0 if the line
rem doesn't end with one. Each CR becomes a space (through a FOR variable:
rem the CR can't be written in the file), so the number is the last word
rem before the "%". dashboard_copy_tail_in_progress is defined when the
rem line ends with a fragment (a file in progress).
setlocal EnableDelayedExpansion
set "percent=0"
set "in_progress="
set "tail=!dashboard_copy_tail!"
if not "!tail:~-3!"=="%%  " goto dashboard_percentage_from_tail_done
set "in_progress=1"
for %%R in ("!carriage_return!") do set "tail=!tail:%%~R= !"
set "tail=!tail:~-12,-3!"
for %%W in (!tail!) do set "percent=%%W"
for /f "delims=." %%I in ("!percent!") do set "percent=%%I"
for /f "delims=0123456789" %%X in ("!percent!") do set "percent=0"
if !percent! gtr 100 set "percent=100"
:dashboard_percentage_from_tail_done
endlocal & set "dashboard_copy_percent_of_file=%percent%" & set "dashboard_copy_tail_in_progress=%in_progress%"
exit /b 0

:dashboard_find_files_done
rem Caller's scope (:dashboard_read_copy_progress, delayed expansion off), a
rem bytes pass run without /np: the files done, found by name in the pass's
rem table (:dashboard_find_file_in_line). With a file in progress (the log's
rem last line, dashboard_copy_tail, ends with a progress fragment), the
rem files before it. With none (the last file started has finished or
rem failed, and robocopy has moved on, e.g. to listing the files the pass's
rem size filter skips), the files up to and including the last one
rem started: the last line holding "%  ", read from find's output in a file
rem (no path on a child command line). The count of files started alone
rem falls one short for every file robocopy could not open (it gets no
rem progress): round 12.3 named the failed file while the next one copied,
rem round 12.5 read "File 3 of 3 (0 %)" after the last one had finished.
rem Not found (the line is robocopy's retry notice or a summary line): the
rem count stands.
if not defined dashboard_copy_tail_in_progress goto dashboard_find_files_done_none_in_progress
call :dashboard_find_file_in_line dashboard_copy_tail
if defined dashboard_copy_file_found set /a "dashboard_copy_files_done=dashboard_copy_file_found - 1"
exit /b 0
:dashboard_find_files_done_none_in_progress
set "dashboard_copy_last_started_line="
"%tool_find%" "%%  " <"%temp_robocopy_unicode_output%" >"%temp_dashboard_started_lines%" 2>nul
for /f "usebackq delims=" %%L in ("%temp_dashboard_started_lines%") do set "dashboard_copy_last_started_line=%%L"
if not defined dashboard_copy_last_started_line exit /b 0
call :dashboard_find_file_in_line dashboard_copy_last_started_line
if defined dashboard_copy_file_found set "dashboard_copy_files_done=%dashboard_copy_file_found%"
exit /b 0

:dashboard_find_file_in_line  lineVar
rem Caller's scope (:dashboard_find_files_done): the index in the pass's
rem table of the file whose path ends the named line of robocopy's log
rem before its first CR (a file's line, "...<TAB><path>", then its progress
rem fragments), into dashboard_copy_file_found; empty if none matches. It
rem is looked up from the count of files started onwards: a file's place in
rem the table is never before its place among the files started, as a file
rem robocopy could not open never starts. The line is compared by position
rem (lengths from :strlen), never cut by FOR /F, so a "!" in a path stays.
setlocal EnableDelayedExpansion
set "line=!%~1!"
set "after_first_cr="
for %%R in ("!carriage_return!") do set "after_first_cr=!line:*%%~R=!"
call :strlen line line_length
set "path_end=!line_length!"
if not "!after_first_cr!"=="!line!" (
    call :strlen after_first_cr after_length
    set /a "path_end=line_length - after_length - 1"
)
set "found="
set /a "first_index=dashboard_copy_files_started"
if !first_index! lss 1 set "first_index=1"
for /l %%N in (!first_index!,1,%dashboard_copy_total%) do if not defined found (
    set "name=!copy_pass_%dashboard_copy_pass%_file_%%N_name!"
    set "name_length=!copy_pass_%dashboard_copy_pass%_file_%%N_name_length!"
    set /a "name_start=path_end - name_length"
    if !name_start! geq 0 for %%S in (!name_start!) do for %%L in (!name_length!) do if "!line:~%%S,%%L!"=="!name!" set "found=%%N"
)
endlocal & set "dashboard_copy_file_found=%found%"
exit /b 0

:dashboard_read_copy_errors
rem Caller's scope (:dashboard_read_copy_progress, delayed expansion off):
rem the copy's second detail line, dashboard_copy_error_text: empty while
rem robocopy has written no ERROR line; otherwise their count and the last
rem one (read only then, from find's output in a file: no path on a child
rem command line). Only the outcome counts: the Copy check's result comes
rem from robocopy's exit code, as always.
set "dashboard_copy_error_text="
if "%dashboard_copy_error_lines%"=="0" exit /b 0
set "dashboard_copy_last_error="
"%tool_find%" "(0x" <"%temp_robocopy_unicode_output%" >"%temp_dashboard_error_lines%" 2>nul
for /f "usebackq delims=" %%L in ("%temp_dashboard_error_lines%") do set "dashboard_copy_last_error=%%L"
call :dashboard_error_text
exit /b 0

:dashboard_error_text
rem Caller's scope: dashboard_copy_error_text from the count and the last
rem ERROR line, which starts at its "ERROR" word (robocopy's local time
rem before it is left out; a line in another language is shown whole).
setlocal EnableDelayedExpansion
set "text=!dashboard_copy_last_error!"
if defined text set "text=!text:*ERROR=ERROR!"
endlocal & set "dashboard_copy_error_text=ERROR lines: %dashboard_copy_error_lines%; latest: %text%"
exit /b 0

:dashboard_copy_detail_text
rem Caller's scope (:dashboard_read_copy_progress): the bar's done and total
rem (dashboard_copy_done, dashboard_copy_bar_total) and the line under the
rem copy's bar. A files pass: files done of the total. A bytes pass: MB
rem done, plus the share of the file in progress that its percentage gives,
rem of the MB in all; the line gives the file in progress, its percentage
rem (a pass without /np), the GB done and in all, and the file by its path
rem within the evidence directory, after the directory's own name (owner,
rem 2026-10-19: "EV03\EV03.E02"), its end if it doesn't fit.
set /a "dashboard_copy_current=dashboard_copy_files_done + 1"
if %dashboard_copy_current% gtr %dashboard_copy_total% set "dashboard_copy_current=%dashboard_copy_total%"
rem Every file done: the last one is shown at 100 %.
if %dashboard_copy_files_done% geq %dashboard_copy_total% set "dashboard_copy_percent_of_file=100"
if "%dashboard_copy_pass_progress%"=="bytes" goto dashboard_copy_detail_bytes
set "dashboard_copy_done=%dashboard_copy_files_done%"
set "dashboard_copy_bar_total=%dashboard_copy_total%"
set "dashboard_copy_detail=%dashboard_copy_pass_label%: %dashboard_copy_files_done% of %dashboard_copy_total% files"
exit /b 0
:dashboard_copy_detail_bytes
setlocal EnableDelayedExpansion
set "done_mb=0"
if %dashboard_copy_files_done% gtr 0 for %%N in (%dashboard_copy_files_done%) do set "done_mb=!copy_pass_%dashboard_copy_pass%_file_%%N_cumulative_mb!"
for %%N in (%dashboard_copy_total%) do set "total_mb=!copy_pass_%dashboard_copy_pass%_file_%%N_cumulative_mb!"
for %%N in (%dashboard_copy_current%) do (
    set "current_name=!copy_pass_%dashboard_copy_pass%_file_%%N_name!"
    set "current_end_mb=!copy_pass_%dashboard_copy_pass%_file_%%N_cumulative_mb!"
)
for %%P in (!dashboard_source_prefix_length!) do set "current_name=!evidence_directory_name!\!current_name:~%%P!"
set /a "bar_done=done_mb + (current_end_mb - done_mb) * dashboard_copy_percent_of_file / 100"
call :dashboard_gb_text bar_done done_gb
call :dashboard_gb_text total_mb total_gb
set "percent_text="
if /i "%dashboard_copy_pass_percentages%"=="yes" set "percent_text= (%dashboard_copy_percent_of_file% %%)"
set "detail_start=File %dashboard_copy_current% of %dashboard_copy_total%!percent_text!, !done_gb! of !total_gb! GB: "
call :strlen detail_start detail_start_length
set /a "name_room=OUTPUT_WIDTH - 4 - detail_start_length"
if !name_room! lss 8 set "name_room=8"
set /a "name_tail_length=name_room - 3"
for %%N in (!name_room!) do if not "!current_name:~%%N!"=="" for %%T in (!name_tail_length!) do set "current_name=...!current_name:~-%%T!"
endlocal & set "dashboard_copy_done=%bar_done%" & set "dashboard_copy_bar_total=%total_mb%" & set "dashboard_copy_detail=%detail_start%%current_name%"
exit /b 0

:dashboard_gb_text  mbVar  outVar
rem "n.n" GB (decimal, 1000 MB) from a count of MB, rounded to the nearest
rem tenth (owner, 2026-10-19: 3.99 GB reads 4.0).
setlocal
set "tenths="
set /a "tenths=(%~1 + 50) / 100" 2>nul
if not defined tenths set "tenths=0"
set /a "whole=tenths / 10, fraction=tenths %% 10"
endlocal & set "%~2=%whole%.%fraction%"
exit /b 0
