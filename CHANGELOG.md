# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 2.3.1 - 2026-10-20

### Changed
- The live display's bars show an estimate of the time left, in hours and
  minutes, from the average rate since that stage began (each copy pass
  on its own), in place of the time elapsed; "estimating" for the first
  minute and the first 1 %. The bars are two characters shorter to fit.
- The copy's detail line names the file by its path within the evidence
  directory, after the directory's own name (`EV03\EV03.E02`), rather than
  by the end of its source path.
- A display line too long for the console ends in "..." where it is cut
  (the summary holds it in full); the Run records row before the copy
  reads "checked before the copy; after it: waiting".
- The note on real-time antivirus scanning is now a warning, listed up
  front with the others and in the live display from its start. It is
  given when Microsoft Defender's real-time protection appears to be on:
  its engine is running and no setting that turns it off is found (Group
  Policy settings count only while Tamper Protection is off, as Defender
  ignores them otherwise). Best efforts: another antivirus gives none.
- Removed from the banner: the note on real-time scanning (above), and the
  reminder that a travelled copy of the script should match the published
  release (the Script check and the log's Script SHA-256 cover it).
  Removed before the source prompt: "The evidence directory is copied,
  under its own name, into a set directory."
- The Hash check's detail line for paths too long reads "paths too long:
  1 source, 1 destination", so it stays on one line.

### Fixed
- A set directory whose path is longer than about 170 characters put its
  custody files past 260 characters, which findstr, find and fc can't open
  by path: a copy from or to it failed (Run records FAIL), named as a
  history mismatch, and the source was hashed anew as the reference
  record. Custody files are now read through a byte-for-byte copy in TEMP.
- When an attribute carried over onto the destination evidence directory
  (Hidden, System, Read-only) couldn't be cleared (attrib doesn't reach a
  directory past 260 characters), the log said it was cleared and then
  warned that it wasn't. Each attribute is now reported as the directory
  has it after the attempt: cleared, or a warning.

## 2.3.0 - 2026-10-19

Known issue (in every release so far, fixed in 2.3.1): a set
directory whose path is longer than about 170 characters puts its custody
files past 260 characters, which cmd's tools can't open; a copy from or to
it fails (Run records FAIL, exit 1), but the failure is named as a history
mismatch and the source is hashed anew as the reference record. The
evidence files inside the set are not affected.

### Added
- A live display on the console while a forensic run works (Windows 10 or
  later, not the legacy console): each check of the result block with its
  status or a progress bar, the file being copied (with robocopy's
  percentage within each large file) or hashed, and the last warnings and
  failures, redrawn in place every 5 s. Console only: the log and every
  record are written as before. `EVIDENCE_ROBOCOPY_PLAIN`, set to anything,
  gives the previous console output instead, as `NO_COLOR` turns colour off.
- A log kept from a run aborted before its header now records the version,
  the Script SHA-256, the start time, host, user and the directories given.

### Changed
- The clock check goes by the time service's last synchronisation: a run
  warns when it is older than 7 days (`CLOCK_SYNC_MAX_AGE_HOURS`) or not
  known, and the header's "Last time sync" says how long ago it was. The
  time service starts and stops on demand and keeps no record of a sync
  from before it last started; that state was reported as "not
  synchronised" even shortly after the clock had been synchronised. The
  warning now reads "The clock's accuracy can't be confirmed (...)" with
  the reason.
- With the live display, robocopy's console output is discarded: its
  per-file lines no longer scroll on the console; its log is written as in
  a plain run. The header's Progress field says what the console showed.
  The large-file pass runs without `/np` (its Options line shows it), so
  its percentages can be shown live; they are left out of the log, each of
  its file lines cut at robocopy's first progress mark.
- The checks after the copy run in the result block's order: metadata,
  then the run records (the custody files are hashed first; that section is
  now titled "Run records: hashing the custody files ..."), then the SHA-256
  hashing and compare. Before, the evidence was hashed before the run
  records were checked.
- A copy pass with no file in its size class is skipped, with a line in the
  log saying so; the last pass always runs, so robocopy still creates every
  directory. On a set of 100,000 small files the large-file pass took about
  108 s to copy nothing.
- Robocopy's output is written into the log in one step when it holds no
  ERROR line (about 100 s less for a log of 100,000 lines); with ERROR
  lines it is rewritten line by line as before. The bytes are the same.

### Fixed
- A file whose full path was about 8,170 characters or longer was left out
  of both hash records without a word, so a run could PASS without
  verifying it (cmd skips a FOR /F iteration whose expanded command would
  pass 8,191 characters; in every release so far). A path of about 4,100
  characters or more emptied both hash records (sort's record limit) and
  the run failed with "Nothing was verified", naming no file. Now a file
  whose full path, on either side, is over 4,000 characters
  (`MAX_FILE_PATH_LENGTH`) is not hashed and fails the run by name (the
  first 200 characters of its path); every listing is read numbered, so a
  line cmd can't carry is refused by name too, and the files listed are
  counted against the files hashed or refused. The hash records' and the
  comparison's rows are counted after sorting, a run record's files
  against their listing, and robocopy's output lines against those
  written into the log: a shortfall fails the run.
- A file certutil couldn't read once was recorded UNREADABLE for good: in a
  first copy that is the set's reference record, and every later copy of
  the set fails on that file. It is now hashed again after 2 s, with both
  attempts noted in the log; a file that fails twice is UNREADABLE as before.
- A robocopy exit code outside robocopy's own range (a stopped or failed
  robocopy, e.g. -1073741510 after Ctrl+C) was decoded bit by bit into
  misleading lines ("Fatal error: nothing was copied ...", "Extra files
  ..."); it now reads "Robocopy ended abnormally (exit code n)". Such a
  code also fails the Copy check, and makes the metadata check and a file
  listing incomplete, whatever its bits: before, a negative code let a
  listing count as complete, and a code without the failure bits let the
  Copy check pass (the hash check still failed the run).

## 2.2.1 - 2026-10-18

Known issue (in every release so far, fixed in 2.3.0): a file whose full
path is about 8,170 characters or longer is left out of both hash records
without any failure, so a run can PASS without verifying it; a path of
about 4,100 to 8,170 characters empties both hash records and the run
fails with "Nothing was verified".

### Changed
- The closing lines give the log's file name, then its directory on a line
  of its own, so an 80-column console doesn't split the path.

### Fixed
- Hashing is back to 2.1.1's speed, slightly faster: the per-file progress
  line on screen is written directly when it fits.
- On screen, colour marks statuses only: PASS, FAIL, NOT RUN, `[FAIL]` or
  `[WARN]` in a file name stay plain. The summary's Reference record shows
  a failed seal check in red, like every other status.

## 2.2.0 - 2026-10-17

Known issues (fixed in 2.2.1): hashing many small files is about 14 %
slower than in 2.1.1 (the per-file progress line on screen). On screen,
PASS, FAIL, NOT RUN, `[FAIL]` or `[WARN]` in a file name can be coloured as
if it were a status; the words, the log and the records are not affected.

### Added
- Console colour where the console supports it: PASS green, WARN yellow,
  FAIL red, the verdict bold; never in the log or records. `NO_COLOR` turns
  it off.
- A "Record written" line in the result block on screen, after the run
  record is written back; a record that wasn't written in full makes the
  run FAIL.

### Changed
- Lines the script writes itself keep within 79 characters, broken at
  spaces with a hanging indent; hashes and long paths stay whole. A hash
  that doesn't fit where a field continues starts at column 5 instead, so
  an 80-column console doesn't split it. The help and the notices before
  the copy continue indented too; the help lists the exit codes one per
  line.
- Sections open with a rule and a title named after the check they belong
  to (Script, Copy, Metadata, Run records, Hash (SHA-256), Record written).
- The summary ends with a result block: the verdict, each check, a pointer
  to the section and list that explain anything not passed, and the
  warning and failure counts. Warnings, failures and the closing sentence
  come before it; on screen it is the last thing shown, before the seal's
  SHA-256 and the log's location, and its counts include the warnings and
  failures of writing the record back.
- When the record couldn't be sealed or written back, the closing lines say
  that it is kept in TEMP, not in the destination, and give its seal's
  SHA-256 without asking for it to be recorded as the set's record (before,
  they read as for a completed record).
- The Hash check leads with the reason when nothing was verified (the
  reference record lists no files), and points to Run records when the
  reference can't be relied on.
- The Hash check's counts are listed one per line.
- The seal SHA-256 of the reference record, of each run record and of the
  previous run is shown on its own line.
- An aborted run ends with a result block naming the reason.
- The run records are checked before the copy as fully as after it, on the
  set whose history the copy continues (every run record against its seal
  too); anything found is a header warning. One checker now does the check
  before the copy, the warnings and the check after it.
- Run records findings are worded the same before and after the copy; a run
  record's sealed history is compared with "the history this run
  continues". Warnings about the Run records check made before the copy
  all end "will fail".
- A warning already listed isn't listed again.
- The summary's Script copy line reads FAIL, not FAILED, when no verified
  copy was placed.

### Fixed
- A history row whose run cell isn't a run's UTC time is a Run records
  failure; it was used as a directory name.

## 2.1.1 - 2026-10-16

### Added
- A warning when a volume's file system can't be read (e.g. the system
  volume when not elevated): times are then compared exactly, so a FAT or
  exFAT volume could fail the metadata check.

### Changed
- The header's Warnings section says that findings made after the copy
  (such as links not copied) are in the summary.
- The summary lists the checks in the order they run: Script, Copy,
  Metadata, Run records, Hash (SHA-256); the closing sentence names failed
  checks in that order. "Copy (robocopy)" is now "Copy".
- An aborted run shows its reason once; a second custody pass with extra
  items in the destination refers to the first one's explanation.

### Fixed
- A file planted in a run record under a name with a `!` that reduces to an
  ignored name (e.g. `!._x`, `desk!top.ini`) was not checked against the
  seal, so the Run records check could pass with an unsealed file present.
- A seal line naming a file with a `!` was read without it, so that file
  was reported missing.
- A drive-root first copy from a volume whose label holds a `!` named the
  set without it.

## 2.1.0 - 2026-10-16

Known issue (fixed in 2.1.1): a file planted in a run record under a name
with a `!` that reduces to an ignored name (e.g. `!._x`, `desk!top.ini`) is
not checked against the seal, so the Run records check can pass with an
unsealed file present. It needs a deliberate plant; evidence files and their
hashes are not affected.

### Changed
- Source and destination paths containing `%` are refused at the prompt;
  a drive-root first copy whose volume label contains `%` is named after
  the volume serial instead.
- A file in the evidence directory that the reference record doesn't list
  (added since) now fails a forensic run; it was a warning.
- A run record that couldn't be sealed completely now fails the run, and
  none of it is written to the destination; it was a console warning. The
  history the run continued is written there unchanged, as when the
  write-back fails.
- The Location check warns when it can't be made because the source set's
  history can't be used; it was skipped silently.
- A confirmed rerun or update no longer warns that the destination wasn't
  empty (the header records it).
- Metadata is compared to 2 s when a network share is involved (robocopy's
  /fft), as it is for FAT and exFAT.
- Run records that predate a restarted history are listed in one warning.
- The banner says to check a travelled copy of the script against the
  published release.

### Fixed
- A file whose name ends in a dot or space (e.g. `report.` beside `report`)
  was hashed under the name Windows normalises it to: the other file's hash,
  so a changed copy could pass. Files are now hashed through the
  extended-length path form, which also verifies paths over 260 characters
  (previously UNREADABLE) and names such as `nul`.
- With a `!` in the destination path, a file added to a sealed run record
  went unreported (the path lost its `!` and the check skipped it). Run
  record files are now listed with delayed expansion off, and a file whose
  place in a run record can't be worked out fails the check.
- A history edited by hand or crafted with a `"` in a cell could run a
  command while being read. History cells and the Script SHA-256 read from
  a log are now treated as data only.
- A `!` in an evidence directory's name was dropped from its copy's name.
- An evidence directory name containing `%` inside a set is refused, like
  typed paths; so is a script path containing `%`.
- On a rerun, a source whose history was unusable restarted the history and
  listed the destination's good run records as outside it; the
  destination's history is now continued, and the copy fails for the
  source's problem.
- Every row of the reference record must now be matched or reported, or
  the Hash check fails; an "unknown" volume serial is no longer compared in
  the location check (a warning says so); a run record listed without a
  seal by a history restart is no longer reported as changed when it still
  has none.
- An evidence file name containing `%NAME%` for a defined variable (e.g.
  `x %OS% y.txt`) was hashed under the expanded name: UNREADABLE, or the
  hash of another file with that name, which could let a changed copy pass.
  Hashing no longer passes file names through a child command line (the
  known issue of 2.0.1 and earlier).
- A set on a network path (UNC or a mapped drive) was refused as a source
  or rerun destination: there, Windows reports a file as a directory when
  asked with a trailing `\`, so the history and the script copy counted as
  evidence directories. Directories are now told by their attributes.
- With the console input closed, a source refused by the set rules after
  Enter (the script's directory) was asked again forever; answers refused
  by the set rules now count towards the prompt's attempts limit.
- A link inside a link that wasn't copied could be listed again as a
  separate warning.
- Wording: the Script check names a previous log that holds no valid Script
  SHA-256 instead of calling it a different SHA-256; /nonforensic compare
  lines say "the source", not "the reference record".
- Wording: the `.partial` line in the Run records log carries "[WARN]"; the
  warning for a run record outside a restarted history now says "its seal
  file still has the SHA-256 listed for it (its files are checked against
  that seal separately)".

## 2.0.1 - 2026-10-16

Known issue (in every release so far, fixed in the next): an evidence file
whose name contains `%NAME%` for a defined environment variable (e.g.
`x %OS% y.txt`) is hashed under the expanded name. It is reported
UNREADABLE (the copy fails) or, if a file with the expanded name exists in
the same directory, gets that file's hash, so a changed copy could pass.

### Added
- A junction or symbolic link in the source that isn't copied (robocopy
  `/xj`) is listed as a warning.

### Fixed
- A set whose records directory held only an interrupted write-back
  (`<run>.partial`) was treated as having run records but no history, so
  copying it on always failed; it now counts as having no earlier runs, with
  the `.partial` warned about up front.
- A first copy from a drive root always failed ("Could not create the
  destination set directory"): the volume label wasn't read.
- Logs of runs with a robocopy ERROR had CR CR LF line endings after the
  error text; records are CRLF throughout again.
- Answers piped to the prompts were lost: `chcp` and `fsutil` no longer
  read the console input.
- "Row n of the history" in Run records messages was one too high.
- An empty evidence directory failed without listing the reason with the
  failures.
- `/nonforensic` header: the script's SHA-256 is shown, and the Writes line
  no longer mentions custody records.
- A leftover `.partial` run record is listed once in the summary warnings,
  not twice.
- Wording: "S1" in the help, capitalised failure lines, the abort for
  unrelated histories, robocopy's ERROR times labelled as local, the
  custody-pass note on extra items, a run record lost with its drive (said
  "nothing is there" when the drive couldn't be read), the Metadata result
  when there were no files to compare, the history fallback warning (read as
  if the source's history were replaced), and the volume line's "no
  label.;".

## 2.0.0 - 2026-10-15

Changes the contract: how sets are laid out, the records and their names,
and `/nonforensic`. Records made by 1.5.x and earlier aren't read: a 1.x set
(the script beside the evidence files) is refused, and without the script it
is copied as raw evidence, starting a new reference record.

### Added
- Set and evidence directories: the evidence is copied as one directory,
  under its own name, into a set directory that also holds the custody files
  (script, history, records directory). Rules S1-S4 (source) and D1-D4
  (destination) decide which set is copied and where it goes; sets are never
  mixed.
- Run records: each run writes its log, hash CSVs (evidence, and custody
  files separately) and history into
  `evidence-robocopy-records\<run UTC>\`, sealed, written as `.partial` and
  renamed once read back.
- History: one row per run (`evidence-robocopy-history.csv`), sealed in
  every run record; each run fills in the previous run's seal SHA-256. Every
  copy checks every run record against its seal and the history (new "Run
  records" check). A history beside the evidence that is missing or doesn't
  match is set aside for the newest sealed history, if that matches, and
  the copy fails.
- Script check against the previous run: newer version warns; older
  version, or the same version with a different SHA-256, fails.
- Location check: a source set moved or copied by other means since the run
  that made it is flagged.

### Changed
- Records are UTF-8 (console switched to code page 65001 for the run) with
  CRLF line endings; every CSV cell is quoted; files are named
  `evidence-robocopy_<UTC>...`.
- A forensic run stops if no UTC time can be read.
- `/nonforensic` is a plain copy utility: ETA progress, no log, no records,
  optional verification shown on screen only, no default source.
- Evidence counts never include custody files.
- The script copy beside the evidence is the script that ran, unless the
  source set's copy is a newer version; never copied and then overwritten.
- If the run record can't be written to the destination, the exit code is
  FAIL (the files stay in TEMP).
- The destination must be an existing directory, in both modes.
- "Directory" replaces "folder" in all output and documentation.
- Help text no longer says what kinds of files it copies.

### Fixed
- Names outside the console's old code page are hashed and logged
  correctly (were UNREADABLE, so the copy failed).

## 1.5.2 - 2026-10-14

### Changed
- In ETA mode (`/nonforensic`, no log) the script no longer places a copy
  of itself in the destination: the copy carries no custody record for it
  to travel with.

### Fixed
- The end-of-run list of warnings and failures was shown on screen only.
  It is now part of the summary, in the log too: warnings that didn't fail
  the run just above the overall result, everything that failed it just
  below.

## 1.5.1 - 2026-10-14

### Changed
- Script rewritten for review: full-word names that match what each
  variable holds or each function does, one meaning per variable, inputs
  passed as parameters, forensic defaults set visibly in MAIN, no clever
  constructs. CONFIG tables renamed accordingly (see README, Extending).
  Output unchanged, except that an empty reference record now says so.

## 1.5.0 - 2026-10-14

### Added
- A reference record carried with the evidence is checked against its own
  run's seal before use: changed, unlisted or unhashable fails the hash
  verification; no seal is a warning. The seal's SHA-256 is logged.

### Changed
- Small files are copied unbuffered too (`/j`), and the log, CSVs, seal and
  script copy are staged in TEMP, then written to the destination
  unbuffered and read back: verification reads every file from the drive,
  not from the Windows cache. Slower on many small files.
- User (with SID) and host are read from `whoami` and `hostname` instead of
  environment variables.
- Help and header describe evidence of any kind and both checks; the
  antivirus banner line states its effect on the copy.
- Summary: the overall result and exit code, with the copy, metadata and
  hash checks beneath it in the order they run, and a closing line stating
  what it covers. The no-seal warning is shown up front.

### Fixed
- The hashing progress counter's total was one too high (it counted a
  blank line in robocopy's listing).

## 1.4.0 - 2026-10-14

### Added
- `/nonforensic`: asks whether to keep a log and whether to verify, each
  with a confirmation, as before. Any other argument stops the run.
- The script travels with the evidence: Enter at the source prompt picks
  the script's folder; run from elsewhere, it places a verified
  copy of itself beside the logs. Script copies at a root are custody
  records, not evidence.

### Changed
- Forensic mode is the default: a log file is kept and every file is
  verified without asking; only the source and destination are prompted.
  The log header records the mode.
- Summary names each check (Hash (SHA-256), Metadata) and is grouped;
  shorter path prompts with the default path shown above the prompt;
  licence in the banner.

### Fixed
- A robocopy pass that copied nothing (exit code 0) is reported as "No files
  were copied in this pass", not as the destination already matching.

## 1.3.1 - 2026-10-13

### Changed
- The OS is named by product, edition and release (e.g. "Microsoft Windows
  11 Pro 25H2"), without the build.
- A source without a hash record is reported neutrally, with a warning,
  instead of being described as a first copy.
- Clearer log: source and destination hashing have their own headings;
  tidier clock and metadata wording.

## 1.3.0 - 2026-10-12

### Added
- At a drive root, more volume housekeeping is skipped: older Windows
  recycle bins, macOS and Linux trash, index and metadata folders, and root
  files such as `.DS_Store`, `._*` and `Thumbs.db`. Only items actually
  present are excluded, by exact path, and the log lists each one.
- Warning when a drive root holds recovered fragments (`FOUND.nnn`,
  `LOST.DIR`); they are copied as contents.

## 1.2.2 - 2026-10-12

### Fixed
- The summary reports the SHA-256 comparison and the metadata check
  separately, and a FAIL names the check that failed.
- Temporary files fall back to TMP or LOCALAPPDATA\Temp, never the
  destination, if TEMP is unset.
- The hashing progress total no longer counts this run's own files.

## 1.2.1 - 2026-10-12

### Added
- Metadata check after the copy: robocopy compares every source file with
  its copy (list-only); a differing size or last-modified time, or a file
  not copied, fails verification. Times to 2 s where FAT/exFAT is involved.

### Changed
- Scope: evidence of any kind, with E01/EWF image sets first and loose
  files (e.g. eDiscovery collections) supported.

## 1.2.0 - 2026-10-12

### Added
- Reference record: the source's oldest source hash record, or on a first
  copy a new one made from the source. Every copy is checked against it.
- Seal: `robocopy_<UTC>.sha256` holds the SHA-256 of the run's log and CSVs;
  its own SHA-256 is shown for chain-of-custody notes.
- Log header in sections (warnings, environment, source, destination), with
  the Windows name and release, and the time source and last sync. All
  pre-copy warnings (sleep, lid, clock, file system, non-empty destination)
  are listed together at the top and repeated in the summary.

### Changed
- Verification hashes the destination against the reference record; the
  source is hashed only on the first copy. The summary states what the
  result covers.
- Exact byte sizes in the log (`/bytes`). A failed file is retried once
  after 2 s (was twice, 5 s apart).
- ETA mode (no log) and declining verification must each be confirmed,
  and are marked as not for evidence.

## 1.1.1 - 2026-10-12

### Fixed
- `$RECYCLE.BIN` and `System Volume Information` are skipped only when the
  source or destination is a drive root. In a folder (or on a UNC path) they
  are evidence content and are copied.

## 1.1.0 - 2026-10-12

### Fixed
- Verification compares every file by relative path, including Hidden and
  System files and awkward names (`!` `%` `&`, spaces). Unhashable files are
  reported as UNREADABLE, never as a match; zero-byte files hash correctly.
- Robocopy's exit code is checked. Each run ends with PASS / FAIL /
  UNVERIFIED and exit code 0 / 1 / 2.
- Output names use UTC (`robocopy_YYYYMMDDTHHMMSSZ.*`) without needing wmic.
  The small-file pass uses half the logical processors, as intended.

### Changed
- Attributes are copied (`/copy:DAT /dcopy:DAT`, `/A-:SH` removed), empty
  folders too (`/e`); junctions are not followed (`/xj`); failed files are
  retried. Only the destination folder's own carried-over attributes are
  cleared.
- Log header records script hash, host, user, volumes, power settings and
  options. The log is kept in `%TEMP%` until the end of the run.
- Paths are normalised and checked for overlap. A non-empty destination
  must be confirmed. Warnings for sleep settings and FAT destinations.

## 1.0.3 - 2025-06-05

### Added
- Optional SHA-256 verification after the copy: `certutil` hashes every file
  in source and destination into `robocopy_<timestamp>_hashes_source.csv` and
  `..._hashes_destination.csv` (written to the destination). The two CSVs are
  then hashed and compared, and the result shown on screen.

### Changed
- Both passes append to a single `robocopy_<timestamp>.log` (`/log+`), replacing
  the separate `_large_files` / `_small_files` logs.

## 1.0.2 - 2024-10-14

### Fixed
- Small-file pass passed an empty `/mt:` value (undefined `num_threads`,
  introduced in 1.0.1). It now uses the logical processor count. Note: it uses
  all of them, not half as the comment says.

### Changed
- `::` comments moved out of parenthesised blocks.

## 1.0.1 - 2024-09-26

### Added
- Choice between a log file (`/np /tee /log`) or on-screen ETA and percentage
  (`/eta`, no log file).

### Changed
- The large/small menu is replaced by two automatic passes split at 100 MiB:
  files of 100 MiB or more with `/j /mt:1`, smaller files multithreaded.
  Each pass writes its own log (`_large_files`, `_small_files`).
- Reminder to disable AV real-time scanning is now always shown at start.

## 1.0.0 - 2024-09-26

### Added
- Menu to choose between large files (`/j`, `/mt:1`) and small files (`/mt:` at
  half the logical processor count, plus a reminder to disable AV real-time
  scanning).
- Excludes `$RECYCLE.BIN` and `System Volume Information` at the source drive
  root, so copying a whole evidence drive no longer copies its recycle bin.
- `/A-:SH` (clear Hidden and System on copied files), to stop the destination
  folder from ending up hidden when the source is a drive root.

### Changed
- One robocopy command line built from the admin check and menu choice,
  instead of two hard-coded variants.
- Source and destination are quoted with a trailing space, so that a trailing
  backslash (e.g. `E:\`) does not escape the closing quote.

## 0.9.0 - 2024-09-19

### Added
- Interactive prompts for source and destination.
- Robocopy tuned for large evidence files (E01, VMs): `/s /copy:DT /dcopy:DT
  /r:0 /w:0 /mt:1 /j /x /v /ts /fp /tee /np`, logging to
  `robocopy_<timestamp>.log` in the destination.
- Backup mode (`/b`) when running elevated (detected with `fsutil dirty query`).
