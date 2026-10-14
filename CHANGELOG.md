# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
