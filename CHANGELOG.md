# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
