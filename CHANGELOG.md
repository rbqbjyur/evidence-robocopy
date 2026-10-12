# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Entries up to and including 1.0.3 were reconstructed retrospectively from the
archived scripts. Their dates are the files' last-modified times (UTC), not
recorded release dates. Before the archived scripts were imported, only three
things were changed: the script name and author lines, an added SPDX licence
line, and the version string of 0.9.0. The code is unchanged.

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

Recovered as a variant labelled "1.0.0b" that reported itself as 1.0.0. Its
content shows it is a pre-release of 1.0.0: everything in it is in 1.0.0, it
has none of the features 1.0.0 added, and 1.0.1 builds on 1.0.0, not on this
file. It is numbered 0.9.0 here.

### Added
- Interactive prompts for source and destination.
- Robocopy tuned for large evidence files (E01, VMs): `/s /copy:DT /dcopy:DT
  /r:0 /w:0 /mt:1 /j /x /v /ts /fp /tee /np`, logging to
  `robocopy_<timestamp>.log` in the destination.
- Backup mode (`/b`) when running elevated (detected with `fsutil dirty query`).
