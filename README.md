# evidence-robocopy

A Windows batch wrapper around robocopy for copying forensic disk images
(E01/EWF, single or split) between drives as they move around a lab:
master to working copies, to servers, to archive. Each copy is verified by
SHA-256 and leaves a log and hash records with the evidence, so the records
of every copy travel with it and support its chain of custody.

It is a batch file on purpose: it uses only tools built into Windows and runs
wherever robocopy does, including workstations where PowerShell or `.ps1`
scripts are restricted, so it can travel with the evidence too.

## What it does

- **SHA-256 verification against a reference record.** On the first copy
  of an evidence set (no hash record in the source yet), the source is
  hashed and recorded. That record is the reference for this and every
  later copy: each copy hashes its destination with `certutil` and compares
  every file by relative path, so it is checked back to the original record,
  not only to its immediate source. Later copies don't hash the source again.
  Files that differ, are missing or are unreadable fail the run.
- **Chain-of-custody records travel with the evidence.** Each run writes its
  log, hash CSVs and a seal (`.sha256`) into the destination, all named with
  the run's UTC start time. Later copies carry them along, so the set
  accumulates a record of every copy, drive and host. The seal's SHA-256 is
  shown at the end for your custody notes, making later changes to the
  records detectable. See [Output](#output).
- **A result that says what it covers**, with an exit code:

  | Result     | Exit code | Meaning |
  |------------|-----------|---------|
  | PASS       | 0         | The copy completed, and every file in the reference record is in the destination with the same SHA-256. |
  | FAIL       | 1         | The copy failed, or a file in the reference record differs, is missing or unreadable, or the run could not start. |
  | UNVERIFIED | 2         | Copied without failures; verification not requested. |

  Files added since the reference record are listed as warnings and don't
  fail the run.
- **Warnings up front.** Before copying, everything to be wary of is listed
  in one **Warnings** section at the top of the log header (and repeated in
  the summary): the machine may sleep or hibernate (power plan or lid), the
  clock isn't synchronised with a time source, the destination is FAT32/FAT
  or wasn't empty, no UTC time source worked.
- **What is preserved.** Data, attributes and timestamps of files and
  subfolders (`/copy:DAT /dcopy:DAT`), so anything hidden stays hidden;
  empty folders (`/e`). Junctions are not followed (`/xj`). Exact byte sizes
  in the log (`/bytes`). When run elevated, backup mode (`/b`) reads files
  regardless of their permissions.
- **Owner and permissions are deliberately not copied:** copies inherit the
  destination's permissions, since the source's users and groups usually
  don't exist on the target system.
- **Source and destination folders are containers, not evidence:**
  - `$RECYCLE.BIN` and `System Volume Information` are skipped only where
    the source or destination is a drive root (`E:\`); anywhere else,
    including any UNC path, they are copied as contents;
  - any Read-only, Hidden or System attribute robocopy carries from the
    source folder onto the destination folder is cleared, unless the
    destination already had it.
- **Copying:** two passes, files of 100 MiB or more unbuffered (`/j`) and
  single-threaded, smaller files with half the logical processors (1–128).
  A failed file is retried once after 2 s, so real failures surface quickly.
- **Prompts:** log file or on-screen ETA, source, destination, and whether
  to verify. ETA mode (no log) and declining verification are for
  non-evidence copies, and each has to be confirmed. Paths can be typed,
  pasted with quotes, or dragged in; relative paths, and a source and
  destination that are the same or inside each other, are refused. A
  destination that already holds files has to be confirmed (robocopy
  overwrites same-named files that differ).

## Output

Written to the destination root, named with the UTC start time:

- `robocopy_YYYYMMDDTHHMMSSZ.log` (log mode only): a header in three
  sections after the warnings (environment: script version, path and
  SHA-256, host, user, Windows version, elevation, UTC start, local offset,
  time source and last sync, options; source and destination: folder, volume label, serial and file
  system, reference record), the robocopy output with exact byte sizes,
  problems and the summary.
  Robocopy's Started/Ended times are local; its per-file times are UTC. The
  log is written to `%TEMP%` during the run and moved to the destination at
  the end.
- `robocopy_YYYYMMDDTHHMMSSZ_hashes_destination.csv` (when verifying), and
  on the first copy also `..._hashes_source.csv`, the reference record:
  `"File","SHA-256"`, one row per file, sorted by relative path. A set ends up
  with one source record and one destination record per copy. A file that could not be hashed has
  `UNREADABLE` in place of a hash. Zero-byte files get the SHA-256 of empty
  input, as `certutil` can't hash them.
- `robocopy_YYYYMMDDTHHMMSSZ.sha256`: the SHA-256 of the log and CSVs of this
  run. All of a run's files share its UTC start time in their names. The script shows the SHA-256 of this file at the end; recorded in your
  chain-of-custody notes, it shows whether this run's records are later
  changed.

Each later copy carries these files along and hashes them as contents.

## Example

A second copy of an E01 set, from a working copy to a NAS. The log
(robocopy's file lists shortened to `...`):

```
===============================================================================
Warnings (read before relying on this copy)
  [WARN] On battery this machine sleeps after 15 min idle: keep it plugged in for the whole copy.

Environment
  Script            : evidence-robocopy 1.2.0
  Script path       : E:\Tools\evidence-robocopy.bat
  Script SHA-256    : 5b1e...c09a
  Started (UTC)     : 2026-10-13T10:15:03Z (source: robocopy)
  Local UTC offset  : +01:00 (robocopy's Started/Ended times are local; its file times are UTC)
  Time source       : time.windows.com,0x9
  Last time sync    : 13/10/2026 09:58:12 (local time, as w32tm reports it)
  Host              : LAB-WS07
  User              : LAB\analyst2
  Windows           : Windows 11 Enterprise 24H2 (build 26100.4061)
  Elevated          : yes (detected by fsutil), backup mode /b
  robocopy          : C:\Windows\System32\Robocopy.exe
  certutil          : C:\Windows\System32\certutil.exe
  Sleep when idle   : never on mains; after 15 min on battery
  Excluded          : "$RECYCLE.BIN" "System Volume Information" (only where a folder is a drive root)
  Retries           : 1 x 2 s
  Progress          : log file (/np /tee)
  Verify            : SHA-256, every file

Source
  Contents of       : F:\Working\Case-0042\
  Volume            : Volume in drive F is WORK03; serial 6C2E-91A4; NTFS
  Hash record       : robocopy_20261009T141500Z_hashes_source.csv (oldest in the source; the destination is checked against it)

Destination
  Copied into       : \\nas01\cases\Case-0042\
  Was               : empty
  Volume            : n/a (network path)
  Log               : \\nas01\cases\Case-0042\robocopy_20261013T101503Z.log
  Log during run    : C:\Users\analyst2\AppData\Local\Temp\evidence-robocopy_20261013T101503Z_12345_robocopy_20261013T101503Z.log
===============================================================================

--- Copy pass: Large files (100 MiB and over), threads: 1 ---

-------------------------------------------------------------------------------
   ROBOCOPY     ::     Robust File Copy for Windows
-------------------------------------------------------------------------------

  Started : Tuesday 13 October 2026 11:15:04
   Source : F:\Working\Case-0042\
     Dest : \\nas01\cases\Case-0042\
  Options : *.* /V /X /TS /FP /BYTES /TEE /S /E /DCOPY:DAT /COPY:DAT /B /J /NP /XJ /MIN:104857600 /MT:1 /R:1 /W:2
...
	    New File  		2097152000 2026/10/09 13:40:12	F:\Working\Case-0042\PC01.E01
	    New File  		2097152000 2026/10/09 13:47:55	F:\Working\Case-0042\PC01.E02
...
               Total    Copied   Skipped  Mismatch    FAILED    Extras
    Dirs :         1         1         0         0         0         0
   Files :        10         5         5         0         0         0
...
Robocopy exit code: 1
  [INFO] Files were copied.

--- Copy pass: Small files (under 100 MiB), threads: 4 ---
...
Robocopy exit code: 1
  [INFO] Files were copied.

Destination folder attributes unchanged.

--- Verification (SHA-256) ---

--- Destination vs reference record: robocopy_20261009T141500Z_hashes_source.csv ---

===============================================================================
Result
  Finished (UTC)    : 2026-10-13T10:41:37Z
  Copy (robocopy)   : OK (robocopy exit codes combined: 1)
  Verification      : PASS: 6 of 6 files in the reference record match the destination
                      0 differ, 0 missing, 0 unreadable, 0 invalid in the record; added since: 4 custody record(s), 0 other file(s)
  Reference record  : robocopy_20261009T141500Z_hashes_source.csv
  OVERALL RESULT    : PASS - the copy completed, and every file in the reference record is in the destination with the same SHA-256
  Exit code         : 0
  Log               : \\nas01\cases\Case-0042\robocopy_20261013T101503Z.log
===============================================================================
```

After the log is saved, the console also shows the seal:

```
Custody records sealed in: robocopy_20261013T101503Z.sha256
  SHA-256: 8f03...b6d1
Record this value in your chain-of-custody notes: it shows whether this
run's log and hash CSVs are later changed.
```

A failed check is listed where it is found and again in the summary, e.g.
`[FAIL] DIFFERS from the reference record: PC01.E03`, with
`OVERALL RESULT : FAIL - the SHA-256 verification failed; see the problems listed`.

## Requirements

- Windows with `robocopy` and `certutil` (both built in). Tested on
  Windows 11 (build 26200). Copying folder attributes (`/dcopy:DAT`) needs a
  recent robocopy; Windows 7's only supports `/dcopy:T`. Older versions are
  untested.
- For the UTC time it uses robocopy's clock plus the registry time-zone bias
  (`ActiveTimeBias`), falling back to `wmic` where present.
- Administrator rights are optional; they enable backup mode, the file
  system of system volumes and the time-service status.

## Usage

Run `evidence-robocopy.bat` (as administrator for backup mode) and answer the
prompts. `evidence-robocopy.bat /?` shows a short help.

## What it does not do

- Replace chain-of-custody documentation: it records copies, not who held
  the media, why, seals or signatures. Case and exhibit details belong with
  the evidence itself.
- Verify an image against its acquisition hash. That needs an EWF verifier.
- Protect its records from change: the seal only makes changes detectable,
  once its SHA-256 is recorded outside the evidence folder.
- Verify alternate data streams or empty directories. Only each file's main
  data stream is hashed.
- Hash files whose names contain characters outside the console code page,
  or whose paths exceed 260 characters, or that only backup mode can read.
  Robocopy copies them, but they are reported as unreadable (FAIL).
- Recognise a mapped drive and its UNC path as the same place.
- Keep the destination folder's own timestamps: robocopy gives it the source
  folder's (`/dcopy:T`), and batch has no way to set them back.
- Check continuity if a later copy takes only a subfolder: the earlier
  records stay at the root of the original set.

## Licence

0BSD. See [LICENSE](LICENSE).
