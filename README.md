# evidence-robocopy

A Windows batch wrapper around robocopy for copying digital evidence between
drives as it moves around a lab (master to working copies, to servers, to
archive), with SHA-256 hash verification and chain-of-custody records. Built
first for forensic images (E01/EWF, single or split), and also usable for
loose-file evidence such as eDiscovery collections. A verified copy leaves its
log and hash records with the evidence, so the records of each copy travel
with it.

It is a batch file on purpose: it uses only tools built into Windows and runs
wherever robocopy does, including workstations where PowerShell or `.ps1`
scripts are restricted, so it can travel with the evidence too.

## What it does

- **SHA-256 verification against a reference record.** If the source holds
  no hash record from an earlier copy, the source is hashed and recorded,
  and a warning says so. That record is the reference for this and every
  later copy: each copy hashes its destination with `certutil` and compares
  every file by relative path, so it is checked back to the original record,
  not only to its immediate source. Later copies don't hash the source again.
  Files that differ, are missing or are unreadable fail the run.
- **Metadata check.** After the copy, robocopy compares every source file
  with its copy in list-only mode: any file whose size or last-modified
  time differs, or that wasn't copied, fails the run. Times are compared
  exactly, or to 2 s where FAT or exFAT is involved.
- **Chain-of-custody records travel with the evidence.** Each run writes its
  log, hash CSVs and a seal (`.sha256`) into the destination, all named with
  the run's UTC start time. Later copies carry them along, so the set
  accumulates a record of each copy made with it, with the drives and hosts
  involved. The seal's SHA-256 is shown at the end; recorded elsewhere, it
  makes later changes to the records detectable. See [Output](#output).
- **A result that says what it covers**, with an exit code:

  | Result     | Exit code | Meaning |
  |------------|-----------|---------|
  | PASS       | 0         | The copy completed, every file in the reference record is in the destination with the same SHA-256, and sizes and last-modified times match the source. |
  | FAIL       | 1         | The copy failed, a file in the reference record differs, is missing or unreadable, a file's size or last-modified time differs, or the run could not start. |
  | UNVERIFIED | 2         | Copied without failures; verification (SHA-256 and metadata) not requested. |

  Files added since the reference record are listed as warnings and don't
  fail the run.
- **Warnings up front.** Before copying, everything to be wary of is listed
  in one **Warnings** section at the top of the log header (and repeated in
  the summary): the machine may sleep or hibernate (power plan or lid), the
  clock isn't synchronised with a time source, the destination is FAT32/FAT
  or wasn't empty, a drive root holds fragments recovered by file-system
  repairs (`FOUND.nnn`, `LOST.DIR`; copied as contents), no UTC time source
  worked.
- **What is preserved.** Data, attributes and timestamps of files and
  subfolders (`/copy:DAT /dcopy:DAT`), so anything hidden stays hidden;
  empty folders (`/e`). Junctions are not followed (`/xj`). Exact byte sizes
  in the log (`/bytes`). When run elevated, backup mode (`/b`) reads files
  regardless of their permissions.
- **Owner and permissions are deliberately not copied:** copies inherit the
  destination's permissions, since the source's users and groups usually
  don't exist on the target system.
- **Source and destination folders are containers, not evidence:**
  - at a drive root (`E:\`) only, the housekeeping that Windows, macOS and
    Linux leave on drives they are plugged into is skipped. Each drive root
    is checked first; only the items actually present are excluded, by exact
    path, and the log lists each one. Folders: `$RECYCLE.BIN`, `RECYCLER`,
    `RECYCLED`, `System Volume Information`, `.Trashes`, `.Spotlight-V100`,
    `.fseventsd`, `.TemporaryItems`, `.DocumentRevisions-V100`, `.Trash-*`.
    Files: `.DS_Store`, `._*`, `.apdisk`, `.VolumeIcon.icns`,
    `.com.apple.timemachine.donotpresent`, `.metadata_never_index*`,
    `Thumbs.db`, `.xdg-volume-info`, `.directory`. Anywhere else, including
    inside evidence folders and on any UNC path, they are copied as contents;
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

- `robocopy_YYYYMMDDTHHMMSSZ.log` (log mode only): the warnings, then a
  header in three sections (environment: script version, path and SHA-256,
  host, user, Windows version, elevation, UTC start, local offset, time
  source and last sync, options; source and destination: folder, volume
  label, serial and file system, reference record, each housekeeping item
  skipped at a drive root), the robocopy output with
  exact byte sizes, problems and the summary. Robocopy's Started/Ended times
  are local; its per-file times are UTC. The log is written to `%TEMP%`
  during the run and moved to the destination at the end. The log records
  the process; the hash CSVs are the authoritative per-file record.
- `robocopy_YYYYMMDDTHHMMSSZ_hashes_destination.csv` (when verifying), and
  when the source holds no hash record also `..._hashes_source.csv`, the
  reference record:
  `"File","SHA-256"`, one row per file, sorted by relative path. A set ends
  up with one source record and one destination record per copy. A file
  that could not be hashed has `UNREADABLE` in place of a hash; zero-byte
  files get the SHA-256 of empty input (`certutil` can't hash them).
- `robocopy_YYYYMMDDTHHMMSSZ.sha256`, the seal: the SHA-256 of this run's log
  and CSVs. Its own SHA-256 is shown at the end of the run.

All of a run's files share its UTC start time in their names.

Later copies carry these files along and hash them as contents.

## Example

A first copy of loose-file evidence from a folder on an internal drive to an
exFAT USB drive, run without elevation. Real output, anonymised (host, user,
paths, volume labels and serials replaced; times, counts, sizes and results
as recorded), with robocopy's file lists left out:

```
===============================================================================
Warnings (read before relying on this copy)
  [WARN] The clock is not synchronised with a time source (w32tm reports leap indicator 3, not synchronised): times in this record rely on this machine's own clock.
  [WARN] No hash record was found in the source root: the source is hashed now and becomes the reference record, so this copy is not checked against any earlier record.

Environment
  Script            : evidence-robocopy 1.3.1
  Script path       : E:\Tools\evidence-robocopy.bat
  Script SHA-256    : aa39c8b2f286d2c03ad409ff8a5dae2656e94f68625102ea111c9da0a72aeb3e
  Started (UTC)     : 2026-10-13T12:57:01Z (source: robocopy)
  Local UTC offset  : +01:00 (robocopy's Started/Ended times are local; its file times are UTC)
  Time source       : time.windows.com,0x9
  Last time sync    : 13/10/2026 12:11:01 (local time, as w32tm reports it)
  Host              : WORKSTATION-01
  User              : WORKSTATION-01\analyst
  OS                : Microsoft Windows 11 Pro 25H2
  Elevated          : no
  robocopy          : C:\Windows\System32\Robocopy.exe
  certutil          : C:\Windows\System32\certutil.exe
  Sleep when idle   : never, on mains or battery
  Excluded          : volume housekeeping at a drive root only (see Source and Destination)
  Retries           : 1 x 2 s
  Progress          : log file (/np /tee)
  Verify            : SHA-256, every file

Source
  Contents of       : C:\Cases\Case-0042\
  Volume            : Volume in drive C is OS; serial 1A2B-3C4D; file system unknown
  Hash record       : none found in the source root: the source is hashed and becomes the reference record
  Skipped at root   : n/a (not a drive root)

Destination
  Copied into       : I:\Case-0042\
  Was               : empty
  Volume            : Volume in drive I is EVIDENCE01; serial 5E6F-7A8B; exFAT
  Left alone at root: n/a (not a drive root)
  Log               : I:\Case-0042\robocopy_20261013T125701Z.log
  Log during run    : C:\Users\analyst\AppData\Local\Temp\evidence-robocopy_20261013T125701Z_7836_robocopy_20261013T125701Z.log
===============================================================================

--- Copy pass: Large files (100 MiB and over), threads: 1 ---
...
  Options : *.* /V /X /TS /FP /BYTES /TEE /S /E /DCOPY:DAT /COPY:DAT /J /NP /XJ /MIN:104857600 /MT:1 /R:1 /W:2
...
               Total    Copied   Skipped  Mismatch    FAILED    Extras
    Dirs :         7         7         1         0         0         0
   Files :        28         1        27         0         0         0
   Bytes : 330770479 178021472 152749007         0         0         0
   Times :   0:00:08   0:00:02                       0:00:00   0:00:02
...
Robocopy exit code: 1
  [INFO] Files were copied.

--- Copy pass: Small files (under 100 MiB), threads: 8 ---
...
               Total    Copied   Skipped  Mismatch    FAILED    Extras
    Dirs :         7         7         7         0         0         0
   Files :        28        27         1         0         0         0
   Bytes : 330770479 152749007 178021472         0         0         0
   Times :   0:00:25   0:00:03                       0:00:00   0:00:00
...
Robocopy exit code: 1
  [INFO] Files were copied.

Destination folder: cleared Read-only (carried over from the source folder).

--- Verification (SHA-256) ---

--- Metadata check: size and last-modified time, compared to 2 s, as FAT/exFAT is involved ---

--- Hashing the source (no hash record found in the source root): it becomes the reference record ---

--- Hashing the destination ---

--- Destination vs reference record: robocopy_20261013T125701Z_hashes_source.csv ---

===============================================================================
Result
  Finished (UTC)    : 2026-10-13T12:57:20Z
  Copy (robocopy)   : OK (robocopy exit codes combined: 1)
  Verification      : PASS: 28 of 28 files in the reference record match the destination
                      0 differ, 0 missing, 0 unreadable, 0 invalid in the record; added since: 0 custody record(s), 0 other file(s)
  Metadata          : PASS: size and last-modified time match for every file (compared to 2 s, as FAT/exFAT is involved)
  Reference record  : robocopy_20261013T125701Z_hashes_source.csv
  OVERALL RESULT    : PASS - the copy completed, every file in the reference record is in the destination with the same SHA-256, and size and last-modified time match the source
  Exit code         : 0
  Log               : I:\Case-0042\robocopy_20261013T125701Z.log
===============================================================================
```

After the log is saved, the console also shows the seal:

```
Custody records sealed in: robocopy_20261013T125701Z.sha256
  SHA-256: 73a3c0cdc56e0e718fcb4cfcf90e33cfeb43175c5e5ccada680d5474ee596d2c
Record this value in your chain-of-custody notes: it shows whether this
run's log and hash CSVs are later changed.
```

A failed check is listed where it is found and again in the summary, e.g.
`[FAIL] DIFFERS from the reference record: <file>`, with
`OVERALL RESULT : FAIL - the SHA-256 verification failed; see the problems listed`.

## Requirements

- Windows with `robocopy` and `certutil` (both built in). Tested on
  Microsoft Windows 11 Pro 25H2. Copying folder attributes (`/dcopy:DAT`) needs a
  recent robocopy; Windows 7's only supports `/dcopy:T`. Older versions are
  untested.
- For the UTC time it uses robocopy's clock plus the registry time-zone bias
  (`ActiveTimeBias`), falling back to `wmic` where present.
- Administrator rights are optional; they enable backup mode and, on some
  systems, reading the file system of system volumes and the time-service
  status.

## Usage

Run `evidence-robocopy.bat` (as administrator for backup mode) and answer the
prompts. `evidence-robocopy.bat /?` shows a short help.

## What it does not do

- Replace chain-of-custody documentation: it records copies, not who held
  the media, why, seals or signatures.
- Verify an image against its acquisition hash.
- Protect its records from change: the seal only makes changes detectable,
  once its SHA-256 is recorded outside the evidence folder.
- Verify alternate data streams, empty directories, attributes or creation
  times. Robocopy copies them; only each file's main data stream is hashed,
  and only size and last-modified time are compared.
- Hash files whose names contain characters outside the console code page,
  or whose paths exceed 260 characters, or that only backup mode can read.
  Robocopy copies them, but they are reported as unreadable (FAIL).
- Recognise a mapped drive and its UNC path as the same place (in the
  check that source and destination don't overlap).
- Keep the destination folder's own timestamps: robocopy gives it the source
  folder's (`/dcopy:T`), and batch has no way to set them back.
- Link a copy of a subfolder to its parent set: the parent's records stay
  at the root of that set, so the subfolder copy starts its own reference
  record.

## Licence

0BSD. See [LICENSE](LICENSE).
