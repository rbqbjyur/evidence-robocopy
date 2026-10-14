# evidence-robocopy

A Windows batch wrapper around robocopy for copying digital evidence between
drives as it moves around a lab (master to working copies, to servers, to
archive), with SHA-256 hash verification and chain-of-custody records. It
copies files of any kind: forensic images in any format (E01/EWF, raw/dd,
mobile extractions and so on) and loose files such as eDiscovery
collections. Every copy is logged and verified by default, and its records
stay with the evidence, together with the script itself.

Robocopy can be run many ways. This script fixes one documented methodology
for evidence, so every copy is made the same way and leaves a record that can
be audited, repeated and defended later.

It is a batch file on purpose: it uses only tools built into Windows and runs
wherever robocopy does, including workstations where PowerShell or `.ps1`
scripts are restricted, so it can travel with the evidence too.

## What it does

- **Forensic by default.** Every run keeps a log file and verifies every
  file, without asking. `/nonforensic` asks whether to keep a log (or show
  ETA instead) and whether to verify; dropping either is for non-evidence
  copies and has to be confirmed.
- **The script travels with the evidence.** Kept in the evidence folder
  with its logs, it offers that folder as the default source.
  Run from elsewhere, it places a copy of itself beside the logs in the
  destination, unless the source already holds one, and checks the copy's
  SHA-256 against the run's log. Copies of the script at a root count as
  custody records, not evidence, so updating it never fails a later copy.
- **SHA-256 verification against a reference record.** If the source holds
  no hash record from an earlier copy, the source is hashed and recorded,
  and a warning says so. That record is the reference for this and every
  later copy: each copy hashes its destination with `certutil` and compares
  every file by relative path, so it is checked back to the original record,
  not only to its immediate source. Later copies don't hash the source again;
  they first check the reference record against its own run's seal, so a
  record changed since it was made fails the run (a reference record with no
  seal gets a warning). Files that differ, are missing or are
  unreadable fail the run.
- **Verified from the drive, not from memory.** Every copy pass and the
  run's own records are written unbuffered (`robocopy /j`), so hashing
  reads file contents back from the destination drive rather than from the
  Windows cache.
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
  | UNVERIFIED | 2         | Copied without failures; verification (SHA-256 and metadata) declined with `/nonforensic`. |

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
- **Prompts:** source (default: the script's folder, when it holds
  anything besides the script) and destination. Paths can be typed, pasted with
  quotes, or dragged in; relative paths, and a source and destination that
  are the same or inside each other, are refused. A destination that
  already holds files has to be confirmed (robocopy overwrites same-named
  files that differ).

## Output

Written to the destination root, named with the UTC start time:

- `robocopy_YYYYMMDDTHHMMSSZ.log` (log mode only): the warnings, then a
  header in three sections (environment: script version, path and SHA-256,
  host, user, Windows version, elevation, UTC start, local offset, time
  source and last sync, options; source and destination: folder, volume
  label, serial and file system, reference record, each housekeeping item
  skipped at a drive root), the robocopy output with
  exact byte sizes, problems and the summary. Robocopy's Started/Ended times
  are local; its per-file times are UTC. During the run the log and the
  other records are kept in a staging folder in `%TEMP%`; at the end they
  are written to the destination unbuffered and read back by SHA-256. If
  that fails, they stay in `%TEMP%` and the console shows where. The log records
  the process; the hash CSVs are the authoritative per-file record.
- `robocopy_YYYYMMDDTHHMMSSZ_hashes_destination.csv` (when verifying), and
  when the source holds no hash record also `..._hashes_source.csv`, the
  reference record:
  `"File","SHA-256"`, one row per file, sorted by relative path. A set ends
  up with one source record and one destination record per copy. A file
  that could not be hashed has `UNREADABLE` in place of a hash; zero-byte
  files get the SHA-256 of empty input (`certutil` can't hash them).
- `robocopy_YYYYMMDDTHHMMSSZ.sha256`, the seal: the SHA-256 of this run's log
  and CSVs (and of the script copy, if one was placed). Its own SHA-256 is
  shown at the end of the run.
- `evidence-robocopy.bat`: a copy of the script, if the source root held
  none.

All of a run's files share its UTC start time in their names.

Later copies carry these files along and hash them as contents.

An interrupted run (window closed, power lost, drive removed) leaves a
partial copy and none of its records in the destination; its log and
records stay in the staging folder in `%TEMP%` (header "Log during run").
A rerun into the same destination copies again every file that differs
from the source, and verifies every file.

## Example

A first copy of an evidence folder on an exFAT USB drive to an internal
drive, with the script kept in the evidence folder and the source picked by
pressing Enter; not elevated. Real output, anonymised (host, user, paths,
volume labels and serials replaced; times, counts, sizes and results as
recorded), with robocopy's file lists left out:

```
===============================================================================
Warnings (read before relying on this copy)
  [WARN] No hash record was found in the source root: the source is hashed now and becomes the reference record, so this copy is not checked against any earlier record.

Environment
  Script            : evidence-robocopy 1.5.0
  Script path       : E:\Case-0042\evidence-robocopy.bat
  Script SHA-256    : 234a0079cf932562daf7479771f4b24b187544c9bd41ec1832f5a0bdc9057d6b
  Mode              : forensic (default): log file and SHA-256 verification
  Started (UTC)     : 2026-10-14T16:09:09Z (source: robocopy)
  Local UTC offset  : +01:00 (robocopy's Started/Ended times are local; its file times are UTC)
  Time source       : time.windows.com,0x9
  Last time sync    : 14/10/2026 16:59:34 (local time, as w32tm reports it)
  Host              : WORKSTATION-01
  User              : workstation-01\analyst (SID S-1-5-21-1111111111-2222222222-3333333333-1001)
  OS                : Microsoft Windows 11 Pro 25H2
  Elevated          : no
  robocopy          : C:\Windows\System32\Robocopy.exe
  certutil          : C:\Windows\System32\certutil.exe
  Sleep when idle   : never, on mains or battery
  Excluded          : volume housekeeping at a drive root only (see Source and Destination)
  Retries           : 1 x 2 s
  Progress          : log file (/np /tee)
  Verify            : SHA-256 hash and metadata (size, last-modified time), every file
  Writes            : unbuffered (robocopy /j), evidence and custody records: verification reads file contents from the drive

Source
  Contents of       : E:\Case-0042\
  Chosen            : the script's folder (the default, taken with Enter)
  Volume            : Volume in drive E is EVIDENCE01; serial 1A2B-3C4D; exFAT
  Hash record       : none found in the source root: the source is hashed and becomes the reference record
  Skipped at root   : n/a (not a drive root)

Destination
  Copied into       : C:\Cases\Case-0042\
  Was               : empty
  Volume            : Volume in drive C is OS; serial 5E6F-7A8B; file system unknown
  Left alone at root: n/a (not a drive root)
  Log               : C:\Cases\Case-0042\robocopy_20261014T160909Z.log
  Log during run    : C:\Users\analyst\AppData\Local\Temp\evidence-robocopy_20261014T160909Z_22671_records\robocopy_20261014T160909Z.log
===============================================================================

--- Copy pass: Large files (100 MiB and over), threads: 1 ---
...
  Options : *.* /V /X /TS /FP /BYTES /TEE /S /E /DCOPY:DAT /COPY:DAT /J /NP /XJ /MIN:104857600 /MT:1 /R:1 /W:2
...
               Total    Copied   Skipped  Mismatch    FAILED    Extras
    Dirs :         6         6         1         0         0         0
   Files :        32         0        32         0         0         0
   Bytes :  17325358         0  17325358         0         0         0
...
Robocopy exit code: 0
  [INFO] No files were copied in this pass.

--- Copy pass: Small files (under 100 MiB), threads: 8 ---
...
               Total    Copied   Skipped  Mismatch    FAILED    Extras
    Dirs :         6         6         6         0         0         0
   Files :        32        32         0         0         0         0
   Bytes :  17325358  17325358         0         0         0         0
   Times :   0:00:03   0:00:00                       0:00:00   0:00:00
...
Robocopy exit code: 1
  [INFO] Files were copied.

Destination folder attributes unchanged.

--- Verification: metadata and SHA-256 hashes ---

--- Metadata check: size and last-modified time, compared to 2 s, as FAT/exFAT is involved ---

--- Hashing the source (no hash record found in the source root): it becomes the reference record ---

--- Hashing the destination ---

--- Destination vs reference record: robocopy_20261014T160909Z_hashes_source.csv ---

===============================================================================
Result
  Finished (UTC)    : 2026-10-14T16:09:17Z
  Script copy       : not needed: the source holds a copy, copied with the evidence
  Reference record  : robocopy_20261014T160909Z_hashes_source.csv
                      made by this run; sealed at the end of it
  Log               : C:\Cases\Case-0042\robocopy_20261014T160909Z.log

  OVERALL RESULT        : PASS (exit code 0)
    |-Copy (robocopy)   : PASS (robocopy exit codes combined: 1)
    |-Metadata          : PASS: size and last-modified time match for every file (compared to 2 s, as FAT/exFAT is involved)
    |-Hash (SHA-256)    : PASS: 31 of 31 files in the reference record match the destination
                          0 differ, 0 missing, 0 unreadable, 0 invalid in the record; added since: 1 custody record(s), 0 other file(s)
The copy completed, every file in the reference record is in the destination with the same SHA-256, and size and last-modified time match the source
===============================================================================
```

The custody record "added since" is the script itself, which travelled with
the evidence. At the end, the console also shows the seal and the
write-back of the records:

```
Custody records sealed in: robocopy_20261014T160909Z.sha256
  SHA-256: 4113f49d07bdce52e08dc1223ca4e70c7a86c2666421457fea7dcb95a909a6b8
Record this value in your chain-of-custody notes: it shows whether this
run's log and hash CSVs are later changed.

Custody records written to the destination and read back: 4 of 4 match.
Log saved: C:\Cases\Case-0042\robocopy_20261014T160909Z.log
```

A failed check is listed where it is found and again in the summary, e.g.
`[FAIL] DIFFERS from the reference record: <file>`, with
`OVERALL RESULT : FAIL (exit code 1)`, the failed check marked FAIL beneath
it, and the closing line `The SHA-256 verification failed; see the problems listed`.

## Requirements

- Windows with `robocopy` and `certutil` (both built in). Tested on
  Microsoft Windows 11 Pro 25H2. Copying folder attributes (`/dcopy:DAT`)
  needs a recent robocopy; Windows 7's only supports `/dcopy:T`. Older
  versions are untested.
- For the UTC time it uses robocopy's clock plus the registry time-zone bias
  (`ActiveTimeBias`), falling back to `wmic` where present.
- Administrator rights are optional; they enable backup mode and, on some
  systems, reading the file system of system volumes and the time-service
  status.

## Usage

```
evidence-robocopy.bat                 forensic mode (default): log and verification
evidence-robocopy.bat /nonforensic    choose whether to keep a log and verify
evidence-robocopy.bat /?              help
```

Run as administrator for backup mode. Any other argument stops the run.

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
- Flush file-system metadata or a drive's own write cache: file contents
  are written unbuffered, but only ejecting or dismounting the drive
  flushes the rest.
- Recognise a mapped drive and its UNC path as the same place (in the
  check that source and destination don't overlap).
- Keep the destination folder's own timestamps: robocopy gives it the source
  folder's (`/dcopy:T`), and batch has no way to set them back.
- Link a copy of a subfolder to its parent set: the parent's records stay
  at the root of that set, so the subfolder copy starts its own reference
  record.

## Extending

Behaviour is set by tables in the CONFIG section at the top of the script,
each documented beside it, so most changes are a new row rather than code:

- `EXCLUDED_ROOT_DIRS`, `EXCLUDED_ROOT_FILES`: housekeeping skipped at a
  drive root, one row per origin (Windows, macOS, Linux).
- `RECOVERED_ROOT_DIRS`: root folders that raise the recovered-fragments
  warning.
- `COPY_PASSES`, `PASS_<id>_*`: the robocopy passes (size split, threads,
  flags).
- `RC_<bit>_*`: what each robocopy exit-code bit means and whether it fails
  the copy.
- `FS_WARN_<file system>`: destination file systems that get a warning.
- `SLEEP_SETTINGS`: power settings read for the sleep advice.
- `CONTAINER_ATTRS`: attributes cleared from the destination folder.
- `UTC_METHODS`, `ADMIN_CHECKS`, `FS_METHODS`: ordered fallbacks; each
  name is a helper (`:utc_from_<name>`, `:admin_check_<name>`,
  `:fs_from_<name>`).

The script header lists the batch conventions (paths with special
characters, output to console and log, error handling).

## Licence

0BSD. See [LICENSE](LICENSE).
