# evidence-robocopy

A Windows batch wrapper around robocopy for copying digital evidence between
drives as it moves around a lab (master to working copies, to servers, to
archive), with SHA-256 hash verification and chain-of-custody records.
Every copy is logged and verified by default, and a sealed record of it
stays with the evidence, together with the script itself.

Robocopy can be run many ways. This script fixes one documented methodology
for evidence, so every copy is made the same way and leaves a record that can
be audited, repeated and defended later.

It is a batch file on purpose: it uses only tools built into Windows and runs
wherever robocopy does, including workstations where PowerShell or `.ps1`
scripts are restricted, so it can travel with the evidence too.

## What it does

- **Forensic by default.** Every run keeps a log, verifies every file and
  adds a sealed run record, without asking. `/nonforensic` is a separate
  plain copy utility for non-evidence copies (see below).
- **Evidence and custody files kept apart.** The evidence is copied as one
  directory, under its own name, into a *set directory*; beside it are the
  *custody files*: the script, the history and the records directory. Nothing
  is ever written into the evidence directory, and nothing is ever written to
  the source. See [Set and evidence directories](#set-and-evidence-directories).
- **SHA-256 verification against a reference record.** A first copy hashes
  the source and records it; that record is the reference for this and every
  later copy. Each copy hashes its destination with `certutil` and compares
  every file by relative path, so it is checked back to the original record,
  not only to its immediate source. Files that differ, are missing or are
  unreadable fail the run.
- **Verified from the drive, not from memory.** Every copy pass and the
  run's own record are written unbuffered (`robocopy /j`), so hashing reads
  file contents back from the destination drive rather than from the
  Windows cache.
- **Metadata check.** After the copy, robocopy compares every source file
  with its copy in list-only mode: any file whose size or last-modified
  time differs, or that wasn't copied, fails the run. Times are compared
  exactly, or to 2 s where FAT or exFAT is involved.
- **A sealed record of every copy, and a history.** Each run writes its
  log, hash CSVs and history into a run record of its own, sealed with
  their SHA-256s. On every copy, every earlier run record is checked against
  its seal and against the history. See [History and run
  records](#history-and-run-records).
- **Checks between copies.** A different script version, and a set that
  reached this drive by other means since the run that made it, are
  flagged. See [Checks between copies](#checks-between-copies).
- **Evidence counts are evidence only.** The custody files are copied in a
  pass of their own and hashed with their own counter into a separate CSV,
  so robocopy's totals, the hashing counters and the summary count evidence
  only, however many copies the set has been through.
- **A result that says what it covers**, with an exit code:

  | Result     | Exit code | Meaning |
  |------------|-----------|---------|
  | PASS       | 0         | The copy completed, every file in the reference record is in the destination with the same SHA-256, sizes and last-modified times match the source, and every earlier run record matches its seal and the history. |
  | FAIL       | 1         | The copy failed, a file in the reference record differs, is missing or unreadable, a file's size or last-modified time differs, a run record or the history doesn't check out, the script check failed, or the run could not start. |
  | UNVERIFIED | 2         | `/nonforensic` only: copied without failures, verification declined. |

  The summary names each check (Copy, Metadata, Hash, Run records, Script)
  and lists every warning just above the result and everything that failed
  the run just below it, in the log as on screen. Files added since the
  reference record are warnings.
- **Warnings up front.** Before copying, everything to be wary of is listed
  in one **Warnings** section at the top of the log header, and repeated in
  the summary: the machine may sleep or hibernate, or its power settings
  can't be read; the clock isn't synchronised with a time source, or its
  status can't be read; the destination is FAT32/FAT, or already holds the
  set; a copy pass doesn't write unbuffered; a drive root holds fragments
  recovered by file-system repairs (`FOUND.nnn`, `LOST.DIR`; copied as
  contents); the source has no history, so the copy isn't checked against
  an earlier record; run records the Run records check will fail; a newer
  script than the previous run's; the set was moved or copied by other
  means; the console couldn't be switched to UTF-8.
- **What is preserved.** Data, attributes and timestamps of files and
  subdirectories (`/copy:DAT /dcopy:DAT`), so anything hidden stays hidden;
  empty directories (`/e`). Junctions and symbolic links are not followed (`/xj`); each one not copied is listed as a warning. Exact byte sizes
  in the log (`/bytes`). When run elevated, backup mode (`/b`) reads files
  regardless of their permissions.
- **Owner and permissions are deliberately not copied:** copies inherit the
  destination's permissions, since the source's users and groups usually
  don't exist on the target system.
- **Drive roots.** When the source is a drive root (`E:\`), the
  housekeeping that Windows, macOS and Linux leave on drives they are
  plugged into is skipped: only the items actually present, by exact path,
  each listed in the log. Directories: `$RECYCLE.BIN`, `RECYCLER`, `RECYCLED`,
  `System Volume Information`, `.Trashes`, `.Spotlight-V100`, `.fseventsd`,
  `.TemporaryItems`, `.DocumentRevisions-V100`, `.Trash-*`. Files:
  `.DS_Store`, `._*`, `.apdisk`, `.VolumeIcon.icns`,
  `.com.apple.timemachine.donotpresent`, `.metadata_never_index*`,
  `Thumbs.db`, `.xdg-volume-info`, `.directory`. Inside directories and on UNC
  paths they are copied as contents.
- **Copying:** two evidence passes, both unbuffered (`/j`): files of 100 MiB
  or more single-threaded, smaller files with half the logical processors
  (1–128); then the custody files in a pass of their own. A failed file is
  retried once after 2 s, so real failures surface quickly.
- **Records are UTF-8** with CRLF line endings, and every CSV cell is
  quoted.

## Set and evidence directories

A **set directory** holds exactly one **evidence directory** and the **custody
files**: the script, `evidence-robocopy-history.csv` and
`evidence-robocopy-records\`. Set directories and the records directory may also
hold the files Explorer and macOS leave when browsing (`.DS_Store`, `._*`,
`.apdisk`, `desktop.ini`, `Thumbs.db`, `.directory`); they are ignored, not
copied or hashed. Inside the evidence directory they are evidence.

**Source: which set is copied?**

| Rule | Source given | It is |
|------|--------------|-------|
| S1 | Enter | The script's own directory is the set directory (offered only when it holds exactly one evidence directory). |
| S2 | A directory holding the custody files | The set directory. |
| S3 | A directory whose parent holds them | That set's evidence directory; the parent is the set directory. |
| S4 | A directory with neither | Raw evidence: a first copy. |

A set directory that holds more than one directory besides the custody files, or
anything else unexpected, is refused, as is a directory that holds custody
files when its parent does too.

**Destination: where does the set go?** The destination must be an
existing directory. Names are compared exactly (ignoring case, as Windows
does). Two steps; junk names (`desktop.ini`, `.DS_Store` and the
like) never count as content.

1. Layout: the first rule that fits gives the set directory. The evidence
   directory's name is looked for before the destination's contents.

| Rule | Destination given | Set directory |
|------|-------------------|------------|
| D1 | Holds the custody files | The destination |
| D2 | Has the evidence directory's name, and its parent holds the custody files or nothing else | Its parent (the destination is the evidence directory) |
| D3 | Empty, or holds only a directory with the evidence directory's name | The destination |
| D4 | Anything else | A directory in it named after the set (made if it isn't there) |

   A directory inside a set that doesn't have its evidence directory's name is
   refused.

2. State, the same whichever rule applied: a set directory holding the custody
   files is the same set (a rerun or an update; its evidence directory must
   have the same name; confirmed before copying). Otherwise it is a new set,
   and it may hold nothing but an empty directory with the evidence directory's
   name. Anything else is refused.

A set directory made by D4 takes the source set directory's name; a first copy has
none, so it takes the evidence directory's name (a drive root's volume label,
or `Volume_<serial>` if it has none).

```
C:\Evidence\CASE18601\                      case directory (D4)
    CASE18601-EV03\                         set directory
        Images\                             evidence directory
        evidence-robocopy.bat
        evidence-robocopy-history.csv
        evidence-robocopy-records\
            20261014T160909Z\               run record
            20261015T091200Z\
```

## History and run records

Each run writes a **run record**, `evidence-robocopy-records\<run UTC>\`,
with every file named `evidence-robocopy_<run UTC>…`:

- `evidence-robocopy_<UTC>.log`: the warnings, then a header in three
  sections (environment: script version, path and SHA-256, host, user,
  Windows version, encoding, elevation, UTC start, local offset, time source
  and last sync, options; source: set and evidence directories, the rule that
  chose them, volume label, serial and file system, reference record,
  history, previous run, each housekeeping item skipped at a drive root;
  destination: the same, and this run's record), the robocopy output with
  exact byte sizes, problems as they are found, and the summary.
  Robocopy's Started/Ended and ERROR times are local; its per-file times
  are UTC.
- `evidence-robocopy_<UTC>_hashes_source.csv` (first copy only): the
  reference record. `…_hashes_destination.csv`: the evidence in the
  destination. Both list evidence only, `"File","SHA-256"`, one row per
  file, sorted by relative path within the evidence directory, so they can be
  compared row for row. A file that could not be hashed has `UNREADABLE` in
  place of a hash; zero-byte files get the SHA-256 of empty input
  (`certutil` can't hash them).
- `…_hashes_custody.csv`: the custody files in the destination set before
  this run's record was added (earlier run records, script copies, the
  history), same columns.
- `…_history.csv`: the history as this run left it (below).
- `…_runs_outside_history.csv` (only when this run restarted the history):
  the run records it found outside the history, with their seals' SHA-256.
- `evidence-robocopy_<UTC>.sha256`, the seal: one `<SHA-256> *<file name>`
  line for each of the above. Its own SHA-256 is shown at the end of the
  run, for the chain-of-custody notes. The script copy isn't listed: the
  sealed log records the script's SHA-256, which the copy is checked
  against.

**The history** has one row per run, newest last:

| Column | Content |
|--------|---------|
| Run (UTC) | the run record's name |
| Result | PASS or FAIL |
| Source directory | the source set directory, or for a first copy the evidence directory copied |
| Source volume serial, Source volume | volume serial number; label line and file system |
| Destination set directory | path |
| Destination volume serial, Destination volume | as for the source |
| Evidence files | files verified |
| Host, User | computer name; account name and SID |
| Script | name and version |
| Seal SHA-256 | that run's seal |

A run can't know its own seal's SHA-256 while writing its record, so in the
history sealed in a run record the newest row reads `see
evidence-robocopy_<UTC>.sha256`; the next run fills it in. The history
beside the evidence is a quick overview with every row filled in, rewritten
by every run. The columns are fixed for all of 2.x; cells never contain `"`
or `|`.

**Run records check**, on every copy, against the history this copy
continues:

- every run in the history has a run record, and its seal has the SHA-256
  the history records;
- every run record's own sealed history is the history up to that run;
- every file in a run record matches its seal, and the seal lists every
  file;
- no run record or file in the records directory is outside the history.

Any of these failing fails the run. The history beside the evidence is
checked against the run records before copying. If it is missing,
unreadable (e.g. saved by a spreadsheet) or doesn't match them, it is
disregarded and the copy continues from the newest sealed history (that of
the run record with the latest run UTC, taken as it is: no other is tried),
provided that one matches the run records: the copy fails, says so, and writes a
complete history beside the evidence again, so the next copy is clean. If
no sealed history matches either, the copy fails and continues from the
history beside the evidence as found, so the discrepancy stays visible; if
there is none, the history restarts with that run's FAIL row, that run
lists the run records it found outside the new history, and later copies
give a warning for each of them as long as it still matches the seal
SHA-256 listed for it. Removing the newest run record together with its
row leaves a consistent but shorter chain: only the seal SHA-256 recorded
in the custody notes shows it. A run record
left as `<UTC>.partial` (an interrupted write-back: each run record is
written under that name, read back by SHA-256 and only then renamed) is a
warning and outside the history.

A rerun into the same destination is a full run (robocopy copies what
differs; every file is verified) and gets its own row, e.g. run 3 FAIL,
run 4 PASS. A destination set whose history doesn't continue the source's
is refused before copying: sets are never mixed. The history follows this
copy's line of descent: copies branched off earlier don't see each other.

An interrupted run leaves a partial copy and no run record in the
destination; its log stays in `%TEMP%` (header "Log during run"). A
destination holding a partial copy without custody files is refused: delete
the partial copy and run again. If the
run record can't be written at the end, the destination keeps the history
it had, the files stay in `%TEMP%`, and the exit code is FAIL. The run's log
is sealed before that write, so a log left in the TEMP staging directory or
in a `<UTC>.partial` shows the verification result (e.g. PASS), not the
failed write; later copies warn about the `.partial`.

## Checks between copies

- **Script check** (its own line in the summary). The script is compared
  with the previous run's: the version from that run's sealed history, the
  SHA-256 from its sealed log. A newer version is a warning; an older
  version, or the same version with a different SHA-256, fails the run. The
  script never vouches for itself: a difference is flagged for the analyst
  to verify both scripts against the published release. The script copy
  beside the evidence comes by one route, decided before copying: the
  source set's copy with the same name if it is a newer version, otherwise
  the script that ran. A newer copy already in the destination is left as
  it is.
- **Location check.** The source set's volume serial and its path,
  ignoring the drive letter and case, are compared with where the run that
  made it copied it. A difference in either is a warning: the set reached
  this place by other means since (copied or moved without this script).

## Non-forensic mode

`/nonforensic` is a plain copy utility for non-evidence copies, confirmed
when chosen: it copies the source directory's contents into the destination
with ETA progress, keeps no log and writes no records, and treats custody
files and histories like any other file. It optionally verifies every file
by SHA-256 and metadata against its source, with the result on screen only.
A later forensic run on its output treats it like any other copy made
without the script.

## Requirements

- Windows with `robocopy` and `certutil` (both built in). Tested on
  Microsoft Windows 11 Pro 25H2. Copying directory attributes (`/dcopy:DAT`)
  needs a recent robocopy; Windows 7's only supports `/dcopy:T`. Older
  versions are untested.
- For the UTC time it uses robocopy's clock plus the registry time-zone bias
  (`ActiveTimeBias`), falling back to `wmic` where present. A forensic run
  stops if neither works.
- Administrator rights are optional; they enable backup mode and, on some
  systems, reading the file system of system volumes and the time-service
  status.

## Usage

```
evidence-robocopy.bat                 forensic mode (default)
evidence-robocopy.bat /nonforensic    plain copy utility, no log or records
evidence-robocopy.bat /?              help
```

Run as administrator for backup mode. Any other argument stops the run.

## Example

The third copy of a set, from its set directory (S2) into an empty
directory (D3). Header and summary of the log; the robocopy and per-file
lines are left out. Names, paths, host, user and serial are anonymised.

```
===============================================================================
Warnings (read before relying on this copy)
  none

Environment
  Script              : evidence-robocopy 2.0.1
  Script path         : C:\Tools\evidence-robocopy.bat
  Script SHA-256      : 1f663674f4dc55e3cc0aaf909f87a72da9dae3d9a5f94cd741482b40db923166
  Mode                : forensic (default): log, SHA-256 verification and run records
  Started (UTC)       : 2026-10-16T00:27:55Z (source: robocopy)
  Local UTC offset    : +01:00 (robocopy's Started/Ended and ERROR times are local; its file times are UTC)
  Time source         : time.windows.com,0x9
  Last time sync      : 15/10/2026 22:32:24 (local time, as w32tm reports it)
  Host                : WORKSTATION-01
  User                : workstation-01\analyst (SID S-1-5-21-1111111111-2222222222-3333333333-1001)
  OS                  : Microsoft Windows 11 Pro 25H2
  Encoding            : UTF-8 (code page 65001)
  Elevated            : yes (detected by fsutil), backup mode /b
  robocopy            : C:\Windows\System32\Robocopy.exe
  certutil            : C:\Windows\System32\certutil.exe
  Sleep when idle     : never, on mains or battery
  Excluded            : volume housekeeping at a drive root only (see Source)
  Retries             : 1 x 2 s
  Progress            : log file (/np /tee)
  Verify              : SHA-256 hash and metadata (size, last-modified time), every file; run records against the history and their seals
  Writes              : unbuffered (robocopy /j), evidence and custody records: verification reads file contents from the drive

Source
  Set directory       : C:\Cases\Case-0042\EV03\
  Evidence directory  : C:\Cases\Case-0042\EV03\Images\
  Chosen              : S2: the directory holds the custody files: it is the set directory
  Volume              : Volume in drive C is OS; serial 1A2B-3C4D; NTFS
  Skipped at root     : n/a (not a drive root)
  Reference record    : evidence-robocopy-records\20261016T002718Z\evidence-robocopy_20261016T002718Z_hashes_source.csv (row 1 of the history)
  History             : 2 earlier run(s); this is run 3
  Previous run        : 20261016T002738Z (PASS, host WORKSTATION-01, seal SHA-256 34f7698af54d9627a500bf5f20b6b0d23f09d14bc0aa2fad9b913529ad633048)

Destination
  Set directory       : C:\Processing\EV03\
  Evidence directory  : C:\Processing\EV03\Images\
  Chosen              : D3: the directory is empty or holds only a directory with the evidence directory's name: it is the set directory
  Was                 : new set (empty, or only an empty evidence directory)
  Volume              : Volume in drive C is OS; serial 1A2B-3C4D; NTFS
  Run record          : C:\Processing\EV03\evidence-robocopy-records\20261016T002755Z\
  Log                 : C:\Processing\EV03\evidence-robocopy-records\20261016T002755Z\evidence-robocopy_20261016T002755Z.log
  Log during run      : C:\Users\analyst\AppData\Local\Temp\evidence-robocopy_20261016T002755Z_27161_staging\records\evidence-robocopy_20261016T002755Z.log
===============================================================================

--- Script check against the previous run ---
  Script              : PASS: same version (2.0.1) and SHA-256 as the previous run's script

[...]

--- Run records against the history and their seals ---
Run record 20261016T002718Z: 5 file(s) match its seal, 0 problem(s). Seal SHA-256: 311b111ac7ed9f7f69780b401ebf3ac1fc4becf489e88d8c77ccc6073d2ee57a
Run record 20261016T002738Z: 4 file(s) match its seal, 0 problem(s). Seal SHA-256: 34f7698af54d9627a500bf5f20b6b0d23f09d14bc0aa2fad9b913529ad633048

--- Destination vs reference record: evidence-robocopy_20261016T002718Z_hashes_source.csv ---

===============================================================================
Result
  Finished (UTC)      : 2026-10-16T00:28:06Z
  Script copy         : placed in the destination set directory as evidence-robocopy.bat; its SHA-256 matches the Script SHA-256 above
  Reference record    : evidence-robocopy_20261016T002718Z_hashes_source.csv
                        matches its seal evidence-robocopy_20261016T002718Z.sha256 (seal SHA-256 311b111ac7ed9f7f69780b401ebf3ac1fc4becf489e88d8c77ccc6073d2ee57a)
  History             : run 3 (2 earlier run(s) in the history)
  Log                 : C:\Processing\EV03\evidence-robocopy-records\20261016T002755Z\evidence-robocopy_20261016T002755Z.log

  Warnings (did not fail the run)
    none

  OVERALL RESULT          : PASS (exit code 0)
    |-Copy (robocopy)     : PASS (robocopy exit codes combined: 1)
    |-Metadata            : PASS: size and last-modified time match for every file (compared exact)
    |-Hash (SHA-256)      : PASS: 31 of 31 files in the reference record match the destination
                            0 differ, 0 missing, 0 unreadable, 0 invalid in the record; added since: 0 file(s)
    |-Run records         : PASS: 2 run record(s) match their seals and the history (9 sealed file(s))
    |-Script              : PASS: same version (2.0.1) and SHA-256 as the previous run's script
The copy completed, every file in the reference record is in the destination with the same SHA-256, and size and last-modified time match the source; every earlier run record matches its seal and the history

  Failures
    none
===============================================================================
```

## What it does not do

- Hash a file whose name contains `%NAME%` for a defined environment
  variable (e.g. `x %OS% y.txt`) correctly (known issue, to be fixed in the
  next release): it is reported UNREADABLE, so the copy fails, or, if a file
  with the expanded name exists beside it, it gets that file's hash.
- Replace chain-of-custody documentation: it records copies, not who held
  the media, why, seals or signatures.
- Verify an image against its acquisition hash.
- Protect its records from change: the seals only make changes detectable,
  once a seal's SHA-256 is recorded outside the evidence.
- Verify alternate data streams, empty directories, attributes or creation
  times. Robocopy copies them; only each file's main data stream is hashed,
  and only size and last-modified time are compared.
- Hash files whose paths exceed 260 characters, or that only backup mode
  can read. Robocopy copies them, but they are reported as unreadable
  (FAIL).
- Flush file-system metadata or a drive's own write cache: file contents
  are written unbuffered, but only ejecting or dismounting the drive
  flushes the rest.
- Recognise a mapped drive and its UNC path as the same place (in the
  check that source and destination don't overlap).
- Keep the evidence directory's own timestamps as new: robocopy gives it the
  source directory's (`/dcopy:T`), and batch has no way to set them back.
- Read records made by 1.5.x and earlier: their first 2.0 copy starts a
  new reference record.
- Link a copy of a subdirectory to its parent set: the copy starts its own
  reference record.

Opening the CSVs in Excel can evaluate cells that start with `=`; open them
as text, imported as UTF-8. Seals have CRLF line endings: convert them before
`sha256sum -c`.

## Extending

Behaviour is set by tables in the CONFIG section at the top of the script,
each documented beside it, so most changes are a new row rather than code:

- `DRIVE_ROOT_HOUSEKEEPING_DIRS`, `DRIVE_ROOT_HOUSEKEEPING_FILES`:
  housekeeping skipped at a drive root, one row per origin (Windows, macOS,
  Linux).
- `DRIVE_ROOT_RECOVERED_DIRS`: drive-root directories that raise the
  recovered-fragments warning.
- `IGNORED_CUSTODY_FILES`: names ignored beside the evidence and in the
  records directory.
- `COPY_PASSES`, `PASS_<id>_*`: the robocopy passes (size split, threads,
  flags).
- `ROBOCOPY_EXIT_<bit>_*`: what each robocopy exit-code bit means and whether
  it fails the copy.
- `FILESYSTEM_WARNING_<file system>`: destination file systems that get a
  warning.
- `SLEEP_SETTINGS`: power settings read for the sleep advice.
- `CONTAINER_ATTRIBUTES`: attributes cleared from the destination evidence
  directory.
- `UTC_METHODS`, `ELEVATION_CHECKS`, `FILESYSTEM_METHODS`: ordered
  fallbacks; each name is a helper (`:utc_from_<name>`,
  `:elevation_check_<name>`, `:filesystem_from_<name>`).

The record layout, names and history columns are part of the 2.x contract:
later 2.x versions read every earlier 2.x record and only add information
as new files in run records; the history's columns never change in 2.x.

The script header lists the terms and the conventions for contributors:
naming, paths with special characters, what goes to the console and what to
the log.

## Licence

0BSD. See [LICENSE](LICENSE).
