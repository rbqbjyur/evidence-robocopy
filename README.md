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

<img src="docs/images/demo.webp" alt="Console: a forensic copy of an EWF image set from W:\Processing\EV03 to a working copy on a USB drive: the source and destination typed at the prompts, the header, then the live display with each check's status, the copy's bar moving through three segments, the checks passing one by one, and the result block, RESULT: PASS (exit code 0)">

A forensic copy to a USB drive, with the live display. The copy is sped up
ten times; the prompts, the checks and the result block play at real speed.

## Table of contents

- [What it does](#what-it-does)
- [Install](#install)
- [Usage](#usage)
- [Set and evidence directories](#set-and-evidence-directories)
- [History and run records](#history-and-run-records)
- [Checks between copies](#checks-between-copies)
- [Verifying a set in place, and moving one](#verifying-a-set-in-place-and-moving-one)
- [Non-forensic mode](#non-forensic-mode)
- [What the records prove](#what-the-records-prove)
- [What it does not do](#what-it-does-not-do)
- [Contributing](#contributing)
- [Licence](#licence)

## What it does

- **Forensic by default.** Every run keeps a log, verifies every file and
  adds a sealed run record, without asking. `/nonforensic` is a separate
  plain copy utility for non-evidence copies (see below).
- **Evidence and custody files kept apart.** The evidence is copied as one
  directory, under its own name, into a *set directory*; beside it are the
  *custody files*: the script, the history and the records directory. Nothing
  is ever written into the evidence directory, and a copy never writes to
  the source (`/check` writes its record into the set it checks and
  `/relocate` moves a set, each confirmed first). See [Set and evidence
  directories](#set-and-evidence-directories).
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
  exactly, or to 2 s where FAT or exFAT or a network share is involved.
- **A sealed record of every copy, and a history.** Each run writes its
  log, hash CSVs and history into a run record of its own, sealed with
  their SHA-256s. On every copy, every earlier run record is checked against
  its seal and against the history. See [History and run
  records](#history-and-run-records).

  <img src="docs/images/history-in-calc.webp" alt="LibreOffice Calc: the history of a set, seven runs, each PASS, with the source directory and volume of each copy">

  *The history in a spreadsheet: one row per copy (first five of 13 columns).*

- **Checks between copies.** A different script version, and a set that
  reached this drive by other means since the run that made it, are
  flagged. See [Checks between copies](#checks-between-copies).
- **A set verified in place, or moved.** `/check` verifies a set where it
  is, without copying, and records the check in it; `/relocate` moves a
  set to a new place on the same volume, verifies it there and records the
  move, so later copies don't flag it. See [Verifying a set in place, and
  moving one](#verifying-a-set-in-place-and-moving-one).
- **Evidence counts are evidence only.** The custody files are copied in a
  pass of their own and hashed with their own counter into a separate CSV,
  so robocopy's totals, the hashing counters and the summary count evidence
  only, however many copies the set has been through.
- **A result that says what it covers**, with an exit code:

  | Result     | Exit code | Meaning |
  |------------|-----------|---------|
  | PASS       | 0         | The copy completed, every file in the reference record is in the destination with the same SHA-256, sizes and last-modified times match the source, and every earlier run record matches its seal and the history. |
  | FAIL       | 1         | The copy failed, a file in the reference record differs, is missing or unreadable, a file in the evidence directory isn't in the reference record, a file's size or last-modified time differs, a run record or the history doesn't check out, the script check failed, the run record couldn't be sealed or written back, or the run could not start. |
  | UNVERIFIED | 2         | `/nonforensic` only: copied without failures, verification declined. |

  The output is in sections named after the checks. The summary lists every
  warning and everything that failed the run, then ends with a result block:
  the verdict, each check in the order it ran (Script, Copy, Metadata, Run
  records, Hash) with a pointer to the section that explains anything not
  passed. On screen the block comes last, after the run record is written
  back, with a line for that write; PASS, WARN and FAIL are coloured where
  the console supports it (never in the log). A check reads WARN when it
  passed with a warning (a script newer than the previous run's, or run
  records that match after a warning about them before the copy); a WARN
  never fails the run. Lines are kept within 80 characters, except hashes
  and long paths. A file in the evidence
  directory that the reference record doesn't list (added since) fails the
  run: it is unexplained and not verified against anything.

  <img src="docs/images/end-summary.webp" alt="Console: the result block of run 7, RESULT: PASS (exit code 0) with the Script, Copy, Metadata, Run records, Hash (SHA-256) and Record written checks each PASS, then the seal's SHA-256 for the custody notes and the log's location">

  *The result block: the verdict and each check.*

- **Warnings up front.** Before copying, everything to be wary of is listed
  in one **Warnings** section at the top of the log header, and repeated in
  the summary: the machine may sleep or hibernate, or its power settings
  can't be read; the clock's last synchronisation is older than 7 days or
  isn't known, or its status can't be read; the destination is FAT32/FAT; a copy pass doesn't write unbuffered; a drive root holds fragments
  recovered by file-system repairs (`FOUND.nnn`, `LOST.DIR`; copied as
  contents); the source has no history, so the copy isn't checked against
  an earlier record; run records the Run records check will fail; a newer
  script than the previous run's; the set was moved or copied by other
  means; the console couldn't be switched to UTF-8. Links in the source
  that weren't copied are found after the copy, so they are listed with the
  summary's warnings.
- **Live display.** While a forensic run works, the console shows one
  block, redrawn in place: each check of the result block with its status
  or a progress bar with an estimate of the time left (from the average
  rate since that stage began; the hashing bars count bytes, with a fixed
  share per file), the file being copied (with robocopy's percentage
  within each large file) or hashed, and the last warnings and failures.
  Console only: the log and the records are written as before. Windows 10
  or later, not the legacy console, in a window of at least 23 rows and 80
  columns that keeps its size during the run; a smaller window, or
  `EVIDENCE_ROBOCOPY_PLAIN=1`, gives the plain output instead (robocopy's
  per-file lines, a line per hashed file), e.g. when the output is
  captured. On a console 100 columns or wider the header's Source and
  Destination sections sit side by side; the log keeps one column.
- **Update check.** Every run asks github.com once which release is the
  latest (a header-only request to the releases page, with a 3 s limit)
  and warns when this script is older, or newer than any release; it never
  updates itself. Offline, behind a proxy, or without `curl.exe`, the run
  goes on with a warning that it couldn't check. `/update` downloads the
  latest release and its `evidence-robocopy.bat.sha256`, checks the
  download's SHA-256 against it and its version line, replaces this file
  and starts the updated script for a normal run; nothing is recorded
  (records are for the evidence). A file that can't be replaced
  (read-only, in use) is left and said so. A set's own copy updated this
  way is flagged by the next copy's Script check, as any replaced copy.
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
  (1–128); then the custody files in a pass of their own. A pass with no
  file in its size class is skipped (the last pass always runs, so every
  directory is created). A failed file is retried once after 2 s, so real
  failures surface quickly; a file certutil can't read is hashed again
  once after 2 s before it is recorded as UNREADABLE.
- **Records are UTF-8** with CRLF line endings, and every CSV cell is
  quoted.

## Install

Download `evidence-robocopy.bat` and `evidence-robocopy.bat.sha256` from the
[latest release](https://github.com/rbqbjyur/evidence-robocopy/releases/latest)
and check that the script's SHA-256 matches the one in the `.sha256` file:

```
certutil -hashfile evidence-robocopy.bat SHA256
type evidence-robocopy.bat.sha256
```

Nothing else is installed: the script is one batch file, run from wherever
it is, and every forensic run puts a copy of it in the set it writes.
`/update` replaces it with the latest release later (see [Usage](#usage)).

### Requirements

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
- The live display and the console colours need a console that takes VT
  sequences: Windows 10 or later, not the legacy console. Elsewhere the
  output is plain.
- The update check and `/update` use `curl.exe` (built into Windows since
  10 1803). Without it, or offline, the check reports "not checked" and
  the run goes on.

## Usage

```
evidence-robocopy.bat                 forensic mode (default)
evidence-robocopy.bat /check          verify a set in place, no copy; a run
                                      record and a history row into the set
evidence-robocopy.bat /relocate       move a set within its volume, verify it
                                      there and record the move
evidence-robocopy.bat /update         replace this file with the latest release
                                      if it is newer, then a forensic run
evidence-robocopy.bat /nonforensic    plain copy utility, no log or records
evidence-robocopy.bat /?              help
```

Run as administrator for backup mode. Any other argument stops the run.
`EVIDENCE_ROBOCOPY_PLAIN=1` in the environment gives the plain console output
instead of the live display; `NO_COLOR=1` turns colour off. Neither changes
the log or the records.

<img src="docs/images/destination-prompt.webp" alt="Console: the banner, the source directory G:\Export\EV03 and the destination directory H:\Review\EV03 typed at the prompts">

*Source and destination, typed at the prompts.*

## Set and evidence directories

A **set directory** holds exactly one **evidence directory** and the **custody
files**: the script, `evidence-robocopy-history.csv` and
`evidence-robocopy-records\`. Set directories and the records directory may also
hold the files Explorer and macOS leave when browsing (`.DS_Store`, `._*`,
`.apdisk`, `desktop.ini`, `Thumbs.db`, `.directory`); they are ignored, not
copied or hashed. Inside the evidence directory they are evidence.

<img src="docs/images/set-tree.webp" alt="tree /f of a set directory: the history and the script copy, the records directory with three sealed run records, and the evidence directory Images with EV03.E01 to E03 and the acquisition log">

*A set: the evidence, the script, the history and a sealed record of each copy.*

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
- `…_relocation.txt` (only when the run was a `/relocate`): what was
  moved, from where to where, when, by whom and on what.
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
| Source directory | the source set directory, or for a first copy the evidence directory copied; for a relocation, where the set was |
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

Any of these failing fails the run. The same checks run before copying,
on the set whose history the copy continues, every run record against its
seal included: anything they find is listed in the header's Warnings, so it
is seen before the copy starts; the result comes from the check of the
copies afterwards. A history row that doesn't name a run (a run's UTC time)
fails the check. The history beside the evidence is
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
is refused before copying: sets are never mixed. If the source's history is
unusable but the destination's matches its run records, a rerun continues
the destination's history and the copy fails for the source's problem. The
history follows this copy's line of descent: copies branched off earlier
don't see each other.

An interrupted run leaves a partial copy and no run record in the
destination; its log stays in `%TEMP%` (header "Log during run"). A
destination holding a partial copy without custody files is refused: delete
the partial copy and run again. If the
run record can't be sealed completely or written at the end, the
destination gets the history the run continued, unchanged, the files stay
in `%TEMP%`, and the exit code is FAIL. The run's log
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

## Verifying a set in place, and moving one

`/check` is a forensic run without a copy: the SOURCE prompt only (a set
directory or its evidence directory; raw evidence is refused, since there
is nothing to verify it against), then, confirmed, every file in the
evidence directory is hashed and compared with the set's reference record,
and every run record is checked against its seal and the history, as on a
copy. A run record and a history row are written into the set (the row's
source and destination are both the set). The Copy and Metadata rows of
the result read NONE: nothing was copied, so there is nothing to compare
sizes and times with. A set whose history names no reference record is
refused.

`/relocate` moves a set to a new location on the same volume: the SOURCE
prompt (a set), then the new location (a full path that doesn't exist yet,
in a directory that does), confirmed. The checks that read the set run
first, where it is; then the set is moved (one rename within the volume:
instant, and done or not), verified at its new location as `/check` does,
and the move is recorded: a history row with the old path as the source
and the new as the destination, and a sealed `…_relocation.txt` in the run
record saying it was a move, not a copy. Later copies compare the set's
location with that row, so a set put right this way isn't flagged as moved
by other means. Refused: a location that exists, another volume (that is a
copy), a network path (its volume can't be read), a location inside the
set, raw evidence, and the set the script itself runs from. A move that
fails leaves the set where it was, and the run stops with the reason.

## Non-forensic mode

`/nonforensic` is a plain copy utility for non-evidence copies, confirmed
when chosen: it copies the source directory's contents into the destination
with ETA progress, keeps no log and writes no records, and treats custody
files and histories like any other file. It optionally verifies every file
by SHA-256 and metadata against its source, with the result on screen only.
A later forensic run on its output treats it like any other copy made
without the script.

## What the records prove

- Each run record shows what that run did and found: when (UTC, with the
  clock's source and sync state), on which host and under which account,
  with which script (its SHA-256), from where to where, robocopy's own
  output, and the SHA-256 of every evidence file. Its seal makes any later
  change to it detectable.
- Every copy is verified against the reference record made at the first
  copy, not only against the copy before it. Nothing before the first copy
  is covered: the reference record is not compared with an acquisition
  hash.
- The history shows the order of the runs and that no run record has been
  removed from it or added outside it. Each sealed history holds every
  earlier run's seal SHA-256, so the newest seal SHA-256 anchors the whole
  chain.
- A set is checked only when it is copied again or checked in place
  (`/check`); between those nothing checks it.
- A relocation's run record shows the set was moved by this script, from
  where to where; a set moved by other means gets no row, and only the
  Location warning of the next copy shows it. A relocation interrupted
  between the move and its record leaves the set at its new place with no
  row: it then looks like a set moved by other means.
- The seals are plain SHA-256 values, not signatures: they make a change
  detectable, not impossible. Someone with write access to the set and the
  script can build a new, consistent chain, or remove the newest run record
  together with its history row; only seal SHA-256 values recorded outside
  the set (e.g. in the custody notes) show either.
- A record can't show what happened after it was sealed: a write-back that
  failed afterwards is shown by the exit code, not by the log.
- The script never vouches for itself: the Script check flags a different
  or older script, but only the published release shows which one is
  genuine.
- Host, user and times are what that machine reported (`hostname`, the
  logon token, its clock).
- Outside the seals: junk names (`desktop.ini`, `Thumbs.db`, `.DS_Store`
  and the like) in the records directory, and `.partial` directories
  (interrupted write-backs: warned about, outside the history). A set
  copied by other means gets no history row; only the Location warning
  shows it.

## What it does not do

- Replace chain-of-custody documentation: it records copies, not who held
  the media, why, seals or signatures.
- Verify an image against its acquisition hash.
- Protect its records from change: the seals only make changes detectable,
  once a seal's SHA-256 is recorded outside the evidence.
- Verify alternate data streams, empty directories, attributes or creation
  times. Robocopy copies them; only each file's main data stream is hashed,
  and only size and last-modified time are compared.
- Hash files that only backup mode can read. Robocopy copies them, but
  they are reported as unreadable (FAIL).
- Hash a file whose full path, on the source or on the destination, is
  longer than 4,000 characters: robocopy copies it, but cmd can't carry
  such a path, so the run fails and names the file by the first 200
  characters of its path. No mainstream system makes paths this long
  (Linux stops at 4,096 bytes, macOS at 1,024).
- Flush file-system metadata or a drive's own write cache: file contents
  are written unbuffered, but only ejecting or dismounting the drive
  flushes the rest.
- Recognise a mapped drive and its UNC path as the same place (in the
  check that source and destination don't overlap).
- Copy files named like DOS devices (`nul`, `aux` and the like) to a network
  (UNC) destination: Windows refuses to create them there, so the copy
  fails and reports them missing. They copy and verify on local drives.
- Keep the evidence directory's own timestamps as new: robocopy gives it the
  source directory's (`/dcopy:T`), and batch has no way to set them back.
- Read records made by 1.5.x and earlier: their first 2.0 copy starts a
  new reference record.
- Link a copy of a subdirectory to its parent set: the copy starts its own
  reference record.
- Use a proxy: a machine that reaches GitHub only through one reports the
  update check as "not checked" (a warning), and `/update` can't download.
- Move a set to another volume or to or from a network path (`/relocate`
  is a rename within one volume; for another volume, copy the set there).

Opening the CSVs in Excel can evaluate cells that start with `=`; open them
as text, imported as UTF-8. Seals have CRLF line endings: convert them before
`sha256sum -c`.

## Contributing

Questions and bug reports:
[GitHub issues](https://github.com/rbqbjyur/evidence-robocopy/issues).
Pull requests are welcome.

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

[0BSD](LICENSE) (Zero-Clause BSD). Copyright (C) 2024 by outis.
Use it for anything, with no attribution required; provided as is, with no
warranty.
