# evidence-robocopy

A Windows batch wrapper around robocopy for copying forensic disk images
(E01/EWF, single or split) between drives: master to working copies, to
servers, to archive. It uses only tools built into Windows, so it can travel
with the evidence. It can also compare SHA-256 hashes of source and
destination.

## What it does

- Prompts for: log file or on-screen ETA, source, destination, and whether to
  verify hashes.
- Copies recursively with robocopy, keeping file data and timestamps
  (`/copy:DT /dcopy:DT`). When run elevated it uses backup mode (`/b`), so file
  permissions don't block reads.
- Copies in two passes: files of 100 MiB or more unbuffered (`/j`) and
  single-threaded, smaller files multithreaded.
- Skips `$RECYCLE.BIN` and `System Volume Information` at the source drive
  root. Clears Hidden and System on copied files (`/A-:SH`), so the destination
  folder doesn't end up hidden when the source is a drive root.
- If verification is chosen: hashes every file in source and destination with
  `certutil`, writes the hashes to CSV, then compares the two CSVs.
- Writes its output to the destination root:
  - `robocopy_<timestamp>.log`
  - `robocopy_<timestamp>_hashes_source.csv`
  - `robocopy_<timestamp>_hashes_destination.csv`

## Requirements

- Windows with `robocopy`, `certutil` and `wmic`.
- Administrator rights are optional; they enable backup mode.

## Usage

Run `evidence-robocopy.bat` (as administrator for backup mode) and answer the
prompts. Enter paths without quotation marks.

## What it does not do

- Copy attributes, owner or ACLs. Hidden and System are cleared on copied
  files.
- Verify an image against its acquisition hash. That needs an EWF verifier.

## Licence

0BSD. See [LICENSE](LICENSE).
