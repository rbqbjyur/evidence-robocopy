# evidence-robocopy

A Windows batch wrapper around robocopy for copying forensic disk images
(E01/EWF, single or split) between drives: master to working copies, to
servers, to archive. It uses only tools built into Windows, so it can travel
with the evidence. It can verify the copy by comparing the SHA-256 of every
file in source and destination.

## What it does

- Prompts for: log file or on-screen ETA (one or the other, so the log stays
  readable), source, destination, and whether to verify.
  Paths can be typed, pasted with quotes, or dragged into the window.
- Refuses relative paths, and refuses a source and destination that are the
  same or inside each other. If the destination already holds files, it says
  so (robocopy overwrites same-named files that differ) and asks before
  continuing.
- Copies the contents of the source folder into the destination folder
  with robocopy, keeping data, attributes and timestamps of files and
  subfolders (`/copy:DAT /dcopy:DAT`), so anything hidden stays hidden.
  Owner and permissions are deliberately not copied: the copies inherit the
  destination's permissions, since the source's users and groups usually
  don't exist on the target system.
  Empty folders are included (`/e`); junctions are not followed (`/xj`).
  Failed files are retried twice, 5 s apart. When run elevated it uses
  backup mode (`/b`), so file permissions don't block reads.
- Copies in two passes: files of 100 MiB or more unbuffered (`/j`) and
  single-threaded, smaller files with half the logical processors (1–128).
- Treats the source and destination folders as containers of the evidence,
  not as evidence themselves:
  - skips `$RECYCLE.BIN` and `System Volume Information` only where the
    source or destination is a drive root (`E:\`), where they belong to the
    volume; anywhere else, including any UNC path, they are copied as
    contents;
  - clears any Read-only, Hidden or System attribute that robocopy carries
    from the source folder onto the destination folder, unless the
    destination already had it. Otherwise the destination can turn hidden, or
    take the source folder's name and icon from a copied `desktop.ini`.
- Before copying, reads the power plan (`powercfg`, no admin needed) and
  warns if the machine may sleep or hibernate during the copy, on mains or
  on battery, or when the lid is closed. It can't tell whether the machine
  is plugged in right now, so the advice covers both.
- Warns if the destination is FAT32 or FAT (file size limits, 2 s
  timestamps).
- Checks robocopy's exit code after each pass and explains it in the log.
- Verification (optional): lists files with robocopy (including Hidden and
  System files, with the same exclusions), hashes each source file and its
  copy with `certutil`, and compares them by relative path. Reports files
  that are mismatched, missing, unreadable, or only present in the
  destination.
- Ends with a summary and a result:

  | Result     | Exit code | Meaning |
  |------------|-----------|---------|
  | PASS       | 0         | Copied, and every source file verified identical. |
  | FAIL       | 1         | A copy failure, or any file not verified identical, or the run could not start. |
  | UNVERIFIED | 2         | Copied without failures; verification not requested. |

  Files only present in the destination are warnings and don't fail the run.

## Output

Written to the destination root, named with the UTC start time:

- `robocopy_YYYYMMDDTHHMMSSZ.log` (log mode only): run header (script
  version, path and SHA-256, host, user, Windows version, elevation, UTC
  start and local offset, source and destination volume label, serial and
  file system, sleep settings, options), the robocopy output, verification problems, and the
  summary. Robocopy's Started/Ended times are local time; its per-file times
  are UTC. The log is written to `%TEMP%` during the run and moved to the
  destination at the end, so robocopy doesn't count it as an extra file. In
  ETA mode the same information is shown on screen only.
- `robocopy_YYYYMMDDTHHMMSSZ_hashes_source.csv` and
  `..._hashes_destination.csv` (when verifying): `"File","SHA-256"`, one row
  per file, sorted by relative path. A file that could not be hashed has
  `UNREADABLE` in place of a hash. `certutil` can't hash empty files, so a
  zero-byte file gets the SHA-256 of empty input (`e3b0c442…b855`).

## Requirements

- Windows with `robocopy` and `certutil` (both built in). Tested on
  Windows 11 (build 26200). Copying folder attributes (`/dcopy:DAT`) needs a
  recent robocopy; Windows 7's only supports `/dcopy:T`. Older versions are
  untested.
- For the UTC time it uses robocopy's clock plus the registry time-zone bias
  (`ActiveTimeBias`), falling back to `wmic` where present.
- Administrator rights are optional; they enable backup mode.

## Usage

Run `evidence-robocopy.bat` (as administrator for backup mode) and answer the
prompts. `evidence-robocopy.bat /?` shows a short help.

## What it does not do

- Verify alternate data streams or empty directories. Only each file's main
  data stream is hashed.
- Verify an image against its acquisition hash. That needs an EWF verifier.
- Hash files whose names contain characters outside the console code page, or
  whose paths exceed 260 characters. Robocopy copies them, but verification
  reports them as unreadable, so the result is FAIL.
- Recognise a mapped drive and its UNC path as the same place.
- Verify files that only backup mode can read: robocopy copies them when
  elevated, but `certutil` can't open them, so they are reported as
  unreadable and the result is FAIL.
- Keep the destination folder's own timestamps: robocopy gives it the source
  folder's (`/dcopy:T`), and batch has no way to set them back.

## Licence

0BSD. See [LICENSE](LICENSE).
