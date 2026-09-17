# AutoLoot Compatibility Check

This is a read-only diagnostic tool for Assassin's Creed Odyssey AutoLoot.
It helps the mod author compare official, older, modified, Game Pass, and
Ubisoft+ builds without asking users to upload copyrighted game executables.

Version 10 automatically scans both supported executable names when present:

- `ACOdyssey.exe`
- `ACOdyssey_plus.exe`

For every discovered executable the checker records:

- the real filename, file size, SHA-256, and known-build status;
- separate binary-profile and runtime-filename support status;
- PE image metadata plus section names, sizes, RVAs, and SHA-256 hashes;
- read-only snapshots of AutoLoot component-table and Extended Reach regions;
- exact and relocation-masked reference-signature matches;
- automatic E9 rel32 trampoline resolution with final RVA and post-jump bytes;
- bounded candidate windows and direct-call xrefs used for porting;
- the existing 1.5.3 manual-wrapper and Extended Reach mapping diagnostics;
- a compact per-file porting summary with `unique`, `ambiguous`, or `missing`
  status for each critical signature and hook pattern. Trampoline-resolved signatures can be reported as resolved_unique.

All raw results are namespaced as `scan.0.*`, `scan.1.*`, etc. The compact
results are written as `summary.0.*`, `summary.1.*`, etc., making reports easy
to compare programmatically across builds.
The checker does **not** start the game, attach to a process, install a hook,
change memory, modify an executable, or load the AutoLoot plugin.

## Player use

1. Download and extract the diagnostic archive.
2. Copy the three runtime files into the Assassin's Creed Odyssey game folder.
3. Run `Run_AutoLoot_Compatibility_Check.bat`.
4. Send `AutoLootCompatibilityReport.txt` to the AutoLoot author.

If both executable names are present, v10 scans both automatically. No renaming
or file-selection step is required.

Advanced users may run `AutoLootCompatibilityCheck.exe` with one or more
explicit executable paths; those files will be scanned instead of auto-discovery.

Do not upload or send either game executable.

See [BUILDING.md](BUILDING.md) for reproducible build instructions.

## Support status

A successful diagnostic report does not automatically make a game build
supported. `binary_profile_supported` and `runtime_filename_supported` are
reported separately, and `currently_supported` is true only when both are true.
Known unsupported candidates remain disabled until AutoLoot receives a dedicated
profile and in-game validation.
