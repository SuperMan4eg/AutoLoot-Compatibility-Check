# AutoLoot Compatibility Check

This is a read-only diagnostic tool for Assassin's Creed Odyssey AutoLoot.
It helps the mod author compare different official or modified builds of
`ACOdyssey.exe` without asking users to upload the copyrighted game executable.

The checker:

- reads the executable selected by the user;
- calculates its SHA-256 hash and file size;
- records PE section metadata and hashes;
- compares a small set of reference code signatures;
- writes `AutoLootCompatibilityReport.txt` next to the checker.

The checker does **not** start the game, attach to a process, install a hook,
change memory, modify the executable, or load the AutoLoot plugin.

## Player use

1. Download and extract the diagnostic archive.
2. Copy its three runtime files next to `ACOdyssey.exe`.
3. Run `Run_AutoLoot_Compatibility_Check.bat`.
4. Send `AutoLootCompatibilityReport.txt` to the AutoLoot author.

Do not upload or send `ACOdyssey.exe`.

See [BUILDING.md](BUILDING.md) for reproducible build instructions.

## Support status

A successful diagnostic report does not automatically make a game build
supported. AutoLoot remains disabled for every executable that has not received
a dedicated profile and an in-game validation.

