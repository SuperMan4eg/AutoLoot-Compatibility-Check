AUTOLOOT COMPATIBILITY CHECK v13

This tool only reads Assassin's Creed Odyssey executable files. It does not
start or modify the game, install a hook, change memory, or alter game files.

Version 13 automatically checks both names when they exist in the game folder:
  ACOdyssey.exe
  ACOdyssey_plus.exe

1. Copy these three files into the Assassin's Creed Odyssey game folder:
   AutoLootCompatibilityCheck.exe
   Run_AutoLoot_Compatibility_Check.bat
   README.txt
2. Double-click Run_AutoLoot_Compatibility_Check.bat.
3. Send AutoLootCompatibilityReport.txt to the AutoLoot author.

No file selection or renaming is required. If both EXE files are present, both
are scanned and stored in one report as scan.0.*, scan.1.*, etc.

The report separates binary-profile support from runtime filename support and
resolves E9 rel32 trampolines to their final code RVA and includes a compact
porting summary for Game Pass / ACOdyssey_plus.exe and older
1.5.3 builds.

Do not send or upload ACOdyssey.exe or ACOdyssey_plus.exe.

A report does not make a build supported automatically. A dedicated AutoLoot
profile and an in-game validation are still required.


