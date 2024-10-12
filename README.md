# Welcome to miniface!

This is some basic code to make use of the features present in [MINI](https://github.com/fail0verflow/mini). 
At the time of writing, the project works (excluding some features), however we cannot yet provide pre-compiled binaries for safety reasons. If you can compile yourself - you'll probably be safe too.

## Features

* Backup of Wii OTP and SEEPROM data
  - including automatic backups, if none are found on SD for this console
* Full backup of NAND with appended keys.bin
  - the appended keys.bin is NOT compatible with CE1LING_CAT due to lack of header information, a gamecube controller will always be needed
* System info printing
  - boot1 version (like CE1LING_CAT)
  - SEEPROM boot2 version
  - serial number
  - NAND usage (in permille)
  - TMD boot2 version
  - System menu (with user-string), BC and MIOS versions
* SEEPROM restore
* NAND restore (without bootblocks)
* Booting system menu, HBC (titleid LULZ), IOS 254 (BootMii stub for MINI reloads)
* Booting `sd/bootmii/ppcboot.elf`
* Support for CE1LING_CAT-style `sd/bootmii/bootmii.ini`
  -  options supported and supported inputs:
    * `VIDEO=`: 4th symbol controls video output mode
      - `C`: NTSC
      - `5`: PAL50
      - `6`: PAL60
      - `G`: Progressive/480p
    * `BOOTDELAY=`: integer value from 0 to 10 seconds to denote autoboot timeout. Must be used with `AUTOBOOT=`, otherwise reset!
    * `AUTOBOOT=`: 1st symbol controls autoboot target. Must be used with `BOOTDELAY=`, otherwise the main menu will load!
      - `S`: SYSMENU for system menu
      - `H`: HBC for Homebrew Channel (LULZ)
      - `0`: title ID (full title ID needed, ex. `0000000100000002`)
      - `/`: MINI-compatible .elf executable (full path needed, compliant with 8.3 naming, ex. `/bootmii/mike5.elf`

## Bugs
* If miniface is loaded from IOS<-HBC, autoboot parameters are still executed, unlike CE1LING_CAT, which could cause unwanted behavior
* `bootmii.ini` options must be within the first 4KB of the file for the parser to work
* in `bootmii.ini` adding "#" before lines does not comment the options, they need to be mangled/removed instead
* when giving a title to `boot2_run()`, its' presence in NAND is not checked, which could potentially lock up the system
* the ELF loading code may be exploited into a UaF from a memory leak protection
* the ELF loading code does not check the binary size and may try to `malloc()` more than MEM1 size, which could potentially lock up the system (slightly less than 24MB)
* `keys.bin` is not generated separately
* `keys.bin` appended to NAND backups does not pass CE1LING_CAT checks due to lack of `BackupMii` header info
* currently no code exists to activate godmode
* only 8.3-style filenames are supported, adding LFN support requires adding a 62KB magic table and would only be useful in 2 functions (godmode and autobackup)
* only 16777216 unique OTPs can be backed up on one SD card
* use of MINI/`armboot.bin` provided by the HackMii Installer is unsupported, due to lack of SEEPROM write logic
* RESET key is disabled because pressing it makes it spam instead of input only after push-down

## To-do list

* Boot more than `sd/bootmii/ppcboot.elf` during runtime
* Support a GUI
* Support USB keyboards
* Support switching to IOS and to MINI without code reloads, with limitations applied to IOS
* Support DI (unlikely to do so)
* Optimize NAND restores, basic optimizations currently break SFFS and take longer than CE1LING_CAT (25min all data blocks from miniface -> 15min from CE1LING_CAT)
* Optimize NAND backups, (45min miniface -> 17min from CE1LING_CAT w/ verification)
* Add more safeguards
* Add fool-proof godmode logic
* Support writing boot2 safely (right now have to deal with ECC and HMAC, best+easiest approach is to use a known-good backup from the same console, which may not be an option for everyone)
* Detect when miniface is loaded from IOS<-HBC and boot2 to avoid executing autoboot parameters if unneeded
* Detect BootMii chainloader stub in boot2

## Compilation

Compilation can be done with your current setup. 

You will need a `powerpc-none-elf` chain. At the time of writing, devkitPPC does not distribute precompiled binaries for this chain. 
Using its' `powerpc-eabi` compilers will **not** work and cause your system to blackscreen.

If you're unsure on how to obtain these compilers, you are welcomed to try using `autobuild.sh` provided in [this `ppcskel` repository](https://github.com/AndrewPiroli/ppcskel/tree/master/compiler).

Afterwards you could probably do `export WIIDEV=/opt/devkitamateur` or wherever you have the `bin` folder with the compilers mentioned above.


Have fun and contribute if you feel like it.
