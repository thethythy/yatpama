# Yet Another Tiny Password Manager or Yatpama

## Presentation

Another password manager in C language because why not ;-)

My objective is to get a simple program able to be compile without extern library link for any POSIX operating system. I have just used the ncurses library for security reasons and for a better user interface.

## Features

- A main password protects informations
- The shape of the main password is controlled by a password policy
- Each information is encrypted with AES 256 (CBC mode) and save in a local file
- Each couple of secret information is controlled by an integrity value (HMAC based on SHA256)
- The encryption key (256 bits) is never saved and is generated by the AES algorithm applied 10,000 rounds in CBC mode from the main password then it is xor-linked to the hash value of the executable file
- Confidential information are decrypted only for displaying; before and after that they are left encrypted in memory
- The local file (that contains encrypted information) is writable and readable only by the owner
- A backup file is automatically created if a local file already exists when a new entry is added

## Compilation and installation

You need a C compiler and the `make` utility or equivalent.

In a terminal, go to the `yatpama` directory.

Just type `make` and you will obtain an executable named `yatpama` to be placed in a directory accessible from your `PATH`.

`make clean` will delete all intermediate files (like `.o` files).

`make delete` will delete all executable files.

## Usage

In a terminal and a directory, a user can:
- Execute `yatpama`
- Choose a main password at first launch (command `p`)
- Add a new entry: a couple of secret information (command `a`)
- List current entries (command `l`)
- Search and print entries according a pattern (command `s`)
- Delete an entry (command `d`)
- Export information to a clear text file (command `x`)
- Import information from a clear text file (command `i`)

After adding the first entry, the file named `yatpama.data` will be created in the current directory. So, a file `yatpama.data` can exist in each directory if you want with a same or a different main paswword.

User can change password until a first entry is added. After that, the same password must be used to get clear information.

User is invited to try `yatpama` with false information until he understands how it works and before using it to store real confidential information.

## Exportation before installing a new version

Each data file `yatpama.data` is linked to the executable file `yatpama` used to create the data file in a way that it is impossible to decypher information without the original `yatpama` version. So, it is **an imperative act to export information before installing a new version of `yatpama`**.

User has to follow the next procedure:
1) Before installation, export information to the temporary file (`yatpama_export.txt`) (command `e`)
2) Install the new version of `yatpama`
3) Execute the new version of `yatpama`

   If a data file `yatpama.data` is found in the current directory from an old version, user will be notified by a help message then the application will exit itself. User has to rename this file `yatpama.data.oldversion` for example before executing the new new version of `yatpama`.

4) Import information with the new installed `yatpama` version (command `i`)
5) Control that the importation is a full success: quit then re-execute `yatpama` and print entries
6) Delete the temporary file (`yatpama_export.txt`) containing clear information if step 5 is a success.

The backup file `yatpama.data.oldversion` can be re-used in case there is a problem with the new version. In this case, user has to re-install previous version of `yatpama` indicated a step 3 then renames `yatpama.data.oldversion` to `yatpama.data`.

## Todo

For now, the user can not edit entries. I will add this functionality in future versions. If you need to modify an entry, it is always possible to add a new entry containing modifications you want then delete the undesired entry.

I have planned to add a shield against password brute force attack.

I will also add more security in the user interface (mask main password during edition, etc.).

## COPYRIGHT

This project is under [*GNU General Public License v3.0*](LICENCE.txt)

- This project use [Tiny AES in C](https://github.com/kokke/tiny-AES-c) under The Unlicense (files [aes.h](lib/aes.h) [aes.c](lib/aes.c) [test_AE128.c](test/test_AES128.c))

- This project use a modified version of the SHA256 implementation of [Brad Conte](https://github.com/B-Con/crypto-algorithms) that is in public domain (files [sha256.h](lib/sha256.h) [sha256.c](lib/sha256.c))