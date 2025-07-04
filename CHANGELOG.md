Changelog
=========

v1.7.3 (2025-07-04)
-------------------
- A_ITALIC is unknowned on some macOS?

v1.7.2 (2025-07-04)
-------------------
- Control the application lifecyle with masked signals
- Some code refactoring

v1.7.1 (2025-02-06)
-------------------

- Use an implentation of the key derivation algorithm PBKDF2 (with HMAC_SHA256)
- Some code refactoring

v1.7.0 (2024-12-13)
-------------------

- Now, you can edit an existing entry
- Now, when the main key is not used, it is left masked in memory
- A more beautiful interface

v1.6.1 (2024-12-10)
-------------------

- Add a brute force attack shield
- Modify screen lock to 60 s.
- Add the possibility of resizing the terminal

v1.6.0 (2024-07-03)
-------------------

- Some corrections and changes suggested by sonar-lint and valgrind tools
- After deleteting an entry, the main window is also clear
- Now, when typing the main password, characters are masked one by one
- The screen is lock after 15 s. elapsed without a new command has been typed

v1.5.0 (2022-12-16)
-------------------

- A better user interface (with the ncurses library)

v1.4.0 (2022-11-28)
-------------------

- New conception: two threads (one for HMI and one for core functions) and a shared list of commands 
- The linked list is now generic
- Minor improvements (code factorization and code suppression)

v1.3.0 (2022-04-21)
-------------------

- A new functionality: importation / exportation is available
- A new security guarantee: the encryption key is linked to the executable
- A better security: AES256 is now used and replace AES128
- Minor improvements

v1.2.0 (2022-02-25)
-------------------

- A new functionality: it is now possible to delete an entry
- Bug correction in del_Element_DLList (delete a node at position x of the list)

v1.1.0 (2022-02-23)
-------------------

- A new functionality: a backup file is created each time the user adds a new entry
- Better code with a double-linked list

v1.0.1 (2022-01-18)
-------------------

- Better code with a structure Entry

v1.0.0 (2022-01-17)
-------------------

Users can:
- Choose a master password
- Add a new entry : a couple of secret information
- Print current entries
- Search and print entries according a pattern