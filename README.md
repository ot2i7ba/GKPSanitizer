# GKPSanitizer
GKPSanitizer is a Python script created to filter and sanitize password data extracted by Magnet Forensics GrayKey [^1]. GrayKey often generates large, cluttered text files that may contain duplicates, JSON-like entries, or other unwanted data. GKPSanitizer helps you clean up those files so they become more readable and manageable for further analysis. Inspired by [gpcleaner](https://github.com/ot2i7ba/gpcleaner), this script has been customized to meet specific forensic needs, enabling professionals to streamline their workflow. Sharing this tool aims to benefit others in the forensic community.

> [!NOTE]
> This tool only sanitizes (i.e., removes redundant or unwanted lines and duplicates). It does not guarantee the correctness or validity of the passwords themselves.

> [!WARNING]
Please note that this script is currently under development, and I cannot provide a 100% guarantee that it operates in a forensically sound manner. It is tailored to meet specific needs at this stage. Use it with caution, especially in environments where forensic integrity is critical.

> [!CAUTION]
> This project is based on the original repository by [ot2i7ba](https://github.com/ot2i7ba).

## Table of Contents
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
   - [Usage](#usage)
   - [PyInstaller](#pyinstaller)
   - [Releases](#releases)
- [Example](#example)
- [Changes](#changes)
- [License](#license)

# Features
- Designed for GrayKey Exports: Streamlines raw text files containing potential passwords (or email/password combinations).
- Filtering & Sanitizing: Excludes duplicates, JSON-like lines, and entries outside user-defined length constraints.
- Dual Operation Modes:
  - Password List: Extracts only passwords based on a chosen prefix.
  - Email:Password Combo: Creates combined credential pairs if valid emails are found.
- Sets for De-duplication: Ensures you get a unique list of passwords or combo lines.
- Progress Spinner: Displays a lightweight spinner in the console during long operations.
- Lightweight & Easy to Use: No external libraries required beyond Python’s standard library.

# Requirements
- Python 3.7 or higher

# Installation
1. **Clone the repository**

   ```sh
   git clone https://github.com/ot2i7ba/GKPSanitizer.git
   cd GKPSanitizer
   ```

## Usage
1. **Export or copy the GrayKey-generated text file(s) (e.g., passwords.txt) into the project folder.**

2. **Run the script**
   ```sh
   python GKPSanitizer.py
   ```

## Follow the Prompts
- Select or provide the path to your GrayKey-exported file.
- Choose between creating a Password List or an Email:Password Combolist.
- Enter your desired prefix (e.g., "Item value:"), as well as minimum/maximum password lengths.
- Review the cleaned output in a newly generated file (e.g., passwords_clean_00.txt or combolist_00.txt).

## PyInstaller
To compile the GKPSanitizer script into a standalone executable, you can use PyInstaller. Follow the steps below:

1. Install PyInstaller (if not already installed):
   ```bash
   pip install pyinstaller
   ```

2. Compile the script using the following command:
   ```bash
   pyinstaller --onefile --name GKPSanitizer --icon=gkpsanitizer.ico GKPSanitizer.py
   ```

- `--onefile`: Create a single executable file.
- `--name GKPSanitizer`: Name the executable GKPSanitizer.
- `--icon=gkpsanitizer.ico`: Use gkpsanitizer.ico as the icon for the executable.

**Running the executable**: After compilation, you can run the executable found in the dist directory.

## Releases
A compiled and 7zip-packed version of GKPSanitizer for Windows is available as a release. You can download it from the **[Releases](https://github.com/ot2i7ba/GKPSanitizer/releases)** section on GitHub. This version includes all necessary dependencies and can be run without requiring Python to be installed on your system.

# Example

## The script lists available TXT files and prompts for selection**
   ```sh
        GrayKey Password Sanitizer [GKPS] v0.1 by ot2i7ba
   ============================================================
   
   Available .txt files:
   
   [1] passwords.txt
   
   [ENTER] Use default: passwords.txt
   [e] Exit GrayKey Password Sanitizer

   Select a file by number, press ENTER for default, or 'e' to exit:
   ```

## After selecting files, the script prompts for options
   ```sh
   Please choose one of the following options:
   
   [1] Create a Password List (only passwords)
   [2] Create a Combo List (email:password)
   
   Your choice [1/2]:
   ```

## Script generate a password list or an email:password combolist, depending on the option selected
   ```sh
   You chose to create a password list (only passwords)
   
   Enter the prefix for line filtering (default: 'Item value:'):
   Enter the minimum password length (default: 4):
   Enter the maximum password length (default: 64):
   
   Processing... |
   Results have been saved to 'passwords_clean_00.txt'.
   Number of unique passwords saved: 262
   Number of duplicates encountered: 311
   Processing time: 0.11 seconds.
   ```

___

# Changes

## v0.0.2
- **Asynchronous Processing:** Converted file processing to asynchronous, line-by-line reading using aiofiles and asyncio to efficiently handle large files.
- **Refined Regex Extraction:** Updated regular expressions to more precisely extract passwords and email:password combinations from the GrayKey output.
- **Improved Length Checking:** Enforced that only values whose lengths fall between the specified minimum and maximum are processed. (The default maximum length has been reduced from 64 to 20.)
- **Configurable Output File Names:** Output file name prefixes are now defined via constants. Files generated with these prefixes are excluded from the file selection menu.
- **Birthdate-Based Passwords:**
  - Introduced an optional feature where users can choose to include additional password combinations based on a birth date.
  - Users must enter a birth date in the format DD.MM.YYYY (with two-digit day/month and a four-digit year).
  - The feature generates combinations using all possible permutations of non-empty subsets of:
    - Day (with and without leading zero),
    - Month (with and without leading zero),
    - Year in three forms: full year (e.g. “1978”), the first two digits (e.g. “19”), and the last two digits (e.g. “78”).
  - If a birth date more than 120 years in the past is entered, it is deemed invalid and no additional combinations are generated.
  - These birthdate-based combinations are appended at the end of the output file (while ensuring duplicates are not added).
- **Security Enhancements:** Enhanced the is_secure_path() function to ensure that only relative filenames (with no directory separators) are accepted, preventing potential path traversal issues.
- **Code Refactoring:** Reduced redundancy by introducing a generic file processing function (process_file_generic()) that encapsulates the common logic for both password list and combo list generation. Specific processing callbacks handle the extraction of passwords and email:password pairs.

## v0.0.1
- Initial release.

___

# License
This project is licensed under the **[MIT license](https://github.com/ot2i7ba/GKPSanitizer/blob/main/LICENSE)**, providing users with flexibility and freedom to use and modify the software according to their needs.

# Contributing
Contributions are welcome! Please fork the repository and submit a pull request for review.

# Disclaimer
This project is provided without warranties. Users are advised to review the accompanying license for more information on the terms of use and limitations of liability.

# Conclusion
This script has been tailored to fit my specific professional needs, and while it may seem like a small tool, it has a significant impact on my workflow. Greetings to my dear colleagues who avoid scripts like the plague and think that consoles and Bash are some sort of dark magic – the [compiled](https://github.com/ot2i7ba/GKPSanitizer/releases) version will spare you the console kung-fu and hopefully be a helpful tool for you as well. 😉

[^1]: [Magnet Forensics GrayKey](https://www.magnetforensics.com/de/products/magnet-graykey/) is a forensic tool to extract data from mobile devices.

