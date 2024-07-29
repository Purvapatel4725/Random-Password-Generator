# Random Password Generator

This repository contains three scripts for generating random passwords with various options and features:

1. **`pass_gen.py`**: A Python script that provides a menu-based interface for generating passwords.
2. **`pass_gen_cli.py`**: A command-line interface (CLI) script for generating passwords with command-line arguments.
3. **`pass_gen_gui.py`**: A graphical user interface (GUI) script using Tkinter for generating passwords.

## Requirements

To run these scripts, you'll need to install the required Python packages. You can install them using `pip`:

```sh
pip install cryptography
pip install tk
```

## Usage

### 1. CLI Script (`pass_gen_cli.py`)

The CLI script allows you to generate passwords using command-line arguments. Below is a guide on how to use it.

**Usage:**

```sh
python pass_gen_cli.py [options]
```

**Options:**

- `-h`, `--help`: Show help information with details on all available options.
- `-l`, `--length`: Specify the length of the password (default: 8).
- `-u`, `--uppercase`: Include uppercase letters in the password.
- `-n`, `--numbers`: Include numbers in the password.
- `-s`, `--special`: Include special characters in the password.
- `--pattern`: Specify a pattern for the password. Choices are:
  - `start_with_letter`: Password starts with a letter.
  - `end_with_number`: Password ends with a number.
- `--key`: Provide an encryption key to encrypt the generated password (optional).

**Example:**

Generate an 12-character password with uppercase letters, numbers, and special characters:

```sh
python pass_gen_cli.py -l 12 -u -n -s
```

Encrypt the generated password with a specified key:

```sh
python pass_gen_cli.py -l 12 -u -n -s --key your_key_here
```

### 2. Menu-Based Script (`pass_gen.py`)

This script provides a menu-based interface to generate passwords. Run the script and follow the on-screen prompts to specify your requirements.

**Usage:**

```sh
python pass_gen.py
```

Follow the prompts to enter:

- Password length.
- Whether to include uppercase letters.
- Whether to include numbers.
- Whether to include special characters.
- A pattern for the password (if any).
- An encryption key (optional).

### 3. GUI Script (`pass_gen_gui.py`)

This script provides a graphical user interface for generating passwords using Tkinter.

**Usage:**

```sh
python pass_gen_gui.py
```

In the GUI:

- Enter the desired password length.
- Check the boxes to include uppercase letters, numbers, or special characters.
- Select a password pattern (if any).
- Enter an encryption key (optional).
- Click the "Generate Password" button to generate and display the password and its strength.

## Author

This repository is maintained by **Purva Patel**.
