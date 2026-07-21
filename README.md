# Toolkit

This `Toolkit` is a collection of project created by the author of this project. It was designed for educational purposes and cybersecurity practice.

---

## Features

- Multiple tools in a single application
- Possibility to return in the main menu after using a tools
- Cross-platform

If you want to see the features of each tool, please check his `README.md` in his Github repository.

---

## How It works

The program asks you which tool you want to use from all tools available.

After using a tool, if you quit it, you will be redirected to the main menu where you can choose a new tools or quit the program.

---

## Installation

Clone the repository

```bash
git clone https://github.com/Maheva-Christan/toolkit.git
```

Move into the repository

```bash
cd toolkit
```

Run the program
```bash
python toolkit.py
```

No additional packages or installation are required

---

## Usage

Launch the program

```bash
python toolkit.py
```

Main menu example:

```text
1) Password analyzer
2) Password generator
99) Exit
```

Follow the on-screen instructions for each tools.

---

## Project Structure

```text
toolkit/
|
|--- LICENSE
|--- README.md
|--- toolkit.py
|
|--- password_analyzer/
|    |--- __init__.py
|    |--- password_analyzer.py
|    |--- data/
|         |--- common_words.txt
|         |--- darkc0de.txt
|
|--- password_generator/
     |--- __init__.py
     |--- password_generator.py
     |--- Backup
     |--- data
          |--- passphrase_wordlist.txt
```

---

## Limitations

- No graphical interface
- All tools have his own limitations

---

## Future Improvements

- Add more tools to the project

---

## License

This project is under MIT License.

Feel free to use, modify, and distribute this project in accordance with the license terms.

See the `LICENSE` file for more information.
