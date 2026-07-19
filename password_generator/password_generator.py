
import string
import sys
import secrets
import re
import os
import math
import time

EQUIVALENCE = {
                "a":["4", "@", "A"], "b":["B", "8", "b"], "c":["(","[", "{", "C"], "d":[")", "]", "}", "D"],
                "e": ["e", "3", "E"], "f":["f", "F"], "g":["9", "g", "G"], "h":["h", "H"], "i":["1", "i", "I"],
                "j":["j", "J", "7"], "k":["k", "K"], "l":["l", "L", "|"],"m":["m", "M"], "n":["#", "n", "N"],
                "o":["o", "0", "O"], "p":["p", "P"], "q":["Q", "q"], "r":["R", "r", "2"], "s":["5", "$", "S"],
                "t":["T", "t", "7"], "u":["u", "U"], "v":["v", "V"], "w":["w", "W"], "x":["x", "X"], "y":["Y", "y"],
                "z":["z", "Z"], " ":[".", ";", "-", "_", "*"]
            }

ADDITIONAL_CHARS = "vsA#I80Xxo-&+=!%/\\"

def entry(possible_entry):
    """Ask the user for an input among allowed choices"""

    prompt = "/".join(possible_entry)

    choice = input("[" + prompt + "]--> ")

    while choice.strip().upper() not in possible_entry:
        print("Wrong entry, try again")
        choice = input("[" + prompt + "]--> ")
    
    return choice.strip().upper()


def exclude_ambigus_chars():
    """To exclude ambigus characters"""
    
    print("\nWould you want to exclude ambigus characters: | 1 i l 0 O o")
    choice = entry(["Y", "N"])

    if choice == "Y":

        letters = ""
        digits = ""
        punctuation = ""
        
        lett = string.ascii_letters
        dig = string.digits
        punc = string.punctuation

        to_exlude = ["|", "i", "l", "0", "O", "o"]

        for ch in lett:
            if ch not in to_exlude:
                letters += ch
        
        for ch in dig:
            if ch not in to_exlude:
                digits += ch
        
        for ch in punc:
            if ch not in to_exlude:
                punctuation += ch
        
        characters = [letters, digits, punctuation]
    
    else:
        characters = [string.ascii_letters, string.digits, string.punctuation]
    
    return characters


def estimate_entropy(password):
    """To calculate the entropy of the generated password"""

    charset = 0
    n = len(password)

    if re.search(r"(?=.*[a-z])", password):
        charset += 26
    
    if re.search(r"(?=.*[A-Z])", password):
        charset += 26

    if re.search(r"(?=.*\d)", password):
        charset += 10

    if re.search(r"(?=.*[^a-zA-Z0-9])", password):
        charset += len(string.ascii_letters)

    if charset == 0:
        return 0

    entropy = n * math.log2(charset) #Entropy = Size * Log2(Sharset)

    return entropy



def generate_secret_sentence():
    """To generate a secure password from a sentence"""

    password = ""

    while True:
        sentence = input("--> ")

        if sentence.strip().upper() == "\\EXIT":
            quit_program()
        
        if sentence.strip().upper() == "\\RETURN":
            return "RETURN"
        
        if sentence.strip().upper() == "\\CLEAR":
            clear_all()
            continue

        else:
            break

    if len(sentence) < 8:
        diff = 8 - len(sentence)

        extension = "".join(secrets.choice(ADDITIONAL_CHARS) for _ in range(int((diff / 2) + 1)))

        sentence = extension + sentence + extension

    for letter in sentence:
        if letter.lower() in EQUIVALENCE:
            password += secrets.choice(EQUIVALENCE[letter.lower()])
            
        else:
            password += letter
    
    return password


def generate_model_random(characters):
    """To generate a password from a model"""

    model = input("[Model]--> ")

    while True:
        if re.match(r"^[ldsLDS]+$", model):
            break
        
        elif model.strip() == "":
            break

        else:
            invalid = ", ".join(re.findall(r"[^ldsLDS]", model))
            print(f"This model contains invalid character(s): {invalid}. Please reenter the full correct model")

        model = input("--> ")
                

    def generate_the_password(model):

        if model.strip() == "":
            min_size = 8
            max_size = 15
            size = secrets.randbelow(max_size - min_size + 1) + min_size

            all_characters = characters[0] + characters[1] + characters[2]

            password = "".join(secrets.choice(all_characters) for _ in range(size))

        else:
            password = ""

            for character in model:
                if character.strip().upper() == "L":
                    password += secrets.choice(characters[0])
                
                elif character.strip().upper() == "D":
                    password += secrets.choice(characters[1])
                
                elif character.strip().upper() == "S":
                    password += secrets.choice(characters[2])
        
        return password
    
    print("\nHow many password do you want to generate[default:1]")

    while True:
        try:
            number = input("[Number]--> ")

            if number.strip() == "":
                number = 1
            
            else:
                number = int(number)

            if number <= 0:
                print(f"Can't generate {number} password")        
                continue

            else:
                break
        
        except ValueError:
            print("Entry contains wrong character")

    r_history = []
    i = 0
    while i < number:
        password = generate_the_password(model)

        r_history.append(password)
        print(f"\nPassword {i + 1}: {password}")
        print(f"Entropy: {estimate_entropy(password)}")

        i += 1

    return r_history


def generation_completly_random(characters):
    """To generate a password completly random"""

    while True:
        try:
            number = input("[Number]--> ")

            if number.strip() == "":
                number = 1
            
            else:
                number = int(number)

            if number <= 0:
                print(f"Can't generate {number} password")        
                continue

            else:
                break
        
        except ValueError:
            print("Entry contains wrong character")


    r_history = []
    i = 0
    while i < number:
        min_size = 8
        max_size = 15

        size = secrets.randbelow(max_size - min_size + 1) + min_size

        all_characters = characters[0] + characters[1] + characters[2]

        password = "".join(secrets.choice(all_characters) for _ in range(size))

        r_history.append(password)
        print(f"\nPassword {i + 1}: {password}")
        print(f"Entropy: {estimate_entropy(password)}")

        i += 1

    return r_history


def generate_passphrase():
    """To generate a passphrase from a wordlist"""

    if not os.path.exists("data/passphrase_wordlist.txt"):
        print("\nThe file passphrase_wordlist.txt is missing, please add it to the program directory")
        quit_program()

    try:
        with open("data/passphrase_wordlist.txt", "r", encoding="utf-8") as file:
            list_passphare = file.read().splitlines()
    
    except UnicodeDecodeError:
        with open("data/passphrase_wordlist.txt", "r", encoding="latin-1") as file:
            list_passphare = file.read().splitlines()

    while True:
        try:
            word_number = int(input("[NUMBER]--> "))

            if word_number > 0:
                break
            else:
                print("Can't generate passphrase with this number of word")
        
        except ValueError:
            print("Wrong entry, try again")

    s_passphrase = set()
    for _ in range(word_number):
        s_passphrase.add(secrets.choice(list_passphare))
    
    while len(s_passphrase) < word_number:
        diff = word_number - len(s_passphrase)
        for _ in range(diff):
            s_passphrase.add(secrets.choice(list_passphare))
        
        if len(s_passphrase) == word_number:
            break
    
    passphrase = "-".join(word.capitalize() for word in s_passphrase)

    return passphrase


def random_password_menu(history):
    """To generate a random password"""

    print("\nDo you want to specify a model or let the generation completly randomness")
    print("1) Specify a model")
    print("2) Let the generation completly randomness")
    print("3) Exit")

    is_random = entry(["1", "2", "3"])

    characters = exclude_ambigus_chars()

    if is_random == "2":
        print("\nHow many password do you want to generate[default:1]")

        while True:
            r_history = generation_completly_random(characters)

            for psswd in r_history:
                history.append(f"Random password  :  {psswd}")
                    
            while True:
                print("\nWould your want to continue to generate or stop now[Y:continue/N:stop/C:clear/R:Return to main menu]")
                again = entry(["Y", "N", "C", "R"])

                if again == "Y":
                    break

                elif again == "R":
                    return
                
                elif again == "C":
                    clear_all()

                else:
                    quit_program()
            
    elif is_random == "3":
        quit_program()
            
    elif is_random == "1":
        print("\nPlease enter here a model or let it empty for a random output")
        print("L:Letters")
        print("D:Digits")
        print("S:Symbols")
        print("Example:LLLSDDSL  ==> mXr$64#P")

        while True:
            r_history = generate_model_random(characters)

            for psswd in r_history:
                history.append(f"Random password  :  {psswd}")
            
            while True:
                print("\nWould your want to continue to generate or stop now[Y:continue/N:stop/C:clear/R:Return to main menu]")
                again = entry(["Y", "N", "C", "R"])

                if again == "Y":
                    break

                elif again == "R":
                    return

                elif again == "C":
                    clear_all()
                        
                else:
                    quit_program()


def secret_sentence_menu(history):
    """To generate a password from a secret sentence"""

    print("\nEnter the sentence for the password")
    print("Type \\exit : to quit , \\return : to return to the main menu , \\clear : to clean the terminal")

    while True:
        password = generate_secret_sentence()

        if password == "RETURN":
            return

        history.append(f"Secret Sentence  :  {password}")
        print(f"\nPassword: {password}")
        print(f"Entropy: {estimate_entropy(password)}")

        print()


def passphrase_menu(history):
    """To generate a passphrase from a wordlist"""

    print("\nEnter the number of words that will be present in passphrase")

    while True:
        passphrase = generate_passphrase()
        history.append(f"Passphrase       :  {passphrase}")
        print(f"\nPassword: {passphrase}")
        print(f"Entropy: {estimate_entropy(passphrase)}")

        while True:
            print("\nWould your want to continue to generate or stop now[Y:continue/N:stop/C:clear/R:Return to main menu]")
            again = entry(["Y", "N", "C", "R"])

            if again == "Y":
                break

            elif again == "R":
                return
            
            elif again == "C":
                clear_all()
                        
            else:
                quit_program()


def show_history(history):
    """To show the history of the current session"""

    if not history:
        print("\nThe history is yet empty for this session")

    else:
        print("\nThe history saved from this session:")
        for psswd in history:
            print(f"- {psswd}")

        print("\nDo you want to save the history in a text file")
        print("Y:Yes, N:No, E:Clear the history")

        choice = entry(["Y", "N", "E"])

        if choice == "Y":
            save_file(history)
        
        elif choice == "E":
            history.clear()
            print("\nHistory cleared successfully")
        
        return


def save_file(history):

    file_name = time.strftime("Backup_%d-%m-%Y_%H-%M-%S.txt")

    path = "password_generator/Backup/" + file_name

    print()
    if not os.path.exists("password_generator/Backup"):
        print("The directory 'Backup' is missing in the current folder, it will be created")
        os.mkdir("password_generator/Backup")

    with open(path, "w") as file:
        for line in history:
            file.write(f"- {line}\n")
    
    print(f"File saved correctly on {path}")


def quit_program():
    """to quit properly the program"""
    print("Thanks for using the tool")
    return "RETURN"


def clear_all():
    """to clean the terminal"""
    os.system("cls" if os.name == "nt" else "clear")


def main(history):
    """Main function of the program"""

    while True:
        print("\nWhich type of password would you want")
        print("1) Random password")
        print("2) A secret sentence")
        print("3) Passphrase")
        print("4) History")
        print("5) Clear the history")
        print("6) Clear the terminal")
        print("7) Exit")

        choice = entry(["1", "2", "3", "4", "5", "6", "7"])
            
        if choice == "7":
            break
        
        elif choice == "6":
            clear_all()

        elif choice == "5":
            history.clear()
            print("History cleared successfully")

        elif choice == "1":
            random_password_menu(history)

        elif choice == "2":
            secret_sentence_menu(history)
        
        elif choice == "4":
            show_history(history)
        
        elif choice == "3":
            passphrase_menu(history)
    
    quit_program()


def run_PG_program():

    history = []

    print("WELCOME! This program generate a secure password of your choice")

    try:
        main(history)
    
    except KeyboardInterrupt:
        quit_program()
    
    except Exception as e:
        print("\nAn error occured: ", e)
        quit_program()

