
import re
import math
import os
import sys


def load_wordlist(path):
    """Put the content of a file in a set"""

    try: #open normally the file
        with open(path, "r", encoding="utf-8") as file:
            words = {line.strip() for line in file if line.strip()}
    
    except UnicodeDecodeError: #if utf-8 can't load the file
        with open(path, "r", encoding="latin-1") as file:
            words = {line.strip().casefold() for line in file if line.strip()}
    
    return words

def wordlist_lower_case(words):
    """Put the content of a set into a lower"""

    lower_words = set()
    for word in words:
        lower_words.add(word.lower())
    
    return lower_words


def load_common_words():
    """Load content of common words in a set"""

    if os.path.exists("password_analyzer/data/common_words.txt"):
        with open("password_analyzer/data/common_words.txt", "r") as c_file:
            common_words = set(c_file.read().splitlines())
    
    else:
        print("Some file is missing or have been removed/displaced, quitting...")
        print("Thanks for using this program")
        sys.exit(0)
    
    return common_words


def remove_spaces(password, display):
    """To remove space between anr around the password entered by the users"""

    if re.search(r"\s", password):
        new_password = "".join(password.split())

        if display:
            print(f"\nSpace(s) have been removed from password: {password} --> {new_password}")
    
    else:
        new_password = password
    
    return new_password


def check_wordlist(password, words, sensitive):
    """To verify if the password is present in the wordlist"""

    word_presence = 0

    if sensitive: #case of a password with case sensitive
        if password in words:
            word_presence = 1

    
    else: #case of password without case sensitive
        if password.casefold() in words:
            word_presence = 1

    
    return word_presence


def estimate_entropy(password):
    """To calculate the entropy of the password"""

    charset = 0
    n = len(password)

    if re.search(r"(?=.*[a-z])", password):
        charset += 26
    
    if re.search(r"(?=.*[A-Z])", password):
        charset += 26
    
    if re.search(r"(?=.*\d)", password):
        charset += 10
    
    if re.search(r"(?=.*[^a-zA-Z0-9])", password):
        charset += 32
    
    if charset == 0:
        return [0, 0]
    
    entropy = n * math.log2(charset) #Entropy = Size * Log2(Sharset)

    return [entropy, charset]


def detect_repetition(password):
    """To detect the password with repeated string"""

    repetition = 0

    if re.search(r"(.{3,})\1", password):
        repetition = 1
    
    return repetition

def detect_character_repetition(password):
    """To detect the password with repeated characters"""

    character_repetition = 0

    if re.search(r"(.)\1{3,}", password):
        character_repetition = 1
    
    return character_repetition

def detect_palindrome(password):
    """To detect if a password is a palindrome"""

    palindrome = 0
    
    reversed_password = password[::-1]

    if reversed_password == password:
        palindrome = 1
    
    return palindrome

def final_evaluation(words, common_words, password, sensitive):
    """To penalize password that contains weakness and return the final score"""

    penalty = 1
    entropy = estimate_entropy(password)[0]

    if check_wordlist(password, words, sensitive): #if the password is present in the wordlist
        penalty *= 0.01

    for word in common_words:
        if word.casefold() in password.casefold(): #if password contains a common words
            penalty *= 0.2
            break
    
    if detect_repetition(password): #if a password contains a repeated string
        penalty *= 0.4
    
    if detect_character_repetition(password): #if a password contains a repeated character
        penalty *= 0.4

    if detect_palindrome(password) and len(password) < 10: #if a password is a weak palindrome
        penalty *= 0.4
    
    elif detect_palindrome(password) and password.isalpha():
        penalty *= 0.4

    elif detect_palindrome(password) and len(password) >= 10 and re.search(r"(?=.*[a-z])", password) and re.search(r"(?=.*[A-Z])", password) and re.search(r"(?=.*[0-9])", password) and re.search(r"(?=.*[^a-zA-Z0-9])", password): #if a password is a strong palindrome
        penalty *= 0.8
    
    if len(password) < 8:
        penalty *= 0.4
    
    if re.match(r"^[a-zA-Z]+$", password) and len(password) < 12:
        penalty *= 0.3

    if re.match(r"^[a-zA-Z]+$", password) and len(password) >= 12:
        penalty *= 0.8
    
    if re.match(r"^[0-9]+$", password):
        penalty *= 0.3
    
    if len(password) > 6 and (len(re.findall(r"^[0-9]$", password)) <= 2 or len(re.findall(r"^[A-Z]$", password)) <= 2 or len(re.findall(r"^[a-z]$", password)) <= 2):
        penalty *= 0.5
    
    security_strength = entropy * penalty

    return [penalty, security_strength]


def display_progress_bar(analysis):

    security_strength = analysis["security_strength"]


    filled = max(0, min(int((security_strength)/5), 20))

    progress_bar = "[" + "="*filled + " "*(20-filled) + "]"

    if security_strength <= 30:
        print(f"\033[31m{progress_bar} {security_strength:.2f}%\033[0m")
    
    elif security_strength <= 65:
        print(f"\033[33m{progress_bar} {security_strength:.2f}%\033[0m")
    
    elif security_strength <= 97:
        print(f"\033[32m{progress_bar} {security_strength:.2f}%\033[0m")
    
    elif security_strength > 97:
        print(f"\033[32m[=================== ] 97.00% \033[0m")


def evaluate_strength(analysis):
    """To evaluate the strength of the password and give the verdict"""

    security_strength = analysis["security_strength"]

    entropy = analysis["entropy"]
    print(f"\nEntropy: {entropy:.2f} bits")
    
    if security_strength <= 20:
        print("Verdict: VERY WEAK")

    elif security_strength <= 40:
        print("Verdict: WEAK")
    
    elif security_strength <= 60:
        print("Verdict: MEDIUM")
    
    elif security_strength <= 80:
        print("Verdict: STRONG")
    
    else:
        print("Verdict: EXCELLENT")
    
    display_progress_bar(analysis)


def reasoning(analysis):
    """To give the reasons of the verdict"""

    password = analysis["password"]

    indication = 0

    print("\nPENALISATION:")

    if analysis["in_wordlist"]: #if the password is present in the wordlist
        print("\t- Your password already exists in the wordlist")
        indication = 1
    
    if re.match(r"^[a-z]+$", analysis["password"]): #if a password contains only lower characters
        print("\t- Your password contains only lower characters")
        indication = 1
        
    elif re.match(r"^[A-Z]+$", analysis["password"]): #if a password contains only upper characters
        print("\t- Your password contains only upper characters")
        indication = 1
    
    elif re.match(r"^[0-9]+$", analysis["password"]): #If a password contains only digits
        print("\t- Your password contains only digits")
        indication = 1

    elif re.match(r"^[a-zA-Z]+$", analysis["password"]): #if a password contains only characters
        print("\t- Your password contains only characters")
        indication = 1

    if analysis["length"] < 8: #if a password is too short
        print("\t- Your password is too short")
        indication = 1

    if re.search(r"(.{3,})\1", analysis["password"]) or re.search(r"(.)\1{3,}", analysis["password"]): #if the password contains repetition
        print("\t- Your password contains repetition")
        indication = 1

    if analysis["contains_common_words"][0]: #if the password contains a common word
        common_words = ""
        for word in analysis["contains_common_words"][1]:
            if word != analysis["contains_common_words"][1][len(analysis["contains_common_words"][1]) - 1]:
                common_words += word + ", "
            else:
                common_words += word
                
        print(f"\t- Your password contains common words: {common_words}")
        indication = 1
    
    if detect_palindrome(password) and (len(password) < 10 or password.isalpha()):
        print("\t- Your password is a weak palindrome")
        indication = 1

    if len(password) > 6 and (len(re.findall(r"^[0-9]$", password)) <= 2 or len(re.findall(r"^[A-Z]$", password)) <= 2 or len(re.findall(r"^[a-z]$", password)) <= 2):
        indication = 1
    
    if (len(re.findall(r"[a-z]", analysis["password"])) >= 3 and len(re.findall(r"[A-Z]", analysis["password"])) >= 3 and len(re.findall(r"[0-9]", analysis["password"])) >= 2 and len(re.findall(r"[^a-zA-Z0-9]", analysis["password"])) >= 2 and analysis["length"] >= 10 and not analysis["in_wordlist"]) or not bool(indication): #Case of a strong password
        print("\nREMARK:")
        print("\t- Your pasword is strong")


def crack_time_detailed(time_seconds):
    """To detailed the time given in seconds"""

    minute = 60
    hour = 3_600
    day = 86_400
    month = 2_592_000
    year = 31_536_000

    f_year = time_seconds // year
    f_seconds = time_seconds % year

    f_month = f_seconds // month
    f_seconds %= month

    f_day = f_seconds // day
    f_seconds %= day

    f_hour = f_seconds // hour
    f_seconds %= hour

    f_minute = f_seconds // minute
    f_seconds %= minute
    
    return f"{int(f_year)} Year {int(f_month)} month {int(f_day)} Day {int(f_hour)} h {int(f_minute)} min {f_seconds:.3f} s"


def estimate_bruteforce(analysis):
    """To estimate the time to crack the password"""

    penalised_combination = analysis["penalised_combination"]
    real_combination = analysis["real_combination"]

    penalised_average_attempts = penalised_combination / 2
    real_average_attempts = real_combination / 2

    # These values can be different as the algorithm used to crack the password
    online_APS = 10
    weak_server_APS = 500
    modern_GPU_APS = 40_000_000_000
    cluster_GPU_APS = 40_000_000_000_000
    standard_offline_APS = 50_000

    print("\nEstimated bruteforce time:")
    if analysis["in_wordlist"]:

        crack_time = (len(analysis["words"]) / 2) / standard_offline_APS

        print(f"\t- Using this wordlist, your password can be cracked with:")
        print(f"\t   {crack_time_detailed(crack_time)}")

    
    print(f"\n\t- Website bruteforce attack:")
    print(f"\t   + With penalisation: {crack_time_detailed(penalised_average_attempts / online_APS)}")
    print(f"\t   + Without penalisation: {crack_time_detailed(real_average_attempts / online_APS)}")

    print(f"\n\t- Weak server attack:")
    print(f"\t   + With penalisation: {crack_time_detailed(penalised_average_attempts / weak_server_APS)}")
    print(f"\t   + Without penaliisation: {crack_time_detailed(real_average_attempts / weak_server_APS)}")

    print(f"\n\t- Modern GPU attack (offline):")
    print(f"\t   + With penalisation: {crack_time_detailed(penalised_average_attempts / modern_GPU_APS)}")
    print(f"\t   + Without penalisation: {crack_time_detailed(real_average_attempts / modern_GPU_APS)}")
    
    print(f"\n\t- Cluster GPU attack (offline):")
    print(f"\t   + With penalisation: {crack_time_detailed(penalised_average_attempts / cluster_GPU_APS)}")
    print(f"\t   + Without penalisation: {crack_time_detailed(real_average_attempts / cluster_GPU_APS)}")


def analyze_password(password, words, common_words, sensitive):

    entropy, charset = estimate_entropy(password)
    penalty, security_strength = final_evaluation(words, common_words, password, sensitive)
    in_wordlist = bool(check_wordlist(password, words, sensitive))
    contains_common_words = [False, []]

    for word in common_words:
        if word.casefold() in password.casefold():
            contains_common_words[0] = True
            contains_common_words[1].append(word.casefold())
    
    if contains_common_words[0]:
        l_string = contains_common_words[1][0]
        u_common_words = []

        for item in contains_common_words[1]:
            if len(l_string) <= len(item):
                l_string = item
        
        u_common_words.append(l_string)

        for item in contains_common_words[1]:
            if item in l_string:
                pass
            else:
                u_common_words.append(item)
        
        contains_common_words[1].clear()
        contains_common_words[1] = u_common_words


    repetition = bool(detect_repetition(password))
    character_repetition = bool(detect_character_repetition(password))
    palindrome = bool(detect_palindrome(password))

    real_combination = 2 ** entropy
    penalised_combination = real_combination * penalty

    analysis = {
        "password":password, "length":len(password), "entropy":entropy,
        "charset":charset, "security_strength":security_strength, "in_wordlist":in_wordlist,
        "contains_common_words":contains_common_words, "repetition":repetition, "palindrome":palindrome,
        "character_repetition":character_repetition, "penalised_combination":penalised_combination,
        "real_combination":real_combination, "words":words, "common_words":common_words}
    
    return analysis
            
    

def main(words):

    common_words = load_common_words()

    print("\nDo you want the verification to be case-sensitive? [Default:yes]")
    print("1) Yes")
    print("2) No")
    print("3) Exit")

    possible_entry = ["1", "2", "3"]

    choice = (input("[1|2|3] --> ")).strip()

    while choice not in possible_entry:
        print("Wrong Entry")
        choice = input("[1|2|3] --> ")

    sensitive = 1

    if choice == "2":
        words = wordlist_lower_case(words)
        sensitive = 0
    
    elif choice == "1":
        pass
    
    else:
        print("\nThanks for using this program")
        sys.exit(0)

    prompt = "[\033[37m----\033[34m] --> "

    os.system("cls" if os.name == "nt" else "clear")

    print("Enter Your password\n")

    try:
        while True:

            password = input("\033[34m" + prompt + "\033[0m")

            if not password or password == " "*len(password):
                print("\033[33mpassword cannot be empty\033[0m")
                continue

            if remove_spaces(password, 0).upper() == "\\EXIT":
                print("\nThanks for using this pogram")
                return
            
            elif remove_spaces(password, 0).upper() == "\\CLEAR":
                os.system("cls" if os.name == "nt" else "clear")
                continue

            password = remove_spaces(password, 1)

            if check_wordlist(password, words, sensitive):
                print("\n\033[31m✘ Warning: Your password is present in the wordlist\033[0m")
                prompt = "[\033[31mFOUND\033[34m] --> "
            
            else:
                print("\n\033[32m✔ Message: Your password is missing in the wordlist\033[0m")
                prompt = "[\033[32mSAFE\033[34m] --> "

            analysis = analyze_password(password, words, common_words, sensitive)

            evaluate_strength(analysis)

            reasoning(analysis)

            estimate_bruteforce(analysis)  

            print()          


    except KeyboardInterrupt:
        print("\nThanks for using this program")
        sys.exit(0)


def load_user_file():
    """To load the user's file"""

    path = ""

    print("Enter the path of the wordlist:")

    try:
        path = input("[PATH] --> ")

        if path.upper() == "\\EXIT":
            print("Thanks for using this parogram")
            sys.exit(0)

        while not os.path.exists(path):
            print("Specified file doesn't exist, please enter a valid path")
            path = input("[PATH] --> ")

            if path.upper() == "\\EXIT":
                print("Thanks for using this parogram")
                sys.exit(0)

        words = load_wordlist(path)

        while words == set():
            print("Specified file is empty, please choose a file with some content")
            path = input("[PATH] --> ")

            if path.upper() == "\\EXIT":
                print("Thanks for using this parogram")
                sys.exit(0)

            words = load_wordlist(path)
    
    except IsADirectoryError:
        print("This is not a file but a Directory")
    
    except KeyboardInterrupt:
        print("Thanks for using this program")
        sys.exit(0)
    
    return words


def run_PA_program():

    default_path = "password_analyzer/data/darkc0de.txt"

    print("This program will check your password strength and will estimate the time to crack it.\n")
    
    print("Would you want to use your own wordlist or the wordlist built-in with this project")
    print("1) Use wordlist built-in with this project")
    print("2) Use your own wordlist")
    print("3) exit")

    possible_entry = ["1", "2", "3"]

    choose_type_file = input("[1|2|3] --> ").strip()

    while choose_type_file not in possible_entry:
        print("Wrong entry")
        choose_type_file = input("[1|2|3] --> ").strip()
    
    if choose_type_file == "2":
        words = load_user_file()
    
    elif choose_type_file == "1":
        if os.path.exists(default_path):
            words = load_wordlist(default_path)
        
        else:
            print("Default file has been removed or displaced, please enter a path of your own file")
            words = load_user_file()

    else:
        print("Thanks for usig the tool")
        return "RETURN"

    main(words)


"""Modification à faire:
percentage = 97 * (1 - math.exp(-entropy / 40)) 

si faible etropie, le pourcentage monte vite
si l'entropie est grande, le pourcentage monte lentement
si l'entropie est énorme, le pourcentage se rapproche de 97%
le pourcentage n'atteint jamais 97%
"""
