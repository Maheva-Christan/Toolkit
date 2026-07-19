
import sys
import os

from password_generator import run_PG_program
from password_analyzer import run_PA_program

    
def display_toolkit():
    
    os.system("cls" if os.name == "nt" else "clear")

    print("""
          
   #########################################
   ##    _____           _ _    _ _       ##
   ##   |_   _|__   ___ | | | _(_) |_     ##
   ##     | |/ _ \ / _ \| | |/ / | __|    ##
   ##     | | (_) | (_) | |   <| | |_     ##
   ##     |_|\___/ \___/|_|_|\_\_|\__|    ##
   ##                                     ##
   #########################################
        """)

def ask_program():
    print("\nChoose the program that you want to use")
    print("1) Password analyzer")
    print("2) Password generator")
    print("99) Exit")

    possible_entry = ["1", "2", "99"]

    choice = input("--> ")

    while choice.strip() not in  possible_entry:
        print("Program not found, try again")
        choice = input("--> ")
    
    return choice

def main():
    display_toolkit()

    choice = ask_program()

    if choice == "1":
        os.system("cls" if os.name == "nt" else "clear")
        run_PA_program()
        
    elif choice == "2":
        os.system("cls" if os.name == "nt" else "clear")
        run_PG_program()
        
    elif choice == "99":
        print("\nThanKs for using this program")
        sys.exit()
    

if __name__ == "__main__":

    while True:
        try:

            main()

        except KeyboardInterrupt:
            print("\nThanks for using this program")
            sys.exit()
        
        except Exception as e:
            print(f"\nAn error occurred: {e}")
            sys.exit()