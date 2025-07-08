import os
import json
from my_functions import *
import secrets

# replace the wild card later

def main():
    new_line = "\n\t-"
    new_or_old = input(f"Do you already have password manager account? (Y/N) {new_line}").lower()


    if new_or_old == "y":
        # doesn't need new acc
        pass
    elif new_or_old == "n":
        # later package up into just one function new_acc() or something

        path_to_json, amount_of_pots = create_pw_manager_json()
        incorrect_format = True
        while incorrect_format:
            real_pw_pot: int = int(input(f"Input a number 1-{amount_of_pots} to specify the real pot{new_line}"))
            if 0 < real_pw_pot <= amount_of_pots:
                real_pot_name: str = f"data {real_pw_pot}"
                incorrect_format = False
            else:
                print("Incorrect input, try again.")   
            # ask the user to provide a secure master-password and then encrypt this specific pot
        # encrypt the rest of the pots with randomly generated keys, no need to store them 
        establish_honeypots_and_encrypt(amount_of_pots, path_to_json)
        print("To set up your account, we will require one initial account information (username and password).")
        placeholder_or_add = input(f"Would you like to provide a password or to use the default placeholder? (provide/default){new_line}").lower()
        if placeholder_or_add == "placeholder": 
            add_info_to_json(path_to_json, "username1", "password1", "www.site1.com", real_pot_name)
            # throws an error, have to fix


    else: 
        print("Your input was not recognized.")

if __name__ == "__main__":
    main()

