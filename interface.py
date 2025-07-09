import os
import json
from my_functions import *
import secrets

# replace the wild card later

def main():
    new_line = "\n\t-"
    unrecognized_input = True
    while unrecognized_input:
        new_or_old = input(f"Do you already have password manager account? (y/n) {new_line}").lower()
        if new_or_old == "y" or new_or_old == "n":
            unrecognized_input = False
        else:
            print("Unrecognized input. Make sure your answer is either y or n.")

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
        initialize_honeypots(amount_of_pots, path_to_json)
        print("To set up your account, we will require one initial account information (username and password).")
        havent_picked_initial_pw = True
        while havent_picked_initial_pw:
            default_or_provide = input(f"Would you like to provide a password or to use the default placeholder? (provide/default){new_line}").lower()
            if default_or_provide == "default": 
                add_info_to_json(path_to_json, "username1", "password1", "www.site1.com", real_pot_name)
                havent_picked_initial_pw = False
            elif default_or_provide == "provide":
                incorrect_info = True
                while incorrect_info:
                    initial_site_input = input(f"Provide the site name please:{new_line}").lower()
                    initial_username_input = input(f"Provide the username for the site:{new_line}").lower()
                    initial_pw_input = input(f"Provide the password for the site:{new_line}").lower()
                    print(f"Inputted information:{new_line}Site: {initial_site_input}{new_line}Username:" 
                        f"{initial_username_input}{new_line}Password: {initial_pw_input}")
                    correct_or_no = input("Is the provided information correct? (y/n)").lower()
                    # could later improve this by letting the user pick what exactly to correct. 
                    # gets annoying when you have to rewrite it constantly 
                    if correct_or_no == "y":
                        add_info_to_json(path_to_json, initial_username_input, initial_pw_input, initial_site_input, real_pot_name)
                        incorrect_info = False
                havent_picked_initial_pw = False
                pass


    else: 
        print("Your input was not recognized.")

if __name__ == "__main__":
    main()

