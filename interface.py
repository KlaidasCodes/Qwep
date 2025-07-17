import os
import json
from my_functions import *
import secrets

# add all the required imports from functions later and remove them from the functions
# replace the wild card later

# at the end introduce a function that would wipe/overwrite RAM after pw manager closes to remove 
# plaintext pws from memory

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
        path_to_json = "/home/curious_ad/Documents/password_manager.json" #later create something a bit better
        invalid_dir = True
        while invalid_dir:
            location_def_or_prov = input(f"Press ENTER to use default dir, alternatively type in the absolute path to where your json file is stored{new_line}")
            if location_def_or_prov != "":
                path_to_json = location_def_or_prov
            dir_exists = os.path.isfile(path_to_json)
            if dir_exists:
                invalid_dir = False
            else:
                if location_def_or_prov == "":
                    print("Default location seems to be missing. Try inputting the path to your json manually.")
                else:
                    print("This directory seems to be missing. Make sure your json is named 'password_manager.json' and try again.")    
        correct_pot_question = input(f"Which pot of data would you like to access?{new_line}")
        correct_pot_name = f"data {correct_pot_question}"
        data_from_json: dict = read_json(path_to_json)
        correct_data_pot: dict = data_from_json[correct_pot_name]
        correct_pot_kdf_salt: bytes = extract_kdf_salt(correct_data_pot)
        correct_nonce, correct_tag = extract_nonce_and_tag(correct_data_pot)
        correct_ciphertext:bytes = extract_ciphertext(correct_data_pot)
        # now need to decrypt this correct ciphertext
        master_key = input(f"Please provide the master password:{new_line}")
        master_key = "snake lobot9my sakal8iukas griaust9nis" # just for testing
        encryption_key, temp_salt, temp_iter = master_to_key_kdf(master_key, correct_pot_kdf_salt)
        plaintext_bytes: bytes = decrypt_data(encryption_key, correct_tag, correct_nonce, correct_ciphertext)
        # convert bytes to ascii
        plaintext_ascii_all_pws: dict = json.loads(plaintext_bytes)
        print(f"Just testing: {plaintext_ascii_all_pws}")
        # works! 

        user_actions_hash = {
            "1": lambda: retrieve_one_pw(plaintext_ascii_all_pws),
            "2": lambda: add_password(plaintext_ascii_all_pws),
            "3": lambda: correct_password(plaintext_ascii_all_pws),
            "4": lambda: get_all_passwords(plaintext_ascii_all_pws)
        } 

        user_not_done = True
        while user_not_done:
            # add 5-removing a password
            action_to_do_with_passwords = input(f"What action would you like to perform?{new_line}1) Retrieve a password{new_line}2) Add a password{new_line}3) Correct a password{new_line}4) Read all passwords{new_line}")
            # definitely not an if/else here, create a hashmap of number----function!!!
            if action_to_do_with_passwords in user_actions_hash:
                user_actions_hash[action_to_do_with_passwords]()
            else:
                print("Invalid input. Make sure the number you inputted is an option in the menu!")
            do_another_action = input(f"Would you like to perform another action? (y/n){new_line}").lower()
            if do_another_action == "n":
                user_not_done = False
                print("Password manager will now apply all the changes made, encrypt the informaiton, wipe the RAM and shut off. Have a good day!")
                # the function of encrypting and uplaoding to json goes here

                
        # Now need to make the logic of updating the json (and the honeypots!!!) and it will fully function
        #TODO-1: encrypt plaintext_ascii_all_pws
        passwords_in_bytes: bytes = json.dumps(plaintext_ascii_all_pws).encode("utf-8")
        new_ciphertext, new_tag, new_nonce  = encrypt_data(encryption_key, passwords_in_bytes)
        #TODO-2: transform from bytes to hex)
        new_ciphertext_hex = bytes.hex(new_ciphertext)
        new_tag_hex = bytes.hex(new_tag)
        new_nonce_hex = bytes.hex(new_nonce)
        #TODO-3: check the length in bytes of the ciphertext
        ciphertext_bytes_len = len(new_ciphertext)
        print(f"This is the ciphertext in bytes: {new_ciphertext}")
        print(f"This is the length in bytes: {ciphertext_bytes_len}")
        #TODO-4: Update the file that we have taken from json by replacing all pots with that length honepots
        #TODO-5: upload the ciphertext to the same real pot (offer the option of changing the real pot)
        #TODO-6: update the other info (salts and stuff)
        #TODO-7: dump that to the json file
        #TODO-9: clean RAM?

        # at some point need to address the logic of having a decoy password pot, to make sure it does not 
        # get overwritten by honeypots. Or to always have it in the same place (but then the open source code
        # would make it too obvious for authorities to expect decoy passwords in a specific pot). SO perhaps
        # a user could pick at the beginning and then keep  it there? Or keep picking every time they make changes 
        # to passwords.

        # OR JUST INTRODUCE AN OPTION OF CHANGING WHERE THE REAL POT IS AND WHERE THE DECOY IS, JUST ADD THAT TO THE 
        # MENU OF FUNCTIONS!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!1










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
            default_or_provide = input(f"Would you like to provide a password or to use the default? (p/d){new_line}").lower()
            if default_or_provide == "p" or default_or_provide == "d":
                havent_picked_initial_pw = False
            else:
                print("Invalid input. Make sure to input p(provide) or d(default)")
        if default_or_provide == "d": 
            add_info_to_json(path_to_json, "username1", "password1", "www.site1.com", real_pot_name)
        elif default_or_provide == "p":
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
        not_passed_all_checks = True
        while not_passed_all_checks:
            master_password = input(f"Now provide a strong master password.\n This password will encrypt the entire password manager, so ensure it is strong.\n" \
            f"Recommended a dictionary-based password with some symbols included, you can generate that online. Make sure you can remember it.{new_line}")
            master_password = "snake lobot9my sakal8iukas griaust9nis" # just for testing
        # include some function that runs the master pw through a bunch of checks to make sure it's strong, returns True if passes all checks
#temporary, until the function is added
            testing_the_password = True # later change to an actual function that would test the pw
            if testing_the_password:
                not_passed_all_checks = False
            else:
                print("The password does not meet our requirements. Try again.") # make it more specific
        # generate the key through kdf and then encyrpt the pot
        derived_enc_key, salt_kdf, iterations = master_to_key_kdf(master_password=master_password) 
        print(f"The key: {derived_enc_key}\nThe salt_kdf: {salt_kdf}\nIterations: {iterations}")
        our_file = read_json(path_to_json)
        text_to_encrypt_dict: dict = our_file[real_pot_name]["data"]["ciphertext"]
        text_to_encrypt_str: str = json.dumps(text_to_encrypt_dict)
        text_to_encrypt_bytes: bytes = text_to_encrypt_str.encode("utf-8")
        cipher_text, tag, nonce = encrypt_data(derived_enc_key, text_to_encrypt_bytes)
        print(f"Encrypted text: {cipher_text}\nTag: {tag}\nNonce: {nonce}")

        cipher_text_hex = bytes.hex(cipher_text)
        tag_hex = bytes.hex(tag)
        nonce_hex = bytes.hex(nonce)
        upload_to_json(path_to_json, real_pot_name, cipher_text_hex, tag_hex, nonce_hex, bytes.hex(salt_kdf))



        ####### after user provides the initial default user info, dont upload it - ask for master key, encrypt and only then upload. No need to upload plaintext and then retrieve it again to encrypt it.
        # will need to adjust the function upload_to_json to take an input of the dictionary instead of opening json itself
        #  

        # Also add honeypot shifting. After each password updating round, offer the choice to the user to switch 
        # the location of the real pot. Save the encrypted pw on the system (to avoid it being lost from RAM in the process
        # in case connectivity goes down at some point). THen initialize all the honeypots and overwrite
        # one of them with real pw info again, just like at the beginning

        ###############
        # testing if it worked by attempting decryption
        # derived_enc_key, salt_kdf, iterations = master_to_key_kdf(master_password, salt_kdf)
        # plaintext_test: bytes = decrypt_data(derived_enc_key, tag, nonce, cipher_text)
        # plaintext_test_dict: dict = json.loads(plaintext_test)        
        # test_call = plaintext_test_dict["www.site1.com"]
        # print(f"Decrypted text: {test_call}")
        # # WORKSSSSSSSSSSSSS


        





    else: 
        print("Your input was not recognized.")

if __name__ == "__main__":
    main()

