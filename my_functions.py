def create_pw_manager_json():
    """Creates a new json file with the pw manager with a specific number of honeypots.
    Returns path to json | amount of pots"""
    import os
    import json
    new_line = "\n\t-"

    new_place = "/home/curious_ad/Documents"
    # UNCOMMENT THIS FOR REAL FUNCTIONALITY
    # new_place = input(f"Input the absolute directory of where you would like the password data located (or relative, but be mindful of where the script is being run){new_line}")
    dir_exists = os.path.isdir(new_place)
    if not dir_exists:
        print("Could not find this directory. Make sure it exists and try again!")
    else:
        honeypot_amount: int = int(input(f"How many honeypots would you like to initialize? (Recommended at least 2) {new_line}"))
        initial_json = {}
        for i in range(honeypot_amount + 1):
            initial_json[f"data {i + 1}"] = {
                "data": {
                    "nonce": "",
                    "ciphertext": "",
                    "tag": ""
                },
                "kdf_salt": "",
                "iterations": ""
            }
        with open(f"{new_place}/password_manager.json", "w") as f:            
            # initializes the json file and its format 
            json.dump(initial_json, f, indent=4)
        print(f"Congratulations! Your passwords will now be stored at the directory {new_place}/password_manager.json")
    return f"{new_place}/password_manager.json", honeypot_amount + 1
        


def initialize_honeypots(amount_of_pots: int, path_to_json: str):
    """Inputs: amount_of_pots: 
    Amount of data pots in the json file
    path_to_json: absolute path to the json file 
    
    Returns: void
    
    Explanation:Fills all pots in json with fake honeypot data 
    """
    import json
    from secrets import token_bytes
    with open(path_to_json, "r") as f:
        the_file = json.load(f)
    for i in range(amount_of_pots):
        temp_nonce_hex = token_bytes(12).hex()
        temp_tag_hex = token_bytes(16).hex()
        temp_data_hex = token_bytes(100).hex()
        temp_kdf_salt_hex = token_bytes(16).hex()
        the_file[f"data {i + 1}"]["data"]["nonce"] = temp_nonce_hex
        the_file[f"data {i + 1}"]["data"]["ciphertext"] = temp_data_hex
        the_file[f"data {i + 1}"]["data"]["tag"] = temp_tag_hex
        the_file[f"data {i + 1}"]["iterations"] = 500000
        the_file[f"data {i + 1}"]["kdf_salt"] = temp_kdf_salt_hex
    with open(path_to_json, "w") as file:
        json.dump(the_file, file, indent=4)
    print("Placeholder information filled in successfully!\n")
    print(f"Your password manager will host {amount_of_pots} data pots. Only one of them is going to host your actual passwords - the rest of them will be honeypots" 
        f" with randomly generated information. \nOnce you pick the 'real' data pot, remember which one it is.")


def initialize_ciphertext(path_to_json, data_pot):
    import json
    with open(path_to_json, "r") as f:
        our_file = json.load(f)
    our_file[data_pot]["data"]["ciphertext"] = {}
    with open(path_to_json, "w") as file:
        json.dump(our_file, file, indent=4)

def add_info_to_json(path_to_json, username, password, site, data_pot):
    import json
    initialize_ciphertext(path_to_json, data_pot)
    with open(path_to_json, "r") as f:
        the_file = json.load(f)
    the_file[data_pot]["data"]["ciphertext"][site] = {
        "username": username,
        "password": password
    }
                                                                                          
    with open(path_to_json, "w") as file:
        json.dump(the_file, file, indent=4)
    print("Information added successfully. Don't forget to encrypt this though!")



