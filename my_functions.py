new_line = "\n\t-"
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

def master_to_key_kdf(master_password, salt_kdf=None, der_key_len=32, hash_algo="sha256", iterations=500000):
    """Converts a master password into a key, returns key(32b), salt(16b), iterations(int).
    Only provide master password, the rest of the arguments are defaults."""
    import secrets
    import hashlib
    if not salt_kdf:
        salt_kdf = secrets.token_bytes(16)
    master_pw_bytes = master_password.encode("utf-8")
    derived_key_bytes = hashlib.pbkdf2_hmac(
        hash_name=hash_algo,
        password=master_pw_bytes,
        iterations=iterations,
        dklen=der_key_len,
        salt=salt_kdf
    )
    return derived_key_bytes, salt_kdf, iterations


def encrypt_data(enc_key: bytes, plaintext: bytes):
    """Takes an input of key and plaintext and encrypts it using AES-GCM
    Returns encrypted text, authentification tag, nonce."""
    import secrets
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    nonce = secrets.token_bytes(12)
    cipher = Cipher(algorithm=algorithms.AES(enc_key), mode=modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag
    return cipher_text, tag, nonce

def decrypt_data(enc_key:bytes, tag:bytes, nonce:bytes, cipher_text:bytes) -> bytes:
    """Takes encrypted text and decrypts it"""
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.exceptions import InvalidTag
    cipher = Cipher(algorithm=algorithms.AES(enc_key), mode=modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    try:
        plaintext = decryptor.update(cipher_text) + decryptor.finalize()
        return plaintext
    except InvalidTag:
        print("Decryption failed. Something smells fishy here.")
        


def read_json(path_to_json) -> dict:
    """Reads json file and returns the contents as dict"""
    import json
    with open(path_to_json, "r") as f:
        return json.load(f)
    
def upload_to_json(path_to_json: str, real_pot: str, cipher_text: str, tag: str, nonce: str, kdf_salt: str, iterations:int = 500000):
    """Uploads the content to specified json. cipher_text, tag, nonce, kdf_salt IN HEX!"""
    import json
    # adjust so that instead of retrieving the json, it just takes the input of a dictionary and uses that.
    our_file = read_json(path_to_json)
    shortcut = our_file[real_pot]
    shortcut["data"]["nonce"] = nonce
    shortcut["data"]["tag"] = tag
    shortcut["data"]["ciphertext"] = cipher_text
    shortcut["kdf_salt"] = kdf_salt
    shortcut["iterations"] = iterations
    with open(path_to_json, "w") as f:
        json.dump(our_file, f, indent=4)
    print("Uploaded the encrypted text to json successfully!")


def extract_kdf_salt(correct_pot_data: dict) -> bytes:
    """extracts hex kdf salt and returns kdf salt bytes"""
    return bytes.fromhex(correct_pot_data["kdf_salt"])


def extract_nonce_and_tag(correct_pot_data: dict) -> tuple[bytes, bytes]:
    """extracts hex nonce and tag and converts to bytes"""
    nonce = bytes.fromhex(correct_pot_data["data"]["nonce"])
    tag = bytes.fromhex(correct_pot_data["data"]["tag"])
    return nonce, tag

def extract_ciphertext(correct_pot_data: dict) -> bytes:
    """extracts hex ciphertext and returns bytes ciphertext"""
    return bytes.fromhex(correct_pot_data["data"]["ciphertext"])


def authenticate_user(path_to_json, kdf_salt, correct_pot_name, tag, nonce, master_pw=None):
    import json
    new_line = "\n\t-"
    if not master_pw:
        master_pw = input(f"Please provide your master password:{new_line}")
    enc_key, kdf_salt, iterations = master_to_key_kdf(master_pw, kdf_salt)
    our_file: dict = read_json(path_to_json)
    correct_pot: dict = our_file[correct_pot_name]
    correct_pot_kdf_salt: str = correct_pot["kdf_salt"]
    correct_pot_iterations: int = correct_pot["iterations"]
    correct_pots_data: str = correct_pot["data"]
    correct_pots_data_nonce = correct_pot["nonce"]
    correct_pots_data_tag = correct_pot["tag"]
    correct_pots_data_ciphertext = correct_pot["ciphertext"]

    plaintext: bytes = decrypt_data(enc_key, correct_pots_data_tag, correct_pots_data_nonce, correct_pots_data_ciphertext)
    plaintext_dict = json.loads(plaintext)  # converts bytes to ascii
    return plaintext_dict



def retrieve_one_pw(all_passwords):
    incorrect_site = True
    while incorrect_site:
        site_to_get = input(f"Enter the site name:{new_line}")
        if site_to_get in all_passwords:
            incorrect_site = False
        else:
            print("Can't find the site. Check the name and try again.")
    username = all_passwords[site_to_get]["username"]
    password = all_passwords[site_to_get]["password"]
    formatted_return = f"{new_line}Site: {site_to_get}{new_line}Username: {username}"\
    f"{new_line}Password: {password}"
    print(formatted_return)
    return site_to_get


def add_password(all_passwords):
    incorrect_info = True
    while incorrect_info:    
        site = input(f"What's the site name?{new_line}")
        username = input(f"What's the username?{new_line}")
        password = input(f"What's the password?{new_line}")
        info_to_add = f"site: {site}\nusername:{username}\npassword: {password}"
        print(info_to_add)
        is_info_correct = input(f"Is the inputted information correct? y/n{new_line}").lower()
        if is_info_correct == "y":
            all_passwords[site] = {
                "username": username,
                "password": password
            }
            incorrect_info = False

        print(f"Testing: {all_passwords}")
    # still need to upload this to json and encrypt. But that could be done at the end of the process, once the 
    # user confirms that there are no additional requests
    return all_passwords


def correct_password(all_passwords):
    incorrect_info = True
    value_hash = {
        "1": "username",
        "2": "password"
    }
    site_to_correct = retrieve_one_pw(all_passwords)
        
    dumb_input = True
    while dumb_input:
        which_to_correct = input(f"Which one would you like to correct?{new_line}1 - username{new_line}2 - password{new_line}")
        if which_to_correct == "1" or which_to_correct == "2":
            dumb_input = False
        else:
            print("Pick 1 or 2!")
    still_incorrect = True
    while still_incorrect:
        correct_info = input(f"Please input the corrected information:{new_line}")
        correct_or_not = input(f"Is this correct? y/n{new_line}{correct_info}{new_line}").lower()
        if correct_or_not == "y":
            all_passwords[site_to_correct][value_hash[which_to_correct]] = correct_info 
            still_incorrect = False
            print("Info successfully changed!")
            # STILL REQUIRES TO BE UPLOADED TO JSON THO
        else:
            print("Then be careful and type it in again please.")

def get_all_passwords(all_passwords):
    for index, site in enumerate(all_passwords):
        username = all_passwords[site]["username"]
        password = all_passwords[site]["password"]
        formatted_info = f"{new_line}Site: {site}{new_line}Username: {username}{new_line}Password: {password}"
        print(f"{index + 1} --------------v---------------v------------------v {formatted_info}")



def change_real_pot(real_pot_name):
    real_pot_no = input(f"Which pot would you like to be your real one?{new_line}")
    real_pot_name = f"data {real_pot_no}"
    