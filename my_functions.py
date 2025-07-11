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
    final_key = ""
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


def read_json(path_to_json):
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


def authenticate_user(path_to_json, kdf_salt, correct_pot_name, tag, nonce, kmaster_pw=None):
    import json
    new_line = "\n\t-"
    if not master_pw:
        master_pw = input(f"Please provide your master password:{new_line}")
    enc_key, kdf_salt, iterations = master_to_key_kdf(master_pw, kdf_salt)
    our_file: dict = read_json(path_to_json)
    correct_pot: str = our_file[correct_pot_name]
    correct_pot_kdf_salt = correct_pot["kdf_salt"]
    correct_pot_iterations: int = correct_pot["iterations"]
    correct_pots_data = correct_pot["data"]
    correct_pots_data_nonce = correct_pot["nonce"]
    correct_pots_data_tag = correct_pot["tag"]
    correct_pots_data_ciphertext = correct_pot["ciphertext"]

    plaintext: bytes = decrypt_data(enc_key, correct_pots_data_tag, correct_pots_data_nonce, correct_pots_data_ciphertext)
    plaintext_dict = json.loads(plaintext)
    return plaintext_dict


def get_all_passwords(decrypted_passwords:dict) -> str:
    for key, value in decrypted_passwords.items():
        print(f"This is the key: {key}\nThis is the value: {value}\n\n")