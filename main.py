import hashlib
import secrets
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes



####
####
####
# SIMPLE OUTLINE OF THE LOGIC
#
#   Input a master password to decrypt the password manager
#   Master password goes through PBKDF2, outputs a secure key which is then used to decrypt the data inside the app
#   Each password inside the manager is encrypted using AES-GCM (Galois/Counter mode) with an initialization vector (to be refered to as IV)
#  
#
#
####
####
####

# the pw manager will require a strong master password (probably dictionary-based instead of letters). Use KDF to derive a 
# key from that master password to encrypt the entire pw manager.

# TODO-1 function that generates a secure password

def generate_password(pw_length=24):
    """Generates a random password of [by default] length 24, len can be changed"""
    avail_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()<>?,./[]\\{}|`~"
    password_str = ""
    for i in range(pw_length):
        password_str += secrets.choice(avail_chars)
    return password_str

# generate_password()

# TODO-2: Generate an initialization vector for the AES (we need access to the password, can't hash it, so IV instead of salt)
def generate_nonce(nonce_len=12):
    """Generates an IV of custom length (12 by default to fit AES-GCM)"""
    return secrets.token_bytes(nonce_len)

# TODO-2.5: Use the KDF (PKDF2) to generate a key
def master_to_key_kdf(master_password, der_key_len=32, hash_algo="sha256", iterations=500000):
    """Converts a master password into a key, returns key, salt, iterations"""
    final_key = ""
    salt_kdf = secrets.token_bytes(16) 
    master_pw_bytes = master_password.encode("utf-8")
    derived_key_bytes = hashlib.pbkdf2_hmac(
        hash_name=hash_algo,
        password=master_pw_bytes,
        iterations=iterations,
        dklen=der_key_len,
        salt=salt_kdf
    )
    return derived_key_bytes, salt_kdf.hex(), iterations

derived_key, salt_used, iteration_no = master_to_key_kdf("password123")
print(f"Derived key: {derived_key}\nSalt: {salt_used}\nIterations: {iteration_no}")



def encrypt_data(enc_key: bytes, plaintext: bytes):
    nonce = generate_nonce()
    cipher = Cipher(algorithm=algorithms.AES(enc_key), mode=modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag
    return cipher_text, tag


def text_to_bytes(text_to_convert):
    return text_to_convert.encode("utf-8")



print(encrypt_data(derived_key, plaintext=text_to_bytes("Haha let's see if this works")))
# def decrypt_data(enc_key: bytes, ciphertext: bytes):



# HONEYPOTTTTTTTTTTTTs




def encrypt_decrypt_func(enc_or_dec_choice):
    if enc_or_dec_choice == "enc":
        pass
    elif enc_or_dec_choice == "dec":
        pass
    else:
        print("Please specify the direction of this tool.")

def read_info_from_json(platform, decryption_key=None):
    with open("./password_manager.json", "r") as file:
        our_file = json.load(file)
    # print(our_file)
    # and now we would use the key do decrypt the json data
    ####
    # decryption function goes here
    #
    ####
    try:
        our_file["data"][platform]    
        info_return = our_file["data"][platform]
        username = info_return["username"]
        password = info_return["password"]
        return username, password
    except KeyError:
        print("An entry for this site does not exist, check the spelling and try again!")
# curr_usr, curr_pw = read_info_from_json()

# read_info_from_json(platform="facebook")

def add_info_to_json(username="username1", password="password1", site="snapchat", decryption_key=None):
    """adds a new entry into the password manager's json"""
    
    with open("./password_manager.json", "r") as file:
        json_file = json.load(file)
    json_file["data"][site] = {
        "username": username,
        "password": password
    }
    with open("./password_manager.json", "w") as f:
        json.dump(json_file, f, indent=4)






# TODO-3: set up a CLI to run through terminal (at first just do text-based, later optimize for terminal)
# question_end = "\n\t-"
# master_password = input(f"Please input you master password:{question_end}")
