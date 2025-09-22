#!/usr/bin/env python3
import argparse
import os


parser = argparse.ArgumentParser(prog="qwep", description="this app will do whatever it needs to do")

parser.add_argument("-t", "--test", action="store_true", help="This command will test whether the cli is active")
parser.add_argument("-d", "--dirAdd", action="store_true", help="Let's the user specify which directory to use for the qwep")
parser.add_argument("-g", "--generate", action="store_true", help="Generates a random secure password of specified length")

args = parser.parse_args()


def get_pw_len_to_generate():
    bad_ans = True
    while bad_ans:
        gen_pw_len = input("How many chars should the character contain?\n\t-")
        try:
            gen_pw_len_int = int(gen_pw_len)
            bad_ans = False
        except ValueError:
            print(f"Please enter a number. Your answer was: {gen_pw_len}\n\n")


def add_dir():
    dir_exists = False
    while not dir_exists:     
        new_dir = input("Please input the absolute directory where the json file will be/is.\n\t-")
        dir_exists = os.path.isdir(new_dir)
        print(f"The new directory has inputted: {new_dir}")
        if dir_exists:
            print("dir does indeed exist")
        else:
            print("the dir does not exist")
    print("The functino has fnished successfully")
    return new_dir

def testing_fun():
    print("the test is surprisingly working!")



if args.test:
    testing_fun()
    # print("the test is surprisingly working!")
elif args.dirAdd:
    dir_to_store = add_dir()
    # add functionality here
elif args.generate:
    password_length = get_pw_len_to_generate()

else:
    print("Please insert a real flag. Try: -h fr help.")




# do this later, not as simple as I had thought
# users_choices_hash = {
#     args.test: lambda: testing_fun,
#     args.dirAdd: lambda: add_dir,

# }




