#!/usr/bin/env python3
import argparse

parser = argparse.ArgumentParser(prog="qwep", description="testing qwep cli")

parser.add_argument("-t", "--test", action="store_true", help="Checks if the CLI is active")

args = parser.parse_args()

if args.test:
    print("The CLI is active and working!")
else:
    print("No flags provided. Try: qwep -h")