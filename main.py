__author__ = 'Phil'

import hashlib
from flask import Flask, send_from_directory, request, url_for, redirect

app = Flask(__name__, static_url_path='')

def test_log_in():
    # Create a new account.
    desired_user = input("Enter a new user name: ")
    desired_password = input("Enter a desired password: ")

    user_base = {}
    encoded_salt = b"example"

    encoded_pass = bytes(desired_password, encoding='UTF-8')

    user_base[desired_user.lower()] = hashlib.sha256(encoded_pass + encoded_salt)

    print()

    logged_in = False

    while not logged_in:
        print("--------LOGIN--------")
        login_user = input("User Name: ")
        login_pass = input("Password: ")

        encoded_pass = bytes(login_pass, encoding='UTF-8')

        try:
            if hashlib.sha256(encoded_pass + encoded_salt).digest() == user_base[login_user].digest():
                print("Logged in!!!")
                logged_in = True
            else:
                print("Incorrect password")

        except KeyError:
            print("User name not found...")


@app.route('/')
def root():
    return redirect(url_for('static', filename='index.html'))

if __name__ == '__main__':
    app.run()