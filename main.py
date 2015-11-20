__author__ = 'Phil'

import hashlib
from flask import Flask, send_from_directory, request, url_for, redirect, render_template

app = Flask(__name__, static_url_path='')

encoded_salt = b"example"

# TEST USERS, DO NOT INCLUDE IN PRODUCTION!!!!!!!!!!!!!!!!
user_base = {'admin' : hashlib.sha256(b'password' + encoded_salt)}


def validate_login(username, password):
    encoded_pass = bytes(password, encoding='UTF-8')
    try:
        if hashlib.sha256(encoded_pass + encoded_salt).digest() == user_base[username.lower()].digest():
            return True
        else:
            return False
    except KeyError:
        return False


@app.route('/')
def root():
    return redirect(url_for('static', filename='index.html'))


@app.route('/index_submit', methods=['POST', 'GET'])
def login():
    error = None
    if request.method == 'POST':
        if validate_login(request.form['username'], request.form['password']):
            return succesful_login(request.form['username'])
        else:
            error = 'Invalid username/password'

    return render_template('index.html', error=error)


def succesful_login(username):
    print(username + " has logged in!")

if __name__ == '__main__':
    app.run()