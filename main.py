__author__ = 'Phil'

import hashlib
import datetime
import time
import users
from flask import Flask, send_from_directory, request, url_for, redirect, render_template

app = Flask(__name__, static_url_path='')

encoded_salt = b"example"


user_base = []  #{'admin' : hashlib.sha256(b'password' + encoded_salt)}



def current_time():
    return datetime.datetime.fromtimestamp(time.time()).strftime('[%Y-%m-%d %H:%M:%S]')


def write_log(message):
    with open('log.txt', 'a') as log:
        log.write(current_time() + message + '\n')


def validate_login(username, password):
    encoded_pass = bytes(password, encoding='UTF-8')
    hashed_pass = hashlib.sha256(encoded_pass + encoded_salt).digest()
    if users.attempt_login(user_base, username.lower(), hashed_pass):
        write_log('Login from user: ' + username)
        return True
    else:
        write_log('Attempted login from user: ' + username)
        return False


def validate_registration(username, password, email):
    username = username.lower()
    encoded_pass = bytes(password, encoding='UTF-8')
    hashed_pass = hashlib.sha256(encoded_pass + encoded_salt).digest()
    print("Attempting to register user: " + username)
    if users.add_user(user_base, username, hashed_pass, email):
        print('Added new user: ' + username)
        write_log("New user added: " + username)
        return True
    else:
        print("Could not validate user...")
        return False


@app.route('/')
def root():
    return redirect(url_for('static', filename='index.html'))


@app.route('/index_submit', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        if validate_login(request.form['username'], request.form['password']):
            return render_template('hello.html', name=request.form['username'])
        else:
            print("Invalid login...")

    return render_template('invalid.html', name=request.form['username'])


@app.route('/register_submit', methods=['POST', 'GET'])
def register():
    print("Attempting registration...")
    if request.method == 'POST':
        if validate_registration(request.form['username'], request.form['password'], request.form['email']):
            return redirect(url_for('static', filename='index.html'))
        else:
            print('Register did not work!')
    print("Rendering template...")
    return render_template('invalid.html', name=request.form['username'])


if __name__ == '__main__':
    user_base = users.populate_users()
    app.run()