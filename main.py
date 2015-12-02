__author__ = 'Phil'

import datetime
import time
import sqlite3
import bcrypt
from Crypto.Cipher import DES
from flask import Flask, request, url_for, redirect, render_template

app = Flask(__name__, static_url_path='')

encoded_salt = b"example"

obj = None

def current_time():
    return datetime.datetime.fromtimestamp(time.time()).strftime('[%Y-%m-%d %H:%M:%S]')


def write_log(message):
    with open('log.txt', 'a') as log:
        log.write(current_time() + ' ' + message + '\n')


def hide_secret(secret):
    # Thanks to http://www.dlitz.net/software/pycrypto/
    # Append period to end of secret
    secret += '.'
    # Strings for DES must be a multiple of 8 in length
    add_x = 8 - (len(secret) % 8)
    secret += 'X' * add_x
    ciph = obj.encrypt(secret)
    return ciph


def unhide_secret(user):
    database = sqlite3.connect('users.db', isolation_level=None)
    c = database.cursor()
    c.execute("SELECT secret FROM users WHERE username = ?", (user,))
    secret = c.fetchone()
    secret = secret[0]
    unhidden_secret = obj.decrypt(secret)
    unhidden_secret = unhidden_secret.decode("utf-8")
    unhidden_secret = unhidden_secret.split('.')
    unhidden_secret = unhidden_secret[:-1]
    unhidden_secret = '.'.join(unhidden_secret)
    return unhidden_secret


def validate_login(attempted_username, attempted_password):
    encoded_pass = bytes(attempted_password, encoding='UTF-8')
    database = sqlite3.connect('users.db', isolation_level=None)
    c = database.cursor()
    # Check if username with matching password exists in the database.
    c.execute("SELECT password FROM users WHERE username = ?", (attempted_username,))
    try:
        try_pass = c.fetchone()
        try_pass = try_pass[0]
        print(try_pass)
        if bcrypt.hashpw(encoded_pass, try_pass) == try_pass:
            return True
        else:
            return False
    except IndexError:
        return False


def validate_registration(username, password, email, secret):
    database = sqlite3.connect('users.db', isolation_level=None)
    c = database.cursor()
    req_username = username.lower()
    req_email = email.lower()
    salt = bcrypt.gensalt()
    encoded_pass = bytes(password, encoding='UTF-8')
    hashed_pass = bcrypt.hashpw(encoded_pass, salt)
    # Encrypt the secret
    enc_secret = hide_secret(secret)
    print("Attempting to register user: " + req_username)
    # Check if username already exists in database
    c.execute("SELECT username FROM users WHERE username = ?", (req_username,))

    if c.fetchone():
        # User already exists
        print("Registration Failure: User of name '" + req_username + "' already exists...")
        write_log("Registration Failure: User of name '" + req_username + "' already exists...")
        return False

    c.execute("SELECT email FROM users WHERE email = ?", (req_username,))

    if c.fetchone():
        # Email already registered.
        print("ERROR: User with email '" + req_email + "' already exists...")
        write_log("Registration Failure: User of name '" + req_username + "' already exists...")
        return False

    # User should be good to go, insert into table.
    print("Adding user to database...")
    c.execute("INSERT INTO users VALUES (?,?,?,?)", (req_username,req_email,hashed_pass,enc_secret))
    database.commit()
    database.close()
    write_log("Added user '" + req_username + "' to the database")
    return True


@app.route('/')
def root():
    return redirect(url_for('static', filename='index.html'))


@app.route('/index_submit', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        attempted_user = request.form['username']
        attempted_password = request.form['password']
        if validate_login(attempted_user, attempted_password):
            # Retrieve the secret.
            secret = unhide_secret(attempted_user)
            print("Successful login from user '" + attempted_user + "'")
            write_log("Successful login from user '" + attempted_user + "'")
            return render_template('hello.html', name=attempted_user, secret=secret)
        else:
            print("Invalid login from user '" + attempted_user + "'")
            write_log("Invalid login from user '" + attempted_user + "'")

    return render_template('invalid.html', name=attempted_user)


@app.route('/register_submit', methods=['POST', 'GET'])
def register():
    print("Attempting registration...")
    if request.method == 'POST':
        if validate_registration(request.form['username'], request.form['password'], request.form['email'],request.form['secret']):
            return redirect(url_for('static', filename='index.html'))
        else:
            print('Registration did not work!')
    print("Rendering template...")
    return render_template('invalid.html', name=request.form['username'])


if __name__ == '__main__':
    obj = DES.new('abcd1234', DES.MODE_ECB)
    app.run()