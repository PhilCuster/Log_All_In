__author__ = 'Phil'

import hashlib
import datetime
import time
import sqlite3
import bcrypt
from flask import Flask, request, url_for, redirect, render_template

app = Flask(__name__, static_url_path='')

encoded_salt = b"example"

def current_time():
    return datetime.datetime.fromtimestamp(time.time()).strftime('[%Y-%m-%d %H:%M:%S]')


def write_log(message):
    with open('log.txt', 'a') as log:
        log.write(current_time() + ' ' + message + '\n')


def validate_login(attempted_username, attempted_password):
    encoded_pass = bytes(attempted_password, encoding='UTF-8')
#    hashed_pass = hashlib.sha256(encoded_pass + encoded_salt).hexdigest()
    database = sqlite3.connect('users.db', isolation_level=None)
    c = database.cursor()
    # Check if username with matching password exists in the database.
    c.execute("SELECT password FROM users WHERE username = ?", (attempted_username,))
    print("1")
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


def validate_registration(username, password, email):
    database = sqlite3.connect('users.db', isolation_level=None)
    c = database.cursor()
    req_username = username.lower()
    req_email = email.lower()
    salt = bcrypt.gensalt()
    encoded_pass = bytes(password, encoding='UTF-8')
#    print(salt)
    hashed_pass = bcrypt.hashpw(encoded_pass, salt)
    print("Attempting to register user: " + req_username)
    # Check if username already exists in database
    c.execute("SELECT username FROM users WHERE username = ?", (req_username,))
    print("Checked for user!")

    if c.fetchone():
        # User already exists
        print("Registration Failure: User of name '" + req_username + "' already exists...")
        write_log("Registration Failure: User of name '" + req_username + "' already exists...")
        return False

    c.execute("SELECT email FROM users WHERE email = ?", (req_username,))
    print("Checked for email!")

    if c.fetchone():
        # Email already registered.
        print("ERROR: User with email '" + req_email + "' already exists...")
        write_log("Registration Failure: User of name '" + req_username + "' already exists...")
        return False

    # User should be good to go, insert into table.
    print("Adding user to database...")
    c.execute("INSERT INTO users VALUES (?,?,?)", (req_username,req_email,hashed_pass))
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
            print("Successful login from user '" + attempted_user + "'")
            write_log("Successful login from user '" + attempted_user + "'")
            return render_template('hello.html', name=attempted_user)
        else:
            print("Invalid login from user '" + attempted_user + "'")
            write_log("Invalid login from user '" + attempted_user + "'")

    return render_template('invalid.html', name=attempted_user)


@app.route('/register_submit', methods=['POST', 'GET'])
def register():
    print("Attempting registration...")
    if request.method == 'POST':
        if validate_registration(request.form['username'], request.form['password'], request.form['email']):
            return redirect(url_for('static', filename='index.html'))
        else:
            print('Registration did not work!')
    print("Rendering template...")
    return render_template('invalid.html', name=request.form['username'])


if __name__ == '__main__':
#    user_base = users.populate_users()
    app.run()