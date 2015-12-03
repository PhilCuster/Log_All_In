__author__ = 'Phil'

import datetime
import time
import sqlite3
import bcrypt
import base64
import smtplib
import random
import string
from Crypto.Cipher import AES
from Crypto import Random
from flask import Flask, request, url_for, redirect, render_template

app = Flask(__name__, static_url_path='')

# Temporary storage for AES encryption key
AES_KEY = None

SITE_URL = "http://127.0.0.1:5000/"
SITE_EMAIL = "logallin3@gmail.com"
SITE_PASSWORD = "blueberry3"

obj = None

def current_time():
    return datetime.datetime.fromtimestamp(time.time()).strftime('[%Y-%m-%d %H:%M:%S]')


def write_log(message):
    with open('log.txt', 'a') as log:
        log.write(current_time() + ' ' + message + '\n')


def send_email(target, code):
    message = "Thank you for registering, please click this link to verify your account: " + SITE_URL + "/" + code
    server = smtplib.SMTP('smtp.gmail.com:587')
    print('1')
    server.ehlo()
    print('2')
    server.starttls()
    print('3')
    server.login(SITE_EMAIL, SITE_PASSWORD)
    print('4')
    msg = "\r\n".join([
            "From: " + SITE_EMAIL,
            "To: " + target,
            "Subject: Verify your account!",
            "",
            message
            ])
    print('5')
    server.sendmail(SITE_EMAIL, target, msg)
    print('6')
    server.quit()


def hide_secret(secret):
    # Block size for AES
    block_size = 16

    # Thanks to http://www.dlitz.net/software/pycrypto/
    # Append period to end of secret
    secret += '.'
    # Strings for DES must be a multiple of 8 in length
    add_x = block_size - (len(secret) % block_size)
    secret += 'X' * add_x

    init_vector = Random.new().read(AES.block_size)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, init_vector)
    return base64.b64encode(init_vector + cipher.encrypt(secret))


def unhide_secret(user):
    database = sqlite3.connect('users.db', isolation_level=None)
    c = database.cursor()
    c.execute("SELECT secret FROM users WHERE username = ?", (user,))
    secret = c.fetchone()
    secret = secret[0]
    secret = base64.b64decode(secret)
    init_vector = secret[:16]
    cipher = AES.new(AES_KEY, AES.MODE_CBC, init_vector)
    unhidden_secret = cipher.decrypt(secret[16:])
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

    c.execute("SELECT email FROM users WHERE email = ?", (req_email,))

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

    # Send email to user.
    validate = ''.join(random.choice(string.ascii_uppercase) for i in range(16))
    print("Sending email to " + req_email)
    send_email(req_email, validate)
    print("Email success!")

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
    AES_KEY = input("Enter AES key: ").encode('utf-8')
    app.run()