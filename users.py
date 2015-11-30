class User:
    def __init__(self, name, password, email):
        self.name = name
        self.password = password
        self.email = email


def add_user(user_base, name, password, email):
    # Check if either username or email are already in use.
    print(user_base)
    if user_base:
        for item in user_base:
            print('checking user: ' + item)
            if item.name == name or item.email == email:
                return False
    print('1')
    new_user = User(name, password, email)
    print('2')
    user_base.append(new_user)
    print('3')
    with open('users.csv', 'a') as file:
        print('4')
        file.write(str(new_user.name) + ',' + str(new_user.password) + ',' + str(new_user.email) + '\n')
    print("Returning true")
    return True


def populate_users():
    user_base = []
    with open('users.csv', 'r') as file:
        for line in file:
            line = line.rstrip()
            line = line.split(',')
            new_user = User(line[0], line[1], line[2])
            user_base.append(new_user)

    return user_base


def attempt_login(user_base, username, password):
    #passed password is already hashed.
    for item in user_base:
        if item.name == username:
            if item.password == password:
                return True
            else:
                return False
        else:
            return False
