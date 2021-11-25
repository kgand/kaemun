from flask import Flask, render_template, request, redirect, url_for, Blueprint, flash, session
from UserDatabase import addUser, queryDB
import traceback, functools, sqlite3, os, hashlib, random, array
from werkzeug.security import check_password_hash, generate_password_hash

#flask app setup stuff
bp = Blueprint('auth', __name__, url_prefix='/app')

app = Flask(__name__)
app.secret_key = 'asdafsdsdf45423'
SECRET_KEY = '\xfd{H\xe5<\x95\xf9\xe3\x96.5\xd1\x01O<!\xd5\xa2\xa0\x9fR"\xa1\xa8'

#no more than 3 logins attempts allowed
loginAttempts = 0
if loginAttempts >= 3:
    print("Too many login attempts")
    redirect(url_for('tooManyAttempts'))

#run the site
@app.route('/')
def RunSite():
    my_netid = "jbrown63"  # Replace with your UVM NetID here!
    return render_template("MainMenu.html", netid=my_netid)

@app.route("/Login", methods=('GET', 'POST'))
def login():
    global loginAttempts
    loginAttempts += 1
    if request.method == 'POST':
        #get username and password from form
        username = request.form['username']
        password = request.form['password']
        error = None
        #get user info from database
        conn = sqlite3.connect('users.db')
        db = conn.cursor()
        user = db.execute('SELECT * FROM user WHERE username = ?', (username,)).fetchone()

        #if no user that matches database
        if user is None:
            error = "Incorrect username"
        elif user != None:
            salt_length = 40  # set salt_length
            stored = user[1]
            print(stored)
            salt = stored[:40]  # extract salt from stored value
            stored_hash = stored[40:]  # extract hash from stored value
            hashable = salt + password  # concatenate hash and plain text
            hashable = hashable.encode('utf-8')  # convert to bytes
            this_hash = hashlib.sha1(hashable).hexdigest()  # hash and digests
            print(this_hash)
            print(stored_hash)
            # return this_hash == stored_hash  # compare
            if this_hash != stored_hash:
                error = "Incorrect password"
            elif this_hash == stored_hash:
                session.clear()
                #set user level in the session for access to directories
                session['userClearance'] = user[2]
                return redirect(url_for('directory'))
        if error != None:
            flash(error)

    return render_template('Login.html')


@app.route("/Register", methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        #get username and password, check that they're filled out
        username = request.form['username']
        if username == "":
            flash("Please enter a username")
        password = request.form['password']
        if password == "":
            flash("Please enter a password")
        level = request.form['level']
        if level == "":
            level = 1
        error = None
        #check password length
        if len(password) < 8 or len(password) > 25:
            error = "Password must be between 8 and 25 characters. Please re-enter password."
        #check password strength
        if testPasswordStrength(password) == False:
            error = "Password must contain at least one number, one lowercase letter, one uppercase letter, " \
                    "and at least one special character"
        #salt and hash password
        salt = str(os.urandom(60))[:40]
        hashable = salt + password  # concatenate salt and plain_text
        hashable = hashable.encode('utf-8')  # convert to bytes
        this_hash = hashlib.sha1(hashable).hexdigest()  # hash w/ SHA-1 and hexdigest
        hashPassword = salt + this_hash  # prepend hash and return
        dataToInsert = [(username, hashPassword, level)]

        if error == None:
            try:#connect to database and add user info to table
                conn = sqlite3.connect('users.db')
                db = conn.cursor()
                db.executemany("INSERT INTO user VALUES (?, ?, ?)", dataToInsert)
                conn.commit()#check if user already exists
            except sqlite3.IntegrityError:
                flash("Error. User already exists.")
            else:
                print("Success")
            finally:
                if db is not None:
                    db.close()
                if conn is not None:
                    conn.close()
            return redirect(url_for('login'))

        if error != None:
            flash(error)

    return render_template('Register.html')


@app.route('/GeneratePassword/')
def generatePassword():
    #arrays of chracters to meet pw specs
    numbers = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
    lowChars = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                'w', 'x', 'y', 'z']

    upChars = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'M', 'N', 'O', 'p', 'Q', 'R', 'S', 'T', 'U', 'V',
               'W', 'X', 'Y', 'Z']

    special = ['@', '#', '$', '%', '=', ':', '?', '.', '/', '|', '~', '>', '*', '(', ')', '<']

    #combine all characters to an array
    combined = numbers + upChars + lowChars + special

    #select random character from each array
    randNum = random.choice(numbers)
    randUp = random.choice(upChars)
    randLow = random.choice(lowChars)
    randSpec = random.choice(special)

    #combine characters
    tempPass = randNum + randUp + randLow + randSpec

    #make password 12 characters
    for x in range(8):
        tempPass = tempPass + random.choice(combined)

        # convert temporary password into array and shuffle to
        # prevent it from having a consistent pattern
        # where the beginning of the password is predictable
        tempPassList = array.array('u', tempPass)
        random.shuffle(tempPassList)

    password = ""
    for x in tempPassList:
        password = password + x

    return password

#every user allowed in next 3 pages
@app.route("/Directory")
def directory():
    return render_template('Directory.html')


@app.route("/Employees")
def employees():
    return render_template('Employees.html')


@app.route("/TimeReporing")
def timeReporting():
    return render_template('TimeReporting.html')

#check that user has proper clearance for next directories
@app.route("/Accounting")
def accounting():
    userClearance = session.get('userClearance')
    if userClearance == "2" or userClearance == "1":
        return render_template('Accounting.html')
    else:
        flash("You do not have clearance to access this directory.")
        return redirect(url_for('directory'))

@app.route("/Sales")
def sales():
    userClearance = session.get('userClearance')
    if userClearance == "1" or userClearance == "2" or userClearance == "3" or userClearance =="4":
        return render_template('Sales.html')
    else:
        flash("You do not have clearance to access this directory.")
        return redirect(url_for('directory'))

@app.route("/Engineering")
def engineering():
    userClearance = session.get('userClearance')
    if userClearance == "1" or userClearance == "3" or userClearance == "5":
        return render_template('Engineering.html')
    else:
        flash("You do not have clearance to access this directory.")
        return redirect(url_for('directory'))

@app.route("/CustomerService")
def customerService():
    userClearance = session.get('userClearance')
    if userClearance == "1" or userClearance == "6":
        return render_template('CustomerService.html')
    else:
        flash("You do not have clearance to access this directory.")
        return redirect(url_for('directory'))

@app.route("/Software")
def software():
    userClearance = session.get('userClearance')
    if userClearance == "1" or userClearance == "3" or userClearance == "5":
        return render_template('Software.html')
    else:
        flash("You do not have clearance to access this directory.")
        return redirect(url_for('directory'))

@app.route("/TooManyAttempts")
def tooManyAttempts():
    return redirect(url_for('TooManyAttempts.html'))

#test password strength, borrowed from previous lab
def testPasswordStrength(password):
    SPECIAL_CHAR = "!@#$%^&*"
    special_char_check = False
    has_upper = False
    has_lower = False
    has_digit = False
    for ch in password:
        if ch in SPECIAL_CHAR:
            special_char_check = True
        if ch.isupper():
            has_upper = True
        if ch.islower():
            has_lower = True
        if ch.isdigit():
            has_digit = True
    if not special_char_check or \
            not has_upper or \
            not has_lower or \
            not has_digit:
        return False
    else:
        return True


if __name__ == '__main__':
    try:
        app.run(debug=app.debug, host='localhost', port=8097)
    except Exception as err:
        traceback.print_exc()
