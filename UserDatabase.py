"""
Example SQLite Python Database
==============================

Experiment with the functions below to understand how the
database is created, data is inserted, and data is retrieved

"""
import sqlite3
from datetime import datetime
import hashlib
import os


def createDB():
    """ Create table 'plants' in 'user' database """
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('''CREATE TABLE user
                    (
                    username text,
                    password text,
                    level text
                    )''')
        conn.commit()
        return True
    except BaseException:
        return False
    finally:
        if c is not None:
            c.close()
        if conn is not None:
            conn.close()

#
# def getDate():
#     """ Generate timestamp for data inserts """
#     d = datetime.now()
#     return d.strftime("%m/%d/%Y, %H:%M:%S")
#

def addUser():
    """ Example data insert into plants table """
    username = str(input("Enter username: "))  # Need exception handling
    password = str(input("Enter password: "))
    level = str(input("Enter clearance level of user: "))  # Need to create valid input check
    salt = str(os.urandom(60))[:40]
    hashable = salt + password  # concatenate salt and plain_text
    hashable = hashable.encode('utf-8')  # convert to bytes
    this_hash = hashlib.sha1(hashable).hexdigest()  # hash w/ SHA-1 and hexdigest
    hashPassword = salt + this_hash  # prepend hash and return
    dataToInsert = [(username, hashPassword, level)]
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.executemany("INSERT INTO user VALUES (?, ?, ?)", dataToInsert)
        conn.commit()
    except sqlite3.IntegrityError:
        print("Error. Tried to add duplicate record!")
    else:
        print("Success")
    finally:
        if c is not None:
            c.close()
        if conn is not None:
            conn.close()


def queryDB():
    """ Display all records in the plants table """
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        for row in c.execute("SELECT * FROM users"):
            print(row)
    except sqlite3.DatabaseError:
        print("Error. Could not retrieve data.")
    finally:
        if c is not None:
            c.close()
        if conn is not None:
            conn.close()


#createDB()  # Run createDB function first time to create the database
#addUser()  # Add a user to the database (calling multiple times will add additional plants)
# query_db()  # View all data stored in the
