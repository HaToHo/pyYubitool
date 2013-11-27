import random
from shutil import copyfile
import argparse
import string
import base64

__author__ = 'haho0032'
#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sqlite3
from os.path import exists

global current_db_name
current_db_name = None


def getText(max, message, error):
    c_len = max + 1
    text = ""
    while c_len > max:
        text = raw_input(message)
        c_len = len(text)
        if c_len > max:
            print error
    return text

def padding(str, char, padding):
    for x in range(len(str), padding):
        str += char
    return str

def db_connect():
    global current_db_name
    if current_db_name is None:
        choose_database()
    if current_db_name is None:
        return
    conn = sqlite3.connect(current_db_name.replace(".db", "") + ".db")
    return conn

def print_help():
    print "This is a tool to create a database for the yubikey tool."
    print "Commands:"
    print "create                     [c]   : Creates a new database."
    print "choose database            [cd]  : Choose the database to operate on."
    print "client add user            [cau] : Add a user that can login with the client."
    print "client list user           [clu] : List all users."
    print "client delete user         [cdu] : Lists all users and makes it possible to delete one at the time."
    print "client add server          [cas] : Add a server that can be used by the client."
    print "client list server         [cls] : List all servers that the client can use."
    print "client delete server       [cds] : Lists all servers and makes it possible to delete one at the time."
    print "server add api_key         [saa] : Add an api_key and id for the server.  "
    print "server list api_key        [sla] : List all api_keys."
    print "server delete api_key      [sda] : Lists all api_keys and makes it possible to delete one at the time."
    print "server add yubikey         [say] : Add a yubikey to the server."
    print "server list yubikey        [sly] : List all yubikeys"
    print "server delete yubikey      [sdy] : List all yubikeys and make it possible to delete one at the time."
    print "help                       [h]   : Print this help."
    print "quit                       [q]   : Quit the tool."

def choose_database():
    global current_db_name
    file_name = None
    while file_name is None:
        db_name = raw_input("Enter database name or q to quit: ")
        if db_name == "q":
            file_name = "q"
        else:
            file_name = db_name.replace(".db", "") + ".db"
            if (not exists(file_name)):
                print "Database do not exists!"
                file_name = None
    if file_name != "q":
        current_db_name = file_name

def add_api_key():
    conn = db_connect()
    c = conn.cursor()
    count = 1
    id = None
    while count != 0:
        id = ''. join(random.choice(string.digits) for x in range(30))
        c.execute('SELECT count(*) FROM local_server_api_key WHERE id=?', (id,))
        response = c.fetchone()
        count = response[0]
    count = 1
    api_key = None
    while count != 0:
        api_key = ''. join(random.choice(string.ascii_uppercase + string.digits) for x in range(30))
        c.execute('SELECT count(*) FROM local_server_api_key WHERE api_key=?', (api_key ,))
        response = c.fetchone()
        count = response[0]
    api_key = base64.b64encode(api_key)
    comment = getText(128, "Enter a comment for this api key (max 128 characters): ",
                      "Comment can only be 128 characters!")
    c.execute("INSERT INTO local_server_api_key VALUES (?,?,?)", (id, api_key, comment))
    conn.commit()
    conn.close()


def list_all_api_keys():
    conn = db_connect()
    c = conn.cursor()
    c.execute('SELECT rowid, lsa.* FROM local_server_api_key lsa')

    print padding("ROWID", ' ', 10) + "|" + padding("ID", ' ', 30) + "|" + padding("API KEY (BASE 64 encoded)", ' ', 50) + "|" + padding("COMMENT", ' ', 128)
    print padding("_", '_', 10) + "|" + padding("_", '_', 30) + "|" +  padding("", '_', 50) + "|" + padding("", '_', 128)
    response = c.fetchmany()
    while len(response) > 0:
        api_key = response[0]
        print padding(str(api_key[0]), ' ', 10) + "|" + api_key[1] + "|" + padding(api_key[2], ' ', 50) + "|" + api_key[3]
        print padding("_", '_', 10) + "|" + padding("_", '_', 30) + "|" +  padding("", '_', 50) + "|" + padding("", '_', 128)
        response = c.fetchmany()
    conn.close()

def delete_api_key():
    conn = db_connect()
    c = conn.cursor()
    rowid = None
    while rowid != "q":
        list_all_api_keys()
        rowid = raw_input("Enter the ROWID to delete or press q to quit: ")
        try:
            c.execute('DELETE FROM local_server_api_key where rowid = ?', (rowid,))
            conn.commit()
        except Exception as ex:
            pass
    conn.close()

def add_yubikey():
    conn = db_connect()
    c = conn.cursor()
    public_id = getText(32,"Enter the public identification for the yubikey: ",
                        "The database only accepts 32 characters!")
    private_id = getText(32,"Enter the private identification for the yubikey: ",
                        "The database only accepts 32 characters!")
    aes = getText(32,"Enter aes key for the yubikey: ",
                        "The database only accepts 32 characters!")
    c.execute("INSERT INTO local_server_yubikey VALUES (?,?,?)", (public_id, private_id, aes))
    conn.commit()
    conn.close()

def list_all_yubikey():
    conn = db_connect()
    c = conn.cursor()
    c.execute('SELECT rowid, lsy.* FROM local_server_yubikey lsy')

    print padding("ROWID", ' ', 10) + "|" + padding("PUBLIC ID", ' ', 32) + "|" + padding("PRIVATE ID", ' ', 32) + "|" + padding("AES KEY", ' ', 32)
    print padding("_", '_', 10) + "|" + padding("_", '_', 32) + "|" +  padding("", '_', 32) + "|" + padding("", '_', 32)
    response = c.fetchmany()
    while len(response) > 0:
        api_key = response[0]
        print padding(str(api_key[0]), ' ', 10) + "|" + padding(api_key[1], ' ', 32) + "|" + padding(api_key[2], ' ', 32) + "|" + padding(api_key[3], ' ', 32)
        print padding("_", '_', 10) + "|" + padding("_", '_', 32) + "|" +  padding("", '_', 32) + "|" + padding("", '_', 32)
        response = c.fetchmany()
    conn.close()

def delete_yubikey():
    conn = db_connect()
    c = conn.cursor()
    rowid = None
    while rowid != "q":
        list_all_yubikey()
        rowid = raw_input("Enter the ROWID to delete or press q to quit: ")
        try:
            c.execute('DELETE FROM local_server_yubikey where rowid = ?', (rowid,))
            conn.commit()
        except Exception as ex:
            pass
    conn.close()

def add_client_server():
    conn = db_connect()
    c = conn.cursor()
    server_url = getText(100,"Enter the complete url to the yubikey validation server: ",
                        "The database only accepts 100 characters!")
    id = getText(32,"Enter the identification for the yubikey validation server: ",
                        "The database only accepts 32 characters!")
    api_key = getText(50,"Enter shared api key (base 64 encoded) for the yubikey validation server: ",
                        "The database only accepts 32 characters!")
    c.execute("INSERT INTO client_servers VALUES (?,?,?)", (server_url, id, api_key))
    conn.commit()
    conn.close()

def list_all_client_server():
    conn = db_connect()
    c = conn.cursor()
    c.execute('SELECT rowid, cs.* FROM client_servers cs')

    print padding("ROWID", ' ', 10) + "|" + padding("SERVER URL", ' ', 100) + "|" + padding("ID", ' ', 32) + "|" + padding("API KEY", ' ', 50)
    print padding("_", '_', 10) + "|" + padding("_", '_', 100) + "|" +  padding("", '_', 32) + "|" + padding("", '_', 32)
    response = c.fetchmany()
    while len(response) > 0:
        api_key = response[0]
        print padding(str(api_key[0]), ' ', 10) + "|" + padding(api_key[1], ' ', 100) + "|" + padding(api_key[2], ' ', 32) + "|" + padding(api_key[3], ' ', 50)
        print padding("_", '_', 10) + "|" + padding("_", '_', 100) + "|" +  padding("", '_', 32) + "|" + padding("", '_', 50)
        response = c.fetchmany()
    conn.close()

def delete_client_server():
    conn = db_connect()
    c = conn.cursor()
    rowid = None
    while rowid != "q":
        list_all_client_server()
        rowid = raw_input("Enter the ROWID to delete or press q to quit: ")
        try:
            c.execute('DELETE FROM client_servers where rowid = ?', (rowid,))
            conn.commit()
        except Exception as ex:
            pass
    conn.close()

def add_client_user():
    conn = db_connect()
    c = conn.cursor()
    public_id = getText(30,"Enter the yubikey public id: ",
                        "The database only accepts 30 characters!")
    user_name = getText(30,"Enter the username connected to the yubikey: ",
                        "The database only accepts 32 characters!")
    c.execute("INSERT INTO client_yubikey_users VALUES (?,?)", (public_id, user_name))
    conn.commit()
    conn.close()

def list_all_client_users():
    conn = db_connect()
    c = conn.cursor()
    c.execute('SELECT rowid, cyu.* FROM client_yubikey_users cyu')

    print padding("ROWID", ' ', 10) + "|" + padding("PUBLIC ID", ' ', 30) + "|" + padding("USERNAME", ' ', 30)
    print padding("_", '_', 10) + "|" + padding("_", '_', 30) + "|" +  padding("", '_', 30)
    response = c.fetchmany()
    while len(response) > 0:
        api_key = response[0]
        print padding(str(api_key[0]), ' ', 10) + "|" + padding(api_key[1], ' ', 30) + "|" + padding(api_key[2], ' ', 30)
        print padding("_", '_', 10) + "|" + padding("_", '_', 30) + "|" +  padding("", '_', 30)
        response = c.fetchmany()
    conn.close()

def delete_client_user():
    conn = db_connect()
    c = conn.cursor()
    rowid = None
    while rowid != "q":
        list_all_client_users()
        rowid = raw_input("Enter the ROWID to delete or press q to quit: ")
        try:
            c.execute('DELETE FROM client_yubikey_users where rowid = ?', (rowid,))
            conn.commit()
        except Exception as ex:
            pass
    conn.close()

def create_db():
    global current_db_name
    file_name = None
    while file_name is None:
        db_name = raw_input("Enter database name or q to quit: ")
        if db_name == "q":
            file_name = "q"
        else:
            file_name = db_name.replace(".db", "") + ".db"
            if (exists(file_name)):
                print "Database already exists. Delete the database file " + file_name + \
                      " manually or choose another name."
                file_name = None

    if file_name != "q":
        conn = sqlite3.connect(db_name.replace(".db", "") + ".db")
        #SQL lite automatically creates a primare key index with the name row id that is incremental.
        #If you want a specific primary key add a type column with type INTEGER PRIMARY KEY AUTOINCREMENT
        c = conn.cursor()
        c.execute('''CREATE TABLE client_servers (server_url text, id text, api_key text)''')
        c.execute('''CREATE TABLE client_yubikey_users (public_id text, user_name text)''')
        c.execute('''CREATE TABLE client_session_log (public_id text primary key, utc_timestamp text, seconds19700101 text,
        yubikey_timestamp text, yubikey_session_counter text, yubikey_sessionuse text)''')

        c.execute('''CREATE TABLE local_server_api_key (id text, api_key text, comment text)''')
        c.execute('''CREATE TABLE local_server_yubikey (public_id text, private_id text, aes text)''')
        c.execute('''CREATE TABLE local_server_replay_log (otp text)''')
        c.execute('''CREATE TABLE local_server_replay_log_nonce (public_id text, nonce text)''')
        c.execute('''CREATE TABLE local_server_session_log (public_id text primary key, utc_timestamp text, seconds19700101 text,
        yubikey_timestamp text, yubikey_session_counter text, yubikey_sessionuse text)''')
        conn.commit()
        conn.close()
        current_db_name = db_name
        print "Database " + current_db_name + " is created and set as current database!"

if __name__ == '__main__':
    print_help()
    while True:
        command = raw_input("Enter command: ")

        if command == "quit" or command == "q":
            break;
        if command == "help" or command == "h":
            print_help();
        if command == "create" or command == "c":
            create_db()
        if command == "server add api_key" or command == "saa":
            add_api_key()
        if command == "server list api_key" or command == "sla":
            list_all_api_keys()
        if command == "server delete api_key" or command == "sda":
            delete_api_key()
        if command == "choose database" or command == "cd":
            choose_database()
        if command == "server add yubikey" or command == "say":
            add_yubikey()
        if command == "server list yubike" or command == "sly":
            list_all_yubikey()
        if command == "server delete yubikey" or command == "sdy":
            delete_yubikey()
        if command == "client add user" or command == "cau":
            add_client_user()
        if command == "client list user" or command == "clu":
            list_all_client_users()
        if command == "client delete user" or command == "cdu":
            delete_client_user()
        if command == "client add server" or command == "cas":
            add_client_server()
        if command == "client list server" or command == "cls":
            list_all_client_server()
        if command == "client delete server" or command == "cds":
            delete_client_server()
