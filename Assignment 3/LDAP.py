'''
*** Author: Laurent Hayez
*** Date: 13 october 2015
*** Course: Security
*** Objective: Code a client that can connect to an Lightweight Directory Access Protocol (LDAP) server,
***            display the directory contents, and add/remove/modify entries from it.
***
*** Note: To be able to run the code, you need to install ldap3 module. On OSX and Debian, type
***           sudo pip install ldap3.
'''

# importing the library for LDAP connections
from ldap3 import Server, Connection, ALL, MODIFY_REPLACE

server_ip = '52.24.54.137'
cont = True

server = Server(server_ip, get_info=ALL)
conn = Connection(server, 'cn = admin, dc = security, dc = ch', 'ldap', auto_bind=True)

print('-----------------------------------------------')
print('-------------  Simple LDAP client -------------')
print('-----------------------------------------------\n')

print('Connected to server: ' + server_ip + '\n')


# While the client wants to continue
while cont:
    print('What operation would you like to do?')
    print('1/ Display;\n2/ Add;\n3/ Remove;\n4/ Modify;\n5/ Display User\n6/ Leave.\n')
    operation = input(('Please type 1, 2, 3, 4, 5, 6, d, a, r, m, du or l: > '))

    # If client wants to display the directory
    if operation == '1' or operation == 'd':
        conn.search('ou = students, dc = security, dc=ch', '(objectclass=person)')
        print(conn.entries)

    # If client wants to add an entry
    elif operation == '2' or operation == 'a':
        print('Entry will be added in ou=students, dc=security, dc=ch\n')
        to_add=[]
        to_add.append(input("Common name: > "))
        to_add.append(input("Surname: > "))
        to_add.append(input("Description: > "))
        to_add.append(input("User Password: > "))
        to_add.append(input("Telephone Number: > "))
        conn.add('cn = '+to_add[0]+', ou = students, dc = security, dc = ch',
                 attributes={'objectClass': 'person',
                             'sn': to_add[1] if to_add[1] != '' else ' ',
                             'description': to_add[2] if to_add[2] != '' else ' ',
                             'userPassword': to_add[3] if to_add[3] != '' else ' ',
                             'telephoneNumber': to_add[4] if to_add[4] != '' else '00000000000000'}
                 )
        print(conn.result)

    # If clients wants to remove an entry
    elif operation == '3' or operation == 'r':
        to_delete = input("Which user would you like to remove: > ")
        sure = input("Are you sure you want to delete " +to_delete+"? y/n : ")
        y_or_n = False
        # Just a little security to be sure what to delete
        while not y_or_n:
            if (sure == 'y' or sure == 'n'):
                y_or_n = True
            else:
                sure = input("type y or n : > ")
        if sure == 'n':
            pass
        else:
            conn.delete('cn='+to_delete+', ou=students, dc=security, dc=ch')
            print(conn.result)

    # If client wants to modify an entry
    elif operation == '4' or operation == 'm':
        to_modify, attr_to_modify, val_to_modify = [], [], []
        str = 'y'
        to_modify.append(input("Which user would you like to modify? > "))
        print("We will get the attributes and values you want to modify, once you are done, type \'n\'.")

        while str != 'n':
            attr_to_modify.append(input("Attribute to modify: > "))
            val_to_modify.append(input("Value to modify: > "))
            str = input("Continue? y/n > ")

        for i in range(len(attr_to_modify)):
            conn.modify('cn='+to_modify[0]+", ou=students, dc=security, dc=ch",
                    {attr_to_modify[i]: [(MODIFY_REPLACE, [val_to_modify[i]])]})
        print(conn.result)

    # If client wants to display a user
    elif operation == '5' or operation == 'du':
        which_user = input("Which user would you like to display? > ")
        if not conn.search('cn = '+which_user+', ou = students, dc = security, dc=ch', '(objectclass=person)'):
            print('User not found')
        else:
            conn.search('ou=students, dc=security, dc=ch', '(&(objectclass=person)(cn = '+which_user+'))',
                        attributes = ['cn', 'sn', 'description', 'userPassword', 'telephoneNumber'])
            entry = conn.entries[0]
            print(entry)

    # Else client wants to exit
    else:
        cont = False
        print('Exiting...\n')
        # closing connection
        conn.unbind()
