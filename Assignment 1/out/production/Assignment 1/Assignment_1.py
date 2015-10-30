"""
*** Author: Laurent Hayez
*** Date: 30 september 2015
*** Course: Security
*** Objective:  create a program that monitors the integrity of files/folders using checksums HMAC (or
***             MD5, CRC32,...)
***             There will be two modes of operation: indexing and analysis.
***             Indexing: creates a signature for every file, skipping exceptions.
***             Analysis: shows which files have changed (modified, deleted, newly created).
"""

'''
*** Now the shit works well, but still some bugs
***   - directories 1 and 1.1. keep being categorized as "changed"
***   - can't hash big files. Need to split the file into smaller chunks to hash it.
***   - maybe add a hash_file function that does it
***   - add some try: exception: for reasons....
***   - add some comments about the code.
***   - when hashing the files for the directories, already store them so
***     that this is not done twice (would be stupid!)
'''

import os
import hashlib
import re
import sys

path = str(sys.argv[2])  # Path for the tests
print("Path to test: ", path)
# path = '/tmp/Test'
mode = str(sys.argv[1])  # Two possible modes: indexing and analysis
print("Mode of execution: ", "indexing" if str(sys.argv[1]) == '-i' else "analysis")
# mode = '-i'
# Path for mac
path_indexing_file = '/Users/laurent/Dropbox/Laurent/Master/Security/Assignments/indexing_file.txt'
# Path for linux
# path_indexing_file = '/home/laurent/Dropbox/Laurent/Master/Security/Assignments/indexing_file.txt'

hasher = hashlib.sha256()


def hash_file(file_path):
    # try to open the file to be hashed. If the file can't be open, close it and continue execution.
    file = open(file_path, 'rb')

    # This part of code was found on http://en.sharejs.com/python/12206.
    # Big files could not be hashed, so they had to be split in parts and hashed separately.
    while 1:
        # Read file in as little chunks
        buf = file.read(4096)
        if not buf:
            break
        hasher.update(hashlib.sha256(buf).digest())

    file.close()

    return hasher.hexdigest()


def get_directory_hash(dir_path):
    for dirpath, dirnames, filenames in os.walk(dir_path):
        if dirpath != dir_path:
            for file in filenames:
                file_path = os.path.join(dirpath, file)
                hasher.update(hash_file(file_path).encode('utf-8'))
    return hasher.hexdigest()


'''
*** Function for indexing files.
*** Description: this function opens the indexing_file.txt in read-write mode,
***              and we start from the root of the directory we want to scan and watch
***              all the files. Everytime we encounter a new file/folder we hash it into the
***              indexing_file.txt with the sha-256 algorithm.
'''


def index_files(start_path):
    try:
        file = open(path_indexing_file, 'w', encoding='utf-8')
    except:
        file.close()
        print("could not open file.")
    for dirpath, dirnames, filenames in os.walk(start_path):
        print("I am in "+dirpath+" and these are my directories: "+str(dirnames))
        file.write(dirpath + " : " + get_directory_hash(dirpath) + "\n")
        for files in filenames:
            file_path = os.path.join(dirpath, files)
            #print("Hashing "+file_path)
            #file.write(file_path + " : " + hash_file(file_path) + "\n")
    file.close()


'''
*** 1. Parser le fichier texte
*** 2. Creer deuxieme dictionnaire pour analyse
*** 3. Comparer les deux dictionnaire
'''


def create_dictionnary(indexing_file):
    dictionnary = {}
    if os.path.exists(indexing_file):
        file = open(indexing_file, 'r', encoding='utf-8')
        for line in file.readlines():
            print(line)
            pattern = re.compile(
                '(?P<key>(/(\.?)(\w|\[|\[|\(|\)|,|-)+)+(\.(\w|\[|\[|\(|\)|,|-)+)*)(/?)\s:\s(?P<hash>\w+)')
            matched = pattern.search(line)
            dictionnary.update({matched.group('key'): matched.group('hash')})
    else:
        print("You did not index the files yet. Indexing them now...\n")
        index_files(path)
        create_dictionnary(path_indexing_file)
    return dictionnary


def print_list(l):
    for element in l:
        print("\t", element, "\n")


'''
*** Function for analysing files
'''


def analyse_files(start_path):
    dictionnary = create_dictionnary(path_indexing_file)
    changed = []
    removed = []
    added = []

    # Faire la mm chose aussi avec les filenames
    # Sinon il considere que les fichiers ont ete supprimes.
    for dirpath, dirnames, filenames in os.walk(start_path):
        if dictionnary.__contains__(dirpath) and dictionnary[dirpath] == get_directory_hash(dirpath):
            dictionnary.__delitem__(dirpath)  # unchanged file/directory
        elif dictionnary.__contains__(dirpath) and dictionnary[dirpath] != get_directory_hash(dirpath):
            changed.append(dirpath)  # hash changed => file/directory changed
            dictionnary.__delitem__(dirpath)
        else:
            added.append(dirpath)  # path is not in dictionnary => wasn't here before => was added

        for files in filenames:
            file_path = os.path.join(dirpath, files)
            if dictionnary.__contains__(file_path) and dictionnary[file_path] == hash_file(file_path):
                dictionnary.__delitem__(file_path)  # unchanged file/directory
            elif dictionnary.__contains__(file_path) and dictionnary[file_path] != hash_file(file_path):
                changed.append(file_path)  # hash changed => file/directory changed
                dictionnary.__delitem__(file_path)
            else:
                added.append(file_path)  # path is not in dictionnary => wasn't here before => was added
    for key in dictionnary:
        removed.append(key)

    print("Elements that have changed:")
    print_list(changed)
    print("Elements that have been removed:")
    print_list(removed)
    print("Elements that were added: ")
    print_list(added)


def main():
    while mode != "-i" or mode != "-a":
        if mode == "-i":
            index_files(path)
            # create_dictionnary(path_indexing_file)
        elif mode == "-a":
            analyse_files(path)
        else:
            print("Expected -i for indexing or -a for analysing. Please retry launching the script.\n")


main()
