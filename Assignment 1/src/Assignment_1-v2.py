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
*** Changes from last version:
***   - Different way to index files: instead of creating a .txt file, I create a dictionnary on
***     the fly while walking through directories and store it in a json file.
***   - For this reason, I assume the file containing the exceptions will also be a json file in
***     a well defined format (eg. {"/tmp/file.txt" : "1", "/bin/local": "1"}. The one is just here to signify
***     that this folder/file must be ignored).
***   - Almost the same way to analyze the files: I creat a dictionnary from the json file, and then walk
***     through the directories and compare the folders/files.
***
*** Using json instead of a home made txt file format increases readability, deacreases the lenght and complexity
*** of the code (no need of the create_dictionary function and regex to parse the file) and is certainly more efficient.
***
*** One assumption about the files' and folders' name: they do not contain line breaks. Nobody does that anyway.
'''

import os
import hashlib
import sys
import json

path = str(sys.argv[2])  # Path for the tests
mode = str(sys.argv[1])  # Two possible modes: indexing and analysis
path_indexing_file = '/tmp/indexing_file.json'
path_exceptions_file = '/tmp/exceptions_file.json'


# Creation of a dictionary for the exceptions.
with open(path_exceptions_file, 'r') as infile:
    exceptions_dict = json.load(infile)

'''
*** function: hash_file
*** input: path of the file to be hashed
*** output: hash of the file
*** description: reads the file in bytes mode. Hash algorithm used is sha-256. No particular reason for this choice.
***              As the file may be too big, we split it in multiple chunks, hash each of those chunks and
***              update the hasher, and finally we return the hash of all these updates.
'''

def hash_file(file_path):
    hasher = hashlib.sha256()
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

'''
*** function:       get_directory_hash
*** input:          path of the directory to hash
*** output:         hash of the directory
*** description:    hashes all the files of the directory using the hash_file function.
***                 if there are subfolders, hash each file of the subfolders, update the hasher with each of
***                 of those hashes and return the hash of the updates.
'''

def get_directory_hash(dir_path):
    hasher = hashlib.sha256()
    for dirpath, dirnames, filenames in os.walk(dir_path):
        if exceptions_dict.__contains__(dirpath):
            print("Permission to access " + dirpath + " denied.")
        else:
            for file in filenames:
                file_path = os.path.join(dirpath, file)
                if exceptions_dict.__contains__(file_path):
                    print("Permission to access " + file_path + " denied.")
                else:
                    hasher.update(hash_file(file_path).encode('utf-8'))
    return hasher.hexdigest()


'''
*** function:       index_files
*** input:          path of the directory to index
*** output:         void
*** description:    Create a json file of all the files and folders in the directory. The json file is a map
***                 between the path of the folder/file and the hash of the folder/file.
***                 I create a dictionary to create the map. For each folder/file in the directory, I store
***                 the path of the folder/file as the dictionary's key, and the hash of the folder/file as the
***                 key's value (if the path is not in the exceptions).
***                 Finally I store the dictionary in a json file.
'''


def index_files(start_path):
    dictionary = {}

    for dirpath, dirnames, filenames in os.walk(start_path):
        if exceptions_dict.__contains__(start_path):
            print("Permission to access " + start_path + " denied.")
            break
        elif exceptions_dict.__contains__(dirpath):
            print("Permission to access " + dirpath + " denied.")
        else:
            dictionary[dirpath] = get_directory_hash(dirpath)
            for files in filenames:
                file_path = os.path.join(dirpath, files)
                if exceptions_dict.__contains__(file_path):
                    print("Permission to access " + file_path + " denied.")
                else:
                    dictionary[file_path] = hash_file(file_path)

    with open(path_indexing_file, 'w') as outfile:
        json.dump(dictionary, outfile)

'''
*** function:       print_list
*** input:          list to print
*** output:         void
*** description:    Prints all the elements of the list.
'''

def print_list(l):
    for element in l:
        print("\t", element, "\n")


'''
*** function:       analyse_files
*** input:          path of the directory to index
*** output:         void
*** description:    Analyzes the files/folders that have been added/modified/removed since the last indexation
***                 I create a dictionary from the json indexing file previously created.
***                 Then I walk in the directory, and do the following checks:
***                 if the file/folder's path is in the dictionary and has the same hash, it means that it did
***                     not change since the indexation and I remove it from the dictionary.
***                 if the file/folder's path is in the dictionary but does not have the same hash, it means it
***                     changed since last indexation. I add the path to changed list and remove it from the dictionary.
***                 Otherwise the file/folder's path is not in the dictionary, and that means that it was added since
***                     last indexation, so I add the path to the added list.
***                 Then I check my dictionary. All the element that are still in it have not been seen while walking
***                     in the directory, it means they have been removed. So I add the path to the removed list.
***                 Finally, I print the added/removed/modified files.
'''


def analyse_files(start_path):
    with open(path_indexing_file, 'r') as infile:
        indexing_dict = json.load(infile)
    changed = []
    removed = []
    added = []

    # Faire la mm chose aussi avec les filenames
    # Sinon il considere que les fichiers ont ete supprimes.
    if exceptions_dict.__contains__(start_path):
        print("Permission to access " + start_path + " denied.")
    else:
        for dirpath, dirnames, filenames in os.walk(start_path):
            if exceptions_dict.__contains__(dirpath):
                print("Permission to access " + dirpath + " denied.")
            else:
                if indexing_dict.__contains__(dirpath) and indexing_dict[dirpath] == get_directory_hash(dirpath):
                    indexing_dict.__delitem__(dirpath)  # unchanged file/directory
                elif indexing_dict.__contains__(dirpath) and indexing_dict[dirpath] != get_directory_hash(dirpath):
                    changed.append(dirpath)  # hash changed => file/directory changed
                    indexing_dict.__delitem__(dirpath)
                else:
                    added.append(dirpath)  # path is not in dictionnary => wasn't here before => was added

                for files in filenames:
                    file_path = os.path.join(dirpath, files)
                    if exceptions_dict.__contains__(file_path):
                        print("Permission to access " + file_path + " denied.")
                    else:
                        if indexing_dict.__contains__(file_path) and indexing_dict[file_path] == hash_file(file_path):
                            indexing_dict.__delitem__(file_path)  # unchanged file/directory
                        elif indexing_dict.__contains__(file_path) and indexing_dict[file_path] != hash_file(file_path):
                            changed.append(file_path)  # hash changed => file/directory changed
                            indexing_dict.__delitem__(file_path)
                        else:
                            added.append(file_path)  # path is not in dictionnary => wasn't here before => was added
        for key in indexing_dict:
            removed.append(key)

        print("Elements that have changed:")
        print_list(changed)
        print("Elements that have been removed:")
        print_list(removed)
        print("Elements that were added: ")
        print_list(added)

'''
*** function:       main
*** input:          none
*** output:         void
*** description:    checks if the program has to do an indexation or an analysis of a directory.
***                 calls the corresponding function.
'''

def main():
    print("Path to test: ", path)
    if mode == "-i":
        print("Mode of execution: ", "Indexing" if mode == "-i" else "Analysis")
        index_files(path)
    elif mode == "-a":
        print("Mode of execution: ", "Indexing" if mode == "-i" else "Analysis")
        analyse_files(path)
    else:
        print(
            "\nExpected -i for indexing or -a for analysing. Please retry launching the script with one of these arguments.\n")


main()
