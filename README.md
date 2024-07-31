# Mongone

## Overview
Mongone is a comprehensive Python-based tool designed for security professionals to facilitate various MongoDB operations, including database enumeration, data exfiltration, data restoration, and bcrypt password brute-forcing. This tool leverages multiple libraries to ensure efficiency and effectiveness.

## Features
- **Port Scanning with NMAP**: Ensures MongoDB port availability and security.
- **Database Enumeration**: Identifies and lists all databases and collections, helping to identify potential security issues.
- **Data Exfiltration**: Securely dumps and removes databases, inserting a ransom message.
- **Data Restoration**: Restores databases from backups.
- **Bcrypt Password Brute-Forcing**: Tests the strength of bcrypt hashed passwords using the rockyou.txt wordlist.

## Why Use This Tool?
- **Security Assessment**: Identify potential vulnerabilities in MongoDB deployments.
- **Database Management**: Perform essential database operations with ease.
- **Ethical Hacking**: Assist in penetration testing and ethical hacking activities.
- **Password Security**: Test the strength of bcrypt hashed passwords.

## Key Configuration Variables
- `PORT`: Default MongoDB port. (Value: `27017`)
- `BACKUP_DIR`: Directory for storing database backups. (Value: `/home/dax21/Desktop/backup`)
- `WORD_LIST`: Path to the wordlist file for brute-forcing passwords. (Value: `rockyou.txt`)

## Setup Requirements
1. **Python and Required Libraries**:
   - Ensure Python is installed on your system.
   - Install required libraries using pip:
     ```sh
     pip install bcrypt pymongo nmap
     ```
2. **rockyou.txt Wordlist**:
   - Download the `rockyou.txt` wordlist.
   - Place it in the specified path for the tool to access:
     ```sh
     /path/to/rockyou.txt
     ```

## Operational Workflow
1. **Port Scanning**: Verifies if the MongoDB port is open using nmap.
2. **User Menu Interactions**: Presents options to the user for different database operations.
3. **Database Operations**:
   - Enumerate all databases.
   - Exfiltrate database.
   - Restore database.
   - Enumerate databases based on user choice.
4. **Password Brute-Forcing**: Detects bcrypt hashed passwords and attempts to crack them with user permission.

## Running the Script
Command to execute:
```sh
python script.py <target_ip>
