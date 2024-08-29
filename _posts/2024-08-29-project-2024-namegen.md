---
title: Generate List of Possible Usernames with given names

categories: [Pentest, Username, Bruteforce, CTF, Password Spraying]

tags: [Pentest, Guessing, Username, Network, Bruteforce, Spray]
---
Quick dirty bash script that generate list of possible usernames based on given full name 

## Example of accepted full name : 
- John Jammond
- John.Jammond

```bash
#!/bin/bash

# Check for help flag or incorrect number of arguments
if [[ $1 == "-h" || $# != 2 ]]; then
    echo "Usage: namegen names-file output-file"
    exit 1
fi

# Check if output file already exists
if [ -f $2 ]; then
    echo "[!] $2 file already exists."
    exit 1
fi

# Read each line in the input file
cat $1 | while read line; do
    # Auto-format if input is in firstname.lastname format
    if [[ $line == *.* ]]; then
        line=$(echo $line | sed 's/\./ /g')
    fi
    
    firstname=$(echo $line | cut -d ' ' -f1 | tr '[:upper:]' '[:lower:]')
    lastname=$(echo $line | cut -d ' ' -f2 | tr '[:upper:]' '[:lower:]')

    echo "$firstname
$lastname
$firstname.$lastname
$(echo $firstname | cut -c1).$lastname
$(echo $firstname | cut -c1)-$lastname
$firstname$lastname
$firstname-$lastname
$(echo $firstname | cut -c1-3)$(echo $lastname | cut -c1-3)
$(echo $firstname | cut -c1-3).$(echo $lastname | cut -c1-3)
$(echo $firstname | cut -c1)$lastname
$lastname$firstname
$lastname-$firstname
$lastname.$firstname
$lastname$(echo $firstname | cut -c1)
$lastname-$(echo $firstname | cut -c1)
$lastname.$(echo $firstname | cut -c1)" >> $2
done

echo "[+] Wordlist generated and saved to $2"

```
- All name will be convert to lowercase

Example Usage :

test-users
```
John.Ham
john doe
```

running the script
```bash
namegen test-users test-result
```

test-result
```
john
ham
john.ham
j.ham
j-ham
johnham
john-ham
johham
joh.ham
jham
hamjohn
ham-john
ham.john
hamj
ham-j
ham.j
john
doe
john.doe
j.doe
j-doe
johndoe
john-doe
johdoe
joh.doe
jdoe
doejohn
doe-john
doe.john
doej
doe-j
doe.j
```

# Linking to the tool
```bash
sudo ln -s /path/to/tool/namegen.sh /usr/local/bin/namegen
```
