# TTLDAP: TopTranslation LDAP script

## What is this?

TTLDAP is a Python script, which simplifies our LDAP user management
at Toptranslation. Our LDAP server resides in a Docker container, and
it doesn't expose itself to the outside world. So instead of manually
playing with LDAP every time we need a change, I wrote this script, in
hope to make our user management easier.

## Dependencies

First of all, clone this repository on your computer:
```
git clone https://github.com/tequir00t/ttldap && cd ttldap
```
This script is written in python3, so you'll need to have it installed:
```
sudo apt-get install python3
```
The easiest way to install the necessarily requirements, is with PIP:
```
sudo apt-get install python3-pip
```
Now, install the dependencies:
```
sudo pip3 install -r requirements.txt
```

## Configuration

Configurations are stored in a *.ini file in the same directory with
the script. Rename [ttldap.ini-example](ttldap.ini-example) to ttldap.ini, and edit it to
suit your own needs. You can also add more sections to the file, so
you can manage multiple LDAP servers, or using multiple users.

The environment is specified using the -E command line option. The
[DEFAULT] section is used if -E is not used.

## Usage

There are 5 modes of operation, **print**, **forward**, **create**,
**delete** and **modify**.

### Print

Use -b for bots, -p for people, and -c for clients. To search for a
user matching john.smith, use the following command:

```
python ttldap.py print -p john.smith
```
Replace -p with -b or -c, if you search for bots or clients.

The script will also check for partially matching names, so in this
case, just writing john or smith should be enough:
```
python ttldap.py print -p smith
```

### Forward

Forward doesn't have any new options, and is used just for SSH
forwarding the LDAP connection to localhost, and could be used to
manually manage users, using other tools on the system, like Apache
Directory Studio.

### Create

Use -b for bots, -p for people, and -c for clients. To create a user
john.smith, use the following command:

```
python ttldap.py create -p john.smith --mail john.smith@toptranslation.com --mail js@toptranslation.com --password 'ASReub076!$)' --description "This is John Smith" --mobile "+1234567890" --mobile "+498765432109" --telephone 44 --telephone 47 --department management --title "windows cleaner"
```

Replace -p with -b or -c, if you want to create a bot or a client.
Just the UID is mandatory, all of the other information could be
skipped. If the password is skipped, "please_change!" is used. Do it
just if the user will change it immediately, otherwise specify a
random password.

### Delete

Use -b for bots, -p for people, and -c for clients. To delete a user,
just the UID is required:

```
python ttldap.py delete -p john.smith
```

### Modify

Use -b for bots, -p for people, and -c for clients. It's syntax is
exactly the same as for create. The only thing important to remember,
is that the attributes which could contain multiple fields (for
example mail, mobile, telephoneNumber), will be first deleted, then
the new ones will be added, so if you want to add a new email to that
person, and want to keep the old email intact, you need to add --mail
twice, once with the old email, and once with the new one.

```
python ttldap.py modify -p john.smith --mail js@toptranslation.com --password 'sntauohe+r,{]' --description "This is not John Smith" --mobile "+1234567890" --mobile "+498765432109" --telephone 44 --telephone 47 --department sales --title "Windows Seller"
```

## Bugs

After I started reading the configuration from the ttldap.ini file,
the --help menu doesn't work anymore. I'll get to fix that ASAP.

## License

All of the code contained here is licensed by the [GNU GPLv3](LICENSE)
