#!/usr/bin/env python3
#
# Copyright (C) 2016 Neagaru Daniel
# <daniel.neagaru@toptranslation.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see
# <http://www.gnu.org/licenses/>.
#
"""Manage users on our LDAP Server.

This script can be used to create, delete, modify, or just print
internal users, bots, or clients. At the moment, we use clients just for
the FTP server. Bots are like normal users, but which aren't used by any
person.

It will connect to our LDAP which resides in a docker container on our
server, by forwarding port 389 from the server, to port 3890 on your
localhost. A valid SSH account is required for this to work. As our
server doesn't expose its port 389 to the external world, that's the
easiest way to manage LDAP in our environment.

The SSH Forwarding code was heavily inspired by paramiko's demo at
https://github.com/paramiko/paramiko/blob/master/demos/forward.py
"""

import os
import argparse
import sys
import getpass
import select
import re
import multiprocessing
import time
import paramiko
import ldap3
from passlib.hash import ldap_salted_sha1 as ssha

try:
    import SocketServer
except ImportError:
    import socketserver as SocketServer

try:
    import ConfigParser as configparser
except ImportError:
    import configparser

__author__ = "Daniel Neagaru, daniel.neagaru@toptranslation.com"
__copyright__ = "Copyright 2016, Toptranslation GmbH"
__credits__ = "Daniel Neagaru"
__license__ = "GPLv3 or later"
__version__ = "0.0.1"
__maintainer__ = "Daniel Neagaru"
__email__ = "daniel.neagaru@toptranslation.com"
__status__ = "Prototype"


def _load_configuration():
    """Load configuration from a file.

    Load configuration from a .ini file, to avoid private information
    being used inside the script.
    """
    # Initiate the config parser.
    config = configparser.RawConfigParser()

    # Get the .ini file path.
    inipath = os.path.join(os.getcwd(), "hermes.ini")

    # Raise exception if couldn't find the file.
    if not config.read(inipath):
        raise Exception("[ERROR] Could not find hermes.ini.")

    return config


class ForwardServer(SocketServer.ThreadingTCPServer):
    """Handle forwarded ports.

    Used in the SSH Forwarding code, and acts as a server, which handles
    the port forwarding.
    """

    daemon_threads = True

    allow_reuse_address = True


class Handler(SocketServer.BaseRequestHandler):
    """Handle the data from the SSH tunnel."""

    def handle(self):
        """Send and receive data from the SSH tunnel."""
        # Try to connect to the SSH Server.
        try:
            chan = self.ssh_transport.open_channel(
                "direct-tcpip",
                (self.chain_host, self.chain_port),
                self.request.getpeername())

        # Server didn't respond.
        except Exception as e:
            print("[ERROR] Incoming request to %s:%d failed: %s" %
                  (self.chain_host, self.chain_port, repr(e)))

            return

        # Server rejected our request.
        if chan is None:
            print("[ERROR] Incoming request to %s:%d was rejected by \
                  the SSH server." % (self.chain_host, self.chain_port))

            return

        # Connection succeeded.
        print("[INFO] Connected! Tunnel open %r -> %r -> %r" %
              (self.request.getpeername(),
               chan.getpeername(),
               (self.chain_host, self.chain_port)))

        # Send and receive the data, until manually interrupted.
        while True:
            r, w, x = select.select([self.request, chan], [], [])

            if self.request in r:
                data = self.request.recv(1024)

                if len(data) == 0:
                    break

                chan.send(data)

            if chan in r:
                data = chan.recv(1024)

                if len(data) == 0:
                    break

                self.request.send(data)

        peername = self.request.getpeername()

        chan.close()

        self.request.close()

        print("[INFO] Tunnel closed from %r" % (peername,))


def forward_tunnel(local_port, remote_host, remote_port, transport):
    """Create a tunnel over SSH.

    Create a tunnel between the remote port on the server and the local
    port on the computer running this script.
    """
    class SubHander(Handler):
        chain_host = remote_host

        chain_port = remote_port

        ssh_transport = transport

    ForwardServer(("", local_port), SubHander).serve_forever()


def verbose(options):
    """Print the output just if -v or --verbose option was set."""
    return print if options.verbose else lambda *a, **k: None


def parse_options(CONFIG):
    """Parse the command line options.

    Parse the command line arguments supplied to this script. It uses
    the argparse python library, and implements 5 different subparsers,
    for subcommands "print", "forward", "create", "delete" and
    "modify".
    """
    # Creating the main parser.
    parser = argparse.ArgumentParser()

    ##################################################################
    #                            GLOBAL                              #
    ##################################################################
    # Add the required parameter username, which will be used to bind
    # to the LDAP server.
    parser.add_argument("-E", "--environment",
                        help="Choose your environment (from hermes.ini)",
                        default="DEFAULT")

    args, remaining_args = parser.parse_known_args()

    defaults = dict(CONFIG.items(args.environment))

    parser.set_defaults(**defaults)

    parser.add_argument("-U", "--username",
                        help="LDAP Bind username")

    # Add the optional server address.
    parser.add_argument("-S", "--server",
                        help="LDAP Server IP or name")

    # Add the optional LDAP SSL.
    parser.add_argument("--ssl",
                        help="Enable SSL",
                        action="store_true",
                        default=CONFIG.getboolean(args.environment,
                                                  "ssl"))

    # Add the optional LDAP port number.
    parser.add_argument("-P", "--port",
                        help="LDAP port number",
                        type=int)

    # Add the optional port number to bind to localhost.
    parser.add_argument("-L", "--localport",
                        help="Localhost port number used for binding",
                        type=int)

    # Add the optional LDAP base.
    parser.add_argument("-B", "--base",
                        help="LDAP Base")

    # Add the optional people DN.
    parser.add_argument("--peopledn",
                        help="LDAP People DN")

    # Add the optional former workers DN.
    parser.add_argument("--formerdn",
                        help="LDAP Former Workers DN")

    # Add the optional bots DN.
    parser.add_argument("--botsdn",
                        help="LDAP Bots DN")

    # Add the optional clients DN.
    parser.add_argument("--clientsdn",
                        help="LDAP Clients DN")

    # Add the optional groups DN.
    parser.add_argument("--groupsdn",
                        help="LDAP Groups DN")

    # Add the optional SSH port number.
    parser.add_argument("-H", "--sshport",
                        help="SSH Port number",
                        type=int)

    # Add the optional verbose flag.
    parser.add_argument("-v", "--verbose",
                        help="Show verbose output",
                        action="store_true")

    # Adding subparser, with their name stored inside COMMAND
    # variable.
    subparsers = parser.add_subparsers(help="Use hermes COMMAND --help \
                                       to see the options available to \
                                       that command.",
                                       dest="COMMAND")

    subparsers.required = True

    ##################################################################
    #                             PRINT                              #
    ##################################################################
    # The print subparser, used to display the users matching the
    # user supplied name. Use -p for people, -b for bots or -c for
    # clients.
    parser_print = subparsers.add_parser("print",
                                         help="Print users matching UID")

    # Add a required positioned argument UID.
    parser_print.add_argument("UID",
                              help="LDAP user. Use \"ALL\" to match \
                              all users")

    # Add a group of mutually exclusive arguments: people, bots, or
    # clients. Exactly one of them should be used at a time.
    group_print = parser_print.add_mutually_exclusive_group(required=True)

    group_print.add_argument("-p", "--people",
                             help="People (Our dear coworkers)",
                             action="store_true")

    group_print.add_argument("-b", "--bots",
                             help="Bots",
                             action="store_true")

    group_print.add_argument("-c", "--clients",
                             help="Clients (At the moment just for FTP)",
                             action="store_true")

    ##################################################################
    #                            FORWARD                             #
    ##################################################################
    # The forward subparser, used just to forward the connection. No
    # other options available.
    subparsers.add_parser("forward",
                          help="Just forward port, use with Apache \
                          Directory Studio, or other LDAP tools.")

    ##################################################################
    #                            CREATE                              #
    ##################################################################
    # The create subparser, used to create a new account with the
    # supplied UID. Use -p for people, -b for bots or -c for clients.
    parser_create = subparsers.add_parser("create",
                                          help="Create a new user with \
                                          uid=UID")

    # Add a required positioned argument UID.
    parser_create.add_argument("UID", help="LDAP user.")

    # Add an optional argument for the password.
    parser_create.add_argument("--password",
                               help="Set up user's password. By \
                               default, it's \"please_change!\"")

    # Add an optional argument for the email.
    parser_create.add_argument("-m", "--mail",
                               help="Add another email in addition to \
                               UID@toptranslation.com. Use multiple \
                               times to add multiple emails",
                               action="append")

    # Add an optional argument for the description.
    parser_create.add_argument("-d", "--description",
                               help="Add a short description to the \
                               account")

    # Add an optional argument for the mobile phone.
    parser_create.add_argument("-M", "--mobile",
                               help="Add a mobile phone. Use multiple \
                               times to add multiple numbers",
                               action="append")

    # Add an optional argument for the work phone.
    parser_create.add_argument("-t", "--telephone",
                               help="Add a telephone phone. Use \
                               multiple times to add multiple numbers",
                               action="append")

    # Add an optional argument for the department.
    parser_create.add_argument("-D", "--department",
                               help="Coworker's department")

    # Add an optional argument for the title.
    parser_create.add_argument("-T", "--title",
                               help="Coworker's title")

    # Add a group of mutually exclusive arguments: people, bots, or
    # clients. Exactly one of them should be used at a time.
    group_create = parser_create.add_mutually_exclusive_group(required=True)

    group_create.add_argument("-p", "--people",
                              help="People (Our dear coworkers)",
                              action="store_true")

    group_create.add_argument("-b", "--bots",
                              help="Bots",
                              action="store_true")

    group_create.add_argument("-c", "--clients",
                              help="Clients (At the moment just for \
                              FTP)",
                              action="store_true")

    ##################################################################
    #                            DELETE                              #
    ##################################################################
    # The delete subparser, used to delete an existing account,
    # matching the supplied UID. Use -p for people, -b for bots or -c
    # for clients.
    parser_delete = subparsers.add_parser("delete",
                                          help="Delete user UID")

    # Add the required positioned argument UID.
    parser_delete.add_argument("UID",
                               help="LDAP user.")

    # Add a group of mutually exclusive arguments: people, bots, or
    # clients. Exactly one of them should be used at a time.
    group_delete = parser_delete.add_mutually_exclusive_group(required=True)

    group_delete.add_argument("-p", "--people",
                              help="People (Our dear coworkers)",
                              action="store_true")

    group_delete.add_argument("-b", "--bots",
                              help="Bots",
                              action="store_true")

    group_delete.add_argument("-c", "--clients",
                              help="Clients (At the moment just for \
                              FTP)",
                              action="store_true")

    ##################################################################
    #                            MODIFY                              #
    ##################################################################
    # The modify subparser, used to modify an existing account,
    # matching the supplied UID. Use -p for people, -b for bots or -c
    # for clients.
    parser_modify = subparsers.add_parser("modify",
                                          help="Modify user matching \
                                          UID. The old parameters will \
                                          be deleted automatically.")

    parser_modify.add_argument("UID",
                               help="LDAP user.")

    # Add an optional argument for the password.
    parser_modify.add_argument("--password",
                               help="Set up user's password. By \
                               default, it's \"please_change!\"")

    # Add an optional argument for the email.
    parser_modify.add_argument("-m", "--mail",
                               help="Add another email in addition to \
                               UID@toptranslation.com. Use multiple \
                               times to add multiple emails",
                               action="append")

    # Add an optional argument for the description.
    parser_modify.add_argument("-d", "--description",
                               help="Add a short description to the \
                               account")

    # Add an optional argument for the mobile phone.
    parser_modify.add_argument("-M", "--mobile",
                               help="Add a mobile phone. Use multiple \
                               times to add multiple numbers",
                               action="append")

    # Add an optional argument for the work phone.
    parser_modify.add_argument("-t", "--telephone",
                               help="Add a telephone phone. Use \
                               multiple times to add multiple numbers",
                               action="append")

    # Add an optional argument for the department.
    parser_modify.add_argument("-D", "--department",
                               help="Coworker's department")

    # Add an optional argument for the title.
    parser_modify.add_argument("-T", "--title",
                               help="Coworker's title")

    # Add a group of mutually exclusive arguments: people, bots, or
    # clients. Exactly one of them should be used at a time.
    group_modify = parser_modify.add_mutually_exclusive_group(required=True)

    group_modify.add_argument("-p", "--people",
                              help="People (Our dear coworkers)",
                              action="store_true")

    group_modify.add_argument("-b", "--bots",
                              help="Bots",
                              action="store_true")

    group_modify.add_argument("-c", "--clients",
                              help="Clients (At the moment just for FTP)",
                              action="store_true")

    return parser.parse_args()


def daemon(options):
    """Forward the LDAP port over SSH.

    Forward the LDAP remote port over SSH, to the local port and wait
    for the client process to exit, or for the user to close the
    connection with Ctrl-C
    """
    # Create a SSH client.
    client = paramiko.SSHClient()

    # Load SSH keys from the host.
    client.load_system_host_keys()

    # Add the non-existing keys to the known_hosts file.
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    verbose(options)("[INFO] Connecting to SSH...")

    # Connect to the SSH server.
    try:
        client.connect(options.server, options.sshport, username="root")

        verbose(options)("[INFO] Forwarding LDAP Port")

    except Exception as e:
        print("[ERROR] Failed to connect to %s:%d: %r" % (options.server,
                                                          options.sshport, e))

        sys.exit(0)

    # Forward the tunnel.
    try:
        forward_tunnel(options.localport,
                       "127.0.0.1",
                       options.port,
                       client.get_transport())

    except KeyboardInterrupt:
        print("\n[INFO] Port forwarding stopped.")

        sys.exit(0)


def client(options):
    """Call the appropiate LDAP function.

    Call the appropiate LDAP function, according to which COMMAND the
    user selected. Connect to the localhost on the port opened by the
    daemon process, and send the requested LDAP instructions.
    """
    # Creates the user DN from the supplied options.
    user = ",".join(("uid=" + options.username,
                     options.peopledn,
                     options.base))

    # Asks for the user password. Don't echo.
    password = getpass.getpass("Password for the user " + user + ": ")

    # Connects to the LDAP server forwarded to a localhost port.
    try:
        conn = ldap3.Connection(server=ldap3.Server("127.0.0.1",
                                                    port=options.localport,
                                                    use_ssl=options.ssl),
                                auto_bind=True,
                                user=user,
                                password=password)

        if options.COMMAND == "print":
            ldapprint(options, conn)

        elif options.COMMAND == "forward":
            # No function necessarily to forward the connection. Just
            # let the daemon do its job.
            pass

        elif options.COMMAND == "create":
            ldapcreate(options, conn)

        elif options.COMMAND == "delete":
            ldapdelete(options, conn)

        elif options.COMMAND == "modify":
            ldapmodify(options, conn)

    except ldap3.core.exceptions.LDAPBindError:
        print("[ERROR] Sorry, Invalid credentials...")

        sys.exit(0)


def ldapprint(options, conn):
    """Print matching LDAP entries.

    Print the matching LDAP entries, for either people, clients, or
    bots. It works even for partial matches, and it accepts UID as
    ``ALL'', to display all valid users.
    """
    if options.people:
        # Join peopledn with the base.
        search_base = ",".join((options.peopledn, options.base))

        if options.UID == "ALL":
            # This will search for all matching people.
            search_filter = "(objectClass=inetOrgPerson)"
        else:
            # This filter will search for approximate matches in
            # displayName, sn and givenName, or for exact match in
            # uid parameter.
            search_filter = "(&" + \
                             "(objectClass=inetOrgPerson)" + \
                             "(|" + \
                             "(displayName=*" + options.UID + "*)" + \
                             "(sn=*" + options.UID + "*)" + \
                             "(givenName=*" + options.UID + "*)" + \
                             "(uid=" + options.UID + ")))"

        # One level should be enough for us.
        search_scope = "LEVEL"

        # List of attributes to get from the server.
        attributes = ["displayName",
                      "mail",
                      "mobile",
                      "telephoneNumber",
                      "ou",
                      "title",
                      "uid"]

        verbose(options)("[INFO] LDAP Search:" +
                         "\n\tsearch_base = " + search_base +
                         "\n\tsearch_filter = " + search_filter +
                         "\n\tsearch_scope = " + search_scope +
                         "\n\tattributes = " + str(attributes))

        # LDAP Search.
        conn.search(search_base=search_base,
                    search_filter=search_filter,
                    search_scope=search_scope,
                    attributes=attributes)

        verbose(options)("[INFO] " + str(conn.result))

        # Now display all the data we obtained from the server. The
        # lambda function sorts the dictionary alphabetically, based
        # on the uid value. Using every entry from the sorted list,
        # we display the relevant information if it exists. If not,
        # the attribute is skipped.
        for entry in sorted(conn.response,
                            key=lambda entry: entry["attributes"]["uid"]):
            try:
                print("\n" + entry["attributes"]["displayName"][0] + ":")

            except KeyError:
                print(entry["attributes"]["uid"][0] + ":")

            try:
                print("\tuid = " + entry["attributes"]["uid"][0])

            except KeyError:
                pass

            try:
                print("\tTitle = " + entry["attributes"]["title"][0])

            except KeyError:
                pass

            try:
                print("\tDepartment = " + entry["attributes"]["ou"][0])

            except KeyError:
                pass

            try:
                for i in entry["attributes"]["mail"]:
                    print("\tMail = " + i)

            except KeyError:
                pass

            try:
                for i in entry["attributes"]["mobile"]:
                    print("\tMobile = " + i)

            except KeyError:
                pass

            try:
                for i in entry["attributes"]["telephoneNumber"]:
                    print("\tPhone = " + i)

            except KeyError:
                pass

    # Now for the bots.
    elif options.bots:
        # Join bots DN with the base.
        search_base = ",".join((options.botsdn, options.base))

        # Search for all bots.
        if options.UID == "ALL":
            search_filter = "(objectClass=inetOrgPerson)"

        # Search for bots with approximate match for the displayName
        # or an exact match with uid argument.
        else:
            search_filter = "(&" + \
                            "(objectClass=inetOrgPerson)" + \
                            "(|" + \
                            "(displayName=*" + options.UID + "*)" + \
                            "(uid=" + options.UID + ")))"

        # One Level is enough.
        search_scope = "LEVEL"

        # Attributes to get from the server.
        attributes = ["displayName", "description", "uid"]

        verbose(options)("[INFO] LDAP Search:" +
                         "\n\tsearch_base = " + search_base +
                         "\n\tsearch_filter = " + search_filter +
                         "\n\tsearch_scope = " + search_scope +
                         "\n\tattributes = " + str(attributes))

        # LDAP Search.
        conn.search(search_base=search_base,
                    search_filter=search_filter,
                    search_scope=search_scope,
                    attributes=attributes)

        verbose(options)("[INFO] " + str(conn.result))

        # Now display all the data we obtained from the server. The
        # lambda function sorts the dictionary alphabetically, based
        # on the uid value. Using every entry from the sorted list,
        # we display the relevant information if it exists. If not,
        # the attribute is skipped.
        for entry in sorted(conn.response,
                            key=lambda entry: entry["attributes"]["uid"]):

            try:
                print("\n" + entry["attributes"]["displayName"][0] + ":")

            except KeyError:
                print(entry["attributes"]["uid"][0] + ":")

            try:
                print("\tuid = " + entry["attributes"]["uid"][0])

            except KeyError:
                pass

            try:
                print("\tDescription = " +
                      entry["attributes"]["description"][0])

            except KeyError:
                pass

    # Now search for clients.
    elif options.clients:
        # Join the clients DN with the base.
        search_base = ",".join((options.clientsdn, options.base))

        # Search for all Posix Accounts (necessarily for FTP).
        if options.UID == "ALL":
            search_filter = "(objectClass=posixAccount)"

        # Search for clients with approximate match for description
        # and displayName, or an exact match on uid.
        else:
            search_filter = "(&" + \
                            "(objectClass=posixAccount)" + \
                            "(|" + \
                            "(description=*" + options.UID + "*)" + \
                            "(displayName=*" + options.UID + "*)" + \
                            "(uid=" + options.UID + ")))"

        # One level is enough.
        search_scope = "LEVEL"

        # We need just description and uid from the server.
        attributes = ["description", "uid"]

        verbose(options)("[INFO] LDAP Search:" +
                         "\n\tsearch_base = " + search_base +
                         "\n\tsearch_filter = " + search_filter +
                         "\n\tsearch_scope = " + search_scope +
                         "\n\tattributes = " + str(attributes))

        # Perform the search.
        conn.search(search_base=search_base,
                    search_filter=search_filter,
                    search_scope=search_scope,
                    attributes=attributes)

        verbose(options)("[INFO] " + str(conn.result))

        # Display the sorted entries.
        for entry in sorted(conn.response,
                            key=lambda entry: entry["attributes"]["uid"]):

            print("\n" + entry["attributes"]["uid"][0]+":")

            try:
                print("\tDescription = " +
                      entry["attributes"]["description"][0])

            except KeyError:
                pass


def ldapcreate(options, conn):
    """Create new LDAP entries.

    Create new LDAP entries, for people, bots, or clients. By default
    not much information is written. To add phone numbers, emails,
    etc. use the appropiate command line arguments.
    """
    if options.people:
        # Check if a person with this name already exists.
        if conn.search(search_base=",".join((options.peopledn, options.base)),
                       search_filter="(&" +
                       "(objectClass=inetOrgPerson)" +
                       "(uid=" + options.UID + "))"):

            print("[WARN] User " + options.UID +
                  " already exists. Please use modify instead of create")

            sys.exit(0)

        # Proceeds just if the username has the form: firstname.lastname.
        if re.match("[a-z]+.[a-z]+", options.UID):

            # Gets the DN of the person to be created.
            dn = ",".join(("uid=" + options.UID,
                           options.peopledn,
                           options.base))

            object_class = "inetOrgPerson"

            attributes = {}

            attributes["uid"] = options.UID

            # If the user supplied a password, it's used, otherwise
            # "please_change!" is set up as a password.
            if options.password:
                attributes["userPassword"] = ssha.encrypt(options.password)
            else:
                attributes["userPassword"] = ssha.encrypt("please_change!")

            # cn will be "Firstname Lastname".
            attributes["cn"] = " ".join(options.UID.split(".")).title()

            # displayName will be "Firstname Lastname".
            attributes["displayName"] = (" ".join(options.UID.split("."))
                                         .title())

            # sn will be Lastname.
            attributes["sn"] = options.UID.split(".")[1].capitalize()

            # givenName will be Firstname.
            attributes["givenName"] = options.UID.split(".")[0].capitalize()

            # initials will be FL.
            attributes["initials"] = (options.UID.split(".")[0][0] +
                                      options.UID.split(".")[1][0])

            # mail will be firstname.lastname@toptranslation.com.
            attributes["mail"] = [options.UID + "@toptranslation.com"]

            # add information from the command line arguments.
            if options.mail:
                attributes["mail"] += options.mail

            if options.mobile:
                attributes["mobile"] = options.mobile

            if options.department:
                attributes["ou"] = options.department

            if options.telephone:
                attributes["telephoneNumber"] = options.mobile

            if options.title:
                attributes["title"] = options.title

            if options.description:
                attributes["description"] = options.description

            verbose(options)("[INFO] LDAP add:" +
                             "\n\t" + dn +
                             "\n\tobject_class = " + object_class +
                             "\n\tattributes = " + str(attributes))

            # Add the new entry.
            conn.add(dn=dn,
                     object_class=object_class,
                     attributes=attributes)

            verbose(options)("[INFO] " + str(conn.result))

            verbose(options)("[INFO] LDAP modify_add:\n\t" +
                             ",".join(("cn=owncloud",
                                       options.groupsdn,
                                       options.base)) +
                             "\n\tmember: " +
                             ",".join(("uid=" + options.UID,
                                       options.peopledn,
                                       options.base)))

            # Add the user to OwnCloud group.
            conn.modify(",".join(("cn=owncloud",
                                  options.groupsdn,
                                  options.base)),
                        {"member": (ldap3.MODIFY_ADD,
                                    [",".join(("uid=" + options.UID,
                                               options.peopledn,
                                               options.base))])})

            verbose(options)("[INFO] " + str(conn.result))

            verbose(options)("[INFO] LDAP modify_add:\n\t" +
                             ",".join(("cn=redmine",
                                       options.groupsdn,
                                       options.base)) +
                             "\n\tmember: " +
                             ",".join(("uid=" + options.UID,
                                       options.peopledn,
                                       options.base)))

            # Add the user to Redmine group.
            conn.modify(",".join(("cn=redmine",
                                  options.groupsdn,
                                  options.base)),
                        {"member": (ldap3.MODIFY_ADD,
                                    [",".join(("uid=" + options.UID,
                                               options.peopledn,
                                               options.base))])})

            verbose(options)("[INFO] " + str(conn.result))

        else:
            print("[ERROR] Please specify the UID for people as \
                  firstname.surname")

            sys.exit(0)

    # If the option -b was specified.
    if options.bots:
        # If user already exists.
        if conn.search(search_base=",".join((options.botsdn,
                                             options.base)),
                       search_filter="(&" +
                       "(objectClass=inetOrgPerson)" +
                       "(uid=" + options.UID+"))"):

            print("[ERROR] User " + options.UID +
                  " already exists. Please use modify instead of create")

            sys.exit(0)

        # Create the bot UID.
        dn = ",".join(("uid=" + options.UID,
                       options.botsdn,
                       options.base))

        # Our bots use inetOrgPerson class.
        object_class = "inetOrgPerson"

        attributes = {}
        attributes["uid"] = options.UID

        # Set up bot's password. If not given, use "please_change!".
        if options.password:
            attributes["userPassword"] = ssha.encrypt(options.password)

        else:
            attributes["userPassword"] = ssha.encrypt("please_change!")

        attributes["cn"] = options.UID

        attributes["sn"] = options.UID

        attributes["displayName"] = options.UID

        attributes["givenName"] = options.UID

        if options.mail:
            attributes["mail"] = options.mail

        if options.mobile:
            attributes["mobile"] = options.mobile

        if options.department:
            attributes["ou"] = options.department

        if options.telephone:
            attributes["telephoneNumber"] = options.mobile

        if options.title:
            attributes["title"] = options.title

        if options.description:
            attributes["description"] = options.description

        verbose(options)("[INFO] LDAP add:" +
                         "\n\t" + dn +
                         "\n\tobject_class = " + object_class +
                         "\n\tattributes = " + str(attributes))

        # Add the new entry.
        conn.add(dn=dn,
                 object_class=object_class,
                 attributes=attributes)

        verbose(options)("[INFO] " + str(conn.result))

    # Create a client for FTP access.
    if options.clients:
        # If the client already exists:
        if conn.search(search_base=",".join((options.clientsdn,
                                             options.base)),
                       search_filter="(&" +
                       "(objectClass=inetOrgPerson)" +
                       "(uid=" + options.UID + "))"):

            print("[ERROR] User " + options.UID +
                  " already exists. Please use modify instead of create")

            sys.exit(0)

        # Create user's DN
        dn = ",".join(("uid=" + options.UID,
                       options.clientsdn,
                       options.base))

        # We need posixAccount and shadowAccount for FTP access.
        object_class = ["inetOrgPerson",
                        "posixAccount",
                        "shadowAccount",
                        "top"]

        attributes = {}

        attributes["uid"] = options.UID

        # Set user's password. If not specified by the user, the
        # default "please_change!" is set.
        if options.password:
            attributes["userPassword"] = ssha.encrypt(options.password)

        else:
            attributes["userPassword"] = ssha.encrypt("please_change!")

        # Set up the necessarily arguments.
        attributes["cn"] = options.UID

        attributes["sn"] = options.UID

        attributes["displayName"] = options.UID

        attributes["givenName"] = options.UID

        attributes["gidNumber"] = 1000

        attributes["homeDirectory"] = "/srv/ftp/" + options.UID

        attributes["uidNumber"] = 1306

        attributes["loginShell"] = "/bin/bash"

        # Set up the arguments from the command line.
        if options.mail:
            attributes["mail"] = options.mail

        if options.mobile:
            attributes["mobile"] = options.mobile

        if options.department:
            attributes["ou"] = options.department

        if options.telephone:
            attributes["telephoneNumber"] = options.mobile

        if options.title:
            attributes["title"] = options.title

        if options.description:
            attributes["description"] = options.description

        verbose(options)("[INFO] LDAP add:" +
                         "\n\t" + dn +
                         "\n\tobject_class = " + str(object_class) +
                         "\n\tattributes = " + str(attributes))

        # Add the new entry.
        conn.add(dn=dn,
                 object_class=object_class,
                 attributes=attributes)

        verbose(options)("[INFO] " + str(conn.result))

        verbose(options)("[INFO] LDAP modify_add:\n\t" +
                         ",".join(("cn=ftp",
                                   options.groupsdn,
                                   options.base)) +
                         "\n\tmember: " +
                         ",".join(("uid=" + options.UID,
                                   options.clientsdn,
                                   options.base)))

        # Add user to the FTP group.
        conn.modify(",".join(("cn=ftp",
                              options.groupsdn,
                              options.base)),
                    {"member": (ldap3.MODIFY_ADD,
                                [",".join(("uid=" + options.UID,
                                           options.clientsdn,
                                           options.base))])})

        verbose(options)("[INFO] " + str(conn.result))


def ldapdelete(options, conn):
    """Delete existing accounts.

    Delete existing accounts from our LDAP server. If this is a bot or a
    client account, the entry is simply removed from the server,
    together with its groups. If it's a people account, it's moved to
    the former workers subtree, so it can be reenabled if necessarily.
    The user's password is mangled, rendering it useless, the Redmine
    and OwnCloud membership is revoked, and the entry moved to the new
    subtree.
    """
    if options.people:
        # If user doesn't exist, quit the script.
        if not conn.search(search_base=",".join((options.peopledn,
                                                 options.base)),
                           search_filter="(&" +
                           "(objectClass=inetOrgPerson)" +
                           "(uid=" + options.UID + "))"):

            print("[ERROR] User " + options.UID +
                  " doesn't exists. Nothing to delete")

            sys.exit(0)

        # Create the user DN.
        dn = ",".join(("uid=" + options.UID,
                       options.peopledn,
                       options.base))

        # This will be the entry's new subtree.
        newdn = ",".join((options.formerdn,
                          options.base))

        verbose(options)("[INFO] Rendering the password useless.")

        verbose(options)("[INFO] LDAP modify_replace:\n\t" + dn +
                         "\n\treplace: userPassword")

        # Set password to salted hash of a salted hash of this string.
        # This should make the password useless.
        conn.modify(dn,
                    {"userPassword": (ldap3.MODIFY_REPLACE,
                                      [ssha.encrypt(
                                          ssha.encrypt(
                                              "randomuselesssaltedpassword"))])})

        verbose(options)("[INFO] " + str(conn.result))

        verbose(options)("[INFO] LDAP modify_delete:\n\t" +
                         ",".join(("cn=owncloud",
                                   options.groupsdn,
                                   options.base)) +
                         "\n\tmember: " + ",".join(("uid=" + options.UID,
                                                    options.peopledn,
                                                    options.base)))

        # Delete user from the OwnCloud group.
        conn.modify(",".join(("cn=owncloud",
                              options.groupsdn,
                              options.base)),
                    {"member": (ldap3.MODIFY_DELETE,
                                [",".join(("uid=" + options.UID,
                                           options.peopledn,
                                           options.base))])})

        # If user wasn't in the group.
        if conn.result["description"] == "noSuchAttribute":
            print("[WARN] User " + options.UID +
                  " is not a member of the OwnCloud group.")

        verbose(options)("[INFO] " + str(conn.result))

        verbose(options)("[INFO] LDAP modify_delete:\n\t" +
                         ",".join(("cn=redmine",
                                   options.groupsdn,
                                   options.base)) +
                         "\n\tmember: " + ",".join(("uid=" + options.UID,
                                                    options.peopledn,
                                                    options.base)))

        # Delete user from the Redmine group.
        conn.modify(",".join(("cn=redmine",
                              options.groupsdn,
                              options.base)),
                    {"member": (ldap3.MODIFY_DELETE,
                                [",".join(("uid=" + options.UID,
                                           options.peopledn,
                                           options.base))])})

        # If user wasn't in the group.
        if conn.result["description"] == "noSuchAttribute":
            print("[WARN] User " + options.UID +
                  " is not a member of the Redmine group.")

        verbose(options)("[INFO] " + str(conn.result))

        # If user already exists in "ou=former workers" subtree:
        if conn.search(search_base=",".join((options.formerdn,
                                             options.base)),
                       search_filter="(&" +
                       "(objectClass=inetOrgPerson)" +
                       "(uid=" + options.UID + "))"):

            print("[WARN] User uid=" + options.UID + "," + newdn +
                  " already exists. Overwriting")

            verbose(options)("[INFO] LDAP delete:\n\t" +
                             ",".join(("uid=" + options.UID,
                                       options.formerdn,
                                       options.base)))

            # Delete the old user in formerdn.
            conn.delete(",".join(("uid=" + options.UID,
                                  options.formerdn,
                                  options.base)))

            verbose(options)("[INFO] " + str(conn.result))

        verbose(options)("[INFO] LDAP move:" +
                         "\n\told DN:" + dn +
                         "\n\tnew DN:" + ",".join(("uid=" + options.UID,
                                                   newdn)))

        # Move the entry to its new subtree.
        conn.modify_dn(dn,
                       "uid=" + options.UID,
                       new_superior=newdn)

        verbose(options)("[INFO] " + str(conn.result))

    # Delete bots.
    if options.bots:
        # If the bot doesn't exist.
        if not conn.search(search_base=",".join((options.botsdn,
                                                 options.base)),
                           search_filter="(&" +
                           "(objectClass=inetOrgPerson)" +
                           "(uid=" + options.UID + "))"):

            print("[ERROR] User " + options.UID +
                  " doesn't exists. Nothing to delete")

            sys.exit(0)

        # Create the bot DN.
        dn = ",".join(("uid=" + options.UID,
                       options.botsdn,
                       options.base))

        verbose(options)("[INFO] LDAP delete:\n\t" + dn)

        # Delete the bot.
        conn.delete(dn)

        verbose(options)("[INFO] " + str(conn.result))

    # Delete clients.
    if options.clients:
        # If the client doesn't exist, exit.
        if not conn.search(search_base=",".join((options.clientsdn,
                                                 options.base)),
                           search_filter="(&" +
                           "(objectClass=inetOrgPerson)" +
                           "(uid=" + options.UID + "))"):

            print("[ERROR] User " + options.UID +
                  " doesn't exists. Nothing to delete")

            sys.exit(0)

        dn = ",".join(("uid=" + options.UID,
                       options.clientsdn,
                       options.base))

        verbose(options)("[INFO] LDAP delete:\n\t" + dn)

        # Delete the node.
        conn.delete(dn)

        verbose(options)("[INFO] " + str(conn.result))


def ldapmodify(options, conn):
    """Modify existing entries.

    Modify an entry from the LDAP server, either a bot, a client, or a
    person. For bots and clients, just the password and description is
    relevant. For people, we can change the password, emails,
    description, mobile and work phones, department, or the title.

    All of the existing attributes with the same name will be removed.
    For example, if the person has 2 emails, and we use this function to
    add a new email, the old mail attributes will be removed, and in the
    end there'll be just a single email. This is done to avoid having
    too many repeating attributes. If you need to keep the old emails,
    add them to the command line, with multiple -m switches.
    """
    if options.people:
        if not conn.search(search_base=",".join((options.peopledn,
                                                 options.base)),
                           search_filter="(&" +
                           "(objectClass=inetOrgPerson)" +
                           "(uid=" + options.UID + "))"):

            print("[ERROR] User " + options.UID +
                  " doesn't exist. Nothing to modify")

            sys.exit(0)

        # Create the user DN.
        dn = ",".join(("uid=" + options.UID,
                       options.peopledn,
                       options.base))

    if options.bots:
        if not conn.search(search_base=",".join((options.botsdn,
                                                 options.base)),
                           search_filter="(&" +
                           "(objectClass=inetOrgPerson)" +
                           "(uid=" + options.UID + "))"):

            print("[ERROR] User " + options.UID +
                  " doesn't exist. Nothing to modify")

            sys.exit(0)

        # Create the user DN.
        dn = ",".join(("uid=" + options.UID,
                       options.botsdn,
                       options.base))

    if options.clients:
        if not conn.search(search_base=",".join((options.clientsdn,
                                                 options.base)),
                           search_filter="(&" +
                           "(objectClass=posixAccount)" +
                           "(uid=" + options.UID + "))"):

            print("[ERROR] User " + options.UID +
                  " doesn't exist. Nothing to modify")

            sys.exit(0)

        # Create the user DN.
        dn = ",".join(("uid=" + options.UID,
                       options.clientsdn,
                       options.base))

    # Set up the arguments from the command line.
    if options.password:
        verbose(options)("[INFO] LDAP modify_replace:\n\t" + dn +
                         "\n\treplace: userPassword")

        # Replace the existing password.
        conn.modify(dn,
                    {"userPassword": (ldap3.MODIFY_REPLACE,
                                      [ssha.encrypt(options.password)])})

        verbose(options)("[INFO] " + str(conn.result))

    if options.mail:
        verbose(options)("[INFO] LDAP modify_delete:\n\t" + dn +
                         "\n\tdelete: mail")

        # Delete all old emails.
        conn.modify(dn, {"mail": (ldap3.MODIFY_DELETE, [])})

        verbose(options)("[INFO] " + str(conn.result))

        verbose(options)("[INFO] LDAP modify_add:\n\t" + dn +
                         "\n\tmail: " + str(options.mail))

        # Add new emails.
        conn.modify(dn,
                    {"mail": (ldap3.MODIFY_ADD,
                              options.mail)})

        verbose(options)("[INFO] " + str(conn.result))

    if options.mobile:
        verbose(options)("[INFO] LDAP modify_delete:\n\t" + dn +
                         "\n\tdelete: mobile")

        # Delete old mobile phones.
        conn.modify(dn, {"mobile": (ldap3.MODIFY_DELETE, [])})

        verbose(options)("[INFO] " + str(conn.result))

        verbose(options)("[INFO] LDAP modify_add:\n\t" + dn +
                         "\n\tmobile: " + str(options.mobile))

        # Add all new mobile phones.
        conn.modify(dn,
                    {"mobile": (ldap3.MODIFY_ADD,
                                options.mobile)})

        verbose(options)("[INFO] " + str(conn.result))

    if options.department:
        verbose(options)("[INFO] LDAP modify_replace:\n\t" + dn +
                         "\n\tou: " + options.department)

        # Replace the existing department.
        conn.modify(dn,
                    {"ou": (ldap3.MODIFY_REPLACE,
                            options.department)})

        verbose(options)("[INFO] " + str(conn.result))

    if options.telephone:
        verbose(options)("[INFO] LDAP modify_delete:\n\t" + dn +
                         "\n\tdelete: telephoneNumber")

        conn.modify(dn, {"telephoneNumber": (ldap3.MODIFY_DELETE, [])})

        verbose(options)("[INFO] " + str(conn.result))

        verbose(options)("[INFO] LDAP modify_add:\n\t" + dn +
                         "\n\ttelephone: " + str(options.telephone))

        conn.modify(dn,
                    {"telephoneNumber": (ldap3.MODIFY_ADD,
                                         options.telephone)})

        verbose(options)("[INFO] " + str(conn.result))

    if options.title:
        verbose(options)("[INFO] LDAP modify_replace:\n\t" + dn +
                         "\n\ttitle: " + options.title)

        conn.modify(dn,
                    {"title": (ldap3.MODIFY_REPLACE,
                               options.title)})

        verbose(options)("[INFO] " + str(conn.result))

    if options.description:
        verbose(options)("[INFO] LDAP modify_add:\n\t" + dn +
                         "\n\tdescription: " + str(options.description))

        conn.modify(dn,
                    {"description": (ldap3.MODIFY_ADD,
                                     options.description)})

        verbose(options)("[INFO] " + str(conn.result))


if __name__ == "__main__":
    # Read the configuration file.
    CONFIG = _load_configuration()

    # Parse the command line arguments.
    options = parse_options(CONFIG)

    verbose(options)(options)

    # Start the daemon process.
    d = multiprocessing.Process(name="daemon",
                                target=daemon,
                                args=(options,))

    # Configure it as a daemon.
    d.daemon = True

    # If forward COMMAND is used, run the daemon indefinitely.
    if options.COMMAND == "forward":
        d.start()

        try:
            d.join()

        except KeyboardInterrupt:
            pass

    # If other COMMAND is used, run the client process.
    else:
        n = multiprocessing.Process(name="client",
                                    target=client,
                                    args=(options,))

        # Not a daemon.
        n.daemon = False

        # Start the daemon.
        d.start()

        # Wait for the port forwarding to establish.
        time.sleep(2)

        # Start the client.
        n.start()

        # Join the client process, so the daemon can close once the
        # client has finished its job.
        n.join()
