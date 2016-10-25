#!/usr/bin/env python
# Script: auditloginfo.py
# Author: Matty <matty91@gmail.com>
# Date: 10-25-2016
# Purpose:
#  This script takes a UID as an argument and checks /var/log/audit
#   to see which system calls have been invoked by the user. The
#   script displays the number of system calls executed, the commands
#   that were run and the files that were opened. This is useful for
#   crafting selinux profiles and for determining which capabilities
#   are needed by a given program.
# License: 
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#  GNU General Public License for more details.

import re
import argparse
from collections import defaultdict

SYSCALLS = {}
SYSCALL_HEADERS = "/usr/include/asm/unistd_64.h"
AUDIT_LOG = "/var/log/audit/audit.log"

# Dictionaries to hold metrics
PROGRAMS_EXECUTED = defaultdict(int)
FILES_OPENED = defaultdict(int)
SYSTEM_CALLS_MADE = defaultdict(int)


def build_system_call_list():
    """
       Parses the system syscall header file and builds
       a dictionary with the system call name and number.
    """
    with open(SYSCALL_HEADERS) as syscalls:
        for line in syscalls:
            if  "_NR_" in line:
                sysc, syscn = re.split('_NR_| ', line)[2:]
                SYSCALLS[syscn.strip()] = sysc


def parse_audit_log(uid):
    """
       Parses /var/log/audit/audit.log to see what system calls are
       being called by a specific userid

       execve():
         type=SYSCALL msg=audit(1477415653.941:59393): arch=c000003e syscall=59 success=yes exit=0
         a0=557cb40973b0 a1=557cb40a1fb0 a2=557cb4252cb0 a3=557cb40a1fb0 items=2
         pid=8444 pid=8969 auid=7005 uid=7005 gid=7005 euid=7005 suid=7005 fsuid=7005
         egid=7005 sgid=7005 fsgid=7005 tty=pts9 ses=758 comm="gzip" exe="/usr/bin/gzip" key=(null)
         type=EXECVE msg=audit(1477415653.941:59393): argc=2 a0="gzip" a1="services"

       open():
         type=SYSCALL msg=audit(1477415593.489:57658): arch=c000003e syscall=2 success=yes exit=3
         a0=7ffc69cb6522 a1=0 a2=fffffffe a3=7f552e354060 items=1 ppid=8444 pid=8641 auid=7005
         uid=7005 gid=7005 euid=7005 suid=7005 fsuid=7005 egid=7005 sgid=7005 fsgid=7005
         tty=pts9 ses=758 comm="head" exe="/usr/bin/head" key=(null)
         type=CWD msg=audit(1477415593.489:57658):  cwd="/home/fmep"
         type=PATH msg=audit(1477415593.489:57658): item=0 name="/etc/services"
         inode=201694595 dev=fd:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL
    """
    queue = {}

    with open(AUDIT_LOG) as audit_log:
        for line in audit_log:
            kv_pairs = dict(audit_entry.split('=', 1) for audit_entry in line.split())
            if "syscall" in kv_pairs and kv_pairs["auid"] == str(uid):
                # Increment the number of system calls from this process
                system_call_number = kv_pairs["syscall"]
                system_call_name = SYSCALLS[system_call_number]
                SYSTEM_CALLS_MADE[system_call_name] += 1

                # System calls: 2 -> open(), 59 -> execve()
                if any(kv_pairs["syscall"] == sysc for sysc in ("2", "59")):
                    audit_id = kv_pairs["msg"]
                    queue[audit_id] = kv_pairs

            # Need to get the file that was passed as arg0 to open()
            elif kv_pairs["type"] == "PATH" and kv_pairs["msg"] in queue:
                filename = kv_pairs["name"].strip('"')
                FILES_OPENED[filename] += 1

            # Need to pair this up with the syscall line
            elif kv_pairs["type"] == "EXECVE" and kv_pairs["msg"] in queue:
                audit_id = kv_pairs["msg"]
                full_command = ""
                for index in range(10):
                    arg = "a" + str(index)
                    if arg in kv_pairs:
                        full_command += kv_pairs[arg].strip('"') + " "
                PROGRAMS_EXECUTED[full_command] += 1
                del queue[audit_id]


def print_report(uid):
    """
       Print out the metrics collected from the audit logs
    """
    print "Audit report for AUID %s" % (uid)

    print "\nSystem calls made:"
    for syscall, num_invocations in sorted(SYSTEM_CALLS_MADE.iteritems(),
                                           key=lambda (k, v): (v, k), reverse=True):
        print "   " + syscall + " " +  str(num_invocations)

    print "\nCommands executed:"
    for command, num_invocations in sorted(PROGRAMS_EXECUTED.iteritems(),
                                           key=lambda (k, v): (v, k), reverse=True):
        print "   " + command + " " +  str(num_invocations)

    print "\nFiles opened:"
    for file_opened, num_invocations in sorted(FILES_OPENED.iteritems(),
                                               key=lambda (k, v): (v, k),
                                               reverse=True):
        print "    " + file_opened + " " +  str(num_invocations)


def main():
    """
       Main code block
    """
    parser = argparse.ArgumentParser(description='Audit Log Analyzer')
    parser.add_argument('--uid', nargs=1, help="Userid to look up in the audit logs",
                        default=0, metavar="uid")
    args = parser.parse_args()

    uid = args.uid[0]
    build_system_call_list()
    parse_audit_log(uid)
    print_report(uid)


if __name__ == "__main__":
    main()
