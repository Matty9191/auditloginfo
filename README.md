# Process audit logs

auditloginfo takes an audit log and produces a report listing the number of system calls run, the commands that were executed and the files that were opened. This is useful information to have when you are assembling SELinux profiles or figuring out which Linux capabilities are needed by a program.

# Sample output
<pre>
$  sudo auditloginfo.py --uid 7005 |more
Audit report for AUID 7005

System calls made:
   read 207
   stat 179
   close 147
   open 142
   rt_sigprocmask 141
   clock_gettime 120
   write 88
   select 59
   rt_sigaction 53
   ioctl 23
   readlink 7
   rt_sigreturn 3
   wait4 2
   kill 1
   getdents 1
   exit_group 1
   
Commands executed:
   clear  2
   /bin/basename bash  2
   uname -m  1
   ps -ef  1
   ps  1
   ls --color=auto -la  1

Files opened:
   /etc/ld.so.cache 17
   /lib64/libc.so.6 15
   /etc/passwd 14
   /usr/lib/locale/locale-archive 12
   /lib64/libpthread.so.0 8
   /lib64/libpcre.so.1 8
</pre>
