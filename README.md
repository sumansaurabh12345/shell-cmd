# shell-cmd
nano script_file.sh =======Note pad open with name (script_file) & .sh means extension

nano = notepade like this

./ (means command execute)

./script_file.sh (execute script_file)

for permission to chek and execute

ls -l  (permission to chek )

for execute command need to provide permission

chmod 777 script_file.sh (7 means R = read , 7 means W = write , 7 means X=execute) RWX

$BASH (variable) 
                    
====================================================================================
#!/bin/bash


echo "i willbe a great Devops ENGINEER"

#echo $BASH

name="Saurabh"

echo "hello ${name}, please enter your age"

read age

echo "My age is ${age}"

echo "Sub: hello"

sleep 2

echo "Me: Apka swagat hai Universe wave pe"

sleep 2

echo "Please subscribe, aur apne dosto ko bhi bulao"

=========================================================================

shell script 2 if else and fi=== means close

=============================================
#!/bin/bash

if [ "$1" = "like" ]
then
 echo "Hey Please $1 this video"
else
 echo "Okay ,then please Subcribe:)"
fi

==============================================
  GNU nano 6.2             if_elif.sh *
#!/bin/bash

a=100
b=200
c=300

if  [[ $a -gt $b && $a -gt $c ]]
then
echo "A is biggest"
elif [[ $b -gt $a && -gt $c ]]
then
echo "B is biggest"
else
echo "C is biggest"
fi

C is biggest


==============================

  GNU nano 6.2              loops.sh                        #!/bin/bash

for ((i=0; i<13; i++))
do
echo "$i"
done

ubuntu@ip-172-31-3-80:~/scripts$ ./loops.sh
0
1
2
3
4
5
6
7
8
9
10
11
12
===================================

ubuntu@ip-172-31-3-80:~/scripts$ touch file-1.txt
ubuntu@ip-172-31-3-80:~/scripts$ touch file-{2..10}.txt
ubuntu@ip-172-31-3-80:~/scripts$ ls
file-1.txt   file-3.txt  file-6.txt  file-9.txt
file-10.txt  file-4.txt  file-7.txt  if_elif.sh
file-2.txt   file-5.txt  file-8.txt  loops.sh


  GNU nano 6.2              loops.sh                        #!/bin/bash

for ((i=0; i<13; i++))
do
echo "$i"
done

for FILE in *
do
echo $FILE
done

ubuntu@ip-172-31-3-80:~/scripts$ ./loops.sh
0
1
2
3
4
5
6
7
8
9
10
11
12
file-1.txt
file-10.txt
file-2.txt
file-3.txt
file-4.txt
file-5.txt
file-6.txt
file-7.txt
file-8.txt
file-9.txt
if_elif.sh
loops.sh

=================

  GNU nano 6.2              loops.sh                        #!/bin/bash

for ((i=0; i<13; i++))
do
echo "$i"
done

for FILE in *.txt
do
echo $FILE
done

ubuntu@ip-172-31-3-80:~/scripts$ ./loops.sh
0
1
2
3
4
5
6
7
8
9
10
11
12
file-1.txt
file-10.txt
file-2.txt
file-3.txt
file-4.txt
file-5.txt
file-6.txt
file-7.txt
file-8.txt
file-9.txt


=======================================


ubuntu@ip-172-31-3-80:~/scripts$ touch file-{2..10}.txt
ubuntu@ip-172-31-3-80:~/scripts$ ls
file-1.txt   file-3.txt  file-6.txt  file-9.txt
file-10.txt  file-4.txt  file-7.txt  if_elif.sh
file-2.txt   file-5.txt  file-8.txt  loops.sh

=================================================

adding function call addding user if i want 
  
GNU nano 6.2                   adding_user.sh                             #!/bin/bash


add_user()
{
USER=$1
PASS=$2

useradd -m -p $PASS $USER && echo "Successfully added user"

}

#MAIN

add_user saurabh Voda@123



ubuntu@ip-172-31-3-80:~/scripts$ chmod 777 adding_user.sh
ubuntu@ip-172-31-3-80:~/scripts$ ./adding_user.sh
useradd: Permission denied.
useradd: cannot lock /etc/passwd; try again later.
ubuntu@ip-172-31-3-80:~/scripts$ sudo ./adding_user.sh
Successfully added user
ubuntu@ip-172-31-3-80:~/scripts$

=============================================================


ubuntu@ip-172-31-3-80:~$ ls
devops_first.shx  if_test.sh  saurabh  script_file.sh  scripts
ubuntu@ip-172-31-3-80:~$ cd
ubuntu@ip-172-31-3-80:~$
ubuntu@ip-172-31-3-80:~$ cd
ubuntu@ip-172-31-3-80:~$
ubuntu@ip-172-31-3-80:~$ cd ..
ubuntu@ip-172-31-3-80:/home$ cd ..
ubuntu@ip-172-31-3-80:/$ ls
bin   dev  home  lib32  libx32      media  opt   root  sbin  srv  tmp  var
boot  etc  lib   lib64  lost+found  mnt    proc  run   snap  sys  usr


==============================================================================

ubuntu@ip-172-31-3-80:/$ cat /etc/pass
cat: /etc/pass: No such file or directory
ubuntu@ip-172-31-3-80:/$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:102:105::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:103:106:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
syslog:x:104:111::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:112:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:113::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:114::/nonexistent:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
landscape:x:111:116::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:117:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
ec2-instance-connect:x:113:65534::/nonexistent:/usr/sbin/nologin
_chrony:x:114:121:Chrony daemon,,,:/var/lib/chrony:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
saurabh:x:1001:1001::/home/saurabh:/bin/sh

=========================================================================================

ubuntu@ip-172-31-3-80:/$ cd /home/ubuntu/scripts
ubuntu@ip-172-31-3-80:~/scripts$ ls
adding_user.sh  file-2.txt  file-5.txt  file-8.txt  loops.sh
file-1.txt      file-3.txt  file-6.txt  file-9.txt
file-10.txt     file-4.txt  file-7.txt  if_elif.sh

=============================================================================

  

GNU nano 6.2                  backup.sh
#!/bin/bash

src_dir=/home/ubuntu/script
tgt_dir=/home/ubuntu/backups

curr_timestamp=$(date "+%y-%m-%d-%H-%M-%S")

echo "$curr_timestamp"

ubuntu@ip-172-31-5-15:~/script$ ./backup.sh
23-05-27-15-24-54
ubuntu@ip-172-31-5-15:~/script$ ./backup.sh
23-05-27-15-24-56
ubuntu@ip-172-31-5-15:~/script$ ./backup.sh
23-05-27-15-25-01
ubuntu@ip-172-31-5-15:~/script$ ./backup.sh
23-05-27-15-25-07
ubuntu@ip-172-31-5-15:~/script$ ./backup.sh
23-05-27-15-25-13
ubuntu@ip-172-31-5-15:~/script$ ./backup.sh
23-05-27-15-25-15

========================================================================


  GNU nano 6.2                  backup.sh                            #!/bin/bash

src_dir=/home/ubuntu/script
tgt_dir=/home/ubuntu/backups

curr_timestamp=$(date "+%y-%m-%d-%H-%M-%S")
backup_file=$tgt_dir/$curr_timestamp.tgz

echo "Taking backup on $curr_timestamp"
echo "$backup_file"

ubuntu@ip-172-31-5-15:~/script$ ./backup.sh
Taking backup on 23-05-27-15-44-57
/home/ubuntu/backups/23-05-27-15-44-57.tgz

===========================================================

#!/bin/bash

src_dir=/home/ubuntu/script
tgt_dir=/home/ubuntu/backups

curr_timestamp=$(date "+%y-%m-%d-%H-%M-%S")
backup_file=$tgt_dir/$curr_timestamp.tgz

echo "Taking backup on $curr_timestamp"
#echo "$backup_file"

tar czf $backup_file $src_dir

echo "Backu complete"

$ ./backup.sh
Taking backup on 23-05-27-16-00-49
Backu complete

====================================================

ubuntu@ip-172-31-5-15:~/backups$ ls
23-05-27-15-58-00.tgz  23-05-27-16-00-49.tgz

=========================================================

ubuntu@ip-172-31-5-15:~/backups$ ls
23-05-27-15-58-00.tgz  23-05-27-16-00-49.tgz  home
ubuntu@ip-172-31-5-15:~/backups$ cd home/
ubuntu@ip-172-31-5-15:~/backups/home$ ls
ubuntu
ubuntu@ip-172-31-5-15:~/backups/home$ cd ubuntu
ubuntu@ip-172-31-5-15:~/backups/home/ubuntu$ ls
script
ubuntu@ip-172-31-5-15:~/backups/home/ubuntu$ cd script
ubuntu@ip-172-31-5-15:~/backups/home/ubuntu/script$ ls
adding_user.sh  file-2.txt  file-6.txt  file-{2..10.txt}
backup.sh       file-3.txt  file-7.txt  if-elif.sh
file-1.txt      file-4.txt  file-8.txt  if_elif.sh
file-10.txt     file-5.txt  file-9.txt  loop.sh

=============================================================

ubuntu@ip-172-31-5-15:~$ df -H
Filesystem      Size  Used Avail Use% Mounted on
/dev/root       8.2G  1.7G  6.5G  21% /
tmpfs           507M     0  507M   0% /dev/shm
tmpfs           203M  906k  202M   1% /run
tmpfs           5.3M     0  5.3M   0% /run/lock
/dev/xvda15     110M  6.4M  104M   6% /boot/efi
tmpfs           102M  4.1k  102M   1% /run/user/1000
========================================================

ubuntu@ip-172-31-5-15:~$ top
top - 16:57:57 up  3:14,  7 users,  load average: 0.00, 0.0 Tasks: 114 total,   1 running, 113 sleeping,   0 stopped,
%Cpu(s):  0.0 us,  0.0 sy,  0.0 ni,100.0 id,  0.0 wa,  0.0
MiB Mem :    965.7 total,    335.3 free,    239.2 used,     MiB Swap:      0.0 total,      0.0 free,      0.0 used.

    PID USER      PR  NI    VIRT    RES    SHR S  %CPU
      1 root      20   0  101916  12840   8368 S   0.0
      2 root      20   0       0      0      0 S   0.0
      3 root       0 -20       0      0      0 I   0.0
      4 root       0 -20       0      0      0 I   0.0

===============================================================================

ubuntu@ip-172-31-5-15:~$ free
               total        used        free      shared  buff/cache   available
Mem:          988920      245000      343368         888      400552      590040
Swap:              0           0           0

========================================================================================

ubuntu@ip-172-31-5-15:~/script$ vim check_dis.sh
#!/bin/bash

df -H | awk '{print $5 " " $1}'
=============================================                                 

ubuntu@ip-172-31-5-15:~/script$ vim check_dis.sh
ubuntu@ip-172-31-5-15:~/script$ chmod 777 check_dis.sh
ubuntu@ip-172-31-5-15:~/script$ ./check_dis.sh
Use% Filesystem
21% /dev/root
0% tmpfs
1% tmpfs
0% tmpfs
6% /dev/xvda15
1% tmpfs

==============================================================================

#!/bin/bash

df -H | awk '{print $5 " " $1}' | while read output
do
 echo "Disk Detail: $output"
done

ubuntu@ip-172-31-5-15:~/script$ ./check_dis.sh
Disk Detail: Use% Filesystem
Disk Detail: 21% /dev/root
Disk Detail: 0% tmpfs
Disk Detail: 1% tmpfs
Disk Detail: 0% tmpfs
Disk Detail: 6% /dev/xvda15
Disk Detail: 1% tmpfs

============================================

#!/bin/bash
alert=1

df -H | awk '{print $5 " " $1}' | while read output;
do
 #echo "Disk Detail: $output"
 usage=$(echo $output | awk '{print $1}' | cut -d'%' -f1)
 file_sys=$(echo $output | awk '{print $1}')
 #echo $usage
if [ $usage -ge $alert ]
then
          echo "CRITICAL for $file_sys"
fi
done


============================================================================
 ubuntu@ip-172-31-15-61:~/scipt1$ bash check_disk.sh
check_disk.sh: line 10: [: Use: integer expression expected
CRITICAL for 35%
CRITICAL for 1%
CRITICAL for 6%
CRITICAL for 1%    

=====================================================

ubuntu@ip-172-31-5-15:~$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
# You can also override PATH, but by default, newer versions inherit it from the environment
#PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#

===========================================================================

ubuntu@ip-172-31-5-15:~$ crontab -l
no crontab for ubuntu
=========================================

ubuntu@ip-172-31-5-15:~$ date
Sat May 27 19:46:52 UTC 2023

crontab -e

# m h  dom mon dow   command

47 19 * * * echo "this is my first cron job" > /home/ubuntu/test_cron_first.txt



===========================================================================

ubuntu@ip-172-31-5-15:~/script$ ./check_dis.sh
./check_dis.sh: line 9: [: Use: integer expression expected
CRITICAL for /dev/root
===================================================================

ubuntu@ip-172-31-5-15:~$ date
Sat May 27 19:49:02 UTC 2023
ubuntu@ip-172-31-5-15:~$ ls
backups  script  test_cron_first.txt
ubuntu@ip-172-31-5-15:~$ cat test_cron_first.txt
this is my first cron job
ubuntu@ip-172-31-5-15:~$
==============================================================

ubuntu@ip-172-31-5-15:~$ crontab -l
# Edit this file to introduce tasks to be run by cron.
#
# Each task to run has to be defined through a single line
# indicating with different fields when the task will be run
# and what command to run for the task
#
# To define the time you can provide concrete values for
# minute (m), hour (h), day of month (dom), month (mon),
# and day of week (dow) or use '*' in these fields (for 'any').
#
# Notice that tasks will be started based on the cron's system
# daemon's notion of time and timezones.
#
# Output of the crontab jobs (including errors) is sent through
# email to the user the crontab file belongs to (unless redirected).
#
# For example, you can run a backup of all your user accounts
# at 5 a.m every week with:
# 0 5 * * 1 tar -zcf /var/backups/home.tgz /home/
#
# For more information see the manual pages of crontab(5) and cron(8)
#
# m h  dom mon dow   command

47 19 * * * echo "this is my first cron job" > /home/ubuntu/test_cron_first.txt
======================================================================================

#!/bin/bash
alert=10
backup_date=$(date +'%m/%d/%Y %H:%M:%S')
df -H | awk '{print $5 " " $1}' | while read output;
do
 #echo "Disk Detail: $output"
 usage=$(echo $output | awk '{print $1}' | cut -d'%' -f1)
 file_sys=$(echo $output | awk '{print $2}')
 #echo $usage
 if [ $usage -ge $alert ]
 then
        echo "CRITICAL for $file_sys on $backup_date"
 fi
done


ubuntu@ip-172-31-5-15:~/script$ bash  check_dis.sh
check_dis.sh: line 10: [: Use: integer expression expected
CRITICAL for /dev/root on 05/27/2023 20:08:00


===================================================================================
backups  check_dis.txt  script  test_cron_first.txt
ubuntu@ip-172-31-5-15:~$ cat check_dis.txt
CRITICAL for /dev/root on 05/27/2023 20:21:01
CRITICAL for /dev/root on 05/27/2023 20:22:01
CRITICAL for /dev/root on 05/27/2023 20:23:01
CRITICAL for /dev/root on 05/27/2023 20:24:01
ubuntu@ip-172-31-5-15:~$ date
Sat May 27 20:25:50 UTC 2023
ubuntu@ip-172-31-5-15:~$ cat  check_dis.txt
CRITICAL for /dev/root on 05/27/2023 20:21:01
CRITICAL for /dev/root on 05/27/2023 20:22:01
CRITICAL for /dev/root on 05/27/2023 20:23:01
CRITICAL for /dev/root on 05/27/2023 20:24:01
CRITICAL for /dev/root on 05/27/2023 20:25:01
CRITICAL for /dev/root on 05/27/2023 20:26:01

====================================================================

# For more information see the manual pages of crontab(5) and cron(8)
#
# m h  dom mon dow   command

47 19 * * * echo "this is my first cron job" > /home/ubuntu/test_cron_first.txt
* * * * * bash /home/ubuntu/script/check_dis.sh >> /home/ubuntu/check_dis.txt


backups  check_dis.txt  script  test_cron_first.txt
ubuntu@ip-172-31-5-15:~$ cat check_dis.txt
CRITICAL for /dev/root on 05/27/2023 20:21:01
CRITICAL for /dev/root on 05/27/2023 20:22:01
CRITICAL for /dev/root on 05/27/2023 20:23:01
CRITICAL for /dev/root on 05/27/2023 20:24:01
ubuntu@ip-172-31-5-15:~$ date
Sat May 27 20:25:50 UTC 2023
ubuntu@ip-172-31-5-15:~$ cat  check_dis.txt
CRITICAL for /dev/root on 05/27/2023 20:21:01
CRITICAL for /dev/root on 05/27/2023 20:22:01
CRITICAL for /dev/root on 05/27/2023 20:23:01
CRITICAL for /dev/root on 05/27/2023 20:24:01
CRITICAL for /dev/root on 05/27/2023 20:25:01
CRITICAL for /dev/root on 05/27/2023 20:26:01





