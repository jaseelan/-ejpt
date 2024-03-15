

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
