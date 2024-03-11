

--------------------------------------------------------------------------------------------------
# eJPT-Cheatsheet            
This is a Cheatsheet for eJPT Exam & Course.

## (1)  Assessment Methodologies

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

```

## (2) Host & Networking Auditing
```

```

## (3) Host & Network Penetration Testing

```
```
## (4) Web Application Penetration Testing

```
```
