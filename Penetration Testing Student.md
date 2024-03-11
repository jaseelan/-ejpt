

--------------------------------------------------------------------------------------------------
# eJPT-Cheatsheet            
This is a Cheatsheet for eJPT Exam & Course.

## (1)  Assessment Methodologies
```sh

```
## fPing
```sh
fping -a -g 10.10.10.0/24 2>/dev/null              #Host Discover
``` 
## IP Route
**Syntax**\
ip route add \<Network-range\> via \<router-IP\> dev \<interface\>
```sh
ip route add 10.10.10.0/24 via 10.10.11.1 dev tap0 

ip route        # Checking defined routes in linux
route           # Checking defined routes in linux
route print     # Checking defined routes in windows
```
## Networking Commands

