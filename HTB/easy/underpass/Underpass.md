
Quick writeup for the underpass box on HTB (linux - easy)

## Table of contents : 
- [User Flag](#user) 
- [Root Flag](#root)

## User

First we start with an inital nmap scan : 
```
eddymalou@parrot:~/Documents/CTF/HTB$ nmap 10.10.11.48
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-02 15:54 CET
Nmap scan report for 10.10.11.48
Host is up (0.027s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

The http server is the default apache2 page and the directory fuzzing didn't reveal anything interesting. 

Let's fuzz for vhosts maybe ? : 
`ffuf -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u "http://$target/" -H "Host: FUZZ.$TARGET" -fc 301`

Still nothing interesting, after looking around I decided to launch another nmap scan including all the ports (-p-) and the udp ports (-sU)

```
Nmap scan report for underpass.htb (10.10.11.48)
Host is up (0.021s latency).
Not shown: 981 closed udp ports (port-unreach)
PORT      STATE         SERVICE
161/udp   open          snmp
682/udp   filtered      xfr
1056/udp  filtered      vfo
1060/udp  filtered      polestar
1812/udp  open|filtered radius
1813/udp  open|filtered radacct
16548/udp filtered      unknown
17185/udp filtered      wdbrpc
17331/udp filtered      unknown
19789/udp filtered      unknown
20359/udp filtered      unknown
22043/udp filtered      unknown
29243/udp filtered      unknown
36489/udp filtered      unknown
38037/udp filtered      landesk-cba
40019/udp filtered      unknown
49171/udp filtered      unknown
51717/udp filtered      unknown
61550/udp filtered      unknown
```
Interesting! 
We can see a snmp port and two radius ports open. 
Let's run snmp-check and snmpwalk

```
eddymalou@parrot:~/Documents/CTF$ snmp-check 10.10.11.48
snmp-check v1.9 - SNMP enumerator
Copyright (c) 2005-2015 by Matteo Cantoni (www.nothink.org)

[+] Try to connect to 10.10.11.48:161 using SNMPv1 and community 'public'

[*] System information:

  Host IP address               : 10.10.11.48
  Hostname                      : UnDerPass.htb is the only daloradius server in the basin!
  Description                   : Linux underpass 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64
  Contact                       : steve@underpass.htb
  Location                      : Nevada, U.S.A. but not Vegas
  Uptime snmp                   : 00:21:45.57
  Uptime system                 : 00:21:29.11
  System date                   : 2025-1-2 15:53:31.0

```
We note a possible user (steve) and also the fact that the radius server is probably a  daloradius instance.

Let's fuzz again the http server using `http://underpass.htb/daloradius/` and we find several interesting endpoints. 

Going on the [official github page of daloradius](https://github.com/lirantal/daloradius) (since it's opensource we can also enumerate everypage)

When trying out the different files we are being redirected to a login page : `http://underpass.htb/daloradius/app/operators/login.php`

![Login form](/HTB/easy/underpass/images/loginpage.png)

We try the default password "administrator" / "radius" and we are in (after several restarts and 502 on the box though :/ )

Navigating through the admin pannel reveals this interesting user / password hash : 

![Login form](/HTB/easy/underpass/images/hash_admin_page.png)

We also find the password policy to exclude special characters, so should be easy enough to crack. Let's use john and rockyou.txt : 

svcMosh: censored

Once that is done we can ssh into the box and get our user flag.

## Root

The root flag was pretty easy but fun and I got to discover a new tool.
Let's run sudo -l : 

![Login form](/HTB/easy/underpass/images/sudol.png)

We are allowed to run /usr/bin/mosh-server with root priviledges on this server. 

Time to read some documentation : https://mosh.org/#usage
After downloading mosh on my computer and trying to fix a problem I didn't need to fix ("Q: I'm getting "mosh requires a UTF-8 locale." How can I fix this?") I managed to get root. 
We first launch a mosh-server with sudo on the ssh shell we have : 

![Login form](/HTB/easy/underpass/images/mosh_server.png)

And then we connect back to it from our laptop using the port and the secret key : 
`MOSH_KEY=gqh9/rVBDZXSj7D2ulVSBg mosh-client 10.10.11.48 60002`

![Login form](/HTB/easy/underpass/images/root_txt.png)
And we're root!
