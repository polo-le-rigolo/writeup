# WifineticTwo - HTB 2024 - Write up 
#### By eddym@lou

Summary of the write up :

1. [Intro](#intro)
2. [OpenPLC RCE](#OpenPLC_RCE)
3. [Wifi attack](#Wifi_attack)

## Intro
This box was labelled is a linux one and is labelled with the difficulty is set to **medium**
As usual on HTB, we launch our vpn, start up the machine and verify the connectivity with a ping. 
Once that is done let's launch a simple nmap scan : 

```
Nmap scan report for 10.10.11.7
Host is up (0.073s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
8080/tcp open  http-proxy
```

Connecting to the web server on port 8080 we are granted with a login page for what appears to be an OpenPLC instance : 
![OpenPLC login](/HTB/medium/images/WifineticTwo/1_OpenPLC_login.png)

A PLC (Programmable Logic Controller) is an industrial computer designed for controlling manufacturing processes, machinery, and factory assembly lines. And as its name suggests, it is programmable, meaning it can be configured and reconfigured by writing and loading different control programs. It typically uses specialized programming languages such as Ladder Logic / Structured Text / Function Block Diagram.

OpenPLC is an open-source PLC platform that provides cheap and flexible alternative to traditional proprietary PLCs. It allows users to create and customize their own PLC systems using open-source tools and resources (can be installed on a lot of different systems including linux, windows, raspberry pis, esp32 and even arduinos if they ahve network capabilities).

Let's get back to our box, a straight forward "OpenPLC Webserver default credentials" internet search and we stumble accross an article on how to set up OpenPLC on a raspberry pi : 
![OpenPLC login](/HTB/medium/images/WifineticTwo/2_OpenPLC_setup_article.png)

We can then login with `openplc` as user / password  

![OpenPLC login](/HTB/medium/images/WifineticTwo/3_OpenPLC_dashboard.png)

## OpenPLC_RCE

From there we have access to several menus, two of them include "programs" and "hardware".
When we first arrive on the dashboard, the PLC is written as "stopped" but clicking on the "Start PLC" button starts it up.

In the program section (endpoint of `/program`), we can list the current programs and browse our computer to upload our own custom programs.
There is currently only one program on the OpenPLC instance : "blank_program.st"
"st" stands for "structured text" and as we said earlier it is a special programming language designed for PLC programming.

In the hardware section, we find the "Hardware Layer Code Box". This allows you to extend the functionality of the current driver by adding custom code to it, such as reading I2C, SPI and 1-Wire sensors, or controling port expanders to add more outputs to your hardware. 
Ultimately, it means that we have the capability to write and upload custom C code that will be executed within the PLC's runtime environment.
Among the different functions we find the following : 

```
//-----------------------------------------------------------------------------
// This function is called by the main OpenduPLC routine when it is initializing.
// Hardware initialization procedures for your custom layer should be here.
//-----------------------------------------------------------------------------
void initCustomLayer()
{
}
```
As written in the comments, the initCustomLayer() function is invoked when the PLC is initialized or started up. Theoretically if we write our own code here and start the PLC we should be able to obtain a RCE on the server.
Let's inject a reverse shell payload (payload.c file) in this block of code and compile it :
![OpenPLC login](/HTB/medium/images/WifineticTwo/4_compiled_RCE_payload.png)

We obtained a root shell on the machine : 
![OpenPLC login](/HTB/medium/images/WifineticTwo/5_successful_rev_shell.png)
Let's stabilise the shell with python : 
![OpenPLC login](/HTB/medium/images/WifineticTwo/6_stabilised_python_shell.png)

## Wifi_attack

As the name suggests something linked to the wifi connection, we can verify the presence of a wifi interface with **ip a** : 
```
root@attica02:/root# ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0@if19: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 00:16:3e:fb:30:c8 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 10.0.3.3/24 brd 10.0.3.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet 10.0.3.44/24 metric 100 brd 10.0.3.255 scope global secondary dynamic eth0
       valid_lft 1948sec preferred_lft 1948sec
    inet6 fe80::216:3eff:fefb:30c8/64 scope link 
       valid_lft forever preferred_lft forever
6: wlan0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc mq state DOWN group default qlen 1000
    link/ether 02:00:00:00:03:00 brd ff:ff:ff:ff:ff:ff
```
We count a loopback address (eth0), an ethernet address (eth0) and finally a wireless address (wlan0).
Let's scan for nearby wifi networks with **iwlist wlan0 scan** and **iw dev wlan0 scan** : 

```
    BSSID 02:00:00:00:01:00(on wlan0)
	SSID: plcrouter
    Encryption key:on   
    IE: IEEE 802.11i/WPA2 Version 1
    Authentication Suites (1) : PSK
	WPS : * Version: 1.0
		  * Wi-Fi Protected Setup State: 2 (Configured)
		  * Response Type: 3 (AP)
		  * Primary Device Type: 0-00000000-0
		  * Version2: 2.0
		 (the informations from both scans have been concatenated and trimmed to show only the most important infos)
```
We detected one wifi network with the SSID *plcrouter*. Encryption is enabled and thus it is not a public network.
The encryption algorithm used is WPA2 : if the password is weak, deauthing a client and grabbing a handshake in order to bruteforce it offline could give us access to the network. Another important information of this scan is the presence of the WPS mecanism. 
Wi-Fi Protected Setup (WPS) is a feature designed to simplify the process of connecting devices to a secure wireless network. It provides easy configuration methods, primarily through either an 8-digit PIN code or a push button. 
Two attacks exists to bypass WPS and access the network without knowing the PIN code : 

1. Plain brute-force attack (attackers try all possible combinations until finding the correct PIN)
The large number of possible combinaisons (the last digit being a checksum of the previous digits we have 10^7 = 10,000,000 possible combinations. ) makes it not practical. However, researchers noted that the registrar verifies the PIN's first and second halves separately. This vulnerability allows attackers to potentially recover the PIN in under four hours by testing a reduced set of possible combinations.[Source](#https://en.wikipedia.org/wiki/Wi-Fi_Protected_Setup#Online_brute-force_attack)

2. Pixie Dust Attack: Exploits weaknesses in how some routers generate and validate these 8-digit PINs, allowing for much faster PIN recovery (poor random number generation algorithms).

Let's try exploit this vulnerability and gain access to the network. Reaver and airgeddon both are tools that I've used in the past for wifi pentesting and that support a pixie dust module. Uploading either of them onto the machine (since the machine doesn't have internet access we can curl the binaries and the shared libraries from our local machine) was my initial idea. Unfortunately I realised that the wireless network adapter (wlan0) didn't support monitor mode. And both reaver and airgeddon require this mode to function. After searching for a tool to perform a pixie dust attack I stumbled accross this on a github repo `OneShot performs Pixie Dust attack without having to switch to monitor mode.`. Sounds promising! Let's check if all the requirement (iw / wpa_supplicant / pixiewps / python 3.6 minimum) are met on the box : 

![OpenPLC login](/HTB/medium/images/WifineticTwo/7_requirements_oneshot.png)

We need to download pixiewps on the box but it doesn't have access to the internet. Let's download pixiewps on our local machine and start a web server with **python3 -m http.server 8080**. We can now download it on the machine : 
![OpenPLC login](/HTB/medium/images/WifineticTwo/8_download_pixiewps.png)

Now we can move it to */usr/sbin/* and we should be able to use the oneshot.py script.
After installing the script using the same method let's launch the attack : 
![OpenPLC login](/HTB/medium/images/WifineticTwo/9_successfull_wifi_attack.png)
We successfully exploited the WPS vulnerability on the plcrouter network.
The pin has been recovered (*12345670*) and the pre shared key has been obtained *NoWWEDoKnowWhaTisReal123!*.
Let's create a wpa_supplicant.conf file and place it into /etc/wpa_supplicant/ : 

```
network={
    ssid="plcrouter"
    psk="NoWWEDoKnowWhaTisReal123!"
}
```
And connect to the wifi network with :`wpa_supplicant -B -i wlan0 -c /etc/wpa_supplicant/wpa_supplicant.conf`
**-B** runs wpa_supplicant in the background (otherwise we'd loose our shell)
Let's check if we managed to successfully connect to our network with **iwconfig** : 
![OpenPLC login](/HTB/medium/images/WifineticTwo/10_iwconfig_connected_to_network.png)
Great! Let's try to get an ip address by running dhclient on wlan0 (still in the background : **dhclient wlan0 &**)
Unfortunately we couldn't seem to get an ip address with dhclient. 
I got stuck at this step, trying several stuff and loosing the shell numerous times. Then I set up a static ip addr in the default private subnet 192.168.1.0/24 : `sudo ip addr add 192.168.1.2/24 dev wlan0`
I downloaded the nmap binary onto the machine, from my local machine, with curl and scanned the subnet. 
One machine answered our ping sweep (192.168.1.1) and port 22 was listening : 
![OpenPLC login](/HTB/medium/images/WifineticTwo/11_root_flag.png)

