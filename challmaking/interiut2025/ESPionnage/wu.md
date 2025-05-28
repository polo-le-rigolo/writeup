# Writeup - ESPionnage

## Description du challenge

Ce challenge est un challenge en trois étapes, conçu dans le cadre de la 10ème édition du CTF
interiut organisé conjointement par HACK2G2 et l'ENSIBS. Le but final du challenge est d’accéder au contenu d'un coffre-fort connecté situé sur la table des admins.

![Coffre connecté](/challmaking/interiut2025/ESPionnage/img/coffre.jpg)

## Sommaire du writeup
1. [ESPionnage 1/3](#ESPionnage_1)
2. [ESPionnage 2/3](#ESPionnage_2)
3. [ESPionnage 3/3](#ESPionnage_3)

## ESPionnage_1

### Description du challenge : 

```
Pour cette première phase, vous interceptez une transmission sur le réseau sans fil de la secte CASTEM lors de l'OTA du coffre. Une capture réseau de cette transmission ainsi qu'une documentation sur le coffre sont à télécharger. À vous de l’analyser pour récupérer le firmware embarqué du système de verrouillage. Le flag de ce premier challenge est le hash sha256 du binaire. 
```

En ouvrant la capture avec Wireshark on remarque directement un `GET http://eddymalou.fr:8080/firmware.elf`. Malheureusement, en exportant les objets http de la capture on se rend vite compte que le firmware.elf n'est pas un elf  : 

![Bait firmware](/challmaking/interiut2025/ESPionnage/img/bait_firmware.png)

On en déduit qu'il faut trouver un moyen de télécharger le firmware depuis le serveur. 
Essayons d'accèder au firmware directement : 

![Access denied](/challmaking/interiut2025/ESPionnage/img/denied.png)

En lisant la documentation (doc.pdf), le fonctionnement de l'OTA est détaillé : 

```
L’appareil tentera automatiquement de s’authentifier à un serveur CASTEM, une fois l’authentification effectuée, le serveur répond avec un token valide 90 secondes qui permet au device de télécharger le firmware pour l’OTA.
```
Après analyse de la capture wireshark, on peut remarquer un échange de messages MQTT avant le curl du firmware. Le device se connecte au broker et subscribe au topic /auth-token, le broker renvoie des messages publiés sur ce même topic. On note les informations suivantes : 

- Username MQTT : *iotcastem*
- Mdp MQTT : *tungtungsahur*
- L'url du broker : *eddymalou.fr*
- Le topic : */auth-token* 

On peut se connecter au broker avec un client mqtt :

![MQTT Token](/challmaking/interiut2025/ESPionnage/img/mqtt_token.png)

Cette commande permet de subscribe à l'ensemble des topics (grâce à la wildcard "#") et notamment le topic /auth-token sur lequel on voit un token publié de manière périodique et qui change toute les 90 secondes, comme la documentation l'indique.

Maintenant que nous avons un moyen de récupérer un token valide on peut :

curl -H "Cookie: auth_token=LE_TOKEN" http://eddymalou.fr:8080/firmware.elf --output firmware.elf

![MQTT Token](/challmaking/interiut2025/ESPionnage/img/flag_firmware.png)


## ESPionnage_2

### Description du challenge : 

```
Vous avez mis la main sur le firmware du coffre-fort, bravo! CASTEM pensait sa technologie inviolable... mais c’est à vous de prouver le contraire.

Dans cette deuxième phase, vous devrez analyser le binaire extrait et comprendre le fonctionnement interne du système de verrouillage. L’objectif est d’identifier la bonne valeur de la carte autorisée à ouvrir le coffre.

Le firmware a été compilé pour une carte ESP32, et contient tout le code nécessaire à la gestion du lecteur NFC et de l’interface graphique.

Le flag de ce challenge est la string décodée hexa -> ascii de la bonne valeur qui ouvre le coffre.
```

Pas besoin de parser le .bin issu d'un dump de ESP32 avec esp32_image_parser, car le fichier firmware.elf est, comme son extension l’indique, déjà un ELF :)

On load le fichier ELF dans Ghidra en s’assurant que l’architecture détectée est bien Xtensa:LE:32. Une fois l’architecture confirmée, on lance l’analyse en laissant tous les paramètres par défaut.

Une fois l’analyse terminée, on peut aller explorer les strings contenues dans le binaire, ce qui nous permet de repérer rapidement une fonction appelée loop.

Dans la programmation de microcontrôleurs (comme les arduino ou esp32), deux fonctions principales structurent le programme :

-setup() qui permet initialiser les périphériques, interfaces ou variables

-loop() qui s'exécute en boucle et représente la logique principale du programme (équivalent du main() dans un programme classique)

En examinant la fonction loop décompilée, on tombe sur un bloc de code particulièrement intéressant :

![Loop decompiled](/challmaking/interiut2025/ESPionnage/img/loop_decompiled.png)

Analysons de plus près ce code, les serial.println de débug laissés par le développeur facilitent le reverse : 

```    
          if (iVar6 == 0) {
            Print::println((Print *)&Serial0,s_Access_granted_!_sector_1_matche_3f4001f1);
            status = s_Lock_status:_Access_granted!_3f400228;
            bVar2 = true;
          }
          else {
            Print::println((Print *)&Serial0,s_Access_denied_!_sector_1_doesn't_3f400245);
            status = s_Lock_status:_Access_denied_3f400282;
```

On comprend ici que si iVar6 == 0, l’accès est accordé (Access granted), sinon l’accès est refusé (Access denied). Voyons ce que vaut iVar6 un peu plus haut dans la fonction :

`iVar6 = memcmp(data, expectedMifareData, 8);`

Le code effectue une comparaison mémoire entre data et expectedMifareData sur les 8 premiers octets. La fonction memcmp retourne 0 uniquement si les deux blocs comparés sont identiques.

data correspond à un buffer contenant les données lues depuis un bloc de la carte MIFARE Classic, via un lecteur NFC (confirmé par le doc.pdf : il s’agit d’un PN532) :
`uVar3 = PN532::mifareclassic_ReadDataBlock(&nfc,'\x04',data);`

Le programme lit donc le bloc 4 de la carte NFC, et compare les 8 premiers octets de ce bloc à une valeur attendue : expectedMifareData.

En double-cliquant sur expectedMifareData dans Ghidra, on accède à l'adresse mémoire contenant cette valeur, ce qui nous permet d’en consulter directement le contenu :

![ExpectedMifareData](/challmaking/interiut2025/ESPionnage/img/expected_mifare_data.png)

On valide donc le challenge avec interiut{rickroll}

## ESPionnage_3

### Description du challenge : 
```
Vous avez désormais en main la valeur autorisée par le firmware du coffre-fort. Mais posséder la connaissance ne suffit pas… il vous faut maintenant agir, comme le ferait un véritable initié de la secte.

Chaque équipe a reçu une carte NFC. À vous de trouver une moyen d'ouvrir le coffre sans se faire prendre par les gardes!  

Le coffre se trouve sur la table des admins, et le flag final se trouve à l’intérieur du coffre.
```

La carte NFC fournie à chaque équipe est une carte MIFARE Classic 1K. Ces cartes utilisent des clés A/B pour contrôler l'accès en lecture/écriture à chaque secteur. Or, la majorité de ces cartes utilisent des clés par défaut et sont donc vulnérables à des attaques de clonage ou de modification, ce qui est justement intéressant ici.
Par ailleurs dans le binaire on trouve également une valeur intéressante : 

![Default Key](/challmaking/interiut2025/ESPionnage/img/default_key.png)

Il s'agit d'une des valeurs par défaut les plus courantes utilisées pour les clés A/B sur les cartes MIFARE Classic.
Grâce à un téléphone Android doté d'une puce NFC, on peut utiliser l'application Mifare Classic Tool pour lire et modifier la carte : 
![Blank card](/challmaking/interiut2025/ESPionnage/img/secteurs.png)

Une MIFARE Classic 1K est divisée en 16 secteurs et chaque secteur contient 4 blocs, chaque bloc contient 16 octets. Donc au total : 16 secteurs × 4 blocs × 16 octets = 1024 octets (1 Ko)

Les blocs sont numérotés de 0 à 63, de façon linéaire, c’est-à-dire :
Secteur 0, les blocs sont 0 / 1 / 2 / 3 
Secteur 1, les blocs sont 4 / 5 / 6 / 7
Et ainsi de suite. 

Le secteur 0 est généralement non modifiable car il contient l’UID de la carte (modifiable uniquement sur certaines cartes chinoises "magic"). Mais cela n'a pas d'importance ici, car la vérification se fait sur le bloc 4, soit le premier bloc du secteur 1 : `uVar3 = PN532::mifareclassic_ReadDataBlock(&nfc,'\x04',data);`

Il suffit donc de modifier les 8 premiers octets du premier bloc du secteur 1 en rajoutant l'hexa de "rickroll"
"72 69 63 6B 72 6F 6C 6C" en ASCII -> rickroll

![Rickroll](/challmaking/interiut2025/ESPionnage/img/rickroll.png)

Ensuite il suffit de cliquer sur les 3 points en haut à droite puis "écrire dump" et c'est bon la carte est maintenant modifiée. On se rend à la table d'admin pour parler à Philippe_Katerine et tester notre carte sur le coffre..
