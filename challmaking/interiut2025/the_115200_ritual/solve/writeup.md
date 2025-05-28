# Writeup - The 115200 Ritual

## Description du challenge

Une transmission étrange a été interceptée dans l’un des centres de recrutement de la secte CASTEM.

Grâce à une brève intrusion sur leur réseau de capteurs, nous avons pu connecter un analyseur logique à l’un de leurs dispositifs.

À vous maintenant de décoder cette transmission !

---

## Fichier fourni

On nous donne un fichier `.vcd`. Après une recherche rapide, on découvre qu'il s'agit d'un **Value Change Dump**, un format utilisé pour enregistrer des changements de valeurs logiques au cours du temps, souvent issu d'un analyseur logique.

## Analyse

Le nom du challenge, **"The 115200 Ritual"**, donne un indice : **115200** est un baudrate typique en communication série (https://en.wikipedia.org/wiki/Serial_port#Settings).

## Étapes de résolution

1. On installe **PulseView** (outil d’analyse de signaux logiques)

2. Aller dans **Import > Value Change Dump (.vcd)** pour importer le fichier

3. Une fois le fichier chargé, on configure le baudrate à **115200**

4. On voit bien les bits 0 et 1 avec les fronts montants et descendants mais ils ne sont pas interprétés. Il faut ajouter un décodeur **UART** :
   - "Add protocol decoder" > UART
   - On configure le **RX** sur le signal `D0`
   - On vérifie que le baudrate est bien défini à **115200**

5. Dans l'onglet new view de la toolbar : **Binary decoder output view**, les données décodées apparaissent

6. Le flag est directement visible dans l'UART décodé : interiut{U4rt_c0mmunic4tion_1s_fun} 

![Pulseview solve](/challmaking/interiut2025/the_115200_ritual/solve)
