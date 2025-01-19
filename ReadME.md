
# Sniffer Réseau

## Projet Python Sniffer réseau




## Installation

Pour lancer ce projet, clonez le repo
Déplacez vous dans le dossier du repo 

Si vous souhaitez un environnement python run :```python3 -m venv 
Nom_De_l'environnement``` 

Pour activer l'environnement faites : 

```source Nom_De_l'environnement/bin/activate ```

Maintenant vous devez installer les dépendance : ```pip install -r requierement.txt ```

## Lancement

Afin de lancer le projet il vous faudra être en root car Scapy a besoin des autorisations root pour fonctionner. 

Faites : ``` sudo python3 src/sniffer.py ``` pour lancer le sniffer.

Choisissez l'interface sur laquelle vous voulez écoutez et ensuite choisissez le nombre de paquet a Capturer .

Après avoir utilisé le sniffer, si vous voulez quitter l'environnement faites la commande:

``` deactivate ```



## Features

Dans une future mise a jour il vous sera possible d'enregistrer vos capture en ".pcap" ou ".txt" 

Une interface utilisateur graphique sera également disponible. 

Certains protocole comme le SSH, POP3, SMB, RDP, LDAP ou IMAP seront par la suite ajouté pour pouvoir travailler sur chaque protocole et ne plus avoir des inconnus ou presque.

Quelques outils tels que Nmap, Hashcat, nitko, gobuster, ou encore enum4linux viendront compléter notre sniffer afin de pouvoir faire un outils de réseau / pentest assez complet.

## Packages
| Package             | Liens                                              
| ----------------- | ------------------------------------------------------------------ |
Scapy |https://scapy.net

#### (suite du projet)
| Package             | Liens                                              
| ----------------- | ------------------------------------------------------------------ |
| Smtplib |https://docs.python.org/3/library/smtplib.html|
| Os |https://docs.python.org/fr/3.13/library/os.html|
| Subprocess|https://docs.python.org/3/library/subprocess.html|

## Authors

- [@quent1grs](https://github.com/quent1grs)
- [@Decorentin](https://github.com/Decorentin)


