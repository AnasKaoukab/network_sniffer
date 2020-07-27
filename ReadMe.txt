Protocoles implémentés:
-Ethernet
-IP / ARP
-ICMP / TCP /SCTP /UDP
-Telnet / IMAP / SMTP /POP / FTP / HTTP / BOOTP DHCP / DNS

Les  commutateurs  de  la  ligne  de  commande  implementés : 
-i <interface> 
-o <fichier> 
-f <filtre> 
-v <1..3> 
-u pour l'usage

Les librairies pour les entetes suivants non trouvées et ainsi cherchés:
-arp (elle est dans network.h)
-dns et bootp (elle est dans application.h)
-sctp.h pour sctp (pris d'un git)

Affichage : 
-packet en HEX puis l'analyse de chaque couche (inspiré de Wireshark)

