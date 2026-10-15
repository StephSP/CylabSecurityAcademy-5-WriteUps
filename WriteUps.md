# CylabSecurityAcademy — Resoluciones CTF (Versión didáctica 1)

Este documento describe cinco ejercicios de ciberseguridad, las herramientas utilizadas para resolverlos y los errores de diseño o configuración que permitieron completar cada reto.

---

## 1. Pachinko — Análisis de una aplicación web

**Categoría:** Web Exploitation

### Objetivo

El desafío consiste en analizar una aplicación web que permite interactuar con un simulador de circuitos lógicos. La tarea es investigar cómo funciona la aplicación y determinar cómo obtener la flag del desafío.

### Procedimiento

Para comenzar, accedí a la aplicación y abrí las herramientas de desarrollador del navegador mediante `F12`. Luego entré en la pestaña **Network**, que permite inspeccionar las solicitudes HTTP que se generan al interactuar con la página.

Después de enviar un circuito desde la interfaz, identifiqué la petición correspondiente y examiné sus detalles. Presté especial atención al método HTTP, los encabezados, los datos enviados en el cuerpo de la solicitud y la respuesta recibida del servidor.

Este análisis permite comprender cómo se comunica el frontend con el backend y qué información devuelve la aplicación después de procesar un intento.

A continuación, el objetivo es comparar las respuestas obtenidas durante las pruebas para identificar diferencias relevantes y determinar qué condiciones permiten completar el desafío. Si resulta necesario repetir solicitudes, es posible utilizar la opción **Copy as cURL** del navegador para reproducirlas desde una terminal y facilitar su análisis.

La respuesta definitiva debe verificarse en la instancia del desafío, buscando la flag proporcionada por el servidor.

### Conclusión

El desafío permite practicar el análisis de aplicaciones web mediante la inspección del tráfico HTTP. La pestaña **Network** resulta especialmente útil porque muestra tanto los datos enviados al servidor como las respuestas recibidas, que pueden contener información que no resulta evidente al observar únicamente la interfaz gráfica.

La flag y los pasos exactos para obtenerla deben confirmarse con la instancia original, ya que no he podido verificar una ejecución concreta de Pachinko para documentar esos resultados.

---

## 1. Apriti Sesamo — Bypass de autenticación mediante SHA-1

**Categoría:** Web Exploitation / Autenticación

### Objetivo

El desafío presenta una aplicación web con un formulario de inicio de sesión. El objetivo consiste en descubrir una vulnerabilidad en la validación de las credenciales para conseguir que el servidor entregue la flag.

### Procedimiento

Para comenzar, accedí a la página del desafío y examiné el formulario de inicio de sesión. Como las pruebas iniciales no permitían identificar fácilmente la vulnerabilidad, revisé las pistas proporcionadas por el reto: *Backup files* y la referencia a un desarrollador que utiliza Emacs.

Esta última pista resultó importante porque Emacs suele guardar copias de respaldo de los archivos añadiendo el carácter `~` al final de su nombre. Por ello, probé acceder al archivo de respaldo de la página de autenticación, utilizando la ruta `impossibleLogin.php~`.

Al inspeccionar el contenido del archivo, encontré código PHP comentado que revelaba la lógica de autenticación. Después de analizar las comparaciones, identifiqué dos condiciones relevantes:

- El nombre de usuario y la contraseña debían ser diferentes entre sí.
- Los valores SHA-1 de ambas entradas debían coincidir.

La segunda condición utiliza una comparación estricta entre los resultados de `sha1()`. Esto sugiere que el objetivo es conseguir que ambas funciones devuelvan el mismo valor, aunque las entradas originales sean distintas.

Para resolverlo, aproveché el comportamiento de PHP al recibir arreglos en lugar de cadenas. Si se envían los campos `username` y `pwd` como arreglos, `sha1()` no puede procesarlos como cadenas normales y devuelve `null` en versiones de PHP que presentan este comportamiento. Al comparar ambos resultados mediante `===`, se obtiene `null === null`, que es verdadero.

En una instancia autorizada del laboratorio, los parámetros pueden enviarse de la siguiente manera:

```text
username[]=aaa&pwd[]=bbb
```

Al ser distintos los valores enviados y coincidir los resultados de la comparación estricta de `sha1()`, se satisface la condición vulnerable y la aplicación puede mostrar el contenido del archivo que contiene la flag.

### Conclusión

La vulnerabilidad de Apriti Sesamo se basa en una validación incorrecta de las credenciales y en el tratamiento de los tipos de datos en PHP. La combinación de un archivo de respaldo accesible y una comparación de hashes que no valida adecuadamente los tipos de entrada permite eludir el inicio de sesión.

Este desafío demuestra la importancia de validar los tipos de datos recibidos del usuario, comprobar los resultados de las funciones criptográficas y evitar depender de comparaciones cuyo comportamiento puede cambiar según los valores proporcionados.

---

## 3. Failure Failure

**Categoría:** Web / Configuración de servidores

### Objetivo

La aplicación estaba construida con Flask y funcionaba detrás de **HAProxy**. Había dos servidores: `s1`, que atendía normalmente, y `s2`, que actuaba como respaldo. La flag se mostraba cuando respondía `s2`, por lo que era necesario provocar el cambio al servidor secundario.

### Procedimiento

Primero examiné `haproxy.cfg`. Allí observé que HAProxy enviaba un **health check** con `GET /` cada dos segundos y esperaba recibir HTTP `200`. Si el servidor principal fallaba dos comprobaciones seguidas, el balanceador lo consideraba no disponible y utilizaba el respaldo.

Después revisé `app.py` y detecté una configuración defectuosa: el límite de **300 solicitudes por minuto** se asociaba a una clave fija, `global`, en lugar de mantener un contador separado por dirección IP. En consecuencia, las solicitudes normales y las comprobaciones de salud de HAProxy compartían el mismo límite.

Para reproducir el comportamiento, utilicé un script llamado `loop.py`, escrito en Python con `ThreadPoolExecutor` y `urllib`, que enviaba varias solicitudes concurrentes al servicio del desafío. La finalidad era consumir el límite común y provocar respuestas diferentes de `200`.

Cuando los health checks comenzaron a fallar, HAProxy marcó `s1` como caído y dirigió el tráfico a `s2`, cuya variable de configuración era `IS_BACKUP=yes`. Al volver a consultar `/`, obtuve la flag.

También observé que, una vez recuperado el servidor principal y superadas las comprobaciones requeridas, el tráfico regresaba a `s1`.

### Conclusión

El cambio al servidor de respaldo era un comportamiento esperado de HAProxy. La debilidad consistía en que **el límite global también afectaba las comprobaciones de salud**, lo que permitía provocar el failover sin comprometer directamente el servidor principal.

---

## 4. No FA — picoCTF 2026

**Categoría:** Web Exploitation

### Objetivo

Había que iniciar sesión como `admin`, superar la autenticación de dos factores (2FA) y llegar a la página que contenía la flag.

### Procedimiento

Comencé examinando el código de Flask y la base de datos. Vi que las contraseñas se verificaban mediante **SHA-256 sin salt**, un enfoque que permite intentar recuperar contraseñas mediante ataques de diccionario.

Para inspeccionar el contenido de la base SQLite ejecuté:

```bash
sqlite3 users.db ".dump"
```

Después utilicé una herramienta de búsqueda por diccionario, como Hashcat en el modo `1400` para SHA-256, para analizar el hash correspondiente a `admin`. Así recuperé la contraseña `apple@123`.

Aunque pude iniciar sesión, el sitio solicitaba un OTP de cuatro cifras. Al revisar `app.py`, encontré que el secreto se almacenaba en `session['otp_secret']`.

La cuestión importante era que, de forma predeterminada, **las cookies de sesión de Flask están firmadas, pero no cifradas**. Abrí las herramientas de desarrollador, localicé la cookie `session` y examiné su contenido con Python, usando Base64 y, cuando correspondía, zlib. Allí pude encontrar el valor de `otp_secret`.

Introduje el código antes de su vencimiento y completé el 2FA. Como la sesión correspondía a la cuenta de administrador, la aplicación mostró la flag.

### Conclusión

El secreto del segundo factor quedaba expuesto en el contenido de la cookie de sesión. Además, el uso de SHA-256 sin salt facilitaba los intentos de recuperación de contraseñas. El aprendizaje principal es que **firmar una cookie no equivale a cifrarla**.

---

## 5. SQL Map1 — picoCTF 2026

**Categoría:** Web Exploitation

### Objetivo

El propósito era recuperar la flag verdadera de una aplicación cuyo buscador era vulnerable a SQL Injection. El fallo permitía consultar información de la base de datos y, posteriormente, acceder con otra cuenta.

### Procedimiento

Me registré en el sitio, inicié sesión y probé una inyección sencilla en el campo de búsqueda:

```sql
' OR 1=1 --
```

La consulta devolvió numerosos registros, entre ellos algunas flags que no eran válidas. Continué examinando la base SQLite hasta localizar la tabla `users`.

Para mostrar los nombres de usuario junto con sus hashes de contraseña, utilicé esta inyección:

```sql
' UNION SELECT 1, GROUP_CONCAT(username || ': ' || password) FROM users --
```

Los valores almacenados correspondían a hashes **MD5**. Recuperé la contraseña de `ctf-player`, cuyo valor era `dyesebel`. Luego cerré la sesión anterior y accedí con esas credenciales, lo que me permitió entrar al área protegida y encontrar la flag correcta.

### Conclusión

En este caso se combinaron una inyección SQL que permitía leer información no autorizada y un mecanismo de almacenamiento de contraseñas inadecuado. La combinación de ambas debilidades hizo posible acceder a otra cuenta.