# ghl-jail

![demo de ghl-jail: crear un proyecto, agregar la herramienta, escribir dentro (permitido), leer un secreto fuera (bloqueado), sin red, git, cleanup](demo.gif)

Ejecuta una herramienta de línea de comandos de modo que **no pueda leer tus secretos ni tus archivos** — solo la única
carpeta de proyecto que le señales. Sin permisos de administrador, sin instalación, sin servicio en segundo plano. Solo
Python 3 y Windows.

Existe por un problema simple y real: instalas o ejecutas una herramienta de línea de comandos — un gestor de paquetes, un
agente de IA que escribe código, un script que alguien te mandó — y esa herramienta corre con *toda tu cuenta*. Puede leer
`~/.ssh`, tus credenciales de la nube, el perfil de tu navegador, tus archivos `.env`, y puede llamar a casa. En abril de
2026 una [versión maliciosa de la CLI de
Bitwarden](https://www.paloaltonetworks.com/blog/cloud-security/bitwardencli-supply-chain-attack/) estuvo viva en npm unos
noventa minutos, leyendo claves SSH, archivos `.env` y credenciales de AWS/Azure/GCP de cada máquina que la instaló; en
octubre, el [repositorio de la CLI oficial de
OVHcloud](https://www.thestack.technology/ovhcloud-cli-repo-compromised-customer-reports-incident/) fue comprometido de la
misma forma, detectado y bloqueado en 94 minutos. Ninguno era un virus que pudieras haber detectado — solo una herramienta
de confianza con una mala actualización. `ghl-jail` es la cerca que pones alrededor de una herramienta así *antes* de
confiar en ella.

> **Esto es reducción de daño, no una bóveda.** Sube mucho el costo de un error. No es una protección contra un atacante que
> ataca activamente este sandbox en concreto. No ejecutes código que sabes que es malicioso dando por hecho que estás a salvo.

---

## Instalación

Nada que instalar. Necesitas Python 3.8 o superior (ya está en casi toda máquina de desarrollo) y Windows 10 u 11. Copia la
carpeta `ghl-jail` a donde quieras y ejecútala.

## Cómo se usa

```
python ghl_jail.py run [opciones] -- <el comando que quieres aislar>
```

Todo lo que va después de `--` es el comando, ejecutado tal como lo harías en una terminal. Tres cosas que conviene saber:

| Opción | Qué hace | Por defecto |
|---|---|---|
| `--project DIR` | La **única** carpeta en la que la herramienta puede escribir y leer con libertad. | la carpeta actual |
| `--mode auto\|container\|token` | Qué tan ajustada es la cerca (ver abajo). | `container` |
| `--net none\|internet\|lan` | Si la herramienta puede llegar a la red (solo en modo container). | `none` |

Dos más para cuando las necesites: `--allow-read PATH` abre una carpeta extra solo para lectura; `--keep-env NAME` deja pasar
una variable de entorno (por ejemplo un token de API que la herramienta sí necesita) a través del entorno que de otro modo se
vacía.

Cuando terminas, `python ghl_jail.py cleanup` quita todos los permisos que la herramienta concedió y borra su carpeta de
trabajo. (Una corrida normal se limpia sola; `cleanup` es el comando de respaldo.)

### Los tres modos, en términos claros

- **`container`** — el más ajustado. La herramienta queda tapiada del resto de la máquina salvo tu carpeta de proyecto, **y no
  tiene red**. El mejor para todo lo que solo necesita tocar tu código: linters, formateadores, pasos de build, un script del
  que no te fías.
- **`token`** — un poco más holgado, y **no bloquea la red**. Úsalo para herramientas que de verdad necesitan salir (instalar
  paquetes) o que se niegan a arrancar en el modo más ajustado (git es una de ellas). Sigue bloqueando todos tus demás
  archivos.
- **`auto`** — no eliges tú. Usa `container` para todo, y cambia a `token` en silencio solo para las pocas herramientas que se
  sabe que lo necesitan (hoy: git), imprimiendo un aviso de una línea cuando lo hace. Este es el que conviene si no quieres
  pensarlo.

### Qué bloquea y qué permite el sandbox (verificado por la batería de pruebas)

| La herramienta intenta... | `container` | `token` |
|---|---|---|
| leer/escribir tu carpeta de proyecto | permitido | permitido |
| leer `~/.ssh`, `~/.aws`, `.env`, datos del navegador, el resto de tu perfil | **bloqueado** | **bloqueado** |
| escribir en cualquier sitio fuera del proyecto | **bloqueado** | **bloqueado** |
| llegar a la red | **bloqueado** (salvo `--net`) | permitido |
| leer un token de API que dejaste en una variable de entorno | **bloqueado** | **bloqueado** |
| ejecutar python, java, node | sí | sí |
| ejecutar git | no (ver la peculiaridad de Windows abajo) | sí |

---

## Tres formas en que la gente lo usa

### 1. Ejecutar una CLI que no es de fiar o recién descargada

Bajaste una CLI de internet — un binario de release, una herramienta global de `pip`/`npm`, un script de instalación. Quieres
probarla sin apostar tus claves SSH y tus tokens de la nube a que es honesta.

```
python ghl_jail.py run --project C:\scratch -- herramienta-sospechosa.exe --haz-lo-tuyo
```

- **Alcance:** la herramienta ve una carpeta de trabajo vacía y nada más tuyo; sin red por la que exfiltrar.
- **Impacto:** una herramienta con puerta trasera como el caso de la CLI de OVHcloud no encuentra credenciales en el disco ni
  salida alguna.
- **Diferencial:** el antivirus pregunta "¿es este archivo *conocido* como malo?" y deja pasar cualquier cosa nueva. Una
  máquina virtual o Docker Desktop harían el trabajo, pero necesitan Pro/Hyper-V, gigabytes y minutos para arrancar.
  `ghl-jail` es un envoltorio de una línea que arranca al instante y funciona en Windows Home sin permisos de administrador.

### 2. Mantener a un agente de IA dentro del repo en el que trabaja

Dejas que un agente de IA (o cualquier script autónomo) edite código y ejecute comandos en tu repo. Quieres que toque *ese
repo* y nada más — ni tus otros proyectos, ni tus dotfiles — y que no salga a la red salvo que tú lo digas.

```
python ghl_jail.py run --project C:\work\mi-repo --net none -- agente --task "refactor del parser"
```

- **Alcance:** el agente lee y escribe solo `mi-repo`; un `rm` perdido o una ruta errada no puede llegar a tus otras carpetas,
  y no puede leer un token que esté en otro proyecto.
- **Impacto:** el radio de daño de un agente confundido o con una inyección de prompt es un repositorio al que puedes hacer
  `git reset`, no toda tu cuenta.
- **Diferencial:** los agentes que *sí* traen un sandbox para Windows (Codex de OpenAI) solo se aíslan *a sí mismos*.
  `ghl-jail` es agnóstico del agente — envuelve cualquier agente, script o herramienta que le entregues, igual todas las veces.

### 3. Instalar dependencias sin entregar tus credenciales de npm/pip

`npm install` y `pip install` ejecutan scripts de instalación arbitrarios de desconocidos, y los corren como tú, con tus
tokens de registro en el entorno. Aquí la herramienta necesita la red pero aun así no debería leer tu carpeta de usuario ni
tus tokens reales.

```
python ghl_jail.py run --project C:\work\app --mode token --net internet -- npm install
```

- **Alcance:** los scripts de instalación pueden llegar al registro y escribir en el `node_modules` del proyecto, pero tus
  `~/.ssh`, `~/.aws` y cualquier secreto que no hayas pasado explícitamente con `--keep-env` quedan invisibles.
- **Impacto:** un script post-install malicioso (el patrón del ataque de cadena de suministro de npm) no puede leer
  credenciales de tu disco ni de tu entorno.
- **Diferencial:** los verificadores de lockfile y `npm audit` te avisan de paquetes *conocidos* como malos, después del
  hecho. Esto contiene la instalación en sí, incluido un paquete malicioso recién salido que ningún escáner ha marcado todavía.

---

## Límites conocidos (para que no te sorprendan)

- **git solo corre en modo `token`/`auto`.** git abre el dispositivo `NUL` por su nombre en cada comando, y en esta versión de
  Windows los permisos del dispositivo no incluyen a las aplicaciones aisladas, algo que solo un administrador podría cambiar.
  `auto` se encarga de esto por ti y te avisa que cambió (para que sepas que esa corrida de git no quedó aislada de la red).
- **El modo `token` no restringe la red,** y todavía puede leer archivos legibles por cualquiera (por ejemplo otra unidad con
  permisos por defecto). Protege tu perfil — donde viven las credenciales —, no todos los archivos de la máquina.
- **npm (y otras herramientas `.cmd`) necesitan el modo `token` cuando tu cadena de herramientas está dentro de tu perfil de
  usuario,** porque el sandbox no puede atravesar las carpetas de tu perfil para leer el script envoltorio. Una cadena de
  herramientas bajo `C:\Program Files` sí es alcanzable en modo `container`. `node` a secas funciona en los dos.
- **Fuera de alcance:** la aplicación a nivel de kernel, el aislamiento de Windows Sandbox/Hyper-V y las funciones de agente de
  Windows 11 quedan fuera por diseño — esto es una herramienta de espacio de usuario, sin administrador y sin controlador.

## Correr las pruebas

```
python test_ghl_jail.py
```

46 pruebas repartidas en los tres modos lanzan las herramientas reales (python, java, node, git, npm) contra archivos señuelo
falsos y confirman que cada muro aguanta. Cada prueba de "está bloqueado" tiene su correspondiente prueba de "está permitido",
así un error de tipeo no puede hacerse pasar por una denegación.
