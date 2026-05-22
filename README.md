# 🔐 Vault Encripter

Herramienta CLI diseñada para cifrar archivos y directorios completos mediante primitivas criptográficas avanzadas. Diseñada con un enfoque en seguridad real; cifrado autenticado, derivación de clave resistente a GPU/ASIC, nonces únicos por bloque y borrado seguro de los archivos originales.

<div align="center">
  
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org/) 
[![XChaCha20-Poly1305](https://img.shields.io/badge/Cipher-XChaCha20--Poly1305-6B21A8?style=flat-square)](https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction) 
[![Scrypt KDF](https://img.shields.io/badge/KDF-Scrypt-0EA5E9?style=flat-square)](https://www.tarsnap.com/scrypt.html)
[![Created by](https://img.shields.io/badge/Created_by-AdZiBo-6C63FF?style=flat)](https://github.com/adzibo)

</div>

---
## 1️⃣ Características

- **Cifrado autenticado (AEAD)** — XChaCha20-Poly1305 garantiza confidencialidad e integridad en cada bloque
- **KDF resistente a fuerza bruta** — Scrypt con **`N=2^17`** dificulta ataques con GPU y hardware especializado
- **Nonces únicos por bloque** — Arquitectura **`[16B aleatorios] + [contador]`** elimina el riesgo de reutilización
- **AAD por bloque** — Protege contra ataques de reordenación de bloques cifrados
- **Procesamiento en paralelo** — Multiprocessing para directorios: escala a múltiples núcleos automáticamente
- **Escritura atómica** — Usa archivos temporales + **`rename()`** POSIX para evitar salidas corruptas
- **Borrado seguro** — Sobreescritura multi-pasada con datos criptográficamente aleatorios (**`os.urandom`**)
- **Detección de CoW** — Advierte si el filesystem es APFS/btrfs/ZFS antes de ejecutar **`--shred`**
- **Barra de progreso TTY-aware** — Solo se muestra en terminales reales; silenciosa en pipes y scripts
- **Limpieza de contraseña en memoria** — **`bytearray`** mutable sobrescrito explícitamente al finalizar

---
## 2️⃣ Requisitos Previos:

> ### 🚀 **pipx**:
> Realizaremos la instalación de **`vaultenc`** mediante **pipx** [^1]
> 
> Puedes verificar si **pipx** está instalado ejecutando **`which pipx`**, o en su defecto, instalarlo ejecutando los siguientes comandos:
>```shell
>sudo apt install pipx
>```
>```shell
>pipx ensurepath
>```
>Ejecutar **`pipx ensurepath`** después de la instalación, es necesario para añadir el directorio de ejecutables de pipx a la variable de entorno PATH, permitiendo a la terminal reconocer y ejecutar las aplicaciones instaladas desde cualquier ubicación.
>
>El **reinicio de la terminal** es indispensable para que la shell recargue los archivos de configuración actualizados y aplique estos cambios.

---
## 3️⃣ Instalación:

⚪ Clona el repositorio y accede a él:

```shell
git clone https://github.com/adzibo/VaultEncripter.git
cd VaultEncripter
```

⚪ Instala la herramienta VaultEncripter ejecutando el siguiente comando de pipx:

```shell
pipx install .
```
---
## 4️⃣ Dependencias que instalará pipx:

> ### 🔑 **cryptography**
> **`cryptography`** [^2] se usa solo para **`Scrypt KDF`**, el algoritmo de derivación de clave.<br>
> Lo implementa de forma nativa y es la opción estándar en Python.

> ### 🔒 **pynacl**
> **`pynacl`** [^3] se usa solo para **`XChaCha20-Poly1305`**, el algoritmo de cifrado. 

---
## 5️⃣ Uso:

### Modos Principales:

| Flag            | Descripción                        |
| --------------- | ---------------------------------- |
| `-c, --encrypt` | Cifrar archivo(s)                  |
| `-d, --decrypt` | Descifrar archivo(s)               |
| `--verify`      | Verificar integridad sin descifrar |
### Opciones:

| Flag              | Descripción                                 |
| ----------------- | ------------------------------------------- |
| `-o, --output`    | PATH y nombre de salida                     |
| `-r, --recursive` | Procesar directorios recursivamente         |
| `-j, --jobs Nº`   | Número de procesos en paralelo              |
| `--shred`         | Borrar el original tras cifrar              |
| `--verify-after`  | Verificar el cifrado antes de hacer --shred |
| `-v, --verbose`   | Modo debug                                  |
### Comandos de Ejemplo:

🔴 Cifrar un archivo:

```bash
vaultenc -c informe.pdf
# -> informe.pdf.encrypted (añade extensión .encrypted)
```

🔴 Descifrar un archivo:

```bash
vaultenc -d informe.pdf.encrypted
# -> informe.pdf (quita extensión .encrypted)
```

🔴 Verificar integridad sin descifrar:

```bash
vaultenc --verify informe.pdf.encrypted
```

🔴 Cifrar + verificar + borrar original + PATH + renombrar archivo:

```bash
vaultenc -c informe.pdf --verify-after --shred -o ~/Downloads/documento.enc
```

⚪ Cifrar un directorio completo en paralelo:

```bash
vaultenc -cr docs
# -> docs.enc (añade extensión .enc)
```

⚪ Descifrar directorio:

```bash
vaultenc -dr docs.enc
# -> docs.enc.dec (añade extensión .dec)
```

⚪ Cifrar un directorio completo (con 8 workers y salida personalizada):

```bash
vaultenc -cr docs -o backup_enc -j 8
# -> backup_enc
```

⚪ Descifrar un directorio completo (con 8 workers y salida personalizada):

```bash
vaultenc -dr backup_enc -o backup -j 8
# -> backup
```

⚫ Comando HELP:

```bash
vaultenc -h
```

---
## 6️⃣ Stack criptográfico

| Componente              | Elección                    | Justificación                                                 |
| ----------------------- | --------------------------- | ------------------------------------------------------------- |
| Cifrado                 | XChaCha20-Poly1305          | AEAD moderno, nonce de 192 bits elimina el riesgo de colisión |
| KDF                     | Scrypt (`N=2^17, r=8, p=1`) | Memory-hard, resistente a GPU/ASIC                            |
| Salt                    | 32 bytes — `os.urandom`     | Único por archivo, previene rainbow tables                    |
| Nonce base              | 24 bytes — `os.urandom`     | Único por archivo, derivado por bloque con contador           |
| Autenticación adicional | Índice de bloque (AAD)      | Previene ataques de reordenación                              |
| Aleatoriedad            | `os.urandom` (CSPRNG)       | Fuente criptográficamente segura del SO                       |

---
## Modelo de amenazas

VaultEnc está diseñado para proteger contra:

- ✅ Atacante con acceso físico o de lectura al disco (archivos en reposo)
- ✅ Modificación o corrupción del archivo cifrado (detectada por Poly1305)
- ✅ Ataques de reordenación de bloques (mitigado con AAD por índice)
- ✅ Ataques de fuerza bruta offline (mitigado por Scrypt `N=2^17`)
- ✅ Recuperación del original tras borrado (mitigado con `--shred`)

**Fuera del alcance / limitaciones conocidas:**

- ❌ Python no garantiza borrado completo de strings en memoria (GC, objetos inmutables)
- ❌ `--shred` no es efectivo en SSDs con wear leveling ni en filesystems CoW (APFS, btrfs, ZFS); VaultEnc lo detecta y advierte
- ❌ En modo directorio, todos los archivos comparten la misma clave maestra derivada; comprometer la clave compromete el directorio completo

⚠️ Para maximizar la seguridad, complementar con cifrado de disco completo (FileVault, LUKS, BitLocker).<br>
⚠️ **`vaultenc`** está diseñado y testeado para funcionar en sistemas Linux/Unix.

---
<div align="center">

**Created by AdZiBo**

[![GitHub](https://img.shields.io/badge/GitHub-adzibo-181717?style=flat&logo=github)](https://github.com/adzibo)

</div>


[^1]: **`pipx`** es una herramienta de línea de comandos del ecosistema de Python que permite instalar y ejecutar aplicaciones Python en entornos virtuales aislados. Desarrollado bajo la Python Packaging Authority, facilita el uso de herramientas de consola sin interferir con las dependencias del sistema o de otros proyectos.

[^2]: **`cryptography`** es una librería de Python que ofrece herramientas criptográficas de alto y bajo nivel: cifrado, firmas, certificados, hashing, y también funciones de derivación de claves. Es mantenida por la Python Software Foundation y es la más usada en el ecosistema Python.

[^3]: **`pynacl`** es un binding de Python sobre libsodium, una librería escrita en C especializada en primitivas criptográficas modernas y de alto rendimiento.
