#!/usr/bin/env python3

# ── Módulos Estándar de Python ────────────────────────────────────────────────────────────────────────────────────────

import os
import sys
import struct
import getpass
import argparse
import logging
import tempfile
import time
import threading
import multiprocessing
from pathlib import Path

# ── Módulos Criptografía ──────────────────────────────────────────────────────────────────────────────────────────────

# KDF (derivación de clave segura desde contraseña)
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# Excepción de errores criptográficos.
from nacl.exceptions import CryptoError

# Primitivas de cifrado autenticado (AEAD: cifrado + integridad)
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
    crypto_aead_xchacha20poly1305_ietf_ABYTES
)

# ── Constantes Principales ────────────────────────────────────────────────────────────────────────────────────────────

MAGIC = b"VLT1" # Identificador del formato del archivo
VERSION = 1     # Versión del formato del archivo cifrado
SALT_SIZE = 32  # Tamaño del salt (un salt grande evita ataques precomputados)

NONCE_SIZE = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES   # Tamaño del nonce para XChaCha20
KEY_SIZE = crypto_aead_xchacha20poly1305_ietf_KEYBYTES      # Tamaño de la clave criptográfica
TAG_SIZE = crypto_aead_xchacha20poly1305_ietf_ABYTES        # Tamaño del tag de autenticación

CHUNK_SIZE = 1024 * 1024  # Tamaño de cada bloque de datos procesado

# ── Parámetros de Derivación de Clave ─────────────────────────────────────────────────────────────────────────────────

SCRYPT_N = 2 ** 17  # Coste computacional (CPU/memoria)
SCRYPT_R = 8        # Parámetro de memoria (afecta consumo RAM del algoritmo)
SCRYPT_P = 1        # Parámetro de paralelización interna

# ── Configuración General ─────────────────────────────────────────────────────────────────────────────────────────────

ENCRYPT_EXT = ".encrypted"
LOG_FORMAT  = "%(levelname)-8s %(message)s"

logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
log = logging.getLogger("vault")


# ── XChaCha20Poly1305 Thin Wrappers ───────────────────────────────────────────────────────────────────────────────────

def _xchacha_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """
    Cifra datos utilizando XChaCha20-Poly1305 (AEAD).

    Esta función es un wrapper ligero sobre la implementación de PyNaCl.
    Realiza cifrado autenticado, lo que significa que:
        - Protege la confidencialidad (los datos no pueden leerse).
        - Protege la integridad (los datos no pueden modificarse sin detectarlo).

    Parámetros:
        key (bytes): Clave secreta de 32 bytes.
        nonce (bytes): Nonce único de 24 bytes (no debe repetirse con la misma clave).
        plaintext (bytes): Datos a cifrar.
        aad (bytes): Datos autenticados adicionales (no se cifran, pero se validan).

    Retorna:
        bytes: Datos cifrados junto con el tag de autenticación (16 bytes).

    Seguridad:
        - El nonce debe ser único por cada operación con la misma clave.
        - El AAD se usa para proteger metadatos (por ejemplo, el índice de bloque).
    """
    return crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext,
        aad,
        nonce,
        key
    )


def _xchacha_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    """
    Descifra datos utilizando XChaCha20-Poly1305 (AEAD) y verifica su integridad.

    Esta función valida automáticamente el tag de autenticación. Si los datos
    han sido modificados o la contraseña es incorrecta, la operación falla.

    Parámetros:
        key (bytes): Clave secreta de 32 bytes.
        nonce (bytes): Nonce utilizado durante el cifrado.
        ciphertext (bytes): Datos cifrados (incluye el tag de autenticación).
        aad (bytes): Datos autenticados adicionales (deben coincidir exactamente).

    Retorna:
        bytes: Datos descifrados (plaintext).

    Excepciones:
        nacl.exceptions.CryptoError:
            - Si el tag de autenticación no es válido.
            - Si el nonce, la clave o el AAD no coinciden.
            - Si los datos han sido manipulados o la contraseña es incorrecta.

    Seguridad:
        - No devuelve datos si la verificación falla.
        - Garantiza que los datos no han sido alterados.
    """
    return crypto_aead_xchacha20poly1305_ietf_decrypt(
        ciphertext,
        aad,
        nonce,
        key
    )


# ── Barra de Progreso ─────────────────────────────────────────────────────────────────────────────────────────────────

class ProgressBar:
    """
    Barra de progreso segura para hilos (thread-safe) y consciente del entorno (TTY-aware).

    Esta clase muestra el progreso de una operación junto a métricas útiles como:
        - porcentaje completado
        - bytes procesados
        - velocidad de procesamiento (throughput)

    Características clave:
        - Thread-safe: puede usarse desde múltiples hilos sin corrupción de estado.
        - TTY-aware: solo renderiza si la salida es un terminal real.
          (evita ensuciar la salida en pipes o scripts automatizados).
        - No intrusiva: si no hay TTY, no muestra nada.
    """
    BAR_WIDTH = 30  # Anchura de la barra visual (número de caracteres)

    def __init__(self, total: int, label: str = ""):
        self._total = max(total, 1)     # Total de bytes (evita división por cero)
        self._label = label             # Etiqueta mostrada en la barra
        self._done = 0                  # Bytes procesados hasta el momento
        self._start = 0.0               # Tiempo de inicio (se inicializa en __enter__)
        self._lock = threading.Lock()   # Lock para garantizar seguridad en entornos concurrentes
        self._tty = sys.stderr.isatty() # Detectar si stderr es un terminal real

    def __enter__(self):
        """
        Inicializa el temporizador y prepara la barra de progreso.
        Se ejecuta al entrar en el bloque `with`.
        """
        self._start = time.monotonic()

        # Añade una línea inicial para que la barra no sobrescriba output previo
        if self._tty:
            sys.stderr.write("\n")

        return self

    def __exit__(self, *_):
        """
        Finaliza la barra de progreso.
        Fuerza la visualización al 100% y añade un salto de línea final limpio.
        """
        if self._tty:
            self._render(force_done=True)
            sys.stderr.write("\n")

    def update(self, n: int) -> None:
        """
        Actualiza el progreso acumulado.
        """
        # Sección crítica protegida (thread-safe)
        with self._lock:
            self._done += n

        # Solo renderiza si estamos en un terminal
        if self._tty:
            self._render()

    def _render(self, force_done: bool = False) -> None:
        """
        Renderiza la barra de progreso en la terminal.
        """
        # Determinar progreso actual
        done = self._done if not force_done else self._total
        # Porcentaje completado
        pct = done / self._total
        # Tiempo transcurrido desde el inicio
        elapsed = time.monotonic() - self._start + 1e-9
        # Velocidad de procesamiento (bytes por segundo)
        speed = done / elapsed

        # Construcción visual de la barra
        filled = int(self.BAR_WIDTH * pct)
        bar = "█" * filled + "░" * (self.BAR_WIDTH - filled)

        # Formateo legible de valores
        speed_str = _fmt_bytes(speed) + "/s"
        done_str = _fmt_bytes(done)
        total_str = _fmt_bytes(self._total)

        # Línea completa de salida
        line = (
            f"\r  {self._label:<14} [{bar}] "
            f"{pct:5.1%}  {done_str}/{total_str}  {speed_str}  "
        )

        # Escribir en stderr (misma línea gracias a '\r')
        sys.stderr.write(line)
        sys.stderr.flush()


# ── Formateo de Bytes ─────────────────────────────────────────────────────────────────────────────────────────────────

def _fmt_bytes(n: float) -> str:
    """
    Convierte un número de bytes en una representación legible para humanos.

    Ejemplos:
        1024 → "1.0 KB"
        1048576 → "1.0 MB"
        1536000 → "1.5 MB"

    Parámetros:
        n (float): Cantidad en bytes.

    Retorna:
        str: Cadena formateada con la unidad adecuada.
    """
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024

    # Para tamaños extremadamente grandes
    return f"{n:.1f} PB"


# ── Derivación de Claves ──────────────────────────────────────────────────────────────────────────────────────────────

def derive_key(password: bytes, salt: bytes) -> bytes:
    """
    Deriva una clave criptográfica de 256 bits a partir de una contraseña usando Scrypt.

    Esta función transforma una contraseña proporcionada por el usuario en una
    clave segura adecuada para cifrado simétrico. Utiliza el algoritmo Scrypt,
    diseñado para ser resistente a ataques de fuerza bruta, especialmente en
    hardware especializado (GPU, ASIC).

    Flujo:
        1. Se configura Scrypt con los parámetros definidos (coste computacional).
        2. Se combina la contraseña con un salt único.
        3. Se genera una clave derivada de 32 bytes (256 bits).

    Parámetros:
        password (bytes): Contraseña en formato binario.
        salt (bytes): Valor aleatorio único por archivo.

    Retorna:
        bytes: Clave derivada de 32 bytes lista para uso criptográfico.

    Seguridad:
        - El uso de salt evita ataques con tablas precomputadas (rainbow tables).
        - Scrypt es memory-hard → dificulta ataques con GPU/ASIC.
        - Los parámetros (N, r, p) determinan el coste del ataque.

    Nota:
        Cada archivo usa un salt distinto, por lo que la misma contraseña
        genera claves diferentes en cada caso.
    """
    # Configuración del algoritmo de derivación de clave (KDF)
    kdf = Scrypt(
        salt=salt,
        length=KEY_SIZE,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P
    )

    # Derivar la clave a partir de la contraseña
    return kdf.derive(password)


# ── Eliminación Segura ────────────────────────────────────────────────────────────────────────────────────────────────

def shred_file(path: Path, passes: int = 3) -> None:
    """
    Sobrescribe un archivo con datos aleatorios múltiples veces y luego lo elimina.

    Esta función intenta dificultar la recuperación del contenido original del
    archivo sobrescribiéndolo varias veces con datos aleatorios antes de borrarlo.

    Flujo:
        1. Se obtiene el tamaño del archivo.
        2. Se sobrescribe completamente con datos aleatorios (varias pasadas).
        3. Se fuerza la escritura en disco (flush + fsync).
        4. Se elimina el archivo.

    Parámetros:
        path (Path): Ruta del archivo a eliminar de forma segura.
        passes (int): Número de pasadas de sobrescritura (por defecto: 3).

    Seguridad:
        - Aumentar el número de pasadas incrementa la dificultad de recuperación.
        - Cada pasada usa datos aleatorios criptográficamente seguros.

    Limitaciones importantes:
        - En SSD modernos (wear leveling) el sistema puede escribir en bloques distintos.
        - En sistemas Copy-on-Write (btrfs, ZFS, APFS) no se garantiza sobrescritura real.
        - En estos casos, el contenido original podría seguir existiendo físicamente.

    Recomendación:
        - Usar cifrado de disco completo (Full Disk Encryption) como complemento.
        - No confiar exclusivamente en shred en sistemas modernos.

    Nota:
        Esta función es una medida "best-effort", no una garantía absoluta.
    """
    size = path.stat().st_size  # Obtener tamaño del archivo

    # Abrir archivo en modo lectura/escritura binaria
    with open(path, "r+b") as f:
        # Repetir el proceso de sobrescritura varias veces
        for _ in range(passes):
            f.seek(0)
            remaining = size

            # Sobrescribir en bloques para no usar demasiada memoria
            while remaining > 0:
                chunk = min(remaining, CHUNK_SIZE)
                f.write(os.urandom(chunk)) # Escribir datos aleatorios criptográficamente seguros
                remaining -= chunk

            # Asegurar que los datos se escriben físicamente en disco
            f.flush()
            os.fsync(f.fileno())

    # Eliminar el archivo del sistema de ficheros
    path.unlink()


# ── Derivación del Nonce por Bloque ───────────────────────────────────────────────────────────────────────────────────

def _chunk_nonce(nonce_base: bytes, index: int) -> bytes:
    """
    Genera un nonce único de 24 bytes para un bloque concreto.

    Esta función construye un nonce determinista pero único para cada bloque
    de datos, a partir de un valor base aleatorio generado por archivo.

    Estructura del nonce: [16 bytes aleatorios] + [contador de bloque (uint64 big-endian)]

    Donde:
        - Los primeros 16 bytes provienen de nonce_base (aleatorio por archivo).
        - Los últimos 8 bytes representan el índice del bloque.

    Parámetros:
        nonce_base (bytes): Nonce base generado aleatoriamente por archivo.
        index (int): Índice del bloque (chunk).

    Retorna:
        bytes: Nonce único de 24 bytes.

    Seguridad:
        - Garantiza unicidad del nonce dentro del archivo.
        - Evita reutilización de nonce con la misma clave (crítico en AEAD).
        - El contador impide colisiones entre bloques.
        - Los 16 bytes aleatorios aseguran unicidad entre archivos.

    IMPORTANTE:
        - Reutilizar un nonce con la misma clave rompe completamente la seguridad.
        - Esta función es crítica para la seguridad del sistema.
    """
    # Construcción del nonce:
    # - Primeros 16 bytes: aleatorios (por archivo)
    # - Últimos 8 bytes: índice del bloque (contador)
    return nonce_base[:16] + struct.pack(">Q", index)


# ======================================================================================================================
# CIFRADO
# ======================================================================================================================

def encrypt_file(
    input_path:    Path,
    output_path:   Path,
    password:      bytes,
    progress:      bool  = False,
    precomputed_key: bytes | None = None,
) -> None:
    """
    Cifra un archivo de entrada y genera un archivo de salida en formato vault.

    El archivo resultante contiene tanto los datos cifrados como la información
    necesaria para poder descifrarlos posteriormente.

    Formato del archivo generado:
        [MAGIC 4B][VERSION 1B][SALT 32B][NONCE_BASE 24B]
        ( [CHUNK_LEN 4B][CIPHERTEXT + TAG 16B] ) * N

    Donde:
        - MAGIC: Identificador del formato del archivo.
        - VERSION: Versión del formato para compatibilidad futura.
        - SALT: Valor aleatorio usado en la derivación de clave (Scrypt).
        - NONCE_BASE: Base para generar nonces únicos por cada bloque.
        - CHUNK_LEN: Tamaño del bloque cifrado.
        - CIPHERTEXT+TAG: Datos cifrados junto con su autenticación (Poly1305).

    Parámetros:
        input_path (Path): Ruta del archivo original a cifrar.
        output_path (Path): Ruta donde se guardará el archivo cifrado.
        password (bytes): Contraseña en formato binario.
        progress (bool): Si es True, muestra barra de progreso.
        precomputed_key (bytes|None): Clave ya derivada.

    Seguridad:
        - Cada archivo usa un salt distinto → protege contra ataques de diccionario.
        - Cada bloque usa un nonce único → evita reutilización peligrosa.
        - Se usa AEAD (XChaCha20-Poly1305) → confidencialidad + integridad.
        - Se usa AAD con el índice del bloque → evita ataques de reordenación.
        - En modo directorio, la contraseña nunca sale del proceso principal.

    Notas de implementación:
        - Se escribe primero en un archivo temporal para evitar corrupción.
        - Solo se reemplaza el archivo final si todo el proceso termina correctamente.
        - Se emite un warning si el archivo de salida ya existe.
    """

    # ── AVISO DE SOBRESCRITURA ────────────────────────────────────────────────────────────────────────────────────────

    # Avisar si el destino ya existe (el reemplazo final es atómico pero irreversible)
    if output_path.exists():
        log.warning("Output file already exists and will be overwritten: %s", output_path)

    # Obtener tamaño total del archivo y etiqueta para mostrar en la barra de progreso.
    total = input_path.stat().st_size
    label = input_path.name[:14]

    # Crear archivo temporal en el mismo directorio de salida.
    # Usar el mismo directorio garantiza que el rename final sea atómico
    # (mismo filesystem) y evita dejar archivos corruptos si el proceso falla.
    tmp_fd, tmp_name = tempfile.mkstemp(
        dir=output_path.parent,
        prefix=".vault_tmp_"
    )

    # ── DERIVACIÓN DE CLAVE ───────────────────────────────────────────────────────────────────────────────────────────

    # En modo directorio se recibe la clave ya derivada
    # (no viaja la contraseña por IPC). En modo archivo único se deriva aquí normalmente.
    salt = os.urandom(SALT_SIZE)  # Salt único por archivo (necesario para el formato)

    if precomputed_key is not None:
        key = precomputed_key   # Modo directorio: usar clave precomputada
    else:
        key = derive_key(password, salt)  # Modo archivo único: derivar desde la contraseña

    # Nonce base aleatorio; los nonces por bloque se derivan de él
    nonce_base = os.urandom(NONCE_SIZE)

    try:
        # Abrir archivo temporal de salida y archivo de entrada simultáneamente
        with open(tmp_fd, "wb") as fout, open(input_path, "rb") as fin:

            # ── ESCRITURA DE CABECERA ─────────────────────────────────────────────────────────────────────────────────

            fout.write(MAGIC) # Identificador del formato (4 bytes)
            fout.write(struct.pack("B", VERSION)) # Versión del formato (1 byte)
            fout.write(salt) # Salt para derivación de clave (32 bytes)
            fout.write(nonce_base) # Base de nonces por bloque (24 bytes)

            # Configurar barra de progreso (o versión nula si no hay TTY)
            pb_ctx = ProgressBar(total, label=label) if progress else _NullProgress()

            with pb_ctx as pb:

                # ── PROCESAMIENTO POR BLOQUES ─────────────────────────────────────────────────────────────────────────

                for chunk, idx in _chunk_iter(fin):
                    nonce = _chunk_nonce(nonce_base, idx) # Nonce único para este bloque
                    aad = struct.pack(">Q", idx) # AAD: protege el orden de los bloques
                    ct = _xchacha_encrypt(key, nonce, chunk, aad) # Cifrar

                    fout.write(struct.pack(">I", len(ct))) # Longitud del bloque cifrado (4 bytes)
                    fout.write(ct) # Datos cifrados + tag Poly1305
                    pb.update(len(chunk)) # Actualizar barra de progreso

        # ── REEMPLAZO ATÓMICO ─────────────────────────────────────────────────────────────────────────────────────────

        # Solo se ejecuta si todo el proceso ha terminado sin errores.
        # rename() es atómico en POSIX: nunca deja un estado intermedio visible.
        Path(tmp_name).replace(output_path)

    except Exception:
        try: # Si ocurre cualquier error, eliminar el temporal para no dejar basura en disco
            os.unlink(tmp_name)
        except OSError:
            pass
        raise  # Propagar la excepción para que sea manejada en niveles superiores


# ======================================================================================================================
# DESCIFRADO
# ======================================================================================================================

def decrypt_file(
    input_path:      Path,
    output_path:     Path,
    password:        bytes,
    progress:        bool  = False,
    precomputed_key: bytes | None = None,
) -> None:
    """
    Descifra un archivo en formato vault y reconstruye el archivo original.

    Esta función realiza el proceso inverso a `encrypt_file`, leyendo la estructura
    del archivo cifrado, derivando la clave a partir de la contraseña y descifrando
    cada bloque de datos de forma independiente.

    Flujo general:
        1. Validar cabecera del archivo (MAGIC y VERSION).
        2. Leer y validar parámetros de cabecera (salt y nonce_base).
        3. Derivar la clave a partir de la contraseña (o usar la precomputada).
        4. Leer y descifrar cada bloque (chunk) secuencialmente.
        5. Escribir el contenido descifrado en un archivo temporal.
        6. Reemplazar el archivo final si todo ha ido correctamente.

    Parámetros:
        input_path (Path): Ruta del archivo cifrado (.encrypted).
        output_path (Path): Ruta donde se guardará el archivo descifrado.
        password (bytes): Contraseña en formato binario.
        progress (bool): Si es True, muestra barra de progreso.
        precomputed_key (bytes|None): Clave ya derivada.

    Excepciones (ValueError):
        - Si el archivo no tiene el formato esperado (MAGIC incorrecto).
        - Si la versión no es compatible.
        - Si la cabecera está truncada (salt o nonce_base incompletos).
        - Si el archivo está truncado o corrupto.
        - Si la contraseña es incorrecta (fallo de autenticación).

    Seguridad:
        - Se valida el formato antes de procesar datos.
        - Se valida la longitud exacta de cada campo de la cabecera.
        - Se usa AEAD (XChaCha20-Poly1305) cualquier modificación provoca un fallo de autenticación.
        - Se usa AAD (índice de bloque) para evitar ataques de reordenación.
        - No se escribe nada en el archivo final hasta que todo ha sido validado.
        - En modo directorio, la contraseña nunca sale del proceso principal.

    Notas de implementación:
        - Se utiliza un archivo temporal para evitar dejar archivos corruptos.
        - La integridad se verifica bloque a bloque durante el descifrado.
        - Se emite un warning si el archivo de salida ya existe.
    """

    # ── AVISO DE SOBRESCRITURA ────────────────────────────────────────────────────────────────────────────────────────

    # Avisar si el destino ya existe antes de sobreescribirlo
    if output_path.exists():
        log.warning("Output file already exists and will be overwritten: %s", output_path)

    # Obtener tamaño total del archivo y etiqueta para la barra de progreso.
    total = input_path.stat().st_size
    label = input_path.name[:14]

    # Crear archivo temporal en el directorio de salida para escritura segura.
    tmp_fd, tmp_name = tempfile.mkstemp(
        dir=output_path.parent,
        prefix=".vault_tmp_"
    )

    try:
        with open(input_path, "rb") as fin:

            # ── VALIDACIÓN DE CABECERA ────────────────────────────────────────────────────────────────────────────────

            # Verificar identificador mágico del formato
            if fin.read(4) != MAGIC:
                raise ValueError("Not a vault file (bad magic bytes)")

            # Verificar versión del formato para compatibilidad futura
            version_data = fin.read(1)
            if len(version_data) != 1:
                raise ValueError("Truncated header: version field missing")
            version = struct.unpack("B", version_data)[0]
            if version != VERSION:
                raise ValueError(f"Unsupported vault version: {version}")

            # ── LECTURA Y VALIDACIÓN DE PARÁMETROS CRIPTOGRÁFICOS ─────────────────────────────────────────────────────

            # Validar longitud exacta: un salt truncado derivaría una clave distinta
            # y fallaría la autenticación con un error confuso.
            salt = fin.read(SALT_SIZE)
            if len(salt) != SALT_SIZE:
                raise ValueError(
                    f"Truncated header: expected {SALT_SIZE}B salt, "
                    f"got {len(salt)}B"
                )

            nonce_base = fin.read(NONCE_SIZE)
            if len(nonce_base) != NONCE_SIZE:
                raise ValueError(
                    f"Truncated header: expected {NONCE_SIZE}B nonce_base, "
                    f"got {len(nonce_base)}B"
                )

            # ── DERIVACIÓN DE CLAVE ───────────────────────────────────────────────────────────────────────────────────

            # En modo directorio se usa la clave precomputada; en modo archivo
            # único se deriva normalmente con el salt leído de la cabecera.
            if precomputed_key is not None:
                key = precomputed_key
            else:
                key = derive_key(password, salt)

            # Configurar barra de progreso (o versión nula si no hay TTY)
            pb_ctx = ProgressBar(total, label=label) if progress else _NullProgress()

            # Abrir archivo temporal de salida
            with pb_ctx as pb, open(tmp_fd, "wb") as fout:

                index = 0

                # ── LECTURA Y DESCIFRADO DE BLOQUES ───────────────────────────────────────────────────────────────────

                while True:
                    # Leer campo de longitud del siguiente bloque (4 bytes, big-endian)
                    size_data = fin.read(4)

                    if not size_data:
                        break  # Fin de archivo legítimo → salir del bucle

                    if len(size_data) != 4:
                        raise ValueError("Truncated chunk length field")

                    size = struct.unpack(">I", size_data)[0]
                    ciphertext = fin.read(size)

                    if len(ciphertext) != size:
                        raise ValueError("Truncated ciphertext chunk")

                    # ── DESCIFRADO Y VERIFICACIÓN DE AUTENTICIDAD ─────────────────────────────────────────────────────

                    # Reconstruir exactamente los mismos parámetros usados al cifrar
                    nonce = _chunk_nonce(nonce_base, index) # Mismo nonce que en encrypt_file
                    aad = struct.pack(">Q", index)  # Mismo AAD que en encrypt_file

                    try:
                        plaintext = _xchacha_decrypt(key, nonce, ciphertext, aad)

                    except CryptoError:
                        # CryptoError indica: contraseña incorrecta, datos modificados,
                        # o nonce/AAD que no coinciden con los del cifrado.
                        raise ValueError(
                            "Decryption failed — wrong password or corrupted file"
                        )

                    fout.write(plaintext)  # Volcar bloque descifrado al temporal
                    pb.update(size)        # Progresar usando el tamaño cifrado leído
                    index += 1

        # ── REEMPLAZO ATÓMICO ─────────────────────────────────────────────────────────────────────────────────────────

        # Solo se ejecuta si TODOS los bloques han sido descifrados y validados.
        Path(tmp_name).replace(output_path)

    except Exception:
        try: # Si ocurre cualquier error, eliminar el temporal para no dejar basura
            os.unlink(tmp_name)
        except OSError:
            pass
        raise  # Propagar para manejo en niveles superiores


# ======================================================================================================================
# VERIFICACIÓN DE ARCHIVO
# ======================================================================================================================

def verify_file(
    input_path:      Path,
    password:        bytes,
    progress:        bool  = False,
    precomputed_key: bytes | None = None,
) -> None:
    """
    Verifica la integridad de un archivo cifrado sin generar ningún archivo de salida.

    Esta función recorre todo el archivo vault, descifrando cada bloque en memoria
    únicamente para comprobar su autenticidad, pero sin guardar el resultado en disco.

    Es útil para:
        - Confirmar que la contraseña es correcta.
        - Detectar corrupción o manipulación del archivo.
        - Validar el archivo antes de eliminar el original (por ejemplo, tras cifrado).

    Flujo general:
        1. Validar cabecera del archivo (MAGIC y VERSION).
        2. Leer y validar parámetros de cabecera (salt y nonce_base).
        3. Derivar la clave a partir de la contraseña (o usar precomputada).
        4. Recorrer todos los bloques cifrados.
        5. Intentar descifrar cada bloque (sin guardar el resultado).
        6. Si todos los bloques pasan la validación → archivo íntegro.

    Parámetros:
        input_path (Path): Ruta del archivo cifrado (.encrypted).
        password (bytes): Contraseña en formato binario.
        progress (bool): Si es True, muestra barra de progreso.
        precomputed_key (bytes|None): Clave ya derivada.

    ValueError:
        - Si el archivo no es válido (MAGIC incorrecto).
        - Si la versión no es compatible.
        - Si la cabecera está truncada (salt o nonce_base incompletos).
        - Si el archivo está truncado.
        - Si la contraseña es incorrecta.
        - Si algún bloque ha sido manipulado.

    Seguridad:
        - Usa AEAD (XChaCha20-Poly1305): cada bloque incluye autenticación.
        - Si cualquier byte del archivo cambia, la verificación falla.
        - No se escribe nada en disco → operación segura y no destructiva.
        - Se valida la longitud exacta de cada campo de la cabecera.

    Nota:
        Esta función es esencial cuando se usa la opción --shred, ya que permite
        asegurarse de que el archivo cifrado es válido antes de borrar el original.
    """
    # Obtener tamaño total y etiqueta para la barra de progreso
    total = input_path.stat().st_size
    label = input_path.name[:14]

    with open(input_path, "rb") as fin:

        # ── VALIDACIÓN DE CABECERA ────────────────────────────────────────────────────────────────────────────────────

        if fin.read(4) != MAGIC:
            raise ValueError("Not a vault file (bad magic bytes)")

        version_data = fin.read(1)
        if len(version_data) != 1:
            raise ValueError("Truncated header: version field missing")

        version = struct.unpack("B", version_data)[0]
        if version != VERSION:
            raise ValueError(f"Unsupported vault version: {version}")

        # ── LECTURA Y VALIDACIÓN DE PARÁMETROS CRIPTOGRÁFICOS ─────────────────────────────────────────────────────────

        # Validar longitud exacta: un salt truncado derivaría una clave distinta
        # y fallaría la autenticación con un error confuso.
        salt = fin.read(SALT_SIZE)
        if len(salt) != SALT_SIZE:
            raise ValueError(
                f"Truncated header: expected {SALT_SIZE}B salt, "
                f"got {len(salt)}B"
            )

        nonce_base = fin.read(NONCE_SIZE)
        if len(nonce_base) != NONCE_SIZE:
            raise ValueError(
                f"Truncated header: expected {NONCE_SIZE}B nonce_base, "
                f"got {len(nonce_base)}B"
            )

        # ── DERIVACIÓN DE CLAVE ───────────────────────────────────────────────────────────────────────────────────────

        # En modo directorio se usa la clave precomputada; en modo archivo
        # único se deriva normalmente con el salt de la cabecera.
        if precomputed_key is not None:
            key = precomputed_key
        else:
            key = derive_key(password, salt)

        # Configurar barra de progreso (o versión nula si no hay TTY)
        pb_ctx = ProgressBar(total, label=label) if progress else _NullProgress()

        with pb_ctx as pb:
            index = 0

            # ── VERIFICACIÓN BLOQUE A BLOQUE ──────────────────────────────────────────────────────────────────────────

            while True:
                size_data = fin.read(4)

                if not size_data:
                    break  # Fin de archivo legítimo

                if len(size_data) != 4:
                    raise ValueError("Truncated chunk length field")

                size = struct.unpack(">I", size_data)[0]
                ciphertext = fin.read(size)

                if len(ciphertext) != size:
                    raise ValueError("Truncated ciphertext chunk")

                # Reconstruir nonce y AAD con los mismos parámetros del cifrado
                nonce = _chunk_nonce(nonce_base, index)
                aad = struct.pack(">Q", index)

                # ── VALIDACIÓN CRIPTOGRÁFICA ──────────────────────────────────────────────────────────────────────────

                # Se descifra en memoria únicamente para verificar el tag Poly1305.
                # El resultado se descarta inmediatamente (sin escritura en disco).
                try:
                    _xchacha_decrypt(key, nonce, ciphertext, aad)

                except CryptoError:
                    raise ValueError(
                        f"Integrity check failed at chunk {index} — "
                        "wrong password or file has been tampered with"
                    )

                pb.update(size)
                index += 1


# ── Barra de Progreso Nula ────────────────────────────────────────────────────────────────────────────────────────────

class _NullProgress:
    """
    Implementación "vacía" de la barra de progreso.

    Esta clase actúa como sustituto de `ProgressBar` cuando:
        - El usuario desactiva el progreso (progress=False).
        - La salida no es un terminal (no TTY).

    Su objetivo es permitir que el código use siempre la misma interfaz
    (context manager + método update) sin tener que añadir condicionales
    en cada punto del flujo.
    """
    def __enter__(self):
        """
        Permite usar la clase como context manager (`with`).
        Retorna:
            self: para mantener la misma interfaz que ProgressBar.
        """
        return self

    def __exit__(self, *_):
        """
        Método requerido por el context manager.
        No realiza ninguna acción.
        """
        pass

    def update(self, n: int):
        """
        Método de actualización del progreso.
        Parámetros:
            n (int): Número de bytes procesados.
        Comportamiento:
            No hace nada (no-op).
        """
        pass


# ── Iterador de Bloques (Chunk Iterator) ──────────────────────────────────────────────────────────────────────────────

def _chunk_iter(file_obj):
    """
    Itera sobre un archivo abierto devolviendo bloques de tamaño fijo.

    Esta función permite procesar archivos grandes sin cargarlos completamente
    en memoria. Divide el contenido en fragmentos (chunks) de tamaño CHUNK_SIZE.

    Flujo:
        1. Lee un bloque del archivo.
        2. Si está vacío → fin del archivo.
        3. Devuelve el bloque junto con su índice.
        4. Repite hasta terminar.

    Parámetros:
        file_obj: Objeto de archivo abierto en modo binario.

    Tuple:
        - chunk (bytes): Fragmento de datos leído.
        - index (int): Índice del bloque (0, 1, 2, ...).

    Ventajas:
        - Permite trabajar con archivos grandes (streaming).
        - Evita consumo excesivo de memoria.
        - Facilita el cifrado por bloques (chunk-based encryption).

    El índice se usa posteriormente para:
        - generar nonces únicos por bloque
        - incluir AAD (datos autenticados)
    """
    index = 0

    while True:
        # Leer siguiente bloque
        chunk = file_obj.read(CHUNK_SIZE)

        # Si no hay datos → fin del archivo
        if not chunk:
            break

        # Devolver bloque + índice
        yield chunk, index
        index += 1


# ── Worker para Multiprocessing ───────────────────────────────────────────────────────────────────────────────────────

def _worker(task: tuple) -> tuple:
    """
    Función worker ejecutada en procesos paralelos.

    Esta función procesa una única tarea (archivo) dentro de un pool de
    multiprocessing. Está diseñada para ser "picklable", es decir, puede ser
    serializada y enviada a otros procesos.

    Entrada:
        task (tuple): (
            mode, → "encrypt" | "decrypt" | "verify"
            in_str, → ruta de entrada (string)
            out_str, → ruta de salida (string)
            key, → clave criptográfica derivada (bytes, no la contraseña)
            do_shred, → bool → eliminar original tras cifrar
            do_verify → bool → verificar tras cifrar
        )

    Flujo:
        1. Reconstruye objetos Path desde strings.
        2. Crea el directorio de salida si no existe.
        3. Ejecuta la operación según el modo:
            - encrypt → cifra con clave precomputada (+ opcional verify + shred)
            - decrypt → descifra con clave precomputada
            - verify → verifica integridad con clave precomputada
        4. Devuelve resultado estructurado.

    Retorna:
        tuple: (
            input_path (str),
            success (bool),
            error_msg (str) — vacío si success=True
        )

    Diseño:
        - Nunca lanza excepciones fuera → siempre devuelve resultado estructurado.
        - Permite al proceso principal gestionar errores sin romper el pool.
        - Aisla cada tarea (fault isolation).

    IMPORTANTE (multiprocessing):
        - Debe estar definida a nivel global (no dentro de otra función).
        - No debe capturar estado externo complejo (closures).
        - Solo usa tipos serializables con pickle.

    Nota:
        progress=False porque múltiples procesos escribiendo en terminal
        simultáneamente causarían salida corrupta e ilegible.
    """
    # Desempaquetar la tarea — key es la clave derivada, no la contraseña
    mode, in_str, out_str, key, do_shred, do_verify = task

    # Reconstruir rutas desde strings (los Path no son picklables de forma fiable)
    in_path = Path(in_str)
    out_path = Path(out_str)

    try:
        # Asegurar que el directorio de salida existe antes de escribir
        out_path.parent.mkdir(parents=True, exist_ok=True)

        # ── MODO CIFRADO ──────────────────────────────────────────────────────────────────────────────────────────────

        if mode == "encrypt":
            encrypt_file(
                in_path, out_path,
                password=b"", # ignorado cuando se provee precomputed_key
                progress=False,
                precomputed_key=key
            )

            # Verificación opcional tras cifrado (útil antes de hacer shred)
            if do_verify:
                verify_file(
                    out_path,
                    password=b"",
                    progress=False,
                    precomputed_key=key
                )

            # Borrado seguro del archivo original
            if do_shred:
                shred_file(in_path)

        # ── MODO DESCIFRADO ───────────────────────────────────────────────────────────────────────────────────────────

        elif mode == "decrypt":
            decrypt_file(
                in_path, out_path,
                password=b"",
                progress=False,
                precomputed_key=key
            )

        # ── MODO VERIFICACIÓN ─────────────────────────────────────────────────────────────────────────────────────────

        else:
            verify_file(
                in_path,
                password=b"",
                progress=False,
                precomputed_key=key
            )

        return (in_str, True, "")

    except Exception as exc:
        # Capturar cualquier error y devolverlo como resultado estructurado.
        # No relanzar: si un worker falla, el pool debe seguir con el resto.
        return (in_str, False, str(exc))


# ── Construcción de Tareas para Procesamiento Recursivo ───────────────────────────────────────────────────────────────

def _build_tasks(
    mode:       str,
    source_dir: Path,
    dest_dir:   Path,
    key:        bytes,
    do_shred:   bool,
    do_verify:  bool,
) -> list[tuple]:
    """
    Genera la lista de tareas a ejecutar para un procesamiento recursivo.

    Recorre el directorio de origen y construye una lista de trabajos
    (tasks) que serán ejecutados posteriormente en paralelo por workers.

    Cada tarea representa el procesamiento de un único archivo.

    Flujo:
        1. Recorre todos los archivos del directorio (recursivamente).
        2. Filtra según el modo de operación:
            - encrypt → ignora archivos ya cifrados (.encrypted)
            - decrypt → solo procesa archivos .encrypted
            - verify → solo procesa archivos .encrypted
        3. Calcula la ruta relativa del archivo.
        4. Genera la ruta de salida correspondiente.
        5. Construye la tupla de tarea.

    Parámetros:
        mode (str): "encrypt" | "decrypt" | "verify"
        source_dir (Path): Directorio de entrada
        dest_dir (Path): Directorio de salida
        key (bytes): Clave criptográfica precomputada (no la contraseña).
        do_shred (bool): Si se debe eliminar el original tras cifrar
        do_verify (bool): Si se debe verificar tras cifrar

    Retorna:
        list[tuple]: Lista de tareas para multiprocessing

    Diseño:
        - Separa la fase de planificación (tasks) de la ejecución.
        - Mantiene la estructura de directorios original (rel paths).
        - Evita reprocesar archivos innecesarios.
    """
    tasks = []

    # Recorrido recursivo ordenado (determinista y reproducible)
    for src in sorted(source_dir.rglob("*")):

        # Ignorar directorios, solo procesar archivos
        if not src.is_file():
            continue

        # Ruta relativa respecto al directorio origen (preserva la estructura)
        rel = src.relative_to(source_dir)

        # ── MODO CIFRADO ──────────────────────────────────────────────────────────────────────────────────────────────

        if mode == "encrypt":
            # Evitar cifrar archivos que ya tienen la extensión de vault
            if src.suffix == ENCRYPT_EXT:
                log.debug("Skipping already-encrypted: %s", rel)
                continue

            # Ruta de salida: misma estructura, añadiendo extensión de vault
            out = dest_dir / rel.with_suffix(rel.suffix + ENCRYPT_EXT)

        # ── MODO DESCIFRADO ───────────────────────────────────────────────────────────────────────────────────────────

        elif mode == "decrypt":
            # Solo procesar archivos con la extensión de vault
            if src.suffix != ENCRYPT_EXT:
                log.debug("Skipping non-vault: %s", rel)
                continue

            # Ruta de salida: misma estructura, eliminando extensión de vault
            out = dest_dir / rel.with_suffix("")

        # ── MODO VERIFICACIÓN ─────────────────────────────────────────────────────────────────────────────────────────

        else:
            # Solo verificar archivos con la extensión de vault
            if src.suffix != ENCRYPT_EXT:
                log.debug("Skipping non-vault: %s", rel)
                continue

            # En verificación no hay salida real; se usa src como placeholder
            out = src

        # Construcción de la tarea (serializable) — incluye la clave, no la contraseña
        tasks.append((mode, str(src), str(out), key, do_shred, do_verify))

    return tasks


def _detect_cow_filesystem(path: Path) -> str | None:
    """
    Detecta si la ruta indicada reside en un filesystem Copy-on-Write (CoW).

    En filesystems CoW (btrfs, ZFS, APFS), el borrado seguro mediante
    sobreescritura no es efectivo: el SO puede redirigir las escrituras
    a bloques nuevos, dejando los datos originales físicamente en disco.

    Parámetros:
        path (Path): Ruta a inspeccionar.

    Retorna:
        str: Nombre del filesystem detectado ("apfs", "btrfs", "zfs").
        None: Si no se detecta ningún filesystem CoW, o si no se puede determinar.

    Implementación:
        - macOS: APFS es el sistema de ficheros por defecto desde macOS 10.13.
          Se detecta por plataforma directamente.
        - Linux: Se lee /proc/mounts y se busca el punto de montaje que cubra
          la ruta del archivo, luego se comprueba el tipo de filesystem.
    """
    # ── macOS → siempre APFS (Copy-on-Write por defecto desde High Sierra) ────────────────────────────────────────────
    if sys.platform == "darwin":
        return "apfs"

    # ── Linux → leer /proc/mounts para determinar el filesystem ───────────────────────────────────────────────────────

    if sys.platform.startswith("linux"):
        try:
            resolved = path.resolve()
            best_mount  = Path("/")
            best_fstype = ""

            with open("/proc/mounts") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) < 3:
                        continue

                    mount_point = Path(parts[1])
                    fstype = parts[2].lower()

                    # Encontrar el punto de montaje más específico que cubra la ruta
                    try:
                        resolved.relative_to(mount_point)
                        if len(mount_point.parts) > len(best_mount.parts):
                            best_mount = mount_point
                            best_fstype = fstype
                    except ValueError:
                        pass

            if best_fstype in ("btrfs", "zfs"):
                return best_fstype

        except OSError:
            pass  # /proc/mounts no disponible o error de lectura → ignorar

    return None  # Filesystem no identificado como CoW


def process_directory(
    mode:       str,
    source_dir: Path,
    dest_dir:   Path,
    password:   bytes,
    workers:    int,
    do_shred:   bool = False,
    do_verify:  bool = False,
) -> None:
    """
    Procesa un directorio completo en paralelo utilizando multiprocessing.

    Esta función coordina la ejecución de múltiples tareas (archivos)
    distribuyéndolas entre varios procesos para mejorar el rendimiento.

    Flujo:
        1. Derivar la clave una sola vez en el proceso principal.
        2. Emitir warning si --shred se usa en filesystem CoW.
        3. Generar la lista de tareas con la clave (no la contraseña).
        4. Si no hay tareas → aviso y salida.
        5. Crear un pool de procesos.
        6. Distribuir las tareas entre los workers.
        7. Recoger resultados en tiempo real.
        8. Mostrar resumen final.

    Parámetros:
        mode (str): "encrypt" | "decrypt" | "verify"
        source_dir (Path): Directorio de entrada
        dest_dir (Path): Directorio de salida
        password (bytes): Contraseña (solo se usa aquí para derivar la clave)
        workers (int): Número de procesos paralelos
        do_shred (bool): Eliminar originales tras cifrado
        do_verify (bool): Verificar tras cifrado

    Seguridad:
        La contraseña se deriva una sola vez aquí. Los workers reciben la clave
        derivada (32 bytes), no la contraseña — nunca viaja por IPC (pickle).
        El salt de directorio se guarda en dest_dir/.vault_salt; es necesario
        para reproducir la misma clave en decrypt/verify.

    Diseño:
        - Usa multiprocessing para paralelizar I/O + CPU.
        - Usa imap_unordered → resultados llegan según se completan.
        - Manejo robusto de errores (no detiene todo el proceso si uno falla).

    Rendimiento:
        - Escala bien con múltiples núcleos.
        - Ideal para procesar muchos archivos pequeños/medianos.
    """
    # DERIVACIÓN DE CLAVE
    # Se deriva una sola vez aquí; los workers reciben la clave, nunca la contraseña.
    #
    # El salt se persiste en dest_dir/.vault_salt para que decrypt/verify puedan
    # reproducir la misma clave maestra. En cifrado se genera uno nuevo; en
    # decrypt/verify se lee el existente.
    dest_dir.mkdir(parents=True, exist_ok=True)
    salt_path = (source_dir if mode != "encrypt" else dest_dir) / ".vault_salt"

    if mode == "encrypt":
        dir_salt = os.urandom(SALT_SIZE)
        salt_path.write_bytes(dir_salt)
    else:
        if not salt_path.exists():
            raise FileNotFoundError(
                f"Directory salt not found: {salt_path}\n"
                "Was this directory encrypted with vaultenc?"
            )
        dir_salt = salt_path.read_bytes()
        if len(dir_salt) != SALT_SIZE:
            raise ValueError(f"Corrupt directory salt in {salt_path}")

    log.info("Deriving key from password (this may take a moment)…")
    directory_key = derive_key(password, salt=dir_salt)

    # ── ADVERTENCIA DE SHRED EN FILESYSTEMS CoW ───────────────────────────────────────────────────────────────────────

    # En APFS, btrfs y ZFS la sobreescritura no garantiza borrado físico real.
    if do_shred:
        cow_fs = _detect_cow_filesystem(source_dir)
        if cow_fs:
            log.warning(
                "--shred is NOT reliable on %s (Copy-on-Write filesystem). "
                "The original data may remain physically on disk after shredding. "
                "Use full-disk encryption (e.g. FileVault, LUKS) as a complement.",
                cow_fs.upper()
            )

    # ── GENERACIÓN DE TAREAS ──────────────────────────────────────────────────────────────────────────────────────────

    # Las tareas incluyen la clave derivada (no la contraseña)
    tasks = _build_tasks(mode, source_dir, dest_dir, directory_key, do_shred, do_verify)

    if not tasks:
        log.warning("No eligible files found in '%s'.", source_dir)
        return

    total = len(tasks)

    # Mensajes descriptivos según el modo de operación
    verbs = {
        "encrypt": "Encrypting",
        "decrypt": "Decrypting",
        "verify": "Verifying"
    }

    log.info("%s %d file(s) using %d worker(s)…", verbs[mode], total, workers)

    # Contadores de resultados para el resumen final
    ok_count  = 0
    err_count = 0

    # ── POOL DE PROCESOS ──────────────────────────────────────────────────────────────────────────────────────────────

    # Imap_unordered: los resultados llegan según se completan, no en orden.
    # Esto maximiza la utilización de los workers sin esperar al más lento.
    with multiprocessing.Pool(processes=workers) as pool:
        for in_str, success, err_msg in pool.imap_unordered(_worker, tasks):
            if success:
                ok_count += 1
                log.info("  [OK]  %s", Path(in_str))
            else:
                err_count += 1
                log.error("  [ERR] %s — %s", Path(in_str), err_msg)

    # ── RESUMEN FINAL ─────────────────────────────────────────────────────────────────────────────────────────────────

    log.info("Done: %d succeeded, %d failed.", ok_count, err_count)

    # Salir con código de error si algún archivo falló (útil para scripts)
    if err_count:
        sys.exit(1)


# ======================================================================================================================
# CLI
# ======================================================================================================================

def parse_args():
    parser = argparse.ArgumentParser(
        prog="vault",
        description="3 VaultEncryption — secure file/directory encryption CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
        Examples:
            vault -c secret.txt                        # encrypt file  → secret.txt.encrypted
            vault -c secret.txt --shred                # encrypt + shred original
            vault -c secret.txt --shred --verify-after # encrypt, verify, then shred
            vault -d secret.txt.encrypted              # decrypt file
            vault --verify secret.txt.encrypted        # verify without decrypting
            vault -c -r docs/                          # encrypt directory (parallel)
            vault -c -r docs/ --shred --verify-after   # encrypt + verify + shred
            vault --verify -r docs.enc/                # verify entire directory
            vault -c -r src/ -o out/ -j 8              # 8 workers, custom output
        """
    )

    # ── MODO (obligatorio y exclusivo) ────────────────────────────────────────────────────────────────────────────────

    mode_group = parser.add_mutually_exclusive_group(required=True)

    mode_group.add_argument(
        "-c", "--encrypt",
        action="store_const",
        const="encrypt",
        dest="mode",
        help="Cifrar archivo(s)"
    )

    mode_group.add_argument(
        "-d", "--decrypt",
        action="store_const",
        const="decrypt",
        dest="mode",
        help="Descifrar archivo(s)"
    )

    mode_group.add_argument(
        "--verify",
        action="store_const",
        const="verify",
        dest="mode",
        help="Verificar integridad sin descifrar"
    )

    # ── ARGUMENTOS GENERALES ──────────────────────────────────────────────────────────────────────────────────────────

    parser.add_argument(
        "input",
        help="Archivo o directorio de entrada"
    )

    parser.add_argument(
        "-o", "--output",
        default=None,
        help="Ruta de salida (opcional)"
    )

    parser.add_argument(
        "-r", "--recursive",
        action="store_true",
        help="Procesar directorios de forma recursiva"
    )

    parser.add_argument(
        "-j", "--jobs",
        type=int,
        default=max(1, multiprocessing.cpu_count() - 1),
        help="Número de procesos en paralelo"
    )

    parser.add_argument(
        "--shred",
        action="store_true",
        help="Borrar el archivo original tras cifrar"
    )

    parser.add_argument(
        "--verify-after",
        dest="verify_after",
        action="store_true",
        help="Verificar después de cifrar (recomendado si usas --shred)"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Mostrar información detallada (debug)"
    )

    # Parsear y devolver argumentos
    return parser.parse_args()


def _default_output(mode: str, input_path: Path, recursive: bool) -> Path:
    """
    Genera automáticamente la ruta de salida si el usuario no la especifica.

    Lógica:
        Modo recursivo (directorios):
            encrypt → añade ".enc" al nombre del directorio
            decrypt → añade ".dec"
            verify → no genera salida (usa input)

    Modo archivo:
        encrypt → añade extensión ".encrypted"
        decrypt → elimina extensión ".encrypted"
        verify → no genera salida

    Parámetros:
        mode (str): "encrypt" | "decrypt" | "verify"
        input_path (Path): Ruta de entrada
        recursive (bool): Indica si es procesamiento recursivo

    Retorna:
        Path: Ruta de salida calculada

    Diseño:
        - Mantiene comportamiento predecible para el usuario.
        - Evita sobrescribir archivos por defecto.
        - Conserva extensiones originales en cifrado.

    Ejemplos:
        file.txt → file.txt.encrypted
        file.txt.encrypted → file.txt
        docs/ → docs.enc/
    """
    if recursive:
        # Para directorios, añadimos sufijos claros
        suffix = ".enc" if mode == "encrypt" else (".dec" if mode == "decrypt" else "")
        return input_path.parent / (input_path.name + suffix)

    else:
        # Para archivos individuales
        if mode == "encrypt":
            return input_path.with_suffix(input_path.suffix + ENCRYPT_EXT)
        elif mode == "decrypt":
            return input_path.with_suffix("")
        else:  # verify → no hay salida real
            return input_path


def _ask_password(mode: str) -> bytearray:
    """
    Solicita la contraseña al usuario de forma segura.

    Comportamiento:
        - Siempre solicita contraseña.
        - En modo 'encrypt', solicita confirmación adicional.
        - Si no coinciden → aborta ejecución.

    Parámetros:
        mode (str): "encrypt" | "decrypt" | "verify"

    Retorna:
        bytearray: Contraseña en formato mutable (para poder borrarla de memoria)

    Seguridad:
        - Usa getpass (no muestra la contraseña en pantalla).
        - Convierte a bytearray para permitir sobrescritura posterior.
        - Elimina variables intermedias para reducir exposición en memoria.

    Nota:
        Python no garantiza borrado completo en memoria (GC, copias internas),
        pero este enfoque reduce significativamente el riesgo.

    Flujo:
        1. Solicitar contraseña.
        2. (Opcional) Confirmar si es cifrado.
        3. Convertir a bytes.
        4. Borrar strings originales.
        5. Devolver versión mutable.
    """
    # Solicitar contraseña sin mostrarla en pantalla
    password_str = getpass.getpass("Password: ")

    # Confirmación solo en cifrado
    if mode == "encrypt":
        confirm = getpass.getpass("Confirm password: ")

        if password_str != confirm:
            log.error("Passwords do not match.")
            sys.exit(1)

        # Eliminar confirmación de memoria
        del confirm

    # Convertir a bytearray (mutable → se puede limpiar después)
    result = bytearray(password_str.encode("utf-8"))

    # Eliminar string original (inmutable)
    del password_str

    return result


# ======================================================================================================================
# MAIN
# ======================================================================================================================

def main():
    """
    Punto de entrada principal de la herramienta CLI.

    Esta función coordina todo el flujo de ejecución:
        - Parseo de argumentos
        - Validación de entrada
        - Configuración de entorno (logging, paths)
        - Selección de modo (encrypt / decrypt / verify)
        - Ejecución (archivo único o directorio)
        - Manejo de errores y salida

    Flujo general:
        1. Parsear argumentos de línea de comandos.
        2. Configurar nivel de logging.
        3. Validar combinaciones de flags (--shred, --verify, etc.).
        4. Validar rutas de entrada (archivo vs directorio).
        5. Determinar ruta de salida.
        6. Solicitar contraseña al usuario.
        7. Ejecutar operación (single-file o recursiva).
        8. Manejar errores y limpiar datos sensibles.

    Seguridad:
        - La contraseña se borra de memoria al finalizar.
        - Se advierte al usuario antes de operaciones destructivas (--shred).
        - Se valida el formato de entrada antes de procesar.
    """

    # ── 1. Parseo de argumentos CLI ───────────────────────────────────────────────────────────────────────────────────

    args = parse_args()

    # Activar modo debug si el usuario lo solicita
    if args.verbose:
        log.setLevel(logging.DEBUG)

    # ── 2. Validación de flags ────────────────────────────────────────────────────────────────────────────────────────

    # --shred solo tiene sentido en cifrado
    if args.shred and args.mode != "encrypt":
        log.error("--shred can only be used with -c/--encrypt.")
        sys.exit(1)

    # Advertencia si se destruyen originales sin verificar primero
    if args.shred and not args.verify_after:
        log.warning(
            "--shred without --verify-after: originals will be destroyed without "
            "confirming the encrypted output is readable. Consider adding --verify-after."
        )

    # ── 3. Validación de la ruta de entrada ───────────────────────────────────────────────────────────────────────────

    input_path = Path(args.input)

    if args.recursive:
        # En modo recursivo → debe ser directorio
        if not input_path.is_dir():
            log.error("'%s' is not a directory.", input_path)
            sys.exit(1)
    else:
        # En modo simple → debe ser archivo
        if not input_path.is_file():
            log.error("'%s' is not a file.", input_path)
            sys.exit(1)

    # ── 4. Resolución de ruta de salida ───────────────────────────────────────────────────────────────────────────────

    output_path = (
        Path(args.output)
        if args.output
        else _default_output(args.mode, input_path, args.recursive)
    )

    # ── ADVERTENCIA DE SHRED EN FILESYSTEMS CoW ───────────────────────────────────────────────────────────────────────

    # Se emite antes de pedir la contraseña para que el usuario pueda cancelar.
    # En modo directorio lo emite process_directory.
    if args.shred and not args.recursive:
        cow_fs = _detect_cow_filesystem(input_path)
        if cow_fs:
            log.warning(
                "--shred is NOT reliable on %s (Copy-on-Write filesystem). "
                "The original data may remain physically on disk after shredding. "
                "Use full-disk encryption (e.g. FileVault, LUKS) as a complement.",
                cow_fs.upper()
            )

    # ── 5. Obtención de contraseña ────────────────────────────────────────────────────────────────────────────────────

    password = _ask_password(args.mode)

    try:

        # ── 6. Ejecución en modo recursivo (multiprocessing) ──────────────────────────────────────────────────────────

        # Process_directory deriva la clave internamente y la distribuye a los
        # workers. La contraseña nunca sale del proceso principal.
        if args.recursive:
            process_directory(
                mode=args.mode,
                source_dir=input_path,
                dest_dir=output_path,
                password=bytes(password),
                workers=args.jobs,
                do_shred=args.shred,
                do_verify=args.verify_after,
            )

        # ── 7. Ejecución en modo archivo único ────────────────────────────────────────────────────────────────────────

        else:
            # Mostrar barra de progreso solo si stderr es un terminal real
            show_progress = sys.stderr.isatty()

            # ── CIFRADO ───────────────────────────────────────────────────────────────────────────────────────────────

            if args.mode == "encrypt":
                # Asegurar que el directorio de salida existe
                output_path.parent.mkdir(parents=True, exist_ok=True)

                encrypt_file(
                    input_path,
                    output_path,
                    bytes(password),
                    progress=show_progress
                )

                # Verificación opcional antes de hacer shred (recomendado)
                if args.verify_after:
                    log.info("Verifying encrypted output…")
                    verify_file(
                        output_path,
                        bytes(password),
                        progress=show_progress
                    )
                    log.info("Verification passed.")

                # Borrado seguro del original (tras verificación si se solicitó)
                if args.shred:
                    log.info("Shredding original: %s", input_path)
                    shred_file(input_path)
                    log.info("Shred complete.")

            # ── DESCIFRADO ────────────────────────────────────────────────────────────────────────────────────────────

            elif args.mode == "decrypt":
                output_path.parent.mkdir(parents=True, exist_ok=True)

                decrypt_file(
                    input_path,
                    output_path,
                    bytes(password),
                    progress=show_progress
                )

            # ── VERIFICACIÓN ──────────────────────────────────────────────────────────────────────────────────────────

            else:
                verify_file(
                    input_path,
                    bytes(password),
                    progress=show_progress
                )
                log.info("OK — %s is intact.", input_path)

            # Mensaje final (excepto en modo verify, que ya imprime su propio OK)
            if args.mode != "verify":
                log.info("Done → %s", output_path)

    # ── 8. Manejo de errores ──────────────────────────────────────────────────────────────────────────────────────────

    except ValueError as exc:
        # Errores controlados (ej: contraseña incorrecta, archivo corrupto)
        log.error("%s", exc)
        sys.exit(1)

    except KeyboardInterrupt:
        # Interrupción manual (Ctrl+C)
        log.warning("Interrupted.")
        sys.exit(130)

    finally:

        # ── 9. Limpieza de datos sensibles ────────────────────────────────────────────────────────────────────────────

        # Sobrescribir la contraseña en memoria (best-effort)
        for i in range(len(password)):
            password[i] = 0


if __name__ == "__main__":
    main()
