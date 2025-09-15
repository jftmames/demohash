"""
Funciones puras de hashing y helpers.
- hash_text: hash de texto con sal (hex) opcional y pepper opcional.
- hash_file_chunked: hash incremental de archivo con callback de progreso.
- hmac_text: HMAC del texto con clave dada.
- compare_hashes_consttime: comparación constante-tiempo.
- make_salt: genera bytes aleatorios para sal.
"""

import io
import hmac
import hashlib
import secrets
from typing import Optional, Callable, Dict, Any

SUPPORTED_ALGOS = ["sha256", "sha1", "sha512", "blake2b"]


def _get_hasher(algorithm: str):
    algo = algorithm.lower()
    if algo not in SUPPORTED_ALGOS:
        raise ValueError(f"Algoritmo no soportado: {algorithm}")
    if algo == "sha256":
        return hashlib.sha256()
    if algo == "sha1":
        return hashlib.sha1()
    if algo == "sha512":
        return hashlib.sha512()
    if algo == "blake2b":
        return hashlib.blake2b()
    raise ValueError(f"Algoritmo no soportado: {algorithm}")


def make_salt(length: int = 16) -> bytes:
    """Genera una sal criptográficamente aleatoria."""
    if length <= 0:
        raise ValueError("La longitud de la sal debe ser > 0.")
    return secrets.token_bytes(length)


def _maybe_hex_to_bytes(hex_or_none: Optional[str]) -> Optional[bytes]:
    if not hex_or_none:
        return None
    try:
        return bytes.fromhex(hex_or_none)
    except ValueError as e:
        raise ValueError("Sal en formato hex inválido.") from e


def hash_text(
    text: str,
    algorithm: str = "sha256",
    *,
    salt_hex: Optional[str] = None,
    pepper: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Calcula el hash de `text` (UTF-8) con algoritmo dado.
    - Si `salt_hex` se proporciona, se concatena como bytes delante del mensaje.
    - Si `pepper` se proporciona, también se concatena (como bytes) delante.
    Nota: En escenarios reales, el orden y formato se deben definir y documentar.
    """
    hasher = _get_hasher(algorithm)
    msg = text.encode("utf-8")
    salt_bytes = _maybe_hex_to_bytes(salt_hex)

    # Concatenación: pepper || salt || msg (decisión didáctica)
    if pepper:
        hasher.update(pepper.encode("utf-8"))
    if salt_bytes:
        hasher.update(salt_bytes)
    hasher.update(msg)

    digest = hasher.hexdigest()
    return {
        "algorithm": algorithm.lower(),
        "input_len": len(msg),
        "salt_hex": salt_hex,
        "pepper_used": bool(pepper),
        "hexdigest": digest,
    }


def hash_file_chunked(
    file_obj: io.BufferedReader,
    algorithm: str = "sha256",
    *,
    chunk_size: int = 8192,
    progress_callback: Optional[Callable[[int, Optional[int]], None]] = None,
    max_bytes: Optional[int] = None,
    pepper: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Hash incremental de un archivo usando chunks para memoria estable.
    - `file_obj` es el objeto subido por Streamlit (tiene .read() y .size).
    - Si `pepper` se proporciona, se antepone al contenido.
    - `progress_callback(read_bytes, total_bytes)` actualiza barra de progreso.
    - `max_bytes` corta lectura si se excede el límite.
    """
    hasher = _get_hasher(algorithm)
    total = getattr(file_obj, "size", None)
    read_total = 0

    # Prepend pepper si existe
    if pepper:
        hasher.update(pepper.encode("utf-8"))

    file_obj.seek(0)
    while True:
        chunk = file_obj.read(chunk_size)
        if not chunk:
            break
        read_total += len(chunk)
        if max_bytes is not None and read_total > max_bytes:
            raise ValueError("Archivo supera el máximo permitido durante la lectura.")
        hasher.update(chunk)
        if progress_callback:
            progress_callback(len(chunk), total)

    return {
        "algorithm": algorithm.lower(),
        "size": total,
        "pepper_used": bool(pepper),
        "hexdigest": hasher.hexdigest(),
    }


def hmac_text(
    text: str,
    key: bytes,
    algorithm: str = "sha256",
) -> str:
    """
    Calcula HMAC(text) con `key` y digest `algorithm`.
    HMAC proporciona integridad + autenticidad si la clave se mantiene secreta.
    """
    algo = algorithm.lower()
    if algo not in SUPPORTED_ALGOS:
        raise ValueError(f"Algoritmo HMAC no soportado: {algorithm}")
    digestmod = getattr(hashlib, algo)
    return hmac.new(key, text.encode("utf-8"), digestmod=digestmod).hexdigest()


def compare_hashes_consttime(a_hex: str, b_hex: str) -> bool:
    """Compara dos hex digests en tiempo constante para evitar timing attacks."""
    if not isinstance(a_hex, str) or not isinstance(b_hex, str):
        return False
    return hmac.compare_digest(a_hex.strip().lower(), b_hex.strip().lower())
