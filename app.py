import io
import csv
import hmac as hmaclib
from typing import Optional, Dict, Any, List

import streamlit as st

from hash_utils import (
    SUPPORTED_ALGOS,
    hash_text,
    hash_file_chunked,
    compare_hashes_consttime,
    make_salt,
    hmac_text,
)

# -----------------------------
# Configuración básica de la app
# -----------------------------
st.set_page_config(
    page_title="Hash Demo — SHA256/Salt/Pepper/HMAC",
    page_icon="assets/icon.svg",
    layout="centered",
)

# Secrets opcionales (no romper si no están)
PEPPER = st.secrets.get("PEPPER", None)
HMAC_KEY = st.secrets.get("HMAC_KEY", None)

# Estado de sesión para exportación CSV
if "history" not in st.session_state:
    st.session_state.history: List[Dict[str, Any]] = []

st.title("🔐 Demo didáctica de Hash • Streamlit")
st.caption(
    "Hash de textos y archivos (SHA-256/1/512/BLAKE2b). Salting, Peppering y HMAC. "
    "Exporta resultados a CSV. *Hash ≠ cifrado; SHA-1 solo con fines didácticos.*"
)

# -----------------------------
# Sidebar: opciones globales
# -----------------------------
st.sidebar.header("Opciones")
algorithm = st.sidebar.selectbox(
    "Algoritmo",
    options=SUPPORTED_ALGOS,
    index=SUPPORTED_ALGOS.index("sha256"),
    help="Elige el algoritmo de hash. SHA-256 por defecto. SHA-1 tiene colisiones conocidas.",
)

chunk_size = st.sidebar.number_input(
    "Tamaño de chunk (bytes) para archivos",
    min_value=1024,
    max_value=1024 * 1024,
    step=1024,
    value=8192,
    help="Lectura incremental del archivo para memoria estable.",
)

max_bytes = st.sidebar.number_input(
    "Límite de tamaño de archivo (bytes)",
    min_value=1024 * 1024,
    max_value=1024 * 1024 * 1024,
    step=1024 * 1024,
    value=10 * 1024 * 1024,  # 10 MB
    help="Evita bloquear la app con ficheros enormes en la versión gratuita.",
)

use_pepper = st.sidebar.checkbox(
    "Usar PEPPER desde `st.secrets` (si disponible)", value=True
)
use_hmac = st.sidebar.checkbox("Mostrar sección HMAC (si `HMAC_KEY` está en secrets)", value=True)

st.sidebar.info(
    "💡 *Sal* se guarda junto al hash (no secreto). *Pepper* es secreto global en servidor. "
    "Para autenticidad usa **HMAC** con clave."
)

# -----------------------------
# Tabs principales
# -----------------------------
tab_text, tab_file, tab_compare, tab_hmac, tab_export = st.tabs(
    ["Texto", "Archivo", "Comparar", "HMAC", "Exportar"]
)

# ---- TAB: TEXTO ----
with tab_text:
    st.subheader("Hash de texto (+ sal / + pepper opcional)")
    text = st.text_area("Texto a hashear", placeholder="Escribe aquí…", height=140)

    col1, col2, col3 = st.columns([1,1,1])
    with col1:
        salt_input = st.text_input(
            "Sal (hex, opcional)",
            value="",
            help="Cadena hex; si se deja vacía, puedes generar una sal aleatoria.",
        )
    with col2:
        salt_len = st.number_input(
            "Longitud sal aleatoria (bytes)",
            min_value=8,
            max_value=64,
            value=16,
            step=1,
            help="Tamaño típico 16–32 bytes en escenarios didácticos.",
        )
    with col3:
        if st.button("Generar sal aleatoria"):
            st.session_state["generated_salt"] = make_salt(salt_len).hex()

    if "generated_salt" in st.session_state and not salt_input:
        salt_input = st.session_state["generated_salt"]
        st.info(f"Sal generada: {salt_input}")

    if st.button("Calcular hash de texto", type="primary", disabled=(not text)):
        try:
            result = hash_text(
                text=text,
                algorithm=algorithm,
                salt_hex=salt_input or None,
                pepper=PEPPER if (use_pepper and PEPPER) else None,
            )
            st.code(result["hexdigest"], language="text")
            with st.expander("Detalles"):
                st.json(result)

            # Registrar en histórico
            st.session_state.history.append(
                {
                    "mode": "text",
                    "algorithm": algorithm,
                    "input_len": len(text),
                    "salt_hex": result.get("salt_hex") or "",
                    "pepper_used": bool(result.get("pepper_used")),
                    "hexdigest": result["hexdigest"],
                }
            )

        except ValueError as e:
            st.error(str(e))

# ---- TAB: ARCHIVO ----
with tab_file:
    st.subheader("Hash de archivo (streaming por chunks)")
    uploaded = st.file_uploader("Selecciona un archivo", type=None)

    if uploaded is not None:
        if uploaded.size > max_bytes:
            st.error(
                f"Archivo supera el límite configurado ({uploaded.size} > {max_bytes} bytes)."
            )
        else:
            if st.button("Calcular hash de archivo", type="primary"):
                progress = st.progress(0.0, text="Procesando…")
                n_read = 0

                def _progress_cb(read_bytes: int, total_bytes: Optional[int]):
                    nonlocal n_read
                    n_read += read_bytes
                    if total_bytes:
                        progress.progress(min(n_read / total_bytes, 1.0))

                result = hash_file_chunked(
                    file_obj=uploaded,
                    algorithm=algorithm,
                    chunk_size=chunk_size,
                    progress_callback=_progress_cb,
                    max_bytes=max_bytes,
                    pepper=PEPPER if (use_pepper and PEPPER) else None,
                )
                progress.progress(1.0, text="Listo")
                st.code(result["hexdigest"], language="text")
                with st.expander("Detalles"):
                    st.json(result)

                st.session_state.history.append(
                    {
                        "mode": "file",
                        "algorithm": algorithm,
                        "filename": uploaded.name,
                        "size": uploaded.size,
                        "pepper_used": bool(result.get("pepper_used")),
                        "hexdigest": result["hexdigest"],
                    }
                )

# ---- TAB: COMPARAR ----
with tab_compare:
    st.subheader("Comparar hashes (constante-tiempo)")
    a = st.text_input("Hash A (hex)")
    b = st.text_input("Hash B (hex)")
    if st.button("Comparar"):
        same = compare_hashes_consttime(a, b)
        if same:
            st.success("✅ Coinciden.")
        else:
            st.warning("❌ No coinciden.")

# ---- TAB: HMAC ----
with tab_hmac:
    st.subheader("HMAC (clave en `st.secrets`)")
    if not (use_hmac and HMAC_KEY):
        st.info("Para usar HMAC, define `HMAC_KEY` en *Settings → Secrets* de Streamlit.")
    else:
        msg = st.text_area("Mensaje para HMAC", placeholder="Texto…", height=120, key="hmac_msg")
        if st.button("Calcular HMAC", disabled=(not msg)):
            h = hmac_text(
                text=msg,
                key=HMAC_KEY.encode("utf-8"),
                algorithm=algorithm,
            )
            st.code(h, language="text")
            st.session_state.history.append(
                {
                    "mode": "hmac",
                    "algorithm": algorithm,
                    "input_len": len(msg),
                    "hexdigest": h,
                }
            )

# ---- TAB: EXPORTAR ----
with tab_export:
    st.subheader("Exportar resultados (CSV)")
    if not st.session_state.history:
        st.info("No hay resultados aún. Genera un hash o HMAC primero.")
    else:
        output = io.StringIO()
        writer = csv.DictWriter(
            output,
            fieldnames=[
                "mode",
                "algorithm",
                "filename",
                "size",
                "input_len",
                "salt_hex",
                "pepper_used",
                "hexdigest",
            ],
        )
        writer.writeheader()
        for row in st.session_state.history:
            writer.writerow(row)
        csv_bytes = output.getvalue().encode("utf-8")
        st.download_button(
            "Descargar CSV",
            data=csv_bytes,
            file_name="hash_results.csv",
            mime="text/csv",
        )

# -----------------------------
# Notas y limitaciones
# -----------------------------
with st.expander("Notas didácticas y limitaciones"):
    st.markdown(
        """
- **Hash ≠ cifrado**. Un hash no recupera el mensaje original.
- **Sal** no es secreto y suele almacenarse con el hash.
- **Pepper** es un secreto global del servidor (úsalo con `st.secrets`).
- **HMAC** aporta integridad y autenticidad mediante una clave.
- **SHA-1** tiene colisiones conocidas → **solo** uso didáctico.
- Si el objetivo son **contraseñas**, considera PBKDF2/Argon2/scrypt (no cubierto aquí).
"""
    )
