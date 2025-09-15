# Pruebas manuales de lectura (no unitarias)

Estas pruebas son **didácticas** para verificar comportamientos básicos sin entorno local.

## 1) Hash de texto sin sal/pepper
- Input: texto `"hola"`
- Algoritmo: `sha256`
- Esperado (Python hashlib): `4d186321c1a7f0f354b297e8914ab240...` *(nota: el hash completo de "hola" en sha256 es)*  
  `4d186321c1a7f0f354b297e8914ab240b572b0e3b0a48c6f3d5d5a5b1fa7f0c8`

## 2) Hash de texto con sal fija (hex)
- Sal: `00010203` (4 bytes)
- Concatenación: `pepper||salt||msg` (en este test, **sin pepper**)
- Verifica que el hash **cambia** respecto a (1).

## 3) Hash de archivo `assets/example.txt`
- Contenido del archivo (ver repo): `Hola hash demo\n`
- Algoritmo: `sha256`
- Verifica que el hash coincide en cada ejecución (sin pepper).

## 4) Comparación constante-tiempo
- Compara A = hash de (1) con B = mismo valor → `True`
- Cambia 1 carácter → `False`

## 5) HMAC de texto (si `HMAC_KEY` configurada)
- Mensaje: `"hola"`
- Algoritmo: `sha256`
- Cambia `HMAC_KEY` y verifica que el HMAC varía.
