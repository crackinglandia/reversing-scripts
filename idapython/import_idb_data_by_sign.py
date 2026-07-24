"""
Importa a IDA Pro 9.3 lo generado por el script de exportacion:
  - types_export.h         -> structs/unions/enums/typedefs
  - functions_export.json  -> nombres, prototipos y comentarios de funciones

IMPORTANTE: las direcciones del JSON deben corresponder al MISMO binario
(o a uno con el mismo layout de memoria). Si el binario esta rebaseado,
ajusta BASE_DELTA mas abajo.
"""

import os
import json

import idc
import idautils
import ida_funcs
import ida_typeinf
import ida_kernwin
import ida_funcs

# ------------------------------------------------------------------
# CONFIGURACION
# ------------------------------------------------------------------
INPUT_DIR = r"C:\Users\fastix\Desktop\ida_export"
JSON_PATH = os.path.join(INPUT_DIR, "functions_export.json")
TYPES_PATH = os.path.join(INPUT_DIR, "types_export.h")

# Si el binario en este IDB esta cargado en una base distinta a la
# original, poné acá la diferencia (nueva_base - base_original).
# Si es el mismo binario/misma base, dejalo en 0.
BASE_DELTA = 0


def bytes_match_signature(cur_bytes, sig_bytes, sig_mask):
    n = min(len(cur_bytes), len(sig_bytes), len(sig_mask))
    if n == 0:
        return False
    concrete = 0
    for i in range(n):
        if sig_mask[i] == 'x':
            concrete += 1
            if cur_bytes[i] != sig_bytes[i]:
                return False
    return concrete > 0

def build_size_index():
    idx = {}
    for funcea in idautils.Functions():
        func = ida_funcs.get_func(funcea)
        if not func:
            continue
        size = func.end_ea - func.start_ea
        idx.setdefault(size, []).append(funcea)
    return idx

def find_match(entry, size_index):
    size = entry.get("tamano")
    sig_hex = entry.get("firma_bytes")
    sig_mask = entry.get("firma_mascara")
    if not sig_hex or not sig_mask:
        return None
    sig_bytes = bytes.fromhex(sig_hex)

    def scan(candidates):
        found = []
        for cand_ea in candidates:
            cur = idc.get_bytes(cand_ea, len(sig_bytes)) or b''
            if bytes_match_signature(cur, sig_bytes, sig_mask):
                found.append(cand_ea)
        return found

    matches = scan(size_index.get(size, []))

    if not matches:
        # fallback: tolerar pequeña diferencia de tamaño (padding, alineacion)
        for cand_size, cand_list in size_index.items():
            if abs(cand_size - size) <= 4 and cand_size != size:
                matches.extend(scan(cand_list))

    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        print(f"[!] Ambiguedad ({len(matches)} candidatos) para '{entry.get('nombre')}', se omite.")
    return None
    
# ------------------------------------------------------------------
# 1) Importar tipos locales desde el .h
# ------------------------------------------------------------------
def import_local_types():
    if not os.path.isfile(TYPES_PATH):
        print(f"[!] No se encontro {TYPES_PATH}, se omite importacion de tipos.")
        return

    til = ida_typeinf.get_idati()

    hti_flags = (
        ida_typeinf.HTI_DCL       # parsear como declaraciones
        | ida_typeinf.HTI_NWR     # no advertir sobre redefiniciones
    )

    print("Importando tipos locales...")
    err_count = ida_typeinf.idc_parse_types(TYPES_PATH, hti_flags)

    if err_count == 0:
        print("-> Tipos importados sin errores.")
    else:
        print(f"-> Importacion de tipos finalizada con {err_count} errores/advertencias "
              f"(revisa el Output window para el detalle).")


# ------------------------------------------------------------------
# 2) Importar funciones: nombre, prototipo y comentarios
# ------------------------------------------------------------------
def rebase(ea_hex):
    return int(ea_hex, 16) + BASE_DELTA


def import_functions():
    if not os.path.isfile(JSON_PATH):
        print(f"[!] No se encontro {JSON_PATH}.")
        return

    with open(JSON_PATH, "r", encoding="utf-8") as f:
        functions_data = json.load(f)

    size_index = build_size_index()

    renamed = typed = commented = 0
    unmatched = []

    for entry in functions_data:
        matched_ea = find_match(entry, size_index)
        if matched_ea is None:
            unmatched.append(entry.get("nombre"))
            continue

        nombre_deseado = entry.get("nombre")
        if nombre_deseado and idc.get_func_name(matched_ea) != nombre_deseado:
            if idc.set_name(matched_ea, nombre_deseado, idc.SN_NOWARN):
                renamed += 1

        prototipo = entry.get("prototipo")
        if prototipo and idc.SetType(matched_ea, prototipo):
            typed += 1

        if entry.get("comentario"):
            idc.set_func_cmt(matched_ea, entry["comentario"], 0)
            commented += 1
        if entry.get("comentario_repetible"):
            idc.set_func_cmt(matched_ea, entry["comentario_repetible"], 1)
            commented += 1

        for lc in entry.get("comentarios_de_linea", []):
            ea = matched_ea + lc["offset"]
            repeatable = 1 if lc.get("tipo") == "repetible" else 0
            idc.set_cmt(ea, lc["comentario"], repeatable)
            commented += 1

    print(f"-> Renombradas: {renamed} | Prototipos: {typed} | Comentarios: {commented}")
    print(f"-> Sin match: {len(unmatched)}")
    if unmatched:
        print("   " + ", ".join(unmatched[:50]) + (" ..." if len(unmatched) > 50 else ""))

# ------------------------------------------------------------------
# MAIN
# ------------------------------------------------------------------
def main():
    # Los tipos van primero: los prototipos de funciones pueden depender
    # de structs/enums recien definidos.
    import_local_types()
    import_functions()
    print("Completo.")


main()