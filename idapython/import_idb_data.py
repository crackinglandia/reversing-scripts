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
        print(f"[!] No se encontro {JSON_PATH}, se omite importacion de funciones.")
        return

    with open(JSON_PATH, "r", encoding="utf-8") as f:
        functions_data = json.load(f)

    renamed = 0
    typed = 0
    commented = 0
    skipped = 0

    for entry in functions_data:
        funcea = rebase(entry["direccion"])

        func = ida_funcs.get_func(funcea)
        if func is None:
            print(f"[!] No hay funcion en {hex(funcea)} ({entry.get('nombre')}), se omite.")
            skipped += 1
            continue

        # --- Nombre ---
        nombre_deseado = entry.get("nombre")
        if nombre_deseado:
            nombre_actual = idc.get_func_name(funcea)
            if nombre_actual != nombre_deseado:
                ok = idc.set_name(funcea, nombre_deseado, idc.SN_NOWARN)
                if ok:
                    renamed += 1
                else:
                    print(f"[!] No se pudo renombrar {hex(funcea)} a '{nombre_deseado}'")

        # --- Prototipo ---
        prototipo = entry.get("prototipo")
        if prototipo:
            ok = idc.SetType(funcea, prototipo)
            if ok:
                typed += 1
            else:
                print(f"[!] No se pudo aplicar prototipo en {hex(funcea)}: {prototipo}")

        # --- Comentario de funcion (normal y repetible) ---
        cmt = entry.get("comentario")
        if cmt:
            idc.set_func_cmt(funcea, cmt, 0)
            commented += 1

        cmt_rpt = entry.get("comentario_repetible")
        if cmt_rpt:
            idc.set_func_cmt(funcea, cmt_rpt, 1)
            commented += 1

        # --- Comentarios de linea dentro de la funcion ---
        for line_cmt in entry.get("comentarios_de_linea", []):
            ea = rebase(line_cmt["ea"])
            repeatable = 1 if line_cmt.get("tipo") == "repetible" else 0
            idc.set_cmt(ea, line_cmt["comentario"], repeatable)
            commented += 1

    print(f"-> Funciones renombradas: {renamed}")
    print(f"-> Prototipos aplicados: {typed}")
    print(f"-> Comentarios aplicados: {commented}")
    print(f"-> Funciones omitidas (no encontradas): {skipped}")


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