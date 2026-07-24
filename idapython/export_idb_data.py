"""
Exporta funciones, comentarios y tipos locales (structs/unions/enums/typedefs)
desde IDA Pro 9.3 usando IDAPython.

Genera dos archivos:
  - functions_export.json  -> nombres, direcciones y comentarios de funciones
  - types_export.h         -> declaraciones C de los tipos locales definidos
"""

import os
import json

import idc
import idautils
import ida_funcs
import ida_typeinf

# ------------------------------------------------------------------
# CONFIGURACION - Ajusta la carpeta de salida
# ------------------------------------------------------------------
OUTPUT_DIR = r"C:\Users\fastix\Desktop\ida_export"
os.makedirs(OUTPUT_DIR, exist_ok=True)

JSON_PATH = os.path.join(OUTPUT_DIR, "functions_export.json")
TYPES_PATH = os.path.join(OUTPUT_DIR, "types_export.h")


# ------------------------------------------------------------------
# 1) Exportar funciones + comentarios
# ------------------------------------------------------------------
def export_functions():
    functions_data = []

    for funcea in idautils.Functions():
        func_name = idc.get_func_name(funcea)
        func_cmt = idc.get_func_cmt(funcea, 0)      # comentario no repetible
        func_cmt_rpt = idc.get_func_cmt(funcea, 1)  # comentario repetible

        func = ida_funcs.get_func(funcea)
        line_comments = []

        if func:
            for head in idautils.Heads(func.start_ea, func.end_ea):
                cmt = idc.get_cmt(head, 0)
                rpt_cmt = idc.get_cmt(head, 1)
                if cmt:
                    line_comments.append({
                        "ea": hex(head),
                        "tipo": "normal",
                        "comentario": cmt
                    })
                if rpt_cmt:
                    line_comments.append({
                        "ea": hex(head),
                        "tipo": "repetible",
                        "comentario": rpt_cmt
                    })

        # Prototipo/tipo de la función, si está definido
        func_type = idc.get_type(funcea)

        entry = {
            "direccion": hex(funcea),
            "nombre": func_name,
            "prototipo": func_type if func_type else "",
            "comentario": func_cmt if func_cmt else "",
            "comentario_repetible": func_cmt_rpt if func_cmt_rpt else "",
            "comentarios_de_linea": line_comments,
        }
        functions_data.append(entry)

    return functions_data


# ------------------------------------------------------------------
# 2) Exportar tipos locales (structs, unions, enums, typedefs)
# ------------------------------------------------------------------
def export_local_types():
    til = ida_typeinf.get_idati()

    # get_ordinal_qty fue removida en IDA 9.x -> usar get_ordinal_limit
    limit = ida_typeinf.get_ordinal_limit()

    flags = (
        ida_typeinf.PRTYPE_MULTI
        | ida_typeinf.PRTYPE_TYPE
        | ida_typeinf.PRTYPE_SEMI
    )

    declarations = []

    for ordinal in range(1, limit):
        tif = ida_typeinf.tinfo_t()
        if not tif.get_numbered_type(til, ordinal):
            continue

        name = tif.get_type_name()
        if not name:
            continue

        try:
            decl = tif.print(name, flags)
        except Exception as e:
            decl = f"// No se pudo imprimir el tipo '{name}': {e}"

        if decl:
            declarations.append(decl.rstrip())

    return declarations
    
# ------------------------------------------------------------------
# MAIN
# ------------------------------------------------------------------
def main():
    print("Exportando funciones y comentarios...")
    functions_data = export_functions()

    with open(JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(functions_data, f, indent=2, ensure_ascii=False)

    print(f"-> {len(functions_data)} funciones exportadas a: {JSON_PATH}")

    print("Exportando tipos locales (structs/unions/enums/typedefs)...")
    declarations = export_local_types()

    with open(TYPES_PATH, "w", encoding="utf-8") as f:
        f.write("// Tipos locales exportados desde IDA Pro 9.3\n\n")
        for decl in declarations:
            f.write(decl + "\n\n")

    print(f"-> {len(declarations)} tipos exportados a: {TYPES_PATH}")
    print("Completo.")


main()