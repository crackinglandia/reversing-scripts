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
import ida_ua

# ------------------------------------------------------------------
# CONFIGURACION - Ajusta la carpeta de salida
# ------------------------------------------------------------------
OUTPUT_DIR = r"C:\Users\fastix\Desktop\ida_export"
os.makedirs(OUTPUT_DIR, exist_ok=True)

JSON_PATH = os.path.join(OUTPUT_DIR, "functions_export.json")
TYPES_PATH = os.path.join(OUTPUT_DIR, "types_export.h")

MAX_SIG_LEN = 96  # bytes maximos de firma por funcion

def get_function_signature(start_ea, end_ea, max_len=MAX_SIG_LEN):
    """Devuelve (bytes_hex, mascara) donde la mascara tiene 'x' para bytes
    concretos y '?' para bytes de operandos que referencian direcciones
    (y por lo tanto cambian al reubicar el binario)."""
    cur = start_ea
    limit = min(end_ea, start_ea + max_len)
    sig_bytes = bytearray()
    sig_mask = []

    while cur < limit:
        insn = ida_ua.insn_t()
        length = ida_ua.decode_insn(insn, cur)
        if length <= 0:
            remaining = limit - cur
            raw = idc.get_bytes(cur, remaining) or (b'\x00' * remaining)
            sig_bytes.extend(raw)
            sig_mask.extend(['?'] * remaining)
            break

        raw = idc.get_bytes(cur, length)
        if raw is None:
            break

        mask = ['x'] * length
        for op in insn.ops:
            if op.type == ida_ua.o_void:
                continue
            if op.type in (ida_ua.o_mem, ida_ua.o_displ,
                            ida_ua.o_near, ida_ua.o_far, ida_ua.o_imm):
                offb = op.offb
                if offb <= 0:
                    continue
                for i in range(offb, length):
                    mask[i] = '?'

        sig_bytes.extend(raw)
        sig_mask.extend(mask)
        cur += length

    # recortar por si la ultima instruccion se paso del limite
    sig_bytes = sig_bytes[:max_len]
    sig_mask = sig_mask[:max_len]

    return sig_bytes.hex(), ''.join(sig_mask)
    
# ------------------------------------------------------------------
# 1) Exportar funciones + comentarios
# ------------------------------------------------------------------
def export_functions():
    functions_data = []

    for funcea in idautils.Functions():
        func = ida_funcs.get_func(funcea)
        if not func:
            continue

        func_name = idc.get_func_name(funcea)
        func_cmt = idc.get_func_cmt(funcea, 0)
        func_cmt_rpt = idc.get_func_cmt(funcea, 1)
        func_type = idc.get_type(funcea)
        func_size = func.end_ea - func.start_ea

        line_comments = []
        for head in idautils.Heads(func.start_ea, func.end_ea):
            cmt = idc.get_cmt(head, 0)
            rpt_cmt = idc.get_cmt(head, 1)
            offset = head - func.start_ea  # relativo, no absoluto
            if cmt:
                line_comments.append({"offset": offset, "tipo": "normal", "comentario": cmt})
            if rpt_cmt:
                line_comments.append({"offset": offset, "tipo": "repetible", "comentario": rpt_cmt})

        sig_bytes_hex, sig_mask = get_function_signature(func.start_ea, func.end_ea)

        functions_data.append({
            "direccion": hex(funcea),          # solo informativo, no se usa para matchear
            "nombre": func_name,
            "prototipo": func_type if func_type else "",
            "comentario": func_cmt if func_cmt else "",
            "comentario_repetible": func_cmt_rpt if func_cmt_rpt else "",
            "comentarios_de_linea": line_comments,
            "tamano": func_size,
            "firma_bytes": sig_bytes_hex,
            "firma_mascara": sig_mask,
        })

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