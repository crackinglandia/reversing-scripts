# -*- coding: utf-8 -*-
"""
IDA Sync Plugin
===============

Exporta e importa, entre IDBs del mismo binario (o variantes reubicadas /
reempaquetadas del mismo binario):

  - Nombres de funciones
  - Prototipos de funciones
  - Comentarios de funcion (normales y repetibles)
  - Comentarios de linea dentro de cada funcion
  - Tipos locales (structs, unions, enums, typedefs)

Soporta DOS metodos de matcheo al importar:

  1) Direcciones / RVA (+ delta de base opcional)
     -> Rapido, ideal cuando el binario destino tiene el mismo layout
        de memoria (o un offset fijo y conocido respecto al original).

  2) Firma de bytes (byte matching)
     -> Robusto ante reubicaciones no triviales (ej. una DLL convertida
        a EXE con un stub que reordena/inserta secciones). Compara el
        tamano de cada funcion y sus bytes de opcode, comodinizando los
        operandos que referencian direcciones (que cambian al reubicar).

Compatible con IDA Pro 9.3 / IDAPython 3.

Instalacion:
    Copiar este archivo dentro de la carpeta "plugins" de tu instalacion
    de IDA, por ejemplo:

        C:\\Program Files\\IDA Professional 9.3\\plugins\\ida_sync_plugin.py

    Reiniciar IDA (o Edit > Plugins > Rescan plugins si tu build lo soporta).

Uso:
    Menu:  Edit > Plugins > IDA Sync Exporter
           Edit > Plugins > IDA Sync Importer

    Atajos: Ctrl-Alt-E  -> Exportar
            Ctrl-Alt-I  -> Importar

    Tambien podes ejecutar el plugin "principal" (Edit > Plugins > IDA Sync
    (Export/Import)) y elegir la operacion desde un dialogo.
"""

import os
import json

import idaapi
import idautils
import idc
import ida_funcs
import ida_typeinf
import ida_kernwin
import ida_ua


PLUGIN_NAME = "IDA Sync (Export/Import)"
PLUGIN_HOTKEY_EXPORT = "Ctrl-Alt-E"
PLUGIN_HOTKEY_IMPORT = "Ctrl-Alt-I"

MAX_SIG_LEN = 96  # bytes maximos de firma por funcion

JSON_FILENAME = "functions_export.json"
TYPES_FILENAME = "types_export.h"


# ---------------------------------------------------------------------------
# Firma de bytes (para byte matching)
# ---------------------------------------------------------------------------

def get_function_signature(start_ea, end_ea, max_len=MAX_SIG_LEN):
    """Devuelve (bytes_hex, mascara) para una funcion.

    La mascara tiene 'x' para bytes concretos (deben coincidir exacto) y
    '?' para bytes de operandos que referencian direcciones/desplazamientos
    (o_mem, o_displ, o_near, o_far, o_imm), que cambian al reubicar el
    binario y por lo tanto se ignoran al comparar.
    """
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

    sig_bytes = sig_bytes[:max_len]
    sig_mask = sig_mask[:max_len]

    return sig_bytes.hex(), ''.join(sig_mask)


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


# ---------------------------------------------------------------------------
# EXPORT
# ---------------------------------------------------------------------------

def export_functions(include_line_comments=True):
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
        if include_line_comments:
            for head in idautils.Heads(func.start_ea, func.end_ea):
                cmt = idc.get_cmt(head, 0)
                rpt_cmt = idc.get_cmt(head, 1)
                offset = head - func.start_ea  # relativo al inicio de la funcion
                if cmt:
                    line_comments.append({"offset": offset, "tipo": "normal", "comentario": cmt})
                if rpt_cmt:
                    line_comments.append({"offset": offset, "tipo": "repetible", "comentario": rpt_cmt})

        sig_bytes_hex, sig_mask = get_function_signature(func.start_ea, func.end_ea)

        functions_data.append({
            "direccion": hex(funcea),           # usado en modo "address"
            "nombre": func_name,
            "prototipo": func_type if func_type else "",
            "comentario": func_cmt if func_cmt else "",
            "comentario_repetible": func_cmt_rpt if func_cmt_rpt else "",
            "comentarios_de_linea": line_comments,
            "tamano": func_size,                # usado en modo "signature"
            "firma_bytes": sig_bytes_hex,
            "firma_mascara": sig_mask,
        })

    return functions_data


def export_local_types():
    til = ida_typeinf.get_idati()
    limit = ida_typeinf.get_ordinal_limit()  # reemplaza a get_ordinal_qty (removida en 9.x)

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
            decl = "// No se pudo imprimir el tipo '%s': %s" % (name, e)

        if decl:
            declarations.append(decl.rstrip())

    return declarations


def do_export(output_dir, include_types=True, include_line_comments=True):
    os.makedirs(output_dir, exist_ok=True)
    json_path = os.path.join(output_dir, JSON_FILENAME)
    types_path = os.path.join(output_dir, TYPES_FILENAME)

    functions_data = export_functions(include_line_comments=include_line_comments)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(functions_data, f, indent=2, ensure_ascii=False)

    types_count = 0
    if include_types:
        declarations = export_local_types()
        with open(types_path, "w", encoding="utf-8") as f:
            f.write("// Tipos locales exportados desde IDA Pro (IDA Sync Plugin)\n\n")
            for decl in declarations:
                f.write(decl + "\n\n")
        types_count = len(declarations)

    return len(functions_data), types_count, json_path, types_path


# ---------------------------------------------------------------------------
# IMPORT
# ---------------------------------------------------------------------------

def import_local_types(types_path):
    hti_flags = ida_typeinf.HTI_DCL | ida_typeinf.HTI_NWR
    err_count = ida_typeinf.idc_parse_types(types_path, hti_flags)
    return err_count


def build_size_index():
    idx = {}
    for funcea in idautils.Functions():
        func = ida_funcs.get_func(funcea)
        if not func:
            continue
        size = func.end_ea - func.start_ea
        idx.setdefault(size, []).append(funcea)
    return idx


def find_match_by_signature(entry, size_index):
    size = entry.get("tamano")
    sig_hex = entry.get("firma_bytes")
    sig_mask = entry.get("firma_mascara")
    if not sig_hex or not sig_mask or size is None:
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
        # fallback: tolerar pequena diferencia de tamano (padding/alineacion)
        for cand_size, cand_list in size_index.items():
            if cand_size != size and abs(cand_size - size) <= 4:
                matches.extend(scan(cand_list))

    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        print("[IDA Sync] Ambiguedad (%d candidatos) para '%s', se omite." %
              (len(matches), entry.get("nombre")))
    return None


def find_match_by_address(entry, base_delta):
    try:
        funcea = int(entry["direccion"], 16) + base_delta
    except (KeyError, ValueError, TypeError):
        return None
    func = ida_funcs.get_func(funcea)
    if func is None:
        return None
    if func.start_ea == funcea:
        return funcea
    # tolerar que la ea calculada caiga dentro del cuerpo de la funcion
    if func.start_ea <= funcea < func.end_ea:
        return func.start_ea
    return None


def apply_function_data(matched_ea, entry):
    counts = {"renamed": 0, "typed": 0, "commented": 0}

    nombre_deseado = entry.get("nombre")
    if nombre_deseado and idc.get_func_name(matched_ea) != nombre_deseado:
        if idc.set_name(matched_ea, nombre_deseado, idc.SN_NOWARN):
            counts["renamed"] += 1

    prototipo = entry.get("prototipo")
    if prototipo:
        if idc.SetType(matched_ea, prototipo):
            counts["typed"] += 1

    if entry.get("comentario"):
        idc.set_func_cmt(matched_ea, entry["comentario"], 0)
        counts["commented"] += 1
    if entry.get("comentario_repetible"):
        idc.set_func_cmt(matched_ea, entry["comentario_repetible"], 1)
        counts["commented"] += 1

    for lc in entry.get("comentarios_de_linea", []):
        ea = matched_ea + lc["offset"]
        repeatable = 1 if lc.get("tipo") == "repetible" else 0
        idc.set_cmt(ea, lc["comentario"], repeatable)
        counts["commented"] += 1

    return counts


def do_import(input_dir, mode="signature", base_delta=0, include_types=True):
    json_path = os.path.join(input_dir, JSON_FILENAME)
    types_path = os.path.join(input_dir, TYPES_FILENAME)

    result = {
        "renamed": 0, "typed": 0, "commented": 0,
        "unmatched": [], "types_errors": None,
    }

    if include_types and os.path.isfile(types_path):
        result["types_errors"] = import_local_types(types_path)

    if not os.path.isfile(json_path):
        return result

    with open(json_path, "r", encoding="utf-8") as f:
        functions_data = json.load(f)

    size_index = build_size_index() if mode == "signature" else None

    for entry in functions_data:
        if mode == "address":
            matched_ea = find_match_by_address(entry, base_delta)
        else:
            matched_ea = find_match_by_signature(entry, size_index)

        if matched_ea is None:
            result["unmatched"].append(entry.get("nombre"))
            continue

        counts = apply_function_data(matched_ea, entry)
        result["renamed"] += counts["renamed"]
        result["typed"] += counts["typed"]
        result["commented"] += counts["commented"]

    return result


# ---------------------------------------------------------------------------
# GUI - Formularios (ida_kernwin.Form)
# ---------------------------------------------------------------------------

class ExportForm(ida_kernwin.Form):
    def __init__(self):
        F = ida_kernwin.Form
        F.__init__(self, r"""STARTITEM 0
BUTTON YES* Exportar
BUTTON CANCEL Cancelar
IDA Sync - Exportar datos

<#Carpeta donde se guardaran functions_export.json y types_export.h#Carpeta de salida\::{dirOutput}>

<Incluir tipos locales (structs / unions / enums / typedefs):{chkTypes}>
<Incluir comentarios de linea dentro de cada funcion:{chkLineComments}>{cGroup}>
""", {
            'dirOutput': F.DirInput(),
            'cGroup': F.ChkGroupControl(('chkTypes', 'chkLineComments')),
        })

    def get_values(self):
        return {
            "output_dir": self.dirOutput.value,
            "include_types": bool(self.chkTypes.checked),
            "include_line_comments": bool(self.chkLineComments.checked),
        }


class ImportForm(ida_kernwin.Form):
    def __init__(self):
        F = ida_kernwin.Form
        F.__init__(self, r"""STARTITEM 0
BUTTON YES* Importar
BUTTON CANCEL Cancelar
IDA Sync - Importar datos

<#Carpeta que contiene functions_export.json y types_export.h#Carpeta de entrada\::{dirInput}>

<Direcciones / RVA (usar delta de base):{rbAddress}>
<Firma de bytes (byte matching - recomendado ante reubicaciones):{rbSignature}>{rbGroup}>

<Delta de base en hex (solo aplica al modo Direcciones / RVA, ej. -1000):{numDelta}>

<Incluir tipos locales al importar:{chkTypes}>{cGroup}>
""", {
            'dirInput': F.DirInput(),
            'rbGroup': F.RadGroupControl(('rbAddress', 'rbSignature')),
            'numDelta': F.NumericInput(tp=ida_kernwin.Form.FT_HEX),
            'cGroup': F.ChkGroupControl(('chkTypes',)),
        })

    def get_values(self):
        mode = "address" if self.rbGroup.value == 0 else "signature"
        return {
            "input_dir": self.dirInput.value,
            "mode": mode,
            "base_delta": self.numDelta.value,
            "include_types": bool(self.chkTypes.checked),
        }


# ---------------------------------------------------------------------------
# GUI - Action handlers
# ---------------------------------------------------------------------------

def _default_dir():
    try:
        path = idaapi.get_input_file_path()
        if path:
            return os.path.dirname(path)
    except Exception:
        pass
    return ""


class ExportAction(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        form = ExportForm()
        form.Compile()
        form.dirOutput.value = _default_dir()
        form.chkTypes.checked = True
        form.chkLineComments.checked = True

        ok = form.Execute()
        if ok == 1:
            values = form.get_values()
            form.Free()

            if not values["output_dir"]:
                ida_kernwin.warning("Debes indicar una carpeta de salida.")
                return 1

            n_funcs, n_types, json_path, types_path = do_export(
                values["output_dir"],
                include_types=values["include_types"],
                include_line_comments=values["include_line_comments"],
            )

            msg = "Exportacion completa.\n\nFunciones exportadas: %d\n" % n_funcs
            if values["include_types"]:
                msg += "Tipos exportados: %d\n" % n_types
            msg += "\nJSON: %s" % json_path
            if values["include_types"]:
                msg += "\nHeader: %s" % types_path

            ida_kernwin.info(msg)
        else:
            form.Free()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class ImportAction(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        form = ImportForm()
        form.Compile()
        form.dirInput.value = _default_dir()
        form.rbGroup.value = 1  # por defecto: firma de bytes (mas robusto)
        form.numDelta.value = 0
        form.chkTypes.checked = True

        ok = form.Execute()
        if ok == 1:
            values = form.get_values()
            form.Free()

            if not values["input_dir"] or not os.path.isdir(values["input_dir"]):
                ida_kernwin.warning("Debes indicar una carpeta de entrada valida.")
                return 1

            result = do_import(
                values["input_dir"],
                mode=values["mode"],
                base_delta=values["base_delta"],
                include_types=values["include_types"],
            )

            modo_txt = "Direcciones / RVA" if values["mode"] == "address" else "Firma de bytes"
            msg = (
                "Importacion completa (modo: %s).\n\n"
                "Renombradas: %d\n"
                "Prototipos aplicados: %d\n"
                "Comentarios aplicados: %d\n"
                "Sin match: %d\n"
            ) % (modo_txt, result["renamed"], result["typed"],
                 result["commented"], len(result["unmatched"]))

            if result["types_errors"] is not None:
                msg += "\nErrores/advertencias al importar tipos: %d" % result["types_errors"]

            if result["unmatched"]:
                nombres = [n for n in result["unmatched"] if n]
                preview = ", ".join(nombres[:30])
                if len(nombres) > 30:
                    preview += " ..."
                msg += "\n\nEjemplos sin match:\n%s" % preview

            ida_kernwin.info(msg)
        else:
            form.Free()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------

class IDASyncPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Exporta/Importa nombres de funciones, comentarios y tipos entre IDBs"
    help = "Edit > Plugins > IDA Sync Exporter / IDA Sync Importer"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""

    ACTION_EXPORT = "ida_sync:export"
    ACTION_IMPORT = "ida_sync:import"

    def init(self):
        export_desc = ida_kernwin.action_desc_t(
            self.ACTION_EXPORT,
            "IDA Sync: Exportar funciones/comentarios/tipos...",
            ExportAction(),
            PLUGIN_HOTKEY_EXPORT,
            "Exporta nombres de funciones, prototipos, comentarios y tipos locales",
            -1,
        )
        import_desc = ida_kernwin.action_desc_t(
            self.ACTION_IMPORT,
            "IDA Sync: Importar funciones/comentarios/tipos...",
            ImportAction(),
            PLUGIN_HOTKEY_IMPORT,
            "Importa nombres de funciones, prototipos, comentarios y tipos locales",
            -1,
        )

        ida_kernwin.register_action(export_desc)
        ida_kernwin.register_action(import_desc)

        ida_kernwin.attach_action_to_menu(
            "Edit/Plugins/IDA Sync Exporter", self.ACTION_EXPORT, ida_kernwin.SETMENU_APP
        )
        ida_kernwin.attach_action_to_menu(
            "Edit/Plugins/IDA Sync Importer", self.ACTION_IMPORT, ida_kernwin.SETMENU_APP
        )

        print("[IDA Sync] Plugin cargado. Ctrl-Alt-E = Exportar, Ctrl-Alt-I = Importar.")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        choice = ida_kernwin.ask_buttons(
            "Exportar", "Importar", "Cancelar", 1,
            "IDA Sync\n\nQue operacion deseas realizar?"
        )
        if choice == 1:
            ExportAction().activate(None)
        elif choice == 0:
            ImportAction().activate(None)

    def term(self):
        try:
            ida_kernwin.detach_action_from_menu("Edit/Plugins/IDA Sync Exporter", self.ACTION_EXPORT)
            ida_kernwin.detach_action_from_menu("Edit/Plugins/IDA Sync Importer", self.ACTION_IMPORT)
            ida_kernwin.unregister_action(self.ACTION_EXPORT)
            ida_kernwin.unregister_action(self.ACTION_IMPORT)
        except Exception:
            pass


def PLUGIN_ENTRY():
    return IDASyncPlugin()
