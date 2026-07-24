"""
pattern_gen.py — IDA Pro Plugin: Generador de patrones con wildcards
═════════════════════════════════════════════════════════════════════
Compatible con IDA Pro 9.3+, Python 3.

Instalación:
    Copiar a %APPDATA%\\Hex-Rays\\IDA Pro\\plugins\\

Uso:
    1. Seleccionar rango en la vista de disassembly (Shift+click / Alt+L)
    2. Ctrl+Alt+P  o  Edit → Plugins → Pattern Generator
       o click derecho → Pattern Generator
"""

import ida_idaapi
import ida_kernwin
import ida_bytes
import ida_ua
import ida_segment
import idc
import idautils

# ── Qt ───────────────────────────────────────────────────────────────────────
try:
    from PyQt5 import QtWidgets, QtCore, QtGui
    from PyQt5.QtCore import Qt
except ImportError:
    try:
        from PySide2 import QtWidgets, QtCore, QtGui
        from PySide2.QtCore import Qt
    except ImportError:
        QtWidgets = None

PLUGIN_NAME    = "Pattern Generator"
PLUGIN_HOTKEY  = "Ctrl+Alt+P"
PLUGIN_VERSION = "1.3"
ACTION_ID      = "patterngen:generate"


# ═════════════════════════════════════════════════════════════════════════════
# Tablas de constantes de ida_ua construidas dinámicamente
# (evita AttributeError en cualquier versión de IDA)
# ═════════════════════════════════════════════════════════════════════════════

def _getua(name, default=None):
    """getattr seguro sobre ida_ua."""
    return getattr(ida_ua, name, default)


# Tipos de operando (o_*) — existen desde IDA 6, pero usamos getattr
# para ser completamente defensivos
_O_VOID  = _getua("o_void",  0)
_O_REG   = _getua("o_reg",   1)
_O_MEM   = _getua("o_mem",   2)
_O_PHRASE= _getua("o_phrase",3)
_O_DISPL = _getua("o_displ", 4)
_O_IMM   = _getua("o_imm",   5)
_O_FAR   = _getua("o_far",   6)
_O_NEAR  = _getua("o_near",  7)

# Máximo de operandos por instrucción
_MAX_OPS = _getua("UA_MAXOP", 8)

# Mapa dtype → bytes, construido con getattr para cada constante dt_*
# Si una constante no existe en esta versión de IDA simplemente no se incluye
def _build_dtype_map():
    entries = [
        ("dt_byte",     1),
        ("dt_word",     2),
        ("dt_dword",    4),
        ("dt_float",    4),
        ("dt_qword",    8),
        ("dt_double",   8),
        ("dt_tbyte",   10),
        ("dt_fword",    6),
        ("dt_3byte",    3),
        ("dt_packreal", 12),
        ("dt_xword",   16),   # IDA < 9.x: XMM (128-bit)
        ("dt_yword",   32),   # AVX (256-bit)
        ("dt_zword",   64),   # AVX-512 (512-bit)
        ("dt_ldbl",    10),   # long double alternativo
    ]
    m = {}
    for name, size in entries:
        val = _getua(name)
        if val is not None:
            m[val] = size
    return m

_DTYPE_MAP = _build_dtype_map()


def _dtype_to_bytes(dtype):
    """Convierte dtype de IDA a número de bytes; default 4 si no se conoce."""
    return _DTYPE_MAP.get(dtype, 4)


# Tipos de widget habilitados, construidos dinámicamente
def _build_widget_types():
    names = ("BWN_DISASM", "BWN_PSEUDOCODE", "BWN_DUMP", "BWN_HEXVIEW")
    s = set()
    for n in names:
        v = getattr(ida_kernwin, n, None)
        if v is not None:
            s.add(v)
    return s

_ENABLED_WIDGETS = _build_widget_types()


# ═════════════════════════════════════════════════════════════════════════════
# Lógica de generación de patrón
# ═════════════════════════════════════════════════════════════════════════════

def is_absolute_address(value):
    """True si el valor cae dentro de algún segmento cargado."""
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if seg and seg.start_ea <= value < seg.end_ea:
            return True
    return False


def _estimate_opcode_len(raw):
    """Estima longitud de prefijos + opcode (sin operandos)."""
    prefixes = {
        0x26, 0x2E, 0x36, 0x3E,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
        0x64, 0x65, 0x66, 0x67, 0xF0, 0xF2, 0xF3,
    }
    i = 0
    while i < len(raw) and raw[i] in prefixes:
        i += 1
    if i < len(raw) and raw[i] == 0x0F:
        i += 1
        if i < len(raw) and raw[i] in (0x38, 0x3A):
            i += 1
    i += 1
    return max(1, min(i, len(raw)))


def get_wildcard_mask(insn):
    """
    Retorna lista de bool (True=fijo, False=wildcard) de longitud insn.size.

    Wildcardea:
      - Offsets relativos de call/jmp (o_near, o_far)
      - Referencias a memoria (o_mem) — incluye RIP-relative en x64
      - Displacement grande en [base+disp] (o_displ)
      - Immediates que parecen dirección o offset de 3+ bytes
    Mantiene fijos:
      - Bytes de opcode y prefijos
      - Operandos de registro
      - Immediates pequeños (<= 0xFFFF)
    """
    size = insn.size
    raw  = ida_bytes.get_bytes(insn.ea, size)
    if not raw:
        return [True] * size

    mask = [True] * size

    for i in range(_MAX_OPS):
        op = insn.ops[i]
        if op.type == _O_VOID:
            break

        wildcard = False

        if op.type in (_O_NEAR, _O_FAR):
            # Offset relativo de salto/call → siempre wildcard
            wildcard = True

        elif op.type == _O_MEM:
            # Cualquier referencia a memoria (incluye RIP-relative en x64)
            wildcard = True

        elif op.type == _O_DISPL:
            # [base_reg + disp]: wildcard si el disp es grande o parece VA
            addr = op.addr & 0xFFFFFFFFFFFFFFFF
            if is_absolute_address(addr) or addr > 0xFFFF:
                wildcard = True

        elif op.type == _O_IMM:
            val = op.value & 0xFFFFFFFFFFFFFFFF
            if is_absolute_address(val) or val > 0x7FFFF:
                wildcard = True

        if not wildcard:
            continue

        offb     = op.offb
        op_bytes = _dtype_to_bytes(op.dtype)

        if offb > 0:
            for j in range(offb, min(offb + op_bytes, size)):
                mask[j] = False
        else:
            # IDA no reportó offset exacto: wildcardear desde después del opcode
            opc_len = _estimate_opcode_len(raw)
            for j in range(opc_len, size):
                mask[j] = False

    return mask


def generate_pattern(start_ea, end_ea):
    """
    Genera el patrón entre start_ea y end_ea.
    Retorna (pattern_str, stats_dict).
    """
    tokens    = []
    total     = 0
    wildcards = 0
    n_insn    = 0
    ea        = start_ea

    while ea < end_ea:
        insn     = ida_ua.insn_t()
        insn_len = ida_ua.decode_insn(insn, ea)

        if insn_len == 0:
            b = ida_bytes.get_byte(ea)
            tokens.append(f"{b:02X}")
            total += 1
            ea    += 1
            continue

        actual = min(insn_len, end_ea - ea)
        mask   = get_wildcard_mask(insn)
        raw    = ida_bytes.get_bytes(ea, actual)

        for i in range(actual):
            if mask[i]:
                tokens.append(f"{raw[i]:02X}")
            else:
                tokens.append("??")
                wildcards += 1

        total  += actual
        n_insn += 1
        ea     += insn_len

    pattern = " ".join(tokens)
    stats   = {
        "bytes":        total,
        "wildcards":    wildcards,
        "fixed":        total - wildcards,
        "instructions": n_insn,
        "specificity":  round((total - wildcards) / total * 100, 1) if total else 0,
    }
    return pattern, stats


# ═════════════════════════════════════════════════════════════════════════════
# Diálogo Qt
# ═════════════════════════════════════════════════════════════════════════════

class PatternDialog(QtWidgets.QDialog):

    def __init__(self, pattern, stats, start_ea, end_ea, parent=None):
        super().__init__(parent, Qt.Window)
        self.pattern = pattern
        self.setWindowTitle(f"{PLUGIN_NAME} v{PLUGIN_VERSION}")
        self.setMinimumWidth(760)
        self._build_ui(pattern, stats, start_ea, end_ea)

    def _build_ui(self, pattern, stats, start_ea, end_ea):
        root = QtWidgets.QVBoxLayout(self)
        root.setSpacing(8)

        name = idc.get_name(start_ea) or hex(start_ea)
        info = (f"Rango: {name} → {hex(end_ea)}   "
                f"({stats['instructions']} instrucciones, {stats['bytes']} bytes)   "
                f"Fijos: {stats['fixed']}   "
                f"Wildcards: {stats['wildcards']}   "
                f"Especificidad: {stats['specificity']}%")
        lbl = QtWidgets.QLabel(info)
        lbl.setWordWrap(True)
        root.addWidget(lbl)

        root.addWidget(QtWidgets.QLabel("Patrón (con espacios — para Frida / searchpattern.py):"))
        self._te_spaced = self._make_textedit(self._format_16(pattern))
        root.addWidget(self._te_spaced)

        root.addWidget(QtWidgets.QLabel("Patrón (sin espacios):"))
        self._te_nospace = self._make_textedit(pattern.replace(" ", ""), lines=2)
        root.addWidget(self._te_nospace)

        root.addWidget(QtWidgets.QLabel("Patrón estilo C / PIN (array de bytes):"))
        self._te_c = self._make_textedit(self._to_c_array(pattern), lines=2)
        root.addWidget(self._te_c)

        btn_row = QtWidgets.QHBoxLayout()
        buttons = [
            ("Copiar (espacios)",    lambda: self._copy(pattern)),
            ("Copiar (sin espacios)",lambda: self._copy(pattern.replace(" ", ""))),
            ("Copiar (C array)",     lambda: self._copy(self._to_c_array(pattern))),
            ("Guardar en archivo…",  self._save),
            ("Cerrar",               self.accept),
        ]
        for label, slot in buttons:
            b = QtWidgets.QPushButton(label)
            b.clicked.connect(slot)
            btn_row.addWidget(b)
        root.addLayout(btn_row)

    @staticmethod
    def _make_textedit(text, lines=4):
        te = QtWidgets.QPlainTextEdit(text)
        te.setReadOnly(True)
        te.setFont(QtGui.QFont("Courier New", 9))
        te.setFixedHeight(lines * 20 + 12)
        return te

    @staticmethod
    def _format_16(pattern):
        tokens = pattern.split()
        rows   = []
        for i in range(0, len(tokens), 16):
            rows.append(" ".join(tokens[i:i+16]))
        return "\n".join(rows)

    @staticmethod
    def _to_c_array(pattern):
        parts = [f"0x{t}" if t != "??" else "0x??" for t in pattern.split()]
        return "{ " + ", ".join(parts) + " }"

    @staticmethod
    def _copy(text):
        QtWidgets.QApplication.clipboard().setText(text)
        ida_kernwin.msg(f"[PatternGen] Copiado al clipboard ({len(text)} chars)\n")

    def _save(self):
        path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Guardar patrón", "",
            "Text files (*.txt *.pat);;All files (*)")
        if not path:
            return
        try:
            with open(path, "a", encoding="utf-8") as f:
                f.write(f"# {self.windowTitle()}\n")
                f.write(self.pattern + "\n\n")
            ida_kernwin.msg(f"[PatternGen] Guardado en {path}\n")
        except Exception as ex:
            QtWidgets.QMessageBox.warning(self, "Error", str(ex))


def _get_ida_main_widget():
    """Intenta obtener el widget principal de IDA para usarlo como parent."""
    try:
        for name in ("IDA View-A", "Pseudocode-A", "IDA View-0"):
            w = ida_kernwin.find_widget(name)
            if w:
                return ida_kernwin.PluginForm.FormToPyQtWidget(w)
    except Exception:
        pass
    return None


def show_pattern_dialog(pattern, stats, start_ea, end_ea):
    parent = _get_ida_main_widget()
    dlg    = PatternDialog(pattern, stats, start_ea, end_ea, parent)
    dlg.exec_()


def show_pattern_fallback(pattern, stats, start_ea, end_ea):
    """Fallback sin Qt: imprime en output window."""
    ida_kernwin.msg("=" * 60 + "\n")
    ida_kernwin.msg(f"[PatternGen] {hex(start_ea)} → {hex(end_ea)}\n")
    ida_kernwin.msg(f"  Instrucciones : {stats['instructions']}\n")
    ida_kernwin.msg(f"  Especificidad : {stats['specificity']}%\n")
    ida_kernwin.msg(f"  Patrón:\n{pattern}\n")
    ida_kernwin.msg("=" * 60 + "\n")


# ═════════════════════════════════════════════════════════════════════════════
# Hook para menú contextual (click derecho)
# ═════════════════════════════════════════════════════════════════════════════

class PatternGenHooks(ida_kernwin.UI_Hooks):

    def finish_populating_widget_popup(self, widget, popup):
        if ida_kernwin.get_widget_type(widget) in _ENABLED_WIDGETS:
            ida_kernwin.attach_action_to_popup(
                widget, popup, ACTION_ID, None, ida_kernwin.SETMENU_APP)


# ═════════════════════════════════════════════════════════════════════════════
# Acción
# ═════════════════════════════════════════════════════════════════════════════

class GeneratePatternAction(ida_kernwin.action_handler_t):

    def activate(self, ctx):
        sel, start_ea, end_ea = ida_kernwin.read_range_selection(ctx.widget)

        if not sel or start_ea == idc.BADADDR or end_ea == idc.BADADDR:
            cur = idc.get_screen_ea()
            if cur == idc.BADADDR:
                ida_kernwin.warning("No hay dirección activa.")
                return 0
            insn     = ida_ua.insn_t()
            insn_len = ida_ua.decode_insn(insn, cur)
            if insn_len == 0:
                ida_kernwin.warning(
                    "No se pudo decodificar la instrucción.\n"
                    "Seleccioná un rango e intentá de nuevo.")
                return 0
            start_ea = cur
            end_ea   = cur + insn_len

        if end_ea <= start_ea:
            ida_kernwin.warning("Rango inválido.")
            return 0

        try:
            pattern, stats = generate_pattern(start_ea, end_ea)
        except Exception as ex:
            ida_kernwin.warning(f"Error al generar patrón:\n{ex}")
            return 0

        if not pattern:
            ida_kernwin.warning("No se generaron bytes.")
            return 0

        ida_kernwin.msg(
            f"[PatternGen] {hex(start_ea)} → {hex(end_ea)}: "
            f"{stats['instructions']} instrucciones, "
            f"{stats['specificity']}% especificidad\n")

        if QtWidgets is not None:
            show_pattern_dialog(pattern, stats, start_ea, end_ea)
        else:
            show_pattern_fallback(pattern, stats, start_ea, end_ea)

        return 1

    def update(self, ctx):
        if ctx.widget_type in _ENABLED_WIDGETS:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


ACTION_DESC = ida_kernwin.action_desc_t(
    ACTION_ID,
    PLUGIN_NAME,
    GeneratePatternAction(),
    PLUGIN_HOTKEY,
    "Genera patrón de bytes con wildcards desde el rango seleccionado",
    -1)


# ═════════════════════════════════════════════════════════════════════════════
# Plugin
# ═════════════════════════════════════════════════════════════════════════════

class PatternGenPlugin(ida_idaapi.plugin_t):
    flags         = ida_idaapi.PLUGIN_KEEP
    comment       = "Generador de patrones con wildcards"
    help          = ""
    wanted_name   = PLUGIN_NAME
    wanted_hotkey = ""

    def init(self):
        if not ida_kernwin.register_action(ACTION_DESC):
            print("[PatternGen] Error: no se pudo registrar la acción.")
            return ida_idaapi.PLUGIN_SKIP

        ida_kernwin.attach_action_to_menu(
            "Edit/Plugins/", ACTION_ID, ida_kernwin.SETMENU_APP)

        self._hooks = PatternGenHooks()
        self._hooks.hook()

        print(f"[PatternGen] v{PLUGIN_VERSION} listo.  "
              f"Shortcut: {PLUGIN_HOTKEY}  |  Click derecho en disassembly")
        print(f"[PatternGen] Constantes cargadas: "
              f"MAX_OPS={_MAX_OPS}, "
              f"dtypes conocidos={len(_DTYPE_MAP)}, "
              f"widget types={len(_ENABLED_WIDGETS)}")
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        ida_kernwin.process_ui_action(ACTION_ID)

    def term(self):
        if hasattr(self, "_hooks"):
            self._hooks.unhook()
        ida_kernwin.detach_action_from_menu("Edit/Plugins/", ACTION_ID)
        ida_kernwin.unregister_action(ACTION_ID)
        print("[PatternGen] descargado.")


def PLUGIN_ENTRY():
    return PatternGenPlugin()
