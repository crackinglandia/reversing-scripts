"""
searchpattern.py — Frida pattern scanner con Interceptor+Stalker y hook en OEP

Uso:
  python searchpattern.py --spawn C:\\target.exe --pattern-file patterns.txt
  python searchpattern.py --attach target.exe   --pattern-file patterns.txt
  python searchpattern.py --pid 1234 --module target.exe --pattern-file patterns.txt

Formato de patterns.txt:
  # Línea simple (usa los defaults de la CLI)
  48 8B ?? 4D ??

  # Bloque con opciones propias
  [pattern]
  bytes = 48 81 EC A0 02 00 00 48 8B 05 ?? ?? ?? ??
  name  = cifrado_stack_init
  regs  = rcx,rdx,r8
  buf   = rcx:256
  dis   = 32

Para salir: Enter o Ctrl+C.
"""

import frida
import sys
import argparse
import json
import os
import threading


# ── Script JS ────────────────────────────────────────────────────────────────

JS_TEMPLATE = r"""
(function() {
    var CFG       = {config};
    var modName   = CFG.module;
    var entries   = CFG.patterns;
    var disDef    = CFG.dis_bytes;
    var spawnMode = CFG.spawn_mode;   // true cuando se usó --spawn

    var mod  = Process.getModuleByName(modName);
    var base = mod.base;
    var size = mod.size;

    // ── Helpers ──────────────────────────────────────────────────────────────

    function pad(s, n) {
        s = String(s);
        while (s.length < n) s = " " + s;
        return s;
    }

    function disassemble(addr, maxBytes) {
        try {
            var lines = [], cur = addr, total = 0;
            while (total < maxBytes) {
                var ins = Instruction.parse(cur);
                lines.push("    " + cur + "  " + ins.mnemonic + " " + ins.opStr);
                total += ins.size;
                cur    = cur.add(ins.size);
            }
            return lines.join("\n");
        } catch(e) {
            return "    [disasm error: " + e.message + "]";
        }
    }

    function reportHit(label, context, bufReg, bufSize, regs) {
        var out = "[HIT] '" + label + "'  RIP=" + context.pc;
        if (regs && regs.length > 0) {
            out += "\n  [REGS]";
            regs.forEach(function(r) {
                try   { out += "\n    " + pad(r,4) + " = " + context[r]; }
                catch(e) { out += "\n    " + pad(r,4) + " = [error]"; }
            });
        }
        if (bufReg) {
            try {
                var ptr   = context[bufReg];
                var bytes = Memory.readByteArray(ptr, bufSize);
                out += "\n  [BUF] " + bufReg + "=" + ptr + "  size=" + bufSize;
                send({ type: "hit",  msg: out });
                send({ type: "dump", data: bytes,
                       label: "'" + label + "' BUF@" + ptr });
                return;
            } catch(e) {
                out += "\n  [BUF ERR] " + e.message;
            }
        }
        send({ type: "hit", msg: out });
    }

    // ── Leer OEP desde el PE header ──────────────────────────────────────────
    // DOS Header → e_lfanew → NT Headers → OptionalHeader.AddressOfEntryPoint

    function findOEP() {
        try {
            var e_lfanew       = base.add(0x3C).readU32();
            var ntHeaders      = base.add(e_lfanew);
            var peSig          = ntHeaders.readU32();
            if (peSig !== 0x4550) {          // "PE\0\0"
                send({ type: "info", msg: "[OEP] Firma PE inválida, no se puede leer OEP" });
                return null;
            }
            // OptionalHeader comienza en NT_HEADERS + 0x18 (Signature 4 + FileHeader 20)
            // AddressOfEntryPoint está en OptionalHeader + 0x10
            var oepRva = ntHeaders.add(0x18).add(0x10).readU32();
            if (oepRva === 0) {
                send({ type: "info", msg: "[OEP] OEP es 0 (DLL sin entry point?)" });
                return null;
            }
            return base.add(oepRva);
        } catch(e) {
            send({ type: "info", msg: "[OEP] Error leyendo PE header: " + e.message });
            return null;
        }
    }

    // ── Mapa de direcciones para Stalker ──────────────────────────────────────
    var stalkerMap  = {};
    var needStalker = false;

    function transformForStalker(iterator) {
        var ins = iterator.next();
        while (ins !== null) {
            var key = ins.address.toString();
            if (stalkerMap[key]) {
                var t = stalkerMap[key];
                iterator.putCallout((function(entry) {
                    return function(context) {
                        reportHit(entry.label, context,
                                  entry.bufReg, entry.bufSize, entry.regs);
                    };
                })(t));
            }
            iterator.keep();
            ins = iterator.next();
        }
    }

    function followThread(tid, reason) {
        try {
            Stalker.follow(tid, {
                events:    { call: false, ret: false, exec: false },
                transform: transformForStalker
            });
            send({ type: "info", msg:
                "[STALKER] Thread " + tid + " seguido" +
                (reason ? " (" + reason + ")" : "") });
        } catch(e) {
            // "already following" es normal si el thread ya estaba cubierto
            if (e.message.indexOf("already") === -1)
                send({ type: "info", msg:
                    "[STALKER] Thread " + tid + " error: " + e.message });
        }
    }

    // ── Scan y hookeo ─────────────────────────────────────────────────────────

    entries.forEach(function(entry) {
        var patBytes = entry.bytes;
        var label    = entry.name || patBytes.substring(0, 28) + "...";
        var regs     = entry.regs     || [];
        var bufReg   = entry.buf_reg  || "";
        var bufSize  = entry.buf_size || 64;
        var disBytes = (entry.dis_bytes !== undefined) ? entry.dis_bytes : disDef;

        send({ type: "info", msg: "[SCAN] '" + label + "'  =>  " + patBytes });

        var matches = Memory.scanSync(base, size, patBytes);
        if (matches.length === 0) {
            send({ type: "info", msg: "[MISS] '" + label + "': patron no encontrado" });
            return;
        }

        matches.forEach(function(match) {
            var addr     = match.address;
            var offset   = addr.sub(base).toInt32();
            var insSize  = 0;
            try { insSize = Instruction.parse(addr).size; } catch(e) {}

            send({ type: "info", msg:
                "[MATCH] '" + label + "'  " + addr +
                "  offset=+0x" + offset.toString(16).toUpperCase() +
                "  insn_size=" + insSize + "B"
            });

            if (disBytes > 0)
                send({ type: "info", msg:
                    "[DISASM @ " + addr + "]\n" + disassemble(addr, disBytes) });

            // Intentar Interceptor primero
            var hooked = false;
            try {
                Interceptor.attach(addr, {
                    onEnter: (function(lbl, br, bs, rg) {
                        return function(args) {
                            reportHit(lbl, this.context, br, bs, rg);
                        };
                    })(label, bufReg, bufSize, regs)
                });
                hooked = true;
                send({ type: "info", msg:
                    "[HOOK] '" + label + "' via Interceptor (insn " + insSize + "B)" });
            } catch(e) {
                send({ type: "info", msg:
                    "[HOOK] '" + label + "' Interceptor falló (" + e.message +
                    ") → Stalker" });
            }

            if (!hooked) {
                stalkerMap[addr.toString()] = {
                    label:   label,
                    regs:    regs,
                    bufReg:  bufReg,
                    bufSize: bufSize,
                };
                needStalker = true;
            }
        });
    });

    // ── Activar Stalker ───────────────────────────────────────────────────────

    if (needStalker) {
        var nTargets = Object.keys(stalkerMap).length;
        send({ type: "info", msg:
            "[STALKER] Necesario para " + nTargets + " dirección(es)" });

        if (spawnMode) {
            // ── Modo spawn: hookear el OEP ────────────────────────────────────
            // El proceso está suspendido en el loader. Cuando el OEP ejecuta,
            // el thread principal YA ESTÁ corriendo → Stalker.follow desde adentro
            // del thread es la forma más confiable.
            var oep = findOEP();
            if (oep) {
                send({ type: "info", msg: "[OEP] Entry point del exe: " + oep });
                try {
                    Interceptor.attach(oep, {
                        onEnter: function(args) {
                            var tid = Process.getCurrentThreadId();
                            send({ type: "info", msg:
                                "[OEP] Hit! Thread=" + tid +
                                " — activando Stalker antes de que corra el exe..." });
                            followThread(tid, "OEP hook");

                            // También seguir cualquier thread que ya exista
                            // (threads del CRT creados antes del OEP)
                            Process.enumerateThreads().forEach(function(t) {
                                if (t.id !== tid) followThread(t.id, "pre-OEP");
                            });
                        }
                    });
                    send({ type: "info", msg:
                        "[OEP] Hook instalado — Stalker se activará al llegar al entry point" });
                } catch(e) {
                    send({ type: "info", msg:
                        "[OEP] No se pudo hookear OEP (" + e.message +
                        ") — siguiendo threads actuales como fallback" });
                    Process.enumerateThreads().forEach(function(t) {
                        followThread(t.id, "fallback spawn");
                    });
                }
            } else {
                // No se pudo leer OEP: seguir threads actuales
                Process.enumerateThreads().forEach(function(t) {
                    followThread(t.id, "no-OEP fallback");
                });
            }
        } else {
            // ── Modo attach/pid: seguir todos los threads existentes ──────────
            var threads = Process.enumerateThreads();
            send({ type: "info", msg:
                "[STALKER] Modo attach — siguiendo " + threads.length + " thread(s)" });
            threads.forEach(function(t) {
                followThread(t.id, "attach");
            });
        }
    }

    // ── Exception handler ─────────────────────────────────────────────────────
    // Loggea excepciones y las pasa al handler del programa (return false).
    // Necesario cuando el programa usa excepciones como flujo de control
    // (ej: VEH que descifra código, anti-debug tricks, etc.)
    Process.setExceptionHandler(function(details) {
        send({ type: "info", msg:
            "[EXCEPTION] type="    + details.type +
            "  addr="              + details.address +
            "  → pasando al handler del programa"
        });
        // false = no lo manejamos, que lo tome el SEH/VEH del programa
        return false;
    });

    // ── VirtualProtect hook → Stalker cache invalidation ─────────────────────
    // Cuando el programa modifica páginas de código (self-modifying code /
    // unpacking / cifrado en runtime), Stalker tiene el JIT del código viejo.
    // Al detectar un VirtualProtect que hace páginas ejecutables, invalidamos
    // el cache de Stalker para que recompile el código nuevo.
    if (needStalker) {
        var vpAddr = Module.findExportByName("kernel32.dll", "VirtualProtect");
        if (vpAddr) {
            Interceptor.attach(vpAddr, {
                onEnter: function(args) {
                    this.lpAddr  = args[0];
                    this.dwSize  = args[1].toInt32();
                    this.flProt  = args[2].toInt32();
                },
                onLeave: function(retval) {
                    if (retval.toInt32() === 0) return; // VirtualProtect falló
                    // Flags de página ejecutable: PAGE_EXECUTE*
                    var EXEC = 0x10 | 0x20 | 0x40 | 0x80;
                    if (!(this.flProt & EXEC)) return;

                    var rangeAddr = this.lpAddr;
                    var rangeSize = this.dwSize;
                    send({ type: "info", msg:
                        "[VP] Código modificado: " + rangeAddr +
                        "  size=" + rangeSize +
                        "  prot=0x" + this.flProt.toString(16) +
                        "  → invalidando cache de Stalker"
                    });

                    // Invalidar el JIT cache de Stalker para todos los threads
                    // que estamos siguiendo, para que recompile el nuevo código
                    Process.enumerateThreads().forEach(function(t) {
                        try {
                            Stalker.invalidate(t.id, rangeAddr);
                        } catch(e) { /* thread no seguido por Stalker */ }
                    });
                }
            });
            send({ type: "info", msg: "[VP] Hook VirtualProtect instalado" });
        } else {
            send({ type: "info", msg: "[VP] VirtualProtect no encontrado en kernel32" });
        }
    }

    send({ type: "info", msg: "[READY] Setup completo. Esperando hits..." });
})();
"""


# ── Helpers Python ────────────────────────────────────────────────────────────

def hexdump_py(data: bytes) -> str:
    lines = []
    for i in range(0, len(data), 16):
        chunk    = data[i:i+16]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        asc_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {i:04X}  {hex_part:<48}  |{asc_part}|")
    return "\n".join(lines)


def _strip_comment(line):
    if "#" in line:
        line = line[:line.index("#")]
    return line.strip()


def _validate_bytes(line, lineno):
    invalid = [c for c in line if c not in "0123456789abcdefABCDEF? \t"]
    if invalid:
        print(f"[WARN] línea {lineno}: caracteres inválidos {invalid!r}, ignorada.")
        return False
    return True


def load_patterns_from_file(path, default_regs, default_buf_reg,
                             default_buf_size, default_dis):
    entries = []
    current = None

    def flush(block):
        if not block:
            return
        if not block.get("bytes"):
            print(f"[WARN] bloque '{block.get('name','?')}' sin 'bytes =', ignorado.")
            return
        entries.append(block)

    def new_block():
        return {
            "bytes":     "",
            "name":      "",
            "regs":      list(default_regs),
            "buf_reg":   default_buf_reg,
            "buf_size":  default_buf_size,
            "dis_bytes": default_dis,
        }

    with open(path, "r", encoding="utf-8") as f:
        for lineno, raw in enumerate(f, 1):
            line = _strip_comment(raw)
            if not line:
                continue
            if line.lower() == "[pattern]":
                flush(current)
                current = new_block()
                continue
            if current is not None and "=" in line:
                key, _, val = line.partition("=")
                key = key.strip().lower()
                val = val.strip()
                if key == "bytes":
                    if _validate_bytes(val, lineno):
                        current["bytes"] = val
                elif key == "name":
                    current["name"] = val
                elif key == "regs":
                    current["regs"] = [r.strip() for r in val.split(",") if r.strip()]
                elif key == "buf":
                    parts = val.split(":")
                    current["buf_reg"]  = parts[0].strip()
                    current["buf_size"] = int(parts[1]) if len(parts) > 1 else 64
                elif key == "dis":
                    current["dis_bytes"] = int(val)
                else:
                    print(f"[WARN] línea {lineno}: clave desconocida '{key}', ignorada.")
                continue
            if not _validate_bytes(line, lineno):
                continue
            flush(current)
            current = None
            entries.append({
                "bytes":     line,
                "name":      (line[:28] + "...") if len(line) > 28 else line,
                "regs":      list(default_regs),
                "buf_reg":   default_buf_reg,
                "buf_size":  default_buf_size,
                "dis_bytes": default_dis,
            })

    flush(current)
    return entries


def build_script(module_name, pattern_entries, dis_bytes_default, spawn_mode):
    config = {
        "module":     module_name,
        "patterns":   pattern_entries,
        "dis_bytes":  dis_bytes_default,
        "spawn_mode": spawn_mode,
    }
    return JS_TEMPLATE.replace("{config}", json.dumps(config))


class Logger:
    def __init__(self, log_path=None):
        self._con  = sys.stdout
        self._file = open(log_path, "w", encoding="utf-8", buffering=1) if log_path else None

    def write(self, s):
        self._con.write(s)
        self._con.flush()
        if self._file:
            self._file.write(s)
            self._file.flush()

    def close(self):
        if self._file:
            self._file.close()

    def __call__(self, *args, sep=" ", end="\n"):
        self.write(sep.join(str(a) for a in args) + end)


def main():
    ap = argparse.ArgumentParser(
        description="Frida pattern scanner — Interceptor+Stalker con OEP hook en spawn",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)

    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--spawn",  metavar="EXE",    help="Lanzar proceso desde cero (pausa en OEP)")
    mode.add_argument("--attach", metavar="NOMBRE", help="Attachear por nombre")
    mode.add_argument("--pid",    metavar="PID", type=int, help="Attachear por PID")

    pat = ap.add_mutually_exclusive_group(required=True)
    pat.add_argument("--pattern",      metavar="HEX",  help="Patrón hex con ?? wildcards")
    pat.add_argument("--pattern-file", metavar="FILE", help="Archivo con patrones")

    ap.add_argument("--module", metavar="NOMBRE", help="Módulo a escanear")
    ap.add_argument("--regs",   metavar="REG[,REG...]", default="",
                    help="Default global de registros a loggear")
    ap.add_argument("--buf",    metavar="REG:SIZE", default="",
                    help="Default global de buffer a dumpear")
    ap.add_argument("--dis",    metavar="BYTES", type=int, default=64,
                    help="Default global de disasm en bytes (0=off)")
    ap.add_argument("--log",    metavar="FILE",
                    help="Archivo de log con flush inmediato")

    args = ap.parse_args()
    log  = Logger(args.log)

    default_regs     = [r.strip() for r in args.regs.split(",") if r.strip()]
    default_buf_reg  = ""
    default_buf_size = 64
    if args.buf:
        parts            = args.buf.split(":")
        default_buf_reg  = parts[0].strip()
        default_buf_size = int(parts[1]) if len(parts) > 1 else 64

    if args.pattern:
        entries = [{
            "bytes":     args.pattern,
            "name":      (args.pattern[:28] + "...") if len(args.pattern) > 28 else args.pattern,
            "regs":      default_regs,
            "buf_reg":   default_buf_reg,
            "buf_size":  default_buf_size,
            "dis_bytes": args.dis,
        }]
    else:
        entries = load_patterns_from_file(
            args.pattern_file,
            default_regs, default_buf_reg, default_buf_size, args.dis)
        if not entries:
            log("[ERR] Sin patrones válidos.")
            sys.exit(1)
        log(f"[CFG] {len(entries)} patrón(es) desde '{args.pattern_file}'")

    device     = frida.get_local_device()
    done       = threading.Event()
    spawn_mode = args.spawn is not None

    if args.spawn:
        mod_name = args.module or os.path.basename(args.spawn)
        log(f"[*] Spawning (pausa en OEP): {args.spawn}")
        pid     = device.spawn(args.spawn)
        session = device.attach(pid)
    elif args.attach:
        mod_name   = args.module or args.attach
        spawn_mode = False
        log(f"[*] Attaching to: {args.attach}")
        session = device.attach(args.attach)
        pid     = None
    else:
        mod_name   = args.module or ""
        spawn_mode = False
        if not mod_name:
            log("[ERR] Con --pid necesitás --module.")
            sys.exit(1)
        log(f"[*] Attaching to PID: {args.pid}")
        session = device.attach(args.pid)
        pid     = None

    log(f"[CFG] Módulo: {mod_name}  |  spawn_mode={spawn_mode}")
    for i, e in enumerate(entries):
        buf_str = f"{e['buf_reg']}:{e['buf_size']}" if e["buf_reg"] else "(ninguno)"
        log(f"  [{i+1}] '{e['name']}'  regs={e['regs'] or '[]'}  "
            f"buf={buf_str}  dis={e['dis_bytes']}B")
    log("")

    def on_message(message, data):
        if message["type"] == "send":
            p    = message["payload"]
            kind = p.get("type", "")
            if kind in ("info", "hit"):
                log(p["msg"])
            elif kind == "dump":
                log(f"  [{p.get('label','DUMP')}]")
                log(hexdump_py(bytes(data)) if data else "  (sin datos)")
        elif message["type"] == "error":
            log(f"[JS ERROR] {message['description']}")
            if message.get("stack"):
                log(message["stack"])

    def on_detached(reason):
        log(f"\n[!] Sesión terminada: {reason}")
        done.set()

    session.on("detached", on_detached)

    script = session.create_script(
        build_script(mod_name, entries, args.dis, spawn_mode))
    script.on("message", on_message)
    script.load()

    if pid is not None:
        log("[*] Script cargado. Reanudando proceso...")
        device.resume(pid)

    log("[*] Corriendo. Presioná Enter o Ctrl+C para salir.\n")

    def wait_for_enter():
        try:
            input()
        except Exception:
            pass
        done.set()

    threading.Thread(target=wait_for_enter, daemon=True).start()

    try:
        done.wait()
    except KeyboardInterrupt:
        log("\n[*] Ctrl+C recibido.")
    finally:
        log("[*] Cerrando...")
        try:
            session.detach()
        except Exception:
            pass
        log.close()


if __name__ == "__main__":
    main()
