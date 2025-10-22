# -*- coding: utf-8 -*-
# EmberScale_RE_Toolbox.py
# @author Kevin Mitchell
# @category AI Analysis
# @toolbar
#
# Anthropic tool-use loop for Ghidra (Jython-safe).
# - Read-only tools for reverse engineering assistance.
# - API key/model from Preferences or env (no hardcoded secrets).
# - Java HTTPS transport (trust-all) to avoid Jython SSL issues.
#
# Env overrides (optional):
#   ANTHROPIC_API_KEY / CLAUDE_API_KEY
#   ANTHROPIC_MODEL (e.g., "claude-sonnet-4-20250514")

import os
import json
from ghidra.framework.preferences import Preferences
from ghidra.util.task import ConsoleTaskMonitor

ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"

# -------------------------
# API key / model
# -------------------------
def get_api_key_from_preferences():
    prefs = Preferences.getUserPreferences()
    key = prefs.getString("ANTHROPIC_API_KEY", None)
    if key:
        return key
    key = os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("CLAUDE_API_KEY")
    if key:
        prefs.putString("ANTHROPIC_API_KEY", key)
        prefs.flush()
        print("Stored Anthropic API key in Preferences: {}".format(prefs.getFilename()))
        return key
    try:
        entered = askString("Anthropic API Key", "Enter your Anthropic API key (will be saved in Preferences):", "")
        if entered and entered.strip():
            key = entered.strip()
            prefs.putString("ANTHROPIC_API_KEY", key)
            prefs.flush()
            print("Stored Anthropic API key in Preferences: {}".format(prefs.getFilename()))
            return key
    except Exception:
        pass
    print("ERROR: Anthropic API key is required.")
    return None

def choose_model():
    # Try decxy.config if present
    try:
        from decxy.config import CLAUDE_MODELS
        if isinstance(CLAUDE_MODELS, (list, tuple)) and len(CLAUDE_MODELS) > 0:
            if len(CLAUDE_MODELS) == 1:
                return CLAUDE_MODELS[0]
            try:
                return askChoice("Claude Model", "Select a model", CLAUDE_MODELS, CLAUDE_MODELS[0])
            except Exception:
                return CLAUDE_MODELS[0]
    except Exception:
        pass
    # Env override
    m = os.environ.get("ANTHROPIC_MODEL")
    if m and m.strip():
        return m.strip()
    # Default
    return "claude-sonnet-4-20250514"

# -------------------------
# Context helpers
# -------------------------
def collect_function_map(max_count=200):
    fm = currentProgram.getFunctionManager()
    out = []
    it = fm.getFunctions(True)
    for f in it:
        if len(out) >= max_count:
            break
        out.append({"name": f.getName(), "entry": f.getEntryPoint().toString()})
    return out

def collect_strings(max_count=80):
    listing = currentProgram.getListing()
    it = listing.getDefinedData(True)
    out = []
    c = 0
    while it.hasNext() and c < max_count:
        d = it.next()
        try:
            dt = d.getDataType()
            if dt and dt.getName() and dt.getName().lower().startswith("string"):
                s = str(d.getValue()).encode("ascii", "ignore")
                if 3 < len(s) < 160:
                    out.append({"addr": d.getAddress().toString(), "s": s})
                    c += 1
        except Exception:
            pass
    return out

def build_intro(question, func_map, string_lits, examples_text):
    lines = []
    lines.append("You are assisting inside Ghidra. Tools are available; call them as needed.")
    lines.append("")
    lines.append("### User question")
    lines.append(question)
    if func_map:
        lines.append("")
        lines.append("### Functions (sample name -> entry)")
        for x in func_map[:50]:
            lines.append("- {} : {}".format(x["name"], x["entry"]))
    if string_lits:
        lines.append("")
        lines.append("### Strings (sample)")
        for s in string_lits[:25]:
            lines.append("- {} : {}".format(s["addr"], s["s"]))
    lines.append("")
    lines.append("When you need code, xrefs, signature info, or control-flow, use tools, then reason succinctly.")
    lines.append("")
    lines.append("### Example queries you can expect")
    lines.append(examples_text)
    return "\n".join(lines)

def print_usage_banner():
    examples = [
        "Map out what writes to 0x000B1C7C and show the basic blocks of the callee that does the most writes.",
        "Decompile FUN_000b0f54, then list its callers and give me a short summary of each caller's purpose based on xrefs/strings.",
        "Find strings containing 'auth' and show xrefs -> which functions are likely auth checks?",
        "At 0x000B1E6C, show 8 instructions before and 16 after, and tell me if this is part of a bounds check.",
        "Give me the full signature + locals for process_grid_pattern_copy, and explain the role of each parameter.",
    ]
    print("\n=== EmberScale RE Toolbox — example prompts ===")
    for ex in examples:
        print(" - " + ex)
    print("==============================================\n")
    return "\n".join("- " + ex for ex in examples)

# -------------------------
# USER PROMPT HELPER (inline menu)
# -------------------------
def _normalize_hex_addr(s):
    if not s:
        return None
    s = s.strip()
    if s.lower().startswith("0x"):
        s = s[2:]
    s = "".join([c for c in s if c in "0123456789abcdefABCDEF"]).upper()
    return s if s else None

def get_user_question():
    """
    Small menu of common RE tasks; asks for just the needed params and
    returns a synthesized natural-language question.
    """
    choices = [
        "Freeform",
        "Map writes to address + hottest callee basic blocks",
        "Decompile function + summarize callers via xrefs/strings",
        "Find strings by pattern + rank likely auth checks",
        "Disassemble window around address + check for bounds",
        "Function signature + locals + explain params"
    ]
    choice = None
    try:
        choice = askChoice("EmberScale RE Toolbox", "Select a task (or Freeform):", choices, choices[0])
    except Exception:
        choice = "Freeform"

    if choice == "Freeform":
        return askString("EmberScale RE Toolbox", "What do you want to analyze or inspect?", "")

    if choice == "Map writes to address + hottest callee basic blocks":
        a = askString("Target address", "Address (hex, e.g., 000B1C7C):", "000B1C7C")
        if not a: return None
        hx = _normalize_hex_addr(a)
        if not hx: return None
        return "Map out what writes to 0x{} and show the basic blocks of the callee that does the most writes.".format(hx)

    if choice == "Decompile function + summarize callers via xrefs/strings":
        fn = askString("Function", "Function name or entry (hex):", "FUN_000b0f54")
        if not fn: return None
        return "Decompile {}, then list its callers and give me a short summary of each caller's purpose based on xrefs/strings.".format(fn.strip())

    if choice == "Find strings by pattern + rank likely auth checks":
        pat = askString("String pattern", "Substring to search for in strings:", "auth")
        if not pat: return None
        return "Find strings containing {} and show xrefs -> which functions are likely auth checks?".format(pat.strip())

    if choice == "Disassemble window around address + check for bounds":
        a = askString("Center address", "Address (hex, e.g., 000B1E6C):", "000B1E6C")
        if not a: return None
        hx = _normalize_hex_addr(a)
        if not hx: return None
        try:
            before = askString("Look-behind", "How many instructions before?", "8")
            after  = askString("Look-ahead",  "How many instructions after?",  "16")
            b = int(before or "8"); af = int(after or "16")
        except Exception:
            b, af = 8, 16
        return "At 0x{}, show {} instructions before and {} after, and tell me if this is part of a bounds check.".format(hx, b, af)

    if choice == "Function signature + locals + explain params":
        fn = askString("Function", "Function name or entry (hex):", "process_grid_pattern_copy")
        if not fn: return None
        return "Give me the full signature + locals for {}, and explain the role of each parameter.".format(fn.strip())

    return askString("EmberScale RE Toolbox", "What do you want to analyze or inspect?", "")

# -------------------------
# Tool specs (Anthropic)
# -------------------------
TOOL_SPECS = [
    {
        "name": "ghidra_list_functions",
        "description": "List functions in the current program, optionally filtered by address or name pattern.",
        "input_schema": {
            "type": "object",
            "properties": {
                "start": {"type": "string"},
                "end": {"type": "string"},
                "pattern": {"type": "string"}
            }
        }
    },
    {
        "name": "ghidra_get_decompilation",
        "description": "Return decompiled pseudocode and locals for a function by name or address.",
        "input_schema": {
            "type": "object",
            "properties": {
                "function": {"type": "string"},
                "annotate_addresses": {"type": "boolean", "default": False}
            },
            "required": ["function"]
        }
    },
    {
        "name": "ghidra_xrefs",
        "description": "Get references to/from an address.",
        "input_schema": {
            "type": "object",
            "properties": {
                "addr": {"type": "string"},
                "direction": {"type": "string", "enum": ["to","from"], "default": "to"}
            },
            "required": ["addr"]
        }
    },
    {
        "name": "ghidra_callgraph",
        "description": "Return callers or callees for a function.",
        "input_schema": {
            "type": "object",
            "properties": {
                "function": {"type": "string"},
                "mode": {"type": "string", "enum": ["callers","callees"], "default": "callers"}
            },
            "required": ["function"]
        }
    },
    {
        "name": "ghidra_disassemble",
        "description": "Disassemble around an address (look-behind/ahead).",
        "input_schema": {
            "type": "object",
            "properties": {
                "addr": {"type": "string"},
                "before": {"type": "integer", "default": 8},
                "after": {"type": "integer", "default": 16}
            },
            "required": ["addr"]
        }
    },
    {
        "name": "ghidra_function_signature",
        "description": "Get function prototype, return type, parameters, and calling convention.",
        "input_schema": {
            "type": "object",
            "properties": {
                "function": {"type": "string"}
            },
            "required": ["function"]
        }
    },
    {
        "name": "ghidra_locals_and_params",
        "description": "List locals and parameters (type + storage).",
        "input_schema": {
            "type": "object",
            "properties": {
                "function": {"type": "string"}
            },
            "required": ["function"]
        }
    },
    {
        "name": "ghidra_basic_blocks",
        "description": "List basic blocks for a function (start/end/size).",
        "input_schema": {
            "type": "object",
            "properties": {
                "function": {"type": "string"}
            },
            "required": ["function"]
        }
    },
    {
        "name": "ghidra_search_strings",
        "description": "List defined ASCII strings (optional substring filter).",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string"},
                "max_count": {"type": "integer", "default": 100}
            }
        }
    },
    {
        "name": "ghidra_read_bytes",
        "description": "Read bytes from memory at an address.",
        "input_schema": {
            "type": "object",
            "properties": {
                "addr": {"type": "string"},
                "length": {"type": "integer"},
                "encoding": {"type": "string", "enum": ["hex","base64"], "default": "hex"}
            },
            "required": ["addr","length"]
        }
    }
]

# -------------------------
# Tool implementations (Ghidra)
# -------------------------
def _to_addr(s):
    return toAddr(s.strip())

def _find_function(spec):
    fm = currentProgram.getFunctionManager()
    try:
        if spec and (spec.startswith("0x") or all(c in "0123456789abcdefABCDEF" for c in spec)):
            f = fm.getFunctionAt(_to_addr(spec))
            if f: return f
    except Exception:
        pass
    return fm.getFunction(spec)

def tool_ghidra_list_functions(args):
    start = args.get("start"); end = args.get("end"); pattern = args.get("pattern")
    fm = currentProgram.getFunctionManager()
    res = []
    it = fm.getFunctions(True)
    for f in it:
        ep = f.getEntryPoint()
        if start and ep.compareTo(_to_addr(start)) < 0: continue
        if end and ep.compareTo(_to_addr(end)) > 0: continue
        name = f.getName()
        if pattern and (pattern not in name): continue
        res.append({"name": name, "entry": ep.toString(), "size": f.getBody().getNumAddresses()})
    return {"count": len(res), "functions": res[:500]}

def tool_ghidra_get_decompilation(args):
    from decxy.decompiler import decompile_function
    fn = args.get("function")
    if not fn:
        f = getFunctionContaining(currentAddress)
        if not f:
            return {"error": "no function provided and none at current address"}
    else:
        f = _find_function(fn)
        if not f:
            return {"error": "function not found: {}".format(fn)}
    annotate = bool(args.get("annotate_addresses", False))
    code, vars_ = decompile_function(f, currentProgram, ConsoleTaskMonitor(), annotate_addresses=annotate)
    return {"function": f.getName(), "entry": f.getEntryPoint().toString(), "code": code, "variables": vars_}

def tool_ghidra_xrefs(args):
    rm = currentProgram.getReferenceManager()
    addr = _to_addr(args["addr"]); direction = args.get("direction","to")
    out = []
    if direction == "to":
        for r in rm.getReferencesTo(addr):
            out.append({"from": r.getFromAddress().toString(), "type": str(r.getReferenceType())})
    else:
        for r in rm.getReferencesFrom(addr):
            out.append({"to": r.getToAddress().toString(), "type": str(r.getReferenceType())})
    return {"count": len(out), "refs": out[:500]}

def tool_ghidra_callgraph(args):
    mon = ConsoleTaskMonitor()
    f = _find_function(args["function"])
    if not f: return {"error": "function not found"}
    mode = args.get("mode","callers")
    res = []
    if mode == "callers":
        for caller in f.getCallingFunctions(mon):
            res.append({"name": caller.getName(), "entry": caller.getEntryPoint().toString()})
    else:
        for callee in f.getCalledFunctions(mon):
            res.append({"name": callee.getName(), "entry": callee.getEntryPoint().toString()})
    return {"mode": mode, "items": res[:500]}

def tool_ghidra_disassemble(args):
    listing = currentProgram.getListing()
    addr = _to_addr(args["addr"])
    before = int(args.get("before", 8)); after = int(args.get("after", 16))
    ins = listing.getInstructionAt(addr)
    if ins is None:
        ins = listing.getInstructionAfter(addr) or listing.getInstructionBefore(addr)
        if ins is None:
            return {"error": "no instruction near address"}
    # backward
    back = []
    cur = ins
    for _ in range(before):
        prev_i = cur.getPrevious()
        if prev_i is None: break
        back.append(prev_i); cur = prev_i
    back = [i for i in reversed(back)]
    # forward
    fwd = [ins]
    cur = ins
    for _ in range(after):
        nxt = cur.getNext()
        if nxt is None: break
        fwd.append(nxt); cur = nxt
    def fmt(i):
        try:
            return {"addr": i.getAddress().toString(), "text": i.toString()}
        except Exception:
            return {"addr": str(i.getAddress()), "text": str(i)}
    seq = [fmt(i) for i in back + fwd]
    return {"count": len(seq), "instructions": seq}

def tool_ghidra_function_signature(args):
    f = _find_function(args["function"])
    if not f: return {"error": "function not found"}
    sig = f.getSignature()
    try:
        proto = f.getPrototypeString(True, False)
    except Exception:
        proto = f.getName()
    try:
        ret = str(sig.getReturnType())
    except Exception:
        ret = None
    params = []
    try:
        for p in f.getParameters():
            params.append({
                "name": p.getName(),
                "type": str(p.getDataType()),
                "storage": str(p.getVariableStorage())
            })
    except Exception:
        pass
    cc = None
    try:
        cc = f.getCallingConventionName()
    except Exception:
        pass
    varargs = False
    try:
        varargs = bool(f.hasVarArgs())
    except Exception:
        pass
    return {
        "name": f.getName(),
        "entry": f.getEntryPoint().toString(),
        "prototype": proto,
        "return_type": ret,
        "calling_convention": cc,
        "varargs": varargs,
        "parameters": params
    }

def tool_ghidra_locals_and_params(args):
    f = _find_function(args["function"])
    if not f: return {"error": "function not found"}
    locals_out = []
    try:
        for v in f.getLocalVariables():
            entry = {
                "name": v.getName(),
                "type": str(v.getDataType()),
                "storage": str(v.getVariableStorage())
            }
            try:
                off = v.getStackOffset()
                entry["stack_off"] = int(off)
            except Exception:
                pass
            locals_out.append(entry)
    except Exception:
        pass
    params_out = []
    try:
        for p in f.getParameters():
            params_out.append({
                "name": p.getName(),
                "type": str(p.getDataType()),
                "storage": str(p.getVariableStorage())
            })
    except Exception:
        pass
    return {
        "function": f.getName(),
        "entry": f.getEntryPoint().toString(),
        "locals": locals_out,
        "parameters": params_out
    }

def tool_ghidra_basic_blocks(args):
    from ghidra.program.model.block import BasicBlockModel
    f = _find_function(args["function"])
    if not f: return {"error": "function not found"}
    bbm = BasicBlockModel(currentProgram)
    it = bbm.getCodeBlocksContaining(f.getBody(), ConsoleTaskMonitor())
    out = []
    while it.hasNext():
        b = it.next()
        out.append({
            "start": b.getMinAddress().toString(),
            "end": b.getMaxAddress().toString(),
            "size": int(b.getNumAddresses())
        })
    return {"count": len(out), "blocks": out}

def tool_ghidra_search_strings(args):
    pat = args.get("pattern"); maxc = int(args.get("max_count", 100))
    listing = currentProgram.getListing()
    it = listing.getDefinedData(True)
    out = []; c = 0
    while it.hasNext() and c < maxc:
        d = it.next()
        try:
            dt = d.getDataType()
            if dt and dt.getName().lower().startswith("string"):
                s = str(d.getValue()).encode("ascii","ignore")
                if 3 < len(s) < 200 and (not pat or (pat in s)):
                    out.append({"addr": d.getAddress().toString(), "s": s}); c += 1
        except Exception:
            pass
    return {"count": len(out), "strings": out}

def tool_ghidra_read_bytes(args):
    import base64
    addr = _to_addr(args["addr"]); ln = int(args.get("length")); enc = args.get("encoding","hex")
    mem = currentProgram.getMemory()
    ba = bytearray(ln)
    mem.getBytes(addr, ba)
    if enc == "base64":
        try:
            return {"length": ln, "base64": base64.b64encode(bytes(ba))}
        except Exception:
            # Jython fallback
            return {"length": ln, "base64": base64.b64encode(str(bytearray(ba)))}
    # hex
    hex_parts = []
    for b in ba:
        try:
            val = b if isinstance(b, int) else ord(b)
        except Exception:
            val = ord(b)
        hex_parts.append("{:02x}".format(val & 0xff))
    return {"length": ln, "hex": " ".join(hex_parts)}

TOOL_IMPLS = {
    "ghidra_list_functions": tool_ghidra_list_functions,
    "ghidra_get_decompilation": tool_ghidra_get_decompilation,
    "ghidra_xrefs": tool_ghidra_xrefs,
    "ghidra_callgraph": tool_ghidra_callgraph,
    "ghidra_disassemble": tool_ghidra_disassemble,
    "ghidra_function_signature": tool_ghidra_function_signature,
    "ghidra_locals_and_params": tool_ghidra_locals_and_params,
    "ghidra_basic_blocks": tool_ghidra_basic_blocks,
    "ghidra_search_strings": tool_ghidra_search_strings,
    "ghidra_read_bytes": tool_ghidra_read_bytes,
}

# -------------------------
# Java HTTPS transport
# -------------------------
def anthropic_messages_java(api_key, model, messages, tools=None, max_tokens=1600):
    from java.net import URL
    from java.io import DataOutputStream, BufferedReader, InputStreamReader
    from javax.net.ssl import HttpsURLConnection, SSLContext, X509TrustManager
    from java.security import SecureRandom

    class TrustAllManager(X509TrustManager):
        def checkClientTrusted(self, chain, authType): pass
        def checkServerTrusted(self, chain, authType): pass
        def getAcceptedIssuers(self): return None

    ssl_ctx = SSLContext.getInstance("SSL")
    ssl_ctx.init(None, [TrustAllManager()], SecureRandom())
    HttpsURLConnection.setDefaultSSLSocketFactory(ssl_ctx.getSocketFactory())

    payload = {"model": model, "max_tokens": max_tokens, "messages": messages}
    if tools:
        payload["tools"] = tools

    body = json.dumps(payload)
    u = URL(ANTHROPIC_URL)
    con = u.openConnection()
    con.setRequestMethod("POST")
    con.setDoOutput(True)
    con.setConnectTimeout(30000)
    con.setReadTimeout(30000)
    con.setRequestProperty("Content-Type", "application/json")
    con.setRequestProperty("anthropic-version", ANTHROPIC_VERSION)
    con.setRequestProperty("x-api-key", api_key)

    out = DataOutputStream(con.getOutputStream())
    out.writeBytes(body); out.flush(); out.close()

    code = con.getResponseCode()
    if code != 200:
        try:
            br = BufferedReader(InputStreamReader(con.getErrorStream()))
            err = []; line = br.readLine()
            while line is not None:
                err.append(line); line = br.readLine()
            br.close()
            print("HTTP {}: {}".format(code, "".join(err)[:200]))
        except Exception:
            print("HTTP {} error".format(code))
        return None

    br = BufferedReader(InputStreamReader(con.getInputStream()))
    buf = []; line = br.readLine()
    while line is not None:
        buf.append(line); line = br.readLine()
    br.close()

    try:
        return json.loads("".join(buf))
    except Exception as e:
        print("Failed to parse JSON: {}".format(e))
        return None

# -------------------------
# Tool loop
# -------------------------
def run_tool_session(api_key, model, intro_text):
    messages = [{"role": "user", "content": [{"type": "text", "text": intro_text}]}]

    for _ in range(8):  # safety cap
        resp = anthropic_messages_java(api_key, model, messages, tools=TOOL_SPECS, max_tokens=1700)
        if not resp:
            print("No response from Anthropic.")
            return
        blocks = resp.get("content", [])
        if not isinstance(blocks, list):
            print("Malformed response content.")
            return

        text_out = []; tool_calls = []
        for b in blocks:
            t = b.get("type")
            if t == "text":
                text_out.append(b.get("text",""))
            elif t == "tool_use":
                tool_calls.append(b)

        if text_out:
            print("\n--- Assistant ---\n")
            try:
                print(u"{}".format("\n".join(text_out)))
            except Exception:
                print("\n".join(text_out))

        if not tool_calls:
            return  # finished

        # Record assistant turn (including its tool_use requests)
        messages.append({"role": "assistant", "content": blocks})

        # Execute tools and send results back
        results = []
        for call in tool_calls:
            name = call.get("name"); tuid = call.get("id"); args = call.get("input") or {}
            try:
                impl = TOOL_IMPLS.get(name)
                if not impl:
                    results.append({
                        "type": "tool_result", "tool_use_id": tuid, "is_error": True,
                        "content": json.dumps({"error": "unsupported tool: {}".format(name)})
                    })
                    continue
                out = impl(args)
                results.append({
                    "type": "tool_result", "tool_use_id": tuid,
                    "content": json.dumps(out)
                })
            except Exception as e:
                results.append({
                    "type": "tool_result", "tool_use_id": tuid, "is_error": True,
                    "content": json.dumps({"error": str(e)})
                })

        messages.append({"role": "user", "content": results})

    print("Stopped after max tool iterations.")

# -------------------------
# Main
# -------------------------
def main():
    api_key = get_api_key_from_preferences()
    if not api_key:
        return
    model = choose_model()
    if not model:
        print("No model selected.")
        return

    examples_text = print_usage_banner()

    # OLD: q = askString("EmberScale RE Toolbox", "What do you want to analyze or inspect?")
    # NEW: use helper menu to build a clean question
    q = get_user_question()
    if not q:
        print("No prompt given.")
        return

    print("Collecting context...")
    funcs = collect_function_map()
    strs = collect_strings()
    intro = build_intro(q, funcs, strs, examples_text)

    print("Starting tool-enabled session...")
    run_tool_session(api_key, model, intro)

if __name__ == "__main__":
    main()
