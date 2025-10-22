# -*- coding: utf-8 -*-
# Claude_SingleTool_Decompile.py
# @category AI Analysis
# @toolbar
#
# Single-tool Anthropic loop for Ghidra:
#   Tool: ghidra_get_decompilation(function, annotate_addresses?)
# Transport: Java HTTPS (trust-all) for Jython compatibility.
# Secrets: pulled from Preferences/env; never hardcoded.

import os, json
from ghidra.framework.preferences import Preferences
from ghidra.util.task import ConsoleTaskMonitor

# -------------------------
# Usage Tracking
# -------------------------
def track_usage_for_operation(operation_name, tokens_used=None):
    """Stub function for usage tracking - functionality not implemented yet."""
    print("Usage tracking: {} (tokens: {})".format(operation_name, tokens_used or 0))

ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"

# ----------------- key/model -----------------
def get_api_key():
    prefs = Preferences
    k = prefs.getProperty("ANTHROPIC_API_KEY")
    if k: return k
    k = os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("CLAUDE_API_KEY")
    if k:
        prefs.setProperty("ANTHROPIC_API_KEY", k); prefs.store()
        print("Stored Anthropic API key in Preferences: {}".format(prefs.getFilename()))
        return k
    try:
        entered = askString("Anthropic API Key", "Enter key (saved in Preferences):", "")
        if entered and entered.strip():
            k = entered.strip()
            prefs.setProperty("ANTHROPIC_API_KEY", k); prefs.store()
            print("Stored Anthropic API key in Preferences: {}".format(prefs.getFilename()))
            return k
    except Exception:
        pass
    print("ERROR: Anthropic API key required."); return None

def choose_model():
    try:
        from decyx.config import CLAUDE_MODELS
        if isinstance(CLAUDE_MODELS, (list, tuple)) and len(CLAUDE_MODELS) > 0:
            if len(CLAUDE_MODELS) == 1: return CLAUDE_MODELS[0]
            try:
                return askChoice("Claude Model", "Select model", CLAUDE_MODELS, CLAUDE_MODELS[0])
            except Exception:
                return CLAUDE_MODELS[0]
    except Exception:
        pass
    m = os.environ.get("ANTHROPIC_MODEL")
    return m.strip() if m else "claude-sonnet-4-20250514"

# ----------------- tiny context -----------------
def collect_function_map(max_count=200):
    fm = currentProgram.getFunctionManager()
    out = []; it = fm.getFunctions(True)
    for f in it:
        if len(out) >= max_count: break
        out.append({"name": f.getName(), "entry": f.getEntryPoint().toString()})
    return out

def build_intro(question, func_map):
    lines = []
    lines.append("You are assisting inside Ghidra. ONE tool is available: ghidra_get_decompilation.")
    lines.append("Use it whenever you need a function's pseudocode+locals, then reason succinctly.")
    lines.append("")
    lines.append("### User question")
    lines.append(question)
    if func_map:
        lines.append("")
        lines.append("### Functions (sample name->entry)")
        for x in func_map[:50]:
            lines.append("- {} : {}".format(x["name"], x["entry"]))
    lines.append("")
    lines.append("Prefer targeting by function name; address is also accepted.")
    return "\n".join(lines)

# ----------------- single tool spec -----------------
TOOL_SPECS = [
    {
        "name": "ghidra_get_decompilation",
        "description": "Return decompiled pseudocode and locals for a function by name or address.",
        "input_schema": {
            "type": "object",
            "properties": {
                "function": {"type": "string", "description": "Function name or hex address"},
                "annotate_addresses": {"type": "boolean", "default": False}
            },
            "required": ["function"]
        }
    }
]

# ----------------- tool impl -----------------
def _to_addr(s):
    return toAddr(s.strip())

def _find_function(spec):
    fm = currentProgram.getFunctionManager()
    try:
        if spec.startswith("0x") or all(c in "0123456789abcdefABCDEF" for c in spec):
            f = fm.getFunctionAt(_to_addr(spec))
            if f: return f
    except Exception:
        pass
    return fm.getFunction(spec)

def tool_ghidra_get_decompilation(args):
    from decyx.decompiler import decompile_function
    fn = args.get("function")
    if not fn:
        # default: current function if caller forgot
        f = getFunctionContaining(currentAddress)
        if not f: return {"error": "no function provided and none at current address"}
    else:
        f = _find_function(fn)
        if not f: return {"error": "function not found: {}".format(fn)}
    annotate = bool(args.get("annotate_addresses", False))
    code, vars_ = decompile_function(f, currentProgram, ConsoleTaskMonitor(), annotate_addresses=annotate)
    return {"function": f.getName(), "entry": f.getEntryPoint().toString(), "code": code, "variables": vars_}

TOOL_IMPLS = {"ghidra_get_decompilation": tool_ghidra_get_decompilation}

# ----------------- Java HTTPS transport -----------------
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
    if tools: payload["tools"] = tools

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
            while line is not None: err.append(line); line = br.readLine()
            br.close()
            print("HTTP {}: {}".format(code, "".join(err)[:200]))
        except Exception:
            print("HTTP {} error".format(code))
        return None

    br = BufferedReader(InputStreamReader(con.getInputStream()))
    buf = []; line = br.readLine()
    while line is not None: buf.append(line); line = br.readLine()
    br.close()

    try:
        return json.loads("".join(buf))
    except Exception as e:
        print("Failed to parse JSON: {}".format(e)); return None

# ----------------- single-tool loop -----------------
def run_single_tool_session(api_key, model, intro_text):
    messages = [{"role": "user", "content": [{"type": "text", "text": intro_text}]}]

    for _ in range(5):  # small cap
        resp = anthropic_messages_java(api_key, model, messages, tools=TOOL_SPECS, max_tokens=1600)
        if not resp:
            print("No response from Anthropic."); return

        blocks = resp.get("content", [])
        if not isinstance(blocks, list):
            print("Malformed response."); return

        text_out = []; tool_calls = []
        for b in blocks:
            t = b.get("type")
            if t == "text":
                text_out.append(b.get("text",""))
            elif t == "tool_use":
                tool_calls.append(b)

        if text_out:
            print("\n--- Assistant ---\n")
            try: print(u"{}".format("\n".join(text_out)))
            except Exception: print("\n".join(text_out))

        if not tool_calls:
            return  # finished

        messages.append({"role": "assistant", "content": blocks})

        # Execute only our single tool
        results = []
        for call in tool_calls:
            name = call.get("name"); tuid = call.get("id"); args = call.get("input") or {}
            if name != "ghidra_get_decompilation":
                results.append({"type": "tool_result", "tool_use_id": tuid,
                                "is_error": True, "content": json.dumps({"error":"unsupported tool"})})
                continue
            try:
                out = TOOL_IMPLS[name](args)
                results.append({"type": "tool_result", "tool_use_id": tuid, "content": json.dumps(out)})
            except Exception as e:
                results.append({"type": "tool_result", "tool_use_id": tuid,
                                "is_error": True, "content": json.dumps({"error": str(e)})})

        messages.append({"role": "user", "content": results})

    print("Stopped after max iterations.")

# ----------------- main -----------------
def main():
    # Track usage
    track_usage_for_operation("Single_Decompile_Analysis")
    
    api_key = get_api_key()
    if not api_key: return
    model = choose_model()
    if not model:
        print("No model selected."); return

    q = askString("EmberScale (Single Decompile)", "What do you want Claude to analyze?")
    if not q:
        print("No prompt given."); return

    funcs = collect_function_map()
    intro = build_intro(q, funcs)

    print("Starting decompile-on-demand session...")
    run_single_tool_session(api_key, model, intro)

if __name__ == "__main__":
    main()
