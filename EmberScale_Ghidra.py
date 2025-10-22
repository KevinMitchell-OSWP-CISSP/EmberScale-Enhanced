# Python extension that leverages Anthropic's Claude to assist in reverse engineering and binary analysis.
# @author Kevin Mitchell
# @category AI Analysis
# @menupath
# @toolbar
# -*- coding: utf-8 -*-
# @toolbar
#
# Batch/agent script for Ghidra (Jython) that:
#  - Decompiles functions in a selection or address range
#  - Builds prompts for rename/retype, line comments, and explanations
#  - Calls Anthropic Claude via decyx.api with Jython-safe normalization
#  - Applies results back into Ghidra
#
# Notes:
#  - Provide ANTHROPIC_API_KEY in your environment or enter it once when prompted.
#    export ANTHROPIC_API_KEY=sk-ant-REDACTED

import os
import json
from ghidra.util.task import ConsoleTaskMonitor

import decyx.api as decyx_api  # module import so we can patch it
from decyx.decompiler import decompile_function
from decyx.utils import (
    prepare_prompt, apply_selected_suggestions,
    apply_line_comments, apply_explanation
)

# -------------------------
# Configuration
# -------------------------
MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")
ACTIONS = ["rename_retype", "line_comments", "explanation"]

# -------------------------
# Logging (ASCII only)
# -------------------------
def log_info(msg):
    print("[INFO] " + msg)

def log_warn(msg):
    print("[WARN] " + msg)

def log_err(msg):
    print("[ERROR] " + msg)

# -------------------------
# Jython compatibility shims
# -------------------------
try:
    basestring  # type: ignore
except NameError:
    basestring = (str,)
try:
    unicode  # type: ignore
except NameError:
    unicode = str  # py3 fallback

# -------------------------
# Unicode / API key safety
# -------------------------
def _normalize_prompt(p):
    if p is None:
        return ""
    if isinstance(p, dict):
        try:
            return json.dumps(p, ensure_ascii=False)
        except Exception:
            return str(p)
    try:
        return u"" + unicode(p)  # Jython unicode coercion
    except Exception:
        return str(p)

def _to_text(x, default=""):
    if x is None:
        return default
    try:
        return x if isinstance(x, basestring) else str(x)
    except Exception:
        return str(x)

def _ensure_api_key(key_candidate=None):
    key = (
        _to_text(key_candidate, "") or
        _to_text(os.environ.get("ANTHROPIC_API_KEY"), "") or
        _to_text(os.environ.get("CLAUDE_API_KEY"), "")
    )
    if key:
        return key.strip()
    try:
        entered = askString("Anthropic API Key", "Enter your Anthropic API key (not saved):", "")
        if entered and entered.strip():
            return entered.strip()
    except Exception:
        pass
    log_err("Anthropic API key missing. Set ANTHROPIC_API_KEY or enter it when prompted.")
    raise SystemExit(1)

# -------------------------
# Patch decyx.api with a safe wrapper (monitor-safe)
# -------------------------
_ORIG_GET = decyx_api.get_response_from_claude

def get_response_from_claude_safe(prompt, api_key=None, model=None, monitor=None, is_explanation=False):
    norm_prompt = _normalize_prompt(prompt)
    norm_model  = _to_text(model or os.environ.get("ANTHROPIC_MODEL") or "claude-sonnet-4-20250514",
                           "claude-sonnet-4-20250514")
    norm_key    = _ensure_api_key(api_key)

    # Ensure a real monitor object so decyx.api can call setMessage(...)
    try:
        safe_monitor = monitor if monitor is not None else ConsoleTaskMonitor()
    except Exception:
        class _MiniMonitor(object):
            def setMessage(self, msg): pass
            def isCancelled(self): return False
        safe_monitor = _MiniMonitor()

    try:
        return _ORIG_GET(
            norm_prompt,
            norm_key,
            norm_model,
            safe_monitor,
            is_explanation=is_explanation,
        )
    except AttributeError as e:
        # If a particular build still chokes on monitor, retry with a tiny shim
        if "setMessage" in str(e):
            class _MiniMonitor(object):
                def setMessage(self, msg): pass
                def isCancelled(self): return False
            try:
                return _ORIG_GET(
                    norm_prompt,
                    norm_key,
                    norm_model,
                    _MiniMonitor(),
                    is_explanation=is_explanation,
                )
            except Exception as e2:
                log_err("API call failed after shim: %s" % e2)
                log_info("model=%s, prompt_len=%d" % (norm_model, len(norm_prompt)))
                return None
        log_err("API call failed: %s" % e)
        log_info("model=%s, prompt_len=%d" % (norm_model, len(norm_prompt)))
        return None
    except Exception as e:
        log_err("API call failed: %s" % e)
        log_info("model=%s, prompt_len=%d" % (norm_model, len(norm_prompt)))
        return None

# Patch module symbol so any code using decyx.api gets the safe version
decyx_api.get_response_from_claude = get_response_from_claude_safe
# Local alias if this file references the name directly
get_response_from_claude = get_response_from_claude_safe

# -------------------------
# Address range selection
# -------------------------
def get_address_range():
    sel = currentSelection
    if sel and not sel.isEmpty():
        try:
            use_sel = askYesNo(
                "Address Range",
                "Use current selection (%s to %s)?" % (sel.getMinAddress(), sel.getMaxAddress())
            )
        except Exception:
            use_sel = True  # headless default
        if use_sel:
            return sel.getMinAddress(), sel.getMaxAddress()

    # Manual input
    try:
        start_str = askString("Start Address", "Enter start address (hex, e.g., 00090140):", "")
        end_str   = askString("End Address",   "Enter end address (hex, e.g., 0009FFE0):", "")
    except Exception:
        start_str = end_str = ""

    start_addr = None
    end_addr = None
    try:
        if start_str and start_str.strip():
            start_addr = toAddr(start_str.strip())
        if end_str and end_str.strip():
            end_addr = toAddr(end_str.strip())
    except Exception as e:
        log_warn("Invalid address format: %s" % e)
        log_info("Proceeding with all functions.")
        return None, None

    if start_addr and end_addr and start_addr.compareTo(end_addr) >= 0:
        log_warn("Start address must be less than end address.")
        return None, None

    return start_addr, end_addr

# -------------------------
# Core agent
# -------------------------
def run_agent_mode():
    monitor = ConsoleTaskMonitor()

    start_addr, end_addr = get_address_range()
    if start_addr and end_addr:
        log_info("Processing functions from %s to %s" % (start_addr, end_addr))
    else:
        log_info("Processing all functions in the program")

    fm = currentProgram.getFunctionManager()
    all_funcs = []

    it = fm.getFunctions(True)
    for func in it:
        # Range filter
        if start_addr and end_addr:
            ep = func.getEntryPoint()
            if ep.compareTo(start_addr) < 0 or ep.compareTo(end_addr) > 0:
                continue

        try:
            code, variables = decompile_function(func, currentProgram, monitor)
        except Exception as e:
            log_warn("Decompile failed for %s: %s" % (func.getName(), e))
            continue

        if code:
            all_funcs.append((func, code, variables))

    log_info("%d functions in range to process." % len(all_funcs))

    for func, code, variables in all_funcs:
        log_info("Function: %s" % func.getName())

        for action in ACTIONS:
            log_info(" -> [%s] Running..." % action)
            try:
                prompt = prepare_prompt(code, variables, action=action)
            except Exception as e:
                log_warn("Prompt generation failed for %s: %s" % (action, e))
                continue

            if not prompt:
                log_warn("Skipped: empty prompt.")
                continue

            resp = get_response_from_claude(
                prompt=prompt,
                api_key=None,               # env/prompt inside _ensure_api_key
                model=MODEL,
                monitor=monitor,
                is_explanation=(action == "explanation"),
            )
            if not resp:
                log_err("No response from Claude.")
                continue

            try:
                if action == "rename_retype":
                    # If your utils expect (structured, full_text), adapt accordingly
                    apply_selected_suggestions(func, resp, resp, state.getTool())
                elif action == "line_comments":
                    apply_line_comments(func, resp)
                elif action == "explanation":
                    apply_explanation(func, resp)
                log_info("Applied %s successfully." % action)
            except Exception as e:
                log_warn("Failed to apply %s: %s" % (action, e))

    log_info("Agent Mode: All actions completed.")

# -------------------------
# Main
# -------------------------
def main():
    run_agent_mode()

if __name__ == "__main__":
    main()

