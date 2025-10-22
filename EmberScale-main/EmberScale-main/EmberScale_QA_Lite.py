# -*- coding: utf-8 -*-
# @category Claude Query
# @toolbar

import os
from ghidra.framework.preferences import Preferences
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.listing import CodeUnit
from decxy.api import get_response_from_claude

# Optional model list if present
try:
    from decxy.config import CLAUDE_MODELS
except Exception:
    CLAUDE_MODELS = None

# -------------------------
# Helpers (no hardcoded secrets)
# -------------------------
def get_api_key_from_preferences():
    """
    Resolve Anthropic API key in this order:
      1) Ghidra Preferences: ANTHROPIC_API_KEY
      2) Env: ANTHROPIC_API_KEY or CLAUDE_API_KEY (and store into Preferences)
      3) Prompt the user once and store into Preferences
    """
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
    """
    Resolve model name:
      1) If CLAUDE_MODELS provided: use single choice or ask user to pick
      2) Env: ANTHROPIC_MODEL
      3) Sensible default
    """
    # Try decyx.config first
    if isinstance(CLAUDE_MODELS, (list, tuple)) and len(CLAUDE_MODELS) > 0:
        if len(CLAUDE_MODELS) == 1:
            return CLAUDE_MODELS[0]
        # If multiple, try to let the user pick; fall back to first on headless
        try:
            return askChoice("Claude Model", "Select a model", CLAUDE_MODELS, CLAUDE_MODELS[0])
        except Exception:
            return CLAUDE_MODELS[0]

    # Env var
    model = os.environ.get("ANTHROPIC_MODEL")
    if model and model.strip():
        return model.strip()

    # Default (not a secret; just a name)
    return "claude-sonnet-4-20250514"

# -------------------------
# Context collectors
# -------------------------
def collect_function_names(max_count=200):
    func_mgr = currentProgram.getFunctionManager()
    names = []
    it = func_mgr.getFunctions(True)
    for func in it:
        if len(names) >= max_count:
            break
        name = func.getName()
        names.append(name)
    return names

def collect_strings(max_count=50):
    strings = []
    listing = currentProgram.getListing()
    data_iter = listing.getDefinedData(True)
    count = 0

    while data_iter.hasNext() and count < max_count:
        data = data_iter.next()
        try:
            dt = data.getDataType()
            if dt and dt.getName() and dt.getName().lower().startswith("string"):
                val = str(data.getValue())
                val = val.encode("ascii", "ignore")
                if 3 < len(val) < 100:
                    strings.append(val)
                    count += 1
        except Exception:
            continue
    return strings

def build_prompt(question, func_names, string_literals):
    parts = []
    parts.append("You are analyzing a binary firmware file using Ghidra.")
    parts.append("The user has a question about the firmware's logic, structure, or behavior.\n")
    parts.append("### User's Question:\n{}\n".format(question))
    if func_names:
        parts.append("### Function Names (sample):\n{}\n".format(", ".join(func_names[:30])))
    if string_literals:
        parts.append("### Embedded Strings (sample):\n{}\n".format(
            "\n".join("- {}".format(s) for s in string_literals[:20])
        ))
    parts.append("Please provide your best technical insight based on the above. "
                 "If you are unsure, explain what additional information from Ghidra would help.")
    return "\n".join(parts)

# -------------------------
# Main
# -------------------------
def main():
    monitor = ConsoleTaskMonitor()

    api_key = get_api_key_from_preferences()
    if not api_key:
        return

    model = choose_model()
    if not model:
        print("No model selected.")
        return

    question = askString("Ask Claude", "What do you want to ask about this binary?")
    if not question:
        print("No question provided.")
        return

    print("Collecting context...")
    func_names = collect_function_names()
    strings = collect_strings()

    prompt = build_prompt(question, func_names, strings)

    print("Sending question to Claude...")
    # decyx.api handles JSON/transport and uses monitor for status
    response = get_response_from_claude(prompt, api_key, model, monitor, is_explanation=True)

    if response:
        print("\n=== Claude's Response ===\n")
        try:
            # Ensure we always print a unicode-safe string in Jython
            print(u"{}".format(response))
        except Exception:
            print(str(response))
    else:
        print("No response received.")

if __name__ == "__main__":
    main()
