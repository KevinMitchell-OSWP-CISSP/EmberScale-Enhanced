# utils.py

import re
import json

# --- Safe import for PROMPTS (won't crash if config missing) ---
try:
    from config import PROMPTS
except Exception:
    PROMPTS = {}

# Ghidra imports
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import VariableSizeException
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.util import CodeUnitInsertionException
from ghidra.app.services import DataTypeManagerService

# -------------------------------------------------------------------
# Logging helpers (simple + consistent)
# -------------------------------------------------------------------
def _info(msg): print "[INFO] " + msg
def _warn(msg): print "[WARN] " + msg
def _err(msg):  print "[ERROR] " + msg


# -------------------------------------------------------------------
# Utilities: memory safety helpers
# -------------------------------------------------------------------
def _bytes_available_in_block(program, addr):
    """
    Return how many bytes remain in the current initialized block starting
    at 'addr' (inclusive). If not inside an initialized block, return 0.
    """
    try:
        mem = program.getMemory()
        block = mem.getBlock(addr)
        if block is None or not block.isInitialized():
            return 0
        # inclusive
        return block.getEnd().subtract(addr) + 1
    except Exception as e:
        _warn("bytes_available_in_block failed at {}: {}".format(addr, e))
        return 0


def _clear_range_safe(listing, addr, size):
    """
    Clear conflicting code/data at [addr, addr+size-1] using Listing.clearCodeUnits.
    Does not cross block boundaries; caller must ensure 'size' is safe.
    """
    if size <= 0:
        return True
    try:
        start = addr
        end = addr.add(size - 1)
        # False => keep comments/bookmarks; only clear code/data
        listing.clearCodeUnits(start, end, False)
        return True
    except Exception as e:
        _warn("clearCodeUnits exception at {}: {}".format(addr, e))
        return False


# -------------------------------------------------------------------
# Data type lookup & formatting
# -------------------------------------------------------------------
def format_new_type(type_str):
    """
    Fix formatting of pointer types by ensuring spaces before '*' characters.
    """
    fixed_type = re.sub(r'(?<!\s)\*', ' *', type_str)
    fixed_type = re.sub(r'\*\*+', lambda m: ' ' + ' *' * len(m.group()), fixed_type)
    fixed_type = re.sub(r'\s+', ' ', fixed_type).strip()
    return fixed_type


def find_data_type_by_name(name, tool):
    """
    Finds a data type by its name from all available DataTypeManagers.
    Tries a few variations and a full scan. Never raises.
    """
    if not name or tool is None:
        _warn("find_data_type_by_name: invalid inputs (name='{}', tool={})".format(name, tool))
        return None

    try:
        service = tool.getService(DataTypeManagerService)
        if service is None:
            _warn("DataTypeManagerService unavailable; cannot resolve '{}'".format(name))
            return None

        dtm_list = service.getDataTypeManagers()
        if dtm_list is None:
            _warn("No DataTypeManagers; cannot resolve '{}'".format(name))
            return None

        candidates = [name, "/" + name, format_new_type(name)]
        # Try exact matches first (with and without leading slash)
        for manager in dtm_list:
            for cand in candidates:
                dt = manager.getDataType(cand)
                if dt is not None:
                    return dt

        # Slow path: search through all data types (case-insensitive)
        lname = name.lower()
        for manager in dtm_list:
            try:
                all_types = manager.getAllDataTypes()
                for dt in all_types:
                    if dt.getName().lower() == lname:
                        return dt
            except Exception as e:
                _warn("Scanning types failed in a manager: {}".format(e))

        _warn("Data type '{}' not found".format(name))
        return None

    except Exception as e:
        _warn("find_data_type_by_name exception for '{}': {}".format(name, e))
        return None


# -------------------------------------------------------------------
# Retyping & renaming locals
# -------------------------------------------------------------------
def retype_variable(variable, new_type_name, tool):
    """
    Changes the data type of a local/parameter variable to a new specified type.
    Safe: returns False on any failure.
    """
    if variable is None:
        _warn("retype_variable: variable is None")
        return False

    new_type_name = format_new_type(new_type_name) if new_type_name else new_type_name
    new_data_type = find_data_type_by_name(new_type_name, tool)

    if new_data_type is None:
        _warn("retype_variable: type '{}' not found".format(new_type_name))
        return False

    try:
        variable.setDataType(new_data_type, SourceType.USER_DEFINED)
        _info("Successfully retyped variable '{}' to '{}'".format(variable.getName(), new_type_name))
        return True
    except VariableSizeException as e:
        _warn("Variable size conflict when retyping '{}' to '{}': {}".format(
            variable.getName(), new_type_name, e))
        return False
    except Exception as e:
        _warn("Error retyping variable '{}' to '{}': {}".format(
            variable.getName(), new_type_name, e))
        return False


# -------------------------------------------------------------------
# Globals: rename & retype (robust)
# -------------------------------------------------------------------
def retype_global_variable(listing, symbol, new_data_type):
    """
    Retype a global variable safely:
      - Checks block & available bytes before clearing/creating
      - Clears only the needed range (keeps comments/bookmarks)
      - Attempts createData; if that fails, tries to modify existing data at addr
      - Logs failures; never raises
    """
    if symbol is None or listing is None or new_data_type is None:
        _warn("retype_global_variable: bad inputs (symbol={}, listing={}, type={})".format(
            symbol, listing, new_data_type))
        return

    program = listing.getProgram()
    addr = symbol.getAddress()
    need = new_data_type.getLength()

    # Safety: ensure we are inside an initialized block and have enough room
    available = _bytes_available_in_block(program, addr)
    if available <= 0:
        _warn("Retype skipped at {}: not in an initialized memory block.".format(addr))
        return
    if available < need:
        _warn("Retype skipped at {}: only {} byte(s) available; need {}.".format(addr, available, need))
        return

    try:
        # Clear any conflicting code/data first
        if not _clear_range_safe(listing, addr, need):
            _warn("Unable to clear {} byte(s) at {}; keeping existing layout.".format(need, addr))

        # Try to create new data of the requested type
        try:
            data = listing.createData(addr, new_data_type)
            if data:
                _info("Retyped global '{}' to '{}'".format(symbol.getName(), new_data_type.getName()))
                return
        except CodeUnitInsertionException as e:
            _warn("createData insertion exception at {}: {}".format(addr, e))
        except Exception as e:
            _warn("createData failed at {}: {}".format(addr, e))

        # Fallback: modify existing data unit at the address
        try:
            existing_data = listing.getDataAt(addr)
            if existing_data:
                existing_data.setDataType(new_data_type, SourceType.USER_DEFINED)
                _info("Modified existing data type for global '{}' to '{}'".format(
                    symbol.getName(), new_data_type.getName()))
                return
        except Exception as e:
            _warn("Modifying existing data failed at {}: {}".format(addr, e))

        _warn("Failed to create or modify data for global '{}' with type '{}'".format(
            symbol.getName(), new_data_type.getName()))

    except Exception as e:
        _warn("Error retyping global '{}' to '{}': {}".format(
            symbol.getName(), new_data_type.getName(), e))


def rename_function(func, new_name):
    """Rename the given function safely."""
    if not func or not new_name:
        return
    try:
        func.setName(new_name, SourceType.USER_DEFINED)
        _info("Renamed function to '{}'".format(new_name))
    except Exception as e:
        _warn("Rename function '{}' failed: {}".format(new_name, e))


def rename_symbol(symbol, new_name):
    """Rename the given symbol (local/global) safely."""
    if not symbol or not new_name:
        return
    try:
        old_name = symbol.getName()
    except Exception:
        old_name = "<unknown>"

    try:
        symbol.setName(new_name, SourceType.USER_DEFINED)
        _info("Renamed '{}' to '{}'".format(old_name, new_name))
    except Exception as e:
        _warn("Rename '{}' -> '{}' failed: {}".format(old_name, new_name, e))


def _first_symbol_by_name(symbol_table, name):
    """
    Return the first symbol whose name matches 'name' (exact), or None.
    Using a simple iterator for Jython compatibility.
    """
    try:
        for s in symbol_table.getSymbols(name):
            return s
    except Exception:
        pass
    return None


def process_global_variable(symbol_table, listing, old_name, new_name, new_type_name, tool):
    """Process a global variable for renaming and retyping (never raises)."""
    if not symbol_table or not listing or not old_name:
        _warn("process_global_variable: bad inputs")
        return

    # Normalize common naming quirks
    name_try = old_name[1:] if old_name.startswith('_') else old_name

    # Try exact first
    symbol = _first_symbol_by_name(symbol_table, name_try)

    # If not found, try original (in case underscore mattered)
    if symbol is None and name_try != old_name:
        symbol = _first_symbol_by_name(symbol_table, old_name)

    if symbol is None:
        _warn("Global variable '{}' not found".format(old_name))
        return

    # Rename first; even if retype fails, the rename is still useful
    if new_name:
        rename_symbol(symbol, new_name)

    # Retype if requested
    if new_type_name:
        dt = find_data_type_by_name(new_type_name, tool)
        if dt is not None:
            retype_global_variable(listing, symbol, dt)
        else:
            _warn("Data type '{}' not found for global '{}'".format(new_type_name, symbol.getName()))


def process_local_variable(var_obj, new_name, new_type_name, tool):
    """Process a local variable (rename + retype), safely."""
    if var_obj is None:
        return
    if new_name:
        rename_symbol(var_obj, new_name)
    if new_type_name:
        ok = retype_variable(var_obj, new_type_name, tool)
        if not ok:
            _warn("Failed to retype variable '{}' to '{}'; continuing.".format(
                var_obj.getName(), new_type_name))


# -------------------------------------------------------------------
# Batch application from suggestions
# -------------------------------------------------------------------
def apply_selected_suggestions(func, suggestions, selected, tool):
    """
    Applies the selected suggestions for renaming and retyping of variables and functions.

    Args:
        func (Function): Function being modified.
        suggestions (dict): Original suggestions { "variables": [ { "old_name": ... }, ... ] }
        selected (dict): User-selected actions { "function_name": str, "variables": [ {...}, ... ] }
        tool (Tool): Tool context for data type ops.

    Returns:
        None
    """
    if func is None:
        _warn("apply_selected_suggestions: func is None")
        return

    program = func.getProgram()
    listing = program.getListing()
    symbol_table = program.getSymbolTable()

    # Function rename (safe)
    try:
        new_func_name = selected.get('function_name') if selected else None
    except Exception:
        new_func_name = None
    if new_func_name:
        rename_function(func, new_func_name)

    # Collect all locals/params once
    try:
        all_vars = list(func.getParameters()) + list(func.getLocalVariables())
    except Exception:
        all_vars = []

    # Variable actions
    try:
        selected_vars = selected.get('variables', []) if selected else []
        sugg_vars = suggestions.get('variables', []) if suggestions else []
    except Exception:
        selected_vars, sugg_vars = [], []

    for i, var_sel in enumerate(selected_vars):
        if not var_sel:
            continue

        old_name = None
        try:
            old_name = sugg_vars[i].get('old_name') if i < len(sugg_vars) else None
        except Exception:
            pass

        new_name = var_sel.get('new_name') if hasattr(var_sel, 'get') else None
        new_type = var_sel.get('new_type') if hasattr(var_sel, 'get') else None

        if not old_name:
            _warn("Selected change has no old_name; skipping entry {}".format(i))
            continue

        # Heuristic: global if looks like decompiler auto 'DAT_xxx'
        if "DAT" in old_name:
            process_global_variable(symbol_table, listing, old_name, new_name, new_type, tool)
            continue

        # Local/param path
        var_obj = None
        try:
            for v in all_vars:
                if v.getName() == old_name:
                    var_obj = v
                    break
        except Exception:
            var_obj = None

        if var_obj:
            process_local_variable(var_obj, new_name, new_type, tool)
        else:
            _warn("Variable '{}' not found in function; skipping.".format(old_name))


# -------------------------------------------------------------------
# Comments & explanations
# -------------------------------------------------------------------
def apply_line_comments(func, comments):
    """
    Applies PRE comments to both the assembly listing and (as PRE) visible in the decompiler.

    Args:
        func (Function)
        comments (dict[str,str]): { "0xADDRESS": "comment", ... }
    """
    if func is None or not comments:
        return

    program = func.getProgram()
    listing = program.getListing()
    af = program.getAddressFactory()

    for address_str, comment in comments.items():
        try:
            address = af.getAddress(address_str)
            if address is None:
                _warn("Invalid address {}".format(address_str))
                continue

            code_unit = listing.getCodeUnitAt(address)
            if code_unit:
                code_unit.setComment(CodeUnit.PRE_COMMENT, comment)
                _info("Added PRE comment at {}: {}".format(address_str, comment))
            else:
                _warn("No code unit at {}; skipping comment".format(address_str))
        except Exception as e:
            _warn("Failed to set comment at {}: {}".format(address_str, e))

    _info("Line comments have been applied to both assembly and decompiled views.")


def apply_explanation(func, explanation):
    """Attach a function-level comment with the explanation (safe)."""
    if not func or not explanation:
        return
    try:
        func.setComment(explanation)
        _info("Added explanation as comment to the function.")
    except Exception as e:
        _warn("apply_explanation failed: {}".format(e))


# -------------------------------------------------------------------
# Prompt prep (unchanged behavior, but safe if PROMPTS missing)
# -------------------------------------------------------------------
def prepare_prompt(code, variables, action='rename_retype', callers_code=None):
    """
    Prepares a prompt using PROMPTS[action], with optional callers' code.
    """
    prompt_template = PROMPTS.get(action) if isinstance(PROMPTS, dict) else None
    if not prompt_template:
        return None

    prompt = prompt_template

    if callers_code:
        prompt += "### Additional Context: Callers' Code\n"
        try:
            for caller_name, caller_code in callers_code.items():
                prompt += "#### Caller: {}\n\n{}\n\n\n".format(caller_name, caller_code)
        except Exception:
            pass

    try:
        prompt += "### Code:\n\n{}\n\n".format(code)
    except Exception:
        prompt += "### Code:\n\n<unavailable>\n\n"

    # Include variables only if action is not 'line_comments'
    if action != 'line_comments':
        try:
            prompt += "### Variables:\n\n{}\n\n".format(json.dumps(variables, indent=2))
        except Exception:
            prompt += "### Variables:\n\n<unavailable>\n\n"

    return prompt

