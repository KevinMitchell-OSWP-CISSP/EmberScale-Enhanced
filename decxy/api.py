# -*- coding: utf-8 -*-
# api.py
#
# Note: Decyx doesn't use Anthropic's official python API as it is intended for Python 3+

import os
import json
import urllib2
try:
    # Prefer config value, allow env override, and provide a safe default.
    from config import CLAUDE_API_URL as _CFG_URL
except Exception:
    _CFG_URL = None
CLAUDE_API_URL = os.environ.get("CLAUDE_API_URL") or _CFG_URL or "https://api.anthropic.com/v1/messages"

def _to_str(x, default=""):
    if x is None:
        return default
    try:
        return x if isinstance(x, basestring) else str(x)
    except Exception:
        return str(x)

def send_request(url, headers, data):
    """Send a POST request to the specified URL with the given headers and data.
    Returns the response object or None if an error occurs.
    """
    # Ensure payload is bytes and headers/URL are strings (no None) for Jython/Py2.
    if isinstance(data, basestring):
        payload = data
    else:
        payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
    clean_headers = dict((k, _to_str(v, "")) for k, v in headers.items())
    url = _to_str(url, "")
    req = urllib2.Request(url, payload, clean_headers)
    try:
        response = urllib2.urlopen(req)
        return response
    except Exception as e:
        print "Error sending request: {}".format(e)
        return None

def read_response(response):
    """Read the response content from the response object.
    Returns the content as a string or None if an error occurs.
    """
    try:
        if hasattr(response, 'read'):
            content = response.read()
        else:
            content = response
        return content
    except Exception as e:
        print "Error reading response: {}".format(e)
        return None

def parse_json_response(content):
    """Parse JSON content from the response.
    Returns the parsed JSON object or None if parsing fails.
    """
    try:
        return json.loads(content)
    except Exception as e:
        print "Error parsing JSON: {}".format(e)
        return None

def get_response_from_claude(prompt, api_key, model, monitor, is_explanation=False):
    """Get a response from Claude API.
    Returns the response content or None if an error occurs.
    """
    try:
        monitor.setMessage("Sending request to Claude API...")
        # Normalize inputs / defaults
        api_key = _to_str(api_key) or _to_str(os.environ.get("ANTHROPIC_API_KEY")) or _to_str(os.environ.get("CLAUDE_API_KEY"))
        if not api_key:
            raise ValueError("Anthropic API key is missing")
        model = _to_str(model) or _to_str(os.environ.get("ANTHROPIC_MODEL")) or "claude-3-5-sonnet-20240620"
        if prompt is None:
            prompt = ""
        elif not isinstance(prompt, basestring):
            prompt = json.dumps(prompt, ensure_ascii=False)

        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01"
        }
        data = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 2000,
            "temperature": 0.2,
            "top_p": 1.0,
            "top_k": 30
        }

        response = send_request(CLAUDE_API_URL, headers, data)
        if not response:
            return None

        content = read_response(response)

        if content:
            print "Received response from Claude API."
            try:
                response_json = json.loads(content)
            except Exception as je:
                print "Failed to parse top-level JSON: {}".format(je)
                print "Raw content (truncated): {}".format(_to_str(content)[:300])
                return None

            blocks = response_json.get('content') or []
            content_text = blocks[0].get('text') if blocks and isinstance(blocks[0], dict) else ""

            if is_explanation:
                return _to_str(content_text).strip()
            # Many prompts expect JSON in the assistant text. Try strict parse first, then brace-scan.
            try:
                return json.loads(content_text)
            except Exception:
                parsed = parse_json_response(_to_str(content_text))
                return parsed if parsed is not None else _to_str(content_text).strip()

        return None

    except Exception as e:
        print "Exception in get_response_from_claude: {}".format(e)
        return None
    finally:
        monitor.setMessage("")