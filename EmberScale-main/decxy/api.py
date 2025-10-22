# api.py
#
# Jython-safe Anthropic API client with Unicode-safe urllib2 and a Java HTTPS fallback.

import os
import json

# -------------------------
# Py2/Jython compatibility
# -------------------------
try:
    import urllib2  # Jython 2.7
except Exception:
    urllib2 = None

try:
    basestring  # Py2 / Jython
except NameError:  # Py3 safety if ever run there
    basestring = (str, bytes)

def _is_str(x):
    try:
        return isinstance(x, basestring)
    except Exception:
        return isinstance(x, (str, bytes))

def _to_text(x, default=u""):
    """Return a unicode/str (never None)."""
    if x is None:
        return default
    try:
        if isinstance(x, unicode):  # type: ignore
            return x
    except Exception:
        pass
    try:
        if isinstance(x, bytes):
            return x.decode("utf-8", "replace")
    except Exception:
        pass
    try:
        return unicode(x)  # type: ignore
    except Exception:
        return str(x)

def _to_bytes(x):
    """Return UTF-8 encoded bytes."""
    if x is None:
        return b""
    if isinstance(x, bytes):
        return x
    try:
        return (_to_text(x) or u"").encode("utf-8")
    except Exception:
        return str(x).encode("utf-8")

# -------------------------
# Config / Defaults
# -------------------------
try:
    # Prefer config value, allow env override, and provide a safe default.
    from decxy.config import CLAUDE_API_URL as _CFG_URL
except Exception:
    _CFG_URL = None

CLAUDE_API_URL = (
    os.environ.get("CLAUDE_API_URL")
    or _CFG_URL
    or "https://api.anthropic.com/v1/messages"
)

ANTHROPIC_VERSION = "2023-06-01"

# -------------------------
# Transport (urllib2 first, Java HTTPS fallback)
# -------------------------
def _urllib2_post(url, headers, body_bytes):
    """POST using urllib2 (works in most Jython builds)."""
    if urllib2 is None:
        return None
    try:
        # Coerce headers to plain text (no None)
        clean_headers = {}
        for k, v in (headers or {}).items():
            k_s = _to_text(k, u"").strip()
            v_s = _to_text(v, u"").strip()
            if k_s and v_s:
                clean_headers[k_s] = v_s

        req = urllib2.Request(_to_text(url, u""), body_bytes, clean_headers)
        return urllib2.urlopen(req)
    except Exception as e:
        print "urllib2 transport failed: {}".format(_to_text(e))
        return None

def _java_https_post(url, headers, body_bytes):
    """POST using Java HttpsURLConnection (robust in Jython for Unicode)."""
    try:
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

        u = URL(_to_text(url, u""))
        con = u.openConnection()
        con.setRequestMethod("POST")
        con.setDoOutput(True)
        con.setConnectTimeout(30000)
        con.setReadTimeout(30000)

        # Set headers
        for k, v in (headers or {}).items():
            k_s = _to_text(k, u"").strip()
            v_s = _to_text(v, u"").strip()
            if k_s and v_s:
                con.setRequestProperty(k_s, v_s)

        out = DataOutputStream(con.getOutputStream())
        out.write(body_bytes)
        out.flush()
        out.close()

        code = con.getResponseCode()
        stream = con.getInputStream() if 200 <= code < 300 else con.getErrorStream()
        br = BufferedReader(InputStreamReader(stream))
        buf = []
        line = br.readLine()
        while line is not None:
            buf.append(line)
            line = br.readLine()
        br.close()
        return code, u"".join(buf)
    except Exception as e:
        print "Java HTTPS transport failed: {}".format(_to_text(e))
        return None, None

# -------------------------
# High-level helpers
# -------------------------
def send_request(url, headers, data):
    """
    Send a POST (JSON) to Anthropic.
    Returns an object with .read() on success (urllib2 response), or a tiny shim with .read() when Java fallback is used.
    """
    try:
        # Serialize JSON as UTF-8 bytes (never None)
        if _is_str(data):
            body_bytes = _to_bytes(data)
        else:
            body_bytes = _to_bytes(json.dumps(data, ensure_ascii=False))

        # Ensure baseline headers
        final_headers = dict(headers or {})
        if "Content-Type" not in final_headers:
            final_headers["Content-Type"] = "application/json; charset=utf-8"

        # Try urllib2 first
        resp = _urllib2_post(url, final_headers, body_bytes)
        if resp is not None:
            return resp

        # Fallback to Java HTTPS
        code, text = _java_https_post(url, final_headers, body_bytes)
        if text is None:
            return None

        class _ShimResp(object):
            def __init__(self, payload):
                self._payload = _to_bytes(payload)
            def read(self):
                return self._payload

        if code and not (200 <= code < 300):
            print "HTTP {} from Anthropic".format(code)
        return _ShimResp(text)

    except Exception as e:
        print "Error sending request: {}".format(_to_text(e))
        return None

def read_response(response):
    """Return raw bytes from response (or None)."""
    if response is None:
        return None
    try:
        return response.read()
    except Exception as e:
        print "read_response failed: {}".format(_to_text(e))
        return None

def parse_json_response(content):
    """
    Parse JSON from raw bytes / text; if top-level fails, try to extract an inner JSON object.
    """
    if not content:
        return None
    try:
        if isinstance(content, bytes):
            s = content.decode("utf-8", "replace")
        else:
            s = _to_text(content)
        return json.loads(s)
    except Exception:
        pass

    # Try to find a JSON object inside text
    try:
        import re
        s = s if 's' in locals() else _to_text(content)
        for m in re.finditer(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', s):
            try:
                return json.loads(m.group(0))
            except Exception:
                continue
    except Exception:
        pass
    return None

def get_response_from_claude(prompt, api_key, model, monitor, is_explanation=False):
    """
    Call Anthropic Messages API and return either:
      - explanation: plain text
      - else: parsed JSON if possible, else plaintext
    """
    try:
        monitor.setMessage("Sending request to Claude API...")

        # Resolve API key / model safely
        key = _to_text(api_key) or _to_text(os.environ.get("ANTHROPIC_API_KEY")) or _to_text(os.environ.get("CLAUDE_API_KEY"))
        if not key:
            raise ValueError("Anthropic API key is missing")
        mdl = _to_text(model) or _to_text(os.environ.get("ANTHROPIC_MODEL")) or "claude-3-5-sonnet-20240620"

        safe_prompt = _to_text(prompt, u"")

        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "x-api-key": key,
            "anthropic-version": ANTHROPIC_VERSION,
        }
        data = {
            "model": mdl,
            "messages": [{"role": "user", "content": safe_prompt}],
            "max_tokens": 2000,
            "temperature": 0.2,
            "top_p": 1.0,
            "top_k": 30,
        }

        resp = send_request(CLAUDE_API_URL, headers, data)
        if resp is None:
            return None

        raw = read_response(resp)
        if not raw:
            return None

        # Decode once; keep a text copy for brace-scan fallback
        text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else _to_text(raw)

        try:
            response_json = json.loads(text)
        except Exception as je:
            print "Failed to parse top-level JSON: {}".format(_to_text(je))
            print "Raw content (truncated): {}".format(text[:300])
            return None

        blocks = response_json.get("content") or []
        content_text = blocks[0].get("text") if (blocks and isinstance(blocks[0], dict)) else ""

        if is_explanation:
            return _to_text(content_text).strip()

        # Many prompts expect JSON: try strict first, then inner-object scan.
        try:
            return json.loads(_to_text(content_text))
        except Exception:
            parsed = parse_json_response(content_text)
            return parsed if parsed is not None else _to_text(content_text).strip()

    except Exception as e:
        print "Exception in get_response_from_claude: {}".format(_to_text(e))
        return None
    finally:
        try:
            monitor.setMessage("")
        except Exception:
            pass