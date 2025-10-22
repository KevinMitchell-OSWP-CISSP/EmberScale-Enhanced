# -*- coding: utf-8 -*-
# api.py - Advanced SSL/TLS fix for Jython compatibility issues (quiet by default)

import os
import json
import urllib2
import ssl
from config import CLAUDE_API_URL

# -------------------------
# Simple log-level controls
# -------------------------
_LOG_LEVELS = {"ERROR": 40, "WARN": 30, "INFO": 20, "DEBUG": 10}
_LOG_LEVEL = _LOG_LEVELS.get(os.environ.get("EMBERSCALE_LOG_LEVEL", "WARN").upper(), 30)

def _log_debug(msg):
    if _LOG_LEVEL <= 10:
        print "DEBUG: " + msg

def _log_info(msg):
    if _LOG_LEVEL <= 20:
        print "INFO: " + msg

def _log_warn(msg):
    if _LOG_LEVEL <= 30:
        print "WARN: " + msg

def _log_error(msg):
    if _LOG_LEVEL <= 40:
        print "ERROR: " + msg

# -------------------------
# Small text helpers (py2/Jython-safe)
# -------------------------
try:
    basestring  # type: ignore
except NameError:
    basestring = (str,)

try:
    unicode  # type: ignore
except NameError:
    unicode = str

def _to_text(x):
    if x is None:
        return ""
    try:
        return unicode(x)
    except Exception:
        try:
            return str(x)
        except Exception:
            return repr(x)

# -------------------------
# SSL context configuration
# -------------------------
def configure_ssl_context():
    """
    Configure a few SSL contexts for Jython compatibility. We DO NOT verify certs here.
    Only used as a best-effort path; primary transport may be Java HTTPS.
    """
    try:
        contexts_to_try = []

        # Method 1: TLSv1.2 if available
        try:
            if hasattr(ssl, 'PROTOCOL_TLSv1_2'):
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                contexts_to_try.append(("TLSv1.2", ctx))
        except Exception:
            pass

        # Method 2: SSLv23 / PROTOCOL_TLS with SSLv2/3 disabled
        try:
            proto = getattr(ssl, "PROTOCOL_SSLv23", None) or getattr(ssl, "PROTOCOL_TLS", None)
            if proto is not None:
                ctx = ssl.SSLContext(proto)
                if hasattr(ssl, "OP_NO_SSLv2"):
                    ctx.options |= ssl.OP_NO_SSLv2
                if hasattr(ssl, "OP_NO_SSLv3"):
                    ctx.options |= ssl.OP_NO_SSLv3
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                contexts_to_try.append(("SSLv23 no v2/v3", ctx))
        except Exception:
            pass

        return contexts_to_try

    except Exception as e:
        _log_debug("Error configuring SSL contexts: " + _to_text(e))
        return []

def test_ssl_connection(host, port=443, timeout=10):
    """
    Try connecting with various SSL contexts; return the first that works.
    Only logs at DEBUG level now.
    """
    import socket

    contexts = configure_ssl_context()
    for name, ctx in contexts:
        try:
            _log_debug("Testing SSL context: " + name)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            if ctx:
                ssl_sock = ctx.wrap_socket(sock, server_hostname=host)
            else:
                ssl_sock = ssl.wrap_socket(sock)
            ssl_sock.connect((host, port))
            _log_debug("SSL context '" + name + "' works")
            ssl_sock.close()
            return ctx
        except Exception as e:
            _log_debug("SSL context '" + name + "' failed: " + _to_text(e))
            try:
                ssl_sock.close()
            except Exception:
                pass
            continue

    _log_debug("No working SSL context found")
    return None

def send_request_with_context(url, headers, data, context=None, timeout=30):
    """
    Send request with a specific SSL context (quiet unless DEBUG).
    """
    try:
        json_data = json.dumps(data)
        req = urllib2.Request(url, json_data, headers)
        if context:
            try:
                https_handler = urllib2.HTTPSHandler(context=context)
                opener = urllib2.build_opener(https_handler)
                resp = opener.open(req, timeout=timeout)
            except TypeError:
                # Jython's HTTPSHandler may not accept 'context'
                resp = urllib2.urlopen(req, timeout=timeout)
        else:
            resp = urllib2.urlopen(req, timeout=timeout)
        return resp
    except Exception as e:
        _log_debug("Request failed with provided SSL context: " + _to_text(e))
        return None

def send_request_java_approach(url, headers, data, timeout_ms=30000):
    """
    Java HTTPS via Jython; accepts all certs (INSECURE). Quiet by default; detailed only at DEBUG.
    """
    try:
        from java.net import URL
        from java.io import DataOutputStream, BufferedReader, InputStreamReader
        from javax.net.ssl import HttpsURLConnection, SSLContext, X509TrustManager
        from java.security import SecureRandom

        class TrustAllManager(X509TrustManager):
            def checkClientTrusted(self, chain, authType): pass
            def checkServerTrusted(self, chain, authType): pass
            def getAcceptedIssuers(self): return None

        # "SSL" is widely supported on older stacks; verification is disabled above.
        ssl_ctx = SSLContext.getInstance("SSL")
        ssl_ctx.init(None, [TrustAllManager()], SecureRandom())
        HttpsURLConnection.setDefaultSSLSocketFactory(ssl_ctx.getSocketFactory())

        java_url = URL(url)
        conn = java_url.openConnection()
        conn.setRequestMethod("POST")
        conn.setDoOutput(True)
        conn.setConnectTimeout(timeout_ms)
        conn.setReadTimeout(timeout_ms)

        for k, v in headers.items():
            conn.setRequestProperty(k, v)

        json_data = json.dumps(data)
        out = DataOutputStream(conn.getOutputStream())
        out.writeBytes(json_data)
        out.flush()
        out.close()

        code = conn.getResponseCode()
        _log_debug("Java HTTP response code: " + _to_text(code))

        if code == 200:
            reader = BufferedReader(InputStreamReader(conn.getInputStream()))
            buf = []
            line = reader.readLine()
            while line is not None:
                buf.append(line)
                line = reader.readLine()
            reader.close()
            content = "".join(buf)
            _log_debug("Java HTTP success, response length: " + _to_text(len(content)))

            class MockResponse(object):
                def __init__(self, content):
                    self._c = content
                def read(self):
                    return self._c

            return MockResponse(content)

        _log_debug("Java HTTP failed with code: " + _to_text(code))
        return None

    except Exception as e:
        _log_debug("Java HTTP approach failed: " + _to_text(e))
        try:
            import traceback
            if _LOG_LEVEL <= 10:
                traceback.print_exc()
        except Exception:
            pass
        return None

def send_request_curl(url, headers, data):
    """
    Fallback to system curl (quiet unless DEBUG).
    """
    try:
        import subprocess
        import tempfile
        import os as _os

        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write(json.dumps(data))
            temp_file = f.name

        try:
            cmd = [
                'curl', '-s', '-X', 'POST',
                '-H', 'Content-Type: application/json',
                '-H', 'x-api-key: {}'.format(headers.get('x-api-key', '')),
                '-H', 'anthropic-version: {}'.format(headers.get('anthropic-version', '')),
                '--data', '@{}'.format(temp_file),
                url
            ]
            _log_debug("Executing curl command...")
            result = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
            _log_debug("Curl succeeded, response length: " + _to_text(len(result)))

            class MockResponse(object):
                def __init__(self, content):
                    self._c = content
                def read(self):
                    return self._c

            return MockResponse(result)

        finally:
            try:
                _os.unlink(temp_file)
            except Exception:
                pass

    except Exception as e:
        _log_debug("Curl approach failed: " + _to_text(e))
        return None

def send_request(url, headers, data):
    """
    Send request using (1) Python SSL contexts (if one works), else (2) Java HTTPS, else (3) curl.
    Only high-level INFO is printed; detail at DEBUG.
    """
    method = (os.environ.get("EMBERSCALE_HTTP_METHOD") or "").lower().strip()
    if method == "java":
        _log_info("Using Java HTTP transport")
        resp = send_request_java_approach(url, headers, data)
        if resp:
            return resp
        _log_warn("Java HTTP transport failed; trying curl fallback")
        return send_request_curl(url, headers, data)

    if method == "curl":
        _log_info("Using curl transport")
        return send_request_curl(url, headers, data)

    # Default: try SSL contexts quietly, then Java, then curl.
    _log_debug("Testing SSL contexts...")
    ctx = test_ssl_connection("api.anthropic.com")
    if ctx:
        _log_info("Using Python HTTPS with working SSL context")
        resp = send_request_with_context(CLAUDE_API_URL, headers, data, ctx)
        if resp:
            return resp
        _log_warn("Python HTTPS failed with working context; trying Java transport")

    _log_info("Using Java HTTP transport")
    resp = send_request_java_approach(url, headers, data)
    if resp:
        return resp

    _log_warn("Java transport failed; trying curl fallback")
    return send_request_curl(url, headers, data)

def read_response(response):
    """Read the response (quiet)."""
    if response is None:
        return None
    elif isinstance(response, urllib2.HTTPError):
        try:
            error_content = response.read()
        except Exception:
            error_content = ""
        _log_error("HTTP response code " + _to_text(response.code))
        if error_content:
            snippet = error_content[:200]
            if len(error_content) > 200:
                snippet += "..."
            _log_error("HTTP error body: " + snippet)
        return None
    else:
        try:
            return response.read()
        except Exception as e:
            _log_error("Failed reading response: " + _to_text(e))
            return None

def parse_json_response(content):
    """Parse the JSON response from Claude API."""
    if not content:
        _log_warn("No content to parse")
        return None

    json_start = content.find('{')
    json_end = content.rfind('}') + 1
    if json_start != -1 and json_end != -1 and json_end > json_start:
        json_str = content[json_start:json_end]
        try:
            return json.loads(json_str)
        except ValueError as e:
            _log_error("Failed to parse JSON: " + _to_text(e))
    else:
        _log_warn("No JSON object found in body")
    return None

def get_response_from_claude(prompt, api_key, model, monitor, is_explanation=False):
    """Get a response from the Claude API with enhanced error handling."""
    try:
        # Validate inputs
        if not prompt or not api_key or not model:
            _log_error("Missing required parameters")
            return None
        
        # Validate API key format
        if not api_key.startswith("sk-ant-"):
            _log_error("Invalid API key format")
            return None

        prompt_str = _to_text(prompt)
        api_key_str = _to_text(api_key)
        model_str = _to_text(model)

        try:
            monitor.setMessage("Sending request to Claude API...")
        except Exception:
            pass

        headers = {
            "Content-Type": "application/json",
            "x-api-key": api_key_str,
            "anthropic-version": "2023-06-01"
        }
        data = {
            "model": model_str,
            "messages": [{"role": "user", "content": prompt_str}],
            "max_tokens": 2000,
            "temperature": 0.2,
            "top_p": 1.0,
            "top_k": 30
        }

        _log_info("Sending request to Claude API")
        resp = send_request(CLAUDE_API_URL, headers, data)
        if resp is None:
            _log_error("Failed to get response from Claude API")
            return None

        try:
            monitor.setMessage("Processing response from Claude API...")
        except Exception:
            pass

        content = read_response(resp)
        if not content:
            _log_error("No content received")
            return None

        _log_debug("Response content length: " + _to_text(len(content)))

        # Parse the envelope returned by Anthropic
        try:
            response_json = json.loads(content)
            # Expected: {'content': [{'type': 'text','text': '...'}], ...}
            content_text = response_json['content'][0]['text']
        except Exception:
            # If the whole body isn't JSON (e.g., proxy), attempt salvage
            body = _to_text(content)
            try:
                response_json = json.loads(body)
                content_text = response_json['content'][0]['text']
            except Exception:
                _log_error("Failed to parse JSON envelope from response")
                _log_debug("Raw content preview: " + body[:200])
                return None

        if is_explanation:
            return _to_text(content_text).strip()
        else:
            # The assistant payload (for rename/retype/comments) is itself JSON text
            return parse_json_response(_to_text(content_text))

    except Exception as e:
        _log_error("Exception in get_response_from_claude: " + _to_text(e))
        try:
            import traceback
            if _LOG_LEVEL <= 10:
                traceback.print_exc()
        except Exception:
            pass
        return None
    finally:
        try:
            monitor.setMessage("")
        except Exception:
            pass
