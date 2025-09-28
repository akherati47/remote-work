from burp import IBurpExtender, IHttpListener
from java.io import PrintWriter
from java.lang import Throwable
import json

def decode_obfuscated_string(s):
    N = 100
    out_chars = []
    for ch in s:
        code = ord(ch)
        orig = (code - N + 256) % 256
        out_chars.append(chr(orig)) 
    return ''.join(out_chars)

def decode(text):
    byte_array = bytearray(ord(c) for c in text)
    return byte_array.decode("utf-8", errors="replace")

def utf8_decode(text) :
    byte_array = bytes([ord(c) for c in text])
    return byte_array.decode('utf-8', errors='replace')


class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)

        callbacks.setExtensionName("request decoder")
        callbacks.registerHttpListener(self)

        self._stdout.println("[+] Jython Safe Request Modifier loaded")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Only process requests
        if not messageIsRequest:
            return

        try:
            service = messageInfo.getHttpService()
            request = messageInfo.getRequest()

            analyzed = self._helpers.analyzeRequest(service, request)

            # get URL if available (not strictly needed here)
            try:
                url = analyzed.getUrl()
            except:
                url = None

            headers = list(analyzed.getHeaders())
            body_offset = analyzed.getBodyOffset()

            body_bytes = request[body_offset:]
            body = self._helpers.bytesToString(body_bytes) if body_bytes else ""

            self._stdout.println("[*] Modified request. body:\n  %s \n" % (type(body)))

            # --- ensure header X-My-Extension is present/updated ---
            header_key = "X-My-Extension:"
            new_header = "X-My-Extension: injected-by-jython"
            found = False
            new_headers = []
            for h in headers:
                if h.lower().startswith(header_key.lower()):
                    # replace existing header
                    new_headers.append(new_header)
                    found = True
                else:
                    new_headers.append(h)
            if not found:
                new_headers.append(new_header)

            # --- parse body as JSON and modify it ---
            try:
                data = json.loads(body) if body else {}
            except Exception as e:
                # can't parse JSON -> log and leave request unchanged
                self._stderr.println("[!] Could not parse body as JSON: %s" % str(e))
                return

            # example modification: decode obfuscated string in data["parameters"]
            if "parameters" in data:
                try:
                    data["parameters"] = decode_obfuscated_string(decode(data["parameters"])) 
                     
                except Exception as e:
                    self._stderr.println("[!] decode_obfuscated_string error: %s" % str(e))

            # --- build new body bytes from modified JSON --- 
            new_body_str = json.dumps(data, ensure_ascii=False, separators=(',', ': '))
            new_body_str = new_body_str.replace("\\\"", "\"") 
            new_body_str = new_body_str.replace("\"parameters\": \"", "\"parameters\": ") 
            new_body_str = new_body_str.replace("}\"}", "} }") 
            new_body_bytes = self._helpers.stringToBytes(new_body_str)

            # --- update or add Content-Length header ---
            content_length_key = "Content-Length:"
            found_cl = False
            updated_headers = []
            for h in new_headers:
                if h.lower().startswith(content_length_key.lower()):
                    updated_headers.append("Content-Length: %d" % len(new_body_bytes))
                    found_cl = True
                else:
                    updated_headers.append(h)
            if not found_cl:
                # Insert Content-Length. For correctness, insert near end of headers (before any blank line).
                updated_headers.append("Content-Length: %d" % len(new_body_bytes))

            # --- ensure Content-Type application/json is present (optional but recommended) ---
            content_type_key = "Content-Type:"
            found_ct = any(h.lower().startswith(content_type_key.lower()) for h in updated_headers)
            if not found_ct:
                updated_headers.append("Content-Type: application/json")

            # --- build and set the new request ---
            new_request = self._helpers.buildHttpMessage(updated_headers, new_body_bytes)
            messageInfo.setRequest(new_request)
 
            self._stdout.println("[*] Modified request. data:\n  %s \n" % (data))
            self._stdout.println("[*] Modified request. new_body_str:\n %s \n" % (new_body_str))
            self._stdout.println("[*] Modified request. New parameters:\n %s \n" % (str(data.get("parameters", "<none>"))))

        except Exception as e:
            self._stderr.println("[!] Exception in processHttpMessage: %s" % str(e))
