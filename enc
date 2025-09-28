from burp import IBurpExtender, IHttpListener
from java.io import PrintWriter
from java.lang import Throwable
import json
from java.lang import String


def encode_obfuscated_string(s):
    N = 100
    out_chars = []
    for ch in s:
        code = ord(ch)
        obf = (code + N) % 256
        out_chars.append(chr(obf))
    return ''.join(out_chars)

def encode(text):
    # Convert string to UTF-8 bytes
    utf8_bytes = text.encode("utf-8")
    # Convert each byte to a character using chr()
    return utf8_bytes
 

class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)

        callbacks.setExtensionName("request encoder")
        callbacks.registerHttpListener(self)

        self._stdout.println("[+] Jython Safe Request Modifier loaded")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Only process requests
        if messageIsRequest:
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
                        self._stdout.println("[*] Modified Before request. data123:\n  %s \n" % (data['parameters']))
                        self._stdout.println("[*] Modified Before request. data2:\n  %s \n" % (encode_obfuscated_string(str(data['parameters']))))
                        # data["parameters"] = encode_obfuscated_string(str(data['parameters']))
                        data["parameters"] = "test"

                    except Exception as e:
                        self._stderr.println("[!] decode_obfuscated_string error: %s" % str(e))
    
                # data["parameters"] = encode(data["parameters"])
                try:
                    self._stdout.println("[*] Modified Before request. data2:\n  %s \n" % (encode(data["parameters"])))
                    self._stdout.println("[*] Modified Before request. data2:\n  %s \n" % (data))
                    new_body_str = json.dumps(data, ensure_ascii=False, separators=(',', ': '))
                    new_body_bytes = String(new_body_str).getBytes("UTF-8")
                except Exception as e:
                    print(e)
                
                # new_body_bytes = self._helpers.stringToBytes(body)

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

            except Exception as e:
                self._stderr.println("[!] Exception in processHttpMessage: %s" % str(e))

         
