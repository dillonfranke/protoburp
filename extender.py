import json
import subprocess
import inspect
import base64

from burp import IBurpExtender
from burp import IHttpListener
from burp import ITab
from javax.swing import JPanel
from javax.swing import JButton
from javax.swing import JFileChooser
from java.awt import FlowLayout
from tab import Tab

# Add correct directory to sys.path
_BASE_DIR = os.path.abspath(
    os.path.dirname(inspect.getfile(inspect.currentframe()))
)

sys.path.insert(0, _BASE_DIR + "/deps/protobuf/python/")

EXTENSION_NAME = "ProtoBurp"

class BurpExtender(IBurpExtender, IHttpListener):

    # Implement IBurpExtender methods
    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object (Burp Extensibility Feature)
        self._callbacks = callbacks

        # set our extension name that will display in the Extender tool when loaded
        self._callbacks.setExtensionName(EXTENSION_NAME)

        # register ourselves as an HTTP listener
        self._callbacks.registerHttpListener(self)

        # get burp helper functions
        self._helpers = self._callbacks.getHelpers()

        self.suite_tab = Tab(self, callbacks)

        # Add the custom tab
        callbacks.addSuiteTab(self.suite_tab)

    def getTabCaption(self):
        return "ProtoBurp"

    def getUiComponent(self):
        return self._jPanel

    def file_chooser(self, event):
        chooser = JFileChooser()
        action = chooser.showOpenDialog(self._jPanel)

        if action == JFileChooser.APPROVE_OPTION:
            file = chooser.getSelectedFile()

    def json_to_protobuf_in_python3(self, json_body):
        # Prepare the command to run in Python 3
        cmd = ["python3", os.path.join(_BASE_DIR, "protobuf-encoder.py"), "--json", json.dumps(json_body), "--protobuf_definition", str(self.suite_tab.selectedFilePath)]

        output = ""
        # Run the command
        try:
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            print("Subprocess exited with error (status code {}):".format(e.returncode))
            print(e.output.decode())
        
        output = output.decode("utf-8").strip()
        protobuf = base64.b64decode(output)

        return protobuf

    # Implement IHttpListener methods
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Only continue if the extension is enabled
        if not self.suite_tab.protoburp_enabled:
            return
        # Only process requests
        if not messageIsRequest:
            return

        # Get the HTTP service for the request
        httpService = messageInfo.getHttpService()
        # Convert the request to a IRequestInfo object
        requestInfo = self._helpers.analyzeRequest(httpService, messageInfo.getRequest())
        # requestInfo is an IRequestInfo object
        headers = requestInfo.getHeaders()

        # Convert header names to lower case for case-insensitive comparison
        header_names = [header.split(":")[0].lower() for header in headers]

        # Only process if the ProtoBurp header exists
        if not "protoburp" in header_names:
            return

        # Get the body of the request
        body = messageInfo.getRequest()[requestInfo.getBodyOffset():]
        # Convert the body from bytes to string
        body_string = body.tostring().decode()
        # Convert the string to a JSON object
        json_body = json.loads(body_string)
        # Convert the JSON to Protobuf
        protobuf = self.json_to_protobuf_in_python3(json_body)
        # Create a new HTTP message with the Protobuf body
        new_message = self._helpers.buildHttpMessage(headers, protobuf)
        # Update the request in the messageInfo object
        messageInfo.setRequest(new_message)