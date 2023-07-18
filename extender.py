import json
import subprocess
import inspect

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
sys.path.insert(0, _BASE_DIR + "/deps/six/")

EXTENSION_NAME = "ProtoBurp"

def fix_protobuf():
    import six

    u = six.u

    def new_u(s):
        if s == r"[\ud800-\udfff]":
            # Don't match anything
            return "$^"
        else:
            return u(s)

    six.u = new_u

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
            print "File Selected:", file.getAbsolutePath()
            # You can now use file.getAbsolutePath() as your variable



    def json_to_protobuf(self, json_body):
        # proto_module = imp.load_source('GetMyMessages_pb2', self.suite_tab.selectedFilePath)
        # loader = importlib.machinery.SourceFileLoader('GetMyMessages_pb2', self.suite_tab.selectedFilePath)
        # proto_module = loader.load_module()
        # spec = importlib.util.spec_from_file_location("module.name", self.selectedFilePath)
        # proto_module = importlib.util.module_from_spec(spec)
        # spec.loader.exec_module(proto_module)

        sys.path.insert(0, os.path.dirname(self.suite_tab.selectedFilePath))
        proto_module = __import__('GetMyMessages_pb2')

        proto_msg = proto_module.GetMyMessages()
        self.dict_to_protobuf(json_body, proto_msg)
        encoded_protobuf = proto_msg.SerializeToString()
        return encoded_protobuf

    def dict_to_protobuf(self, msg, pb_obj):
        for field_name, value in msg.items():
            field = pb_obj.DESCRIPTOR.fields_by_name[field_name]
            if field.type == field.TYPE_MESSAGE:
                self.dict_to_protobuf(value, getattr(pb_obj, field_name))
            elif field.type == field.TYPE_ENUM:
                enum_value = field.enum_type.values_by_name[value].number
                setattr(pb_obj, field_name, enum_value)
            else:
                setattr(pb_obj, field_name, value)

    # Implement IHttpListener methods
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Get the directory of the currently running script

        # Define the path for the new file
        new_file_path = os.path.join(_BASE_DIR, "chickens")

        # Create the new file
        with open(new_file_path, "w") as file:
            file.write(sys.version)
        # Only continue if the extension is enabled
        if not self.suite_tab.protoburp_enabled:
            return
        # Only process requests
        if not messageIsRequest:
            return

        print("Processing request.")

        print("Processing HTTP message...")

        print("Processing HTTP message...")

        # Get the HTTP service for the request
        httpService = messageInfo.getHttpService()
        print("HTTP Service obtained.")

        # Convert the request to a IRequestInfo object
        requestInfo = self._helpers.analyzeRequest(httpService, messageInfo.getRequest())
        print("Request Info analyzed.")

        # Get the headers of the request
        headers = requestInfo.getHeaders()
        print("Headers extracted.")

        # Get the body of the request
        body = messageInfo.getRequest()[requestInfo.getBodyOffset():]
        print("Body of request extracted.")
        print(body)

        # Convert the body from bytes to string
        body_string = body.tostring().decode()
        print(body_string)
        print("Body converted from bytes to string.")

        # Convert the string to a JSON object
        json_body = json.loads(body_string)
        print("String converted to JSON object.")

        # Convert the JSON to Protobuf
        protobuf = self.json_to_protobuf(json_body)
        print("JSON converted to Protobuf.")

        # Create a new HTTP message with the Protobuf body
        new_message = self._helpers.buildHttpMessage(headers, protobuf)
        print("New HTTP message created with Protobuf body.")

        # Update the request in the messageInfo object
        messageInfo.setRequest(new_message)
        print("Request updated in the messageInfo object.")



