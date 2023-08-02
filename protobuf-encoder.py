import sys
import os
import argparse
import json
import base64
import importlib.util
import inspect

_BASE_DIR = os.path.abspath(
    os.path.dirname(inspect.getfile(inspect.currentframe()))
)
sys.path.insert(0, _BASE_DIR + "/deps/protobuf/python/")
from google.protobuf.json_format import Parse
from google.protobuf.message import Message

def main():
    with open('log.txt', 'w') as logfile:
        
        # Parse arguments
        logfile.write("Parsing Args...\n")
        parser = argparse.ArgumentParser()
        parser.add_argument("--json")
        parser.add_argument("--protobuf_definition")
        args = parser.parse_args()

        # Load protobuf module from specified file
        logfile.write("Loading protobuf module...\n")
        sys.path.insert(0, os.path.dirname(args.protobuf_definition))

        # Get the filename with the extension
        base_name = os.path.basename(args.protobuf_definition)

        # Remove the extension
        class_name = os.path.splitext(base_name)[0]
        proto_module = __import__(class_name)

        proto_class = None

        for name, obj in inspect.getmembers(proto_module):
            if inspect.isclass(obj) and issubclass(obj, Message):
                proto_class = getattr(proto_module, name)
                break

        # Convert JSON to protobuf
        proto_msg = proto_class()
        logfile.write("Parsing JSON string into protobuf\n")
        Parse(args.json, proto_msg)

        logfile.write("Serializing protobuf structure to string\n")
        serialized_protobuf = proto_msg.SerializeToString()

        # Print the resulting protobuf
        logfile.write("Done, returning base64 encoded string\n")
        logfile.write(base64.b64encode(serialized_protobuf).decode())
    print(base64.b64encode(serialized_protobuf).decode())


main()




