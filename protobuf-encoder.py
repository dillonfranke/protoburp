import sys
import os
import argparse
import json
import base64
import importlib.util
import logging
import inspect

_BASE_DIR = os.path.abspath(
    os.path.dirname(inspect.getfile(inspect.currentframe()))
)
sys.path.insert(0, _BASE_DIR + "/deps/protobuf/python/")
from google.protobuf.json_format import Parse
from google.protobuf.message import Message

# Configure logging settings
logging.basicConfig(
    filename='/Users/dillon.franke/Tools/protoburp/exceptions.log',
    filemode='a',  # Append to the file if it exists, create it otherwise
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.ERROR,  # Log only error messages and above (e.g., critical)
)

# Custom exception hook to log unhandled exceptions
def log_exception_hook(exc_type, exc_value, exc_traceback):
    # Log the exception
    logging.error(
        "Uncaught exception",
        exc_info=(exc_type, exc_value, exc_traceback)
    )

    # Call the default exception hook to print the exception to stderr
    sys.__excepthook__(exc_type, exc_value, exc_traceback)

# Set the custom exception hook as the global exception hook
sys.excepthook = log_exception_hook

# def dict_to_protobuf(msg, pb_obj):
#     for field_name, value in msg.items():
#         field = pb_obj.DESCRIPTOR.fields_by_name[field_name]
#         if field.type == field.TYPE_MESSAGE:
#             dict_to_protobuf(value, getattr(pb_obj, field_name))
#         elif field.type == field.TYPE_ENUM:
#             enum_value = field.enum_type.values_by_name[value].number
#             setattr(pb_obj, field_name, enum_value)
#         else:
#             setattr(pb_obj, field_name, value)

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
        # json_body = json.loads(args.json)
        proto_msg = proto_class()
        logfile.write("Parsing JSON string into protobuf\n")
        Parse(args.json, proto_msg)
        # dict_to_protobuf(json_body, proto_msg)

        logfile.write("Serializing protobuf structure to string\n")
        serialized_protobuf = proto_msg.SerializeToString()

        # Print the resulting protobuf
        logfile.write("Done, returning base64 encoded string\n")
        logfile.write(base64.b64encode(serialized_protobuf).decode())
    print(base64.b64encode(serialized_protobuf).decode())


main()




