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

def dict_to_protobuf(msg, pb_obj):
    for field_name, value in msg.items():
        field = pb_obj.DESCRIPTOR.fields_by_name[field_name]
        if field.type == field.TYPE_MESSAGE:
            dict_to_protobuf(value, getattr(pb_obj, field_name))
        elif field.type == field.TYPE_ENUM:
            enum_value = field.enum_type.values_by_name[value].number
            setattr(pb_obj, field_name, enum_value)
        else:
            setattr(pb_obj, field_name, value)

def main():
    # Parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("--json")
    parser.add_argument("--protobuf_definition")
    args = parser.parse_args()

    # Load protobuf module from specified file
    sys.path.insert(0, os.path.dirname(args.protobuf_definition))
    sys.path.insert(0, _BASE_DIR + "/deps/protobuf/python/")
    proto_module = __import__('GetMyMessages_pb2')

    # Convert JSON to protobuf
    json_body = json.loads(args.json)
    proto_msg = proto_module.GetMyMessages()
    dict_to_protobuf(json_body, proto_msg)

    # Print the resulting protobuf
    print(base64.b64encode(proto_msg.SerializeToString()).decode())


main()




