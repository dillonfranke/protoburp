import os
import inspect
import sys
# Add correct directory to sys.path
_BASE_DIR = os.path.abspath(
    os.path.dirname(inspect.getfile(inspect.currentframe()))
)

sys.path.insert(0, _BASE_DIR + "/deps/protobuf/python/")

from google.protobuf.json_format import MessageToJson
import importlib
import importlib.util

def set_placeholder_values(message):
    for field in message.DESCRIPTOR.fields:
        try:
            if field.type == field.TYPE_DOUBLE or field.type == field.TYPE_FLOAT:
                if field.label == field.LABEL_REPEATED:
                    getattr(message, field.name).extend([1.1, 2.2])
                else:
                    setattr(message, field.name, 1.1)
            elif field.type == field.TYPE_INT64 or field.type == field.TYPE_UINT64 or \
                    field.type == field.TYPE_INT32 or field.type == field.TYPE_FIXED64 or \
                    field.type == field.TYPE_FIXED32 or field.type == field.TYPE_UINT32 or \
                    field.type == field.TYPE_SFIXED32 or field.type == field.TYPE_SFIXED64 or \
                    field.type == field.TYPE_SINT32 or field.type == field.TYPE_SINT64:
                if field.label == field.LABEL_REPEATED:
                    getattr(message, field.name).extend([1, 2])
                else:
                    setattr(message, field.name, 1)
            elif field.type == field.TYPE_BOOL:
                if field.label == field.LABEL_REPEATED:
                    getattr(message, field.name).extend([True, False])
                else:
                    setattr(message, field.name, True)
            elif field.type == field.TYPE_STRING:
                if field.label == field.LABEL_REPEATED:
                    getattr(message, field.name).extend(['example1', 'example2'])
                else:
                    setattr(message, field.name, 'example')
            elif field.type == field.TYPE_BYTES:
                if field.label == field.LABEL_REPEATED:
                    getattr(message, field.name).extend([b'example1', b'example2'])
                else:
                    setattr(message, field.name, b'example')
            elif field.type == field.TYPE_ENUM:
                if field.label == field.LABEL_REPEATED:
                    getattr(message, field.name).extend([list(field.enum_type.values_by_name.values())[i].number for i in range(2)])
                else:
                    setattr(message, field.name, list(field.enum_type.values_by_name.values())[0].number)

            elif field.type == field.TYPE_MESSAGE:
                if field.label == field.LABEL_REPEATED:
                    nested_message = getattr(message, field.name).add()
                    set_placeholder_values(nested_message)
                    nested_message = getattr(message, field.name).add()
                    set_placeholder_values(nested_message)
                else:
                    nested_message = getattr(message, field.name)
                    set_placeholder_values(nested_message)
        except Exception as e:
            sys.stderr.write(f"Had an issue with the {field.name} field, so keeping it uninitialized...")

def generate_example_json(protobuf_module, message_name):
    # Get the protobuf message class
    message_class = getattr(protobuf_module, message_name)
    # Instantiate the message class
    message = message_class()

    set_placeholder_values(message)
    
    # Convert the protobuf message to a JSON string and return it
    return MessageToJson(message, including_default_value_fields=True)

def main():
    try:
        protobuf_definition_path = sys.argv[1]
        message_name = sys.argv[2]
    except:
        print("Usage: python3 json-generator.py <compiled_proto_definition_pb2.py> <MessageName>")
        exit(1)    
    # Add the directory of protobuf_definition_path to sys.path
    sys.path.insert(0, os.path.dirname(os.path.abspath(protobuf_definition_path)))
    # Dynamically import the module
    protobuf_module = importlib.import_module(os.path.splitext(os.path.basename(protobuf_definition_path))[0])
    
    # Generate and print an example JSON object
    json_obj = generate_example_json(protobuf_module, message_name)
    print(json_obj)

if __name__ == '__main__':
    main()

