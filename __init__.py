import os
import sys
import inspect

_BASE_DIR = os.path.abspath(
    os.path.dirname(inspect.getfile(inspect.currentframe()))
)

sys.path.insert(0, _BASE_DIR + "/deps/protobuf/python/")
sys.path.insert(0, _BASE_DIR + "/deps/six/")
sys.path.insert(0, _BASE_DIR + "/gen")

# Hack to fix loading protobuf libraries within Jython. See https://github.com/protocolbuffers/protobuf/issues/7776
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


fix_protobuf()