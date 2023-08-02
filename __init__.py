import os
import sys
import inspect

_BASE_DIR = os.path.abspath(
    os.path.dirname(inspect.getfile(inspect.currentframe()))
)

sys.path.insert(0, _BASE_DIR + "/deps/protobuf/python/")
sys.path.insert(0, _BASE_DIR + "/gen")

