from binaryninja import *
from os.path import exists

def get_addr(bv: BinaryView, addr: int):
    imageBase = bv.start
    return imageBase + addr

class Il2CppProcessTask(BackgroundTaskThread):
    def __init__(self, bv: BinaryView, script_path: str,
                 header_path: str):
        BackgroundTaskThread.__init__(self, "Il2Cpp start", True)
        self.bv = bv
        self.script_path = script_path
        self.header_path = header_path
        self.has_types = False
    
    def process_header(self):
        self.progress = "Il2Cpp types (1/3)"
        with open(self.header_path) as f:
            result = self.bv.parse_types_from_string(f.read())
        length = len(result.types)
        i = 0
        for name in result.types:
            i += 1
 