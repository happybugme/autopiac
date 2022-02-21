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
            if i % 100 == 0:
                percent = i / length * 100
                self.progress = f"Il2Cpp types: {percent:.2f}%"
            if self.bv.get_type_by_name(name):
                continue
            self.bv.define_user_type(name, result.types[name])
    
    def process_methods(self, data: dict):
        self.progress = f"Il2Cpp methods (2/3)"
        scriptMethods = data["ScriptMethod"]
        length = len(scriptMethods)
        i = 0
        for scriptMethod in scriptMethods:
            if self.cancelled:
                self.progress = "Il2Cpp cancelled, aborting"
                return
            i += 1
            if i % 100 == 0: