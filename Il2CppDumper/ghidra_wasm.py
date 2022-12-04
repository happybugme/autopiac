# -*- coding: utf-8 -*-
import json

from wasm import WasmLoader
from wasm.analysis import WasmAnalysis
from ghidra.util.task import ConsoleTaskMonitor

monitor = ConsoleTaskMonitor()
WasmLoader.loadElementsToTable(currentProgram, WasmAnalysis.getState(currentProgram).module, 0, 0, 0, monitor)

runScript("analyze_dyncalls.py")

processFields = [
	"ScriptMethod",
	"ScriptString",
	"ScriptMetadata",
	"ScriptMetadataMethod",
	"Addresses",
]

functionManager = currentProgram.getFunctionManager()
progspace = currentProgram.addressFactory.getAddressSpace("ram")
USER_DEFINED = ghidra.program.model.symbol.SourceType.USER_DEFINED

def get_addr(addr):
	return progspace.getAddress(addr)

def set_name(addr, name):
	name = name.replace(' '