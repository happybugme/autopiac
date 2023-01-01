
# -*- coding: utf-8 -*-
import json

from ghidra.app.util.cparser.C import CParserUtils
from ghidra.app.cmd.function import ApplyFunctionSignatureCmd

processFields = [
	"ScriptMethod",
	"ScriptString",
	"ScriptMetadata",
	"ScriptMetadataMethod",
	"Addresses",
]

functionManager = currentProgram.getFunctionManager()
baseAddress = currentProgram.getImageBase()
USER_DEFINED = ghidra.program.model.symbol.SourceType.USER_DEFINED

def get_addr(addr):
	return baseAddress.add(addr)

def set_name(addr, name):
    try:
        name = name.replace(' ', '-')
        createLabel(addr, name, True, USER_DEFINED)
    except:
        print("set_name() Failed.")

def set_type(addr, type):
	# Requires types (il2cpp.h) to be imported first
	newType = type.replace("*"," *").replace("  "," ").strip()
	dataTypes = getDataTypes(newType)
	addrType = None
	if len(dataTypes) == 0:
		if newType == newType[:-2] + " *":
			baseType = newType[:-2]
			dataTypes = getDataTypes(baseType)
			if len(dataTypes) == 1:
				dtm = currentProgram.getDataTypeManager()
				pointerType = dtm.getPointer(dataTypes[0])
				addrType = dtm.addDataType(pointerType, None)
	elif len(dataTypes) > 1:
		print("Conflicting data types found for type " + type + "(parsed as '" + newType + "')")
		return
	else:
		addrType = dataTypes[0]
	if addrType is None:
		print("Could not identify type " + type + "(parsed as '" + newType + "')")
	else:
	    try:
	        createData(addr, addrType)
	    except ghidra.program.model.util.CodeUnitInsertionException:
	        print("Warning: unable to set type (CodeUnitInsertionException)")
	    

def make_function(start):
	func = getFunctionAt(start)
	if func is None:
		try:
			createFunction(start, None)
		except:
			print("Warning: Unable to create function")

def set_sig(addr, name, sig):
	try: 
		typeSig = CParserUtils.parseSignature(None, currentProgram, sig, False)
	except ghidra.app.util.cparser.C.ParseException:
		print("Warning: Unable to parse")
		print(sig)
		print("Attempting to modify...")
		# try to fix by renaming the parameters
		try:
			newSig = sig.replace(", ","ext, ").replace("\)","ext\)")
			typeSig = CParserUtils.parseSignature(None, currentProgram, newSig, False)
		except:
			print("Warning: also unable to parse")
			print(newSig)
			print("Skipping.")
			return
	if typeSig is not None:
		try:
            		typeSig.setName(name)
            		ApplyFunctionSignatureCmd(addr, typeSig, USER_DEFINED, False, True).applyTo(currentProgram)
		except:
			print("Warning: unable to set Signature. ApplyFunctionSignatureCmd() Failed.")

f = askFile("script.json from Il2cppdumper", "Open")
data = json.loads(open(f.absolutePath, 'rb').read().decode('utf-8'))

if "ScriptMethod" in data and "ScriptMethod" in processFields:
	scriptMethods = data["ScriptMethod"]
	monitor.initialize(len(scriptMethods))
	monitor.setMessage("Methods")
	for scriptMethod in scriptMethods:
		addr = get_addr(scriptMethod["Address"])
		name = scriptMethod["Name"].encode("utf-8")
		set_name(addr, name)
		monitor.incrementProgress(1)

if "ScriptString" in data and "ScriptString" in processFields:
	index = 1
	scriptStrings = data["ScriptString"]
	monitor.initialize(len(scriptStrings))
	monitor.setMessage("Strings")
	for scriptString in scriptStrings:
		addr = get_addr(scriptString["Address"])
		value = scriptString["Value"].encode("utf-8")
		name = "StringLiteral_" + str(index)