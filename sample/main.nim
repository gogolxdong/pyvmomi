import re,strutils,strscans,macros,pegs,strformat,packedjson,sequtils,tables,os

# import vmodl
# let p = peg"""
# function_call <- \ident "(" parameters ")"
# parameters    <- (parens / string / [^)] )*
# parens        <- "(" parameters ")"
# string    <- dq_string / sq_string
# dq_string <- DQUOTE (BSLASH . / [^DQUOTE])* DQUOTE
# sq_string <- SQUOTE (BSLASH . / [^SQUOTE])* SQUOTE
# DQUOTE <- """
# SQUOTE <- """
# BSLASH <- "\\"
# """
# removeFile("ServerObjects")
# let reg = re"(CreateEnumType\(|CreateDataType\(|CreateManagedType\()+.*"
# const coreContent = staticRead("../pyVmomi/CoreTypes.py")
# var coreObjects = coreContent.findAll(reg)

# const pbmContent = staticRead("../pyVmomi/PbmObjects.py")
# var pbmObjects = pbmContent.findAll(reg)

# const queryContent = staticRead("../pyVmomi/QueryTypes.py")
# var queryTypes = queryContent.findAll(reg)

# const smsContent = staticRead("../pyVmomi/SmsObjects.py")
# var smsObjects = smsContent.findAll(reg)

# const serverContent = staticRead("../pyVmomi/ServerObjects.py")
# var serverObjects = serverContent.findAll(reg)

# const eamContent = staticRead("../pyVmomi/EamObjects.py")
# var eamObjects = eamContent.findAll(reg)

# writeFile("ServerObjects",coreObjects.concat(queryTypes).concat(pbmObjects).concat(smsObjects).concat(eamObjects).concat(serverObjects).join("\L"))

var vmodlTypes = {
    "void": "void",
    "anyType": "pointer",
    "boolean":"bool",
    "byte":"byte",
    "string":"string",
    "int":"int",
    "short":"int16",
    "long":"int64",
    "float":"float32",
    "double":"float64",
    "Link":"string",
    "vmodl.URI":  "string",
    "vmodl.Binary":"byte",
    "vmodl.DateTime":"string",
    "vmodl.TypeName":"string",
    "vmodl.MethodName":"string",
    "vmodl.DataObject":"DataObject",
    "vmodl.ManagedObject":"ManagedObject",
    "vmodl.PropertyPath":"string"}.toTable

template CreateManagedType(typename,parent):untyped {.dirty.}= 
    type 
        typename* = ref object of parent

template CreateDataType(typename,parent):untyped {.dirty.}= 
    type 
        typename* = ref object of parent


macro vmware(): untyped = 
    var vmodlTypes = {
        "void": "void",
        "anyType": "pointer",
        "boolean":"bool",
        "byte":"byte",
        "string":"string",
        "int":"int",
        "short":"int16",
        "long":"int64",
        "float":"float32",
        "double":"float64",
        "Link":"string",
        "vmodl.URI":  "string",
        "vmodl.Binary":"byte",
        "vmodl.DateTime":"string",
        "vmodl.TypeName":"string",
        "vmodl.MethodName":"string",
        "vmodl.DataObject":"DataObject",
        "vmodl.ManagedObject":"ManagedObject",
        "vmodl.PropertyPath":"string"}.toTable
    result = newStmtList()
    const lines = staticRead("ServerObjects").splitLines
    var vm = newTable[string, NimNode]()

    var propMap = newTable[string,NimNode]()
    var methodMap = newTable[string,NimNode]()
    for i in 0..lines.len-1:
        # echo i
        var node = parseStmt(lines[i])
        for n in node:
            if n[0].strVal == "CreateDataType":
                let (vmodl, wsdl, parent, version, props) = (n[1].strVal, n[2].strVal, n[3].strVal, n[4].strVal, n[5])
                var dataType = wsdl
                vmodlTypes[vmodl] = dataType
                propMap[vmodl] = props


            elif n[0].strVal == "CreateEnumType":
                let (vmodl,wsdl,version,value) = (n[1].strVal, n[2].strVal,n[3].strVal, n[4])
                vmodlTypes[vmodl] = wsdl
                func `@`(node: NimNode): seq[NimNode]  =
                    result = @[]
                    for n in node:
                        result.add(newIdentNode n.strVal)
                vm[vmodl] = newEnum(newIdentNode wsdl, @(value), true, true)
        
            elif n[0].strVal == "CreateManagedType" :
                let (vmodl,wsdl,parent,version,props,methods) = (n[1].strVal.split(".")[^1], n[2].strVal, n[3].strVal, n[4].strVal, n[5], n[6])
                vmodlTypes[vmodl] = wsdl
                propMap[vmodl] = props
                methodMap[vmodl] = methods
    echo vmodlTypes
    for i in 0..lines.len-1:
        # echo i
        var node = parseStmt(lines[i])
        for n in node:
            if n[0].strVal == "CreateDataType":
                let (vmodl, wsdl, parent, version, props) = (n[1].strVal, n[2].strVal, n[3].strVal, n[4].strVal, n[5])
                var parentType = vmodlTypes[parent] 
                vm[vmodl] = getAst(CreateDataType(newIdentNode wsdl, newIdentNode parentType))
        
            elif n[0].strVal == "CreateManagedType" :
                let (vmodl,wsdl,parent,version,props,methods) = (n[1].strVal.split(".")[^1], n[2].strVal, n[3].strVal, n[4].strVal, n[5], n[6])
                var parentIdent = newIdentNode parent.split(".")[1]
                vm[vmodl] = getAst(CreateManagedType(newIdentNode wsdl, parentIdent))

    for vmodl,props in propMap:
        var recList = newNimNode(nnkRecList)
        for p in props:
            var propName = p[0].strVal
            var typeName = p[1].strVal
            
            if typeName.endsWith("[]"):
                var seqType = typeName[0..^3]
                if vmodlTypes.hasKey seqType:
                    typeName = fmt"seq[{vmodlTypes[seqType]}]"
                else:
                    typeName = fmt"seq[{seqType}]"
            elif typeName.contains("."):
                if vmodlTypes.hasKey typeName:
                    typeName = vmodlTypes[typeName]
            else: 
                typeName = vmodlTypes[typeName]
            # echo fmt"{propName}:{typeName}"
            recList.add newIdentDefs(newNimNode(nnkPostfix).add(newIdentNode"*", newIdentNode propName), newIdentNode typeName)
        # echo repr recList
        vm[vmodl].add recList

    var vmodl,vim,pbm,sms,types = newStmtList()            
    for k,v in vm:
        types.add v
        if k.startsWith("vmodl."):
            vmodl.add v
        elif k.startsWith("vim."):
            vim.add v
        elif k.startsWith("pbm."):
            pbm.add v
        elif k.startsWith("sms."):
            sms.add v

    result.add newLetStmt(newIdentNode("vmodl"), newLit repr vmodl)
    result.add newLetStmt(newIdentNode("vim"), newLit repr vim)
    result.add newLetStmt(newIdentNode("pbm"), newLit repr pbm)
    result.add newLetStmt(newIdentNode("sms"), newLit repr sms)
    # result.add newLetStmt(newIdentNode("types", newLit repr types)


vmware()
writeFile("vmodl.nim",vmodl)
writeFile("vim.nim",vim)
writeFile("pbm.nim",pbm)
writeFile("sms.nim",sms)
# writeFile("vmodl.nim",types)

