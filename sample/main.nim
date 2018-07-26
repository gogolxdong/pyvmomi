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
    var dataVmodl,enumVmodl,objectVmodl = newTable[string, NimNode]()
    var vmodlParent = newTable[string, string]()

    var propMap = newTable[string,NimNode]()
    var methodMap = newTable[string,NimNode]()
    for i in 0..lines.len-1:
        # echo i
        var node = parseStmt(lines[i])
        for n in node:
            if n[0].strVal == "CreateDataType":
                let (vmodl, wsdl, parent, version, props) = (n[1].strVal, n[2].strVal, n[3].strVal, n[4].strVal, n[5])
                vmodlTypes[vmodl] = wsdl
                propMap[vmodl] = props
                vmodlParent[vmodl] = parent
                dataVmodl[vmodl] = newTree(nnkTypeDef,newIdentNode(wsdl),newEmptyNode())
                
                # vm[vmodl] = getAst(CreateDataType(newIdentNode wsdl, newNilLit))

            elif n[0].strVal == "CreateEnumType":
                let (vmodl,wsdl,version,value) = (n[1].strVal, n[2].strVal,n[3].strVal, n[4])
                vmodlTypes[vmodl] = wsdl

                func `@`(node: NimNode): seq[NimNode]  =
                    result = @[]
                    for n in node:
                        result.add(newIdentNode n.strVal)
                enumVmodl[vmodl] = newEnum(newIdentNode wsdl, @(value), true, true)
        
            elif n[0].strVal == "CreateManagedType" :
                let (vmodl,wsdl,parent,version,props,methods) = (n[1].strVal, n[2].strVal, n[3].strVal, n[4].strVal, n[5], n[6])
                vmodlTypes[vmodl] = wsdl
                propMap[vmodl] = props
                methodMap[vmodl] = methods
                vmodlParent[vmodl] = parent
                objectVmodl[vmodl] = newTree(nnkTypeDef,newIdentNode(wsdl),newEmptyNode()) 
                # vm[vmodl] = getAst(CreateManagedType(newIdentNode wsdl, newEmptyNode()))
    for vmodl, ast in objectVmodl.mpairs:
        if vmodlParent.hasKey vmodl:
            ast.add newTree(nnkObjectTy, newEmptyNode(),newTree(nnkOfInherit,newIdentNode(vmodlTypes[vmodlParent[vmodl]])))

    for vmodl, ast in dataVmodl.mpairs:
        if vmodlParent.hasKey vmodl:
            ast.add newTree(nnkObjectTy, newEmptyNode(),newTree(nnkOfInherit,newIdentNode(vmodlTypes[vmodlParent[vmodl]])))

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
            recList.add newIdentDefs(newNimNode(nnkPostfix).add(newIdentNode"*", newIdentNode propName), newIdentNode typeName)
        if objectVmodl.hasKey vmodl:
            # echo objectVmodl[vmodl].len
            objectVmodl[vmodl][2].add recList

    var enumVmodls,enumVim,enumPbm,enumSms = newStmtList()     
    var dataVmodls,dataVim,dataPbm,dataSms = newStmtList()     
    var objectVmodls,objectVim,objectPbm,objectSms = newStmtList()    

    for vmodl,ast in enumVmodl:
        if vmodl.startsWith("vmodl."):
            enumVmodls.add ast
        elif vmodl.startsWith("vim."):
            enumVim.add  ast
        elif vmodl.startsWith("pbm."):
            enumPbm.add  ast
        elif vmodl.startsWith("sms."):
            enumSms.add  ast

    for vmodl,ast in dataVmodl:
        if vmodl.startsWith("vmodl."):
            dataVmodls.add ast
        elif vmodl.startsWith("vim."):
            dataVim.add  ast
        elif vmodl.startsWith("pbm."):
            dataPbm.add  ast
        elif vmodl.startsWith("sms."):
            dataSms.add  ast

    for vmodl,ast in objectVmodl:
        if vmodl.startsWith("vmodl."):
            objectVmodls.add ast
        elif vmodl.startsWith("vim."):
            objectVim.add  ast
        elif vmodl.startsWith("pbm."):
            objectPbm.add  ast
        elif vmodl.startsWith("sms."):
            objectSms.add  ast
    # echo repr objectVim
    result.add newLetStmt(newIdentNode("vmodl"), newLit repr add(enumVmodls,newNimNode(nnkTypeSection).add dataVmodls).add(newNimNode(nnkTypeSection).add objectVmodls))
    result.add newLetStmt(newIdentNode("vim"), newLit repr add(enumVim,newNimNode(nnkTypeSection).add dataVim).add(newNimNode(nnkTypeSection).add objectVim))
    result.add newLetStmt(newIdentNode("pbm"), newLit repr add(enumPbm,newNimNode(nnkTypeSection).add dataPbm).add(newNimNode(nnkTypeSection).add objectPbm))
    result.add newLetStmt(newIdentNode("sms"), newLit repr add(enumSms,newNimNode(nnkTypeSection).add dataSms).add(newNimNode(nnkTypeSection).add objectSms))


vmware()
writeFile("vmodl.nim",vmodl)
writeFile("vim.nim",vim)
writeFile("pbm.nim",pbm)
writeFile("sms.nim",sms)

