import re,strutils,strscans,macros,pegs,strformat,packedjson,sequtils,tables

# import vmodl
# let p = peg"""
# function_call <- \ident '(' parameters ')'
# parameters    <- (parens / string / [^)] )*
# parens        <- '(' parameters ')'
# string    <- dq_string / sq_string
# dq_string <- DQUOTE (BSLASH . / [^DQUOTE])* DQUOTE
# sq_string <- SQUOTE (BSLASH . / [^SQUOTE])* SQUOTE
# DQUOTE <- '"'
# SQUOTE <- "'"
# BSLASH <- "\\"
# """

let reg = re"(CreateEnumType\(|CreateDataType\(|CreateManagedType\()+.*"
proc write() = 
    const serverContent = staticRead("../pyVmomi/ServerObjects.py")
    var serverObjects = serverContent.findAll(reg)

    const pbmContent = staticRead("../pyVmomi/PbmObjects.py")
    var pbmObjects = pbmContent.findAll(reg)

    const queryContent = staticRead("../pyVmomi/QueryTypes.py")
    var queryTypes = queryContent.findAll(reg)

    const smsContent = staticRead("../pyVmomi/SmsObjects.py")
    var smsObjects = smsContent.findAll(reg)
    writeFile("ServerObjects",serverObjects.concat(pbmObjects).concat(queryTypes).concat(smsObjects).join("\L"))

write()


template CreateManagedType(typename,parent):untyped {.dirty.}= 
    type 
        typename* = ref object of parent

template CreateDataType(typename,parent):untyped {.dirty.}= 
    type 
        typename* = ref object of parent

template attachMangedType():untyped {.dirty} = 
    for wsdlName, _ in vm:
        if vmodl.contains(wsdlName & ".") :
            var field = substr(vmodl, wsdlName.len+1, vmodl.len-1)
            var fields = split(field,".")
            if fields.len == 0:
                vm[wsdlName][1].add  newIdentDefs(newNimNode(nnkPostfix).add(newIdentNode"*", newIdentNode field),newIdentNode n[2].strVal)
            elif fields.len > 0:
                for f in fields:
                    if vm[wsdlName].len == 2:
                        vm[wsdlName][1].add  newIdentDefs(newNimNode(nnkPostfix).add(newIdentNode"*", newIdentNode f),newIdentNode n[2].strVal)
                    else:
                        vm[wsdlName].add  newIdentDefs(newNimNode(nnkPostfix).add(newIdentNode"*", newIdentNode f),newIdentNode n[2].strVal)

macro vmware(): untyped = 
    result = newStmtList()
    const lines = staticRead("ServerObjects").splitLines
    var vm = newTable[string, NimNode]()
    for i in 0..lines.len-1:
        # echo i
        var node = parseStmt(lines[i])
        for n in node:
            var objFields = newNimNode(nnkRecList)
            if n[0].strVal == "CreateDataType":
                let (vmodl, wsdl, parent, version, props) = (n[1].strVal, n[2].strVal, n[3].strVal, n[4].strVal, n[5])
                vm[wsdl] = getAst(CreateDataType(newIdentNode wsdl, newIdentNode parent))
                attachMangedType()

            elif n[0].strVal == "CreateEnumType":
                let (vmodl,wsdl,version,value) = (n[1].strVal, n[2].strVal,n[3].strVal, n[4])
                func `@`(node: NimNode): seq[NimNode]  =
                    result = @[]
                    for n in node:
                        result.add(newIdentNode n.strVal)
                vm[wsdl] = newEnum(newIdentNode wsdl, @(value), true, true)
                attachMangedType()
            elif n[0].strVal == "CreateManagedType" :
                let (vmodl,wsdl,parent,version,props,methods) = (n[1].strVal, n[2].strVal, n[3].strVal, n[4].strVal, n[5], n[6])
                var parentIdent = newIdentNode parent.split(".")[1]
                var recList = newNimNode(nnkRecList)
                for p in props:
                    var propName = p[0].strVal
                    var typeName = p[1].strVal.split(".")[^1]
                    if typeName.endsWith("[]"):
                        typeName = fmt"seq[{typeName[0..^3]}]"
                    if typeName == "boolean":
                        typeName = "bool"
                    recList.add newIdentDefs(newNimNode(nnkPostfix).add(newIdentNode"*", newIdentNode propName), newIdentNode typeName)
                vm[wsdl] = getAst(CreateManagedType(newIdentNode wsdl, parentIdent)).add(recList)

    var vmodl,vim,pbm,sms = newStmtList()            
    for k,v in vm:
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


vmware()
writeFile("vmodl.nim",vmodl)
writeFile("vim.nim",vim)
writeFile("pbm.nim",pbm)
writeFile("sms.nim",sms)
