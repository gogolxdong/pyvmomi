
type
  SelectionSpec* = ref object of DynamicData
    name*: string

type
  KeyAnyValue* = ref object of DynamicData
    key*: string
    value*: pointer

type
  MissingObject* = ref object of DynamicData
    obj*: ManagedObject
    fault*: MethodFault

type
  MethodFault* = ref object of DynamicData
    msg*: string
    faultCause*: MethodFault
    faultMessage*: seq[LocalizableMessage]

type
  ObjectSpec* = ref object of DynamicData
    obj*: ManagedObject
    skip*: bool
    selectSet*: seq[SelectionSpec]

type
  HostNotReachable* = ref object of HostCommunication
  
type
  MethodNotFound* = ref object of InvalidRequest
    receiver*: ManagedObject
    method*: string

type
  PropertySpec* = ref object of DynamicData
    type*: string
    all*: bool
    pathSet*: seq[string]

type
  InvalidArgument* = ref object of RuntimeFault
    invalidProperty*: string

type
  DynamicProperty* = ref object of DataObject
    name*: string
    val*: pointer

type
  ObjectUpdate* = ref object of DynamicData
    kind*: ObjectUpdateKind
    obj*: ManagedObject
    changeSet*: seq[PropertyChange]
    missingSet*: seq[MissingProperty]

type
  RetrieveResult* = ref object of DynamicData
    token*: string
    objects*: seq[ObjectContent]

type
  RetrieveOptions* = ref object of DynamicData
    maxObjects*: int

type
  DynamicData* = ref object of DataObject
    dynamicType*: string
    dynamicProperty*: seq[DynamicProperty]

type
  PropertyFilterUpdate* = ref object of DynamicData
    filter*: PropertyFilter
    objectSet*: seq[ObjectUpdate]
    missingSet*: seq[MissingObject]

type
  UpdateSet* = ref object of DynamicData
    version*: string
    filterSet*: seq[PropertyFilterUpdate]
    truncated*: bool

type
  NotEnoughLicenses* = ref object of RuntimeFault
  
type
  InvalidCollectorVersion* = ref object of MethodFault
  
type
  NotImplemented* = ref object of RuntimeFault
  
type
  HostCommunication* = ref object of RuntimeFault
  
type
  LocalizableMessage* = ref object of DynamicData
    key*: string
    arg*: seq[KeyAnyValue]
    message*: string

type
  HostNotConnected* = ref object of HostCommunication
  
type
  RuntimeFault* = ref object of MethodFault
  
type
  UnexpectedFault* = ref object of RuntimeFault
    faultName*: string
    fault*: MethodFault

type
  PropertyCollector* = ref object of vmodl.ManagedObject
    filter*: seq[PropertyFilter]

type
  PropertyChange* = ref object of DynamicData
    name*: string
    op*: PropertyChangeOp
    val*: pointer

type
  InvalidType* = ref object of InvalidRequest
    argument*: string

type
  PropertyChangeOp* {.pure.} = enum
    add, remove, assign, indirectRemove
type
  ObjectContent* = ref object of DynamicData
    obj*: ManagedObject
    propSet*: seq[DynamicProperty]
    missingSet*: seq[MissingProperty]

type
  ObjectUpdateKind* {.pure.} = enum
    modify, enter, leave
type
  PropertyFilter* = ref object of vmodl.ManagedObject
    spec*: PropertyFilterSpec
    partialUpdates*: bool

type
  MissingProperty* = ref object of DynamicData
    path*: string
    fault*: MethodFault

type
  RequestCanceled* = ref object of RuntimeFault
  
type
  SystemError* = ref object of RuntimeFault
    reason*: string

type
  InvalidProperty* = ref object of MethodFault
    name*: string

type
  InvalidRequest* = ref object of RuntimeFault
  
type
  SecurityError* = ref object of RuntimeFault
  
type
  WaitOptions* = ref object of DynamicData
    maxWaitSeconds*: int
    maxObjectUpdates*: int

type
  ManagedObjectNotFound* = ref object of RuntimeFault
    obj*: ManagedObject

type
  DynamicArray* = ref object of DataObject
    dynamicType*: string
    val*: seq[pointer]

type
  NotSupported* = ref object of RuntimeFault
  
type
  TraversalSpec* = ref object of SelectionSpec
    type*: string
    path*: string
    skip*: bool
    selectSet*: seq[SelectionSpec]

type
  PropertyFilterSpec* = ref object of DynamicData
    propSet*: seq[PropertySpec]
    objectSet*: seq[ObjectSpec]
    reportMissingObjectsInResults*: bool
