
type
  ObjectUpdateKind* {.pure.} = enum
    modify, enter, leave
type
  PropertyChangeOp* {.pure.} = enum
    add, remove, assign, indirectRemove
type
    SelectionSpec = object of DynamicData
    KeyAnyValue = object of DynamicData
    MissingObject = object of DynamicData
    MethodFault = object of DynamicData
    ObjectSpec = object of DynamicData
    HostNotReachable = object of HostCommunication
    MethodNotFound = object of InvalidRequest
    PropertySpec = object of DynamicData
    InvalidArgument = object of RuntimeFault
    DynamicProperty = object of DataObject
    ObjectUpdate = object of DynamicData
    RetrieveResult = object of DynamicData
    RetrieveOptions = object of DynamicData
    DynamicData = object of DataObject
    PropertyFilterUpdate = object of DynamicData
    UpdateSet = object of DynamicData
    NotEnoughLicenses = object of RuntimeFault
    InvalidCollectorVersion = object of MethodFault
    NotImplemented = object of RuntimeFault
    HostCommunication = object of RuntimeFault
    LocalizableMessage = object of DynamicData
    HostNotConnected = object of HostCommunication
    RuntimeFault = object of MethodFault
    UnexpectedFault = object of RuntimeFault
    PropertyChange = object of DynamicData
    InvalidType = object of InvalidRequest
    ObjectContent = object of DynamicData
    MissingProperty = object of DynamicData
    RequestCanceled = object of RuntimeFault
    SystemError = object of RuntimeFault
    InvalidProperty = object of MethodFault
    InvalidRequest = object of RuntimeFault
    SecurityError = object of RuntimeFault
    WaitOptions = object of DynamicData
    ManagedObjectNotFound = object of RuntimeFault
    DynamicArray = object of DataObject
    NotSupported = object of RuntimeFault
    TraversalSpec = object of SelectionSpec
    PropertyFilterSpec = object of DynamicData
type
    PropertyFilter = object of ManagedObject
      spec*: PropertyFilterSpec
      partialUpdates*: bool

    PropertyCollector = object of ManagedObject
      filter*: seq[PropertyFilter]
