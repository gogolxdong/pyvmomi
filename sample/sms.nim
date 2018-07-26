
type
  AlarmType* {.pure.} = enum
    SpaceCapacityAlarm, CapabilityAlarm, StorageObjectAlarm, ObjectAlarm,
    ComplianceAlarm, ManageabilityAlarm, ReplicationAlarm
type
  VpType* {.pure.} = enum
    PERSISTENCE, DATASERVICE, UNKNOWN
type
  VasaProviderStatus* {.pure.} = enum
    online, offline, syncError, unknown, connected, disconnected
type
  FileSystemInterfaceVersion* {.pure.} = enum
    NFSV3_0
type
  SmsEntityType* {.pure.} = enum
    StorageArrayEntity, StorageProcessorEntity, StoragePortEntity,
    StorageLunEntity, StorageFileSystemEntity, StorageCapabilityEntity,
    CapabilitySchemaEntity, CapabilityProfileEntity, DefaultProfileEntity,
    ResourceAssociationEntity, StorageContainerEntity, StorageObjectEntity,
    MessageCatalogEntity, ProtocolEndpointEntity, VirtualVolumeInfoEntity,
    BackingStoragePoolEntity, FaultDomainEntity, ReplicationGroupEntity
type
  EntityReferenceEntityType* {.pure.} = enum
    datacenter, resourcePool, storagePod, cluster, vm, datastore, host, vmFile,
    scsiPath, scsiTarget, scsiVolume, scsiAdapter, nasMount
type
  FileSystemInterface* {.pure.} = enum
    nfs, otherFileSystem
type
  ThinProvisioningStatus* {.pure.} = enum
    RED, YELLOW, GREEN
type
  BlockDeviceInterface* {.pure.} = enum
    fc, iscsi, fcoe, otherBlock
type
  VasaAuthenticationType* {.pure.} = enum
    LoginByToken, UseSessionId
type
  SmsTaskState* {.pure.} = enum
    queued, running, success, error
type
  VpCategory* {.pure.} = enum
    internal, external
type
  VasaProviderProfile* {.pure.} = enum
    blockDevice, fileSystem, capability
type
  BackingStoragePoolType* {.pure.} = enum
    thinProvisioningPool, deduplicationPool, thinAndDeduplicationCombinedPool
type
  SmsAlarmStatus* {.pure.} = enum
    Red, Green, Yellow
type
  ProviderProfile* {.pure.} = enum
    ProfileBasedManagement, Replication
type
  ReplicationReplicationState* {.pure.} = enum
    SOURCE, TARGET, FAILEDOVER, INTEST, REMOTE_FAILEDOVER
type
  VasaProfile* {.pure.} = enum
    blockDevice, fileSystem, capability, policy, object, statistics,
    storageDrsBlockDevice, storageDrsFileSystem
type
  VasaProviderCertificateStatus* {.pure.} = enum
    valid, expirySoftLimitReached, expiryHardLimitReached, expired, invalid
type
    NoCommonProviderForAllBackings = object of QueryExecutionFault
    SupportedVendorModelMapping = object of DynamicData
    StoragePort = object of DynamicData
    ProviderOutOfResource = object of MethodFault
    StorageFileSystem = object of DynamicData
    AlarmResult = object of DynamicData
    ProviderRegistrationFault = object of MethodFault
    SmsResourceInUse = object of ResourceInUse
    QueryReplicationGroupSuccessResult = object of GroupOperationResult
    VasaProviderInfo = object of SmsProviderInfo
    VirtualDiskMoId = object of DeviceId
    TargetDeviceId = object of DynamicData
    ReplicaId = object of DynamicData
    ProxyRegistrationFailed = object of RuntimeFault
    LunHbaAssociation = object of DynamicData
    FcoeStoragePort = object of StoragePort
    InvalidProfile = object of MethodFault
    ProviderOutOfProvisioningResource = object of MethodFault
    DeviceId = object of DynamicData
    ProviderSyncFailed = object of MethodFault
    PeerNotReachable = object of SmsReplicationFault
    ProviderBusy = object of MethodFault
    NameValuePair = object of DynamicData
    DrsMigrationCapabilityResult = object of DynamicData
    InvalidFunctionTarget = object of SmsReplicationFault
    SyncReplicationGroupSuccessResult = object of GroupOperationResult
    InvalidSession = object of NoPermission
    VasaProviderSpec = object of SmsProviderSpec
    VirtualMachineMoId = object of VirtualMachineId
    ResyncSpec = object of DynamicData
    FcStoragePort = object of StoragePort
    StorageArray = object of DynamicData
    NoReplicationTarget = object of SmsReplicationFault
    PolicyAssociation = object of DynamicData
    VirtualMachineId = object of DeviceId
    VirtualDiskKey = object of DeviceId
    BackingConfig = object of DynamicData
    QueryPointInTimeReplicaSummaryResult = object of GroupOperationResult
    FaultDomainInfo = object of FaultDomainId
    InvalidCertificate = object of ProviderRegistrationFault
    StorageAlarm = object of DynamicData
    SourceGroupInfo = object of GroupInfo
    SmsTaskInfo = object of DynamicData
    SmsProviderSpec = object of DynamicData
    SmsReplicationFault = object of MethodFault
    StorageContainer = object of DynamicData
    InvalidReplicationState = object of SmsReplicationFault
    ProviderUnregistrationFault = object of MethodFault
    VirtualMachineFilePath = object of VirtualMachineId
    NoValidReplica = object of SmsReplicationFault
    FaultDomainFilter = object of DynamicData
    ReverseReplicationSuccessResult = object of GroupOperationResult
    SyncOngoing = object of SmsReplicationFault
    VVolId = object of DeviceId
    DatastoreBackingPoolMapping = object of DynamicData
    VasaVirtualDiskId = object of DeviceId
    DatastorePair = object of DynamicData
    ServiceNotInitialized = object of RuntimeFault
    QueryNotSupported = object of InvalidArgument
    ReplicationTargetInfo = object of DynamicData
    IscsiStoragePort = object of StoragePort
    QueryExecutionFault = object of MethodFault
    BatchErrorResult = object of DynamicData
    AlarmFilter = object of DynamicData
    QueryPointInTimeReplicaParam = object of DynamicData
    FailoverParam = object of DynamicData
    VvolRebindFault = object of MethodFault
    AlreadyDone = object of SmsReplicationFault
    StorageFileSystemInfo = object of DynamicData
    RelatedStorageArray = object of DynamicData
    PromoteParam = object of DynamicData
    RecoveredDiskInfo = object of DynamicData
    BatchReturnStatus = object of DynamicData
    DrsMigrationCapabilityResultEx = object of DynamicData
    PointInTimeReplicaInfo = object of DynamicData
    TooMany = object of MethodFault
    RecoveredTargetGroupMemberInfo = object of TargetGroupMemberInfo
    ProviderConnectionFailed = object of RuntimeFault
    CertificateAuthorityFault = object of ProviderRegistrationFault
    GroupInfo = object of DynamicData
    ReplicaIntervalQueryResult = object of DynamicData
    GroupOperationResult = object of DynamicData
    ReplicaQueryIntervalParam = object of DynamicData
    VirtualMachineUUID = object of VirtualMachineId
    SmsFault = object of MethodFault
    DatastoreSet = object of DynamicData
    BackingStoragePool = object of DynamicData
    ReplicationGroupData = object of DynamicData
    FailoverSuccessResult = object of GroupOperationResult
    SmsAboutInfo = object of DynamicData
    SmsInvalidLogin = object of MethodFault
    TargetToSourceInfo = object of DynamicData
    CertificateRefreshFailed = object of MethodFault
    TestFailoverParam = object of FailoverParam
    MultipleSortSpecsNotSupported = object of InvalidArgument
    VsanProvidersResyncFailed = object of MethodFault
    NotSupportedByProvider = object of MethodFault
    InactiveProvider = object of MethodFault
    AuthConnectionFailed = object of NoPermission
    CertificateNotTrusted = object of ProviderRegistrationFault
    StorageLun = object of DynamicData
    StorageCapability = object of DynamicData
    RecoveredDevice = object of DynamicData
    CertificateRevocationFailed = object of MethodFault
    StorageProcessor = object of DynamicData
    ReplicationGroupFilter = object of DynamicData
    FaultDomainProviderMapping = object of DynamicData
    StorageContainerSpec = object of DynamicData
    SourceGroupMemberInfo = object of DynamicData
    ProviderNotFound = object of QueryExecutionFault
    TargetGroupInfo = object of GroupInfo
    SmsProviderInfo = object of DynamicData
    GroupErrorResult = object of GroupOperationResult
    ProviderUnavailable = object of MethodFault
    InvalidUrl = object of ProviderRegistrationFault
    QueryReplicationPeerResult = object of DynamicData
    QueryPointInTimeReplicaSuccessResult = object of GroupOperationResult
    PointInTimeReplicaId = object of DynamicData
    VmodlVasaProviderSpec = object of SmsProviderSpec
    TargetGroupMemberInfo = object of DynamicData
    VmscProfileNotSupported = object of VvolRebindFault
    VvolRebindSpec = object of DynamicData
    IncorrectUsernamePassword = object of ProviderRegistrationFault
    StorageContainerResult = object of DynamicData
    DuplicateEntry = object of MethodFault
    EntityReference = object of DynamicData
    CertificateNotImported = object of ProviderRegistrationFault
    SyncInProgress = object of ProviderSyncFailed
type
    VasaProvider = object of SmsProvider
    
    SmsSessionManager = object of ManagedObject
    
    SmsServiceInstance = object of ManagedObject
    
    SmsStorageManager = object of ManagedObject
    
    SmsTask = object of ManagedObject
    
    SmsProvider = object of ManagedObject
    