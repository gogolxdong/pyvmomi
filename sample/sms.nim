
type
  NoCommonProviderForAllBackings* = ref object of QueryExecutionFault
  
type
  SmsSessionManager* = ref object of vmodl.ManagedObject
  
type
  SupportedVendorModelMapping* = ref object of DynamicData
    vendorId*: string
    modelId*: string

type
  StoragePort* = ref object of DynamicData
    uuid*: string
    type*: string
    alternateName*: seq[string]

type
  ProviderOutOfResource* = ref object of MethodFault
  
type
  StorageFileSystem* = ref object of DynamicData
    uuid*: string
    info*: seq[StorageFileSystemInfo]
    nativeSnapshotSupported*: bool
    thinProvisioningStatus*: string
    type*: string
    version*: string
    backingConfig*: BackingConfig

type
  SmsEntityType* {.pure.} = enum
    StorageArrayEntity, StorageProcessorEntity, StoragePortEntity,
    StorageLunEntity, StorageFileSystemEntity, StorageCapabilityEntity,
    CapabilitySchemaEntity, CapabilityProfileEntity, DefaultProfileEntity,
    ResourceAssociationEntity, StorageContainerEntity, StorageObjectEntity,
    MessageCatalogEntity, ProtocolEndpointEntity, VirtualVolumeInfoEntity,
    BackingStoragePoolEntity, FaultDomainEntity, ReplicationGroupEntity
type
  AlarmResult* = ref object of DynamicData
    storageAlarm*: seq[StorageAlarm]
    pageMarker*: string

type
  ProviderRegistrationFault* = ref object of MethodFault
  
type
  SmsResourceInUse* = ref object of ResourceInUse
    deviceIds*: seq[DeviceId]

type
  QueryReplicationGroupSuccessResult* = ref object of GroupOperationResult
    rgInfo*: GroupInfo

type
  VasaProviderInfo* = ref object of SmsProviderInfo
    url*: string
    certificate*: string
    status*: string
    statusFault*: MethodFault
    vasaVersion*: string
    namespace*: string
    lastSyncTime*: string
    supportedVendorModelMapping*: seq[SupportedVendorModelMapping]
    supportedProfile*: seq[string]
    supportedProviderProfile*: seq[string]
    relatedStorageArray*: seq[RelatedStorageArray]
    providerId*: string
    certificateExpiryDate*: string
    certificateStatus*: string
    serviceLocation*: string
    needsExplicitActivation*: bool
    maxBatchSize*: int64
    retainVasaProviderCertificate*: bool
    arrayIndependentProvider*: bool
    type*: string
    category*: string
    priority*: int
    failoverGroupId*: string

type
  VirtualDiskMoId* = ref object of DeviceId
    vcUuid*: string
    vmMoid*: string
    diskKey*: string

type
  TargetDeviceId* = ref object of DynamicData
    domainId*: FaultDomainId
    deviceId*: ReplicaId

type
  ThinProvisioningStatus* {.pure.} = enum
    RED, YELLOW, GREEN
type
  ReplicaId* = ref object of DynamicData
    id*: string

type
  ProxyRegistrationFailed* = ref object of RuntimeFault
  
type
  LunHbaAssociation* = ref object of DynamicData
    canonicalName*: string
    hba*: seq[HostHostBusAdapter]

type
  FcoeStoragePort* = ref object of StoragePort
    portWwn*: string
    nodeWwn*: string

type
  InvalidProfile* = ref object of MethodFault
  
type
  ProviderOutOfProvisioningResource* = ref object of MethodFault
    provisioningResourceId*: string
    availableBefore*: int64
    availableAfter*: int64
    total*: int64
    isTransient*: bool

type
  DeviceId* = ref object of DynamicData
  
type
  SmsTaskState* {.pure.} = enum
    queued, running, success, error
type
  ProviderSyncFailed* = ref object of MethodFault
  
type
  PeerNotReachable* = ref object of SmsReplicationFault
  
type
  ProviderBusy* = ref object of MethodFault
  
type
  NameValuePair* = ref object of DynamicData
    parameterName*: string
    parameterValue*: string

type
  DrsMigrationCapabilityResult* = ref object of DynamicData
    recommendedDatastorePair*: seq[DatastorePair]
    nonRecommendedDatastorePair*: seq[DatastorePair]

type
  InvalidFunctionTarget* = ref object of SmsReplicationFault
  
type
  SyncReplicationGroupSuccessResult* = ref object of GroupOperationResult
    timeStamp*: string
    pitId*: PointInTimeReplicaId
    pitName*: string

type
  InvalidSession* = ref object of NoPermission
    sessionCookie*: string

type
  EntityReferenceEntityType* {.pure.} = enum
    datacenter, resourcePool, storagePod, cluster, vm, datastore, host, vmFile,
    scsiPath, scsiTarget, scsiVolume, scsiAdapter, nasMount
type
  VasaProviderSpec* = ref object of SmsProviderSpec
    username*: string
    password*: string
    url*: string
    certificate*: string

type
  VirtualMachineMoId* = ref object of VirtualMachineId
    vcUuid*: string
    vmMoid*: string

type
  ResyncSpec* = ref object of DynamicData
  
type
  FcStoragePort* = ref object of StoragePort
    portWwn*: string
    nodeWwn*: string

type
  VasaProviderProfile* {.pure.} = enum
    blockDevice, fileSystem, capability
type
  StorageArray* = ref object of DynamicData
    name*: string
    uuid*: string
    vendorId*: string
    modelId*: string
    firmware*: string
    alternateName*: seq[string]
    supportedBlockInterface*: seq[string]
    supportedFileSystemInterface*: seq[string]
    supportedProfile*: seq[string]
    priority*: int

type
  SmsAlarmStatus* {.pure.} = enum
    Red, Green, Yellow
type
  NoReplicationTarget* = ref object of SmsReplicationFault
  
type
  PolicyAssociation* = ref object of DynamicData
    id*: DeviceId
    policyId*: string
    datastore*: Datastore

type
  ReplicationReplicationState* {.pure.} = enum
    SOURCE, TARGET, FAILEDOVER, INTEST, REMOTE_FAILEDOVER
type
  VirtualMachineId* = ref object of DeviceId
  
type
  VirtualDiskKey* = ref object of DeviceId
    vmInstanceUUID*: string
    deviceKey*: int

type
  BackingConfig* = ref object of DynamicData
    thinProvisionBackingIdentifier*: string
    deduplicationBackingIdentifier*: string
    autoTieringEnabled*: bool
    deduplicationEfficiency*: int64
    performanceOptimizationInterval*: int64

type
  QueryPointInTimeReplicaSummaryResult* = ref object of GroupOperationResult
    intervalResults*: seq[ReplicaIntervalQueryResult]

type
  FaultDomainInfo* = ref object of FaultDomainId
    name*: string
    description*: string
    storageArrayId*: string
    children*: seq[FaultDomainId]
    provider*: SmsProvider

type
  InvalidCertificate* = ref object of ProviderRegistrationFault
    certificate*: string

type
  StorageAlarm* = ref object of DynamicData
    alarmId*: int64
    alarmType*: string
    containerId*: string
    objectId*: string
    objectType*: string
    status*: string
    alarmTimeStamp*: string
    messageId*: string
    parameterList*: seq[NameValuePair]
    alarmObject*: pointer

type
  SourceGroupInfo* = ref object of GroupInfo
    name*: string
    description*: string
    state*: string
    replica*: seq[ReplicationTargetInfo]
    memberInfo*: seq[SourceGroupMemberInfo]

type
  SmsTaskInfo* = ref object of DynamicData
    key*: string
    task*: SmsTask
    object*: ManagedObject
    error*: MethodFault
    result*: pointer
    startTime*: string
    completionTime*: string
    state*: string
    progress*: int

type
  SmsProvider* = ref object of vmodl.ManagedObject
  
type
  SmsProviderSpec* = ref object of DynamicData
    name*: string
    description*: string

type
  SmsReplicationFault* = ref object of MethodFault
  
type
  StorageContainer* = ref object of DynamicData
    uuid*: string
    name*: string
    maxVvolSizeInMB*: int64
    providerId*: seq[string]
    arrayId*: seq[string]

type
  InvalidReplicationState* = ref object of SmsReplicationFault
    desiredState*: seq[string]
    currentState*: string

type
  ProviderUnregistrationFault* = ref object of MethodFault
  
type
  VirtualMachineFilePath* = ref object of VirtualMachineId
    vcUuid*: string
    dsUrl*: string
    vmxPath*: string

type
  NoValidReplica* = ref object of SmsReplicationFault
    deviceId*: DeviceId

type
  FaultDomainFilter* = ref object of DynamicData
    providerId*: string

type
  ReverseReplicationSuccessResult* = ref object of GroupOperationResult
    newGroupId*: DeviceGroupId

type
  SyncOngoing* = ref object of SmsReplicationFault
    task*: SmsTask

type
  VasaProvider* = ref object of sms.provider.Provider
  
type
  VVolId* = ref object of DeviceId
    id*: string

type
  DatastoreBackingPoolMapping* = ref object of DynamicData
    datastore*: seq[Datastore]
    backingStoragePool*: seq[BackingStoragePool]

type
  VasaVirtualDiskId* = ref object of DeviceId
    diskId*: string

type
  DatastorePair* = ref object of DynamicData
    datastore1*: Datastore
    datastore2*: Datastore

type
  VpCategory* {.pure.} = enum
    internal, external
type
  ServiceNotInitialized* = ref object of RuntimeFault
  
type
  QueryNotSupported* = ref object of InvalidArgument
    entityType*: EntityReferenceEntityType
    relatedEntityType*: EntityReferenceEntityType

type
  ReplicationTargetInfo* = ref object of DynamicData
    targetGroupId*: ReplicationGroupId
    replicationAgreementDescription*: string

type
  IscsiStoragePort* = ref object of StoragePort
    identifier*: string

type
  QueryExecutionFault* = ref object of MethodFault
  
type
  VpType* {.pure.} = enum
    PERSISTENCE, DATASERVICE, UNKNOWN
type
  BatchErrorResult* = ref object of DynamicData
    error*: seq[MethodFault]

type
  AlarmFilter* = ref object of DynamicData
    alarmStatus*: string
    alarmType*: string
    entityType*: string
    entityId*: seq[pointer]
    pageMarker*: string

type
  QueryPointInTimeReplicaParam* = ref object of DynamicData
    replicaTimeQueryParam*: ReplicaQueryIntervalParam
    pitName*: string
    tags*: seq[string]

type
  FailoverParam* = ref object of DynamicData
    isPlanned*: bool
    checkOnly*: bool
    replicationGroupsToFailover*: seq[ReplicationGroupData]
    policyAssociations*: seq[PolicyAssociation]

type
  FileSystemInterfaceVersion* {.pure.} = enum
    NFSV3_0
type
  VvolRebindFault* = ref object of MethodFault
  
type
  AlreadyDone* = ref object of SmsReplicationFault
  
type
  StorageFileSystemInfo* = ref object of DynamicData
    fileServerName*: string
    fileSystemPath*: string
    ipAddress*: string

type
  RelatedStorageArray* = ref object of DynamicData
    arrayId*: string
    active*: bool
    manageable*: bool
    priority*: int

type
  PromoteParam* = ref object of DynamicData
    isPlanned*: bool
    replicationGroupsToPromote*: seq[ReplicationGroupId]

type
  RecoveredDiskInfo* = ref object of DynamicData
    deviceKey*: int
    dsUrl*: string
    diskPath*: string

type
  BatchReturnStatus* = ref object of DynamicData
    uniqueId*: string
    returnStatus*: BatchErrorResult

type
  DrsMigrationCapabilityResultEx* = ref object of DynamicData
    nonRecommendedDatastoreSet*: seq[DatastoreSet]

type
  PointInTimeReplicaInfo* = ref object of DynamicData
    id*: PointInTimeReplicaId
    pitName*: string
    timeStamp*: string
    tags*: seq[string]

type
  TooMany* = ref object of MethodFault
    maxBatchSize*: int64

type
  RecoveredTargetGroupMemberInfo* = ref object of TargetGroupMemberInfo
    recoveredDeviceId*: DeviceId

type
  ProviderConnectionFailed* = ref object of RuntimeFault
  
type
  SmsStorageManager* = ref object of vmodl.ManagedObject
  
type
  ProviderProfile* {.pure.} = enum
    ProfileBasedManagement, Replication
type
  CertificateAuthorityFault* = ref object of ProviderRegistrationFault
    faultCode*: int

type
  GroupInfo* = ref object of DynamicData
    groupId*: ReplicationGroupId

type
  ReplicaIntervalQueryResult* = ref object of DynamicData
    fromDate*: string
    toDate*: string
    number*: int

type
  GroupOperationResult* = ref object of DynamicData
    groupId*: ReplicationGroupId
    warning*: seq[MethodFault]

type
  ReplicaQueryIntervalParam* = ref object of DynamicData
    fromDate*: string
    toDate*: string
    number*: int

type
  VirtualMachineUUID* = ref object of VirtualMachineId
    vmInstanceUUID*: string

type
  SmsFault* = ref object of MethodFault
  
type
  DatastoreSet* = ref object of DynamicData
    datastore*: seq[Datastore]

type
  BackingStoragePool* = ref object of DynamicData
    uuid*: string
    type*: string
    capacityInMB*: int64
    usedSpaceInMB*: int64

type
  ReplicationGroupData* = ref object of DynamicData
    groupId*: ReplicationGroupId
    pitId*: PointInTimeReplicaId

type
  FailoverSuccessResult* = ref object of GroupOperationResult
    newState*: string
    pitId*: PointInTimeReplicaId
    pitIdBeforeFailover*: PointInTimeReplicaId
    recoveredDeviceInfo*: seq[RecoveredDevice]
    timeStamp*: string

type
  SmsAboutInfo* = ref object of DynamicData
    name*: string
    fullName*: string
    vendor*: string
    apiVersion*: string
    instanceUuid*: string
    vasaApiVersion*: string

type
  SmsInvalidLogin* = ref object of MethodFault
  
type
  SmsServiceInstance* = ref object of vmodl.ManagedObject
  
type
  TargetToSourceInfo* = ref object of DynamicData
    sourceGroupId*: ReplicationGroupId
    replicationAgreementDescription*: string

type
  BackingStoragePoolType* {.pure.} = enum
    thinProvisioningPool, deduplicationPool, thinAndDeduplicationCombinedPool
type
  CertificateRefreshFailed* = ref object of MethodFault
    providerId*: seq[string]

type
  TestFailoverParam* = ref object of FailoverParam
  
type
  MultipleSortSpecsNotSupported* = ref object of InvalidArgument
  
type
  VasaProfile* {.pure.} = enum
    blockDevice, fileSystem, capability, policy, object, statistics,
    storageDrsBlockDevice, storageDrsFileSystem
type
  VasaProviderCertificateStatus* {.pure.} = enum
    valid, expirySoftLimitReached, expiryHardLimitReached, expired, invalid
type
  VsanProvidersResyncFailed* = ref object of MethodFault
    providerUrl*: seq[string]

type
  NotSupportedByProvider* = ref object of MethodFault
  
type
  InactiveProvider* = ref object of MethodFault
    mapping*: seq[FaultDomainProviderMapping]

type
  AlarmType* {.pure.} = enum
    SpaceCapacityAlarm, CapabilityAlarm, StorageObjectAlarm, ObjectAlarm,
    ComplianceAlarm, ManageabilityAlarm, ReplicationAlarm
type
  AuthConnectionFailed* = ref object of NoPermission
  
type
  CertificateNotTrusted* = ref object of ProviderRegistrationFault
    certificate*: string

type
  VasaProviderStatus* {.pure.} = enum
    online, offline, syncError, unknown, connected, disconnected
type
  StorageLun* = ref object of DynamicData
    uuid*: string
    vSphereLunIdentifier*: string
    vendorDisplayName*: string
    capacityInMB*: int64
    usedSpaceInMB*: int64
    lunThinProvisioned*: bool
    alternateIdentifier*: seq[string]
    drsManagementPermitted*: bool
    thinProvisioningStatus*: string
    backingConfig*: BackingConfig

type
  StorageCapability* = ref object of DynamicData
    uuid*: string
    name*: string
    description*: string

type
  RecoveredDevice* = ref object of DynamicData
    targetDeviceId*: ReplicaId
    recoveredDeviceId*: DeviceId
    sourceDeviceId*: DeviceId
    info*: seq[string]
    datastore*: Datastore
    recoveredDiskInfo*: seq[RecoveredDiskInfo]
    error*: MethodFault
    warnings*: seq[MethodFault]

type
  CertificateRevocationFailed* = ref object of MethodFault
  
type
  StorageProcessor* = ref object of DynamicData
    uuid*: string
    alternateIdentifer*: seq[string]

type
  FileSystemInterface* {.pure.} = enum
    nfs, otherFileSystem
type
  VasaAuthenticationType* {.pure.} = enum
    LoginByToken, UseSessionId
type
  ReplicationGroupFilter* = ref object of DynamicData
    groupId*: seq[ReplicationGroupId]

type
  FaultDomainProviderMapping* = ref object of DynamicData
    activeProvider*: SmsProvider
    faultDomainId*: seq[FaultDomainId]

type
  StorageContainerSpec* = ref object of DynamicData
    containerId*: seq[string]

type
  SourceGroupMemberInfo* = ref object of DynamicData
    deviceId*: DeviceId
    targetId*: seq[TargetDeviceId]

type
  ProviderNotFound* = ref object of QueryExecutionFault
  
type
  TargetGroupInfo* = ref object of GroupInfo
    sourceInfo*: TargetToSourceInfo
    state*: string
    devices*: seq[TargetGroupMemberInfo]
    isPromoteCapable*: bool

type
  SmsProviderInfo* = ref object of DynamicData
    uid*: string
    name*: string
    description*: string
    version*: string

type
  GroupErrorResult* = ref object of GroupOperationResult
    error*: seq[MethodFault]

type
  ProviderUnavailable* = ref object of MethodFault
  
type
  InvalidUrl* = ref object of ProviderRegistrationFault
    url*: string

type
  QueryReplicationPeerResult* = ref object of DynamicData
    sourceDomain*: FaultDomainId
    targetDomain*: seq[FaultDomainId]
    error*: seq[MethodFault]
    warning*: seq[MethodFault]

type
  QueryPointInTimeReplicaSuccessResult* = ref object of GroupOperationResult
    replicaInfo*: seq[PointInTimeReplicaInfo]

type
  PointInTimeReplicaId* = ref object of DynamicData
    id*: string

type
  BlockDeviceInterface* {.pure.} = enum
    fc, iscsi, fcoe, otherBlock
type
  VmodlVasaProviderSpec* = ref object of SmsProviderSpec
    url*: string
    authenticationType*: string

type
  TargetGroupMemberInfo* = ref object of DynamicData
    replicaId*: ReplicaId
    sourceId*: DeviceId
    targetDatastore*: Datastore

type
  VmscProfileNotSupported* = ref object of VvolRebindFault
  
type
  VvolRebindSpec* = ref object of DynamicData
    storageContainerId*: string
    vvolId*: seq[string]

type
  IncorrectUsernamePassword* = ref object of ProviderRegistrationFault
  
type
  StorageContainerResult* = ref object of DynamicData
    storageContainer*: seq[StorageContainer]
    providerInfo*: seq[SmsProviderInfo]

type
  SmsTask* = ref object of vmodl.ManagedObject
  
type
  DuplicateEntry* = ref object of MethodFault
  
type
  EntityReference* = ref object of DynamicData
    id*: string
    type*: EntityReferenceEntityType

type
  CertificateNotImported* = ref object of ProviderRegistrationFault
  
type
  SyncInProgress* = ref object of ProviderSyncFailed
  