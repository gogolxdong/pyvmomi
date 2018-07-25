
type
  GuestRegValueQwordSpec* = ref object of GuestRegValueDataSpec
    value*: int64

type
  ProfileReferenceHostChangedEvent* = ref object of ProfileEvent
    referenceHost*: HostSystem
    referenceHostName*: string
    prevReferenceHostName*: string

type
  VirtualDiskManagerDiskUnit* = ref object of DynamicData
    name*: string
    datacenter*: Datacenter

type
  VirtualSCSIController* = ref object of VirtualController
    hotAddRemove*: bool
    sharedBus*: VirtualSCSISharing
    scsiCtlrUnitNumber*: int

type
  HostSerialAttachedTargetTransport* = ref object of HostTargetTransport
  
type
  ActiveDirectoryProfile* = ref object of ApplyProfile
  
type
  NoVmInVApp* = ref object of VAppConfigFault
  
type
  VirtualMachineFlagInfoVirtualMmuUsage* {.pure.} = enum
    automatic, on, off
type
  IpPool* = ref object of DynamicData
    id*: int
    name*: string
    ipv4Config*: IpPoolIpPoolConfigInfo
    ipv6Config*: IpPoolIpPoolConfigInfo
    dnsDomain*: string
    dnsSearchPath*: string
    hostPrefix*: string
    httpProxy*: string
    networkAssociation*: seq[IpPoolAssociation]
    availableIpv4Addresses*: int
    availableIpv6Addresses*: int
    allocatedIpv4Addresses*: int
    allocatedIpv6Addresses*: int

type
  Profile* = ref object of vmodl.ManagedObject
    config*: ProfileConfigInfo
    description*: ProfileDescription
    name*: string
    createdTime*: string
    modifiedTime*: string
    entity*: seq[ManagedEntity]
    complianceStatus*: string

type
  LicenseKeyEntityMismatch* = ref object of NotEnoughLicenses
  
type
  VirtualAppLinkInfo* = ref object of DynamicData
    key*: ManagedEntity
    destroyWithParent*: bool

type
  FaultToleranceConfigSpec* = ref object of DynamicData
    metaDataPath*: FaultToleranceMetaSpec
    secondaryVmSpec*: FaultToleranceVMConfigSpec

type
  DatacenterEventArgument* = ref object of EntityEventArgument
    datacenter*: Datacenter

type
  TooManyNativeCloneLevels* = ref object of FileFault
  
type
  DiskIsNonLocal* = ref object of VsanDiskFault
  
type
  TaskFilterSpecByEntity* = ref object of DynamicData
    entity*: ManagedEntity
    recursion*: TaskFilterSpecRecursionOption

type
  AllVirtualMachinesLicensedEvent* = ref object of LicenseEvent
  
type
  HostPatchManagerResult* = ref object of DynamicData
    version*: string
    status*: seq[HostPatchManagerStatus]
    xmlResult*: string

type
  AnswerFileUpdateFailed* = ref object of VimFault
    failure*: seq[AnswerFileUpdateFailure]

type
  ClusterComplianceCheckedEvent* = ref object of ClusterEvent
    profile*: ProfileEventArgument

type
  NetworkInaccessible* = ref object of NasConfigFault
  
type
  IncorrectHostInformation* = ref object of NotEnoughLicenses
  
type
  DvsPortLinkDownEvent* = ref object of DvsEvent
    portKey*: string
    runtimeInfo*: DVPortStatus

type
  HostGraphicsInfoGraphicsType* {.pure.} = enum
    basic, shared, direct, sharedDirect
type
  NetworkRollbackEvent* = ref object of Event
    methodName*: string
    transactionId*: string

type
  LinkDiscoveryProtocolConfigProtocolType* {.pure.} = enum
    cdp, lldp
type
  ExternalStatsManagerTimeValuePair* = ref object of DynamicData
    duration*: int64
    value*: int64

type
  StructuredCustomizations* = ref object of HostProfilesEntityCustomizations
    entity*: ManagedEntity
    customizations*: AnswerFile

type
  VmDasBeingResetEvent* = ref object of VmEvent
    reason*: string

type
  SAMLTokenAuthentication* = ref object of GuestAuthentication
    token*: string
    username*: string

type
  NotSupportedDeviceForFTDeviceType* {.pure.} = enum
    virtualVmxnet3, paraVirtualSCSIController
type
  VirtualDiskRawDiskMappingVer1BackingOption* = ref object of VirtualDeviceDeviceBackingOption
    descriptorFileNameExtensions*: ChoiceOption
    compatibilityMode*: ChoiceOption
    diskMode*: ChoiceOption
    uuid*: bool

type
  VirtualHdAudioCard* = ref object of VirtualSoundCard
  
type
  VmInstanceUuidAssignedEvent* = ref object of VmEvent
    instanceUuid*: string

type
  ScheduledTaskFailedEvent* = ref object of ScheduledTaskEvent
    reason*: MethodFault

type
  ClusterComputeResourceFtConfigSpecVerificationResult* = ref object of DynamicData
    errors*: seq[MethodFault]
    warnings*: seq[MethodFault]

type
  CDCAlarmChangeKind* {.pure.} = enum
    triggered, retriggered, acknowledged, cleared
type
  ScsiLunDescriptorQuality* {.pure.} = enum
    highQuality, mediumQuality, lowQuality, unknownQuality
type
  VmFailedToSuspendEvent* = ref object of VmEvent
    reason*: MethodFault

type
  SlpDiscoveryMethod* {.pure.} = enum
    slpDhcp, slpAutoUnicast, slpAutoMulticast, slpManual
type
  OvfConsumerOstNode* = ref object of DynamicData
    id*: string
    type*: string
    section*: seq[OvfConsumerOvfSection]
    child*: seq[OvfConsumerOstNode]
    entity*: ManagedEntity

type
  CbrcDigestRuntimeInfoResult* = ref object of CbrcDigestOperationResult
    runtimeInfo*: CbrcDigestRuntimeInfo

type
  HostFileSystemVolumeFileSystemType* {.pure.} = enum
    VMFS, NFS, NFS41, CIFS, vsan, VFFS, VVOL, PMEM, OTHER
type
  NasSessionCredentialConflict* = ref object of NasConfigFault
    remoteHost*: string
    remotePath*: string
    userName*: string

type
  VirtualUSBOption* = ref object of VirtualDeviceOption
  
type
  DvsHealthStatusChangeEvent* = ref object of HostEvent
    switchUuid*: string
    healthResult*: HostMemberHealthCheckResult

type
  VirtualEnsoniq1371* = ref object of VirtualSoundCard
  
type
  VmGuestShutdownEvent* = ref object of VmEvent
  
type
  HostProfileManagerAnswerFileStatus* {.pure.} = enum
    valid, invalid, unknown
type
  HostDatastoreSystemDatastoreEventType* {.pure.} = enum
    VvolFastPolling, PreUnmount, FailedUnmount
type
  HostNasVolumeUserInfo* = ref object of DynamicData
    user*: string

type
  HostWwnChangedEvent* = ref object of HostEvent
    oldNodeWwns*: seq[int64]
    oldPortWwns*: seq[int64]
    newNodeWwns*: seq[int64]
    newPortWwns*: seq[int64]

type
  ProxyServiceLocalTunnelSpec* = ref object of ProxyServiceTunnelSpec
    port*: int

type
  VirtualMachineConfigSpec* = ref object of DynamicData
    changeVersion*: string
    name*: string
    version*: string
    createDate*: string
    uuid*: string
    instanceUuid*: string
    npivNodeWorldWideName*: seq[int64]
    npivPortWorldWideName*: seq[int64]
    npivWorldWideNameType*: string
    npivDesiredNodeWwns*: int16
    npivDesiredPortWwns*: int16
    npivTemporaryDisabled*: bool
    npivOnNonRdmDisks*: bool
    npivWorldWideNameOp*: string
    locationId*: string
    guestId*: string
    alternateGuestName*: string
    annotation*: string
    files*: VirtualMachineFileInfo
    tools*: ToolsConfigInfo
    flags*: VirtualMachineFlagInfo
    consolePreferences*: VirtualMachineConsolePreferences
    powerOpInfo*: VirtualMachineDefaultPowerOpInfo
    numCPUs*: int
    numCoresPerSocket*: int
    memoryMB*: int64
    memoryHotAddEnabled*: bool
    cpuHotAddEnabled*: bool
    cpuHotRemoveEnabled*: bool
    virtualICH7MPresent*: bool
    virtualSMCPresent*: bool
    deviceChange*: seq[VirtualDeviceConfigSpec]
    cpuAllocation*: ResourceAllocationInfo
    memoryAllocation*: ResourceAllocationInfo
    latencySensitivity*: LatencySensitivity
    cpuAffinity*: VirtualMachineAffinityInfo
    memoryAffinity*: VirtualMachineAffinityInfo
    networkShaper*: VirtualMachineNetworkShaperInfo
    cpuFeatureMask*: seq[VirtualMachineCpuIdInfoSpec]
    extraConfig*: seq[OptionValue]
    swapPlacement*: string
    bootOptions*: VirtualMachineBootOptions
    vAppConfig*: VmConfigSpec
    ftInfo*: FaultToleranceConfigInfo
    repConfig*: ReplicationConfigSpec
    vAppConfigRemoved*: bool
    vAssertsEnabled*: bool
    changeTrackingEnabled*: bool
    firmware*: string
    maxMksConnections*: int
    guestAutoLockEnabled*: bool
    managedBy*: ManagedByInfo
    memoryReservationLockedToMax*: bool
    nestedHVEnabled*: bool
    vPMCEnabled*: bool
    scheduledHardwareUpgradeInfo*: ScheduledHardwareUpgradeInfo
    vmProfile*: seq[VirtualMachineProfileSpec]
    messageBusTunnelEnabled*: bool
    crypto*: CryptoSpec
    migrateEncryption*: string

type
  IpRange* = ref object of IpAddress
    addressPrefix*: string
    prefixLength*: int

type
  OvfUnsupportedSubType* = ref object of OvfUnsupportedPackage
    elementName*: string
    instanceId*: string
    deviceType*: int
    deviceSubType*: string

type
  DvsReconfiguredEvent* = ref object of DvsEvent
    configSpec*: DVSConfigSpec
    configChanges*: ChangesInfoEventArgument

type
  HostDatastoreExistsConnectInfo* = ref object of HostDatastoreConnectInfo
    newDatastoreName*: string

type
  NoDisksToCustomize* = ref object of CustomizationFault
  
type
  OvfHardwareCheck* = ref object of OvfImport
  
type
  ClusterResourceUsageSummary* = ref object of DynamicData
    cpuUsedMHz*: int
    cpuCapacityMHz*: int
    memUsedMB*: int
    memCapacityMB*: int
    pMemAvailableMB*: int64
    pMemCapacityMB*: int64
    storageUsedMB*: int64
    storageCapacityMB*: int64

type
  NetBIOSConfigInfo* = ref object of DynamicData
    mode*: string

type
  AccountCreatedEvent* = ref object of HostEvent
    spec*: HostAccountSpec
    group*: bool

type
  SimpleCommandEncoding* {.pure.} = enum
    CSV, HEX, STRING
type
  LicenseManagerEvaluationInfo* = ref object of DynamicData
    properties*: seq[KeyAnyValue]

type
  StorageDrsPodSelectionSpec* = ref object of DynamicData
    initialVmConfig*: seq[VmPodConfigForPlacement]
    storagePod*: StoragePod

type
  HostIpConfig* = ref object of DynamicData
    dhcp*: bool
    ipAddress*: string
    subnetMask*: string
    ipV6Config*: HostIpConfigIpV6AddressConfiguration

type
  DatastoreRemovedOnHostEvent* = ref object of HostEvent
    datastore*: DatastoreEventArgument

type
  ClusterDasAamNodeStateDasState* {.pure.} = enum
    uninitialized, initialized, configuring, unconfiguring, running, error,
    agentShutdown, nodeFailed
type
  IscsiPortInfoPathStatus* {.pure.} = enum
    notUsed, active, standBy, lastActive
type
  IoFilterHostIssue* = ref object of DynamicData
    host*: HostSystem
    issue*: seq[MethodFault]

type
  ProxyServiceRemoteServiceSpec* = ref object of ProxyServiceServiceSpec
    hostName*: string
    port*: int

type
  VirtualDeviceOption* = ref object of DynamicData
    type*: string
    connectOption*: VirtualDeviceConnectOption
    busSlotOption*: VirtualDeviceBusSlotOption
    controllerType*: string
    autoAssignController*: BoolOption
    backingOption*: seq[VirtualDeviceBackingOption]
    defaultBackingOptionIndex*: int
    licensingLimit*: seq[string]
    deprecated*: bool
    plugAndPlay*: bool
    hotRemoveSupported*: bool

type
  RDMNotSupportedOnDatastore* = ref object of VmConfigFault
    device*: string
    datastore*: Datastore
    datastoreName*: string

type
  VirtualParallelPortFileBackingInfo* = ref object of VirtualDeviceFileBackingInfo
  
type
  OvfWrongElement* = ref object of OvfElement
  
type
  DvsHostVNicProfile* = ref object of DvsVNicProfile
  
type
  HostProfileCompleteConfigSpec* = ref object of HostProfileConfigSpec
    applyProfile*: HostApplyProfile
    customComplyProfile*: ComplianceProfile
    disabledExpressionListChanged*: bool
    disabledExpressionList*: seq[string]
    validatorHost*: HostSystem
    validating*: bool
    hostConfig*: HostProfileConfigInfo

type
  ClusterTransitionalEVCManagerEVCState* = ref object of DynamicData
    supportedEVCMode*: seq[EVCMode]
    currentEVCModeKey*: string
    guaranteedCPUFeatures*: seq[HostCpuIdInfo]
    featureCapability*: seq[HostFeatureCapability]
    featureMask*: seq[HostFeatureMask]
    featureRequirement*: seq[VirtualMachineFeatureRequirement]

type
  HostFibreChannelTargetTransport* = ref object of HostTargetTransport
    portWorldWideName*: int64
    nodeWorldWideName*: int64

type
  MissingLinuxCustResources* = ref object of CustomizationFault
  
type
  DiagnosticManagerLogFormat* {.pure.} = enum
    plain
type
  QuarantineModeFaultFaultType* {.pure.} = enum
    NoCompatibleNonQuarantinedHost, CorrectionDisallowed, CorrectionImpact
type
  RawDiskNotSupported* = ref object of DeviceNotSupported
  
type
  LicenseDataManagerLicenseData* = ref object of DynamicData
    licenseKeys*: seq[LicenseDataManagerLicenseKeyEntry]

type
  DrsRecoveredFromFailureEvent* = ref object of ClusterEvent
  
type
  PlacementSpec* = ref object of DynamicData
    priority*: VirtualMachineMovePriority
    vm*: VirtualMachine
    configSpec*: VirtualMachineConfigSpec
    relocateSpec*: VirtualMachineRelocateSpec
    hosts*: seq[HostSystem]
    datastores*: seq[Datastore]
    storagePods*: seq[StoragePod]
    disallowPrerequisiteMoves*: bool
    rules*: seq[ClusterRuleInfo]
    key*: string
    placementType*: string
    cloneSpec*: VirtualMachineCloneSpec
    cloneName*: string

type
  VmShutdownOnIsolationEvent* = ref object of VmPoweredOffEvent
    isolatedHost*: HostEventArgument
    shutdownResult*: string

type
  UserNotFound* = ref object of VimFault
    principal*: string
    unresolved*: bool

type
  VirtualResourcePoolUsage* = ref object of DynamicData
    vrpId*: string
    cpuReservationMhz*: int64
    memReservationMB*: int64
    cpuReservationUsedMhz*: int64
    memReservationUsedMB*: int64

type
  HostEnterMaintenanceResult* = ref object of DynamicData
    vmFaults*: seq[FaultsByVM]
    hostFaults*: seq[FaultsByHost]

type
  ClusterHostInfraUpdateHaModeActionOperationType* {.pure.} = enum
    enterQuarantine, exitQuarantine, enterMaintenance
type
  SessionManagerLocalTicket* = ref object of DynamicData
    userName*: string
    passwordFilePath*: string

type
  VirtualE1000Option* = ref object of VirtualEthernetCardOption
  
type
  VchaState* {.pure.} = enum
    configured, notConfigured, invalid, prepared
type
  VmStoppingEvent* = ref object of VmEvent
  
type
  HostHostUpdateProxyManager* = ref object of vmodl.ManagedObject
  
type
  AuthorizationRole* = ref object of DynamicData
    roleId*: int
    system*: bool
    name*: string
    info*: Description
    privilege*: seq[string]

type
  ProxyServiceTicketTunnelSpec* = ref object of ProxyServiceTunnelSpec
    pipePattern*: string

type
  VsanDecommissioningSatisfiability* = ref object of DynamicData
    canDecommission*: bool
    reason*: LocalizableMessage
    cost*: VsanDecommissioningCost
    dp*: VsanDecomParam

type
  VirtualDiskManager* = ref object of vmodl.ManagedObject
  
type
  ContentLibraryItem* = ref object of vim.ManagedEntity
  
type
  IscsiFaultVnicHasActivePaths* = ref object of IscsiFault
    vnicDevice*: string

type
  RestrictedByAdministrator* = ref object of RuntimeFault
    details*: string

type
  UserPrivilegeResult* = ref object of DynamicData
    entity*: ManagedEntity
    privileges*: seq[string]

type
  VirtualMachineRelocateSpec* = ref object of DynamicData
    service*: ServiceLocator
    folder*: Folder
    datastore*: Datastore
    diskMoveType*: string
    pool*: ResourcePool
    host*: HostSystem
    disk*: seq[VirtualMachineRelocateSpecDiskLocator]
    transform*: VirtualMachineRelocateTransformation
    deviceChange*: seq[VirtualDeviceConfigSpec]
    profile*: seq[VirtualMachineProfileSpec]

type
  InventoryView* = ref object of vim.view.ManagedObjectView
  
type
  OvfElementInvalidValue* = ref object of OvfElement
    value*: string

type
  HostOvercommittedEvent* = ref object of ClusterOvercommittedEvent
  
type
  DatacenterRenamedEvent* = ref object of DatacenterEvent
    oldName*: string
    newName*: string

type
  VirtualSerialPortFileBackingInfo* = ref object of VirtualDeviceFileBackingInfo
  
type
  ImportHostAddFailure* = ref object of DvsFault
    hostIp*: seq[string]

type
  VmSuspendingEvent* = ref object of VmEvent
  
type
  VmResumingEvent* = ref object of VmEvent
  
type
  VmRelayoutSuccessfulEvent* = ref object of VmEvent
  
type
  HostAutoStartManagerConfig* = ref object of DynamicData
    defaults*: AutoStartDefaults
    powerInfo*: seq[AutoStartPowerInfo]

type
  VirtualSIOControllerOption* = ref object of VirtualControllerOption
    numFloppyDrives*: IntOption
    numSerialPorts*: IntOption
    numParallelPorts*: IntOption

type
  NsxHostVNicProfile* = ref object of ApplyProfile
    key*: string
    ipConfig*: IpAddressProfile

type
  OvfNetworkInfo* = ref object of DynamicData
    name*: string
    description*: string

type
  AboutInfo* = ref object of DynamicData
    name*: string
    fullName*: string
    vendor*: string
    version*: string
    build*: string
    localeVersion*: string
    localeBuild*: string
    osType*: string
    productLineId*: string
    apiType*: string
    apiVersion*: string
    instanceUuid*: string
    licenseProductName*: string
    licenseProductVersion*: string

type
  HistoryCollector* = ref object of vmodl.ManagedObject
    filter*: pointer

type
  PlacementRankResult* = ref object of DynamicData
    key*: string
    candidate*: ClusterComputeResource
    reservedSpaceMB*: int64
    usedSpaceMB*: int64
    totalSpaceMB*: int64
    utilization*: float64
    faults*: seq[MethodFault]

type
  HostInternetScsiHbaDiscoveryProperties* = ref object of DynamicData
    iSnsDiscoveryEnabled*: bool
    iSnsDiscoveryMethod*: string
    iSnsHost*: string
    slpDiscoveryEnabled*: bool
    slpDiscoveryMethod*: string
    slpHost*: string
    staticTargetDiscoveryEnabled*: bool
    sendTargetsDiscoveryEnabled*: bool

type
  GuestOsDescriptorSupportLevel* {.pure.} = enum
    experimental, legacy, terminated, supported, unsupported, deprecated, techPreview
type
  TagPolicy* = ref object of vim.ManagedEntity
  
type
  HostStorageSystemDiskLocatorLedResult* = ref object of DynamicData
    key*: string
    fault*: MethodFault

type
  InvalidDiskFormat* = ref object of InvalidFormat
  
type
  HostProfileConfigSpec* = ref object of ProfileCreateSpec
  
type
  Action* = ref object of DynamicData
  
type
  VirtualMachineSnapshotInfo* = ref object of DynamicData
    currentSnapshot*: VirtualMachineSnapshot
    rootSnapshotList*: seq[VirtualMachineSnapshotTree]

type
  DvsAcceptNetworkRuleAction* = ref object of DvsNetworkRuleAction
  
type
  DeviceBackedVirtualDiskSpec* = ref object of VirtualDiskSpec
    device*: string

type
  ResourcePoolResourceUsage* = ref object of DynamicData
    reservationUsed*: int64
    reservationUsedForVm*: int64
    unreservedForPool*: int64
    unreservedForVm*: int64
    overallUsage*: int64
    maxUsage*: int64

type
  VirtualMachineConfigSummary* = ref object of DynamicData
    name*: string
    template*: bool
    vmPathName*: string
    memorySizeMB*: int
    cpuReservation*: int
    memoryReservation*: int
    numCpu*: int
    numEthernetCards*: int
    numVirtualDisks*: int
    uuid*: string
    instanceUuid*: string
    guestId*: string
    guestFullName*: string
    annotation*: string
    product*: VAppProductInfo
    installBootRequired*: bool
    ftInfo*: FaultToleranceConfigInfo
    managedBy*: ManagedByInfo
    tpmPresent*: bool
    numVmiopBackings*: int

type
  ClusterProfileConfigSpec* = ref object of ClusterProfileCreateSpec
  
type
  InvalidFolder* = ref object of VimFault
    target*: ManagedEntity

type
  HostLocalAccountManager* = ref object of vmodl.ManagedObject
  
type
  VirtualMachineRuntimeInfo* = ref object of DynamicData
    device*: seq[VirtualMachineDeviceRuntimeInfo]
    host*: HostSystem
    connectionState*: VirtualMachineConnectionState
    powerState*: VirtualMachinePowerState
    faultToleranceState*: VirtualMachineFaultToleranceState
    dasVmProtection*: VirtualMachineRuntimeInfoDasProtectionState
    toolsInstallerMounted*: bool
    suspendTime*: string
    bootTime*: string
    suspendInterval*: int64
    question*: VirtualMachineQuestionInfo
    memoryOverhead*: int64
    maxCpuUsage*: int
    maxMemoryUsage*: int
    numMksConnections*: int
    recordReplayState*: VirtualMachineRecordReplayState
    cleanPowerOff*: bool
    needSecondaryReason*: string
    onlineStandby*: bool
    minRequiredEVCModeKey*: string
    consolidationNeeded*: bool
    offlineFeatureRequirement*: seq[VirtualMachineFeatureRequirement]
    featureRequirement*: seq[VirtualMachineFeatureRequirement]
    featureMask*: seq[HostFeatureMask]
    vFlashCacheAllocation*: int64
    paused*: bool
    snapshotInBackground*: bool
    quiescedForkParent*: bool
    instantCloneFrozen*: bool
    cryptoState*: string

type
  HostDiskPartitionInfoPartitionFormat* {.pure.} = enum
    gpt, mbr, unknown
type
  HostCnxFailedNoConnectionEvent* = ref object of HostEvent
  
type
  HostDiskPartitionAttributes* = ref object of DynamicData
    partition*: int
    startSector*: int64
    endSector*: int64
    type*: string
    guid*: string
    logical*: bool
    attributes*: byte
    partitionAlignment*: int64

type
  ImportHostProfileCustomizationsResultEntityCustomizationsResult* = ref object of DynamicData
    entity*: ManagedEntity
    validationResult*: AnswerFileValidationResult
    customizations*: AnswerFile

type
  VAppCloneSpec* = ref object of DynamicData
    location*: Datastore
    host*: HostSystem
    resourceSpec*: ResourceConfigSpec
    vmFolder*: Folder
    networkMapping*: seq[VAppCloneSpecNetworkMappingPair]
    property*: seq[KeyValue]
    resourceMapping*: seq[VAppCloneSpecResourceMap]
    provisioning*: string

type
  GuestWindowsRegistryManager* = ref object of vmodl.ManagedObject
  
type
  ProfileExecuteResultStatus* {.pure.} = enum
    success, needInput, error
type
  DvsMergedEvent* = ref object of DvsEvent
    sourceDvs*: DvsEventArgument
    destinationDvs*: DvsEventArgument

type
  VmSecondaryEnabledEvent* = ref object of VmEvent
  
type
  HttpNfcLeaseManifestEntry* = ref object of DynamicData
    key*: string
    sha1*: string
    checksum*: string
    checksumType*: string
    size*: int64
    disk*: bool
    capacity*: int64
    populatedSize*: int64

type
  CannotPlaceWithoutPrerequisiteMoves* = ref object of VimFault
  
type
  ReplicationIncompatibleWithFT* = ref object of ReplicationFault
  
type
  InvalidHostConnectionState* = ref object of InvalidHostState
  
type
  VmRegisteredEvent* = ref object of VmEvent
  
type
  AlarmEmailFailedEvent* = ref object of AlarmEvent
    entity*: ManagedEntityEventArgument
    to*: string
    reason*: MethodFault

type
  HostStorageArrayTypePolicyOption* = ref object of DynamicData
    policy*: ElementDescription

type
  OvfConsumerContext* = ref object of DynamicData
    sessionId*: string
    userName*: string
    locale*: string

type
  HostCpuPackageVendor* {.pure.} = enum
    unknown, intel, amd, arm
type
  ClusterDasAdmissionControlInfo* = ref object of DynamicData
  
type
  LocalTSMEnabledEvent* = ref object of HostEvent
  
type
  EnteringStandbyModeEvent* = ref object of HostEvent
  
type
  ClusterPowerOnVmOption* {.pure.} = enum
    OverrideAutomationLevel, ReserveResources
type
  CryptoSpecShallowRecrypt* = ref object of CryptoSpec
    newKeyId*: CryptoKeyId

type
  NoGateway* = ref object of HostConfigFault
  
type
  ClusterFailoverLevelAdmissionControlPolicy* = ref object of ClusterDasAdmissionControlPolicy
    failoverLevel*: int
    slotPolicy*: ClusterSlotPolicy

type
  PerfEntityMetric* = ref object of PerfEntityMetricBase
    sampleInfo*: seq[PerfSampleInfo]
    value*: seq[PerfMetricSeries]

type
  ComplianceProfile* = ref object of DynamicData
    expression*: seq[ProfileExpression]
    rootExpression*: string

type
  VirtualMachineFaultToleranceState* {.pure.} = enum
    notConfigured, disabled, enabled, needSecondary, starting, running
type
  VsanUpgradeSystemUpgradeHistoryDiskGroupOp* = ref object of VsanUpgradeSystemUpgradeHistoryItem
    operation*: string
    diskMapping*: VsanHostDiskMapping

type
  View* = ref object of vmodl.ManagedObject
  
type
  VirtualMachineWipeResult* = ref object of DynamicData
    diskId*: int
    shrinkableDiskSpace*: int64

type
  VirtualMachinePciPassthroughInfo* = ref object of VirtualMachineTargetInfo
    pciDevice*: HostPciDevice
    systemId*: string

type
  GuestComponentsOutOfDate* = ref object of GuestOperationsFault
  
type
  VirtualFloppyImageBackingOption* = ref object of VirtualDeviceFileBackingOption
  
type
  ScsiDiskType* {.pure.} = enum
    native512, emulated512, native4k, SoftwareEmulated4k, unknown
type
  InvalidLicense* = ref object of VimFault
    licenseContent*: string

type
  HostOpaqueNetworkInfo* = ref object of DynamicData
    opaqueNetworkId*: string
    opaqueNetworkName*: string
    opaqueNetworkType*: string
    pnicZone*: seq[string]
    capability*: OpaqueNetworkCapability
    extraConfig*: seq[OptionValue]

type
  FileSystemMountInfoVStorageSupportStatus* {.pure.} = enum
    vStorageSupported, vStorageUnsupported, vStorageUnknown
type
  HostNoAvailableNetworksEvent* = ref object of HostDasEvent
    ips*: string

type
  MissingWindowsCustResources* = ref object of CustomizationFault
  
type
  HostSignatureInfo* = ref object of DynamicData
    signingMethod*: string
    signatureValue*: seq[byte]
    signingKey*: string
    nonce*: seq[byte]
    dateTime*: string

type
  VMwareDVSHealthCheckConfig* = ref object of DVSHealthCheckConfig
  
type
  VmNoNetworkAccessEvent* = ref object of VmEvent
    destHost*: HostEventArgument

type
  RDMConversionNotSupported* = ref object of MigrationFault
    device*: string

type
  DasAgentUnavailableEvent* = ref object of ClusterEvent
  
type
  NonPersistentDisksNotSupported* = ref object of DeviceNotSupported
  
type
  LockerMisconfiguredEvent* = ref object of Event
    datastore*: DatastoreEventArgument

type
  ClusterComputeResourceFtCompatibleHostResult* = ref object of DynamicData
    ftHost*: HostSystem
    errors*: seq[MethodFault]
    warnings*: seq[MethodFault]

type
  HostSystemHealthInfo* = ref object of DynamicData
    numericSensorInfo*: seq[HostNumericSensorInfo]

type
  CustomizationEvent* = ref object of VmEvent
    logLocation*: string

type
  HostLowLevelProvisioningManagerDiskLayoutSpec* = ref object of DynamicData
    controllerType*: string
    busNumber*: int
    unitNumber*: int
    srcFilename*: string
    dstFilename*: string

type
  ProxyServiceAccessMode* {.pure.} = enum
    httpOnly, httpsOnly, httpsWithRedirect, httpAndHttps
type
  HostDatastoreBrowserSearchResults* = ref object of DynamicData
    datastore*: Datastore
    folderPath*: string
    file*: seq[FileInfo]

type
  HostVMotionManagerVMotionDeviceSpec* = ref object of VirtualDeviceConfigSpec
    busNumber*: int
    controllerType*: string

type
  ScheduledHardwareUpgradeInfoHardwareUpgradePolicy* {.pure.} = enum
    never, onSoftPowerOff, always
type
  StorageDrsCannotMoveFTVm* = ref object of VimFault
  
type
  TaskHistoryCollector* = ref object of vim.HistoryCollector
    latestPage*: seq[TaskInfo]

type
  ToolsConfigInfo* = ref object of DynamicData
    toolsVersion*: int
    toolsInstallType*: string
    afterPowerOn*: bool
    afterResume*: bool
    beforeGuestStandby*: bool
    beforeGuestShutdown*: bool
    beforeGuestReboot*: bool
    toolsUpgradePolicy*: string
    pendingCustomization*: string
    customizationKeyId*: CryptoKeyId
    syncTimeWithHost*: bool
    lastInstallInfo*: ToolsConfigInfoToolsLastInstallInfo
    upgradeRebootPredict*: bool

type
  VirtualVideoCardOption* = ref object of VirtualDeviceOption
    videoRamSizeInKB*: LongOption
    numDisplays*: IntOption
    useAutoDetect*: BoolOption
    support3D*: BoolOption
    use3dRendererSupported*: BoolOption
    graphicsMemorySizeInKB*: LongOption
    graphicsMemorySizeSupported*: BoolOption

type
  DisableAlarmExpression* = ref object of AlarmExpression
  
type
  SSLDisabledFault* = ref object of HostConnectFault
  
type
  MessageBusProxyFault* = ref object of VimFault
  
type
  CustomizationLicenseDataMode* {.pure.} = enum
    perServer, perSeat
type
  VmCloneFailedEvent* = ref object of VmCloneEvent
    destFolder*: FolderEventArgument
    destName*: string
    destHost*: HostEventArgument
    reason*: MethodFault

type
  AlarmCreatedEvent* = ref object of AlarmEvent
    entity*: ManagedEntityEventArgument

type
  MethodActionArgument* = ref object of DynamicData
    value*: pointer

type
  VirtualMachinePowerOpType* {.pure.} = enum
    soft, hard, preset
type
  HostSnmpConfigSpec* = ref object of DynamicData
    enabled*: bool
    port*: int
    readOnlyCommunities*: seq[string]
    trapTargets*: seq[HostSnmpDestination]
    option*: seq[KeyValue]

type
  VmClonedEvent* = ref object of VmCloneEvent
    sourceVm*: VmEventArgument

type
  HostNatServicePortForwardSpec* = ref object of DynamicData
    type*: string
    name*: string
    hostPort*: int
    guestPort*: int
    guestIpAddress*: string

type
  CustomizationName* = ref object of DynamicData
  
type
  HostSystemIdentificationInfoIdentifier* {.pure.} = enum
    AssetTag, ServiceTag, OemSpecificString
type
  DvsVnicAllocatedResource* = ref object of DynamicData
    vm*: VirtualMachine
    vnicKey*: string
    reservation*: int64

type
  RoleRemovedEvent* = ref object of RoleEvent
  
type
  DatastoreCapability* = ref object of DynamicData
    directoryHierarchySupported*: bool
    rawDiskMappingsSupported*: bool
    perFileThinProvisioningSupported*: bool
    storageIORMSupported*: bool
    nativeSnapshotSupported*: bool
    topLevelDirectoryCreateSupported*: bool
    seSparseSupported*: bool
    vmfsSparseSupported*: bool
    vsanSparseSupported*: bool
    upitSupported*: bool
    vmdkExpandSupported*: bool

type
  DVPortStatus* = ref object of DynamicData
    linkUp*: bool
    blocked*: bool
    vlanIds*: seq[NumericRange]
    trunkingMode*: bool
    mtu*: int
    linkPeer*: string
    macAddress*: string
    statusDetail*: string
    vmDirectPathGen2Active*: bool
    vmDirectPathGen2InactiveReasonNetwork*: seq[string]
    vmDirectPathGen2InactiveReasonOther*: seq[string]
    vmDirectPathGen2InactiveReasonExtended*: string

type
  CustomizationUnknownIpV6Generator* = ref object of CustomizationIpV6Generator
  
type
  VirtualNVDIMMControllerOption* = ref object of VirtualControllerOption
    numNVDIMMControllers*: IntOption

type
  VirtualMachineCapability* = ref object of DynamicData
    snapshotOperationsSupported*: bool
    multipleSnapshotsSupported*: bool
    snapshotConfigSupported*: bool
    poweredOffSnapshotsSupported*: bool
    memorySnapshotsSupported*: bool
    revertToSnapshotSupported*: bool
    quiescedSnapshotsSupported*: bool
    disableSnapshotsSupported*: bool
    lockSnapshotsSupported*: bool
    consolePreferencesSupported*: bool
    cpuFeatureMaskSupported*: bool
    s1AcpiManagementSupported*: bool
    settingScreenResolutionSupported*: bool
    toolsAutoUpdateSupported*: bool
    vmNpivWwnSupported*: bool
    npivWwnOnNonRdmVmSupported*: bool
    vmNpivWwnDisableSupported*: bool
    vmNpivWwnUpdateSupported*: bool
    swapPlacementSupported*: bool
    toolsSyncTimeSupported*: bool
    virtualMmuUsageSupported*: bool
    diskSharesSupported*: bool
    bootOptionsSupported*: bool
    bootRetryOptionsSupported*: bool
    settingVideoRamSizeSupported*: bool
    settingDisplayTopologySupported*: bool
    settingDisplayTopologyModesSupported*: bool
    recordReplaySupported*: bool
    changeTrackingSupported*: bool
    multipleCoresPerSocketSupported*: bool
    hostBasedReplicationSupported*: bool
    guestAutoLockSupported*: bool
    memoryReservationLockSupported*: bool
    featureRequirementSupported*: bool
    poweredOnMonitorTypeChangeSupported*: bool
    vmfsNativeSnapshotSupported*: bool
    seSparseDiskSupported*: bool
    nestedHVSupported*: bool
    vPMCSupported*: bool
    toolsRebootPredictSupported*: bool
    messageBusSupported*: bool
    canConnectUSBDevices*: bool
    secureBootSupported*: bool
    perVmEvcSupported*: bool
    virtualMmuUsageIgnored*: bool
    virtualExecUsageIgnored*: bool
    diskOnlySnapshotOnSuspendedVMSupported*: bool

type
  OptionManager* = ref object of vmodl.ManagedObject
    supportedOption*: seq[OptionDef]
    setting*: seq[OptionValue]

type
  VirtualMachineStandbyActionType* {.pure.} = enum
    checkpoint, powerOnSuspend
type
  VslmCloneSpec* = ref object of VslmMigrateSpec
    name*: string
    keepAfterDeleteVm*: bool

type
  BlockedByFirewall* = ref object of HostConfigFault
  
type
  HostAccessManager* = ref object of vmodl.ManagedObject
    lockdownMode*: HostLockdownMode

type
  CannotDecryptPasswords* = ref object of CustomizationFault
  
type
  GeneralUserEvent* = ref object of GeneralEvent
    entity*: ManagedEntityEventArgument

type
  ApplyHostProfileConfigurationResult* = ref object of DynamicData
    startTime*: string
    completeTime*: string
    host*: HostSystem
    status*: string
    errors*: seq[MethodFault]

type
  VirtualPointingDeviceOption* = ref object of VirtualDeviceOption
  
type
  ProfilePolicyMetadata* = ref object of DynamicData
    id*: ExtendedElementDescription
    possibleOption*: seq[ProfilePolicyOptionMetadata]

type
  ClusterVmReadinessReadyCondition* {.pure.} = enum
    none, poweredOn, guestHbStatusGreen, appHbStatusGreen, useClusterDefault
type
  HostStatusChangedEvent* = ref object of ClusterStatusChangedEvent
  
type
  VirtualMachineProfileDetailsDiskProfileDetails* = ref object of DynamicData
    diskId*: int
    profile*: seq[VirtualMachineProfileSpec]

type
  VirtualMachineMemoryAllocationPolicy* {.pure.} = enum
    swapNone, swapSome, swapMost
type
  QuestionPending* = ref object of InvalidState
    text*: string

type
  VirtualCdromRemoteAtapiBackingInfo* = ref object of VirtualDeviceRemoteDeviceBackingInfo
  
type
  ClusterDasConfigInfo* = ref object of DynamicData
    enabled*: bool
    vmMonitoring*: string
    hostMonitoring*: string
    vmComponentProtecting*: string
    failoverLevel*: int
    admissionControlPolicy*: ClusterDasAdmissionControlPolicy
    admissionControlEnabled*: bool
    defaultVmSettings*: ClusterDasVmSettings
    option*: seq[OptionValue]
    heartbeatDatastore*: seq[Datastore]
    hBDatastoreCandidatePolicy*: string

type
  VmDiskFileQueryFlags* = ref object of DynamicData
    diskType*: bool
    capacityKb*: bool
    hardwareVersion*: bool
    controllerType*: bool
    diskExtents*: bool
    thin*: bool
    encryption*: bool

type
  VMwareDVSVspanConfigSpec* = ref object of DynamicData
    vspanSession*: VMwareVspanSession
    operation*: string

type
  WillLoseHAProtectionResolution* {.pure.} = enum
    svmotion, relocate
type
  ProfileCreateSpec* = ref object of DynamicData
    name*: string
    annotation*: string
    enabled*: bool

type
  FaultToleranceNeedsThickDisk* = ref object of MigrationFault
    vmName*: string

type
  ClusterEVCManagerEVCState* = ref object of DynamicData
    supportedEVCMode*: seq[EVCMode]
    currentEVCModeKey*: string
    guaranteedCPUFeatures*: seq[HostCpuIdInfo]
    featureCapability*: seq[HostFeatureCapability]
    featureMask*: seq[HostFeatureMask]
    featureRequirement*: seq[VirtualMachineFeatureRequirement]

type
  OvfResourceMap* = ref object of DynamicData
    source*: string
    parent*: ResourcePool
    resourceSpec*: ResourceConfigSpec
    datastore*: Datastore

type
  IscsiFaultVnicHasMultipleUplinks* = ref object of IscsiFault
    vnicDevice*: string

type
  NotFound* = ref object of VimFault
  
type
  HostUnresolvedVmfsVolume* = ref object of DynamicData
    extent*: seq[HostUnresolvedVmfsExtent]
    vmfsLabel*: string
    vmfsUuid*: string
    totalBlocks*: int
    resolveStatus*: HostUnresolvedVmfsVolumeResolveStatus

type
  HostPersistentMemoryInfo* = ref object of DynamicData
    capacityInMB*: int64
    volumeUUID*: string

type
  AuthorizationManager* = ref object of vmodl.ManagedObject
    privilegeList*: seq[AuthorizationPrivilege]
    roleList*: seq[AuthorizationRole]
    description*: AuthorizationDescription

type
  HostDnsConfig* = ref object of DynamicData
    dhcp*: bool
    virtualNicDevice*: string
    ipv6VirtualNicDevice*: string
    hostName*: string
    domainName*: string
    address*: seq[string]
    searchDomain*: seq[string]

type
  DataProviderFilterLogicalOperator* {.pure.} = enum
    And, Or
type
  HostFeatureVersionKey* {.pure.} = enum
    faultTolerance
type
  ClusterStatusChangedEvent* = ref object of ClusterEvent
    oldStatus*: string
    newStatus*: string

type
  HostDevice* = ref object of DynamicData
    deviceName*: string
    deviceType*: string

type
  HostLockdownMode* {.pure.} = enum
    lockdownDisabled, lockdownNormal, lockdownStrict
type
  HostDigestInfo* = ref object of DynamicData
    digestMethod*: string
    digestValue*: seq[byte]
    objectName*: string

type
  UserGroupProfile* = ref object of ApplyProfile
    key*: string

type
  StorageDrsCannotMoveManuallyPlacedSwapFile* = ref object of VimFault
  
type
  HAErrorsAtDest* = ref object of MigrationFault
  
type
  KeyProviderId* = ref object of DynamicData
    id*: string

type
  HostInAuditModeEvent* = ref object of HostEvent
  
type
  ClusterVmOrchestrationInfo* = ref object of DynamicData
    vm*: VirtualMachine
    vmReadiness*: ClusterVmReadiness

type
  ClusterProfileCreateSpec* = ref object of ProfileCreateSpec
  
type
  VslmCreateSpecRawDiskMappingBackingSpec* = ref object of VslmCreateSpecBackingSpec
    lunUuid*: string
    compatibilityMode*: string

type
  PlatformConfigFault* = ref object of HostConfigFault
    text*: string

type
  PatchBinariesNotFound* = ref object of VimFault
    patchID*: string
    binary*: seq[string]

type
  HostFaultToleranceManager* = ref object of vmodl.ManagedObject
  
type
  VmwareDistributedVirtualSwitchPvlanSpec* = ref object of VmwareDistributedVirtualSwitchVlanSpec
    pvlanId*: int

type
  DisabledMethodRequest* = ref object of DynamicData
    method*: string
    reasonId*: string

type
  DatacenterMismatchArgument* = ref object of DynamicData
    entity*: ManagedEntity
    inputDatacenter*: Datacenter

type
  VirtualMachineHtSharing* {.pure.} = enum
    any, none, internal
type
  HostAddFailedEvent* = ref object of HostEvent
    hostname*: string

type
  VMwareDVSConfigInfo* = ref object of DVSConfigInfo
    vspanSession*: seq[VMwareVspanSession]
    pvlanConfig*: seq[VMwareDVSPvlanMapEntry]
    maxMtu*: int
    linkDiscoveryProtocolConfig*: LinkDiscoveryProtocolConfig
    ipfixConfig*: VMwareIpfixConfig
    lacpGroupConfig*: seq[VMwareDvsLacpGroupConfig]
    lacpApiVersion*: string
    multicastFilteringMode*: string

type
  VmSnapshotFileInfo* = ref object of FileInfo
  
type
  UserUnassignedFromGroup* = ref object of HostEvent
    userLogin*: string
    group*: string

type
  VirtualUSBRemoteClientBackingInfo* = ref object of VirtualDeviceRemoteDeviceBackingInfo
    hostname*: string

type
  VirtualMachineGuestSummary* = ref object of DynamicData
    guestId*: string
    guestFullName*: string
    toolsStatus*: VirtualMachineToolsStatus
    toolsVersionStatus*: string
    toolsVersionStatus2*: string
    toolsRunningStatus*: string
    hostName*: string
    ipAddress*: string

type
  VspanDestPortConflict* = ref object of DvsFault
    vspanSessionKey1*: string
    vspanSessionKey2*: string
    portKey*: string

type
  VMwareDVSTeamingMatchStatus* {.pure.} = enum
    iphashMatch, nonIphashMatch, iphashMismatch, nonIphashMismatch
type
  HostPlugStoreTopologyDevice* = ref object of DynamicData
    key*: string
    lun*: ScsiLun
    path*: seq[HostPlugStoreTopologyPath]

type
  ReplicationVmFault* = ref object of ReplicationFault
    reason*: string
    state*: string
    instanceId*: string
    vm*: VirtualMachine

type
  DistributedVirtualSwitchManagerDvsProductSpec* = ref object of DynamicData
    newSwitchProductSpec*: DistributedVirtualSwitchProductSpec
    distributedVirtualSwitch*: DistributedVirtualSwitch

type
  DvsPortDisconnectedEvent* = ref object of DvsEvent
    portKey*: string
    connectee*: DistributedVirtualSwitchPortConnectee

type
  DateTimeProfile* = ref object of ApplyProfile
  
type
  HostDiskBlockInfoMapping* = ref object of DynamicData
    element*: string
    extent*: seq[HostDiskBlockInfoExtent]

type
  EVCModeUnsupportedByHosts* = ref object of EVCConfigFault
    evcMode*: string
    host*: seq[HostSystem]
    hostName*: seq[string]

type
  VirtualMachineFlagInfo* = ref object of DynamicData
    disableAcceleration*: bool
    enableLogging*: bool
    useToe*: bool
    runWithDebugInfo*: bool
    monitorType*: string
    htSharing*: string
    snapshotDisabled*: bool
    snapshotLocked*: bool
    diskUuidEnabled*: bool
    virtualMmuUsage*: string
    virtualExecUsage*: string
    snapshotPowerOffBehavior*: string
    recordReplayEnabled*: bool
    faultToleranceType*: string
    cbrcCacheEnabled*: bool
    vvtdEnabled*: bool
    vbsEnabled*: bool

type
  UpgradePolicy* {.pure.} = enum
    manual, upgradeAtPowerCycle
type
  HostVirtualSwitchBondBridge* = ref object of HostVirtualSwitchBridge
    nicDevice*: seq[string]
    beacon*: HostVirtualSwitchBeaconConfig
    linkDiscoveryProtocolConfig*: LinkDiscoveryProtocolConfig

type
  ClusterDasFailoverLevelAdvancedRuntimeInfo* = ref object of ClusterDasAdvancedRuntimeInfo
    slotInfo*: ClusterDasFailoverLevelAdvancedRuntimeInfoSlotInfo
    totalSlots*: int
    usedSlots*: int
    unreservedSlots*: int
    totalVms*: int
    totalHosts*: int
    totalGoodHosts*: int
    hostSlots*: seq[ClusterDasFailoverLevelAdvancedRuntimeInfoHostSlots]
    vmsRequiringMultipleSlots*: seq[ClusterDasFailoverLevelAdvancedRuntimeInfoVmSlots]

type
  VsanPolicyCost* = ref object of DynamicData
    changeDataSize*: int64
    currentDataSize*: int64
    tempDataSize*: int64
    copyDataSize*: int64
    changeFlashReadCacheSize*: int64
    currentFlashReadCacheSize*: int64
    currentDiskSpaceToAddressSpaceRatio*: float32
    diskSpaceToAddressSpaceRatio*: float32

type
  VirtualDiskConfigSpec* = ref object of VirtualDeviceConfigSpec
    diskMoveType*: string
    migrateCache*: bool

type
  PosixUserSearchResult* = ref object of UserSearchResult
    id*: int
    shellAccess*: bool

type
  ClusterVersionedStringData* = ref object of DynamicData
    version*: int64
    data*: string

type
  MisfeaturedHostsBlockingEVC* = ref object of EVCConfigFault
    badHardwareHosts*: seq[HostSystem]
    badHardwareHostNames*: seq[string]
    badSoftwareHosts*: seq[HostSystem]
    badSoftwareHostNames*: seq[string]

type
  StringExpression* = ref object of NegatableExpression
    value*: string

type
  VirtualDiskFlatVer1BackingInfo* = ref object of VirtualDeviceFileBackingInfo
    diskMode*: string
    split*: bool
    writeThrough*: bool
    contentId*: string
    parent*: VirtualDiskFlatVer1BackingInfo

type
  DvsGreEncapNetworkRuleAction* = ref object of DvsNetworkRuleAction
    encapsulationIp*: SingleIp

type
  GuestRegValueMultiStringSpec* = ref object of GuestRegValueDataSpec
    value*: seq[string]

type
  VsanHostConfigInfoClusterInfo* = ref object of DynamicData
    uuid*: string
    nodeUuid*: string

type
  HostInternetScsiHbaNetworkBindingSupportType* {.pure.} = enum
    notsupported, optional, required
type
  CryptoManagerHost* = ref object of vim.encryption.CryptoManager
  
type
  HostSecuritySpec* = ref object of DynamicData
    adminPassword*: string
    removePermission*: seq[Permission]
    addPermission*: seq[Permission]

type
  Description* = ref object of DynamicData
    label*: string
    summary*: string

type
  VirtualMachineBackupEventInfoBackupEventType* {.pure.} = enum
    reset, requestorError, requestorAbort, providerAbort, snapshotPrepare,
    snapshotCommit, requestorDone, backupManifest, writerError, keepAlive
type
  ExternalStatsManagerStatsUpdate* = ref object of DynamicData
    entity*: ManagedEntity
    statsData*: seq[ExternalStatsManagerMetricValueMap]

type
  VmMessageEvent* = ref object of VmEvent
    message*: string
    messageInfo*: seq[VirtualMachineMessage]

type
  ReplicationVmProgressInfo* = ref object of DynamicData
    progress*: int
    bytesTransferred*: int64
    bytesToTransfer*: int64
    checksumTotalBytes*: int64
    checksumComparedBytes*: int64

type
  DvsPortJoinPortgroupEvent* = ref object of DvsEvent
    portKey*: string
    portgroupKey*: string
    portgroupName*: string

type
  RemoteDeviceNotSupported* = ref object of DeviceNotSupported
  
type
  VmWwnAssignedEvent* = ref object of VmEvent
    nodeWwns*: seq[int64]
    portWwns*: seq[int64]

type
  MessageBusProxyInfo* = ref object of DynamicData
    configured*: bool
    brokerURI*: seq[string]
    running*: bool

type
  VcenterVStorageObjectManager* = ref object of vim.vslm.VStorageObjectManagerBase
  
type
  HostNicOrderPolicy* = ref object of DynamicData
    activeNic*: seq[string]
    standbyNic*: seq[string]

type
  GuestListFileInfo* = ref object of DynamicData
    files*: seq[GuestFileInfo]
    remaining*: int

type
  StorageDrsCannotMoveVmWithNoFilesInLayout* = ref object of VimFault
  
type
  ClusterGroupSpec* = ref object of ArrayUpdateSpec
    info*: ClusterGroupInfo

type
  HostSpecificationRequireEvent* = ref object of HostEvent
  
type
  HostHardwareElementInfo* = ref object of DynamicData
    name*: string
    status*: ElementDescription

type
  HostMultipathStateInfo* = ref object of DynamicData
    path*: seq[HostMultipathStateInfoPath]

type
  HostNtpConfig* = ref object of DynamicData
    server*: seq[string]
    configFile*: seq[string]

type
  VmEndRecordingEvent* = ref object of VmEvent
  
type
  DrsInjectorWorkload* = ref object of DynamicData
    key*: Datastore
    slope1*: float64
    intercept1*: float64
    slope2*: float64
    intercept2*: float64
    inflectionPoint*: float64
    writeSlope*: float64
    writeIntercept*: float64
    correlation*: seq[DrsDatastoreCorrelation]

type
  HostInternetScsiHbaIPCapabilities* = ref object of DynamicData
    addressSettable*: bool
    ipConfigurationMethodSettable*: bool
    subnetMaskSettable*: bool
    defaultGatewaySettable*: bool
    primaryDnsServerAddressSettable*: bool
    alternateDnsServerAddressSettable*: bool
    ipv6Supported*: bool
    arpRedirectSettable*: bool
    mtuSettable*: bool
    hostNameAsTargetAddress*: bool
    nameAliasSettable*: bool
    ipv4EnableSettable*: bool
    ipv6EnableSettable*: bool
    ipv6PrefixLengthSettable*: bool
    ipv6PrefixLength*: int
    ipv6DhcpConfigurationSettable*: bool
    ipv6LinkLocalAutoConfigurationSettable*: bool
    ipv6RouterAdvertisementConfigurationSettable*: bool
    ipv6DefaultGatewaySettable*: bool
    ipv6MaxStaticAddressesSupported*: int

type
  VirtualSATAController* = ref object of VirtualController
  
type
  HostLowLevelProvisioningManagerSnapshotLayoutSpec* = ref object of DynamicData
    id*: int
    srcFilename*: string
    dstFilename*: string
    disk*: seq[HostLowLevelProvisioningManagerDiskLayoutSpec]

type
  DasAgentFoundEvent* = ref object of ClusterEvent
  
type
  ClusterPerResourceValue* = ref object of DynamicData
    resourceType*: string
    value*: int

type
  AnswerFileValidationInfoStatus* {.pure.} = enum
    success, failed, failed_defaults
type
  HostIncompatibleForFaultToleranceReason* {.pure.} = enum
    product, processor
type
  CryptoSpecRegister* = ref object of CryptoSpecNoOp
    cryptoKeyId*: CryptoKeyId

type
  HostIpRouteConfigSpec* = ref object of HostIpRouteConfig
    gatewayDeviceConnection*: HostVirtualNicConnection
    ipV6GatewayDeviceConnection*: HostVirtualNicConnection

type
  DvsPortConnectedEvent* = ref object of DvsEvent
    portKey*: string
    connectee*: DistributedVirtualSwitchPortConnectee

type
  ScsiLunCapabilities* = ref object of DynamicData
    updateDisplayNameSupported*: bool

type
  AlarmState* = ref object of DynamicData
    key*: string
    entity*: ManagedEntity
    alarm*: Alarm
    overallStatus*: ManagedEntityStatus
    time*: string
    acknowledged*: bool
    acknowledgedByUser*: string
    acknowledgedTime*: string
    eventKey*: int

type
  DvsHostJoinedEvent* = ref object of DvsEvent
    hostJoined*: HostEventArgument

type
  WillModifyConfigCpuRequirements* = ref object of MigrationFault
  
type
  HostCnxFailedTimeoutEvent* = ref object of HostEvent
  
type
  OvfConsumerInvalidSection* = ref object of OvfConsumerCallbackFault
    lineNumber*: int
    description*: string

type
  FaultToleranceDiskSpec* = ref object of DynamicData
    disk*: VirtualDevice
    datastore*: Datastore

type
  VmConfigIncompatibleForFaultTolerance* = ref object of VmConfigFault
    fault*: MethodFault

type
  HostVirtualNicOpaqueNetworkSpec* = ref object of DynamicData
    opaqueNetworkId*: string
    opaqueNetworkType*: string

type
  ProfileProfileStructureProperty* = ref object of DynamicData
    propertyName*: string
    array*: bool
    element*: ProfileProfileStructure

type
  ServiceConsoleReservationInfo* = ref object of DynamicData
    serviceConsoleReservedCfg*: int64
    serviceConsoleReserved*: int64
    unreserved*: int64

type
  ClusterProfileServiceType* {.pure.} = enum
    DRS, HA, DPM, FT
type
  CannotMoveVmWithNativeDeltaDisk* = ref object of MigrationFault
  
type
  NoLicenseEvent* = ref object of LicenseEvent
    feature*: LicenseFeatureInfo

type
  DatabaseSizeParam* = ref object of DynamicData
    inventoryDesc*: InventoryDescription
    perfStatsDesc*: PerformanceStatisticsDescription

type
  VirtualMachineDefaultPowerOpInfo* = ref object of DynamicData
    powerOffType*: string
    suspendType*: string
    resetType*: string
    defaultPowerOffType*: string
    defaultSuspendType*: string
    defaultResetType*: string
    standbyAction*: string

type
  EVCUnsupportedByHostSoftware* = ref object of EVCConfigFault
    host*: seq[HostSystem]
    hostName*: seq[string]

type
  CannotPowerOffVmInCluster* = ref object of InvalidState
    operation*: string
    vm*: VirtualMachine
    vmName*: string

type
  DvsDropNetworkRuleAction* = ref object of DvsNetworkRuleAction
  
type
  HostDasEvent* = ref object of HostEvent
  
type
  HostDVSConfigSpec* = ref object of DynamicData
    uuid*: string
    name*: string
    switchIpAddress*: string
    uplinkPortgroupKey*: seq[string]
    uplinkPortKey*: seq[string]
    modifyVendorSpecificDvsConfig*: bool
    vendorSpecificDvsConfig*: seq[DistributedVirtualSwitchKeyedOpaqueBlob]
    backing*: DistributedVirtualSwitchHostMemberBacking
    maxProxySwitchPorts*: int
    modifyVendorSpecificHostMemberConfig*: bool
    vendorSpecificHostMemberConfig*: seq[DistributedVirtualSwitchKeyedOpaqueBlob]
    healthCheckConfig*: seq[DVSHealthCheckConfig]
    vmwareSetting*: HostDVSVmwareConfigSpec
    enableNetworkResourceManagement*: bool
    networkResourcePoolKeys*: seq[string]
    uplinkPortResourceSpec*: seq[UplinkPortResourceSpec]
    hostInfrastructureTrafficResource*: seq[DvsHostInfrastructureTrafficResource]
    dynamicHostInfrastructureTrafficResource*: seq[DvsHostInfrastructureTrafficResource]
    networkResourceControlVersion*: string
    pnicCapacityRatioForReservation*: int
    status*: string
    statusDetail*: string
    keyedOpaqueDataList*: DVSKeyedOpaqueDataList
    hostOpaqueDataList*: DVSOpaqueDataList
    dvsOpaqueDataList*: DVSOpaqueDataList
    extraConfig*: seq[KeyValue]

type
  DiagnosticPartitionStorageType* {.pure.} = enum
    directAttached, networkAttached
type
  HostProxySwitchConfig* = ref object of DynamicData
    changeOperation*: string
    uuid*: string
    spec*: HostProxySwitchSpec

type
  PerformanceManagerCounterLevelMapping* = ref object of DynamicData
    counterId*: int
    aggregateLevel*: int
    perDeviceLevel*: int

type
  DrsRecommendationReasonCode* {.pure.} = enum
    fairnessCpuAvg, fairnessMemAvg, jointAffin, antiAffin, hostMaint
type
  DataProviderOptionalPropertyValue* = ref object of DynamicData
    value*: pointer

type
  VirtualUSBXHCIControllerOption* = ref object of VirtualControllerOption
    autoConnectDevices*: BoolOption
    supportedSpeeds*: seq[string]

type
  HostCryptoState* {.pure.} = enum
    incapable, prepared, safe
type
  CustomizationFixedIp* = ref object of CustomizationIpGenerator
    ipAddress*: string

type
  ProfileConfigInfo* = ref object of DynamicData
    name*: string
    annotation*: string
    enabled*: bool

type
  GuestWindowsFileAttributes* = ref object of GuestFileAttributes
    hidden*: bool
    readOnly*: bool
    createTime*: string

type
  DVSOpaqueDataConfigInfo* = ref object of DynamicData
    dvsUuid*: string
    portKey*: string
    portgroupKey*: string
    host*: HostSystem
    keyedOpaqueData*: seq[DVSKeyedOpaqueData]

type
  HostSystemInfo* = ref object of DynamicData
    vendor*: string
    model*: string
    uuid*: string
    otherIdentifyingInfo*: seq[HostSystemIdentificationInfo]
    serialNumber*: string

type
  SystemEventInfo* = ref object of DynamicData
    recordId*: int64
    when*: string
    selType*: int64
    message*: string
    sensorNumber*: int64

type
  AnswerFileOptionsCreateSpec* = ref object of AnswerFileCreateSpec
    userInput*: seq[ProfileDeferredPolicyOptionParameter]

type
  VmBeingClonedEvent* = ref object of VmCloneEvent
    destFolder*: FolderEventArgument
    destName*: string
    destHost*: HostEventArgument

type
  MissingIpPool* = ref object of VAppPropertyFault
  
type
  VmConfigMissingEvent* = ref object of VmEvent
  
type
  VirtualVmxnet* = ref object of VirtualEthernetCard
  
type
  VirtualSerialPortPipeBackingInfo* = ref object of VirtualDevicePipeBackingInfo
    endpoint*: string
    noRxLoss*: bool

type
  VirtualSIOController* = ref object of VirtualController
  
type
  FaultToleranceVMConfigSpec* = ref object of DynamicData
    vmConfig*: Datastore
    disks*: seq[FaultToleranceDiskSpec]

type
  OvfWrongNamespace* = ref object of OvfInvalidPackage
    namespaceName*: string

type
  VirtualMachineVMCIDeviceFilterInfo* = ref object of DynamicData
    filters*: seq[VirtualMachineVMCIDeviceFilterSpec]

type
  ExtendedEvent* = ref object of GeneralEvent
    eventTypeId*: string
    managedObject*: ManagedObject
    data*: seq[ExtendedEventPair]

type
  ComputeResourceEventArgument* = ref object of EntityEventArgument
    computeResource*: ComputeResource

type
  VirtualMachineDefaultProfileSpec* = ref object of VirtualMachineProfileSpec
  
type
  DiskTooSmall* = ref object of VsanDiskFault
  
type
  VirtualMachineDefinedProfileSpec* = ref object of VirtualMachineProfileSpec
    profileId*: string
    replicationSpec*: ReplicationSpec
    profileData*: VirtualMachineProfileRawData
    profileParams*: seq[KeyValue]

type
  VmUnsupportedStartingEvent* = ref object of VmStartingEvent
    guestId*: string

type
  MonthlyByDayTaskScheduler* = ref object of MonthlyTaskScheduler
    day*: int

type
  PhysicalNicResourcePoolSchedulerDisallowedReason* {.pure.} = enum
    userOptOut, hardwareUnsupported
type
  SharesOption* = ref object of DynamicData
    sharesOption*: IntOption
    defaultLevel*: SharesLevel

type
  LicenseAssignmentManagerLicenseAssignment* = ref object of DynamicData
    entityId*: string
    scope*: string
    entityDisplayName*: string
    assignedLicense*: LicenseManagerLicenseInfo
    properties*: seq[KeyAnyValue]

type
  VirtualSCSIPassthrough* = ref object of VirtualDevice
  
type
  ServiceEndpoint* = ref object of DynamicData
    key*: string
    instanceUuid*: string
    instanceName*: string
    vcInstanceId*: int
    protocol*: string
    url*: string
    sslThumbprint*: string
    certificate*: string

type
  EventEx* = ref object of Event
    eventTypeId*: string
    severity*: string
    message*: string
    arguments*: seq[KeyAnyValue]
    objectId*: string
    objectType*: string
    objectName*: string
    fault*: MethodFault

type
  VirtualCdromRemotePassthroughBackingInfo* = ref object of VirtualDeviceRemoteDeviceBackingInfo
    exclusive*: bool

type
  MigrationWarningEvent* = ref object of MigrationEvent
  
type
  DvsUpgradeInProgressEvent* = ref object of DvsEvent
    productInfo*: DistributedVirtualSwitchProductSpec

type
  VmResourcePoolMovedEvent* = ref object of VmEvent
    oldParent*: ResourcePoolEventArgument
    newParent*: ResourcePoolEventArgument

type
  InsufficientDisks* = ref object of VsanDiskFault
  
type
  VramLimitLicense* = ref object of NotEnoughLicenses
    limit*: int

type
  VirtualMachineAppHeartbeatStatusType* {.pure.} = enum
    appStatusGray, appStatusGreen, appStatusRed
type
  VspanPortMoveFault* = ref object of DvsFault
    srcPortgroupName*: string
    destPortgroupName*: string
    portKey*: string

type
  VStorageObjectSnapshotDetails* = ref object of DynamicData
    path*: string
    changedBlockTrackingId*: string

type
  VirtualMachineWindowsQuiesceSpec* = ref object of VirtualMachineGuestQuiesceSpec
    vssBackupType*: int
    vssBootableSystemState*: bool
    vssPartialFileSupport*: bool
    vssBackupContext*: string

type
  HostDatastoreBrowserSearchSpec* = ref object of DynamicData
    query*: seq[FileQuery]
    details*: FileQueryFlags
    searchCaseInsensitive*: bool
    matchPattern*: seq[string]
    sortFoldersFirst*: bool

type
  PolicyViolatedValueCannotEqual* = ref object of PolicyViolatedByValue
    policyValue*: pointer

type
  VASAStorageArray* = ref object of DynamicData
    name*: string
    uuid*: string
    vendorId*: string
    modelId*: string

type
  UplinkPortMtuSupportEvent* = ref object of DvsHealthStatusChangeEvent
  
type
  NetBIOSConfigInfoMode* {.pure.} = enum
    unknown, enabled, disabled, enabledViaDHCP
type
  VirtualMachineScsiPassthroughType* {.pure.} = enum
    disk, tape, printer, processor, worm, cdrom, scanner, optical, media, com, raid,
    unknown
type
  VimVasaProviderInfo* = ref object of DynamicData
    provider*: VimVasaProvider
    arrayState*: seq[VimVasaProviderStatePerArray]

type
  HostVirtualSwitch* = ref object of DynamicData
    name*: string
    key*: string
    numPorts*: int
    numPortsAvailable*: int
    mtu*: int
    portgroup*: seq[HostPortGroup]
    pnic*: seq[PhysicalNic]
    spec*: HostVirtualSwitchSpec

type
  DistributedVirtualSwitchNetworkResourceControlVersion* {.pure.} = enum
    version2, version3
type
  BaseConfigInfoDiskFileBackingInfo* = ref object of BaseConfigInfoFileBackingInfo
    provisioningType*: string

type
  LogBundlingFailed* = ref object of VimFault
  
type
  WipeDiskFault* = ref object of VimFault
  
type
  UserDirectory* = ref object of vmodl.ManagedObject
    domainList*: seq[string]

type
  HostSpecificationManager* = ref object of vmodl.ManagedObject
  
type
  IntPolicy* = ref object of InheritablePolicy
    value*: int

type
  LargeRDMConversionNotSupported* = ref object of MigrationFault
    device*: string

type
  EventCategory* {.pure.} = enum
    info, warning, error, user
type
  DataProviderSortCriterion* = ref object of DynamicData
    property*: string
    sortDirection*: string
    ignoreCase*: bool

type
  VirtualDiskCompatibilityMode* {.pure.} = enum
    virtualMode, physicalMode
type
  ClusterComputeResourceFtCompatibilityResult* = ref object of DynamicData
    errors*: seq[MethodFault]
    warnings*: seq[MethodFault]

type
  ToolsUpgradeCancelled* = ref object of VmToolsUpgradeFault
  
type
  VmUuidAssignedEvent* = ref object of VmEvent
    uuid*: string

type
  ToolsConfigInfoToolsLastInstallInfo* = ref object of DynamicData
    counter*: int
    fault*: MethodFault

type
  CustomizationDhcpIpV6Generator* = ref object of CustomizationIpV6Generator
  
type
  ComplianceResultStatus* {.pure.} = enum
    compliant, nonCompliant, unknown, running
type
  StorageDrsRelocateDisabled* = ref object of VimFault
  
type
  CustomizationWinOptions* = ref object of CustomizationOptions
    changeSID*: bool
    deleteAccounts*: bool
    reboot*: CustomizationSysprepRebootOption

type
  HostImageAcceptanceLevel* {.pure.} = enum
    vmware_certified, vmware_accepted, partner, community
type
  UnsupportedDatastore* = ref object of VmConfigFault
    datastore*: Datastore

type
  WorkflowStepHandlerInfo* = ref object of DynamicData
    serviceKey*: string
    handler*: WorkflowStepHandler

type
  VMwareDVSTeamingHealthCheckResult* = ref object of HostMemberHealthCheckResult
    teamingStatus*: string

type
  LicenseManager* = ref object of vmodl.ManagedObject
    source*: LicenseSource
    sourceAvailable*: bool
    diagnostics*: LicenseDiagnostics
    featureInfo*: seq[LicenseFeatureInfo]
    licensedEdition*: string
    licenses*: seq[LicenseManagerLicenseInfo]
    licenseAssignmentManager*: LicenseAssignmentManager
    evaluation*: LicenseManagerEvaluationInfo

type
  VirtualMachineBootOptions* = ref object of DynamicData
    bootDelay*: int64
    enterBIOSSetup*: bool
    efiSecureBootEnabled*: bool
    bootRetryEnabled*: bool
    bootRetryDelay*: int64
    bootOrder*: seq[VirtualMachineBootOptionsBootableDevice]
    networkBootProtocol*: string

type
  VirtualDevicePciBusSlotInfo* = ref object of VirtualDeviceBusSlotInfo
    pciSlotNumber*: int

type
  FaultToleranceCannotEditMem* = ref object of VmConfigFault
    vmName*: string
    vm*: VirtualMachine

type
  VmfsDatastoreSpec* = ref object of DynamicData
    diskUuid*: string

type
  NasDatastoreInfo* = ref object of DatastoreInfo
    nas*: HostNasVolume

type
  HostFirewallRulesetRulesetSpec* = ref object of DynamicData
    allowedHosts*: HostFirewallRulesetIpList

type
  VirtualMachinePowerPolicyPowerMode* {.pure.} = enum
    batteryPower, acPower
type
  ResourceNotAvailable* = ref object of VimFault
    containerType*: string
    containerName*: string
    type*: string

type
  VspanPromiscuousPortNotSupported* = ref object of DvsFault
    vspanSessionKey*: string
    portKey*: string

type
  CustomFieldDefAddedEvent* = ref object of CustomFieldDefEvent
  
type
  NotSupportedHost* = ref object of HostConnectFault
    productName*: string
    productVersion*: string

type
  HostBlockHba* = ref object of HostHostBusAdapter
  
type
  HostTelemetryPaginationSpec* = ref object of DynamicData
    offset*: int
    limit*: int

type
  VirtualParallelPortOption* = ref object of VirtualDeviceOption
  
type
  LocalDatastoreInfo* = ref object of DatastoreInfo
    path*: string

type
  HostSystemReconnectSpec* = ref object of DynamicData
    syncState*: bool

type
  ServiceLocatorSAMLCredential* = ref object of ServiceLocatorCredential
    token*: string

type
  UsbScanCodeSpecModifierType* = ref object of DynamicData
    leftControl*: bool
    leftShift*: bool
    leftAlt*: bool
    leftGui*: bool
    rightControl*: bool
    rightShift*: bool
    rightAlt*: bool
    rightGui*: bool

type
  VirtualMachineConsolePreferences* = ref object of DynamicData
    powerOnWhenOpened*: bool
    enterFullScreenOnPowerOn*: bool
    closeOnPowerOffOrSuspend*: bool

type
  CbrcDigestRuntimeInfo* = ref object of DynamicData
    inUse*: bool

type
  LicenseReservationInfoState* {.pure.} = enum
    notUsed, noLicense, unlicensedUse, licensed
type
  HostParallelScsiHba* = ref object of HostHostBusAdapter
  
type
  IpAddress* = ref object of NegatableExpression
  
type
  EsxAgentConfigManagerAgentVmInfo* = ref object of DynamicData
    agentVm*: VirtualMachine
    state*: string

type
  InventoryHasStandardAloneHosts* = ref object of NotEnoughLicenses
    hosts*: seq[string]

type
  HostSpecificationUpdateEvent* = ref object of HostEvent
    hostSpec*: HostSpecification

type
  InvalidIpfixConfig* = ref object of DvsFault
    property*: string

type
  RDMPointsToInaccessibleDisk* = ref object of CannotAccessVmDisk
  
type
  NoPeerHostFound* = ref object of HostPowerOpFailed
  
type
  LicenseAssignmentManagerEntityFeaturePair* = ref object of DynamicData
    entityId*: string
    feature*: string

type
  IncompatibleSetting* = ref object of InvalidArgument
    conflictingProperty*: string

type
  ClusterDrsFaultsFaultsByVm* = ref object of DynamicData
    vm*: VirtualMachine
    fault*: seq[MethodFault]

type
  OvfConsumerFault* = ref object of OvfConsumerCallbackFault
    errorKey*: string
    message*: string
    params*: seq[KeyValue]

type
  VVolHostPE* = ref object of DynamicData
    key*: HostSystem
    protocolEndpoint*: seq[HostProtocolEndpoint]

type
  InvalidIpmiMacAddress* = ref object of VimFault
    userProvidedMacAddress*: string
    observedMacAddress*: string

type
  VirtualDiskBlocksNotFullyProvisioned* = ref object of DeviceBackingNotSupported
  
type
  TaskReasonSchedule* = ref object of TaskReason
    name*: string
    scheduledTask*: ScheduledTask

type
  VsanIncompatibleDiskMapping* = ref object of VsanDiskFault
  
type
  VmfsDatastoreExpandSpec* = ref object of VmfsDatastoreSpec
    partition*: HostDiskPartitionSpec
    extent*: HostScsiDiskPartition

type
  PerfMetricId* = ref object of DynamicData
    counterId*: int
    instance*: string

type
  DVSNetworkResourcePoolAllocationInfo* = ref object of DynamicData
    limit*: int64
    shares*: SharesInfo
    priorityTag*: int

type
  CAMServerRefusedConnection* = ref object of InvalidCAMServer
  
type
  ClusterVmComponentProtectionSettingsStorageVmReaction* {.pure.} = enum
    disabled, warning, restartConservative, restartAggressive, clusterDefault
type
  NamePasswordAuthentication* = ref object of GuestAuthentication
    username*: string
    password*: string

type
  IscsiMigrationDependency* = ref object of DynamicData
    migrationAllowed*: bool
    disallowReason*: IscsiStatus
    dependency*: seq[IscsiDependencyEntity]

type
  ProfileDescription* = ref object of DynamicData
    section*: seq[ProfileDescriptionSection]

type
  LicenseNonComplianceEvent* = ref object of LicenseEvent
    url*: string

type
  HttpNfcLeaseManifestEntryChecksumType* {.pure.} = enum
    sha1, sha256
type
  LicenseDataManagerLicenseKeyEntry* = ref object of DynamicData
    key*: string
    value*: string

type
  OvfConsumerOvfSection* = ref object of DynamicData
    lineNumber*: int
    xml*: string

type
  VirtualMachineGuestOsIdentifier* {.pure.} = enum
    dosGuest, win31Guest, win95Guest, win98Guest, winMeGuest, winNTGuest,
    win2000ProGuest, win2000ServGuest, win2000AdvServGuest, winXPHomeGuest,
    winXPProGuest, winXPPro64Guest, winNetWebGuest, winNetStandardGuest,
    winNetEnterpriseGuest, winNetDatacenterGuest, winNetBusinessGuest,
    winNetStandard64Guest, winNetEnterprise64Guest, winLonghornGuest,
    winLonghorn64Guest, winNetDatacenter64Guest, winVistaGuest, winVista64Guest,
    windows7Guest, windows7_64Guest, windows7Server64Guest, windows8Guest,
    windows8_64Guest, windows8Server64Guest, windows9Guest, windows9_64Guest,
    windows9Server64Guest, windowsHyperVGuest, freebsdGuest, freebsd64Guest,
    freebsd11Guest, freebsd11_64Guest, freebsd12Guest, freebsd12_64Guest,
    redhatGuest, rhel2Guest, rhel3Guest, rhel3_64Guest, rhel4Guest, rhel4_64Guest,
    rhel5Guest, rhel5_64Guest, rhel6Guest, rhel6_64Guest, rhel7Guest, rhel7_64Guest,
    rhel8_64Guest, centosGuest, centos64Guest, centos6Guest, centos6_64Guest,
    centos7Guest, centos7_64Guest, centos8_64Guest, oracleLinuxGuest,
    oracleLinux64Guest, oracleLinux6Guest, oracleLinux6_64Guest, oracleLinux7Guest,
    oracleLinux7_64Guest, oracleLinux8_64Guest, suseGuest, suse64Guest, slesGuest,
    sles64Guest, sles10Guest, sles10_64Guest, sles11Guest, sles11_64Guest,
    sles12Guest, sles12_64Guest, sles15_64Guest, nld9Guest, oesGuest, sjdsGuest,
    mandrakeGuest, mandrivaGuest, mandriva64Guest, turboLinuxGuest,
    turboLinux64Guest, ubuntuGuest, ubuntu64Guest, debian4Guest, debian4_64Guest,
    debian5Guest, debian5_64Guest, debian6Guest, debian6_64Guest, debian7Guest,
    debian7_64Guest, debian8Guest, debian8_64Guest, debian9Guest, debian9_64Guest,
    debian10Guest, debian10_64Guest, asianux3Guest, asianux3_64Guest, asianux4Guest,
    asianux4_64Guest, asianux5_64Guest, asianux7_64Guest, asianux8_64Guest,
    opensuseGuest, opensuse64Guest, fedoraGuest, fedora64Guest, coreos64Guest,
    vmwarePhoton64Guest, other24xLinuxGuest, other26xLinuxGuest, otherLinuxGuest,
    other3xLinuxGuest, other4xLinuxGuest, genericLinuxGuest, other24xLinux64Guest,
    other26xLinux64Guest, other3xLinux64Guest, other4xLinux64Guest,
    otherLinux64Guest, solaris6Guest, solaris7Guest, solaris8Guest, solaris9Guest,
    solaris10Guest, solaris10_64Guest, solaris11_64Guest, os2Guest,
    eComStationGuest, eComStation2Guest, netware4Guest, netware5Guest,
    netware6Guest, openServer5Guest, openServer6Guest, unixWare7Guest, darwinGuest,
    darwin64Guest, darwin10Guest, darwin10_64Guest, darwin11Guest, darwin11_64Guest,
    darwin12_64Guest, darwin13_64Guest, darwin14_64Guest, darwin15_64Guest,
    darwin16_64Guest, darwin17_64Guest, darwin18_64Guest, vmkernelGuest,
    vmkernel5Guest, vmkernel6Guest, vmkernel65Guest, otherGuest, otherGuest64
type
  HostPatchManagerPatchManagerOperationSpec* = ref object of DynamicData
    proxy*: string
    port*: int
    userName*: string
    password*: string
    cmdOption*: string

type
  SoftRuleVioCorrectionDisallowed* = ref object of VmConfigFault
    vmName*: string

type
  OpaqueNetworkTargetInfo* = ref object of VirtualMachineTargetInfo
    network*: OpaqueNetworkSummary
    networkReservationSupported*: bool

type
  VirtualMachineFileLayoutEx* = ref object of DynamicData
    file*: seq[VirtualMachineFileLayoutExFileInfo]
    disk*: seq[VirtualMachineFileLayoutExDiskLayout]
    snapshot*: seq[VirtualMachineFileLayoutExSnapshotLayout]
    timestamp*: string

type
  VirtualMachineSriovInfo* = ref object of VirtualMachinePciPassthroughInfo
    virtualFunction*: bool
    pnic*: string
    devicePool*: VirtualMachineSriovDevicePoolInfo

type
  HostCpuPowerManagementInfo* = ref object of DynamicData
    currentPolicy*: string
    hardwareSupport*: string

type
  ClusterConfigSpec* = ref object of DynamicData
    dasConfig*: ClusterDasConfigInfo
    dasVmConfigSpec*: seq[ClusterDasVmConfigSpec]
    drsConfig*: ClusterDrsConfigInfo
    drsVmConfigSpec*: seq[ClusterDrsVmConfigSpec]
    rulesSpec*: seq[ClusterRuleSpec]

type
  VmMigratedEvent* = ref object of VmEvent
    sourceHost*: HostEventArgument
    sourceDatacenter*: DatacenterEventArgument
    sourceDatastore*: DatastoreEventArgument

type
  HostVsanInternalSystemCmmdsQuery* = ref object of DynamicData
    type*: string
    uuid*: string
    owner*: string

type
  NotAuthenticated* = ref object of NoPermission
  
type
  UnsupportedGuest* = ref object of InvalidVmConfig
    unsupportedGuestOS*: string

type
  StorageIORMConfigOption* = ref object of DynamicData
    enabledOption*: BoolOption
    congestionThresholdOption*: IntOption
    statsCollectionEnabledOption*: BoolOption
    reservationEnabledOption*: BoolOption

type
  StorageDrsSpaceLoadBalanceConfig* = ref object of DynamicData
    spaceThresholdMode*: string
    spaceUtilizationThreshold*: int
    freeSpaceThresholdGB*: int
    minSpaceUtilizationDifference*: int

type
  VirtualCdromIsoBackingOption* = ref object of VirtualDeviceFileBackingOption
  
type
  VmMonitorIncompatibleForFaultTolerance* = ref object of VimFault
  
type
  VirtualMachineNetworkInfo* = ref object of VirtualMachineTargetInfo
    network*: NetworkSummary
    vswitch*: string

type
  InvalidDasConfigArgumentEntryForInvalidArgument* {.pure.} = enum
    admissionControl, userHeartbeatDs, vmConfig
type
  ClusterEnterMaintenanceResult* = ref object of DynamicData
    recommendations*: seq[ClusterRecommendation]
    fault*: ClusterDrsFaults

type
  HostPowerOpFailed* = ref object of VimFault
  
type
  VmNvramFileInfo* = ref object of FileInfo
  
type
  FibreChannelPortType* {.pure.} = enum
    fabric, loop, pointToPoint, unknown
type
  CompositePolicyOption* = ref object of PolicyOption
    option*: seq[PolicyOption]

type
  VirtualEthernetCardDistributedVirtualPortBackingInfo* = ref object of VirtualDeviceBackingInfo
    port*: DistributedVirtualSwitchPortConnection

type
  VmConfigSpec* = ref object of DynamicData
    product*: seq[VAppProductSpec]
    property*: seq[VAppPropertySpec]
    ipAssignment*: VAppIPAssignmentInfo
    eula*: seq[string]
    ovfSection*: seq[VAppOvfSectionSpec]
    ovfEnvironmentTransport*: seq[string]
    installBootRequired*: bool
    installBootStopDelay*: int

type
  ClusterDasVmConfigSpec* = ref object of ArrayUpdateSpec
    info*: ClusterDasVmConfigInfo

type
  CustomizationPassword* = ref object of DynamicData
    value*: string
    plainText*: bool

type
  CannotMoveFaultToleranceVmMoveType* {.pure.} = enum
    resourcePool, cluster
type
  DistributedVirtualSwitchManagerHostArrayFilter* = ref object of DistributedVirtualSwitchManagerHostDvsFilterSpec
    host*: seq[HostSystem]

type
  HostTpmManagerKeyParams* = ref object of DynamicData
    algorithmID*: int
    encScheme*: int
    sigScheme*: int
    params*: seq[byte]

type
  UsbScanCodeSpecKeyEvent* = ref object of DynamicData
    usbHidCode*: int
    modifiers*: UsbScanCodeSpecModifierType

type
  CustomizationOptions* = ref object of DynamicData
  
type
  NetworkManager* = ref object of vmodl.ManagedObject
  
type
  VirtualPCNet32* = ref object of VirtualEthernetCard
  
type
  DisabledMethodInfo* = ref object of DynamicData
    method*: string
    sources*: seq[DisabledMethodSource]

type
  VFlashCacheHotConfigNotSupported* = ref object of VmConfigFault
  
type
  HttpNfcLeaseState* {.pure.} = enum
    initializing, ready, done, error
type
  VmMetadataManagerFault* = ref object of VimFault
  
type
  VMwareDVSFeatureCapability* = ref object of DVSFeatureCapability
    vspanSupported*: bool
    lldpSupported*: bool
    ipfixSupported*: bool
    ipfixCapability*: VMwareDvsIpfixCapability
    multicastSnoopingSupported*: bool
    vspanCapability*: VMwareDVSVspanCapability
    lacpCapability*: VMwareDvsLacpCapability

type
  SSPIChallenge* = ref object of VimFault
    base64Token*: string

type
  HostTelemetryManager* = ref object of vmodl.ManagedObject
  
type
  OvfManagerCommonParams* = ref object of DynamicData
    locale*: string
    deploymentOption*: string
    msgBundle*: seq[KeyValue]
    importOption*: seq[string]

type
  Extension* = ref object of DynamicData
    description*: Description
    key*: string
    company*: string
    type*: string
    version*: string
    subjectName*: string
    server*: seq[ExtensionServerInfo]
    client*: seq[ExtensionClientInfo]
    taskList*: seq[ExtensionTaskTypeInfo]
    eventList*: seq[ExtensionEventTypeInfo]
    faultList*: seq[ExtensionFaultTypeInfo]
    privilegeList*: seq[ExtensionPrivilegeInfo]
    resourceList*: seq[ExtensionResourceInfo]
    lastHeartbeatTime*: string
    healthInfo*: ExtensionHealthInfo
    ovfConsumerInfo*: ExtensionOvfConsumerInfo
    extendedProductInfo*: ExtExtendedProductInfo
    managedEntityInfo*: seq[ExtManagedEntityInfo]
    shownInSolutionManager*: bool
    solutionManagerInfo*: ExtSolutionManagerInfo

type
  HostKernelModuleSystem* = ref object of vmodl.ManagedObject
  
type
  ProfileProfileStructure* = ref object of DynamicData
    profileTypeName*: string
    child*: seq[ProfileProfileStructureProperty]
    mapping*: seq[HostProfileMapping]

type
  ClusterDrsFaults* = ref object of DynamicData
    reason*: string
    faultsByVm*: seq[ClusterDrsFaultsFaultsByVm]

type
  HostSystemSwapConfigurationHostLocalSwapOption* = ref object of HostSystemSwapConfigurationSystemSwapOption
  
type
  HostHyperThreadScheduleInfo* = ref object of DynamicData
    available*: bool
    active*: bool
    config*: bool

type
  ClusterDasVmConfigInfo* = ref object of DynamicData
    key*: VirtualMachine
    restartPriority*: DasVmPriority
    powerOffOnIsolation*: bool
    dasSettings*: ClusterDasVmSettings

type
  PhysicalNic* = ref object of DynamicData
    key*: string
    device*: string
    pci*: string
    driver*: string
    linkSpeed*: PhysicalNicLinkInfo
    validLinkSpecification*: seq[PhysicalNicLinkInfo]
    spec*: PhysicalNicSpec
    wakeOnLanSupported*: bool
    mac*: string
    fcoeConfiguration*: FcoeConfig
    vmDirectPathGen2Supported*: bool
    vmDirectPathGen2SupportedMode*: string
    resourcePoolSchedulerAllowed*: bool
    resourcePoolSchedulerDisallowedReason*: seq[string]
    autoNegotiateSupported*: bool
    enhancedNetworkingStackSupported*: bool

type
  FileBackedVirtualDiskSpec* = ref object of VirtualDiskSpec
    capacityKb*: int64
    profile*: seq[VirtualMachineProfileSpec]
    crypto*: CryptoSpec

type
  DVSCreateSpec* = ref object of DynamicData
    configSpec*: DVSConfigSpec
    productInfo*: DistributedVirtualSwitchProductSpec
    capability*: DVSCapability

type
  HostDateTimeSystem* = ref object of vmodl.ManagedObject
    dateTimeInfo*: HostDateTimeInfo

type
  PatchMetadataInvalid* = ref object of VimFault
    patchID*: string
    metaData*: seq[string]

type
  HostComplianceCheckedEvent* = ref object of HostEvent
    profile*: ProfileEventArgument

type
  DVPortgroupDestroyedEvent* = ref object of DVPortgroupEvent
  
type
  VmVnicPoolReservationViolationRaiseEvent* = ref object of DvsEvent
    vmVnicResourcePoolKey*: string
    vmVnicResourcePoolName*: string

type
  ClusterVersionedBinaryData* = ref object of DynamicData
    version*: int64
    data*: byte

type
  DeviceUnsupportedForVmPlatform* = ref object of InvalidDeviceSpec
  
type
  StorageIOAllocationOption* = ref object of DynamicData
    limitOption*: LongOption
    sharesOption*: SharesOption

type
  HttpNfcLeaseDeviceUrl* = ref object of DynamicData
    key*: string
    importKey*: string
    url*: string
    sslThumbprint*: string
    disk*: bool
    targetId*: string
    datastoreKey*: string
    fileSize*: int64

type
  VStorageObjectStateInfo* = ref object of DynamicData
    tentative*: bool

type
  FaultToleranceConfigInfo* = ref object of DynamicData
    role*: int
    instanceUuids*: seq[string]
    configPaths*: seq[string]
    orphaned*: bool

type
  HostSystemRemediationStateState* {.pure.} = enum
    remediationReady, precheckRemediationRunning, precheckRemediationComplete,
    precheckRemediationFailed, remediationRunning, remediationFailed
type
  ProfileHostProfileEngineHostProfileEngine* = ref object of DynamicData
    hostProfileManager*: ProfileHostProfileEngineHostProfileManager
    hostComplianceManager*: ProfileHostProfileEngineComplianceManager

type
  vslmInfrastructureObjectPolicy* = ref object of DynamicData
    name*: string
    backingObjectId*: string
    profileId*: string
    error*: MethodFault

type
  HostAuthenticationStore* = ref object of vmodl.ManagedObject
    info*: HostAuthenticationStoreInfo

type
  HostInternetScsiHbaIPv6Properties* = ref object of DynamicData
    iscsiIpv6Address*: seq[HostInternetScsiHbaIscsiIpv6Address]
    ipv6DhcpConfigurationEnabled*: bool
    ipv6LinkLocalAutoConfigurationEnabled*: bool
    ipv6RouterAdvertisementConfigurationEnabled*: bool
    ipv6DefaultGateway*: string

type
  HostTpmManagerEncryptedBlob* = ref object of DynamicData
    asymAlgorithm*: HostTpmManagerKeyParams
    symAlgorithm*: HostTpmManagerKeyParams
    asymBlob*: seq[byte]
    symBlob*: seq[byte]

type
  NetIpRouteConfigSpec* = ref object of DynamicData
    ipRoute*: seq[NetIpRouteConfigSpecIpRouteSpec]

type
  ScsiLun* = ref object of HostDevice
    key*: string
    uuid*: string
    descriptor*: seq[ScsiLunDescriptor]
    canonicalName*: string
    displayName*: string
    lunType*: string
    vendor*: string
    model*: string
    revision*: string
    scsiLevel*: int
    serialNumber*: string
    durableName*: ScsiLunDurableName
    alternateName*: seq[ScsiLunDurableName]
    standardInquiry*: seq[byte]
    queueDepth*: int
    operationalState*: seq[string]
    capabilities*: ScsiLunCapabilities
    vStorageSupport*: string
    protocolEndpoint*: bool

type
  NetIpRouteConfigInfo* = ref object of DynamicData
    ipRoute*: seq[NetIpRouteConfigInfoIpRoute]

type
  DatastoreOption* = ref object of DynamicData
    unsupportedVolumes*: seq[VirtualMachineDatastoreVolumeOption]

type
  VmRemoteConsoleDisconnectedEvent* = ref object of VmEvent
  
type
  VStorageObjectConfigInfo* = ref object of BaseConfigInfo
    capacityInMB*: int64
    consumptionType*: seq[string]
    consumerId*: seq[ID]

type
  RuleViolation* = ref object of VmConfigFault
    host*: HostSystem
    rule*: ClusterRuleInfo

type
  VmMaxRestartCountReached* = ref object of VmEvent
  
type
  UnrecognizedHost* = ref object of VimFault
    hostName*: string

type
  SendEmailAction* = ref object of Action
    toList*: string
    ccList*: string
    subject*: string
    body*: string

type
  VirtualMachineProvisioningChecker* = ref object of vmodl.ManagedObject
  
type
  InsufficientHostCpuCapacityFault* = ref object of InsufficientHostCapacityFault
    unreserved*: int64
    requested*: int64

type
  HostLowLevelProvisioningManagerFileReserveSpec* = ref object of DynamicData
    baseName*: string
    parentDir*: string
    fileType*: string
    storageProfile*: string

type
  HostCnxFailedBadUsernameEvent* = ref object of HostEvent
  
type
  IncompatibleHostForVmReplication* = ref object of ReplicationFault
    vmName*: string
    hostName*: string
    reason*: string

type
  OvfCpuCompatibility* = ref object of OvfImport
    registerName*: string
    level*: int
    registerValue*: string
    desiredRegisterValue*: string

type
  EnteredMaintenanceModeEvent* = ref object of HostEvent
  
type
  HostActiveDirectory* = ref object of DynamicData
    changeOperation*: string
    spec*: HostActiveDirectorySpec

type
  VirtualMachineQuestionInfo* = ref object of DynamicData
    id*: string
    text*: string
    choice*: ChoiceOption
    message*: seq[VirtualMachineMessage]

type
  HostDiskDimensionsLba* = ref object of DynamicData
    blockSize*: int
    block*: int64

type
  HostLocalFileSystemVolumeSpec* = ref object of DynamicData
    device*: string
    localPath*: string

type
  DvsPortEnteredPassthruEvent* = ref object of DvsEvent
    portKey*: string
    runtimeInfo*: DVPortStatus

type
  LinkDiscoveryProtocolConfigOperationType* {.pure.} = enum
    none, listen, advertise, both
type
  NvdimmNamespaceDeleteSpec* = ref object of DynamicData
    uuid*: string

type
  VirtualMachineSnapshot* = ref object of vim.ExtensibleManagedObject
    config*: VirtualMachineConfigInfo
    childSnapshot*: seq[VirtualMachineSnapshot]
    vm*: VirtualMachine

type
  HealthStatusChangedEvent* = ref object of Event
    componentId*: string
    oldStatus*: string
    newStatus*: string
    componentName*: string
    serviceId*: string

type
  DuplicateName* = ref object of VimFault
    name*: string
    object*: ManagedObject

type
  DistributedVirtualSwitchManagerHostContainerFilter* = ref object of DistributedVirtualSwitchManagerHostDvsFilterSpec
    hostContainer*: DistributedVirtualSwitchManagerHostContainer

type
  HostPatchManagerInstallState* {.pure.} = enum
    hostRestarted, imageActive
type
  VsanUpgradeSystemUpgradeHistoryItem* = ref object of DynamicData
    timestamp*: string
    host*: HostSystem
    message*: string
    task*: Task

type
  DomainNotFound* = ref object of ActiveDirectoryFault
    domainName*: string

type
  HostCnxFailedNoLicenseEvent* = ref object of HostEvent
  
type
  LicenseSource* = ref object of DynamicData
  
type
  HostDirectoryStore* = ref object of vim.host.AuthenticationStore
  
type
  MethodAction* = ref object of Action
    name*: string
    argument*: seq[MethodActionArgument]

type
  ClusterVmHostRuleInfo* = ref object of ClusterRuleInfo
    vmGroupName*: string
    affineHostGroupName*: string
    antiAffineHostGroupName*: string

type
  DVSManagerDvsConfigTarget* = ref object of DynamicData
    distributedVirtualPortgroup*: seq[DistributedVirtualPortgroupInfo]
    distributedVirtualSwitch*: seq[DistributedVirtualSwitchInfo]

type
  VAppCloneSpecProvisioningType* {.pure.} = enum
    sameAsSource, thin, thick
type
  VsanHostDiskMapping* = ref object of DynamicData
    ssd*: HostScsiDisk
    nonSsd*: seq[HostScsiDisk]

type
  VirtualVmxnet3VrdmaOption* = ref object of VirtualVmxnet3Option
    deviceProtocol*: ChoiceOption

type
  PatchMissingDependencies* = ref object of PatchNotApplicable
    prerequisitePatch*: seq[string]
    prerequisiteLib*: seq[string]

type
  HostProfileAppliedEvent* = ref object of HostEvent
    profile*: ProfileEventArgument

type
  VspanPortgroupPromiscChangeFault* = ref object of DvsFault
    portgroupName*: string

type
  FaultToleranceNotSameBuild* = ref object of MigrationFault
    build*: string

type
  PatchAlreadyInstalled* = ref object of PatchNotApplicable
  
type
  HostGraphicsConfigDeviceType* = ref object of DynamicData
    deviceId*: string
    graphicsType*: string

type
  VirtualDeviceFileBackingOption* = ref object of VirtualDeviceBackingOption
    fileNameExtensions*: ChoiceOption

type
  ClusterComputeResourceSummary* = ref object of ComputeResourceSummary
    currentFailoverLevel*: int
    admissionControlInfo*: ClusterDasAdmissionControlInfo
    numVmotions*: int
    targetBalance*: int
    currentBalance*: int
    usageSummary*: ClusterUsageSummary
    currentEVCModeKey*: string
    dasData*: ClusterDasData

type
  WarningUpgradeEvent* = ref object of UpgradeEvent
  
type
  ResourceAllocationInfo* = ref object of DynamicData
    reservation*: int64
    expandableReservation*: bool
    limit*: int64
    shares*: SharesInfo
    overheadLimit*: int64

type
  MismatchedVMotionNetworkNames* = ref object of MigrationFault
    sourceNetwork*: string
    destNetwork*: string

type
  CannotAccessLocalSource* = ref object of VimFault
  
type
  GuestRegValueBinarySpec* = ref object of GuestRegValueDataSpec
    value*: byte

type
  ConnectedIso* = ref object of OvfExport
    cdrom*: VirtualCdrom
    filename*: string

type
  MigrationDisabled* = ref object of MigrationFault
  
type
  VmRelayoutUpToDateEvent* = ref object of VmEvent
  
type
  VAppOvfSectionSpec* = ref object of ArrayUpdateSpec
    info*: VAppOvfSectionInfo

type
  StorageDrsDatacentersCannotShareDatastore* = ref object of VimFault
  
type
  HostVMotionManagerVMotionType* {.pure.} = enum
    vmotion, fast_suspend_resume, fault_tolerance, disks_only, memory_mirror,
    instant_clone
type
  StorageDrsHmsMoveInProgress* = ref object of VimFault
  
type
  DvpgImportEvent* = ref object of DVPortgroupEvent
    importType*: string

type
  HostAccessControlEntry* = ref object of DynamicData
    principal*: string
    group*: bool
    accessMode*: HostAccessMode

type
  InvalidBundle* = ref object of PlatformConfigFault
  
type
  DiskChangeInfo* = ref object of DynamicData
    startOffset*: int64
    length*: int64
    changedArea*: seq[DiskChangeExtent]

type
  ManagedEntityStatus* {.pure.} = enum
    gray, green, yellow, red
type
  HostOperationCleanupManagerOperationState* {.pure.} = enum
    running, success, failure
type
  DvsUpgradedEvent* = ref object of DvsEvent
    productInfo*: DistributedVirtualSwitchProductSpec

type
  GuestInfoNamespaceGenerationInfo* = ref object of DynamicData
    key*: string
    generationNo*: int

type
  VirtualSCSIPassthroughDeviceBackingInfo* = ref object of VirtualDeviceDeviceBackingInfo
  
type
  HostGraphicsManager* = ref object of vim.ExtensibleManagedObject
    graphicsInfo*: seq[HostGraphicsInfo]
    graphicsConfig*: HostGraphicsConfig
    sharedPassthruGpuTypes*: seq[string]
    sharedGpuCapabilities*: seq[HostSharedGpuCapabilities]

type
  VirtualHdAudioCardOption* = ref object of VirtualSoundCardOption
  
type
  HostRemovedEvent* = ref object of HostEvent
  
type
  UserInputRequiredParameterMetadata* = ref object of ProfilePolicyOptionMetadata
    userInputParameter*: seq[ProfileParameterMetadata]

type
  VirtualMachineNamespaceManagerEventList* = ref object of DynamicData
    events*: seq[string]
    eventsDropped*: bool

type
  VmDasBeingResetWithScreenshotEvent* = ref object of VmDasBeingResetEvent
    screenshotFilePath*: string

type
  VirtualTPM* = ref object of VirtualDevice
    endorsementKeyCertificateSigningRequest*: seq[byte]
    endorsementKeyCertificate*: seq[byte]

type
  EVCConfigFault* = ref object of VimFault
    faults*: seq[MethodFault]

type
  HostProfileManagerHostProfileMetadata* = ref object of DynamicData
    profileMetadata*: seq[ProfileMetadata]
    profileCategoryMetadata*: seq[ProfileCategoryMetadata]
    profileComponentMetadata*: seq[ProfileComponentMetadata]
    policyMetadata*: seq[ProfilePolicyMetadata]

type
  ProfileHostProfileEngineHostInfo* = ref object of DynamicData
    capability*: HostCapability
    config*: HostConfigInfo
    userAccount*: seq[UserSearchResult]
    portgroupInfo*: seq[ProfileHostProfileEngineDvPortgroupInfo]
    permission*: seq[Permission]
    role*: seq[AuthorizationRole]
    extension*: seq[Extension]
    agentVmDatastoreName*: string
    agentVmNetworkName*: string

type
  CryptoManagerKmip* = ref object of vim.encryption.CryptoManager
    kmipServers*: seq[KmipClusterInfo]

type
  GuestAliasManager* = ref object of vmodl.ManagedObject
  
type
  ClusterRuleSpec* = ref object of ArrayUpdateSpec
    info*: ClusterRuleInfo

type
  AnswerFileUpdateFailure* = ref object of DynamicData
    userInputPath*: ProfilePropertyPath
    errMsg*: LocalizableMessage

type
  HostInternetScsiHbaAuthenticationCapabilities* = ref object of DynamicData
    chapAuthSettable*: bool
    krb5AuthSettable*: bool
    srpAuthSettable*: bool
    spkmAuthSettable*: bool
    mutualChapSettable*: bool
    targetChapSettable*: bool
    targetMutualChapSettable*: bool

type
  InvalidPowerState* = ref object of InvalidState
    requestedState*: VirtualMachinePowerState
    existingState*: VirtualMachinePowerState

type
  VirtualDiskSharing* {.pure.} = enum
    sharingNone, sharingMultiWriter
type
  HostVFlashManager* = ref object of vmodl.ManagedObject
    vFlashConfigInfo*: HostVFlashManagerVFlashConfigInfo

type
  PhysicalNicCdpDeviceCapability* = ref object of DynamicData
    router*: bool
    transparentBridge*: bool
    sourceRouteBridge*: bool
    networkSwitch*: bool
    host*: bool
    igmpEnabled*: bool
    repeater*: bool

type
  VAppCloneSpecNetworkMappingPair* = ref object of DynamicData
    source*: Network
    destination*: Network

type
  HostInternetScsiHbaChapAuthenticationType* {.pure.} = enum
    chapProhibited, chapDiscouraged, chapPreferred, chapRequired
type
  VirtualSATAControllerOption* = ref object of VirtualControllerOption
    numSATADisks*: IntOption
    numSATACdroms*: IntOption

type
  ClusterDrsMigration* = ref object of DynamicData
    key*: string
    time*: string
    vm*: VirtualMachine
    cpuLoad*: int
    memoryLoad*: int64
    source*: HostSystem
    sourceCpuLoad*: int
    sourceMemoryLoad*: int64
    destination*: HostSystem
    destinationCpuLoad*: int
    destinationMemoryLoad*: int64

type
  HostIntegrityReportQuoteInfo* = ref object of DynamicData
    versionMajor*: byte
    versionMinor*: byte
    versionRevMajor*: byte
    versionRevMinor*: byte
    fixed*: string
    digestValue*: seq[byte]
    externalData*: seq[byte]

type
  VmDasResetFailedEvent* = ref object of VmEvent
  
type
  HostCertificateManagerCertificateInfoCertificateStatus* {.pure.} = enum
    unknown, expired, expiring, expiringShortly, expirationImminent, good, revoked
type
  HostProfileMappingProfileMappingData* = ref object of HostProfileMappingData
  
type
  OvfParseDescriptorParams* = ref object of OvfManagerCommonParams
  
type
  VsanHostDiskMapResult* = ref object of DynamicData
    mapping*: VsanHostDiskMapping
    diskResult*: seq[VsanHostDiskResult]
    error*: MethodFault

type
  DasConfigFault* = ref object of VimFault
    reason*: string
    output*: string
    event*: seq[Event]

type
  OvfConstraint* = ref object of OvfInvalidPackage
    name*: string

type
  VirtualEthernetCardLegacyNetworkDeviceName* {.pure.} = enum
    bridged, nat, hostonly
type
  VmWwnConflict* = ref object of InvalidVmConfig
    vm*: VirtualMachine
    host*: HostSystem
    name*: string
    wwn*: int64

type
  RetrieveVStorageObjSpec* = ref object of DynamicData
    id*: ID
    datastore*: Datastore

type
  HostStorageElementInfo* = ref object of HostHardwareElementInfo
    operationalInfo*: seq[HostStorageOperationalInfo]

type
  VMwareVspanSession* = ref object of DynamicData
    key*: string
    name*: string
    description*: string
    enabled*: bool
    sourcePortTransmitted*: VMwareVspanPort
    sourcePortReceived*: VMwareVspanPort
    destinationPort*: VMwareVspanPort
    encapsulationVlanId*: int
    stripOriginalVlan*: bool
    mirroredPacketLength*: int
    normalTrafficAllowed*: bool
    sessionType*: string
    samplingRate*: int
    encapType*: string
    erspanId*: int
    erspanCOS*: int
    erspanGraNanosec*: bool
    netstack*: string

type
  HostDatastoreNameConflictConnectInfo* = ref object of HostDatastoreConnectInfo
    newDatastoreName*: string

type
  VsanHostDiskMapInfo* = ref object of DynamicData
    mapping*: VsanHostDiskMapping
    mounted*: bool

type
  VchaNodeRuntimeInfo* = ref object of DynamicData
    nodeState*: string
    nodeRole*: string
    nodeIp*: string

type
  LinkDiscoveryProtocolConfig* = ref object of DynamicData
    protocol*: string
    operation*: string

type
  OvfHostValueNotParsed* = ref object of OvfSystemFault
    property*: string
    value*: string

type
  HostNumericSensorHealthState* {.pure.} = enum
    unknown, green, yellow, red
type
  StorageIORMInfo* = ref object of DynamicData
    enabled*: bool
    congestionThresholdMode*: string
    congestionThreshold*: int
    percentOfPeakThroughput*: int
    statsCollectionEnabled*: bool
    reservationEnabled*: bool
    statsAggregationDisabled*: bool
    reservableIopsThreshold*: int

type
  VmTimedoutStartingSecondaryEvent* = ref object of VmEvent
    timeout*: int64

type
  HostFileSystemMountInfo* = ref object of DynamicData
    mountInfo*: HostMountInfo
    volume*: HostFileSystemVolume
    vStorageSupport*: string

type
  InvalidVmConfig* = ref object of VmConfigFault
    property*: string

type
  ProfileHostProfileEngineHostProfileManagerProfileComponentMetaArray* = ref object of DynamicData
    profileComponentMeta*: seq[ProfileComponentMetadata]

type
  VmFailedToStandbyGuestEvent* = ref object of VmEvent
    reason*: MethodFault

type
  StorageResourceManager* = ref object of vmodl.ManagedObject
  
type
  StringOption* = ref object of OptionType
    defaultValue*: string
    validCharacters*: string

type
  ClockSkew* = ref object of HostConfigFault
  
type
  TemplateBeingUpgradedEvent* = ref object of TemplateUpgradeEvent
  
type
  HostSnmpSystem* = ref object of vmodl.ManagedObject
    configuration*: HostSnmpConfigSpec
    limits*: HostSnmpSystemAgentLimits

type
  HostSpecificationChangedEvent* = ref object of HostEvent
  
type
  StoragePlacementResult* = ref object of DynamicData
    recommendations*: seq[ClusterRecommendation]
    drsFault*: ClusterDrsFaults
    task*: Task

type
  PhysicalNicProfile* = ref object of ApplyProfile
    key*: string

type
  ExtensionHealthInfo* = ref object of DynamicData
    url*: string

type
  ServiceDirectory* = ref object of vmodl.ManagedObject
    service*: seq[ServiceEndpoint]

type
  VirtualUSBRemoteHostBackingOption* = ref object of VirtualDeviceDeviceBackingOption
  
type
  ProfilePolicy* = ref object of DynamicData
    id*: string
    policyOption*: PolicyOption

type
  GatewayHostNotReachable* = ref object of GatewayToHostConnectFault
  
type
  ArrayUpdateOperation* {.pure.} = enum
    add, remove, edit
type
  FolderEventArgument* = ref object of EntityEventArgument
    folder*: Folder

type
  ComputeResourceHostSPBMLicenseInfoHostSPBMLicenseState* {.pure.} = enum
    licensed, unlicensed, unknown
type
  VrpResourceAllocationInfo* = ref object of ResourceAllocationInfo
    reservationLimit*: int64

type
  AuthorizationManagerRequiredPermission* = ref object of DynamicData
    privilege*: string
    entity*: ManagedEntity

type
  VirtualDiskRuleSpecRuleType* {.pure.} = enum
    affinity, antiAffinity, disabled
type
  LicenseServerSource* = ref object of LicenseSource
    licenseServer*: string

type
  DistributedVirtualSwitchManagerHostContainer* = ref object of DynamicData
    container*: ManagedEntity
    recursive*: bool

type
  VirtualLsiLogicSASController* = ref object of VirtualSCSIController
  
type
  HostInternetScsiHbaDiscoveryCapabilities* = ref object of DynamicData
    iSnsDiscoverySettable*: bool
    slpDiscoverySettable*: bool
    staticTargetDiscoverySettable*: bool
    sendTargetsDiscoverySettable*: bool

type
  ResourcePoolEvent* = ref object of Event
    resourcePool*: ResourcePoolEventArgument

type
  NvdimmNamespaceState* {.pure.} = enum
    invalid, notInUse, inUse
type
  VirtualMachineSriovNetworkDevicePoolInfo* = ref object of VirtualMachineSriovDevicePoolInfo
    switchKey*: string
    switchUuid*: string

type
  EVCAdmissionFailedCPUVendorUnknown* = ref object of EVCAdmissionFailed
  
type
  TypeDescription* = ref object of Description
    key*: string

type
  HostHasComponentFailure* = ref object of VimFault
    hostName*: string
    componentType*: string
    componentName*: string

type
  PerfStatsType* {.pure.} = enum
    absolute, delta, rate
type
  VirtualDeviceURIBackingOption* = ref object of VirtualDeviceBackingOption
    directions*: ChoiceOption

type
  StorageDrsSpaceLoadBalanceConfigSpaceThresholdMode* {.pure.} = enum
    utilization, freeSpace
type
  VFlashModuleVersionIncompatible* = ref object of VimFault
    moduleName*: string
    vmRequestModuleVersion*: string
    hostMinSupportedVerson*: string
    hostModuleVersion*: string

type
  DVSRollbackCapability* = ref object of DynamicData
    rollbackSupported*: bool

type
  VirtualBusLogicControllerOption* = ref object of VirtualSCSIControllerOption
  
type
  FaultToleranceCpuIncompatible* = ref object of CpuIncompatible
    model*: bool
    family*: bool
    stepping*: bool

type
  VMwareUplinkPortOrderPolicy* = ref object of InheritablePolicy
    activeUplinkPort*: seq[string]
    standbyUplinkPort*: seq[string]

type
  OvfAttribute* = ref object of OvfInvalidPackage
    elementName*: string
    attributeName*: string

type
  ContentLibrary* = ref object of vim.ManagedEntity
  
type
  PerfProviderSummary* = ref object of DynamicData
    entity*: ManagedObject
    currentSupported*: bool
    summarySupported*: bool
    refreshRate*: int

type
  AnswerFileValidationResult* = ref object of DynamicData
    status*: string
    error*: seq[AnswerFileUpdateFailure]

type
  Permission* = ref object of DynamicData
    entity*: ManagedEntity
    principal*: string
    group*: bool
    roleId*: int
    propagate*: bool

type
  CustomizationFixedName* = ref object of CustomizationName
    name*: string

type
  InsufficientGraphicsResourcesFault* = ref object of InsufficientResourcesFault
  
type
  HostVMotionInfo* = ref object of DynamicData
    netConfig*: HostVMotionNetConfig
    ipConfig*: HostIpConfig

type
  ProfilePolicyOptionMetadata* = ref object of DynamicData
    id*: ExtendedElementDescription
    parameter*: seq[ProfileParameterMetadata]

type
  VirtualPCIPassthroughPluginBackingOption* = ref object of VirtualDeviceBackingOption
  
type
  ExternalStatsManagerMetricType* {.pure.} = enum
    CpuActivePct, MemoryNonZeroActiveMb
type
  ProfilePropertyPath* = ref object of DynamicData
    profilePath*: string
    policyId*: string
    parameterId*: string
    policyOptionId*: string

type
  HostInternetScsiHbaTargetSet* = ref object of DynamicData
    staticTargets*: seq[HostInternetScsiHbaStaticTarget]
    sendTargets*: seq[HostInternetScsiHbaSendTarget]

type
  VirtualDeviceConnectInfoMigrateConnectOp* {.pure.} = enum
    connect, disconnect, unset
type
  HostNotInClusterEvent* = ref object of HostDasEvent
  
type
  ExtSolutionManagerInfoTabInfo* = ref object of DynamicData
    label*: string
    url*: string

type
  Datastore* = ref object of vim.ManagedEntity
    info*: DatastoreInfo
    summary*: DatastoreSummary
    host*: seq[DatastoreHostMount]
    vm*: seq[VirtualMachine]
    browser*: HostDatastoreBrowser
    capability*: DatastoreCapability
    iormConfiguration*: StorageIORMInfo

type
  DVSHostLocalPortInfo* = ref object of DynamicData
    switchUuid*: string
    portKey*: string
    setting*: DVPortSetting
    vnic*: string

type
  NetIpRouteConfigInfoIpRoute* = ref object of DynamicData
    network*: string
    prefixLength*: int
    gateway*: NetIpRouteConfigInfoGateway

type
  CustomizationCustomIpGenerator* = ref object of CustomizationIpGenerator
    argument*: string

type
  HostStorageSystemScsiLunResult* = ref object of DynamicData
    key*: string
    fault*: MethodFault

type
  OvfConsumerOstNodeType* {.pure.} = enum
    envelope, virtualSystem, virtualSystemCollection
type
  HeterogenousHostsBlockingEVC* = ref object of EVCConfigFault
  
type
  BackupBlobReadFailure* = ref object of DvsFault
    entityName*: string
    entityType*: string
    fault*: MethodFault

type
  CollectorAddressUnset* = ref object of DvsFault
  
type
  DVSBackupRestoreCapability* = ref object of DynamicData
    backupRestoreSupported*: bool

type
  VMOnConflictDVPort* = ref object of CannotAccessNetwork
  
type
  VirtualMachineNamespaceManagerDataSpecOpCode* {.pure.} = enum
    updateAlways, updateIfEqual
type
  VirtualMachineBootOptionsBootableEthernetDevice* = ref object of VirtualMachineBootOptionsBootableDevice
    deviceKey*: int

type
  VirtualHardwareCompatibilityIssue* = ref object of VmConfigFault
  
type
  OpaqueNetworkSummary* = ref object of NetworkSummary
    opaqueNetworkId*: string
    opaqueNetworkType*: string

type
  HostCapabilityUnmapMethodSupported* {.pure.} = enum
    priority, fixed, dynamic
type
  DistributedVirtualSwitchHostMemberConfigSpec* = ref object of DynamicData
    operation*: string
    host*: HostSystem
    backing*: DistributedVirtualSwitchHostMemberBacking
    maxProxySwitchPorts*: int
    vendorSpecificConfig*: seq[DistributedVirtualSwitchKeyedOpaqueBlob]

type
  VchaClusterNetworkSpec* = ref object of DynamicData
    witnessNetworkSpec*: NodeNetworkSpec
    passiveNetworkSpec*: PassiveNodeNetworkSpec

type
  VirtualDiskInfo* = ref object of DynamicData
    unit*: VirtualDiskManagerDiskUnit
    diskType*: string
    parent*: string
    nativeSnapshotSupported*: bool
    backingObjectId*: string

type
  HostHostBusAdapter* = ref object of DynamicData
    key*: string
    device*: string
    bus*: int
    status*: string
    model*: string
    driver*: string
    pci*: string

type
  NetIpStackInfo* = ref object of DynamicData
    neighbor*: seq[NetIpStackInfoNetToMedia]
    defaultRouter*: seq[NetIpStackInfoDefaultRouter]

type
  HostNatServiceConfig* = ref object of DynamicData
    changeOperation*: string
    key*: string
    spec*: HostNatServiceSpec

type
  VmRestartedOnAlternateHostEvent* = ref object of VmPoweredOnEvent
    sourceHost*: HostEventArgument

type
  VirtualMachineVideoCard* = ref object of VirtualDevice
    videoRamSizeInKB*: int64
    numDisplays*: int
    useAutoDetect*: bool
    enable3DSupport*: bool
    use3dRenderer*: string
    graphicsMemorySizeInKB*: int64

type
  OvfMissingHardware* = ref object of OvfImport
    name*: string
    resourceType*: int

type
  AlarmTriggerType* {.pure.} = enum
    metric, state, event
type
  HostMemorySystem* = ref object of vim.ExtensibleManagedObject
    consoleReservationInfo*: ServiceConsoleReservationInfo
    virtualMachineReservationInfo*: VirtualMachineMemoryReservationInfo

type
  VmLogFileInfo* = ref object of FileInfo
  
type
  DrsDisabledOnVm* = ref object of VimFault
  
type
  HostWwnConflictEvent* = ref object of HostEvent
    conflictedVms*: seq[VmEventArgument]
    conflictedHosts*: seq[HostEventArgument]
    wwn*: int64

type
  CustomizationAdapterMapping* = ref object of DynamicData
    macAddress*: string
    adapter*: CustomizationIPSettings

type
  HostPosixAccountSpec* = ref object of HostAccountSpec
    posixId*: int
    shellAccess*: bool

type
  FailoverClusterConfigurator* = ref object of vmodl.ManagedObject
    disabledConfigureMethod*: seq[string]

type
  CannotMoveVsanEnabledHost* = ref object of VsanFault
  
type
  HostTargetTransport* = ref object of DynamicData
  
type
  OvfFileItem* = ref object of DynamicData
    deviceId*: string
    path*: string
    compressionMethod*: string
    chunkSize*: int64
    size*: int64
    cimType*: int
    create*: bool

type
  HostIpConfigIpV6AddressConfiguration* = ref object of DynamicData
    ipV6Address*: seq[HostIpConfigIpV6Address]
    autoConfigurationEnabled*: bool
    dhcpV6Enabled*: bool

type
  ChangesInfoEventArgument* = ref object of DynamicData
    modified*: string
    added*: string
    deleted*: string

type
  DVSOpaqueConfigSpec* = ref object of DynamicData
    operation*: string
    opaqueData*: DVSOpaqueData

type
  IDEDiskNotSupported* = ref object of DiskNotSupported
  
type
  ServiceManager* = ref object of vmodl.ManagedObject
    service*: seq[ServiceManagerServiceInfo]

type
  HostFibreChannelHba* = ref object of HostHostBusAdapter
    portWorldWideName*: int64
    nodeWorldWideName*: int64
    portType*: FibreChannelPortType
    speed*: int64

type
  HostNatServiceNameServiceSpec* = ref object of DynamicData
    dnsAutoDetect*: bool
    dnsPolicy*: string
    dnsRetries*: int
    dnsTimeout*: int
    dnsNameServer*: seq[string]
    nbdsTimeout*: int
    nbnsRetries*: int
    nbnsTimeout*: int

type
  HostListSummary* = ref object of DynamicData
    host*: HostSystem
    hardware*: HostHardwareSummary
    runtime*: HostRuntimeInfo
    config*: HostConfigSummary
    quickStats*: HostListSummaryQuickStats
    overallStatus*: ManagedEntityStatus
    rebootRequired*: bool
    customValue*: seq[CustomFieldValue]
    managementServerIp*: string
    maxEVCModeKey*: string
    currentEVCModeKey*: string
    gateway*: HostListSummaryGatewaySummary
    tpmAttestation*: HostTpmAttestationInfo

type
  DistributedVirtualSwitchHostMemberPnicBacking* = ref object of DistributedVirtualSwitchHostMemberBacking
    pnicSpec*: seq[DistributedVirtualSwitchHostMemberPnicSpec]

type
  ClusterTransitionalEVCManager* = ref object of vim.ExtensibleManagedObject
    managedCluster*: ClusterComputeResource
    evcState*: ClusterTransitionalEVCManagerEVCState

type
  VmFaultToleranceConfigIssue* = ref object of VmFaultToleranceIssue
    reason*: string
    entityName*: string
    entity*: ManagedEntity

type
  FileBackedPortNotSupported* = ref object of DeviceNotSupported
  
type
  HostDateTimeInfo* = ref object of DynamicData
    timeZone*: HostDateTimeSystemTimeZone
    ntpConfig*: HostNtpConfig

type
  GatewayNotFound* = ref object of GatewayConnectFault
  
type
  VMwareDVSConfigSpec* = ref object of DVSConfigSpec
    pvlanConfigSpec*: seq[VMwareDVSPvlanConfigSpec]
    vspanConfigSpec*: seq[VMwareDVSVspanConfigSpec]
    maxMtu*: int
    linkDiscoveryProtocolConfig*: LinkDiscoveryProtocolConfig
    ipfixConfig*: VMwareIpfixConfig
    lacpApiVersion*: string
    multicastFilteringMode*: string

type
  PerformanceManagerUnit* {.pure.} = enum
    percent, kiloBytes, megaBytes, megaHertz, number, microsecond, millisecond, second,
    kiloBytesPerSecond, megaBytesPerSecond, watt, joule, celsius, teraBytes
type
  DVSSelection* = ref object of SelectionSet
    dvsUuid*: string

type
  InvalidSnapshotFormat* = ref object of InvalidFormat
  
type
  GuestOperationsManager* = ref object of vmodl.ManagedObject
    authManager*: GuestAuthManager
    fileManager*: GuestFileManager
    processManager*: GuestProcessManager
    guestWindowsRegistryManager*: GuestWindowsRegistryManager
    aliasManager*: GuestAliasManager

type
  CannotMoveHostWithFaultToleranceVm* = ref object of VimFault
  
type
  StorageDrsConfigSpec* = ref object of DynamicData
    podConfigSpec*: StorageDrsPodConfigSpec
    vmConfigSpec*: seq[StorageDrsVmConfigSpec]

type
  InsufficientNetworkResourcePoolCapacity* = ref object of InsufficientResourcesFault
    dvsName*: string
    dvsUuid*: string
    resourcePoolKey*: string
    available*: int64
    requested*: int64
    device*: seq[string]

type
  VsanNewPolicyBatch* = ref object of DynamicData
    size*: seq[int64]
    policy*: string

type
  CannotCreateFile* = ref object of FileFault
  
type
  HostBIOSInfo* = ref object of DynamicData
    biosVersion*: string
    releaseDate*: string
    vendor*: string
    majorRelease*: int
    minorRelease*: int
    firmwareMajorRelease*: int
    firmwareMinorRelease*: int

type
  AlarmFilterSpecAlarmTypeByEntity* {.pure.} = enum
    entityTypeAll, entityTypeHost, entityTypeVm
type
  VirtualMachineAffinityInfo* = ref object of DynamicData
    affinitySet*: seq[int]

type
  VslmCreateSpecBackingSpec* = ref object of DynamicData
    datastore*: Datastore
    path*: string

type
  HostFirewallSystem* = ref object of vim.ExtensibleManagedObject
    firewallInfo*: HostFirewallInfo

type
  DVSSummary* = ref object of DynamicData
    name*: string
    uuid*: string
    numPorts*: int
    productInfo*: DistributedVirtualSwitchProductSpec
    hostMember*: seq[HostSystem]
    vm*: seq[VirtualMachine]
    host*: seq[HostSystem]
    portgroupName*: seq[string]
    description*: string
    contact*: DVSContactInfo
    numHosts*: int

type
  DatastoreSummary* = ref object of DynamicData
    datastore*: Datastore
    name*: string
    url*: string
    capacity*: int64
    freeSpace*: int64
    uncommitted*: int64
    accessible*: bool
    multipleHostAccess*: bool
    type*: string
    maintenanceMode*: string

type
  VMwareDVSMtuHealthCheckResult* = ref object of HostMemberUplinkHealthCheckResult
    mtuMismatch*: bool
    vlanSupportSwitchMtu*: seq[NumericRange]
    vlanNotSupportSwitchMtu*: seq[NumericRange]

type
  DataProviderResourceModelInfo* = ref object of DynamicData
    name*: string
    properties*: seq[string]

type
  PhysCompatRDMNotSupported* = ref object of RDMNotSupported
  
type
  AuthMinimumAdminPermission* = ref object of VimFault
  
type
  VimVasaProviderStatePerArray* = ref object of DynamicData
    priority*: int
    arrayId*: string
    active*: bool

type
  StorageDrsAutomationConfig* = ref object of DynamicData
    spaceLoadBalanceAutomationMode*: string
    ioLoadBalanceAutomationMode*: string
    ruleEnforcementAutomationMode*: string
    policyEnforcementAutomationMode*: string
    vmEvacuationAutomationMode*: string

type
  StorageDrsIoLoadBalanceConfig* = ref object of DynamicData
    reservablePercentThreshold*: int
    reservableIopsThreshold*: int
    reservableThresholdMode*: string
    ioLatencyThreshold*: int
    ioLoadImbalanceThreshold*: int

type
  GatewayOperationRefused* = ref object of GatewayConnectFault
  
type
  HostDiskPartitionInfoType* {.pure.} = enum
    none, vmfs, linuxNative, linuxSwap, extended, ntfs, vmkDiagnostic, vffs
type
  VmfsDatastoreMultipleExtentOption* = ref object of VmfsDatastoreBaseOption
    vmfsExtent*: seq[HostDiskPartitionBlockRange]

type
  VmwareUplinkPortTeamingPolicy* = ref object of InheritablePolicy
    policy*: StringPolicy
    reversePolicy*: BoolPolicy
    notifySwitches*: BoolPolicy
    rollingOrder*: BoolPolicy
    failureCriteria*: DVSFailureCriteria
    uplinkPortOrder*: VMwareUplinkPortOrderPolicy

type
  TpmTrustNotEstablished* = ref object of TpmFault
  
type
  HostVmciAccessManagerMode* {.pure.} = enum
    grant, replace, revoke
type
  VsanDiskIssueType* {.pure.} = enum
    nonExist, stampMismatch, unknown
type
  DrsInvocationFailedEvent* = ref object of ClusterEvent
  
type
  LargeRDMNotSupportedOnDatastore* = ref object of VmConfigFault
    device*: string
    datastore*: Datastore
    datastoreName*: string

type
  DistributedVirtualSwitchHostInfrastructureTrafficClass* {.pure.} = enum
    management, faultTolerance, vmotion, virtualMachine, iSCSI, nfs, hbr, vsan, vdp
type
  AlreadyConnected* = ref object of HostConnectFault
    name*: string

type
  OvfPropertyNetwork* = ref object of OvfProperty
  
type
  VirtualMachineFileLayoutExFileInfo* = ref object of DynamicData
    key*: int
    name*: string
    type*: string
    size*: int64
    uniqueSize*: int64
    backingObjectId*: string
    accessible*: bool

type
  DataProviderPropertyPredicateComparisonOperator* {.pure.} = enum
    Equal, NotEqual, Greater, GreaterOrEqual, Less, LessOrEqual, In, NotIn, Like, Unset
type
  SecondaryVmAlreadyRegistered* = ref object of VmFaultToleranceIssue
    instanceUuid*: string

type
  CustomizationCustomName* = ref object of CustomizationName
    argument*: string

type
  VirtualLsiLogicSASControllerOption* = ref object of VirtualSCSIControllerOption
  
type
  UpdatedAgentBeingRestartedEvent* = ref object of HostEvent
  
type
  InvalidName* = ref object of VimFault
    name*: string
    entity*: ManagedEntity

type
  HostCnxFailedAccountFailedEvent* = ref object of HostEvent
  
type
  ScsiLunState* {.pure.} = enum
    unknownState, ok, error, off, quiesced, degraded, lostCommunication, timeout
type
  VslmTagEntry* = ref object of DynamicData
    tagName*: string
    parentCategoryName*: string

type
  InUseFeatureManipulationDisallowed* = ref object of NotEnoughLicenses
  
type
  VirtualNVDIMMController* = ref object of VirtualController
  
type
  HostDiskMappingPartitionOption* = ref object of DynamicData
    name*: string
    fileSystem*: string
    capacityInKb*: int64

type
  LicenseAvailabilityInfo* = ref object of DynamicData
    feature*: LicenseFeatureInfo
    total*: int
    available*: int

type
  VirtualMachineConfigInfoNpivWwnType* {.pure.} = enum
    vc, host, external
type
  FaultToleranceSecondaryOpResult* = ref object of DynamicData
    vm*: VirtualMachine
    powerOnAttempted*: bool
    powerOnResult*: ClusterPowerOnVmResult

type
  NonVIWorkloadDetectedOnDatastoreEvent* = ref object of DatastoreEvent
  
type
  NetDhcpConfigSpecDhcpOptionsSpec* = ref object of DynamicData
    enable*: bool
    config*: seq[KeyValue]
    operation*: string

type
  ExpiredEditionLicense* = ref object of ExpiredFeatureLicense
  
type
  LocalLicenseSource* = ref object of LicenseSource
    licenseKeys*: string

type
  TooManyConcurrentNativeClones* = ref object of FileFault
  
type
  VirtualMachineStorageSummary* = ref object of DynamicData
    committed*: int64
    uncommitted*: int64
    unshared*: int64
    timestamp*: string

type
  VmPoweredOffEvent* = ref object of VmEvent
  
type
  KmipServerStatus* = ref object of DynamicData
    clusterId*: KeyProviderId
    name*: string
    status*: ManagedEntityStatus
    description*: string

type
  GlobalMessageChangedEvent* = ref object of SessionEvent
    message*: string
    prevMessage*: string

type
  HostCnxFailedBadVersionEvent* = ref object of HostEvent
  
type
  EnvironmentBrowserConfigOptionQuerySpec* = ref object of DynamicData
    key*: string
    host*: HostSystem
    guestId*: seq[string]

type
  TemplateUpgradeEvent* = ref object of Event
    legacyTemplate*: string

type
  HostOperationCleanupManager* = ref object of vmodl.ManagedObject
  
type
  VirtualSerialPortFileBackingOption* = ref object of VirtualDeviceFileBackingOption
  
type
  VMotionNotLicensed* = ref object of VMotionInterfaceIssue
  
type
  ToolsAlreadyUpgraded* = ref object of VmToolsUpgradeFault
  
type
  GuestRegKeyRecordSpec* = ref object of DynamicData
    key*: GuestRegKeySpec
    fault*: MethodFault

type
  InvalidHostState* = ref object of InvalidState
    host*: HostSystem

type
  NoActiveHostInCluster* = ref object of InvalidState
    computeResource*: ComputeResource

type
  ResourceConfigSpec* = ref object of DynamicData
    entity*: ManagedEntity
    changeVersion*: string
    lastModified*: string
    cpuAllocation*: ResourceAllocationInfo
    memoryAllocation*: ResourceAllocationInfo
    networkBandwidthAllocation*: seq[NetworkBandwidthAllocationInfo]

type
  AlarmEventArgument* = ref object of EntityEventArgument
    alarm*: Alarm

type
  CannotAccessVmDisk* = ref object of CannotAccessVmDevice
    fault*: MethodFault

type
  VirtualSoundCardDeviceBackingOption* = ref object of VirtualDeviceDeviceBackingOption
  
type
  RestrictedVersion* = ref object of SecurityError
  
type
  DistributedVirtualSwitchManagerImportResult* = ref object of DynamicData
    distributedVirtualSwitch*: seq[DistributedVirtualSwitch]
    distributedVirtualPortgroup*: seq[DistributedVirtualPortgroup]
    importFault*: seq[ImportOperationBulkFaultFaultOnImport]

type
  GeneralVmErrorEvent* = ref object of GeneralEvent
  
type
  LicenseEntityNotFound* = ref object of VimFault
    entityId*: string

type
  VmBeingRelocatedEvent* = ref object of VmRelocateSpecEvent
    destHost*: HostEventArgument
    destDatacenter*: DatacenterEventArgument
    destDatastore*: DatastoreEventArgument

type
  VmDeployFailedEvent* = ref object of VmEvent
    destDatastore*: EntityEventArgument
    reason*: MethodFault

type
  VmPrimaryFailoverEvent* = ref object of VmEvent
    reason*: string

type
  FilterInUse* = ref object of ResourceInUse
    disk*: seq[VirtualDiskId]

type
  InvalidPropertyValue* = ref object of VAppPropertyFault
  
type
  OvfPropertyNetworkExport* = ref object of OvfExport
    network*: string

type
  ClusterDasFdmAvailabilityState* {.pure.} = enum
    uninitialized, election, master, connectedToMaster,
    networkPartitionedFromMaster, networkIsolated, hostDown, initializationError,
    uninitializationError, fdmUnreachable
type
  VirtualDiskId* = ref object of DynamicData
    vm*: VirtualMachine
    diskId*: int

type
  ClusterFailoverHostAdmissionControlInfoHostStatus* = ref object of DynamicData
    host*: HostSystem
    status*: ManagedEntityStatus

type
  VvolDatastoreSpec* = ref object of DynamicData
    vvol*: HostVvolVolumeSpecification

type
  GhostDvsProxySwitchDetectedEvent* = ref object of HostEvent
    switchUuid*: seq[string]

type
  CustomizationUnknownName* = ref object of CustomizationName
  
type
  DVSManagerDvpgUplinkTeam* = ref object of DynamicData
    dvpgKey*: string
    uplink*: seq[string]

type
  VsanUpgradeSystemAutoClaimEnabledOnHostsIssue* = ref object of VsanUpgradeSystemPreflightCheckIssue
    hosts*: seq[HostSystem]

type
  IntExpression* = ref object of NegatableExpression
    value*: int

type
  HostPatchManagerStatus* = ref object of DynamicData
    id*: string
    applicable*: bool
    reason*: seq[string]
    integrity*: string
    installed*: bool
    installState*: seq[string]
    prerequisitePatch*: seq[HostPatchManagerStatusPrerequisitePatch]
    restartRequired*: bool
    reconnectRequired*: bool
    vmOffRequired*: bool
    supersededPatchIds*: seq[string]

type
  CbrcDigestInfoResult* = ref object of CbrcDigestOperationResult
    info*: CbrcDigestInfo

type
  BoolOption* = ref object of OptionType
    supported*: bool
    defaultValue*: bool

type
  HostResignatureRescanResult* = ref object of DynamicData
    rescan*: seq[HostVmfsRescanResult]
    result*: Datastore

type
  VirtualSriovEthernetCardSriovBackingOption* = ref object of VirtualDeviceBackingOption
  
type
  ReplicationDiskConfigFaultReasonForFault* {.pure.} = enum
    diskNotFound, diskTypeNotSupported, invalidDiskKey, invalidDiskReplicationId,
    duplicateDiskReplicationId, invalidPersistentFilePath,
    reconfigureDiskReplicationIdNotAllowed
type
  NumVirtualCpusIncompatible* = ref object of VmConfigFault
    reason*: string
    numCpu*: int

type
  HostNetworkResource* = ref object of DynamicData
    networkId*: string

type
  DrsWorkloadCharacterization* = ref object of DynamicData
    key*: Datastore
    outstandingIo*: float64
    ioSize*: float64
    readPercent*: float64
    randomPercent*: float64

type
  VirtualEthernetCardNotSupported* = ref object of DeviceNotSupported
  
type
  DasHeartbeatDatastoreInfo* = ref object of DynamicData
    datastore*: Datastore
    hosts*: seq[HostSystem]

type
  VmfsConfigOption* = ref object of DynamicData
    blockSizeOption*: int
    unmapGranularityOption*: seq[int]
    unmapBandwidthFixedValue*: LongOption
    unmapBandwidthDynamicMin*: LongOption
    unmapBandwidthDynamicMax*: LongOption
    unmapBandwidthIncrement*: int64

type
  ClusterDasVmcpPrecheckResult* = ref object of DynamicData
    hostsWithIncompatibleVersion*: seq[HostSystem]
    hostsWithApdTimeoutDisabled*: seq[HostSystem]

type
  UserSearchResult* = ref object of DynamicData
    principal*: string
    fullName*: string
    group*: bool

type
  HostMultipathInfoPath* = ref object of DynamicData
    key*: string
    name*: string
    pathState*: string
    state*: string
    isWorkingPath*: bool
    adapter*: HostHostBusAdapter
    lun*: HostMultipathInfoLogicalUnit
    transport*: HostTargetTransport

type
  ClusterMigrationAction* = ref object of ClusterAction
    drsMigration*: ClusterDrsMigration

type
  HostDatastoreSystemDatastoreResult* = ref object of DynamicData
    key*: Datastore
    fault*: MethodFault

type
  CannotModifyConfigCpuRequirements* = ref object of MigrationFault
  
type
  ExtendedEventPair* = ref object of DynamicData
    key*: string
    value*: string

type
  ReplicationVmFaultReasonForFault* {.pure.} = enum
    notConfigured, poweredOff, suspended, poweredOn, offlineReplicating,
    invalidState, invalidInstanceId, closeDiskError, groupExist
type
  VirtualSCSIPassthroughOption* = ref object of VirtualDeviceOption
  
type
  CustomizationLinuxIdentityFailed* = ref object of CustomizationFailed
  
type
  ExternalStatsManagerProviderInfo* = ref object of DynamicData
    id*: string
    metadata*: string

type
  TaskFilterSpec* = ref object of DynamicData
    entity*: TaskFilterSpecByEntity
    time*: TaskFilterSpecByTime
    userName*: TaskFilterSpecByUsername
    activationId*: seq[string]
    state*: seq[TaskInfoState]
    alarm*: Alarm
    scheduledTask*: ScheduledTask
    eventChainId*: seq[int]
    tag*: seq[string]
    parentTaskKey*: seq[string]
    rootTaskKey*: seq[string]

type
  AdminDisabled* = ref object of HostConfigFault
  
type
  VirtualDiskPartitionedRawDiskVer2BackingOption* = ref object of VirtualDiskRawDiskVer2BackingOption
  
type
  HostLowLevelProvisioningManagerFileType* {.pure.} = enum
    File, VirtualDisk, Directory
type
  ProfileSerializedCreateSpec* = ref object of ProfileCreateSpec
    profileConfigString*: string

type
  VirtualMachineDeviceRuntimeInfoVirtualEthernetCardRuntimeState* = ref object of VirtualMachineDeviceRuntimeInfoDeviceRuntimeState
    vmDirectPathGen2Active*: bool
    vmDirectPathGen2InactiveReasonVm*: seq[string]
    vmDirectPathGen2InactiveReasonOther*: seq[string]
    vmDirectPathGen2InactiveReasonExtended*: string
    reservationStatus*: string
    attachmentStatus*: string
    featureRequirement*: seq[VirtualMachineFeatureRequirement]

type
  OptionDef* = ref object of ElementDescription
    optionType*: OptionType

type
  ClusterDasHostRecommendation* = ref object of DynamicData
    host*: HostSystem
    drsRating*: int

type
  HostLowLevelProvisioningManagerFileReserveResult* = ref object of DynamicData
    baseName*: string
    parentDir*: string
    reservedName*: string

type
  DvsVmVnicResourceAllocation* = ref object of DynamicData
    reservationQuota*: int64

type
  Event* = ref object of DynamicData
    key*: int
    chainId*: int
    createdTime*: string
    userName*: string
    datacenter*: DatacenterEventArgument
    computeResource*: ComputeResourceEventArgument
    host*: HostEventArgument
    vm*: VmEventArgument
    ds*: DatastoreEventArgument
    net*: NetworkEventArgument
    dvs*: DvsEventArgument
    fullFormattedMessage*: string
    changeTag*: string

type
  HostProfilePolicyOptionMapping* = ref object of DynamicData
    id*: string
    data*: HostProfilePolicyOptionMappingPolicyOptionMappingData
    parameterMapping*: seq[HostProfileParameterMapping]

type
  VMwareUplinkLacpMode* {.pure.} = enum
    active, passive
type
  OvfCreateImportSpecParamsDiskProvisioningType* {.pure.} = enum
    monolithicSparse, monolithicFlat, twoGbMaxExtentSparse, twoGbMaxExtentFlat,
    thin, thick, seSparse, eagerZeroedThick, sparse, flat
type
  HostScsiTopologyInterface* = ref object of DynamicData
    key*: string
    adapter*: HostHostBusAdapter
    target*: seq[HostScsiTopologyTarget]

type
  ProxyServiceNamedPipeTunnelSpec* = ref object of ProxyServiceTunnelSpec
    pipeName*: string

type
  HostProfileManagerCompositionValidationResultResultElementStatus* {.pure.} = enum
    success, error
type
  HostAccessRestrictedToManagementServer* = ref object of NotSupported
    managementServer*: string

type
  CDCAlarmChange* = ref object of DynamicData
    kind*: string
    entity*: ManagedEntity
    alarm*: Alarm
    overallStatus*: ManagedEntityStatus
    time*: string
    eventKey*: int
    acknowledgedByUser*: string
    acknowledgedTime*: string

type
  VcAgentUninstallFailedEvent* = ref object of HostEvent
    reason*: string

type
  VMotionCompatibilityType* {.pure.} = enum
    cpu, software
type
  VirtualMachineImportSpec* = ref object of ImportSpec
    configSpec*: VirtualMachineConfigSpec
    resPoolEntity*: ResourcePool

type
  SessionManagerGenericServiceTicket* = ref object of DynamicData
    id*: string
    hostName*: string
    sslThumbprint*: string

type
  HostConnectInfoNetworkInfo* = ref object of DynamicData
    summary*: NetworkSummary

type
  VirtualDeviceDeviceBackingInfo* = ref object of VirtualDeviceBackingInfo
    deviceName*: string
    useAutoDetect*: bool

type
  DiskIsLastRemainingNonSSD* = ref object of VsanDiskFault
  
type
  OutOfSyncDvsHost* = ref object of DvsEvent
    hostOutOfSync*: seq[DvsOutOfSyncHostArgument]

type
  CannotAddHostWithFTVmToDifferentCluster* = ref object of HostConnectFault
  
type
  VMotionNotConfigured* = ref object of VMotionInterfaceIssue
  
type
  HostFirewallRuleProtocol* {.pure.} = enum
    tcp, udp
type
  HostMountInfoInaccessibleReason* {.pure.} = enum
    AllPathsDown_Start, AllPathsDown_Timeout, PermanentDeviceLoss
type
  VirtualMachineBackupAgent* = ref object of vim.ExtensibleManagedObject
  
type
  ReplicationNotSupportedOnHost* = ref object of ReplicationFault
  
type
  HostBootDeviceSystem* = ref object of vmodl.ManagedObject
  
type
  VirtualCdromOption* = ref object of VirtualDeviceOption
  
type
  ProfileExecuteError* = ref object of DynamicData
    path*: ProfilePropertyPath
    message*: LocalizableMessage

type
  LimitExceeded* = ref object of VimFault
    property*: string
    limit*: int

type
  HostLoadEsxManager* = ref object of vmodl.ManagedObject
  
type
  VirtualDeviceRemoteDeviceBackingInfo* = ref object of VirtualDeviceBackingInfo
    deviceName*: string
    useAutoDetect*: bool

type
  HostGetShortNameFailedEvent* = ref object of HostEvent
  
type
  HostNumaInfo* = ref object of DynamicData
    type*: string
    numNodes*: int
    numaNode*: seq[HostNumaNode]

type
  DvsSystemTrafficNetworkRuleQualifier* = ref object of DvsNetworkRuleQualifier
    typeOfSystemTraffic*: StringExpression

type
  CustomFieldValueChangedEvent* = ref object of CustomFieldEvent
    entity*: ManagedEntityEventArgument
    fieldKey*: int
    name*: string
    value*: string
    prevState*: string

type
  HostMemorySpec* = ref object of DynamicData
    serviceConsoleReservation*: int64

type
  ClusterDasAamHostInfo* = ref object of ClusterDasHostInfo
    hostDasState*: seq[ClusterDasAamNodeState]
    primaryHosts*: seq[string]

type
  DistributedVirtualSwitchKeyedOpaqueBlob* = ref object of DynamicData
    key*: string
    opaqueData*: string

type
  HostOperationCleanupManagerOperationEntry* = ref object of DynamicData
    hlogFile*: string
    opId*: int64
    opState*: string
    opActivity*: string
    curHostUuid*: string
    itemList*: seq[HostOperationCleanupManagerCleanupItemEntry]

type
  OvfConnectedDevice* = ref object of OvfHardwareExport
  
type
  DataProviderResourceModel* = ref object of vmodl.ManagedObject
  
type
  VirtualMachineProvisioningPolicyOpType* {.pure.} = enum
    clone, migrate, createSecondary, createForkChild, instantClone
type
  HostCnxFailedAlreadyManagedEvent* = ref object of HostEvent
    serverName*: string

type
  ResourcePlanningManager* = ref object of vmodl.ManagedObject
  
type
  VmPowerOnDisabled* = ref object of InvalidState
  
type
  HostAuthenticationStoreInfo* = ref object of DynamicData
    enabled*: bool

type
  DatastoreFileDeletedEvent* = ref object of DatastoreFileEvent
  
type
  PlacementRankSpec* = ref object of DynamicData
    specs*: seq[PlacementSpec]
    clusters*: seq[ClusterComputeResource]
    rules*: seq[PlacementAffinityRule]
    placementRankByVm*: seq[StorageDrsPlacementRankVmSpec]

type
  HostSystemComplianceCheckState* = ref object of DynamicData
    state*: string
    checkTime*: string

type
  CannotAccessNetwork* = ref object of CannotAccessVmDevice
    network*: Network

type
  HostVMotionCompatibility* = ref object of DynamicData
    host*: HostSystem
    compatibility*: seq[string]

type
  CustomizationDhcpIpGenerator* = ref object of CustomizationIpGenerator
  
type
  EntityImportType* {.pure.} = enum
    createEntityWithNewIdentifier, createEntityWithOriginalIdentifier,
    applyToEntitySpecified
type
  DvsHostStatusUpdated* = ref object of DvsEvent
    hostMember*: HostEventArgument
    oldStatus*: string
    newStatus*: string
    oldStatusDetail*: string
    newStatusDetail*: string

type
  ProfileComplianceManager* = ref object of vmodl.ManagedObject
  
type
  HostRuntimeInfoNetworkRuntimeInfo* = ref object of DynamicData
    netStackInstanceRuntimeInfo*: seq[HostRuntimeInfoNetStackInstanceRuntimeInfo]
    networkResourceRuntime*: HostNetworkResourceRuntime

type
  Tag* = ref object of DynamicData
    key*: string

type
  ClusterDasVmSettingsIsolationResponse* {.pure.} = enum
    none, powerOff, shutdown, clusterIsolationResponse
type
  TaskReasonAlarm* = ref object of TaskReason
    alarmName*: string
    alarm*: Alarm
    entityName*: string
    entity*: ManagedEntity

type
  HostVirtualNicConfig* = ref object of DynamicData
    changeOperation*: string
    device*: string
    portgroup*: string
    spec*: HostVirtualNicSpec

type
  EVCAdmissionFailedCPUModelForMode* = ref object of EVCAdmissionFailed
    currentEVCModeKey*: string

type
  HostDVPortgroupConfigSpec* = ref object of DynamicData
    operation*: string
    key*: string
    specification*: DVPortgroupConfigSpec
    keyedOpaqueDataList*: DVSKeyedOpaqueDataList
    opaqueDataList*: DVSOpaqueDataList

type
  HostSnmpAgentCapability* {.pure.} = enum
    COMPLETE, DIAGNOSTICS, CONFIGURATION
type
  VmNoCompatibleHostForSecondaryEvent* = ref object of VmEvent
  
type
  FileQueryFlags* = ref object of DynamicData
    fileType*: bool
    fileSize*: bool
    modification*: bool
    fileOwner*: bool

type
  FcoeFaultPnicHasNoPortSet* = ref object of FcoeFault
    nicDevice*: string

type
  VirtualEthernetCardOpaqueNetworkBackingInfo* = ref object of VirtualDeviceBackingInfo
    opaqueNetworkId*: string
    opaqueNetworkType*: string

type
  FileNotFound* = ref object of FileFault
  
type
  HostFeatureMask* = ref object of DynamicData
    key*: string
    featureName*: string
    value*: string

type
  ClusterEvent* = ref object of Event
  
type
  VirtualMachinePowerState* {.pure.} = enum
    poweredOff, poweredOn, suspended
type
  HostSerialAttachedHba* = ref object of HostHostBusAdapter
    nodeWorldWideName*: string

type
  PlacementAffinityRule* = ref object of DynamicData
    ruleType*: string
    ruleScope*: string
    vms*: seq[VirtualMachine]
    keys*: seq[string]

type
  NumVirtualCoresPerSocketNotSupported* = ref object of VirtualHardwareCompatibilityIssue
    maxSupportedCoresPerSocketDest*: int
    numCoresPerSocketVm*: int

type
  VmDiskFileEncryptionInfo* = ref object of DynamicData
    keyId*: CryptoKeyId

type
  VmLimitLicense* = ref object of NotEnoughLicenses
    limit*: int

type
  GuestRegistryKeyParentVolatile* = ref object of GuestRegistryKeyFault
  
type
  HostVFlashManagerVFlashResourceConfigInfo* = ref object of DynamicData
    vffs*: HostVffsVolume
    capacity*: int64

type
  Context* = ref object of DynamicData
    wsdlMethodName*: string
    target*: ManagedObject
    instanceId*: string
    opId*: string
    migrationId*: int64
    priority*: VirtualMachineMovePriority
    pool*: ResourcePool
    host*: HostSystem
    data*: seq[KeyAnyValue]
    fault*: MethodFault

type
  DatacenterMismatch* = ref object of MigrationFault
    invalidArgument*: seq[DatacenterMismatchArgument]
    expectedDatacenter*: Datacenter

type
  PMemDatastoreInfo* = ref object of DatastoreInfo
    pmem*: HostPMemVolume

type
  VmFaultToleranceTooManyVMsOnHost* = ref object of InsufficientResourcesFault
    hostName*: string
    maxNumFtVms*: int

type
  FaultToleranceAntiAffinityViolated* = ref object of MigrationFault
    hostName*: string
    host*: HostSystem

type
  DvsHostInfrastructureTrafficResourceAllocation* = ref object of DynamicData
    limit*: int64
    shares*: SharesInfo
    reservation*: int64

type
  NotUserConfigurableProperty* = ref object of VAppPropertyFault
  
type
  ProxyServiceTunnelSpec* = ref object of ProxyServiceEndpointSpec
  
type
  OvfValidateHostResult* = ref object of DynamicData
    downloadSize*: int64
    flatDeploymentSize*: int64
    sparseDeploymentSize*: int64
    error*: seq[MethodFault]
    warning*: seq[MethodFault]
    supportedDiskProvisioning*: seq[string]

type
  HostDhcpService* = ref object of DynamicData
    key*: string
    spec*: HostDhcpServiceSpec

type
  HttpNfcLeaseSourceFile* = ref object of DynamicData
    targetDeviceId*: string
    url*: string
    memberName*: string
    create*: bool
    sslThumbprint*: string
    httpHeaders*: seq[KeyValue]
    size*: int64

type
  TaskReasonSystem* = ref object of TaskReason
  
type
  DVSUplinkPortPolicy* = ref object of DynamicData
  
type
  NoCompatibleDatastore* = ref object of VimFault
  
type
  HostIpRouteEntry* = ref object of DynamicData
    network*: string
    prefixLength*: int
    gateway*: string
    deviceName*: string

type
  VirtualPS2Controller* = ref object of VirtualController
  
type
  TooManyConsecutiveOverrides* = ref object of VimFault
  
type
  VirtualMachineTicket* = ref object of DynamicData
    ticket*: string
    cfgFile*: string
    host*: string
    port*: int
    sslThumbprint*: string

type
  HostDiagnosticPartitionCreateDescription* = ref object of DynamicData
    layout*: HostDiskPartitionLayout
    diskUuid*: string
    spec*: HostDiagnosticPartitionCreateSpec

type
  ClusterDasAdmissionControlPolicy* = ref object of DynamicData
    resourceReductionToToleratePercent*: int

type
  TaskTimeoutEvent* = ref object of TaskEvent
  
type
  HotSnapshotMoveNotSupported* = ref object of SnapshotCopyNotSupported
  
type
  ProfileCategoryMetadata* = ref object of DynamicData
    id*: ExtendedElementDescription
    profileComponents*: seq[string]

type
  AuthenticationProfile* = ref object of ApplyProfile
    activeDirectory*: ActiveDirectoryProfile

type
  CpuIncompatible1ECX* = ref object of CpuIncompatible
    sse3*: bool
    pclmulqdq*: bool
    ssse3*: bool
    sse41*: bool
    sse42*: bool
    aes*: bool
    other*: bool
    otherOnly*: bool

type
  IntOption* = ref object of OptionType
    min*: int
    max*: int
    defaultValue*: int

type
  HostLicenseConnectInfo* = ref object of DynamicData
    license*: LicenseManagerLicenseInfo
    evaluation*: LicenseManagerEvaluationInfo
    resource*: HostLicensableResourceInfo

type
  DrsVmPoweredOnEvent* = ref object of VmPoweredOnEvent
  
type
  OvfInvalidValueFormatMalformed* = ref object of OvfInvalidValue
  
type
  DiagnosticManagerLogCreator* {.pure.} = enum
    vpxd, vpxa, hostd, serverd, install, vpxClient, recordLog
type
  OvfExport* = ref object of OvfFault
  
type
  HostDiagnosticPartition* = ref object of DynamicData
    storageType*: string
    diagnosticType*: string
    slots*: int
    id*: HostScsiDiskPartition

type
  AlarmRemovedEvent* = ref object of AlarmEvent
    entity*: ManagedEntityEventArgument

type
  AlreadyBeingManaged* = ref object of HostConnectFault
    ipAddress*: string

type
  HostNumericSensorType* {.pure.} = enum
    fan, power, temperature, voltage, other, processor, memory, storage, systemBoard,
    battery, bios, cable, watchdog
type
  VirtualEthernetCardMacType* {.pure.} = enum
    manual, generated, assigned
type
  ServiceManagerServiceInfo* = ref object of DynamicData
    serviceName*: string
    location*: seq[string]
    service*: ManagedObject
    description*: string

type
  ClusterDasPrecheckResult* = ref object of DynamicData
    admission*: ClusterDasAdmissionResult

type
  HostDasEnablingEvent* = ref object of HostEvent
  
type
  VMFSDatastoreExtendedEvent* = ref object of HostEvent
    datastore*: DatastoreEventArgument

type
  VmRemoteConsoleConnectedEvent* = ref object of VmEvent
  
type
  ReplicationVmConfigFault* = ref object of ReplicationConfigFault
    reason*: string
    vmRef*: VirtualMachine

type
  DeviceControllerNotSupported* = ref object of DeviceNotSupported
    controller*: string

type
  DrsEnabledEvent* = ref object of ClusterEvent
    behavior*: string

type
  SpbmIoFilterInfo* = ref object of DynamicData
    id*: string
    type*: string

type
  VirtualMachineNetworkShaperInfo* = ref object of DynamicData
    enabled*: bool
    peakBps*: int64
    averageBps*: int64
    burstSize*: int64

type
  HostConnectFault* = ref object of VimFault
  
type
  HostNatService* = ref object of DynamicData
    key*: string
    spec*: HostNatServiceSpec

type
  HostPciPassthruInfo* = ref object of DynamicData
    id*: string
    dependentDevice*: string
    passthruEnabled*: bool
    passthruCapable*: bool
    passthruActive*: bool

type
  VirtualMachineCdromInfo* = ref object of VirtualMachineTargetInfo
    description*: string

type
  VmfsDatastoreBaseOption* = ref object of DynamicData
    layout*: HostDiskPartitionLayout
    partitionFormatChange*: bool

type
  DvsPortCreatedEvent* = ref object of DvsEvent
    portKey*: seq[string]

type
  HostDnsConfigSpec* = ref object of HostDnsConfig
    virtualNicConnection*: HostVirtualNicConnection
    virtualNicConnectionV6*: HostVirtualNicConnection

type
  VirtualEthernetCardResourceAllocation* = ref object of DynamicData
    reservation*: int64
    share*: SharesInfo
    limit*: int64

type
  AlarmFilterSpecAlarmTypeByTrigger* {.pure.} = enum
    triggerTypeAll, triggerTypeEvent, triggerTypeMetric
type
  VmfsDatastoreCreateSpec* = ref object of VmfsDatastoreSpec
    partition*: HostDiskPartitionSpec
    vmfs*: HostVmfsSpec
    extent*: seq[HostScsiDiskPartition]

type
  VirtualMachineDatastoreInfo* = ref object of VirtualMachineTargetInfo
    datastore*: DatastoreSummary
    capability*: DatastoreCapability
    maxFileSize*: int64
    maxVirtualDiskCapacity*: int64
    maxPhysicalRDMFileSize*: int64
    maxVirtualRDMFileSize*: int64
    mode*: string
    vStorageSupport*: string

type
  HostCpuIdInfo* = ref object of DynamicData
    level*: int
    vendor*: string
    eax*: string
    ebx*: string
    ecx*: string
    edx*: string

type
  CustomFieldDefEvent* = ref object of CustomFieldEvent
    fieldKey*: int
    name*: string

type
  VirtualMachineBootOptionsBootableDiskDevice* = ref object of VirtualMachineBootOptionsBootableDevice
    deviceKey*: int

type
  SearchIndex* = ref object of vmodl.ManagedObject
  
type
  VsanHostIpConfig* = ref object of DynamicData
    upstreamIpAddress*: string
    downstreamIpAddress*: string

type
  EnteringMaintenanceModeEvent* = ref object of HostEvent
  
type
  VRPResourceManager* = ref object of vmodl.ManagedObject
  
type
  HostDirectoryStoreInfo* = ref object of HostAuthenticationStoreInfo
  
type
  VirtualMachineDeviceRuntimeInfoDeviceRuntimeState* = ref object of DynamicData
  
type
  HostCapabilityFtUnsupportedReason* {.pure.} = enum
    vMotionNotLicensed, missingVMotionNic, missingFTLoggingNic, ftNotLicensed,
    haAgentIssue, unsupportedProduct, cpuHvUnsupported, cpuHwmmuUnsupported,
    cpuHvDisabled
type
  HbrObjectTag* = ref object of DynamicData
    key*: string
    value*: string

type
  ClusterDasFailoverLevelAdvancedRuntimeInfoVmSlots* = ref object of DynamicData
    vm*: VirtualMachine
    slots*: int

type
  UncommittedUndoableDisk* = ref object of MigrationFault
  
type
  DVSKeyedOpaqueDataList* = ref object of DynamicData
    keyedOpaqueData*: seq[DVSKeyedOpaqueData]

type
  VirtualSoundCardDeviceBackingInfo* = ref object of VirtualDeviceDeviceBackingInfo
  
type
  InsufficientStandbyMemoryResource* = ref object of InsufficientStandbyResource
    available*: int64
    requested*: int64

type
  RemoteTSMEnabledEvent* = ref object of HostEvent
  
type
  NetworkProfile* = ref object of ApplyProfile
    vswitch*: seq[VirtualSwitchProfile]
    vmPortGroup*: seq[VmPortGroupProfile]
    hostPortGroup*: seq[HostPortGroupProfile]
    serviceConsolePortGroup*: seq[ServiceConsolePortGroupProfile]
    dnsConfig*: NetworkProfileDnsConfigProfile
    ipRouteConfig*: IpRouteProfile
    consoleIpRouteConfig*: IpRouteProfile
    pnic*: seq[PhysicalNicProfile]
    dvswitch*: seq[DvsProfile]
    dvsServiceConsoleNic*: seq[DvsServiceConsoleVNicProfile]
    dvsHostNic*: seq[DvsHostVNicProfile]
    nsxHostNic*: seq[NsxHostVNicProfile]
    netStackInstance*: seq[NetStackInstanceProfile]

type
  OptionProfile* = ref object of ApplyProfile
    key*: string

type
  VirtualMachineMksTicket* = ref object of DynamicData
    ticket*: string
    cfgFile*: string
    host*: string
    port*: int
    sslThumbprint*: string

type
  HostAdminEnableEvent* = ref object of HostEvent
  
type
  HostConnectSpec* = ref object of DynamicData
    hostName*: string
    port*: int
    sslThumbprint*: string
    userName*: string
    password*: string
    vmFolder*: Folder
    force*: bool
    vimAccountName*: string
    vimAccountPassword*: string
    managementIp*: string
    lockdownMode*: HostLockdownMode
    hostGateway*: HostGatewaySpec

type
  VirtualNVDIMMBackingInfo* = ref object of VirtualDeviceFileBackingInfo
    parent*: VirtualNVDIMMBackingInfo
    changeId*: string

type
  OvfMissingElementNormalBoundary* = ref object of OvfMissingElement
    boundary*: string

type
  NoCompatibleHost* = ref object of VimFault
    host*: seq[HostSystem]
    error*: seq[MethodFault]

type
  FormattedHostProfilesCustomizations* = ref object of HostProfilesEntityCustomizations
    entity*: ManagedEntity
    format*: string
    formattedCustomizations*: string

type
  HostPlugStoreTopologyTarget* = ref object of DynamicData
    key*: string
    transport*: HostTargetTransport

type
  VirtualMachineConfigInfoOverheadInfo* = ref object of DynamicData
    initialMemoryReservation*: int64
    initialSwapReservation*: int64

type
  HostInternetScsiHbaSendTarget* = ref object of DynamicData
    address*: string
    port*: int
    authenticationProperties*: HostInternetScsiHbaAuthenticationProperties
    digestProperties*: HostInternetScsiHbaDigestProperties
    supportedAdvancedOptions*: seq[OptionDef]
    advancedOptions*: seq[HostInternetScsiHbaParamValue]
    parent*: string

type
  VirtualDiskFlatVer1BackingOption* = ref object of VirtualDeviceFileBackingOption
    diskMode*: ChoiceOption
    split*: BoolOption
    writeThrough*: BoolOption
    growable*: bool

type
  AlarmEvent* = ref object of Event
    alarm*: AlarmEventArgument

type
  EntityBackupConfig* = ref object of DynamicData
    entityType*: string
    configBlob*: byte
    key*: string
    name*: string
    container*: ManagedEntity
    configVersion*: string

type
  OvfInvalidValueEmpty* = ref object of OvfInvalidValue
  
type
  OvfToXmlUnsupportedElement* = ref object of OvfSystemFault
    name*: string

type
  HostSriovDevicePoolInfo* = ref object of DynamicData
    key*: string

type
  VsanHostClusterStatus* = ref object of DynamicData
    uuid*: string
    nodeUuid*: string
    health*: string
    nodeState*: VsanHostClusterStatusState
    memberUuid*: seq[string]

type
  SoftwarePackageVibType* {.pure.} = enum
    bootbank, tools, meta
type
  VAppPropertySpec* = ref object of ArrayUpdateSpec
    info*: VAppPropertyInfo

type
  OvfUnsupportedAttribute* = ref object of OvfUnsupportedPackage
    elementName*: string
    attributeName*: string

type
  EventArgument* = ref object of DynamicData
  
type
  HostEnableAdminFailedEvent* = ref object of HostEvent
    permissions*: seq[Permission]

type
  OvfPropertyQualifierDuplicate* = ref object of OvfProperty
    qualifier*: string

type
  DiagnosticManagerLogDescriptor* = ref object of DynamicData
    key*: string
    fileName*: string
    creator*: string
    format*: string
    mimeType*: string
    info*: Description

type
  CustomizationSpec* = ref object of DynamicData
    options*: CustomizationOptions
    identity*: CustomizationIdentitySettings
    globalIPSettings*: CustomizationGlobalIPSettings
    nicSettingMap*: seq[CustomizationAdapterMapping]
    encryptionKey*: seq[byte]

type
  VslmCreateSpecDiskFileBackingSpec* = ref object of VslmCreateSpecBackingSpec
    provisioningType*: string

type
  PowerSystemInfo* = ref object of DynamicData
    currentPolicy*: HostPowerPolicy

type
  VmfsDatastoreOption* = ref object of DynamicData
    info*: VmfsDatastoreBaseOption
    spec*: VmfsDatastoreSpec

type
  DatastoreFileCopiedEvent* = ref object of DatastoreFileEvent
    sourceDatastore*: DatastoreEventArgument
    sourceFile*: string

type
  UpdateVirtualMachineFilesResultFailedVmFileInfo* = ref object of DynamicData
    vmFile*: string
    fault*: MethodFault

type
  VmMessageErrorEvent* = ref object of VmEvent
    message*: string
    messageInfo*: seq[VirtualMachineMessage]

type
  NasVolumeNotMounted* = ref object of NasConfigFault
    remoteHost*: string
    remotePath*: string

type
  HostInternetScsiHbaIPProperties* = ref object of DynamicData
    mac*: string
    address*: string
    dhcpConfigurationEnabled*: bool
    subnetMask*: string
    defaultGateway*: string
    primaryDnsServerAddress*: string
    alternateDnsServerAddress*: string
    ipv6Address*: string
    ipv6SubnetMask*: string
    ipv6DefaultGateway*: string
    arpRedirectEnabled*: bool
    mtu*: int
    jumboFramesEnabled*: bool
    ipv4Enabled*: bool
    ipv6Enabled*: bool
    ipv6properties*: HostInternetScsiHbaIPv6Properties

type
  GuestOsDescriptorFirmwareType* {.pure.} = enum
    bios, efi, csm
type
  VasaVvolManager* = ref object of vmodl.ManagedObject
  
type
  ClusterDasConfigInfoHBDatastoreCandidate* {.pure.} = enum
    userSelectedDs, allFeasibleDs, allFeasibleDsWithUserPreference
type
  IscsiManager* = ref object of vmodl.ManagedObject
  
type
  HostPlugStoreTopology* = ref object of DynamicData
    adapter*: seq[HostPlugStoreTopologyAdapter]
    path*: seq[HostPlugStoreTopologyPath]
    target*: seq[HostPlugStoreTopologyTarget]
    device*: seq[HostPlugStoreTopologyDevice]
    plugin*: seq[HostPlugStoreTopologyPlugin]

type
  CannotReconfigureVsanWhenHaEnabled* = ref object of VsanFault
  
type
  HostScsiDisk* = ref object of ScsiLun
    capacity*: HostDiskDimensionsLba
    devicePath*: string
    ssd*: bool
    localDisk*: bool
    physicalLocation*: seq[string]
    emulatedDIXDIFEnabled*: bool
    vsanDiskInfo*: VsanHostVsanDiskInfo
    scsiDiskType*: string

type
  SSPIAuthentication* = ref object of GuestAuthentication
    sspiToken*: string

type
  VirtualPointingDeviceBackingOption* = ref object of VirtualDeviceDeviceBackingOption
    hostPointingDevice*: ChoiceOption

type
  VmDiscoveredEvent* = ref object of VmEvent
  
type
  HostFlagInfo* = ref object of DynamicData
    backgroundSnapshotsEnabled*: bool

type
  HostPowerPolicy* = ref object of DynamicData
    key*: int
    name*: string
    shortName*: string
    description*: string

type
  VirtualDiskModeNotSupported* = ref object of DeviceNotSupported
    mode*: string

type
  HostMonitoringStateChangedEvent* = ref object of ClusterEvent
    state*: string
    prevState*: string

type
  HostNasVolumeSecurityType* {.pure.} = enum
    AUTH_SYS, SEC_KRB5, SEC_KRB5I
type
  SnapshotNoChange* = ref object of SnapshotFault
  
type
  VStorageObjectAssociationsVmDiskAssociations* = ref object of DynamicData
    vmId*: string
    diskKey*: int

type
  VirtualMachineFileLayoutExDiskLayout* = ref object of DynamicData
    key*: int
    chain*: seq[VirtualMachineFileLayoutExDiskUnit]

type
  InsufficientStorageIops* = ref object of VimFault
    unreservedIops*: int64
    requestedIops*: int64
    datastoreName*: string

type
  VirtualHardwareVersionNotSupported* = ref object of VirtualHardwareCompatibilityIssue
    hostName*: string
    host*: HostSystem

type
  HostInternetScsiHbaDigestProperties* = ref object of DynamicData
    headerDigestType*: string
    headerDigestInherited*: bool
    dataDigestType*: string
    dataDigestInherited*: bool

type
  CannotUseNetwork* = ref object of VmConfigFault
    device*: string
    backing*: string
    connected*: bool
    reason*: string
    network*: Network

type
  InaccessibleDatastore* = ref object of InvalidDatastore
    detail*: string

type
  CustomizationIpGenerator* = ref object of DynamicData
  
type
  StorageDrsCannotMoveTemplate* = ref object of VimFault
  
type
  DvsUpdateTagNetworkRuleAction* = ref object of DvsNetworkRuleAction
    qosTag*: int
    dscpTag*: int

type
  EVCMode* = ref object of ElementDescription
    guaranteedCPUFeatures*: seq[HostCpuIdInfo]
    featureCapability*: seq[HostFeatureCapability]
    featureMask*: seq[HostFeatureMask]
    featureRequirement*: seq[VirtualMachineFeatureRequirement]
    vendor*: string
    track*: seq[string]
    vendorTier*: int

type
  StorageDrsConfigInfo* = ref object of DynamicData
    podConfig*: StorageDrsPodConfigInfo
    vmConfig*: seq[StorageDrsVmConfigInfo]

type
  DasDisabledEvent* = ref object of ClusterEvent
  
type
  LicenseUsageInfo* = ref object of DynamicData
    source*: LicenseSource
    sourceAvailable*: bool
    reservationInfo*: seq[LicenseReservationInfo]
    featureInfo*: seq[LicenseFeatureInfo]

type
  PerfMetricIntSeries* = ref object of PerfMetricSeries
    value*: seq[int64]

type
  HostIntegrityReportQuoteData* = ref object of DynamicData
    pcrValues*: seq[HostTpmDigestInfo]
    quoteInfo*: HostIntegrityReportQuoteInfo
    tpmSignature*: HostSignatureInfo

type
  HostParallelScsiTargetTransport* = ref object of HostTargetTransport
  
type
  HostLocalAuthentication* = ref object of vim.host.AuthenticationStore
  
type
  SnapshotMoveFromNonHomeNotSupported* = ref object of SnapshotCopyNotSupported
  
type
  SendSNMPAction* = ref object of Action
  
type
  InvalidVmState* = ref object of InvalidState
    vm*: VirtualMachine

type
  HostNasVolumeSpec* = ref object of DynamicData
    remoteHost*: string
    remotePath*: string
    localPath*: string
    accessMode*: string
    type*: string
    userName*: string
    password*: string
    remoteHostNames*: seq[string]
    securityType*: string

type
  VmRemovedEvent* = ref object of VmEvent
  
type
  VsanHostConfigInfoStorageInfo* = ref object of DynamicData
    autoClaimStorage*: bool
    diskMapping*: seq[VsanHostDiskMapping]
    diskMapInfo*: seq[VsanHostDiskMapInfo]
    checksumEnabled*: bool

type
  PolicyViolatedDetail* = ref object of VimFault
    policyUrn*: seq[string]

type
  BoolPolicy* = ref object of InheritablePolicy
    value*: bool

type
  InvalidDasRestartPriorityForFtVm* = ref object of InvalidArgument
    vm*: VirtualMachine
    vmName*: string

type
  NetworksMayNotBeTheSame* = ref object of MigrationFault
    name*: string

type
  VirtualDiskSparseVer1BackingOption* = ref object of VirtualDeviceFileBackingOption
    diskModes*: ChoiceOption
    split*: BoolOption
    writeThrough*: BoolOption
    growable*: bool

type
  DuplicateDisks* = ref object of VsanDiskFault
  
type
  FailToEnableSPBM* = ref object of NotEnoughLicenses
    cs*: ComputeResource
    csName*: string
    hostLicenseStates*: seq[ComputeResourceHostSPBMLicenseInfo]

type
  DrsEnteredStandbyModeEvent* = ref object of EnteredStandbyModeEvent
  
type
  HostProfileManager* = ref object of vim.profile.ProfileManager
    supportedCustomizationFormats*: seq[ExtendedElementDescription]

type
  VAppCloneSpecResourceMap* = ref object of DynamicData
    source*: ManagedEntity
    parent*: ResourcePool
    resourceSpec*: ResourceConfigSpec
    location*: Datastore

type
  HostReconnectionFailedEvent* = ref object of HostEvent
  
type
  VirtualMachineInstantCloneSpec* = ref object of DynamicData
    name*: string
    location*: VirtualMachineRelocateSpec
    config*: seq[OptionValue]
    biosUuid*: string

type
  GuestProgramSpec* = ref object of DynamicData
    programPath*: string
    arguments*: string
    workingDirectory*: string
    envVariables*: seq[string]

type
  HostDistributedVirtualSwitchManagerFetchPortOption* {.pure.} = enum
    runtimeInfoOnly, statsOnly, stateBlobOnly
type
  PolicyViolated* = ref object of RuntimeFault
    reasons*: seq[MethodFault]

type
  TagPolicyOption* = ref object of vim.ManagedEntity
  
type
  OperationDisabledByGuest* = ref object of GuestOperationsFault
  
type
  ServiceLocator* = ref object of DynamicData
    instanceUuid*: string
    url*: string
    credential*: ServiceLocatorCredential
    sslThumbprint*: string

type
  ClusterVmComponentProtectionSettingsVmReactionOnAPDCleared* {.pure.} = enum
    none, reset, useClusterDefault
type
  VmAcquiredTicketEvent* = ref object of VmEvent
    ticketType*: string

type
  DVSNetworkResourceManagementCapability* = ref object of DynamicData
    networkResourceManagementSupported*: bool
    networkResourcePoolHighShareValue*: int
    qosSupported*: bool
    userDefinedNetworkResourcePoolsSupported*: bool
    networkResourceControlVersion3Supported*: bool
    userDefinedInfraTrafficPoolSupported*: bool

type
  DirectoryNotEmpty* = ref object of FileFault
  
type
  VmPodConfigForPlacement* = ref object of DynamicData
    storagePod*: StoragePod
    disk*: seq[PodDiskLocator]
    vmConfig*: StorageDrsVmConfigInfo
    interVmRule*: seq[ClusterRuleInfo]

type
  VmShutdownOnIsolationEventOperation* {.pure.} = enum
    shutdown, poweredOff
type
  GuestAuthAnySubject* = ref object of GuestAuthSubject
  
type
  PatchInstallFailed* = ref object of PlatformConfigFault
    rolledBack*: bool

type
  DasHostIsolatedEvent* = ref object of ClusterEvent
    isolatedHost*: HostEventArgument

type
  DVPortState* = ref object of DynamicData
    runtimeInfo*: DVPortStatus
    stats*: DistributedVirtualSwitchPortStatistics
    vendorSpecificState*: seq[DistributedVirtualSwitchKeyedOpaqueBlob]

type
  VirtualDeviceBackingOption* = ref object of DynamicData
    type*: string

type
  VirtualUSBUSBBackingOption* = ref object of VirtualDeviceDeviceBackingOption
  
type
  VirtualDeviceURIBackingInfo* = ref object of VirtualDeviceBackingInfo
    serviceURI*: string
    direction*: string
    proxyURI*: string

type
  HostInternetScsiHbaStaticTarget* = ref object of DynamicData
    address*: string
    port*: int
    iScsiName*: string
    discoveryMethod*: string
    authenticationProperties*: HostInternetScsiHbaAuthenticationProperties
    digestProperties*: HostInternetScsiHbaDigestProperties
    supportedAdvancedOptions*: seq[OptionDef]
    advancedOptions*: seq[HostInternetScsiHbaParamValue]
    parent*: string

type
  StateAlarmExpression* = ref object of AlarmExpression
    operator*: StateAlarmOperator
    type*: string
    statePath*: string
    yellow*: string
    red*: string

type
  DvsEventArgument* = ref object of EntityEventArgument
    dvs*: DistributedVirtualSwitch

type
  StorageRequirement* = ref object of DynamicData
    datastore*: Datastore
    freeSpaceRequiredInKb*: int64

type
  DeviceNotSupported* = ref object of VirtualHardwareCompatibilityIssue
    device*: string
    reason*: string

type
  HostHealthStatusSystem* = ref object of vmodl.ManagedObject
    runtime*: HealthSystemRuntime

type
  GuestRegValueExpandStringSpec* = ref object of GuestRegValueDataSpec
    value*: string

type
  InvalidLocale* = ref object of VimFault
  
type
  DvsApplyOperationFault* = ref object of DvsFault
    objectFault*: seq[DvsApplyOperationFaultFaultOnObject]

type
  NotSupportedHostForVmemFile* = ref object of NotSupportedHost
    hostName*: string

type
  NotSupportedHostForVmcp* = ref object of NotSupportedHost
    hostName*: string

type
  PhysicalNicIpHint* = ref object of PhysicalNicHint
    ipSubnet*: string

type
  VirtualMachineBootOptionsBootableDevice* = ref object of DynamicData
  
type
  NetworkEventArgument* = ref object of EntityEventArgument
    network*: Network

type
  OvfNoHostNic* = ref object of OvfUnsupportedPackage
  
type
  DvsNetworkRuleDirectionType* {.pure.} = enum
    incomingPackets, outgoingPackets, both
type
  UnableToPlacePrerequisiteGroup* = ref object of VimFault
  
type
  VmFailedMigrateEvent* = ref object of VmEvent
    destHost*: HostEventArgument
    reason*: MethodFault
    destDatacenter*: DatacenterEventArgument
    destDatastore*: DatastoreEventArgument

type
  VmWwnChangedEvent* = ref object of VmEvent
    oldNodeWwns*: seq[int64]
    oldPortWwns*: seq[int64]
    newNodeWwns*: seq[int64]
    newPortWwns*: seq[int64]

type
  LeaseFault* = ref object of VimFault
  
type
  VirtualFloppyDeviceBackingOption* = ref object of VirtualDeviceDeviceBackingOption
  
type
  HostVirtualNicSpec* = ref object of DynamicData
    ip*: HostIpConfig
    mac*: string
    distributedVirtualPort*: DistributedVirtualSwitchPortConnection
    portgroup*: string
    mtu*: int
    tsoEnabled*: bool
    netStackInstanceKey*: string
    opaqueNetwork*: HostVirtualNicOpaqueNetworkSpec
    externalId*: string
    pinnedPnic*: string
    ipRouteSpec*: HostVirtualNicIpRouteSpec

type
  HostFirewallRulesetIpNetwork* = ref object of DynamicData
    network*: string
    prefixLength*: int

type
  VirtualPCIControllerOption* = ref object of VirtualControllerOption
    numSCSIControllers*: IntOption
    numEthernetCards*: IntOption
    numVideoCards*: IntOption
    numSoundCards*: IntOption
    numVmiRoms*: IntOption
    numVmciDevices*: IntOption
    numPCIPassthroughDevices*: IntOption
    numSasSCSIControllers*: IntOption
    numVmxnet3EthernetCards*: IntOption
    numParaVirtualSCSIControllers*: IntOption
    numSATAControllers*: IntOption
    numNVMEControllers*: IntOption
    numVmxnet3VrdmaEthernetCards*: IntOption

type
  NotSupportedHostInCluster* = ref object of NotSupportedHost
  
type
  DvsVmVnicNetworkResourcePoolRuntimeInfo* = ref object of DynamicData
    key*: string
    name*: string
    capacity*: int
    usage*: int
    available*: int
    status*: string
    allocatedResource*: seq[DvsVnicAllocatedResource]

type
  HostConfigSummary* = ref object of DynamicData
    name*: string
    port*: int
    sslThumbprint*: string
    product*: AboutInfo
    vmotionEnabled*: bool
    faultToleranceEnabled*: bool
    featureVersion*: seq[HostFeatureVersionInfo]
    agentVmDatastore*: Datastore
    agentVmNetwork*: Network

type
  VmReloadFromPathEvent* = ref object of VmEvent
    configPath*: string

type
  HealthUpdateManager* = ref object of vmodl.ManagedObject
  
type
  VmUpgradeCompleteEvent* = ref object of VmEvent
    version*: string

type
  HostVirtualSwitchSpec* = ref object of DynamicData
    numPorts*: int
    bridge*: HostVirtualSwitchBridge
    policy*: HostNetworkPolicy
    mtu*: int

type
  TaskInfoState* {.pure.} = enum
    queued, running, success, error
type
  MigrationNotReady* = ref object of MigrationFault
    reason*: string

type
  IoFilterOperation* {.pure.} = enum
    install, uninstall, upgrade
type
  HostMultipathInfoFixedLogicalUnitPolicy* = ref object of HostMultipathInfoLogicalUnitPolicy
    prefer*: string

type
  HostPatchManager* = ref object of vmodl.ManagedObject
  
type
  VmReloadFromPathFailedEvent* = ref object of VmEvent
    configPath*: string

type
  ResourcePoolMovedEvent* = ref object of ResourcePoolEvent
    oldParent*: ResourcePoolEventArgument
    newParent*: ResourcePoolEventArgument

type
  Network* = ref object of vim.ManagedEntity
    summary*: NetworkSummary
    host*: seq[HostSystem]
    vm*: seq[VirtualMachine]

type
  DatastoreDiscoveredEvent* = ref object of HostEvent
    datastore*: DatastoreEventArgument

type
  VirtualMachineFileLayoutExFileType* {.pure.} = enum
    config, extendedConfig, diskDescriptor, diskExtent, digestDescriptor,
    digestExtent, diskReplicationState, log, stat, namespaceData, nvram, snapshotData,
    snapshotMemory, snapshotList, snapshotManifestList, suspend, suspendMemory, swap,
    uwswap, core, screenshot, ftMetadata, guestCustomization
type
  HostSignatureInfoSigningMethodType* {.pure.} = enum
    DSA_SHA1, RSA_SHA1, RSA_MD5
type
  DatastoreIORMReconfiguredEvent* = ref object of DatastoreEvent
  
type
  DeviceNotFound* = ref object of InvalidDeviceSpec
  
type
  FtIssuesOnHost* = ref object of VmFaultToleranceIssue
    host*: HostSystem
    hostName*: string
    errors*: seq[MethodFault]

type
  DatastorePrincipalConfigured* = ref object of HostEvent
    datastorePrincipal*: string

type
  LinkLayerDiscoveryProtocolInfo* = ref object of DynamicData
    chassisId*: string
    portId*: string
    timeToLive*: int
    parameter*: seq[KeyAnyValue]

type
  StorageDrsCannotMoveDiskInMultiWriterMode* = ref object of VimFault
  
type
  LocalizationManagerMessageCatalog* = ref object of DynamicData
    moduleName*: string
    catalogName*: string
    locale*: string
    catalogUri*: string
    lastModified*: string
    md5sum*: string
    version*: string

type
  ClusterDiagnoseResourceAllocationResultVmStaticEntitlement* = ref object of DynamicData
    vm*: VirtualMachine
    staticEntitlement*: seq[ClusterPerResourceValue]

type
  VmfsUnmapBandwidthSpec* = ref object of DynamicData
    policy*: string
    fixedValue*: int64
    dynamicMin*: int64
    dynamicMax*: int64

type
  StorageDrsVmConfigInfo* = ref object of DynamicData
    vm*: VirtualMachine
    enabled*: bool
    behavior*: string
    intraVmAffinity*: bool
    intraVmAntiAffinity*: VirtualDiskAntiAffinityRuleSpec
    virtualDiskRules*: seq[VirtualDiskRuleSpec]

type
  BadUsernameSessionEvent* = ref object of SessionEvent
    ipAddress*: string

type
  OvfPropertyExport* = ref object of OvfExport
    type*: string
    value*: string

type
  NetIpStackInfoDefaultRouter* = ref object of DynamicData
    ipAddress*: string
    device*: string
    lifetime*: string
    preference*: string

type
  ProfileHostHostCustomizationOperationIssues* = ref object of DynamicData
    warnings*: seq[LocalizableMessage]
    errors*: seq[LocalizableMessage]

type
  VirtualEthernetCardOpaqueNetworkBackingOption* = ref object of VirtualDeviceBackingOption
  
type
  CryptoManagerKmipServerCertInfo* = ref object of DynamicData
    certificate*: string
    certInfo*: CryptoManagerKmipCertificateInfo
    clientTrustServer*: bool

type
  InvalidDatastore* = ref object of VimFault
    datastore*: Datastore
    name*: string

type
  InvalidIndexArgument* = ref object of InvalidArgument
    key*: string

type
  InvalidDrsBehaviorForFtVm* = ref object of InvalidArgument
    vm*: VirtualMachine
    vmName*: string

type
  OvfUnsupportedDeviceBackingInfo* = ref object of OvfSystemFault
    elementName*: string
    instanceId*: string
    deviceName*: string
    backingName*: string

type
  VirtualMachineSoundInfo* = ref object of VirtualMachineTargetInfo
  
type
  DatastoreNamespaceManager* = ref object of vmodl.ManagedObject
  
type
  VirtualMachineNamespaceManagerAccessMode* = ref object of DynamicData
    guestWriteable*: bool
    vmodlWriteable*: bool

type
  StorageProfile* = ref object of ApplyProfile
    nasStorage*: seq[NasStorageProfile]

type
  VirtualPointingDeviceHostChoice* {.pure.} = enum
    autodetect, intellimouseExplorer, intellimousePs2, logitechMouseman,
    microsoft_serial, mouseSystems, mousemanSerial, ps2
type
  AlarmTriggeringAction* = ref object of AlarmAction
    action*: Action
    transitionSpecs*: seq[AlarmTriggeringActionTransitionSpec]
    green2yellow*: bool
    yellow2red*: bool
    red2yellow*: bool
    yellow2green*: bool

type
  HostProfileMapping* = ref object of DynamicData
    apiId*: string
    profileTypeName*: string
    data*: HostProfileMappingProfileMappingData
    policyMapping*: seq[HostProfilePolicyMapping]

type
  HostVmfsVolumeUnmapBandwidthPolicy* {.pure.} = enum
    fixed, dynamic
type
  AlreadyExists* = ref object of VimFault
    name*: string

type
  NoClientCertificate* = ref object of VimFault
  
type
  NoVirtualNic* = ref object of HostConfigFault
  
type
  DisallowedDiskModeChange* = ref object of InvalidDeviceSpec
  
type
  VsanHostDecommissionMode* = ref object of DynamicData
    objectAction*: string

type
  HostLicenseExpiredEvent* = ref object of LicenseEvent
  
type
  CryptoSpecDeepRecrypt* = ref object of CryptoSpec
    newKeyId*: CryptoKeyId

type
  VirtualMachineNamespaceManagerDataInfo* = ref object of DynamicData
    key*: string
    value*: string

type
  HostFirewallRulePortType* {.pure.} = enum
    src, dst
type
  VmBeingHotMigratedEvent* = ref object of VmEvent
    destHost*: HostEventArgument
    destDatacenter*: DatacenterEventArgument
    destDatastore*: DatastoreEventArgument

type
  PerfCounterInfo* = ref object of DynamicData
    key*: int
    nameInfo*: ElementDescription
    groupInfo*: ElementDescription
    unitInfo*: ElementDescription
    rollupType*: PerfSummaryType
    statsType*: PerfStatsType
    level*: int
    perDeviceLevel*: int
    associatedCounterId*: seq[int]

type
  HostEsxAgentHostManager* = ref object of vmodl.ManagedObject
    configInfo*: HostEsxAgentHostManagerConfigInfo

type
  EntityDisabledMethodInfo* = ref object of DynamicData
    entity*: ManagedEntity
    methodList*: seq[DisabledMethodInfo]

type
  PlacementAffinityRuleRuleType* {.pure.} = enum
    affinity, antiAffinity, softAffinity, softAntiAffinity
type
  AnswerFileValidationResultMap* = ref object of DynamicData
    host*: HostSystem
    validationResult*: AnswerFileValidationResult
    fault*: MethodFault

type
  ScheduledTaskCreatedEvent* = ref object of ScheduledTaskEvent
  
type
  NegatableExpression* = ref object of DynamicData
    negate*: bool

type
  VirtualFloppyRemoteDeviceBackingOption* = ref object of VirtualDeviceRemoteDeviceBackingOption
  
type
  ClusterDasFdmHostState* = ref object of DynamicData
    state*: string
    stateReporter*: HostSystem

type
  HostDVSPortData* = ref object of DynamicData
    portKey*: string
    portgroupKey*: string
    name*: string
    state*: DVPortState
    setting*: DVPortSetting
    connectionCookie*: int
    portPersistenceLocation*: string
    shadowPort*: bool
    keyedOpaqueDataList*: DVSKeyedOpaqueDataList
    opaqueDataList*: DVSOpaqueDataList
    opaqueRuntimeDataList*: DVSKeyedOpaqueDataList
    runtimeDataList*: DVSOpaqueDataList
    vspanConfig*: seq[VMwareVspanSession]
    extraConfig*: seq[KeyValue]

type
  NotEnoughResourcesToStartVmEvent* = ref object of VmEvent
    reason*: string

type
  StoragePodSummary* = ref object of DynamicData
    name*: string
    capacity*: int64
    freeSpace*: int64

type
  HostNetStackInstanceCongestionControlAlgorithmType* {.pure.} = enum
    newreno, cubic
type
  LicenseDataManagerEntityLicenseData* = ref object of DynamicData
    key*: ManagedEntity
    licenseData*: LicenseDataManagerLicenseData

type
  MemorySizeNotSupportedByDatastore* = ref object of VirtualHardwareCompatibilityIssue
    datastore*: Datastore
    memorySizeMB*: int
    maxMemorySizeMB*: int

type
  VirtualSwitchSelectionProfile* = ref object of ApplyProfile
  
type
  CannotDeleteFile* = ref object of FileFault
  
type
  CbrcVmdkLockFailure* = ref object of VimFault
  
type
  DVSMacManagementPolicy* = ref object of InheritablePolicy
    allowPromiscuous*: bool
    macChanges*: bool
    forgedTransmits*: bool
    macLearningPolicy*: DVSMacLearningPolicy

type
  VMwareDVSVlanHealthCheckResult* = ref object of HostMemberUplinkHealthCheckResult
    trunkedVlan*: seq[NumericRange]
    untrunkedVlan*: seq[NumericRange]

type
  HostDhcpServiceSpec* = ref object of DynamicData
    virtualSwitch*: string
    defaultLeaseDuration*: int
    leaseBeginIp*: string
    leaseEndIp*: string
    maxLeaseDuration*: int
    unlimitedLease*: bool
    ipSubnetAddr*: string
    ipSubnetMask*: string

type
  EVCAdmissionFailedCPUVendor* = ref object of EVCAdmissionFailed
    clusterCPUVendor*: string
    hostCPUVendor*: string

type
  IscsiDependencyEntity* = ref object of DynamicData
    pnicDevice*: string
    vnicDevice*: string
    vmhbaName*: string

type
  MetricAlarmExpression* = ref object of AlarmExpression
    operator*: MetricAlarmOperator
    type*: string
    metric*: PerfMetricId
    yellow*: int
    yellowInterval*: int
    red*: int
    redInterval*: int

type
  VslmCreateSpec* = ref object of DynamicData
    name*: string
    keepAfterDeleteVm*: bool
    backingSpec*: VslmCreateSpecBackingSpec
    capacityInMB*: int64
    profile*: seq[VirtualMachineProfileSpec]

type
  MacRange* = ref object of MacAddress
    address*: string
    mask*: string

type
  DVSOpaqueData* = ref object of DynamicData
    key*: string
    opaqueData*: byte

type
  HostLowLevelProvisioningManagerFileDeleteResult* = ref object of DynamicData
    fileName*: string
    fault*: MethodFault

type
  CannotMoveFaultToleranceVm* = ref object of VimFault
    moveType*: string
    vmName*: string

type
  PerfMetricSeriesCSV* = ref object of PerfMetricSeries
    value*: string

type
  OperationDisallowedOnHost* = ref object of RuntimeFault
  
type
  EVCUnsupportedByHostHardware* = ref object of EVCConfigFault
    host*: seq[HostSystem]
    hostName*: seq[string]

type
  ImportSpec* = ref object of DynamicData
    entityConfig*: VAppEntityConfigInfo
    instantiationOst*: OvfConsumerOstNode

type
  VmEventArgument* = ref object of EntityEventArgument
    vm*: VirtualMachine

type
  InsufficientAgentVmsDeployed* = ref object of InsufficientResourcesFault
    hostName*: string
    requiredNumAgentVms*: int
    currentNumAgentVms*: int

type
  HostVMotionSystem* = ref object of vim.ExtensibleManagedObject
    netConfig*: HostVMotionNetConfig
    ipConfig*: HostIpConfig

type
  DataProviderFilter* = ref object of DynamicData
    criteria*: seq[DataProviderPropertyPredicate]
    operator*: string

type
  HostDVSPortCloneSpec* = ref object of DynamicData
    oldPortKey*: string
    newPortKey*: string
    portPersistenceLocation*: string

type
  HostActiveDirectoryAuthentication* = ref object of vim.host.DirectoryStore
  
type
  VsanUpgradeSystemUpgradeStatus* = ref object of DynamicData
    inProgress*: bool
    history*: seq[VsanUpgradeSystemUpgradeHistoryItem]
    aborted*: bool
    completed*: bool
    progress*: int

type
  VirtualMachineProfileRawData* = ref object of DynamicData
    extensionKey*: string
    objectData*: string

type
  HostLicensableResourceKey* {.pure.} = enum
    numCpuPackages, numCpuCores, memorySize, memoryForVms, numVmsStarted,
    numVmsStarting
type
  PerfEntityMetricCSV* = ref object of PerfEntityMetricBase
    sampleInfoCSV*: string
    value*: seq[PerfMetricSeriesCSV]

type
  ProxyServiceRemoteTunnelSpec* = ref object of ProxyServiceTunnelSpec
    hostName*: string
    port*: int

type
  VmPortGroupProfile* = ref object of PortGroupProfile
  
type
  EventAlarmExpression* = ref object of AlarmExpression
    comparisons*: seq[EventAlarmExpressionComparison]
    eventType*: string
    eventTypeId*: string
    objectType*: string
    status*: ManagedEntityStatus

type
  SnapshotFault* = ref object of VimFault
  
type
  AffinityConfigured* = ref object of MigrationFault
    configuredAffinity*: seq[string]

type
  DistributedVirtualSwitchPortConnectee* = ref object of DynamicData
    connectedEntity*: ManagedEntity
    nicKey*: string
    type*: string
    addressHint*: string

type
  OutOfBounds* = ref object of VimFault
    argumentName*: string

type
  HostDatastoreSystemCapabilities* = ref object of DynamicData
    nfsMountCreationRequired*: bool
    nfsMountCreationSupported*: bool
    localDatastoreSupported*: bool
    vmfsExtentExpansionSupported*: bool

type
  VirtualMachineSnapshotTree* = ref object of DynamicData
    snapshot*: VirtualMachineSnapshot
    vm*: VirtualMachine
    name*: string
    description*: string
    id*: int
    createTime*: string
    state*: VirtualMachinePowerState
    quiesced*: bool
    backupManifest*: string
    childSnapshotList*: seq[VirtualMachineSnapshotTree]
    replaySupported*: bool

type
  NetIpStackInfoPreference* {.pure.} = enum
    reserved, low, medium, high
type
  ExtensionEventTypeInfo* = ref object of DynamicData
    eventID*: string
    eventTypeSchema*: string

type
  InvalidNetworkResource* = ref object of NasConfigFault
    remoteHost*: string
    remotePath*: string

type
  InvalidLogin* = ref object of VimFault
  
type
  VirtualMachineDeviceRuntimeInfoVirtualEthernetCardRuntimeStateVmDirectPathGen2InactiveReasonOther*
      {.pure.} = enum
    vmNptIncompatibleHost, vmNptIncompatibleNetwork
type
  VirtualMachinePowerPolicy* = ref object of DynamicData
    powerMode*: string
    acProfile*: VirtualMachinePowerPolicyProfile
    batteryProfile*: VirtualMachinePowerPolicyProfile

type
  HostDasEnabledEvent* = ref object of HostEvent
  
type
  ClusterHostPowerAction* = ref object of ClusterAction
    operationType*: HostPowerOperationType
    powerConsumptionWatt*: int
    cpuCapacityMHz*: int
    memCapacityMB*: int

type
  CryptoManagerKmipCertificateInfo* = ref object of DynamicData
    subject*: string
    issuer*: string
    serialNumber*: string
    notBefore*: string
    notAfter*: string
    fingerprint*: string
    checkTime*: string
    secondsSinceValid*: int
    secondsBeforeExpire*: int

type
  HostProtocolEndpointPEType* {.pure.} = enum
    block, nas
type
  InsufficientStandbyCpuResource* = ref object of InsufficientStandbyResource
    available*: int64
    requested*: int64

type
  VirtualMachinePauseManager* = ref object of vmodl.ManagedObject
  
type
  HostPatchManagerReason* {.pure.} = enum
    obsoleted, missingPatch, missingLib, hasDependentPatch, conflictPatch,
    conflictLib
type
  NotAFile* = ref object of FileFault
  
type
  HostIpmiInfo* = ref object of DynamicData
    bmcIpAddress*: string
    bmcMacAddress*: string
    login*: string
    password*: string

type
  VirtualMachineBootOptionsBootableFloppyDevice* = ref object of VirtualMachineBootOptionsBootableDevice
  
type
  HostDigestInfoDigestMethodType* {.pure.} = enum
    SHA1, MD5, SHA256, SHA384, SHA512, SM3_256
type
  EsxAgentConfigManagerComputeResourceAgentInfo* = ref object of DynamicData
    computeResource*: ComputeResource
    numRequiredAgents*: int

type
  ExternalStatsManagerMetricValueMap* = ref object of DynamicData
    metricType*: string
    startTimeMs*: int64
    statValues*: seq[ExternalStatsManagerTimeValuePair]

type
  DistributedVirtualSwitchPortStatistics* = ref object of DynamicData
    packetsInMulticast*: int64
    packetsOutMulticast*: int64
    bytesInMulticast*: int64
    bytesOutMulticast*: int64
    packetsInUnicast*: int64
    packetsOutUnicast*: int64
    bytesInUnicast*: int64
    bytesOutUnicast*: int64
    packetsInBroadcast*: int64
    packetsOutBroadcast*: int64
    bytesInBroadcast*: int64
    bytesOutBroadcast*: int64
    packetsInDropped*: int64
    packetsOutDropped*: int64
    packetsInException*: int64
    packetsOutException*: int64
    bytesInFromPnic*: int64
    bytesOutToPnic*: int64

type
  VsanUpgradeSystemUpgradeHistoryDiskGroupOpType* {.pure.} = enum
    add, remove
type
  InventoryDescription* = ref object of DynamicData
    numHosts*: int
    numVirtualMachines*: int
    numResourcePools*: int
    numClusters*: int
    numCpuDev*: int
    numNetDev*: int
    numDiskDev*: int
    numvCpuDev*: int
    numvNetDev*: int
    numvDiskDev*: int

type
  VmStartReplayingEvent* = ref object of VmEvent
  
type
  OptionValue* = ref object of DynamicData
    key*: string
    value*: pointer

type
  ClusterVmComponentProtectionSettings* = ref object of DynamicData
    vmStorageProtectionForAPD*: string
    enableAPDTimeoutForHosts*: bool
    vmTerminateDelayForAPDSec*: int
    vmReactionOnAPDCleared*: string
    vmStorageProtectionForPDL*: string

type
  EntityBackup* = ref object of DynamicData
  
type
  InternetScsiSnsDiscoveryMethod* {.pure.} = enum
    isnsStatic, isnsDhcp, isnsSlp
type
  SelectionSet* = ref object of DynamicData
  
type
  VmRelocateSpecEvent* = ref object of VmEvent
  
type
  EventArgDesc* = ref object of DynamicData
    name*: string
    type*: string
    array*: bool
    eventObject*: bool
    description*: ElementDescription

type
  HostGatewaySpec* = ref object of DynamicData
    gatewayType*: string
    gatewayId*: string
    trustVerificationToken*: string
    hostAuthParams*: seq[KeyValue]

type
  ClusterConfigInfo* = ref object of DynamicData
    dasConfig*: ClusterDasConfigInfo
    dasVmConfig*: seq[ClusterDasVmConfigInfo]
    drsConfig*: ClusterDrsConfigInfo
    drsVmConfig*: seq[ClusterDrsVmConfigInfo]
    rule*: seq[ClusterRuleInfo]

type
  ApplyProfile* = ref object of DynamicData
    enabled*: bool
    policy*: seq[ProfilePolicy]
    profileTypeName*: string
    profileVersion*: string
    property*: seq[ProfileApplyProfileProperty]
    favorite*: bool
    toBeMerged*: bool
    toReplaceWith*: bool
    toBeDeleted*: bool
    copyEnableStatus*: bool
    hidden*: bool

type
  HostActiveDirectoryInfo* = ref object of HostDirectoryStoreInfo
    joinedDomain*: string
    trustedDomain*: seq[string]
    domainMembershipStatus*: string
    smartCardAuthenticationEnabled*: bool

type
  CbrcDigestRecomputeResult* = ref object of CbrcDigestOperationResult
  
type
  UnSupportedDatastoreForVFlash* = ref object of UnsupportedDatastore
    datastoreName*: string
    type*: string

type
  FloppyImageFileInfo* = ref object of FileInfo
  
type
  DrsHostIormStatus* = ref object of DynamicData
    status*: int64
    key*: Datastore

type
  VirtualMachineVMIROM* = ref object of VirtualDevice
  
type
  NumVirtualCpusExceedsLimit* = ref object of InsufficientResourcesFault
    maxSupportedVcpus*: int

type
  VsanHostRuntimeInfoDiskIssue* = ref object of DynamicData
    diskId*: string
    issue*: string

type
  HostConfigInfo* = ref object of DynamicData
    host*: HostSystem
    product*: AboutInfo
    deploymentInfo*: HostDeploymentInfo
    hyperThread*: HostHyperThreadScheduleInfo
    consoleReservation*: ServiceConsoleReservationInfo
    virtualMachineReservation*: VirtualMachineMemoryReservationInfo
    storageDevice*: HostStorageDeviceInfo
    multipathState*: HostMultipathStateInfo
    fileSystemVolume*: HostFileSystemVolumeInfo
    systemFile*: seq[string]
    network*: HostNetworkInfo
    vmotion*: HostVMotionInfo
    virtualNicManagerInfo*: HostVirtualNicManagerInfo
    capabilities*: HostNetCapabilities
    datastoreCapabilities*: HostDatastoreSystemCapabilities
    offloadCapabilities*: HostNetOffloadCapabilities
    service*: HostServiceInfo
    firewall*: HostFirewallInfo
    autoStart*: HostAutoStartManagerConfig
    activeDiagnosticPartition*: HostDiagnosticPartition
    option*: seq[OptionValue]
    optionDef*: seq[OptionDef]
    datastorePrincipal*: string
    localSwapDatastore*: Datastore
    systemSwapConfiguration*: HostSystemSwapConfiguration
    systemResources*: HostSystemResourceInfo
    dateTimeInfo*: HostDateTimeInfo
    flags*: HostFlagInfo
    adminDisabled*: bool
    lockdownMode*: HostLockdownMode
    ipmi*: HostIpmiInfo
    sslThumbprintInfo*: HostSslThumbprintInfo
    sslThumbprintData*: seq[HostSslThumbprintInfo]
    certificate*: seq[byte]
    pciPassthruInfo*: seq[HostPciPassthruInfo]
    authenticationManagerInfo*: HostAuthenticationManagerInfo
    featureVersion*: seq[HostFeatureVersionInfo]
    powerSystemCapability*: PowerSystemCapability
    powerSystemInfo*: PowerSystemInfo
    cacheConfigurationInfo*: seq[HostCacheConfigurationInfo]
    wakeOnLanCapable*: bool
    featureCapability*: seq[HostFeatureCapability]
    maskedFeatureCapability*: seq[HostFeatureCapability]
    vFlashConfigInfo*: HostVFlashManagerVFlashConfigInfo
    vsanHostConfig*: VsanHostConfigInfo
    domainList*: seq[string]
    scriptCheckSum*: byte
    hostConfigCheckSum*: byte
    graphicsInfo*: seq[HostGraphicsInfo]
    sharedPassthruGpuTypes*: seq[string]
    graphicsConfig*: HostGraphicsConfig
    sharedGpuCapabilities*: seq[HostSharedGpuCapabilities]
    ioFilterInfo*: seq[HostIoFilterInfo]
    sriovDevicePool*: seq[HostSriovDevicePoolInfo]

type
  HostAccountSpec* = ref object of DynamicData
    id*: string
    password*: string
    description*: string

type
  CannotUseNetworkReason* {.pure.} = enum
    NetworkReservationNotSupported, MismatchedNetworkPolicies,
    MismatchedDvsVersionOrVendor, VMotionToUnsupportedNetworkType
type
  HostShutdownEvent* = ref object of HostEvent
    reason*: string

type
  MismatchedNetworkPolicies* = ref object of MigrationFault
    device*: string
    backing*: string
    connected*: bool

type
  ProfileHostProfileEngineDvPortgroupInfo* = ref object of DynamicData
    config*: DVPortgroupConfigInfo
    portKeys*: seq[string]

type
  TaskFilterSpecByUsername* = ref object of DynamicData
    systemUser*: bool
    userList*: seq[string]

type
  FaultTolerancePrimaryPowerOnNotAttempted* = ref object of VmFaultToleranceIssue
    secondaryVm*: VirtualMachine
    primaryVm*: VirtualMachine

type
  VirtualUSBControllerPciBusSlotInfo* = ref object of VirtualDevicePciBusSlotInfo
    ehciPciSlotNumber*: int

type
  HostOperationCleanupManagerCleanupItemEntry* = ref object of DynamicData
    path*: string
    type*: string
    removeUpon*: string

type
  HostPowerOperationType* {.pure.} = enum
    powerOn, powerOff
type
  VmMacConflictEvent* = ref object of VmEvent
    conflictedVm*: VmEventArgument
    mac*: string

type
  BatchResultResult* {.pure.} = enum
    success, fail
type
  DVPortgroupCreatedEvent* = ref object of DVPortgroupEvent
  
type
  ScheduledTaskCompletedEvent* = ref object of ScheduledTaskEvent
  
type
  IscsiPortInfo* = ref object of DynamicData
    vnicDevice*: string
    vnic*: HostVirtualNic
    pnicDevice*: string
    pnic*: PhysicalNic
    switchName*: string
    switchUuid*: string
    portgroupName*: string
    portgroupKey*: string
    portKey*: string
    opaqueNetworkId*: string
    opaqueNetworkType*: string
    opaqueNetworkName*: string
    externalId*: string
    complianceStatus*: IscsiStatus
    pathStatus*: string

type
  DatacenterEvent* = ref object of Event
  
type
  LicenseAssignmentManagerFeatureLicenseAvailability* = ref object of DynamicData
    entityFeature*: LicenseAssignmentManagerEntityFeaturePair
    licensed*: bool

type
  VsanUpgradeSystemHostsDisconnectedIssue* = ref object of VsanUpgradeSystemPreflightCheckIssue
    hosts*: seq[HostSystem]

type
  DvsServiceConsoleVNicProfile* = ref object of DvsVNicProfile
  
type
  HostDiskBlockInfoExtent* = ref object of DynamicData
    logicalStart*: int64
    physicalStart*: int64
    length*: int64
    readOnly*: bool
    lazyZero*: bool

type
  EightHostLimitViolated* = ref object of VmConfigFault
  
type
  HostProfileManagerExportCustomizationsResult* = ref object of FormattedHostProfilesCustomizations
    exportIssues*: ProfileHostHostCustomizationOperationIssues

type
  VchaClusterConfigSpec* = ref object of DynamicData
    passiveIp*: string
    witnessIp*: string

type
  EnvironmentBrowserConfigTargetQuerySpec* = ref object of DynamicData
    includeDatastores*: bool
    includeNetworks*: bool
    includeDevices*: bool
    includeDisks*: bool
    vmSpecific*: bool

type
  AffinityType* {.pure.} = enum
    memory, cpu
type
  VmFaultToleranceVmTerminatedEvent* = ref object of VmEvent
    reason*: string

type
  VirtualMachineConnectionState* {.pure.} = enum
    connected, disconnected, orphaned, inaccessible, invalid
type
  IpPoolManager* = ref object of vmodl.ManagedObject
  
type
  VirtualMachineMemoryReservationSpec* = ref object of DynamicData
    virtualMachineReserved*: int64
    allocationPolicy*: string

type
  VmConfigInfo* = ref object of DynamicData
    product*: seq[VAppProductInfo]
    property*: seq[VAppPropertyInfo]
    ipAssignment*: VAppIPAssignmentInfo
    eula*: seq[string]
    ovfSection*: seq[VAppOvfSectionInfo]
    ovfEnvironmentTransport*: seq[string]
    installBootRequired*: bool
    installBootStopDelay*: int

type
  ReplicationConfigSpec* = ref object of DynamicData
    generation*: int64
    vmReplicationId*: string
    destination*: string
    port*: int
    rpo*: int64
    quiesceGuestEnabled*: bool
    paused*: bool
    oppUpdatesEnabled*: bool
    netCompressionEnabled*: bool
    netEncryptionEnabled*: bool
    encryptionDestination*: string
    encryptionPort*: int
    remoteCertificateThumbprint*: string
    disk*: seq[ReplicationInfoDiskSettings]

type
  VchaClusterRuntimeInfo* = ref object of DynamicData
    clusterState*: string
    nodeInfo*: seq[VchaNodeRuntimeInfo]
    clusterMode*: string

type
  VmfsAmbiguousMount* = ref object of VmfsMountFault
  
type
  TemplateConfigFileInfo* = ref object of VmConfigFileInfo
  
type
  ProxyServiceNamedPipeServiceSpec* = ref object of ProxyServiceServiceSpec
    pipeName*: string

type
  HostOpaqueSwitch* = ref object of DynamicData
    key*: string
    name*: string
    pnic*: seq[PhysicalNic]
    pnicZone*: seq[HostOpaqueSwitchPhysicalNicZone]
    status*: string
    vtep*: seq[HostVirtualNic]
    extraConfig*: seq[OptionValue]
    featureCapability*: seq[HostFeatureCapability]

type
  HostIntegrityReport* = ref object of DynamicData
    quoteData*: HostIntegrityReportQuoteData
    tpmEvents*: seq[HostTpmEventLogEntry]
    tpmLogReliable*: bool

type
  VirtualMachineParallelInfo* = ref object of VirtualMachineTargetInfo
  
type
  HostPMemVolume* = ref object of HostFileSystemVolume
    uuid*: string
    version*: string

type
  VmwareDistributedVirtualSwitchPvlanPortType* {.pure.} = enum
    promiscuous, isolated, community
type
  VmEndReplayingEvent* = ref object of VmEvent
  
type
  IncompatibleHostForFtSecondary* = ref object of VmFaultToleranceIssue
    host*: HostSystem
    error*: seq[MethodFault]

type
  VirtualMachineBootOptionsBootableCdromDevice* = ref object of VirtualMachineBootOptionsBootableDevice
  
type
  HostGraphicsConfig* = ref object of DynamicData
    hostDefaultGraphicsType*: string
    sharedPassthruAssignmentPolicy*: string
    deviceType*: seq[HostGraphicsConfigDeviceType]

type
  HostVsanInternalSystemDeleteVsanObjectsResult* = ref object of DynamicData
    uuid*: string
    success*: bool
    failureReason*: seq[LocalizableMessage]

type
  VirtualDiskAntiAffinityRuleSpec* = ref object of ClusterRuleInfo
    diskId*: seq[int]

type
  ClusterDasVmSettingsRestartPriority* {.pure.} = enum
    disabled, lowest, low, medium, high, highest, clusterRestartPriority
type
  BackupBlobWriteFailure* = ref object of DvsFault
    entityName*: string
    entityType*: string
    fault*: MethodFault

type
  HostDVSVmwareConfigSpec* = ref object of DynamicData
    pvlanConfigSpec*: seq[VMwareDVSPvlanConfigSpec]
    pvlanConfig*: seq[VMwareDVSPvlanMapEntry]
    vspanConfig*: seq[VMwareVspanSession]
    maxMtu*: int
    linkDiscoveryProtocolConfig*: LinkDiscoveryProtocolConfig
    beacon*: HostVirtualSwitchBeaconConfig
    ipfixConfig*: VMwareIpfixConfig
    promiscuousModeVspanSession*: string
    lacpGroupConfig*: seq[VMwareDvsLacpGroupConfig]
    multicastFilteringMode*: string
    uplinkTeamingPolicy*: VmwareUplinkPortTeamingPolicy

type
  DistributedVirtualPort* = ref object of DynamicData
    key*: string
    config*: DVPortConfigInfo
    dvsUuid*: string
    portgroupKey*: string
    proxyHost*: HostSystem
    connectee*: DistributedVirtualSwitchPortConnectee
    conflict*: bool
    conflictPortKey*: string
    state*: DVPortState
    connectionCookie*: int
    lastStatusChange*: string
    hostLocalPort*: bool

type
  CustomizationSpecManager* = ref object of vmodl.ManagedObject
    info*: seq[CustomizationSpecInfo]
    encryptionKey*: seq[byte]

type
  OvfUnableToExportDisk* = ref object of OvfHardwareExport
    diskName*: string

type
  ScheduledTaskDescription* = ref object of DynamicData
    action*: seq[TypeDescription]
    schedulerInfo*: seq[ScheduledTaskDetail]
    state*: seq[ElementDescription]
    dayOfWeek*: seq[ElementDescription]
    weekOfMonth*: seq[ElementDescription]

type
  SwapPlacementOverrideNotSupported* = ref object of InvalidVmConfig
  
type
  OvfImportFailed* = ref object of OvfImport
  
type
  IscsiFaultVnicNotFound* = ref object of IscsiFault
    vnicDevice*: string

type
  ProfileHostProfileEngineHostProfileManagerProfileCategoryMetaArray* = ref object of DynamicData
    profileCategoryMeta*: seq[ProfileCategoryMetadata]

type
  DvsNetworkRuleAction* = ref object of DynamicData
  
type
  PodStorageDrsEntry* = ref object of DynamicData
    storageDrsConfig*: StorageDrsConfigInfo
    recommendation*: seq[ClusterRecommendation]
    drsFault*: seq[ClusterDrsFaults]
    actionHistory*: seq[ClusterActionHistory]

type
  RemoveFailed* = ref object of VimFault
  
type
  InsufficientHostCapacityFault* = ref object of InsufficientResourcesFault
    host*: HostSystem

type
  GuestPermissionDenied* = ref object of GuestOperationsFault
  
type
  VirtualVmxnet3VrdmaOptionDeviceProtocols* {.pure.} = enum
    rocev1, rocev2
type
  VirtualLsiLogicController* = ref object of VirtualSCSIController
  
type
  DeviceHotPlugNotSupported* = ref object of InvalidDeviceSpec
  
type
  VirtualMachineGuestState* {.pure.} = enum
    running, shuttingDown, resetting, standby, notRunning, unknown
type
  HostLicenseSpec* = ref object of DynamicData
    source*: LicenseSource
    editionKey*: string
    disabledFeatureKey*: seq[string]
    enabledFeatureKey*: seq[string]

type
  LicenseFeatureInfoUnit* {.pure.} = enum
    host, cpuCore, cpuPackage, server, vm
type
  VMwareDVSVspanCapability* = ref object of DynamicData
    mixedDestSupported*: bool
    dvportSupported*: bool
    remoteSourceSupported*: bool
    remoteDestSupported*: bool
    encapRemoteSourceSupported*: bool
    erspanProtocolSupported*: bool
    mirrorNetstackSupported*: bool

type
  GuestRegValueDataSpec* = ref object of DynamicData
  
type
  VMwareDvsLacpGroupSpec* = ref object of DynamicData
    lacpGroupConfig*: VMwareDvsLacpGroupConfig
    operation*: string

type
  vslmInfrastructureObjectPolicySpec* = ref object of DynamicData
    datastore*: Datastore
    profile*: seq[VirtualMachineProfileSpec]

type
  DistributedVirtualSwitch* = ref object of vim.ManagedEntity
    uuid*: string
    capability*: DVSCapability
    summary*: DVSSummary
    config*: DVSConfigInfo
    networkResourcePool*: seq[DVSNetworkResourcePool]
    portgroup*: seq[DistributedVirtualPortgroup]
    runtime*: DVSRuntimeInfo

type
  NoPermissionOnHost* = ref object of HostConnectFault
  
type
  StorageVmotionIncompatible* = ref object of VirtualHardwareCompatibilityIssue
    datastore*: Datastore

type
  InvalidState* = ref object of VimFault
  
type
  VirtualCdromPassthroughBackingOption* = ref object of VirtualDeviceDeviceBackingOption
    exclusive*: BoolOption

type
  StoragePlacementSpecPlacementType* {.pure.} = enum
    create, reconfigure, relocate, clone
type
  VmLogFileQuery* = ref object of FileQuery
  
type
  NoCompatibleHardAffinityHost* = ref object of VmConfigFault
    vmName*: string

type
  VsanClusterUuidMismatch* = ref object of CannotMoveVsanEnabledHost
    hostClusterUuid*: string
    destinationClusterUuid*: string

type
  DasVmPriority* {.pure.} = enum
    disabled, low, medium, high
type
  VirtualMachineGuestIntegrityInfo* = ref object of DynamicData
    enabled*: bool

type
  InvalidIpmiLoginInfo* = ref object of VimFault
  
type
  ProfileUpdateFailed* = ref object of VimFault
    failure*: seq[ProfileUpdateFailedUpdateFailure]
    warnings*: seq[ProfileUpdateFailedUpdateFailure]

type
  DvsHostLeftEvent* = ref object of DvsEvent
    hostLeft*: HostEventArgument

type
  VmFailedToRebootGuestEvent* = ref object of VmEvent
    reason*: MethodFault

type
  VimFault* = ref object of MethodFault
  
type
  HostMaintenanceSpec* = ref object of DynamicData
    vsanMode*: VsanHostDecommissionMode

type
  ComplianceFailureComplianceFailureValues* = ref object of DynamicData
    comparisonIdentifier*: string
    profileInstance*: string
    hostValue*: pointer
    profileValue*: pointer

type
  VirtualMachineConfigSpecEncryptedVMotionModes* {.pure.} = enum
    disabled, opportunistic, required
type
  HostDisconnectedEventReasonCode* {.pure.} = enum
    sslThumbprintVerifyFailed, licenseExpired, agentUpgrade, userRequest,
    insufficientLicenses, agentOutOfDate, passwordDecryptFailure, unknown,
    vcVRAMCapacityExceeded
type
  SnapshotDisabled* = ref object of SnapshotFault
  
type
  NetworkProfileDnsConfigProfile* = ref object of ApplyProfile
  
type
  VirtualParallelPortFileBackingOption* = ref object of VirtualDeviceFileBackingOption
  
type
  HostHardwareSummary* = ref object of DynamicData
    vendor*: string
    model*: string
    uuid*: string
    otherIdentifyingInfo*: seq[HostSystemIdentificationInfo]
    memorySize*: int64
    cpuModel*: string
    cpuMhz*: int
    numCpuPkgs*: int16
    numCpuCores*: int16
    numCpuThreads*: int16
    numNics*: int
    numHBAs*: int

type
  ProfileAssociatedEvent* = ref object of ProfileEvent
  
type
  VirtualMachinePowerOffBehavior* {.pure.} = enum
    powerOff, revert, prompt, take
type
  DVPortgroupSelection* = ref object of SelectionSet
    dvsUuid*: string
    portgroupKey*: seq[string]

type
  IScsiBootFailureEvent* = ref object of HostEvent
  
type
  HostNetworkConfigNetStackSpec* = ref object of DynamicData
    netStackInstance*: HostNetStackInstance
    operation*: string

type
  OverheadMemoryManager* = ref object of vmodl.ManagedObject
  
type
  VirtualDiskDeltaDiskFormatVariant* {.pure.} = enum
    vmfsSparseVariant, vsanSparseVariant
type
  VirtualDiskLocalPMemBackingOption* = ref object of VirtualDeviceFileBackingOption
    diskMode*: ChoiceOption
    growable*: bool
    hotGrowable*: bool
    uuid*: bool

type
  VirtualAppSummary* = ref object of ResourcePoolSummary
    product*: VAppProductInfo
    vAppState*: VirtualAppVAppState
    suspended*: bool
    installBootRequired*: bool
    instanceUuid*: string

type
  HostProxySwitchHostLagConfig* = ref object of DynamicData
    lagKey*: string
    lagName*: string
    uplinkPort*: seq[KeyValue]

type
  ProfileExpressionMetadata* = ref object of DynamicData
    expressionId*: ExtendedElementDescription
    parameter*: seq[ProfileParameterMetadata]

type
  HostConnectionLostEvent* = ref object of HostEvent
  
type
  VAppProductSpec* = ref object of ArrayUpdateSpec
    info*: VAppProductInfo

type
  LicenseRestricted* = ref object of NotEnoughLicenses
  
type
  VmConfigFileQueryFlags* = ref object of DynamicData
    configVersion*: bool
    encryption*: bool

type
  HostVirtualNicManagerNicType* {.pure.} = enum
    vmotion, faultToleranceLogging, vSphereReplication, vSphereReplicationNFC,
    management, vsan, vSphereProvisioning, vsanWitness
type
  ModeInfo* = ref object of DynamicData
    browse*: string
    read*: string
    modify*: string
    use*: string
    admin*: string
    full*: string

type
  HostNasVolume* = ref object of HostFileSystemVolume
    remoteHost*: string
    remotePath*: string
    userName*: string
    remoteHostNames*: seq[string]
    securityType*: string
    protocolEndpoint*: bool

type
  ActiveDirectoryFault* = ref object of VimFault
    errorCode*: int

type
  HostConfigFailed* = ref object of HostConfigFault
    failure*: seq[MethodFault]

type
  HostPatchManagerLocator* = ref object of DynamicData
    url*: string
    proxy*: string

type
  Task* = ref object of vim.ExtensibleManagedObject
    info*: TaskInfo

type
  HostVMotionConfig* = ref object of DynamicData
    vmotionNicKey*: string
    enabled*: bool

type
  HostDiskMappingPartitionInfo* = ref object of DynamicData
    name*: string
    fileSystem*: string
    capacityInKb*: int64

type
  ResourcePoolReconfiguredEvent* = ref object of ResourcePoolEvent
    configChanges*: ChangesInfoEventArgument

type
  VirtualControllerOption* = ref object of VirtualDeviceOption
    devices*: IntOption
    supportedDevice*: seq[string]

type
  VirtualCdrom* = ref object of VirtualDevice
  
type
  HostProfilePolicyMapping* = ref object of DynamicData
    id*: string
    data*: HostProfilePolicyMappingPolicyMappingData
    policyOptionMapping*: seq[HostProfilePolicyOptionMapping]

type
  HostFirewallRule* = ref object of DynamicData
    port*: int
    endPort*: int
    direction*: HostFirewallRuleDirection
    portType*: HostFirewallRulePortType
    protocol*: string

type
  NvdimmRangeType* {.pure.} = enum
    volatileRange, persistentRange, controlRange, blockRange,
    volatileVirtualDiskRange, volatileVirtualCDRange, persistentVirtualDiskRange,
    persistentVirtualCDRange
type
  StorageIORMThresholdMode* {.pure.} = enum
    automatic, manual
type
  VirtualMachineToolsVersionStatus* {.pure.} = enum
    guestToolsNotInstalled, guestToolsNeedUpgrade, guestToolsCurrent,
    guestToolsUnmanaged, guestToolsTooOld, guestToolsSupportedOld,
    guestToolsSupportedNew, guestToolsTooNew, guestToolsBlacklisted
type
  HostInternetScsiHbaDigestCapabilities* = ref object of DynamicData
    headerDigestSettable*: bool
    dataDigestSettable*: bool
    targetHeaderDigestSettable*: bool
    targetDataDigestSettable*: bool

type
  TaskReason* = ref object of DynamicData
  
type
  VVolVmConfigFileUpdateResult* = ref object of DynamicData
    succeededVmConfigFile*: seq[KeyValue]
    failedVmConfigFile*: seq[VVolVmConfigFileUpdateResultFailedVmConfigFileInfo]

type
  VsanDecommissioningBatch* = ref object of DynamicData
    mode*: VsanHostDecommissionMode
    dp*: seq[VsanDecomParam]

type
  VirtualBusLogicController* = ref object of VirtualSCSIController
  
type
  HostPrimaryAgentNotShortNameEvent* = ref object of HostDasEvent
    primaryAgent*: string

type
  HostDVSCreateSpec* = ref object of HostDVSConfigSpec
    port*: seq[HostDVSPortData]
    portgroup*: seq[HostDVPortgroupConfigSpec]
    productSpec*: DistributedVirtualSwitchProductSpec
    isOpaque*: bool

type
  NetStackInstanceProfile* = ref object of ApplyProfile
    key*: string
    dnsConfig*: NetworkProfileDnsConfigProfile
    ipRouteConfig*: IpRouteProfile

type
  ClusterInfraUpdateHaConfigInfoBehaviorType* {.pure.} = enum
    Manual, Automated
type
  HostFaultToleranceManagerComponentHealthInfo* = ref object of DynamicData
    isStorageHealthy*: bool
    isNetworkHealthy*: bool

type
  VirtualSCSIPassthroughDeviceBackingOption* = ref object of VirtualDeviceDeviceBackingOption
  
type
  PerfSummaryType* {.pure.} = enum
    average, maximum, minimum, latest, summation, none
type
  DVSTrafficShapingPolicy* = ref object of InheritablePolicy
    enabled*: BoolPolicy
    averageBandwidth*: LongPolicy
    peakBandwidth*: LongPolicy
    burstSize*: LongPolicy

type
  DvsCreatedEvent* = ref object of DvsEvent
    parent*: FolderEventArgument

type
  HostSystemSwapConfigurationDisabledOption* = ref object of HostSystemSwapConfigurationSystemSwapOption
  
type
  StorageMigrationAction* = ref object of ClusterAction
    vm*: VirtualMachine
    relocateSpec*: VirtualMachineRelocateSpec
    source*: Datastore
    destination*: Datastore
    sizeTransferred*: int64
    spaceUtilSrcBefore*: float32
    spaceUtilDstBefore*: float32
    spaceUtilSrcAfter*: float32
    spaceUtilDstAfter*: float32
    ioLatencySrcBefore*: float32
    ioLatencyDstBefore*: float32

type
  TicketedSessionAuthentication* = ref object of GuestAuthentication
    ticket*: string

type
  DrsResourceConfigureSyncedEvent* = ref object of HostEvent
  
type
  CannotEnableVmcpForCluster* = ref object of VimFault
    host*: HostSystem
    hostName*: string
    reason*: string

type
  NetIpConfigSpecIpAddressSpec* = ref object of DynamicData
    ipAddress*: string
    prefixLength*: int
    operation*: string

type
  NoAvailableIp* = ref object of VAppPropertyFault
    network*: Network

type
  OvfProperty* = ref object of OvfInvalidPackage
    type*: string
    value*: string

type
  ClusterGroupInfo* = ref object of DynamicData
    name*: string
    userCreated*: bool
    uniqueID*: string

type
  NotSupportedHostForVsan* = ref object of NotSupportedHost
    hostName*: string

type
  LongPolicy* = ref object of InheritablePolicy
    value*: int64

type
  ExtensionClientInfo* = ref object of DynamicData
    version*: string
    description*: Description
    company*: string
    type*: string
    url*: string

type
  PreCallbackResult* = ref object of DynamicData
    extensionKey*: string
    instanceId*: string
    percentDone*: int
    currentResult*: PreCallbackResultResult
    fault*: MethodFault

type
  VirtualMachineDeviceRuntimeInfo* = ref object of DynamicData
    runtimeState*: VirtualMachineDeviceRuntimeInfoDeviceRuntimeState
    key*: int

type
  ClusterDasConfigInfoVmMonitoringState* {.pure.} = enum
    vmMonitoringDisabled, vmMonitoringOnly, vmAndAppMonitoring
type
  WinNetBIOSConfigInfo* = ref object of NetBIOSConfigInfo
    primaryWINS*: string
    secondaryWINS*: string

type
  DistributedVirtualSwitchProductSpec* = ref object of DynamicData
    name*: string
    vendor*: string
    version*: string
    build*: string
    forwardingClass*: string
    bundleId*: string
    bundleUrl*: string

type
  HostIncompatibleForRecordReplayReason* {.pure.} = enum
    product, processor
type
  QuiesceDatastoreIOForHAFailed* = ref object of ResourceInUse
    host*: HostSystem
    hostName*: string
    ds*: Datastore
    dsName*: string

type
  ClusterAttemptedVmInfo* = ref object of DynamicData
    vm*: VirtualMachine
    task*: Task

type
  ExternalStatsManager* = ref object of vmodl.ManagedObject
  
type
  ClusterNotAttemptedVmInfo* = ref object of DynamicData
    vm*: VirtualMachine
    fault*: MethodFault

type
  VirtualUSB* = ref object of VirtualDevice
    connected*: bool
    vendor*: int
    product*: int
    family*: seq[string]
    speed*: seq[string]

type
  DvsPortExitedPassthruEvent* = ref object of DvsEvent
    portKey*: string
    runtimeInfo*: DVPortStatus

type
  VmDiskFileQuery* = ref object of FileQuery
    filter*: VmDiskFileQueryFilter
    details*: VmDiskFileQueryFlags

type
  EventFilterSpecRecursionOption* {.pure.} = enum
    self, children, all
type
  DatabaseError* = ref object of RuntimeFault
  
type
  VirtualDeviceConfigSpecOperation* {.pure.} = enum
    add, remove, edit
type
  VirtualDeviceConnectOption* = ref object of DynamicData
    startConnected*: BoolOption
    allowGuestControl*: BoolOption

type
  HostSriovConfig* = ref object of HostPciPassthruConfig
    sriovEnabled*: bool
    numVirtualFunction*: int

type
  IoFilterInfo* = ref object of DynamicData
    id*: string
    name*: string
    vendor*: string
    version*: string
    type*: string
    summary*: string
    releaseDate*: string

type
  HostSyncFailedEvent* = ref object of HostEvent
    reason*: MethodFault

type
  VirtualSerialPortURIBackingInfo* = ref object of VirtualDeviceURIBackingInfo
  
type
  HostServiceInfo* = ref object of DynamicData
    service*: seq[HostService]

type
  InvalidClientCertificate* = ref object of InvalidLogin
  
type
  HostVsanInternalSystemVsanObjectOperationResult* = ref object of DynamicData
    uuid*: string
    failureReason*: seq[LocalizableMessage]

type
  GuestStackInfo* = ref object of DynamicData
    dnsConfig*: NetDnsConfigInfo
    ipRouteConfig*: NetIpRouteConfigInfo
    ipStackConfig*: seq[KeyValue]
    dhcpConfig*: NetDhcpConfigInfo

type
  HostIsolationIpPingFailedEvent* = ref object of HostDasEvent
    isolationIp*: string

type
  GuestAuthSubject* = ref object of DynamicData
  
type
  VmGuestRebootEvent* = ref object of VmEvent
  
type
  StorageIOAllocationInfo* = ref object of DynamicData
    limit*: int64
    shares*: SharesInfo
    reservation*: int

type
  NvdimmInterleaveSetInfo* = ref object of DynamicData
    setId*: int
    rangeType*: string
    baseAddress*: int64
    size*: int64
    availableSize*: int64
    deviceList*: seq[int]
    state*: string

type
  CryptoManager* = ref object of vmodl.ManagedObject
    enabled*: bool

type
  FailoverLevelRestored* = ref object of ClusterEvent
  
type
  HostDiskPartitionBlockRange* = ref object of DynamicData
    partition*: int
    type*: string
    start*: HostDiskDimensionsLba
    end*: HostDiskDimensionsLba

type
  CannotChangeHaSettingsForFtSecondary* = ref object of VmFaultToleranceIssue
    vm*: VirtualMachine
    vmName*: string

type
  PlacementResult* = ref object of DynamicData
    recommendations*: seq[ClusterRecommendation]
    drsFault*: ClusterDrsFaults

type
  vslmVStorageObjectControlFlag* {.pure.} = enum
    keepAfterDeleteVm, disableRelocation, enableChangedBlockTracking
type
  HostPciPassthruConfig* = ref object of DynamicData
    id*: string
    passthruEnabled*: bool

type
  RollbackFailure* = ref object of DvsFault
    entityName*: string
    entityType*: string

type
  HostInternetScsiHbaIscsiIpv6Address* = ref object of DynamicData
    address*: string
    prefixLength*: int
    origin*: string
    operation*: string

type
  CpuIncompatible* = ref object of VirtualHardwareCompatibilityIssue
    level*: int
    registerName*: string
    registerBits*: string
    desiredBits*: string
    host*: HostSystem

type
  DvsPortUnblockedEvent* = ref object of DvsEvent
    portKey*: string
    runtimeInfo*: DVPortStatus
    prevBlockState*: string

type
  ResourceViolatedEvent* = ref object of ResourcePoolEvent
  
type
  UserAssignedToGroup* = ref object of HostEvent
    userLogin*: string
    group*: string

type
  HostTelemetryInfo* = ref object of DynamicData
    data*: seq[KeyAnyValue]

type
  VirtualMachineNamespaceManagerNamespaceInfo* = ref object of DynamicData
    namespace*: string
    eventsToGuest*: VirtualMachineNamespaceManagerNamespaceInfoNamespaceAllocation
    eventsFromGuest*: VirtualMachineNamespaceManagerNamespaceInfoNamespaceAllocation
    data*: VirtualMachineNamespaceManagerNamespaceInfoNamespaceAllocation
    accessMode*: VirtualMachineNamespaceManagerAccessMode

type
  VmSecondaryStartedEvent* = ref object of VmEvent
  
type
  ClusterDasData* = ref object of DynamicData
  
type
  VirtualDiskVFlashCacheConfigInfoCacheMode* {.pure.} = enum
    write_thru, write_back
type
  VirtualMachineVMCIDeviceProtocol* {.pure.} = enum
    hypervisor, doorbell, queuepair, datagram, stream, anyProtocol
type
  CertificateManager* = ref object of vmodl.ManagedObject
  
type
  VmUpgradeFailedEvent* = ref object of VmEvent
  
type
  VmConnectedEvent* = ref object of VmEvent
  
type
  LicenseServerUnavailableEvent* = ref object of LicenseEvent
    licenseServer*: string

type
  HostMemoryProfile* = ref object of ApplyProfile
  
type
  PowerOnFtSecondaryFailed* = ref object of VmFaultToleranceIssue
    vm*: VirtualMachine
    vmName*: string
    hostSelectionBy*: FtIssuesOnHostHostSelectionType
    hostErrors*: seq[MethodFault]
    rootCause*: MethodFault

type
  GuestFileType* {.pure.} = enum
    file, directory, symlink
type
  VAppNotRunning* = ref object of VmConfigFault
  
type
  FtIssuesOnHostHostSelectionType* {.pure.} = enum
    user, vc, drs
type
  ID* = ref object of DynamicData
    id*: string

type
  SSLVerifyFault* = ref object of HostConnectFault
    selfSigned*: bool
    thumbprint*: string

type
  ProfileExpression* = ref object of DynamicData
    id*: string
    displayName*: string
    negated*: bool

type
  HostScsiTopologyLun* = ref object of DynamicData
    key*: string
    lun*: int
    scsiLun*: ScsiLun

type
  VirtualMachineProvisioningPolicyAction* {.pure.} = enum
    keep, remove
type
  DvsRestoreEvent* = ref object of DvsEvent
  
type
  EVCAdmissionFailedHostSoftware* = ref object of EVCAdmissionFailed
  
type
  CDCChangeSet* = ref object of DynamicData
    sequence*: string
    inventoryChanges*: seq[CDCInventoryChange]
    alarmChanges*: seq[CDCAlarmChange]

type
  ConfigTarget* = ref object of DynamicData
    numCpus*: int
    numCpuCores*: int
    numNumaNodes*: int
    smcPresent*: bool
    datastore*: seq[VirtualMachineDatastoreInfo]
    network*: seq[VirtualMachineNetworkInfo]
    opaqueNetwork*: seq[OpaqueNetworkTargetInfo]
    distributedVirtualPortgroup*: seq[DistributedVirtualPortgroupInfo]
    distributedVirtualSwitch*: seq[DistributedVirtualSwitchInfo]
    cdRom*: seq[VirtualMachineCdromInfo]
    serial*: seq[VirtualMachineSerialInfo]
    parallel*: seq[VirtualMachineParallelInfo]
    sound*: seq[VirtualMachineSoundInfo]
    usb*: seq[VirtualMachineUsbInfo]
    floppy*: seq[VirtualMachineFloppyInfo]
    legacyNetworkInfo*: seq[VirtualMachineLegacyNetworkSwitchInfo]
    scsiPassthrough*: seq[VirtualMachineScsiPassthroughInfo]
    scsiDisk*: seq[VirtualMachineScsiDiskDeviceInfo]
    ideDisk*: seq[VirtualMachineIdeDiskDeviceInfo]
    maxMemMBOptimalPerf*: int
    resourcePool*: ResourcePoolRuntimeInfo
    autoVmotion*: bool
    pciPassthrough*: seq[VirtualMachinePciPassthroughInfo]
    sriov*: seq[VirtualMachineSriovInfo]
    vFlashModule*: seq[VirtualMachineVFlashModuleInfo]
    sharedGpuPassthroughTypes*: seq[VirtualMachinePciSharedGpuPassthroughInfo]
    availablePersistentMemoryReservationMB*: int64

type
  LocalizationManager* = ref object of vmodl.ManagedObject
    catalog*: seq[LocalizationManagerMessageCatalog]

type
  MissingController* = ref object of InvalidDeviceSpec
  
type
  InvalidProfileReferenceHostReason* {.pure.} = enum
    incompatibleVersion, missingReferenceHost
type
  VsanClusterConfigInfo* = ref object of DynamicData
    enabled*: bool
    defaultConfig*: VsanClusterConfigInfoHostDefaultInfo

type
  ClusterDrsConfigInfo* = ref object of DynamicData
    enabled*: bool
    enableVmBehaviorOverrides*: bool
    defaultVmBehavior*: DrsBehavior
    vmotionRate*: int
    option*: seq[OptionValue]

type
  CustomizationNetworkSetupFailed* = ref object of CustomizationFailed
  
type
  VirtualMachineCompatibilityChecker* = ref object of vmodl.ManagedObject
  
type
  DvsFilterParameter* = ref object of DynamicData
    parameters*: seq[string]

type
  VirtualNVDIMMOption* = ref object of VirtualDeviceOption
    capacityInMB*: LongOption
    growable*: bool
    hotGrowable*: bool
    granularityInMB*: int64

type
  HostMissingNetworksEvent* = ref object of HostDasEvent
    ips*: string

type
  VirtualSerialPortOption* = ref object of VirtualDeviceOption
    yieldOnPoll*: BoolOption

type
  DvsUpgradeRejectedEvent* = ref object of DvsEvent
    productInfo*: DistributedVirtualSwitchProductSpec

type
  ApplyHostProfileConfigurationResultStatus* {.pure.} = enum
    success, failed, reboot_failed, stateless_reboot_failed,
    check_compliance_failed, state_not_satisfied, exit_maintenancemode_failed,
    canceled
type
  VmFailedToResetEvent* = ref object of VmEvent
    reason*: MethodFault

type
  HostSubSpecification* = ref object of DynamicData
    name*: string
    createdTime*: string
    data*: seq[byte]
    binaryData*: byte

type
  GuestNicInfo* = ref object of DynamicData
    network*: string
    ipAddress*: seq[string]
    macAddress*: string
    connected*: bool
    deviceConfigId*: int
    dnsConfig*: NetDnsConfigInfo
    ipConfig*: NetIpConfigInfo
    netBIOSConfig*: NetBIOSConfigInfo

type
  CannotChangeDrsBehaviorForFtSecondary* = ref object of VmFaultToleranceIssue
    vm*: VirtualMachine
    vmName*: string

type
  HostRuntimeInfoNetStackInstanceRuntimeInfo* = ref object of DynamicData
    netStackInstanceKey*: string
    state*: string
    vmknicKeys*: seq[string]
    maxNumberOfConnections*: int
    currentIpV6Enabled*: bool

type
  CustomizationNetBIOSMode* {.pure.} = enum
    enableNetBIOSViaDhcp, enableNetBIOS, disableNetBIOS
type
  HostInDomain* = ref object of HostConfigFault
  
type
  DrsExitStandbyModeFailedEvent* = ref object of ExitStandbyModeFailedEvent
  
type
  ResourceAllocationOption* = ref object of DynamicData
    sharesOption*: SharesOption

type
  MigrationFeatureNotSupported* = ref object of MigrationFault
    atSourceHost*: bool
    failedHostName*: string
    failedHost*: HostSystem

type
  VMwareDvsLacpApiVersion* {.pure.} = enum
    singleLag, multipleLag
type
  MtuMatchEvent* = ref object of DvsHealthStatusChangeEvent
  
type
  PhysicalNicNameHint* = ref object of PhysicalNicHint
    network*: string

type
  EsxAgentConfigManager* = ref object of vmodl.ManagedObject
  
type
  CbrcDeviceBackingNotSupported* = ref object of VmConfigFault
    backing*: string

type
  FileNotWritable* = ref object of FileFault
  
type
  HostTpmCommandEventDetails* = ref object of HostTpmEventDetails
    commandLine*: string

type
  HttpNfcLeaseHostInfo* = ref object of DynamicData
    url*: string
    sslThumbprint*: string

type
  VmMacAssignedEvent* = ref object of VmEvent
    adapter*: string
    mac*: string

type
  OvfUnsupportedDeviceExport* = ref object of OvfHardwareExport
  
type
  PolicyViolatedValueTooBig* = ref object of PolicyViolatedByValue
    policyValue*: pointer

type
  VmUuidConflictEvent* = ref object of VmEvent
    conflictedVm*: VmEventArgument
    uuid*: string

type
  CustomizationSucceeded* = ref object of CustomizationEvent
  
type
  HostSslThumbprintInfo* = ref object of DynamicData
    principal*: string
    ownerTag*: string
    sslThumbprints*: seq[string]

type
  ManagedEntityEventArgument* = ref object of EntityEventArgument
    entity*: ManagedEntity

type
  VnicPortArgument* = ref object of DynamicData
    vnic*: string
    port*: DistributedVirtualSwitchPortConnection

type
  VirtualDiskVFlashCacheConfigInfoCacheConsistencyType* {.pure.} = enum
    strong, weak
type
  EventManager* = ref object of vmodl.ManagedObject
    description*: EventDescription
    latestEvent*: Event
    maxCollector*: int

type
  GuestFileAttributes* = ref object of DynamicData
    modificationTime*: string
    accessTime*: string
    symlinkTarget*: string

type
  DuplicateIpDetectedEvent* = ref object of HostEvent
    duplicateIP*: string
    macAddress*: string

type
  InaccessibleVFlashSource* = ref object of VimFault
    hostName*: string

type
  OvfConnectedDeviceIso* = ref object of OvfConnectedDevice
    filename*: string

type
  DiagnosticPartitionType* {.pure.} = enum
    singleHost, multiHost
type
  EVCAdmissionFailedVmActive* = ref object of EVCAdmissionFailed
  
type
  VirtualMachineProfileDetails* = ref object of DynamicData
    profile*: seq[VirtualMachineProfileSpec]
    diskProfileDetails*: seq[VirtualMachineProfileDetailsDiskProfileDetails]

type
  ScheduledTaskEvent* = ref object of Event
    scheduledTask*: ScheduledTaskEventArgument
    entity*: ManagedEntityEventArgument

type
  EventAlarmExpressionComparison* = ref object of DynamicData
    attributeName*: string
    operator*: string
    value*: string

type
  DVPortgroupEvent* = ref object of Event
  
type
  OvfPropertyType* = ref object of OvfProperty
  
type
  VirtualMachineScsiPassthroughInfo* = ref object of VirtualMachineTargetInfo
    scsiClass*: string
    vendor*: string
    physicalUnitNumber*: int

type
  ProfileParameterMetadata* = ref object of DynamicData
    id*: ExtendedElementDescription
    type*: string
    optional*: bool
    defaultValue*: pointer
    hidden*: bool
    securitySensitive*: bool
    readOnly*: bool
    parameterRelations*: seq[ProfileParameterMetadataParameterRelationMetadata]

type
  HostDiskConfigurationResult* = ref object of DynamicData
    devicePath*: string
    success*: bool
    fault*: MethodFault

type
  VsanHostMembershipInfo* = ref object of DynamicData
    nodeUuid*: string
    hostname*: string

type
  EventFilterSpecByUsername* = ref object of DynamicData
    systemUser*: bool
    userList*: seq[string]

type
  HostPlugStoreTopologyPlugin* = ref object of DynamicData
    key*: string
    name*: string
    device*: seq[HostPlugStoreTopologyDevice]
    claimedPath*: seq[HostPlugStoreTopologyPath]

type
  ResourcePoolSummary* = ref object of DynamicData
    name*: string
    config*: ResourceConfigSpec
    runtime*: ResourcePoolRuntimeInfo
    quickStats*: ResourcePoolQuickStats
    configuredMemoryMB*: int

type
  ExtensionTaskTypeInfo* = ref object of DynamicData
    taskID*: string

type
  VmStartingEvent* = ref object of VmEvent
  
type
  DrsRuleViolationEvent* = ref object of VmEvent
  
type
  VirtualParallelPortDeviceBackingOption* = ref object of VirtualDeviceDeviceBackingOption
  
type
  HostDiagnosticPartitionCreateSpec* = ref object of DynamicData
    storageType*: string
    diagnosticType*: string
    id*: HostScsiDiskPartition
    partition*: HostDiskPartitionSpec
    active*: bool

type
  GuestRegistryKeyHasSubkeys* = ref object of GuestRegistryKeyFault
  
type
  HostShortNameToIpFailedEvent* = ref object of HostEvent
    shortName*: string

type
  VirtualSoundBlaster16* = ref object of VirtualSoundCard
  
type
  VMwareDvsLacpCapability* = ref object of DynamicData
    lacpSupported*: bool
    multiLacpGroupSupported*: bool

type
  VirtualSoundCardOption* = ref object of VirtualDeviceOption
  
type
  CbrcDeviceSpec* = ref object of DynamicData
    vm*: VirtualMachine
    deviceKey*: int

type
  HostProxySwitch* = ref object of DynamicData
    dvsUuid*: string
    dvsName*: string
    key*: string
    numPorts*: int
    configNumPorts*: int
    numPortsAvailable*: int
    uplinkPort*: seq[KeyValue]
    mtu*: int
    pnic*: seq[PhysicalNic]
    spec*: HostProxySwitchSpec
    hostLag*: seq[HostProxySwitchHostLagConfig]
    networkReservationSupported*: bool

type
  PhysicalNicVmDirectPathGen2SupportedMode* {.pure.} = enum
    upt
type
  OvfDuplicatedElementBoundary* = ref object of OvfElement
    boundary*: string

type
  CustomizationIPSettingsIpV6AddressSpec* = ref object of DynamicData
    ip*: seq[CustomizationIpV6Generator]
    gateway*: seq[string]

type
  VirtualSerialPortEndPoint* {.pure.} = enum
    client, server
type
  HealthUpdate* = ref object of DynamicData
    entity*: ManagedEntity
    healthUpdateInfoId*: string
    id*: string
    status*: ManagedEntityStatus
    remediation*: string

type
  HostFirewallRulesetIpList* = ref object of DynamicData
    ipAddress*: seq[string]
    ipNetwork*: seq[HostFirewallRulesetIpNetwork]
    allIp*: bool

type
  ClusterDestroyedEvent* = ref object of ClusterEvent
  
type
  OvfConsumerResult* = ref object of DynamicData
    error*: seq[MethodFault]
    warning*: seq[MethodFault]

type
  ClusterProfileCompleteConfigSpec* = ref object of ClusterProfileConfigSpec
    complyProfile*: ComplianceProfile

type
  HostAccessMode* {.pure.} = enum
    accessNone, accessAdmin, accessNoAccess, accessReadOnly, accessOther
type
  CustomizationAutoIpV6Generator* = ref object of CustomizationIpV6Generator
  
type
  HostVvolVolume* = ref object of HostFileSystemVolume
    scId*: string
    hostPE*: seq[VVolHostPE]
    vasaProviderInfo*: seq[VimVasaProviderInfo]
    storageArray*: seq[VASAStorageArray]

type
  ServerLicenseExpiredEvent* = ref object of LicenseEvent
    product*: string

type
  HostVStorageObjectManager* = ref object of vim.vslm.VStorageObjectManagerBase
  
type
  CpuCompatibilityUnknown* = ref object of CpuIncompatible
  
type
  HostDiskManagerLease* = ref object of vmodl.ManagedObject
  
type
  DistributedVirtualSwitchNicTeamingPolicyMode* {.pure.} = enum
    loadbalance_ip, loadbalance_srcmac, loadbalance_srcid, failover_explicit,
    loadbalance_loadbased
type
  VAppIPAssignmentInfo* = ref object of DynamicData
    supportedAllocationScheme*: seq[string]
    ipAllocationPolicy*: string
    supportedIpProtocol*: seq[string]
    ipProtocol*: string

type
  VmEvent* = ref object of Event
    template*: bool

type
  VirtualUSBRemoteHostBackingInfo* = ref object of VirtualDeviceDeviceBackingInfo
    hostname*: string

type
  ProxyServiceLocalServiceSpec* = ref object of ProxyServiceServiceSpec
    port*: int

type
  DeviceNotSupportedReason* {.pure.} = enum
    host, guest
type
  CbrcDigestOperationResult* = ref object of DynamicData
    spec*: CbrcDeviceSpec
    fault*: MethodFault

type
  HostLowLevelProvisioningManager* = ref object of vmodl.ManagedObject
  
type
  LicenseAssignmentManagerEntityArgs* = ref object of DynamicData
    entityId*: string
    args*: seq[KeyAnyValue]

type
  AlarmManager* = ref object of vmodl.ManagedObject
    defaultExpression*: seq[AlarmExpression]
    description*: AlarmDescription
    lastTriggerId*: int

type
  HostSpecificationOperationFailed* = ref object of VimFault
    host*: HostSystem

type
  HostDiskDimensions* = ref object of DynamicData
  
type
  HostHardwareStatusInfo* = ref object of DynamicData
    memoryStatusInfo*: seq[HostHardwareElementInfo]
    cpuStatusInfo*: seq[HostHardwareElementInfo]
    storageStatusInfo*: seq[HostStorageElementInfo]

type
  DVSRuntimeInfo* = ref object of DynamicData
    hostMemberRuntime*: seq[HostMemberRuntimeInfo]
    resourceRuntimeInfo*: DvsResourceRuntimeInfo

type
  ProxyServiceRedirectSpec* = ref object of ProxyServiceEndpointSpec
    redirectType*: string
    hostName*: string
    port*: int

type
  VirtualAppImportSpec* = ref object of ImportSpec
    name*: string
    vAppConfigSpec*: VAppConfigSpec
    resourcePoolSpec*: ResourceConfigSpec
    child*: seq[ImportSpec]

type
  VmResourceReallocatedEvent* = ref object of VmEvent
    configChanges*: ChangesInfoEventArgument

type
  VasaClientContextSpec* = ref object of DynamicData
    domainId*: string

type
  LicenseFeatureInfoState* {.pure.} = enum
    enabled, disabled, optional
type
  VmMessageWarningEvent* = ref object of VmEvent
    message*: string
    messageInfo*: seq[VirtualMachineMessage]

type
  NoPermissionOnNasVolume* = ref object of NasConfigFault
    userName*: string

type
  HostDasErrorEventHostDasErrorReason* {.pure.} = enum
    configFailed, timeout, communicationInitFailed, healthCheckScriptFailed,
    agentFailed, agentShutdown, isolationAddressUnpingable, other
type
  VirtualDiskFlatVer2BackingInfo* = ref object of VirtualDeviceFileBackingInfo
    diskMode*: string
    split*: bool
    writeThrough*: bool
    thinProvisioned*: bool
    eagerlyScrub*: bool
    uuid*: string
    contentId*: string
    changeId*: string
    parent*: VirtualDiskFlatVer2BackingInfo
    deltaDiskFormat*: string
    digestEnabled*: bool
    deltaGrainSize*: int
    deltaDiskFormatVariant*: string
    sharing*: string
    keyId*: CryptoKeyId

type
  VsanHostNodeState* {.pure.} = enum
    error, disabled, agent, master, backup, starting, stopping,
    enteringMaintenanceMode, exitingMaintenanceMode, decommissioning
type
  RecordReplayDisabled* = ref object of VimFault
  
type
  UplinkPortResourceSpec* = ref object of DynamicData
    uplinkPortKey*: string
    configSpec*: seq[DVSNetworkResourcePoolConfigSpec]

type
  HostMultipathInfoLogicalUnitPolicy* = ref object of DynamicData
    policy*: string

type
  HostDasDisablingEvent* = ref object of HostEvent
  
type
  HostVirtualNicManagerNicTypeSelection* = ref object of DynamicData
    vnic*: HostVirtualNicConnection
    nicType*: seq[string]

type
  VirtualApp* = ref object of vim.ResourcePool
    parentFolder*: Folder
    datastore*: seq[Datastore]
    network*: seq[Network]
    vAppConfig*: VAppConfigInfo
    parentVApp*: ManagedEntity
    childLink*: seq[VirtualAppLinkInfo]

type
  HostProfileSerializedHostProfileSpec* = ref object of ProfileSerializedCreateSpec
    validatorHost*: HostSystem
    validating*: bool

type
  VirtualMachineFileLayoutDiskLayout* = ref object of DynamicData
    key*: int
    diskFile*: seq[string]

type
  VirtualMachineVMCIDeviceAction* {.pure.} = enum
    allow, deny
type
  CustomFieldDef* = ref object of DynamicData
    key*: int
    name*: string
    type*: string
    managedObjectType*: string
    fieldDefPrivileges*: PrivilegePolicyDef
    fieldInstancePrivileges*: PrivilegePolicyDef

type
  HostPortGroupProfile* = ref object of PortGroupProfile
    ipConfig*: IpAddressProfile

type
  ResourcePoolCreatedEvent* = ref object of ResourcePoolEvent
    parent*: ResourcePoolEventArgument

type
  HostUpdateProxyConfigInfo* = ref object of DynamicData
    repoLocation*: string
    cacheLocation*: string
    cacheSize*: int64
    cachePruningLimits*: int64

type
  HostOperationCleanupManagerCleanupItemType* {.pure.} = enum
    disk, file, dir, vm
type
  DrsDisabledEvent* = ref object of ClusterEvent
  
type
  FaultToleranceSecondaryConfigInfo* = ref object of FaultToleranceConfigInfo
    primaryVM*: VirtualMachine

type
  FaultToleranceVmNotDasProtected* = ref object of VimFault
    vm*: VirtualMachine
    vmName*: string

type
  PatchNotApplicable* = ref object of VimFault
    patchID*: string

type
  GuestRegistryKeyInvalid* = ref object of GuestRegistryKeyFault
  
type
  MetricAlarmOperator* {.pure.} = enum
    isAbove, isBelow
type
  ImportOperationBulkFaultFaultOnImport* = ref object of DynamicData
    entityType*: string
    key*: string
    fault*: MethodFault

type
  VirtualNVMEControllerOption* = ref object of VirtualControllerOption
    numNVMEDisks*: IntOption

type
  VmFailedToPowerOnEvent* = ref object of VmEvent
    reason*: MethodFault

type
  AlarmSnmpFailedEvent* = ref object of AlarmEvent
    entity*: ManagedEntityEventArgument
    reason*: MethodFault

type
  CustomizationSysprepText* = ref object of CustomizationIdentitySettings
    value*: string

type
  VirtualNVMEController* = ref object of VirtualController
  
type
  HostAdminDisableEvent* = ref object of HostEvent
  
type
  NvdimmDimmInfo* = ref object of DynamicData
    dimmHandle*: int
    healthInfo*: NvdimmHealthInfo
    totalCapacity*: int64
    persistentCapacity*: int64
    availablePersistentCapacity*: int64
    volatileCapacity*: int64
    availableVolatileCapacity*: int64
    blockCapacity*: int64
    regionInfo*: seq[NvdimmRegionInfo]
    representationString*: string

type
  HostInventoryFullEvent* = ref object of LicenseEvent
    capacity*: int

type
  VirtualDiskRuleSpec* = ref object of ClusterRuleInfo
    diskRuleType*: string
    diskId*: seq[int]

type
  StorageDrsPodConfigInfoBehavior* {.pure.} = enum
    manual, automated
type
  VirtualSriovEthernetCardOption* = ref object of VirtualEthernetCardOption
  
type
  DvsPortRuntimeChangeEvent* = ref object of DvsEvent
    portKey*: string
    runtimeInfo*: DVPortStatus

type
  StorageDrsOptionSpec* = ref object of ArrayUpdateSpec
    option*: OptionValue

type
  VmNvramFileQuery* = ref object of FileQuery
  
type
  VirtualMachineToolsInstallType* {.pure.} = enum
    guestToolsTypeUnknown, guestToolsTypeMSI, guestToolsTypeTar, guestToolsTypeOSP,
    guestToolsTypeOpenVMTools
type
  AuthorizationDescription* = ref object of DynamicData
    privilege*: seq[ElementDescription]
    privilegeGroup*: seq[ElementDescription]

type
  HostWakeOnLanConfig* = ref object of DynamicData
    broadcastAddress*: string
    macAddress*: seq[string]
    deviceName*: string

type
  VirtualMachine* = ref object of vim.ManagedEntity
    capability*: VirtualMachineCapability
    config*: VirtualMachineConfigInfo
    layout*: VirtualMachineFileLayout
    layoutEx*: VirtualMachineFileLayoutEx
    storage*: VirtualMachineStorageInfo
    environmentBrowser*: EnvironmentBrowser
    resourcePool*: ResourcePool
    parentVApp*: ManagedEntity
    resourceConfig*: ResourceConfigSpec
    runtime*: VirtualMachineRuntimeInfo
    guest*: GuestInfo
    summary*: VirtualMachineSummary
    datastore*: seq[Datastore]
    network*: seq[Network]
    snapshot*: VirtualMachineSnapshotInfo
    rootSnapshot*: seq[VirtualMachineSnapshot]
    guestHeartbeatStatus*: ManagedEntityStatus

type
  NoGuestHeartbeat* = ref object of MigrationFault
  
type
  HostLowLevelProvisioningManagerReloadTarget* {.pure.} = enum
    currentConfig, snapshotConfig
type
  NamespaceWriteProtected* = ref object of VimFault
    name*: string

type
  VMwareDVSPortSetting* = ref object of DVPortSetting
    vlan*: VmwareDistributedVirtualSwitchVlanSpec
    qosTag*: IntPolicy
    uplinkTeamingPolicy*: VmwareUplinkPortTeamingPolicy
    securityPolicy*: DVSSecurityPolicy
    ipfixEnabled*: BoolPolicy
    txUplink*: BoolPolicy
    lacpPolicy*: VMwareUplinkLacpPolicy
    macManagementPolicy*: DVSMacManagementPolicy

type
  VmfsDatastoreExtendSpec* = ref object of VmfsDatastoreSpec
    partition*: HostDiskPartitionSpec
    extent*: seq[HostScsiDiskPartition]

type
  CbrcDigestConfigureResult* = ref object of CbrcDigestOperationResult
  
type
  VirtualAHCIControllerOption* = ref object of VirtualSATAControllerOption
  
type
  HostServiceTicket* = ref object of DynamicData
    host*: string
    port*: int
    sslThumbprint*: string
    service*: string
    serviceVersion*: string
    sessionId*: string

type
  DvsHostWentOutOfSyncEvent* = ref object of DvsEvent
    hostOutOfSync*: DvsOutOfSyncHostArgument

type
  GuestRegistryValueFault* = ref object of GuestRegistryFault
    keyName*: string
    valueName*: string

type
  EventFilterSpec* = ref object of DynamicData
    entity*: EventFilterSpecByEntity
    time*: EventFilterSpecByTime
    userName*: EventFilterSpecByUsername
    eventChainId*: int
    alarm*: Alarm
    scheduledTask*: ScheduledTask
    disableFullMessage*: bool
    category*: seq[string]
    type*: seq[string]
    tag*: seq[string]
    eventTypeId*: seq[string]
    maxCount*: int

type
  HostReplayUnsupportedReason* {.pure.} = enum
    incompatibleProduct, incompatibleCpu, hvDisabled, cpuidLimitSet, oldBIOS, unknown
type
  VirtualMachineUsbInfoFamily* {.pure.} = enum
    audio, hid, hid_bootable, physical, communication, imaging, printer, storage, hub,
    smart_card, security, video, wireless, bluetooth, wusb, pda, vendor_specific, other,
    unknownFamily
type
  ProfileDissociatedEvent* = ref object of ProfileEvent
  
type
  VirtualEnsoniq1371Option* = ref object of VirtualSoundCardOption
  
type
  OvfMissingElement* = ref object of OvfElement
  
type
  VirtualDiskType* {.pure.} = enum
    preallocated, thin, seSparse, rdm, rdmp, raw, delta, sparse2Gb, thick2Gb,
    eagerZeroedThick, sparseMonolithic, flatMonolithic, thick
type
  ExitingStandbyModeEvent* = ref object of HostEvent
  
type
  DataProviderSortCriterionSortDirection* {.pure.} = enum
    Ascending, Descending
type
  DatastoreSummaryMaintenanceModeState* {.pure.} = enum
    normal, enteringMaintenance, inMaintenance
type
  CheckResult* = ref object of DynamicData
    vm*: VirtualMachine
    host*: HostSystem
    warning*: seq[MethodFault]
    error*: seq[MethodFault]

type
  VmDiskFileQueryFilter* = ref object of DynamicData
    diskType*: seq[string]
    matchHardwareVersion*: seq[int]
    controllerType*: seq[string]
    thin*: bool
    encrypted*: bool

type
  ClusterFixedSizeSlotPolicy* = ref object of ClusterSlotPolicy
    cpu*: int
    memory*: int

type
  DataProviderBatchResultSet* = ref object of DynamicData
    resultSets*: seq[DataProviderResultSet]

type
  DistributedVirtualSwitchHostMemberPnicSpec* = ref object of DynamicData
    pnicDevice*: string
    uplinkPortKey*: string
    uplinkPortgroupKey*: string
    connectionCookie*: int

type
  EventDescriptionEventDetail* = ref object of DynamicData
    key*: string
    description*: string
    category*: string
    formatOnDatacenter*: string
    formatOnComputeResource*: string
    formatOnHost*: string
    formatOnVm*: string
    fullFormat*: string
    longDescription*: string

type
  HostFirewallRuleset* = ref object of DynamicData
    key*: string
    label*: string
    required*: bool
    rule*: seq[HostFirewallRule]
    service*: string
    enabled*: bool
    allowedHosts*: HostFirewallRulesetIpList

type
  ProfileRemovedEvent* = ref object of ProfileEvent
  
type
  ExtensionResourceInfo* = ref object of DynamicData
    locale*: string
    module*: string
    data*: seq[KeyValue]

type
  UpdateVirtualMachineFilesResult* = ref object of DynamicData
    failedVmFile*: seq[UpdateVirtualMachineFilesResultFailedVmFileInfo]

type
  DvsMacRewriteNetworkRuleAction* = ref object of DvsNetworkRuleAction
    rewriteMac*: string

type
  SessionEvent* = ref object of Event
  
type
  GuestAuthNamedSubject* = ref object of GuestAuthSubject
    name*: string

type
  RollbackEvent* = ref object of DvsEvent
    hostName*: string
    methodName*: string

type
  GuestOperationsUnavailable* = ref object of GuestOperationsFault
  
type
  CryptoSpecNoOp* = ref object of CryptoSpec
  
type
  UplinkPortMtuNotSupportEvent* = ref object of DvsHealthStatusChangeEvent
  
type
  VirtualMachinePciSharedGpuPassthroughInfo* = ref object of VirtualMachineTargetInfo
    vgpu*: string

type
  ClusterDependencyRuleInfo* = ref object of ClusterRuleInfo
    vmGroup*: string
    dependsOnVmGroup*: string

type
  VmFailedStartingSecondaryEventFailureReason* {.pure.} = enum
    incompatibleHost, loginFailed, registerVmFailed, migrateFailed
type
  ClusterEVCManagerCheckResult* = ref object of DynamicData
    evcModeKey*: string
    error*: MethodFault
    host*: seq[HostSystem]

type
  HostFileAccess* = ref object of DynamicData
    who*: string
    what*: string

type
  DvsProfile* = ref object of ApplyProfile
    key*: string
    name*: string
    uplink*: seq[PnicUplinkProfile]

type
  OvfPropertyQualifierIgnored* = ref object of OvfProperty
    qualifier*: string

type
  HostProfileValidationFailureInfo* = ref object of DynamicData
    name*: string
    annotation*: string
    updateType*: string
    host*: HostSystem
    applyProfile*: HostApplyProfile
    failures*: seq[ProfileUpdateFailedUpdateFailure]
    faults*: seq[MethodFault]

type
  HostFaultToleranceManagerFaultToleranceType* {.pure.} = enum
    fault_tolerance_using_checkpoints, fault_tolerance_using_recordreplay
type
  HostProfileAttributeCondition* = ref object of DynamicData
    operator*: string
    compareValue*: pointer

type
  VirtualMachineTicketType* {.pure.} = enum
    mks, device, guestControl, dnd, webmks, guestIntegrity
type
  LicenseAssignmentManager* = ref object of vmodl.ManagedObject
  
type
  VMotionLinkCapacityLow* = ref object of VMotionInterfaceIssue
    network*: string

type
  HostPatchManagerIntegrityStatus* {.pure.} = enum
    validated, keyNotFound, keyRevoked, keyExpired, digestMismatch,
    notEnoughSignatures, validationError
type
  VmwareDistributedVirtualSwitchVlanIdSpec* = ref object of VmwareDistributedVirtualSwitchVlanSpec
    vlanId*: int

type
  HostPortGroup* = ref object of DynamicData
    key*: string
    port*: seq[HostPortGroupPort]
    vswitch*: HostVirtualSwitch
    computedPolicy*: HostNetworkPolicy
    spec*: HostPortGroupSpec

type
  NetIpRouteConfigSpecIpRouteSpec* = ref object of DynamicData
    network*: string
    prefixLength*: int
    gateway*: NetIpRouteConfigSpecGatewaySpec
    operation*: string

type
  GuestRegKeyNameSpec* = ref object of DynamicData
    registryPath*: string
    wowBitness*: string

type
  ProfileHostProfileEngineComplianceManager* = ref object of vmodl.ManagedObject
  
type
  InsufficientVFlashResourcesFault* = ref object of InsufficientResourcesFault
    freeSpaceInMB*: int64
    freeSpace*: int64
    requestedSpaceInMB*: int64
    requestedSpace*: int64

type
  ExtensionServerInfo* = ref object of DynamicData
    url*: string
    description*: Description
    company*: string
    type*: string
    adminEmail*: seq[string]
    serverThumbprint*: string

type
  DvsRenamedEvent* = ref object of DvsEvent
    oldName*: string
    newName*: string

type
  SecurityProfile* = ref object of ApplyProfile
    permission*: seq[PermissionProfile]

type
  ValidateMigrationTestType* {.pure.} = enum
    sourceTests, compatibilityTests, diskAccessibilityTests, resourceTests
type
  HostScsiTopology* = ref object of DynamicData
    adapter*: seq[HostScsiTopologyInterface]

type
  IscsiFaultVnicIsLastPath* = ref object of IscsiFault
    vnicDevice*: string

type
  VsanUpgradeSystemRogueHostsInClusterIssue* = ref object of VsanUpgradeSystemPreflightCheckIssue
    uuids*: seq[string]

type
  VStorageObjectSnapshotInfoVStorageObjectSnapshot* = ref object of DynamicData
    id*: ID
    backingObjectId*: string
    createTime*: string
    description*: string

type
  DvsPortBlockedEvent* = ref object of DvsEvent
    portKey*: string
    statusDetail*: string
    runtimeInfo*: DVPortStatus
    prevBlockState*: string

type
  VirtualPCIPassthroughDeviceBackingOption* = ref object of VirtualDeviceDeviceBackingOption
  
type
  NonHomeRDMVMotionNotSupported* = ref object of MigrationFeatureNotSupported
    device*: string

type
  CDCChangeLogCollectorChangeLog* {.pure.} = enum
    inventory, alarmStatus
type
  OvfElement* = ref object of OvfInvalidPackage
    name*: string

type
  ClusterRuleInfo* = ref object of DynamicData
    key*: int
    status*: ManagedEntityStatus
    enabled*: bool
    name*: string
    mandatory*: bool
    userCreated*: bool
    inCompliance*: bool
    ruleUuid*: string

type
  VirtualMachineMetadataManagerVmMetadata* = ref object of DynamicData
    vmId*: string
    metadata*: string

type
  ScheduledTaskStartedEvent* = ref object of ScheduledTaskEvent
  
type
  VirtualMachineNamespaceManagerQueryResult* = ref object of DynamicData
    dataInfo*: seq[VirtualMachineNamespaceManagerDataInfo]
    nextQuery*: string

type
  HostConnectedEvent* = ref object of HostEvent
  
type
  VirtualMachineVMCIDevice* = ref object of VirtualDevice
    id*: int64
    allowUnrestrictedCommunication*: bool
    filterEnable*: bool
    filterInfo*: VirtualMachineVMCIDeviceFilterInfo

type
  VsanHostClusterStatusState* = ref object of DynamicData
    state*: string
    completion*: VsanHostClusterStatusStateCompletionEstimate

type
  DVSInheritedOpaqueData* = ref object of DVSOpaqueData
    inherited*: bool

type
  DvsTrafficFilterConfig* = ref object of DvsFilterConfig
    trafficRuleset*: DvsTrafficRuleset

type
  VMotionProtocolIncompatible* = ref object of MigrationFault
  
type
  CustomFieldDefRemovedEvent* = ref object of CustomFieldDefEvent
  
type
  DvsOutOfSyncHostArgument* = ref object of DynamicData
    outOfSyncHost*: HostEventArgument
    configParamters*: seq[string]

type
  PerformanceManager* = ref object of vmodl.ManagedObject
    description*: PerformanceDescription
    historicalInterval*: seq[PerfInterval]
    perfCounter*: seq[PerfCounterInfo]

type
  StoragePlacementSpec* = ref object of DynamicData
    type*: string
    priority*: VirtualMachineMovePriority
    vm*: VirtualMachine
    podSelectionSpec*: StorageDrsPodSelectionSpec
    cloneSpec*: VirtualMachineCloneSpec
    cloneName*: string
    configSpec*: VirtualMachineConfigSpec
    relocateSpec*: VirtualMachineRelocateSpec
    resourcePool*: ResourcePool
    host*: HostSystem
    folder*: Folder
    disallowPrerequisiteMoves*: bool
    resourceLeaseDurationSec*: int

type
  OvfConsumerUndeclaredSection* = ref object of OvfConsumerCallbackFault
    qualifiedSectionType*: string

type
  VirtualDeviceConnectInfo* = ref object of DynamicData
    migrateConnect*: string
    startConnected*: bool
    allowGuestControl*: bool
    connected*: bool
    status*: string

type
  HostInternetScsiHbaAuthenticationProperties* = ref object of DynamicData
    chapAuthEnabled*: bool
    chapName*: string
    chapSecret*: string
    chapAuthenticationType*: string
    chapInherited*: bool
    mutualChapName*: string
    mutualChapSecret*: string
    mutualChapAuthenticationType*: string
    mutualChapInherited*: bool

type
  TpmFault* = ref object of VimFault
  
type
  VirtualMachineConfigSpecNpivWwnOp* {.pure.} = enum
    generate, set, remove, extend
type
  HostNewNetworkConnectInfo* = ref object of HostConnectInfoNetworkInfo
  
type
  StorageDrsCannotMoveIndependentDisk* = ref object of VimFault
  
type
  GenericDrsFault* = ref object of VimFault
    hostFaults*: seq[MethodFault]

type
  ClusterDasFailoverLevelAdvancedRuntimeInfoSlotInfo* = ref object of DynamicData
    numVcpus*: int
    cpuMHz*: int
    memoryMB*: int

type
  FloatOption* = ref object of OptionType
    min*: float32
    max*: float32
    defaultValue*: float32

type
  NetworkSummary* = ref object of DynamicData
    network*: Network
    name*: string
    accessible*: bool
    ipPoolName*: string
    ipPoolId*: int

type
  BaseConfigInfoBackingInfo* = ref object of DynamicData
    datastore*: Datastore

type
  VslmMigrateSpec* = ref object of DynamicData
    backingSpec*: VslmCreateSpecBackingSpec
    profile*: seq[VirtualMachineProfileSpec]
    consolidate*: bool

type
  EntityPrivilege* = ref object of DynamicData
    entity*: ManagedEntity
    privAvailability*: seq[PrivilegeAvailability]

type
  HostDiskBlockInfoVmfsMapping* = ref object of HostDiskBlockInfoMapping
  
type
  OvfConsumer* = ref object of vmodl.ManagedObject
  
type
  HostDiskMappingInfo* = ref object of DynamicData
    physicalPartition*: HostDiskMappingPartitionInfo
    name*: string
    exclusive*: bool

type
  VirtualMachineWindowsQuiesceSpecVssBackupContext* {.pure.} = enum
    ctx_auto, ctx_backup, ctx_file_share_backup
type
  VmConfigFileEncryptionInfo* = ref object of DynamicData
    keyId*: CryptoKeyId

type
  OvfValidateHostParams* = ref object of OvfManagerCommonParams
  
type
  CryptoSpecEncrypt* = ref object of CryptoSpec
    cryptoKeyId*: CryptoKeyId

type
  DasHostFailedEvent* = ref object of ClusterEvent
    failedHost*: HostEventArgument

type
  HostCnxFailedNotFoundEvent* = ref object of HostEvent
  
type
  CryptoSpec* = ref object of DynamicData
  
type
  VvolDatastoreInfo* = ref object of DatastoreInfo
    vvolDS*: HostVvolVolume

type
  KmipServerInfo* = ref object of DynamicData
    name*: string
    address*: string
    port*: int
    proxyAddress*: string
    proxyPort*: int
    reconnect*: int
    protocol*: string
    nbio*: int
    timeout*: int
    userName*: string

type
  VirtualMachineMetadataManagerVmMetadataInput* = ref object of DynamicData
    operation*: string
    vmMetadata*: VirtualMachineMetadataManagerVmMetadata

type
  VMwareDvsLacpGroupConfig* = ref object of DynamicData
    key*: string
    name*: string
    mode*: string
    uplinkNum*: int
    loadbalanceAlgorithm*: string
    vlan*: VMwareDvsLagVlanConfig
    ipfix*: VMwareDvsLagIpfixConfig
    uplinkName*: seq[string]
    uplinkPortKey*: seq[string]

type
  VirtualCdromRemotePassthroughBackingOption* = ref object of VirtualDeviceRemoteDeviceBackingOption
    exclusive*: BoolOption

type
  HostSystemDebugManagerProcessKey* {.pure.} = enum
    hostd
type
  HostVmfsRescanResult* = ref object of DynamicData
    host*: HostSystem
    fault*: MethodFault

type
  HostDasDisabledEvent* = ref object of HostEvent
  
type
  VirtualMachineRelocateDiskMoveOptions* {.pure.} = enum
    moveAllDiskBackingsAndAllowSharing, moveAllDiskBackingsAndDisallowSharing,
    moveChildMostDiskBacking, createNewChildDiskBacking,
    moveAllDiskBackingsAndConsolidate
type
  DVPortgroupRenamedEvent* = ref object of DVPortgroupEvent
    oldName*: string
    newName*: string

type
  ExtSolutionManagerInfo* = ref object of DynamicData
    tab*: seq[ExtSolutionManagerInfoTabInfo]
    smallIconUrl*: string

type
  FcoeFault* = ref object of VimFault
  
type
  OvfInternalError* = ref object of OvfSystemFault
  
type
  NvdimmNvdimmHealthInfoState* {.pure.} = enum
    normal, error
type
  PerformanceStatisticsDescription* = ref object of DynamicData
    intervals*: seq[PerfInterval]

type
  ManagedEntity* = ref object of vim.ExtensibleManagedObject
    parent*: ManagedEntity
    customValue*: seq[CustomFieldValue]
    overallStatus*: ManagedEntityStatus
    configStatus*: ManagedEntityStatus
    configIssue*: seq[Event]
    effectiveRole*: seq[int]
    permission*: seq[Permission]
    name*: string
    disabledMethod*: seq[string]
    recentTask*: seq[Task]
    declaredAlarmState*: seq[AlarmState]
    triggeredAlarmState*: seq[AlarmState]
    alarmActionsEnabled*: bool
    tag*: seq[Tag]

type
  FeatureRequirementsNotMet* = ref object of VirtualHardwareCompatibilityIssue
    featureRequirement*: seq[VirtualMachineFeatureRequirement]
    vm*: VirtualMachine
    host*: HostSystem

type
  ExtensionManager* = ref object of vmodl.ManagedObject
    extensionList*: seq[Extension]

type
  HostInternetScsiHbaIscsiIpv6AddressAddressConfigurationType* {.pure.} = enum
    DHCP, AutoConfigured, Static, Other
type
  VmRenamedEvent* = ref object of VmEvent
    oldName*: string
    newName*: string

type
  VmValidateMaxDevice* = ref object of VimFault
    device*: string
    max*: int
    count*: int

type
  HostRuntimeInfoNetStackInstanceRuntimeInfoState* {.pure.} = enum
    inactive, active, deactivating, activating
type
  VirtualEthernetCardDVPortBackingOption* = ref object of VirtualDeviceBackingOption
  
type
  CustomFieldStringValue* = ref object of CustomFieldValue
    value*: string

type
  VirtualMachineCreateChildSpec* = ref object of DynamicData
    location*: VirtualMachineRelocateSpec
    persistent*: bool
    configParams*: seq[OptionValue]

type
  FaultToleranceMetaSpec* = ref object of DynamicData
    metaDataDatastore*: Datastore

type
  ClusterActionHistory* = ref object of DynamicData
    action*: ClusterAction
    time*: string

type
  ExtendedDescription* = ref object of Description
    messageCatalogKeyPrefix*: string
    messageArg*: seq[KeyAnyValue]

type
  ClusterIoFilterInfo* = ref object of IoFilterInfo
    opType*: string
    vibUrl*: string

type
  LicenseAssignmentFailed* = ref object of RuntimeFault
    reason*: string

type
  HostProxySwitchSpec* = ref object of DynamicData
    backing*: DistributedVirtualSwitchHostMemberBacking

type
  VirtualMachineMemoryReservationInfo* = ref object of DynamicData
    virtualMachineMin*: int64
    virtualMachineMax*: int64
    virtualMachineReserved*: int64
    allocationPolicy*: string

type
  ExtensionFaultTypeInfo* = ref object of DynamicData
    faultID*: string

type
  InsufficientStorageSpace* = ref object of InsufficientResourcesFault
  
type
  ScheduledTaskEventArgument* = ref object of EntityEventArgument
    scheduledTask*: ScheduledTask

type
  DvsOperationBulkFault* = ref object of DvsFault
    hostFault*: seq[DvsOperationBulkFaultFaultOnHost]

type
  HbrManager* = ref object of vmodl.ManagedObject
  
type
  ClusterIncreaseAllocationAction* = ref object of ClusterAction
    delta*: ClusterPerResourceValue

type
  InvalidEditionEvent* = ref object of LicenseEvent
    feature*: string

type
  DvsPortReconfiguredEvent* = ref object of DvsEvent
    portKey*: seq[string]
    configChanges*: seq[ChangesInfoEventArgument]

type
  StorageDrsHbrDiskNotMovable* = ref object of VimFault
    nonMovableDiskIds*: string

type
  HostSystemRemediationState* = ref object of DynamicData
    state*: string
    operationTime*: string

type
  EnvironmentBrowser* = ref object of vmodl.ManagedObject
    datastoreBrowser*: HostDatastoreBrowser

type
  AgentInstallFailedReason* {.pure.} = enum
    NotEnoughSpaceOnDevice, PrepareToUpgradeFailed, AgentNotRunning,
    AgentNotReachable, InstallTimedout, SignatureVerificationFailed,
    AgentUploadFailed, AgentUploadTimedout, UnknownInstallerError
type
  HostNetCapabilities* = ref object of DynamicData
    canSetPhysicalNicLinkSpeed*: bool
    supportsNicTeaming*: bool
    nicTeamingPolicy*: seq[string]
    supportsVlan*: bool
    usesServiceConsoleNic*: bool
    supportsNetworkHints*: bool
    maxPortGroupsPerVswitch*: int
    vswitchConfigSupported*: bool
    vnicConfigSupported*: bool
    ipRouteConfigSupported*: bool
    dnsConfigSupported*: bool
    dhcpOnVnicSupported*: bool
    ipV6Supported*: bool

type
  ProductComponentInfo* = ref object of DynamicData
    id*: string
    name*: string
    version*: string
    release*: int

type
  ElementDescription* = ref object of Description
    key*: string

type
  ProfileChangedEvent* = ref object of ProfileEvent
  
type
  GuestRegValueStringSpec* = ref object of GuestRegValueDataSpec
    value*: string

type
  VMwareDvsLagVlanConfig* = ref object of DynamicData
    vlanId*: seq[NumericRange]

type
  VirtualMachineConfigOptionDescriptor* = ref object of DynamicData
    key*: string
    description*: string
    host*: seq[HostSystem]
    createSupported*: bool
    defaultConfigOption*: bool
    runSupported*: bool
    upgradeSupported*: bool

type
  EntityEventArgument* = ref object of EventArgument
    name*: string

type
  NoDiskSpace* = ref object of FileFault
    datastore*: string

type
  StoragePod* = ref object of vim.Folder
    summary*: StoragePodSummary
    podStorageDrsEntry*: PodStorageDrsEntry

type
  HostListSummaryGatewaySummary* = ref object of DynamicData
    gatewayType*: string
    gatewayId*: string

type
  ProfileUpdateFailedUpdateFailure* = ref object of DynamicData
    profilePath*: ProfilePropertyPath
    errMsg*: LocalizableMessage

type
  HostDvpgNetworkResource* = ref object of HostNetworkResource
    uplinkNames*: seq[string]

type
  DVPortgroupConfigSpec* = ref object of DynamicData
    configVersion*: string
    name*: string
    numPorts*: int
    portNameFormat*: string
    defaultPortConfig*: DVPortSetting
    description*: string
    type*: string
    scope*: seq[ManagedEntity]
    policy*: DVPortgroupPolicy
    vendorSpecificConfig*: seq[DistributedVirtualSwitchKeyedOpaqueBlob]
    autoExpand*: bool
    vmVnicNetworkResourcePoolKey*: string

type
  ParaVirtualSCSIControllerOption* = ref object of VirtualSCSIControllerOption
  
type
  SharesLevel* {.pure.} = enum
    low, normal, high, custom
type
  StaticRouteProfile* = ref object of ApplyProfile
    key*: string

type
  WitnessNodeInfo* = ref object of DynamicData
    ipSettings*: CustomizationIPSettings
    biosUuid*: string

type
  VirtualFloppyRemoteDeviceBackingInfo* = ref object of VirtualDeviceRemoteDeviceBackingInfo
  
type
  HostLowLevelProvisioningManagerVmRecoveryInfo* = ref object of DynamicData
    version*: string
    biosUUID*: string
    instanceUUID*: string
    ftInfo*: FaultToleranceConfigInfo

type
  ResourcePool* = ref object of vim.ManagedEntity
    summary*: ResourcePoolSummary
    runtime*: ResourcePoolRuntimeInfo
    owner*: ComputeResource
    resourcePool*: seq[ResourcePool]
    vm*: seq[VirtualMachine]
    config*: ResourceConfigSpec
    childConfiguration*: seq[ResourceConfigSpec]

type
  NvdimmSystemInfo* = ref object of DynamicData
    summary*: NvdimmSummary
    dimms*: seq[int]
    dimmInfo*: seq[NvdimmDimmInfo]
    interleaveSet*: seq[int]
    iSetInfo*: seq[NvdimmInterleaveSetInfo]
    namespace*: seq[NvdimmGuid]
    nsInfo*: seq[NvdimmNamespaceInfo]

type
  DvsTrafficRule* = ref object of DynamicData
    key*: string
    description*: string
    sequence*: int
    qualifier*: seq[DvsNetworkRuleQualifier]
    action*: DvsNetworkRuleAction
    direction*: string

type
  NoHostSuitableForFtSecondary* = ref object of VmFaultToleranceIssue
    vm*: VirtualMachine
    vmName*: string

type
  FilesystemQuiesceFault* = ref object of SnapshotFault
  
type
  ImageLibraryManagerMediaType* {.pure.} = enum
    Ovf, Vmdk, Iso, Flp, Cust, Generic
type
  ConflictingConfiguration* = ref object of DvsFault
    configInConflict*: seq[ConflictingConfigurationConfig]

type
  VmDasUpdateOkEvent* = ref object of VmEvent
  
type
  HostSystemSwapConfiguration* = ref object of DynamicData
    option*: seq[HostSystemSwapConfigurationSystemSwapOption]

type
  OvfUnsupportedElement* = ref object of OvfUnsupportedPackage
    name*: string

type
  LicenseFault* = ref object of NotEnoughLicenses
  
type
  HostCnxFailedNoAccessEvent* = ref object of HostEvent
  
type
  FileLocked* = ref object of FileFault
  
type
  InvalidAffinitySettingFault* = ref object of VimFault
  
type
  ClusterDasDataSummary* = ref object of ClusterDasData
    hostListVersion*: int64
    clusterConfigVersion*: int64
    compatListVersion*: int64

type
  VsanHostDiskResultState* {.pure.} = enum
    inUse, eligible, ineligible
type
  ClusterFailoverResourcesAdmissionControlInfo* = ref object of ClusterDasAdmissionControlInfo
    currentCpuFailoverResourcesPercent*: int
    currentMemoryFailoverResourcesPercent*: int

type
  DiskChangeExtent* = ref object of DynamicData
    start*: int64
    length*: int64

type
  Alarm* = ref object of vim.ExtensibleManagedObject
    info*: AlarmInfo

type
  HostCpuPackage* = ref object of DynamicData
    index*: int16
    vendor*: string
    hz*: int64
    busHz*: int64
    description*: string
    threadId*: seq[int16]
    cpuFeature*: seq[HostCpuIdInfo]

type
  VStorageObjectManagerBase* = ref object of vmodl.ManagedObject
  
type
  NasConfigFault* = ref object of HostConfigFault
    name*: string

type
  NoDiskFound* = ref object of VimFault
  
type
  DeviceBackingNotSupported* = ref object of DeviceNotSupported
    backing*: string

type
  HostVmfsSpec* = ref object of DynamicData
    extent*: HostScsiDiskPartition
    blockSizeMb*: int
    majorVersion*: int
    volumeName*: string
    blockSize*: int
    unmapGranularity*: int
    unmapPriority*: string
    unmapBandwidthSpec*: VmfsUnmapBandwidthSpec

type
  KmipServerSpec* = ref object of DynamicData
    clusterId*: KeyProviderId
    info*: KmipServerInfo
    password*: string

type
  HostProfileManagerCompositionValidationResultResultElement* = ref object of DynamicData
    target*: Profile
    status*: string
    errors*: seq[LocalizableMessage]
    sourceDiffForToBeMerged*: HostApplyProfile
    targetDiffForToBeMerged*: HostApplyProfile
    toBeAdded*: HostApplyProfile
    toBeDeleted*: HostApplyProfile
    toBeDisabled*: HostApplyProfile
    toBeEnabled*: HostApplyProfile
    toBeReenableCC*: HostApplyProfile

type
  PowerOnFtSecondaryTimedout* = ref object of Timedout
    vm*: VirtualMachine
    vmName*: string
    timeout*: int

type
  DistributedVirtualSwitchHostMember* = ref object of DynamicData
    runtimeState*: DistributedVirtualSwitchHostMemberRuntimeState
    config*: DistributedVirtualSwitchHostMemberConfigInfo
    productInfo*: DistributedVirtualSwitchProductSpec
    uplinkPortKey*: seq[string]
    status*: string
    statusDetail*: string

type
  ScheduledTaskEmailFailedEvent* = ref object of ScheduledTaskEvent
    to*: string
    reason*: MethodFault

type
  VmDiskFailedEvent* = ref object of VmEvent
    disk*: string
    reason*: MethodFault

type
  DistributedVirtualSwitchPortConnection* = ref object of DynamicData
    switchUuid*: string
    portgroupKey*: string
    portKey*: string
    connectionCookie*: int

type
  HostSystemConnectionState* {.pure.} = enum
    connected, notResponding, disconnected
type
  IscsiFaultPnicInUse* = ref object of IscsiFault
    pnicDevice*: string

type
  VsanHostDiskResult* = ref object of DynamicData
    disk*: HostScsiDisk
    state*: string
    vsanUuid*: string
    error*: MethodFault
    degraded*: bool

type
  ResourceType* {.pure.} = enum
    cpu, memory
type
  OvfDiskMappingNotFound* = ref object of OvfSystemFault
    diskName*: string
    vmName*: string

type
  ClusterDasFailoverLevelAdvancedRuntimeInfoHostSlots* = ref object of DynamicData
    host*: HostSystem
    slots*: int

type
  VspanSameSessionPortConflict* = ref object of DvsFault
    vspanSessionKey*: string
    portKey*: string

type
  HostService* = ref object of DynamicData
    key*: string
    label*: string
    required*: bool
    uninstallable*: bool
    running*: bool
    ruleset*: seq[string]
    policy*: string
    sourcePackage*: HostServiceSourcePackage

type
  DatastoreInfo* = ref object of DynamicData
    name*: string
    url*: string
    freeSpace*: int64
    maxFileSize*: int64
    maxVirtualDiskCapacity*: int64
    maxMemoryFileSize*: int64
    timestamp*: string
    containerId*: string

type
  TaskManager* = ref object of vmodl.ManagedObject
    recentTask*: seq[Task]
    description*: TaskDescription
    maxCollector*: int

type
  HostInternetScsiHbaDigestType* {.pure.} = enum
    digestProhibited, digestDiscouraged, digestPreferred, digestRequired
type
  ClusterFailoverLevelAdmissionControlInfo* = ref object of ClusterDasAdmissionControlInfo
    currentFailoverLevel*: int

type
  MemoryHotPlugNotSupported* = ref object of VmConfigFault
  
type
  NoCompatibleSoftAffinityHost* = ref object of VmConfigFault
    vmName*: string

type
  CannotMoveVmWithDeltaDisk* = ref object of MigrationFault
    device*: string

type
  HostAutoStartManager* = ref object of vmodl.ManagedObject
    config*: HostAutoStartManagerConfig

type
  VirtualFloppy* = ref object of VirtualDevice
  
type
  ImageLibraryManager* = ref object of vmodl.ManagedObject
  
type
  ScheduledTaskInfo* = ref object of ScheduledTaskSpec
    scheduledTask*: ScheduledTask
    entity*: ManagedEntity
    lastModifiedTime*: string
    lastModifiedUser*: string
    nextRunTime*: string
    prevRunTime*: string
    state*: TaskInfoState
    error*: MethodFault
    result*: pointer
    progress*: int
    activeTask*: Task
    taskObject*: ManagedObject

type
  HostStandbyMode* {.pure.} = enum
    entering, exiting, in, none
type
  PerfQuerySpec* = ref object of DynamicData
    entity*: ManagedObject
    startTime*: string
    endTime*: string
    maxSample*: int
    metricId*: seq[PerfMetricId]
    intervalId*: int
    format*: string

type
  NoPermission* = ref object of SecurityError
    object*: ManagedObject
    privilegeId*: string

type
  HostTpmDigestInfo* = ref object of HostDigestInfo
    pcrNumber*: int

type
  TimedOutHostOperationEvent* = ref object of HostEvent
  
type
  HostTpmSoftwareComponentEventDetails* = ref object of HostTpmEventDetails
    componentName*: string
    vibName*: string
    vibVersion*: string
    vibVendor*: string

type
  HostVsanInternalSystem* = ref object of vmodl.ManagedObject
  
type
  HostVsanSystem* = ref object of vmodl.ManagedObject
    config*: VsanHostConfigInfo

type
  NodeDeploymentSpec* = ref object of DynamicData
    esxHost*: HostSystem
    datastore*: Datastore
    publicNetworkPortGroup*: Network
    clusterNetworkPortGroup*: Network
    folder*: Folder
    resourcePool*: ResourcePool
    managementVc*: ServiceLocator
    nodeName*: string
    ipSettings*: CustomizationIPSettings

type
  DasConfigFaultDasConfigFaultReason* {.pure.} = enum
    HostNetworkMisconfiguration, HostMisconfiguration, InsufficientPrivileges,
    NoPrimaryAgentAvailable, Other, NoDatastoresConfigured, CreateConfigVvolFailed,
    VSanNotSupportedOnHost, DasNetworkMisconfiguration
type
  ReplicationSpec* = ref object of DynamicData
    replicationGroupId*: ReplicationGroupId

type
  OvfPropertyValue* = ref object of OvfProperty
  
type
  HostVFlashManagerVFlashConfigInfo* = ref object of DynamicData
    vFlashResourceConfigInfo*: HostVFlashManagerVFlashResourceConfigInfo
    vFlashCacheConfigInfo*: HostVFlashManagerVFlashCacheConfigInfo

type
  HostVmfsVolume* = ref object of HostFileSystemVolume
    blockSizeMb*: int
    blockSize*: int
    unmapGranularity*: int
    unmapPriority*: string
    unmapBandwidthSpec*: VmfsUnmapBandwidthSpec
    maxBlocks*: int
    majorVersion*: int
    version*: string
    uuid*: string
    extent*: seq[HostScsiDiskPartition]
    vmfsUpgradable*: bool
    forceMountedInfo*: HostForceMountedInfo
    ssd*: bool
    local*: bool
    scsiDiskType*: string

type
  HostProfileManagerCompositionResult* = ref object of DynamicData
    errors*: seq[LocalizableMessage]
    results*: seq[HostProfileManagerCompositionResultResultElement]

type
  HostIpToShortNameFailedEvent* = ref object of HostEvent
  
type
  CustomFieldsManager* = ref object of vmodl.ManagedObject
    field*: seq[CustomFieldDef]

type
  InsufficientFailoverResourcesFault* = ref object of InsufficientResourcesFault
  
type
  ProxyService* = ref object of vmodl.ManagedObject
    httpsPort*: int
    httpPort*: int
    endpointList*: seq[ProxyServiceEndpointSpec]

type
  VspanPortConflict* = ref object of DvsFault
    vspanSessionKey1*: string
    vspanSessionKey2*: string
    portKey*: string

type
  VirtualDevice* = ref object of DynamicData
    key*: int
    deviceInfo*: Description
    backing*: VirtualDeviceBackingInfo
    connectable*: VirtualDeviceConnectInfo
    slotInfo*: VirtualDeviceBusSlotInfo
    controllerKey*: int
    unitNumber*: int

type
  HostConfigChangeOperation* {.pure.} = enum
    add, remove, edit, ignore
type
  FcoeConfig* = ref object of DynamicData
    priorityClass*: int
    sourceMac*: string
    vlanRange*: seq[FcoeConfigVlanRange]
    capabilities*: FcoeConfigFcoeCapabilities
    fcoeActive*: bool

type
  HostPortGroupConfig* = ref object of DynamicData
    changeOperation*: string
    spec*: HostPortGroupSpec

type
  VirtualMachineNeedSecondaryReason* {.pure.} = enum
    initializing, divergence, lostConnection, partialHardwareFailure, userAction,
    checkpointError, other
type
  VirtualDiskDeltaDiskFormatsSupported* = ref object of DynamicData
    datastoreType*: string
    deltaDiskFormat*: ChoiceOption

type
  LibraryFault* = ref object of VimFault
  
type
  GuestRegValueSpec* = ref object of DynamicData
    name*: GuestRegValueNameSpec
    data*: GuestRegValueDataSpec

type
  ClusterAntiAffinityRuleSpec* = ref object of ClusterRuleInfo
    vm*: seq[VirtualMachine]

type
  DrsVmotionIncompatibleFault* = ref object of VirtualHardwareCompatibilityIssue
    host*: HostSystem

type
  DisallowedChangeByServiceDisallowedChange* {.pure.} = enum
    hotExtendDisk
type
  VRPEditSpec* = ref object of DynamicData
    vrpId*: string
    description*: string
    cpuAllocation*: VrpResourceAllocationInfo
    memoryAllocation*: VrpResourceAllocationInfo
    addedHubs*: seq[ManagedEntity]
    removedHubs*: seq[ManagedEntity]
    changeVersion*: int64

type
  ClusterDasAamNodeState* = ref object of DynamicData
    host*: HostSystem
    name*: string
    configState*: string
    runtimeState*: string

type
  DvsLogNetworkRuleAction* = ref object of DvsNetworkRuleAction
  
type
  VmMetadataInvalidOwner* = ref object of VmMetadataManagerFault
    name*: string

type
  VAppAutoStartAction* {.pure.} = enum
    none, powerOn, powerOff, guestShutdown, suspend
type
  TeamingMatchEvent* = ref object of DvsHealthStatusChangeEvent
  
type
  HostNetOffloadCapabilities* = ref object of DynamicData
    csumOffload*: bool
    tcpSegmentation*: bool
    zeroCopyXmit*: bool

type
  ProfileCompositePolicyOptionMetadata* = ref object of ProfilePolicyOptionMetadata
    option*: seq[string]

type
  UnsupportedVmxLocation* = ref object of VmConfigFault
  
type
  HostFibreChannelOverEthernetHbaLinkInfo* = ref object of DynamicData
    vnportMac*: string
    fcfMac*: string
    vlanId*: int

type
  InvalidProfileReferenceHost* = ref object of RuntimeFault
    reason*: string
    host*: HostSystem
    profile*: Profile
    profileName*: string

type
  HostConfigSpec* = ref object of DynamicData
    nasDatastore*: seq[HostNasVolumeConfig]
    network*: HostNetworkConfig
    nicTypeSelection*: seq[HostVirtualNicManagerNicTypeSelection]
    service*: seq[HostServiceConfig]
    firewall*: HostFirewallConfig
    option*: seq[OptionValue]
    datastorePrincipal*: string
    datastorePrincipalPasswd*: string
    datetime*: HostDateTimeConfig
    storageDevice*: HostStorageDeviceInfo
    license*: HostLicenseSpec
    security*: HostSecuritySpec
    userAccount*: seq[HostAccountSpec]
    usergroupAccount*: seq[HostAccountSpec]
    memory*: HostMemorySpec
    activeDirectory*: seq[HostActiveDirectory]
    genericConfig*: seq[KeyAnyValue]
    graphicsConfig*: HostGraphicsConfig

type
  HostDasOkEvent* = ref object of HostEvent
  
type
  CanceledHostOperationEvent* = ref object of HostEvent
  
type
  NetDhcpConfigInfoDhcpOptions* = ref object of DynamicData
    enable*: bool
    config*: seq[KeyValue]

type
  RoleEvent* = ref object of AuthorizationEvent
    role*: RoleEventArgument

type
  VirtualPointingDevice* = ref object of VirtualDevice
  
type
  LicenseFeatureInfo* = ref object of DynamicData
    key*: string
    featureName*: string
    featureDescription*: string
    state*: LicenseFeatureInfoState
    costUnit*: string
    sourceRestriction*: string
    dependentKey*: seq[string]
    edition*: bool
    expiresOn*: string

type
  VirtualEthernetCardOption* = ref object of VirtualDeviceOption
    supportedOUI*: ChoiceOption
    macType*: ChoiceOption
    wakeOnLanEnabled*: BoolOption
    vmDirectPathGen2Supported*: bool
    uptCompatibilityEnabled*: BoolOption

type
  HostVFlashManagerVFlashResourceRunTimeInfo* = ref object of DynamicData
    usage*: int64
    capacity*: int64
    accessible*: bool
    capacityForVmCache*: int64
    freeForVmCache*: int64

type
  DeviceGroupId* = ref object of DynamicData
    id*: string

type
  DVSHealthCheckCapability* = ref object of DynamicData
  
type
  ProfileHostProfileEngineComplianceManagerExpressionMetaArray* = ref object of DynamicData
    exprMeta*: seq[ProfileExpressionMetadata]

type
  WillLoseHAProtection* = ref object of MigrationFault
    resolution*: string

type
  DistributedVirtualPortgroup* = ref object of vim.Network
    key*: string
    config*: DVPortgroupConfigInfo
    portKeys*: seq[string]

type
  VirtualMachineNamespaceManagerNamespaceInfoNamespaceAllocation* = ref object of DynamicData
    limit*: int64
    allocated*: int64

type
  HostDisconnectedEvent* = ref object of HostEvent
    reason*: string

type
  VirtualMachineFileInfo* = ref object of DynamicData
    vmPathName*: string
    snapshotDirectory*: string
    suspendDirectory*: string
    logDirectory*: string
    ftMetadataDirectory*: string

type
  VspanPortPromiscChangeFault* = ref object of DvsFault
    portKey*: string

type
  RecurrentTaskScheduler* = ref object of TaskScheduler
    interval*: int

type
  ServerStartedSessionEvent* = ref object of SessionEvent
  
type
  DvsHostBackInSyncEvent* = ref object of DvsEvent
    hostBackInSync*: HostEventArgument

type
  DistributedVirtualSwitchHostMemberRuntimeState* = ref object of DynamicData
    currentMaxProxySwitchPorts*: int

type
  LongOption* = ref object of OptionType
    min*: int64
    max*: int64
    defaultValue*: int64

type
  VirtualDiskVFlashCacheConfigInfo* = ref object of DynamicData
    vFlashModule*: string
    reservationInMB*: int64
    cacheConsistencyType*: string
    cacheMode*: string
    blockSizeInKB*: int64

type
  MonthlyByWeekdayTaskScheduler* = ref object of MonthlyTaskScheduler
    offset*: WeekOfMonth
    weekday*: DayOfWeek

type
  DistributedVirtualSwitchHostMemberConfigInfo* = ref object of DynamicData
    host*: HostSystem
    maxProxySwitchPorts*: int
    vendorSpecificConfig*: seq[DistributedVirtualSwitchKeyedOpaqueBlob]
    backing*: DistributedVirtualSwitchHostMemberBacking

type
  VMotionAcrossNetworkNotSupported* = ref object of MigrationFeatureNotSupported
  
type
  DistributedVirtualSwitchManager* = ref object of vmodl.ManagedObject
  
type
  VirtualPCIPassthroughVmiopBackingInfo* = ref object of VirtualPCIPassthroughPluginBackingInfo
    vgpu*: string

type
  VirtualEthernetCardNetworkBackingOption* = ref object of VirtualDeviceDeviceBackingOption
  
type
  VirtualDeviceRemoteDeviceBackingOption* = ref object of VirtualDeviceBackingOption
    autoDetectAvailable*: BoolOption

type
  StorageDrsHmsUnreachable* = ref object of VimFault
  
type
  DeviceUnsupportedForVmVersion* = ref object of InvalidDeviceSpec
    currentVersion*: string
    expectedVersion*: string

type
  HostUnresolvedVmfsExtent* = ref object of DynamicData
    device*: HostScsiDiskPartition
    devicePath*: string
    vmfsUuid*: string
    isHeadExtent*: bool
    ordinal*: int
    startBlock*: int
    endBlock*: int
    reason*: string

type
  CustomizationIPSettings* = ref object of DynamicData
    ip*: CustomizationIpGenerator
    subnetMask*: string
    gateway*: seq[string]
    ipV6Spec*: CustomizationIPSettingsIpV6AddressSpec
    dnsServerList*: seq[string]
    dnsDomain*: string
    primaryWINS*: string
    secondaryWINS*: string
    netBIOS*: CustomizationNetBIOSMode

type
  HostProfileManagerCompositionResultResultElement* = ref object of DynamicData
    target*: Profile
    status*: string
    errors*: seq[LocalizableMessage]

type
  NetworkBandwidthAllocationInfo* = ref object of ResourceAllocationInfo
    distributedVirtualSwitch*: DistributedVirtualSwitch
    distributedVirtualPort*: DistributedVirtualPort
    inShapingPolicy*: HostNetworkTrafficShapingPolicy
    outShapingPolicy*: HostNetworkTrafficShapingPolicy

type
  VirtualHardware* = ref object of DynamicData
    numCPU*: int
    numCoresPerSocket*: int
    memoryMB*: int
    virtualICH7MPresent*: bool
    virtualSMCPresent*: bool
    device*: seq[VirtualDevice]

type
  DisabledMethodSource* = ref object of DynamicData
    sourceId*: string
    reasonId*: string

type
  VsanUpgradeSystemPreflightCheckIssue* = ref object of DynamicData
    msg*: string

type
  OvfFault* = ref object of VimFault
  
type
  FileInfo* = ref object of DynamicData
    path*: string
    friendlyName*: string
    fileSize*: int64
    modification*: string
    owner*: string

type
  CustomizationGuiRunOnce* = ref object of DynamicData
    commandList*: seq[string]

type
  PolicyDisallowsOperation* = ref object of PolicyViolatedDetail
    notSupportedOperation*: string

type
  VirtualMachineTargetInfoConfigurationTag* {.pure.} = enum
    compliant, clusterWide
type
  StateAlarmOperator* {.pure.} = enum
    isEqual, isUnequal
type
  DVPortSetting* = ref object of DynamicData
    blocked*: BoolPolicy
    vmDirectPathGen2Allowed*: BoolPolicy
    inShapingPolicy*: DVSTrafficShapingPolicy
    outShapingPolicy*: DVSTrafficShapingPolicy
    vendorSpecificConfig*: DVSVendorSpecificConfig
    networkResourcePoolKey*: StringPolicy
    filterPolicy*: DvsFilterPolicy

type
  VirtualMachineVideoCardUse3dRenderer* {.pure.} = enum
    automatic, software, hardware
type
  FileManagerFileType* {.pure.} = enum
    File, VirtualDisk
type
  PlacementAffinityRuleRuleScope* {.pure.} = enum
    cluster, host, storagePod, datastore
type
  MigrationErrorEvent* = ref object of MigrationEvent
  
type
  ChoiceOption* = ref object of OptionType
    choiceInfo*: seq[ElementDescription]
    defaultIndex*: int

type
  VirtualMachineNamespaceManagerDataSpec* = ref object of DynamicData
    opCode*: VirtualMachineNamespaceManagerDataSpecOpCode
    key*: string
    value*: string
    oldValue*: string

type
  IpRouteProfile* = ref object of ApplyProfile
    staticRoute*: seq[StaticRouteProfile]

type
  VmDasBeingResetEventReasonCode* {.pure.} = enum
    vmtoolsHeartbeatFailure, appHeartbeatFailure, appImmediateResetRequest,
    vmcpResetApdCleared, guestOsCrashFailure
type
  UplinkPortVlanTrunkedEvent* = ref object of DvsHealthStatusChangeEvent
  
type
  NetIpStackInfoNetToMedia* = ref object of DynamicData
    ipAddress*: string
    physicalAddress*: string
    device*: string
    type*: string

type
  VmMaxFTRestartCountReached* = ref object of VmEvent
  
type
  GuestDiskInfo* = ref object of DynamicData
    diskPath*: string
    capacity*: int64
    freeSpace*: int64

type
  HostTpmAttestationReport* = ref object of DynamicData
    tpmPcrValues*: seq[HostTpmDigestInfo]
    tpmEvents*: seq[HostTpmEventLogEntry]
    tpmLogReliable*: bool

type
  BaseConfigInfo* = ref object of DynamicData
    id*: ID
    name*: string
    createTime*: string
    keepAfterDeleteVm*: bool
    relocationDisabled*: bool
    nativeSnapshotSupported*: bool
    changedBlockTrackingEnabled*: bool
    backing*: BaseConfigInfoBackingInfo
    iofilter*: seq[string]

type
  IpPoolManagerIpAllocation* = ref object of DynamicData
    ipAddress*: string
    allocationId*: string

type
  InvalidOperationOnSecondaryVm* = ref object of VmFaultToleranceIssue
    instanceUuid*: string

type
  AlarmFilterSpec* = ref object of DynamicData
    status*: seq[ManagedEntityStatus]
    typeEntity*: string
    typeTrigger*: string

type
  TooManyHosts* = ref object of HostConnectFault
  
type
  WakeOnLanNotSupported* = ref object of VirtualHardwareCompatibilityIssue
  
type
  HostUpgradeFailedEvent* = ref object of HostEvent
  
type
  VmInstanceUuidChangedEvent* = ref object of VmEvent
    oldInstanceUuid*: string
    newInstanceUuid*: string

type
  NetIpRouteConfigInfoGateway* = ref object of DynamicData
    ipAddress*: string
    device*: string

type
  DVPortgroupConfigInfo* = ref object of DynamicData
    key*: string
    name*: string
    numPorts*: int
    distributedVirtualSwitch*: DistributedVirtualSwitch
    defaultPortConfig*: DVPortSetting
    description*: string
    type*: string
    policy*: DVPortgroupPolicy
    portNameFormat*: string
    scope*: seq[ManagedEntity]
    vendorSpecificConfig*: seq[DistributedVirtualSwitchKeyedOpaqueBlob]
    configVersion*: string
    autoExpand*: bool
    vmVnicNetworkResourcePoolKey*: string
    uplink*: bool

type
  CannotDisconnectHostWithFaultToleranceVm* = ref object of VimFault
    hostName*: string

type
  VmMetadataInaccessibleFault* = ref object of VmMetadataManagerFault
  
type
  OvfImport* = ref object of OvfFault
  
type
  VirtualMachineProvisioningPolicyConfigPolicy* = ref object of DynamicData
    specPropPath*: string
    specPropPathRegex*: string
    capabilitySupportRequired*: seq[string]
    policy*: seq[VirtualMachineProvisioningPolicyPolicy]

type
  OvfPropertyQualifier* = ref object of OvfProperty
    qualifier*: string

type
  GhostDvsProxySwitchRemovedEvent* = ref object of HostEvent
    switchUuid*: seq[string]

type
  HostCertificateManagerCertificateInfo* = ref object of DynamicData
    issuer*: string
    notBefore*: string
    notAfter*: string
    subject*: string
    status*: string

type
  ClusterDpmHostConfigSpec* = ref object of ArrayUpdateSpec
    info*: ClusterDpmHostConfigInfo

type
  OvfConsumerOstResult* = ref object of OvfConsumerResult
    tree*: OvfConsumerOstNode

type
  IscsiStatus* = ref object of DynamicData
    reason*: seq[MethodFault]

type
  VmHealthMonitoringStateChangedEvent* = ref object of ClusterEvent
    state*: string
    prevState*: string

type
  PerfFormat* {.pure.} = enum
    normal, csv
type
  VAppTaskInProgress* = ref object of TaskInProgress
  
type
  VmotionInterfaceNotEnabled* = ref object of HostPowerOpFailed
  
type
  NoConnectedDatastore* = ref object of VimFault
  
type
  AlarmExpression* = ref object of DynamicData
  
type
  CannotAccessVmComponent* = ref object of VmConfigFault
  
type
  OvfNetworkMapping* = ref object of DynamicData
    name*: string
    network*: Network

type
  IoFilterQueryIssueResult* = ref object of DynamicData
    opType*: string
    hostIssue*: seq[IoFilterHostIssue]

type
  FaultsByHost* = ref object of DynamicData
    host*: HostSystem
    faults*: seq[MethodFault]

type
  HostPlugStoreTopologyAdapter* = ref object of DynamicData
    key*: string
    adapter*: HostHostBusAdapter
    path*: seq[HostPlugStoreTopologyPath]

type
  FaultsByVM* = ref object of DynamicData
    vm*: VirtualMachine
    faults*: seq[MethodFault]

type
  ExtManagedEntityInfo* = ref object of DynamicData
    type*: string
    smallIconUrl*: string
    iconUrl*: string
    description*: string

type
  SourceNodeSpec* = ref object of DynamicData
    managementVc*: ServiceLocator
    activeVc*: VirtualMachine

type
  IpHostnameGeneratorError* = ref object of CustomizationFault
  
type
  HostGraphicsConfigGraphicsType* {.pure.} = enum
    shared, sharedDirect
type
  DasAdmissionControlEnabledEvent* = ref object of ClusterEvent
  
type
  CustomizationStatelessIpV6Generator* = ref object of CustomizationIpV6Generator
  
type
  HostInternetScsiHbaStaticTargetTargetDiscoveryMethod* {.pure.} = enum
    staticMethod, sendTargetMethod, slpMethod, isnsMethod, unknownMethod
type
  InvalidController* = ref object of InvalidDeviceSpec
    controllerKey*: int

type
  VirtualPCIPassthroughPluginBackingInfo* = ref object of VirtualDeviceBackingInfo
  
type
  VirtualAppVAppState* {.pure.} = enum
    started, stopped, starting, stopping
type
  DistributedVirtualPortgroupInfo* = ref object of DynamicData
    switchName*: string
    switchUuid*: string
    portgroupName*: string
    portgroupKey*: string
    portgroupType*: string
    uplinkPortgroup*: bool
    portgroup*: DistributedVirtualPortgroup
    networkReservationSupported*: bool

type
  TeamingMisMatchEvent* = ref object of DvsHealthStatusChangeEvent
  
type
  ScsiLunDescriptor* = ref object of DynamicData
    quality*: string
    id*: string

type
  HostDasErrorEvent* = ref object of HostEvent
    message*: string
    reason*: string

type
  VirtualSerialPortThinPrintBackingInfo* = ref object of VirtualDeviceBackingInfo
  
type
  VirtualMachineCryptoState* {.pure.} = enum
    unlocked, locked
type
  VsanHostHealthState* {.pure.} = enum
    unknown, healthy, unhealthy
type
  DVPortConfigInfo* = ref object of DynamicData
    name*: string
    scope*: seq[ManagedEntity]
    description*: string
    setting*: DVPortSetting
    configVersion*: string

type
  GuestPosixFileAttributes* = ref object of GuestFileAttributes
    ownerId*: int
    groupId*: int
    permissions*: int64

type
  HostProtocolEndpointProtocolEndpointType* {.pure.} = enum
    scsi, nfs, nfs4x
type
  VmSecondaryDisabledBySystemEvent* = ref object of VmEvent
    reason*: MethodFault

type
  OvfExportFailed* = ref object of OvfExport
  
type
  VsanDiskFault* = ref object of VsanFault
    device*: string

type
  VmStartingSecondaryEvent* = ref object of VmEvent
  
type
  ClusterDpmHostConfigInfo* = ref object of DynamicData
    key*: HostSystem
    enabled*: bool
    behavior*: DpmBehavior

type
  ComplianceFailure* = ref object of DynamicData
    failureType*: string
    message*: LocalizableMessage
    expressionName*: string
    failureValues*: seq[ComplianceFailureComplianceFailureValues]

type
  VmConfigFileQueryFilter* = ref object of DynamicData
    matchConfigVersion*: seq[int]
    encrypted*: bool

type
  InvalidGuestLogin* = ref object of GuestOperationsFault
  
type
  DvsNotAuthorized* = ref object of DvsFault
    sessionExtensionKey*: string
    dvsExtensionKey*: string

type
  TemplateConfigFileQuery* = ref object of VmConfigFileQuery
  
type
  HostInventoryFull* = ref object of NotEnoughLicenses
    capacity*: int

type
  PlacementAction* = ref object of ClusterAction
    vm*: VirtualMachine
    targetHost*: HostSystem
    relocateSpec*: VirtualMachineRelocateSpec

type
  DataProviderResultSet* = ref object of DynamicData
    properties*: seq[string]
    items*: seq[DataProviderResourceItem]
    totalCount*: int64

type
  LegacyNetworkInterfaceInUse* = ref object of CannotAccessNetwork
  
type
  NetworkPolicyProfile* = ref object of ApplyProfile
  
type
  EVCAdmissionFailedHostDisconnected* = ref object of EVCAdmissionFailed
  
type
  MemorySizeNotSupported* = ref object of VirtualHardwareCompatibilityIssue
    memorySizeMB*: int
    minMemorySizeMB*: int
    maxMemorySizeMB*: int

type
  DiskIsUSB* = ref object of VsanDiskFault
  
type
  NetDnsConfigInfo* = ref object of DynamicData
    dhcp*: bool
    hostName*: string
    domainName*: string
    ipAddress*: seq[string]
    searchDomain*: seq[string]

type
  SingleIp* = ref object of IpAddress
    address*: string

type
  MultipleCertificatesVerifyFault* = ref object of HostConnectFault
    thumbprintData*: seq[MultipleCertificatesVerifyFaultThumbprintData]

type
  AutoStartAction* {.pure.} = enum
    none, systemDefault, powerOn, powerOff, guestShutdown, suspend
type
  AuthorizationEvent* = ref object of Event
  
type
  HostEventArgument* = ref object of EntityEventArgument
    host*: HostSystem

type
  NotSupportedHostForChecksum* = ref object of VimFault
  
type
  ClusterConfigSpecEx* = ref object of ComputeResourceConfigSpec
    dasConfig*: ClusterDasConfigInfo
    dasVmConfigSpec*: seq[ClusterDasVmConfigSpec]
    drsConfig*: ClusterDrsConfigInfo
    drsVmConfigSpec*: seq[ClusterDrsVmConfigSpec]
    rulesSpec*: seq[ClusterRuleSpec]
    orchestration*: ClusterOrchestrationInfo
    vmOrchestrationSpec*: seq[ClusterVmOrchestrationSpec]
    dpmConfig*: ClusterDpmConfigInfo
    dpmHostConfigSpec*: seq[ClusterDpmHostConfigSpec]
    vsanConfig*: VsanClusterConfigInfo
    vsanHostConfigSpec*: seq[VsanHostConfigInfo]
    groupSpec*: seq[ClusterGroupSpec]
    infraUpdateHaConfig*: ClusterInfraUpdateHaConfigInfo
    proactiveDrsConfig*: ClusterProactiveDrsConfigInfo

type
  LicenseExpiredEvent* = ref object of Event
    feature*: LicenseFeatureInfo

type
  TaskInfo* = ref object of DynamicData
    key*: string
    task*: Task
    description*: LocalizableMessage
    name*: string
    descriptionId*: string
    entity*: ManagedEntity
    entityName*: string
    locked*: seq[ManagedEntity]
    state*: TaskInfoState
    cancelled*: bool
    cancelable*: bool
    error*: MethodFault
    result*: pointer
    progress*: int
    reason*: TaskReason
    queueTime*: string
    startTime*: string
    completeTime*: string
    eventChainId*: int
    changeTag*: string
    parentTaskKey*: string
    rootTaskKey*: string
    activationId*: string

type
  DvsDestroyedEvent* = ref object of DvsEvent
  
type
  MonthlyTaskScheduler* = ref object of DailyTaskScheduler
  
type
  ExitStandbyModeFailedEvent* = ref object of HostEvent
  
type
  DVSSecurityPolicy* = ref object of InheritablePolicy
    allowPromiscuous*: BoolPolicy
    macChanges*: BoolPolicy
    forgedTransmits*: BoolPolicy

type
  AlarmSpec* = ref object of DynamicData
    name*: string
    systemName*: string
    description*: string
    enabled*: bool
    expression*: AlarmExpression
    action*: AlarmAction
    actionFrequency*: int
    setting*: AlarmSetting
    alarmMetadata*: string

type
  RecommendationType* {.pure.} = enum
    V1
type
  VmSuspendedEvent* = ref object of VmEvent
  
type
  InvalidKey* = ref object of VimFault
    key*: string

type
  HostDVSPortDeleteSpec* = ref object of DynamicData
    portKey*: string
    deletePortFile*: bool
    systemCleanup*: bool

type
  HostVirtualSwitchConfig* = ref object of DynamicData
    changeOperation*: string
    name*: string
    spec*: HostVirtualSwitchSpec

type
  Relation* = ref object of DynamicData
    constraint*: string
    name*: string
    version*: string

type
  IscsiFaultVnicNotBound* = ref object of IscsiFault
    vnicDevice*: string

type
  LastEventFilterSpec* = ref object of DynamicData
    entity*: seq[ManagedEntity]
    type*: seq[string]

type
  LicenseEntityAlreadyExists* = ref object of VimFault
    entityId*: string

type
  LinuxVolumeNotClean* = ref object of CustomizationFault
  
type
  CloneFromSnapshotNotSupported* = ref object of MigrationFault
  
type
  VsanHostClusterStatusStateCompletionEstimate* = ref object of DynamicData
    completeTime*: string
    percentComplete*: int

type
  RecoveryEvent* = ref object of DvsEvent
    hostName*: string
    portKey*: string
    dvsUuid*: string
    vnic*: string

type
  ResourceConfigOption* = ref object of DynamicData
    cpuAllocationOption*: ResourceAllocationOption
    memoryAllocationOption*: ResourceAllocationOption

type
  UnusedVirtualDiskBlocksNotScrubbed* = ref object of DeviceBackingNotSupported
  
type
  VirtualMachineDiskDeviceInfo* = ref object of VirtualMachineTargetInfo
    capacity*: int64
    vm*: seq[VirtualMachine]

type
  NumVirtualCpusNotSupported* = ref object of VirtualHardwareCompatibilityIssue
    maxSupportedVcpusDest*: int
    numCpuVm*: int

type
  VmAcquiredMksTicketEvent* = ref object of VmEvent
  
type
  DatastoreDuplicatedEvent* = ref object of DatastoreEvent
  
type
  DistributedVirtualSwitchManagerCompatibilityResult* = ref object of DynamicData
    host*: HostSystem
    error*: seq[MethodFault]

type
  UserUpgradeEvent* = ref object of UpgradeEvent
  
type
  VirtualPointingDeviceDeviceBackingInfo* = ref object of VirtualDeviceDeviceBackingInfo
    hostPointingDevice*: string

type
  IncorrectHostInformationEvent* = ref object of LicenseEvent
  
type
  PolicyUrnInvalid* = ref object of VimFault
    urn*: string

type
  MemoryFileFormatNotSupportedByDatastore* = ref object of UnsupportedDatastore
    datastoreName*: string
    type*: string

type
  VirtualE1000* = ref object of VirtualEthernetCard
  
type
  PerfSampleInfo* = ref object of DynamicData
    timestamp*: string
    interval*: int

type
  ClusterDasConfigInfoServiceState* {.pure.} = enum
    disabled, enabled
type
  MessageBusProxyConfigSpec* = ref object of DynamicData
    brokerURI*: seq[string]

type
  ClusterOvercommittedEvent* = ref object of ClusterEvent
  
type
  TaskReasonUser* = ref object of TaskReason
    userName*: string

type
  DVSHealthCheckConfig* = ref object of DynamicData
    enable*: bool
    interval*: int

type
  DvsCopyNetworkRuleAction* = ref object of DvsNetworkRuleAction
  
type
  CannotDisableSnapshot* = ref object of VmConfigFault
  
type
  DisconnectedHostsBlockingEVC* = ref object of EVCConfigFault
  
type
  PerfCounterInfoInt* = ref object of PerfCounterInfo
    enabledByDefault*: bool
    enabled*: bool

type
  HostDiskDimensionsChs* = ref object of DynamicData
    cylinder*: int64
    head*: int
    sector*: int

type
  ClusterDrsRecommendation* = ref object of DynamicData
    key*: string
    rating*: int
    reason*: string
    reasonText*: string
    migrationList*: seq[ClusterDrsMigration]

type
  ReplicationVmConfigFaultReasonForFault* {.pure.} = enum
    incompatibleHwVersion, invalidVmReplicationId, invalidGenerationNumber,
    outOfBoundsRpoValue, invalidDestinationIpAddress, invalidDestinationPort,
    invalidExtraVmOptions, staleGenerationNumber,
    reconfigureVmReplicationIdNotAllowed,
    cannotRetrieveVmReplicationConfiguration, replicationAlreadyEnabled,
    invalidPriorConfiguration, replicationNotEnabled,
    replicationConfigurationFailed, encryptedVm, invalidThumbprint,
    incompatibleDevice
type
  HostDiskBlockInfo* = ref object of DynamicData
    size*: int64
    granularity*: int64
    minBlockSize*: int
    provisionBlockSize*: int
    mapStart*: int64
    mapLength*: int64
    map*: seq[HostDiskBlockInfoMapping]

type
  VirtualMachineConfigInfo* = ref object of DynamicData
    changeVersion*: string
    modified*: string
    name*: string
    guestFullName*: string
    version*: string
    uuid*: string
    createDate*: string
    instanceUuid*: string
    npivNodeWorldWideName*: seq[int64]
    npivPortWorldWideName*: seq[int64]
    npivWorldWideNameType*: string
    npivDesiredNodeWwns*: int16
    npivDesiredPortWwns*: int16
    npivTemporaryDisabled*: bool
    npivOnNonRdmDisks*: bool
    locationId*: string
    template*: bool
    guestId*: string
    alternateGuestName*: string
    annotation*: string
    files*: VirtualMachineFileInfo
    tools*: ToolsConfigInfo
    flags*: VirtualMachineFlagInfo
    consolePreferences*: VirtualMachineConsolePreferences
    defaultPowerOps*: VirtualMachineDefaultPowerOpInfo
    hardware*: VirtualHardware
    cpuAllocation*: ResourceAllocationInfo
    memoryAllocation*: ResourceAllocationInfo
    latencySensitivity*: LatencySensitivity
    memoryHotAddEnabled*: bool
    cpuHotAddEnabled*: bool
    cpuHotRemoveEnabled*: bool
    hotPlugMemoryLimit*: int64
    hotPlugMemoryIncrementSize*: int64
    cpuAffinity*: VirtualMachineAffinityInfo
    memoryAffinity*: VirtualMachineAffinityInfo
    networkShaper*: VirtualMachineNetworkShaperInfo
    extraConfig*: seq[OptionValue]
    cpuFeatureMask*: seq[HostCpuIdInfo]
    datastoreUrl*: seq[VirtualMachineConfigInfoDatastoreUrlPair]
    swapPlacement*: string
    bootOptions*: VirtualMachineBootOptions
    ftInfo*: FaultToleranceConfigInfo
    repConfig*: ReplicationConfigSpec
    vAppConfig*: VmConfigInfo
    vAssertsEnabled*: bool
    changeTrackingEnabled*: bool
    firmware*: string
    maxMksConnections*: int
    guestAutoLockEnabled*: bool
    managedBy*: ManagedByInfo
    memoryReservationLockedToMax*: bool
    initialOverhead*: VirtualMachineConfigInfoOverheadInfo
    nestedHVEnabled*: bool
    vPMCEnabled*: bool
    scheduledHardwareUpgradeInfo*: ScheduledHardwareUpgradeInfo
    forkConfigInfo*: VirtualMachineForkConfigInfo
    vFlashCacheReservation*: int64
    vmxConfigChecksum*: byte
    messageBusTunnelEnabled*: bool
    vmStorageObjectId*: string
    swapStorageObjectId*: string
    keyId*: CryptoKeyId
    guestIntegrityInfo*: VirtualMachineGuestIntegrityInfo
    migrateEncryption*: string

type
  VirtualMachineMetadataManagerVmMetadataOwner* = ref object of DynamicData
    name*: string

type
  VirtualDiskSparseVer1BackingInfo* = ref object of VirtualDeviceFileBackingInfo
    diskMode*: string
    split*: bool
    writeThrough*: bool
    spaceUsedInKB*: int64
    contentId*: string
    parent*: VirtualDiskSparseVer1BackingInfo

type
  VsanHostFaultDomainInfo* = ref object of DynamicData
    name*: string

type
  DistributedVirtualSwitchInfo* = ref object of DynamicData
    switchName*: string
    switchUuid*: string
    distributedVirtualSwitch*: DistributedVirtualSwitch
    networkReservationSupported*: bool

type
  BaseConfigInfoRawDiskMappingBackingInfo* = ref object of BaseConfigInfoFileBackingInfo
    lunUuid*: string
    compatibilityMode*: string

type
  AntiAffinityGroup* = ref object of vim.ManagedEntity
  
type
  NotSupportedDeviceForFT* = ref object of VmFaultToleranceIssue
    host*: HostSystem
    hostName*: string
    vm*: VirtualMachine
    vmName*: string
    deviceType*: string
    deviceLabel*: string

type
  DVSMacLimitPolicyType* {.pure.} = enum
    allow, drop
type
  Timedout* = ref object of VimFault
  
type
  HostProfileManagerConfigTaskList* = ref object of DynamicData
    configSpec*: HostConfigSpec
    taskDescription*: seq[LocalizableMessage]
    taskListRequirement*: seq[string]

type
  ServiceInstance* = ref object of vmodl.ManagedObject
    serverClock*: string
    capability*: Capability
    content*: ServiceContent

type
  RoleAddedEvent* = ref object of RoleEvent
    privilegeList*: seq[string]

type
  DVPortgroupReconfiguredEvent* = ref object of DVPortgroupEvent
    configSpec*: DVPortgroupConfigSpec
    configChanges*: ChangesInfoEventArgument

type
  RebootRequired* = ref object of VimFault
    patch*: string

type
  VirtualMachineBootOptionsNetworkBootProtocolType* {.pure.} = enum
    ipv4, ipv6
type
  DVPortSelection* = ref object of SelectionSet
    dvsUuid*: string
    portKey*: seq[string]

type
  VirtualVMIROMOption* = ref object of VirtualDeviceOption
  
type
  DVSNetworkResourcePool* = ref object of DynamicData
    key*: string
    name*: string
    description*: string
    configVersion*: string
    allocationInfo*: DVSNetworkResourcePoolAllocationInfo

type
  VmInstanceUuidConflictEvent* = ref object of VmEvent
    conflictedVm*: VmEventArgument
    instanceUuid*: string

type
  ServiceProtocol* {.pure.} = enum
    vimApi, vimWebServices, viImageLibrary, unknown
type
  HostCpuInfo* = ref object of DynamicData
    numCpuPackages*: int16
    numCpuCores*: int16
    numCpuThreads*: int16
    hz*: int64

type
  HostProfileMappingData* = ref object of DynamicData
    basePath*: string
    attributePath*: string
    condition*: HostProfileAttributeCondition
    lookup*: HostProfileMappingLookup

type
  HostCnxFailedCcagentUpgradeEvent* = ref object of HostEvent
  
type
  ExpiredFeatureLicense* = ref object of NotEnoughLicenses
    feature*: string
    count*: int
    expirationDate*: string

type
  NvdimmNamespaceInfo* = ref object of DynamicData
    uuid*: string
    friendlyName*: string
    blockSize*: int64
    blockCount*: int64
    type*: string
    namespaceHealthStatus*: string
    locationID*: int
    state*: string

type
  InsufficientCpuResourcesFault* = ref object of InsufficientResourcesFault
    unreserved*: int64
    requested*: int64

type
  DvsEvent* = ref object of Event
  
type
  EntityAndComplianceStatus* = ref object of DynamicData
    entity*: ManagedEntity
    complianceStatus*: string

type
  HttpNfcLeaseMode* {.pure.} = enum
    pushOrGet, pull
type
  ApplyStorageRecommendationResult* = ref object of DynamicData
    vm*: VirtualMachine

type
  OptionType* = ref object of DynamicData
    valueIsReadonly*: bool

type
  HostCompliantEvent* = ref object of HostEvent
  
type
  HostVirtualNicIpRouteSpec* = ref object of DynamicData
    ipRouteConfig*: HostIpRouteConfig

type
  MissingPowerOffConfiguration* = ref object of VAppConfigFault
  
type
  RecommendationReasonCode* {.pure.} = enum
    fairnessCpuAvg, fairnessMemAvg, jointAffin, antiAffin, hostMaint, enterStandby,
    reservationCpu, reservationMem, powerOnVm, powerSaving, increaseCapacity,
    checkResource, unreservedCapacity, colocateCommunicatingVM,
    balanceNetworkBandwidthUsage, vmHostHardAffinity, vmHostSoftAffinity,
    increaseAllocation, balanceDatastoreSpaceUsage, balanceDatastoreIOLoad,
    balanceDatastoreIOPSReservation, datastoreMaint, virtualDiskJointAffin,
    virtualDiskAntiAffin, datastoreSpaceOutage, storagePlacement,
    iolbDisabledInternal, xvmotionPlacement, networkBandwidthReservation,
    hostInDegradation, hostExitDegradation, maxVmsConstraint, ftConstraints
type
  IscsiFaultInvalidVnic* = ref object of IscsiFault
    vnicDevice*: string

type
  ClusterRecommendation* = ref object of DynamicData
    key*: string
    type*: string
    time*: string
    rating*: int
    reason*: string
    reasonText*: string
    warningText*: string
    warningDetails*: LocalizableMessage
    prerequisite*: seq[string]
    action*: seq[ClusterAction]
    target*: ManagedObject

type
  DvsVmVnicResourcePoolConfigSpec* = ref object of DynamicData
    operation*: string
    key*: string
    configVersion*: string
    allocationInfo*: DvsVmVnicResourceAllocation
    name*: string
    description*: string

type
  InvalidNasCredentials* = ref object of NasConfigFault
    userName*: string

type
  StorageDrsIolbDisabledInternally* = ref object of VimFault
  
type
  HostSystemSwapConfigurationHostCacheOption* = ref object of HostSystemSwapConfigurationSystemSwapOption
  
type
  ComputeResourceConfigInfo* = ref object of DynamicData
    vmSwapPlacement*: string
    spbmEnabled*: bool
    defaultHardwareVersionKey*: string

type
  ExtensibleManagedObject* = ref object of vmodl.ManagedObject
    value*: seq[CustomFieldValue]
    availableField*: seq[CustomFieldDef]

type
  AlarmScriptCompleteEvent* = ref object of AlarmEvent
    entity*: ManagedEntityEventArgument
    script*: string

type
  HostDatastoreSystem* = ref object of vmodl.ManagedObject
    datastore*: seq[Datastore]
    capabilities*: HostDatastoreSystemCapabilities

type
  DistributedVirtualPortgroupPortgroupType* {.pure.} = enum
    earlyBinding, lateBinding, ephemeral
type
  OvfCreateDescriptorParams* = ref object of DynamicData
    ovfFiles*: seq[OvfFile]
    name*: string
    description*: string
    includeImageFiles*: bool
    exportOption*: seq[string]
    snapshot*: VirtualMachineSnapshot

type
  ClusterHostInfraUpdateHaModeAction* = ref object of ClusterAction
    operationType*: string

type
  HostVMotionManagerVMotionNVDIMMSpec* = ref object of HostVMotionManagerVMotionDeviceSpec
    deviceNumber*: int
    filename*: string
    parentFilename*: string

type
  SecondaryVmNotRegistered* = ref object of VmFaultToleranceIssue
    instanceUuid*: string

type
  VAppOperationInProgress* = ref object of RuntimeFault
  
type
  UnconfiguredPropertyValue* = ref object of InvalidPropertyValue
  
type
  IoFilterType* {.pure.} = enum
    cache, replication, encryption, compression, inspection, datastoreIoControl,
    dataProvider
type
  HostNumericSensorInfo* = ref object of DynamicData
    name*: string
    healthState*: ElementDescription
    currentReading*: int64
    unitModifier*: int
    baseUnits*: string
    rateUnits*: string
    sensorType*: string
    id*: string
    timeStamp*: string

type
  CustomizationLinuxOptions* = ref object of CustomizationOptions
  
type
  InsufficientResourcesFault* = ref object of VimFault
  
type
  HostVirtualNicConnection* = ref object of DynamicData
    portgroup*: string
    dvPort*: DistributedVirtualSwitchPortConnection
    opNetwork*: HostVirtualNicOpaqueNetworkSpec

type
  VirtualE1000e* = ref object of VirtualEthernetCard
  
type
  ResourcePoolQuickStats* = ref object of DynamicData
    overallCpuUsage*: int64
    overallCpuDemand*: int64
    guestMemoryUsage*: int64
    hostMemoryUsage*: int64
    distributedCpuEntitlement*: int64
    distributedMemoryEntitlement*: int64
    staticCpuEntitlement*: int
    staticMemoryEntitlement*: int
    privateMemory*: int64
    sharedMemory*: int64
    swappedMemory*: int64
    balloonedMemory*: int64
    overheadMemory*: int64
    consumedOverheadMemory*: int64
    compressedMemory*: int64

type
  StorageDrsDisabledOnVm* = ref object of VimFault
  
type
  CDCInventoryChange* = ref object of DynamicData
    kind*: string
    object*: ManagedObject
    properties*: seq[string]

type
  HostVsanInternalSystemVsanPhysicalDiskDiagnosticsResult* = ref object of DynamicData
    diskUuid*: string
    success*: bool
    failureReason*: string

type
  StorageDrsStaleHmsCollection* = ref object of VimFault
  
type
  OvfFile* = ref object of DynamicData
    deviceId*: string
    path*: string
    compressionMethod*: string
    chunkSize*: int64
    size*: int64
    capacity*: int64
    populatedSize*: int64

type
  RetrieveCustomizationsResult* = ref object of StructuredCustomizations
    fault*: MethodFault

type
  AlarmAction* = ref object of DynamicData
  
type
  HostExtraNetworksEvent* = ref object of HostDasEvent
    ips*: string

type
  NetIpConfigInfoIpAddressStatus* {.pure.} = enum
    preferred, deprecated, invalid, inaccessible, unknown, tentative, duplicate
type
  DrsDatastoreCorrelation* = ref object of DynamicData
    datastore*: Datastore
    state*: DrsInjectorWorkloadCorrelationState

type
  HostInternetScsiTargetTransport* = ref object of HostTargetTransport
    iScsiName*: string
    iScsiAlias*: string
    address*: seq[string]

type
  VirtualDisk* = ref object of VirtualDevice
    capacityInKB*: int64
    capacityInBytes*: int64
    shares*: SharesInfo
    storageIOAllocation*: StorageIOAllocationInfo
    diskObjectId*: string
    vFlashCacheConfigInfo*: VirtualDiskVFlashCacheConfigInfo
    iofilter*: seq[string]
    vDiskId*: ID
    nativeUnmanagedLinkedClone*: bool

type
  DvsFilterPolicy* = ref object of InheritablePolicy
    filterConfig*: seq[DvsFilterConfig]

type
  StorageDrsCannotMoveVmInUserFolder* = ref object of VimFault
  
type
  NetIpConfigInfoIpAddressOrigin* {.pure.} = enum
    other, manual, dhcp, linklayer, random
type
  VsanHostDecommissionModeObjectAction* {.pure.} = enum
    noAction, ensureObjectAccessibility, evacuateAllData
type
  OvfUnsupportedSection* = ref object of OvfUnsupportedElement
    info*: string

type
  GuestRegistryValueNotFound* = ref object of GuestRegistryValueFault
  
type
  AnswerFileSerializedCreateSpec* = ref object of AnswerFileCreateSpec
    answerFileConfigString*: string

type
  NvdimmRegionInfo* = ref object of DynamicData
    regionId*: int
    setId*: int
    rangeType*: string
    startAddr*: int64
    size*: int64
    offset*: int64

type
  VAppProductInfo* = ref object of DynamicData
    key*: int
    classId*: string
    instanceId*: string
    name*: string
    vendor*: string
    version*: string
    fullVersion*: string
    vendorUrl*: string
    productUrl*: string
    appUrl*: string

type
  PasswordField* = ref object of DynamicData
    value*: string

type
  VsanHostConfigInfoNetworkInfoPortConfig* = ref object of DynamicData
    ipConfig*: VsanHostIpConfig
    device*: string

type
  VirtualCdromPassthroughBackingInfo* = ref object of VirtualDeviceDeviceBackingInfo
    exclusive*: bool
    description*: string

type
  ClusterFailoverHostAdmissionControlPolicy* = ref object of ClusterDasAdmissionControlPolicy
    failoverHosts*: seq[HostSystem]
    failoverLevel*: int

type
  VirtualSwitchProfile* = ref object of ApplyProfile
    key*: string
    name*: string
    link*: LinkProfile
    numPorts*: NumPortsProfile
    networkPolicy*: NetworkPolicyProfile

type
  VAppConfigSpec* = ref object of VmConfigSpec
    entityConfig*: seq[VAppEntityConfigInfo]
    annotation*: string
    instanceUuid*: string
    managedBy*: ManagedByInfo

type
  VsanUpgradeSystemPreflightCheckResult* = ref object of DynamicData
    issues*: seq[VsanUpgradeSystemPreflightCheckIssue]
    diskMappingToRestore*: VsanHostDiskMapping

type
  StorageDrsCannotMoveSharedDisk* = ref object of VimFault
  
type
  DVSOpaqueConfigInfo* = ref object of DynamicData
    selection*: SelectionSet
    opaqueData*: seq[DVSOpaqueData]

type
  VirtualMachineGuestOsFamily* {.pure.} = enum
    windowsGuest, linuxGuest, netwareGuest, solarisGuest, darwinGuestFamily,
    otherGuestFamily
type
  DrsExitedStandbyModeEvent* = ref object of ExitedStandbyModeEvent
  
type
  HostLocalAuthenticationInfo* = ref object of HostAuthenticationStoreInfo
  
type
  VmwareDistributedVirtualSwitchVlanSpec* = ref object of InheritablePolicy
  
type
  HostDiskManagerLeaseInfo* = ref object of DynamicData
    lease*: HostDiskManagerLease
    ddbOption*: seq[OptionValue]
    blockInfo*: HostDiskBlockInfo
    leaseTimeout*: int

type
  DvsSingleIpPort* = ref object of DvsIpPort
    portNumber*: int

type
  VmfsAlreadyMounted* = ref object of VmfsMountFault
  
type
  CDCChangeLogCollector* = ref object of vmodl.ManagedObject
  
type
  CannotAddHostWithFTVmToNonHACluster* = ref object of HostConnectFault
  
type
  DvsPuntNetworkRuleAction* = ref object of DvsNetworkRuleAction
  
type
  PolicyOption* = ref object of DynamicData
    id*: string
    parameter*: seq[KeyAnyValue]

type
  ResourcePoolEventArgument* = ref object of EntityEventArgument
    resourcePool*: ResourcePool

type
  VirtualMachineConfigInfoDatastoreUrlPair* = ref object of DynamicData
    name*: string
    url*: string

type
  VirtualDeviceConfigSpecBackingSpec* = ref object of DynamicData
    parent*: VirtualDeviceConfigSpecBackingSpec
    crypto*: CryptoSpec

type
  DvsApplyOperationFaultFaultOnObject* = ref object of DynamicData
    objectId*: string
    type*: string
    fault*: MethodFault

type
  PhysicalNicSpec* = ref object of DynamicData
    ip*: HostIpConfig
    linkSpeed*: PhysicalNicLinkInfo
    enableEnhancedNetworkingStack*: bool

type
  ProfileDeferredPolicyOptionParameter* = ref object of DynamicData
    inputPath*: ProfilePropertyPath
    parameter*: seq[KeyAnyValue]

type
  WorkflowStepHandlerResult* = ref object of DynamicData
    data*: seq[KeyAnyValue]
    fault*: MethodFault

type
  ProfileDescriptionSection* = ref object of DynamicData
    description*: ExtendedElementDescription
    message*: seq[LocalizableMessage]

type
  VirtualMachineMessage* = ref object of DynamicData
    id*: string
    argument*: seq[pointer]
    text*: string

type
  UnsupportedVimApiVersion* = ref object of VimFault
    version*: string

type
  HostFirewallConfig* = ref object of DynamicData
    rule*: seq[HostFirewallConfigRuleSetConfig]
    defaultBlockingPolicy*: HostFirewallDefaultPolicy

type
  VirtualSCSIControllerOption* = ref object of VirtualControllerOption
    numSCSIDisks*: IntOption
    numSCSICdroms*: IntOption
    numSCSIPassthrough*: IntOption
    sharing*: seq[VirtualSCSISharing]
    defaultSharedIndex*: int
    hotAddRemove*: BoolOption
    scsiCtlrUnitNumber*: int

type
  VmPoweredOnEvent* = ref object of VmEvent
  
type
  VAppIPAssignmentInfoAllocationSchemes* {.pure.} = enum
    dhcp, ovfenv
type
  VmOrphanedEvent* = ref object of VmEvent
  
type
  PermissionUpdatedEvent* = ref object of PermissionEvent
    role*: RoleEventArgument
    propagate*: bool
    prevRole*: RoleEventArgument
    prevPropagate*: bool

type
  VchaClusterState* {.pure.} = enum
    healthy, degraded, isolated
type
  HostDateTimeConfig* = ref object of DynamicData
    timeZone*: string
    ntpConfig*: HostNtpConfig

type
  VirtualVmxnet3Vrdma* = ref object of VirtualVmxnet3
    deviceProtocol*: string

type
  TemplateUpgradedEvent* = ref object of TemplateUpgradeEvent
  
type
  VirtualMachineVMCIDeviceOption* = ref object of VirtualDeviceOption
    allowUnrestrictedCommunication*: BoolOption
    filterSpecOption*: VirtualMachineVMCIDeviceOptionFilterSpecOption
    filterSupported*: BoolOption

type
  EVCAdmissionFailed* = ref object of NotSupportedHostInCluster
    faults*: seq[MethodFault]

type
  GeneralVmInfoEvent* = ref object of GeneralEvent
  
type
  HostDVSPortResetSpec* = ref object of DynamicData
    portKey*: string
    resetStats*: bool

type
  ExitedStandbyModeEvent* = ref object of HostEvent
  
type
  HostNetworkInfo* = ref object of DynamicData
    vswitch*: seq[HostVirtualSwitch]
    proxySwitch*: seq[HostProxySwitch]
    portgroup*: seq[HostPortGroup]
    pnic*: seq[PhysicalNic]
    vnic*: seq[HostVirtualNic]
    consoleVnic*: seq[HostVirtualNic]
    dnsConfig*: HostDnsConfig
    ipRouteConfig*: HostIpRouteConfig
    consoleIpRouteConfig*: HostIpRouteConfig
    routeTableInfo*: HostIpRouteTableInfo
    dhcp*: seq[HostDhcpService]
    nat*: seq[HostNatService]
    ipV6Enabled*: bool
    atBootIpV6Enabled*: bool
    netStackInstance*: seq[HostNetStackInstance]
    opaqueSwitch*: seq[HostOpaqueSwitch]
    opaqueNetwork*: seq[HostOpaqueNetworkInfo]

type
  StorageResourceManagerStorageProfileStatistics* = ref object of DynamicData
    profileId*: string
    totalSpaceMB*: int64
    usedSpaceMB*: int64

type
  InsufficientFailoverResourcesEvent* = ref object of ClusterEvent
  
type
  DVSNetworkResourcePoolConfigSpec* = ref object of DynamicData
    key*: string
    configVersion*: string
    allocationInfo*: DVSNetworkResourcePoolAllocationInfo
    name*: string
    description*: string

type
  PhysicalNicCdpInfo* = ref object of DynamicData
    cdpVersion*: int
    timeout*: int
    ttl*: int
    samples*: int
    devId*: string
    address*: string
    portId*: string
    deviceCapability*: PhysicalNicCdpDeviceCapability
    softwareVersion*: string
    hardwarePlatform*: string
    ipPrefix*: string
    ipPrefixLen*: int
    vlan*: int
    fullDuplex*: bool
    mtu*: int
    systemName*: string
    systemOID*: string
    mgmtAddr*: string
    location*: string

type
  VirtualMachineVMCIDeviceFilterSpec* = ref object of DynamicData
    rank*: int64
    action*: string
    protocol*: string
    direction*: string
    lowerDstPortBoundary*: int64
    upperDstPortBoundary*: int64

type
  DayOfWeek* {.pure.} = enum
    sunday, monday, tuesday, wednesday, thursday, friday, saturday
type
  InvalidResourcePoolStructureFault* = ref object of InsufficientResourcesFault
  
type
  ToolsImageSignatureCheckFailed* = ref object of VmToolsUpgradeFault
  
type
  AnswerFileValidationInfo* = ref object of DynamicData
    status*: string
    result*: ProfileExecuteResult

type
  PolicyViolatedValueNotInSet* = ref object of PolicyViolatedByValue
    policyValue*: seq[pointer]

type
  HostProfileMappingLookup* = ref object of DynamicData
    baseProfilePath*: string
    apiMapping*: seq[HostProfileMappingLookupMappingPair]
    profileMapping*: seq[HostProfileMappingLookupMappingPair]

type
  CustomizationIpV6Generator* = ref object of DynamicData
  
type
  SnapshotMoveToNonHomeNotSupported* = ref object of SnapshotCopyNotSupported
  
type
  CpuHotPlugNotSupported* = ref object of VmConfigFault
  
type
  HostVmciAccessManager* = ref object of vmodl.ManagedObject
  
type
  FloppyImageFileQuery* = ref object of FileQuery
  
type
  HostFirewallConfigRuleSetConfig* = ref object of DynamicData
    rulesetId*: string
    enabled*: bool
    allowedHosts*: HostFirewallRulesetIpList

type
  VirtualMachineFlagInfoVirtualExecUsage* {.pure.} = enum
    hvAuto, hvOn, hvOff
type
  VFlashModuleNotSupportedReason* {.pure.} = enum
    CacheModeNotSupported, CacheConsistencyTypeNotSupported,
    CacheBlockSizeNotSupported, CacheReservationNotSupported, DiskSizeNotSupported
type
  InvalidFormat* = ref object of VmConfigFault
  
type
  VirtualDiskRawDiskMappingVer1BackingInfo* = ref object of VirtualDeviceFileBackingInfo
    lunUuid*: string
    deviceName*: string
    compatibilityMode*: string
    diskMode*: string
    uuid*: string
    contentId*: string
    changeId*: string
    parent*: VirtualDiskRawDiskMappingVer1BackingInfo
    deltaDiskFormat*: string
    deltaGrainSize*: int
    sharing*: string

type
  DistributedVirtualSwitchProductSpecOperationType* {.pure.} = enum
    preInstall, upgrade, notifyAvailableUpgrade, proceedWithUpgrade,
    updateBundleInfo
type
  VsanHostRuntimeInfo* = ref object of DynamicData
    membershipList*: seq[VsanHostMembershipInfo]
    diskIssues*: seq[VsanHostRuntimeInfoDiskIssue]
    accessGenNo*: int

type
  LicenseManagerLicenseKey* {.pure.} = enum
    esxFull, esxVmtn, esxExpress, san, iscsi, nas, vsmp, backup, vc, vcExpress, esxHost,
    gsxHost, serverHost, drsPower, vmotion, drs, das
type
  HostSystemPowerState* {.pure.} = enum
    poweredOn, poweredOff, standBy, unknown
type
  DatastoreDestroyedEvent* = ref object of DatastoreEvent
  
type
  AnswerFileStatusError* = ref object of DynamicData
    userInputPath*: ProfilePropertyPath
    errMsg*: LocalizableMessage

type
  GuestAliases* = ref object of DynamicData
    base64Cert*: string
    aliases*: seq[GuestAuthAliasInfo]

type
  SnapshotIncompatibleDeviceInVm* = ref object of SnapshotFault
    fault*: MethodFault

type
  DvsIpNetworkRuleQualifier* = ref object of DvsNetworkRuleQualifier
    sourceAddress*: IpAddress
    destinationAddress*: IpAddress
    protocol*: IntExpression
    sourceIpPort*: DvsIpPort
    destinationIpPort*: DvsIpPort
    tcpFlags*: IntExpression

type
  EventEventSeverity* {.pure.} = enum
    error, warning, info, user
type
  ProfileMetadata* = ref object of DynamicData
    key*: string
    profileTypeName*: string
    description*: ExtendedDescription
    sortSpec*: seq[ProfileMetadataProfileSortSpec]
    profileCategory*: string
    profileComponent*: string
    operationMessages*: seq[ProfileMetadataProfileOperationMessage]

type
  SoftRuleVioCorrectionImpact* = ref object of VmConfigFault
    vmName*: string

type
  WakeOnLanNotSupportedByVmotionNIC* = ref object of HostPowerOpFailed
  
type
  UpgradeEvent* = ref object of Event
    message*: string

type
  VirtualCdromAtapiBackingInfo* = ref object of VirtualDeviceDeviceBackingInfo
    description*: string

type
  GuestMappedAliases* = ref object of DynamicData
    base64Cert*: string
    username*: string
    subjects*: seq[GuestAuthSubject]

type
  DiskMoveTypeNotSupported* = ref object of MigrationFault
  
type
  InaccessibleFTMetadataDatastore* = ref object of InaccessibleDatastore
  
type
  OvfHostResourceConstraint* = ref object of OvfConstraint
    value*: string

type
  ClusterComputeResourceDrmDumpInfo* = ref object of DynamicData
    totalNumberOfDumpFiles*: int
    latestDumpFileTimestamp*: string
    earliestDumpFileTimestamp*: string

type
  CustomizationUnknownIpGenerator* = ref object of CustomizationIpGenerator
  
type
  VmVnicPoolReservationViolationClearEvent* = ref object of DvsEvent
    vmVnicResourcePoolKey*: string
    vmVnicResourcePoolName*: string

type
  HostRuntimeInfo* = ref object of DynamicData
    connectionState*: HostSystemConnectionState
    powerState*: HostSystemPowerState
    standbyMode*: string
    inMaintenanceMode*: bool
    inQuarantineMode*: bool
    bootTime*: string
    healthSystemRuntime*: HealthSystemRuntime
    dasHostState*: ClusterDasFdmHostState
    tpmPcrValues*: seq[HostTpmDigestInfo]
    cpuCapacityForVm*: int64
    memoryCapacityForVm*: int64
    vsanRuntimeInfo*: VsanHostRuntimeInfo
    networkRuntimeInfo*: HostRuntimeInfoNetworkRuntimeInfo
    vFlashResourceRuntimeInfo*: HostVFlashManagerVFlashResourceRunTimeInfo
    hostMaxVirtualDiskCapacity*: int64
    cryptoState*: string
    cryptoKeyId*: CryptoKeyId

type
  DatastoreEvent* = ref object of Event
    datastore*: DatastoreEventArgument

type
  HostEvent* = ref object of Event
  
type
  HostLoadEsxManagerInfo* = ref object of DynamicData
    loadEsxEnabled*: bool
    loadEsxBoot*: bool

type
  MigrationHostWarningEvent* = ref object of MigrationEvent
    dstHost*: HostEventArgument

type
  CryptoManagerHostKMS* = ref object of vim.encryption.CryptoManagerHost
  
type
  VMwareDVSVspanSessionType* {.pure.} = enum
    mixedDestMirror, dvPortMirror, remoteMirrorSource, remoteMirrorDest,
    encapsulatedRemoteMirrorSource
type
  NoMaintenanceModeDrsRecommendationForVM* = ref object of VmEvent
  
type
  HostCpuSchedulerSystem* = ref object of vim.ExtensibleManagedObject
    hyperthreadInfo*: HostHyperThreadScheduleInfo

type
  GuestAuthManager* = ref object of vmodl.ManagedObject
  
type
  OvfConsumerUndefinedPrefix* = ref object of OvfConsumerCallbackFault
    prefix*: string

type
  VMwareDVSPvlanConfigSpec* = ref object of DynamicData
    pvlanEntry*: VMwareDVSPvlanMapEntry
    operation*: string

type
  DataProviderQuerySpec* = ref object of DynamicData
    properties*: seq[string]
    resourceModel*: string
    filter*: DataProviderFilter
    sortCriteria*: seq[DataProviderSortCriterion]
    offset*: int
    limit*: int
    returnTotalCount*: bool

type
  HostOpaqueNetworkData* = ref object of DynamicData
    id*: string
    name*: string
    type*: string
    portAttachMode*: string
    pnicZone*: seq[string]
    extraConfig*: seq[OptionValue]

type
  HostProfileConfigInfo* = ref object of ProfileConfigInfo
    applyProfile*: HostApplyProfile
    defaultComplyProfile*: ComplianceProfile
    defaultComplyLocator*: seq[ComplianceLocator]
    customComplyProfile*: ComplianceProfile
    disabledExpressionList*: seq[string]
    description*: ProfileDescription

type
  HostDiagnosticPartitionCreateOption* = ref object of DynamicData
    storageType*: string
    diagnosticType*: string
    disk*: HostScsiDisk

type
  IncompatibleHostForVmReplicationIncompatibleReason* {.pure.} = enum
    rpo, netCompression
type
  HostVMotionManager* = ref object of vmodl.ManagedObject
  
type
  HostStorageSystemVmfsVolumeResult* = ref object of DynamicData
    key*: string
    fault*: MethodFault

type
  VirtualMachineMetadataManager* = ref object of vmodl.ManagedObject
  
type
  NotSupportedHostInDvs* = ref object of NotSupportedHost
    switchProductSpec*: DistributedVirtualSwitchProductSpec

type
  TooManyTickets* = ref object of VimFault
  
type
  CryptoKeyId* = ref object of DynamicData
    keyId*: string
    providerId*: KeyProviderId

type
  ScheduledTaskReconfiguredEvent* = ref object of ScheduledTaskEvent
    configChanges*: ChangesInfoEventArgument

type
  ProfileCompositeExpression* = ref object of ProfileExpression
    operator*: string
    expressionName*: seq[string]

type
  HostOpaqueNetworkResource* = ref object of HostNetworkResource
    pnicZone*: seq[string]

type
  VmUpgradingEvent* = ref object of VmEvent
    version*: string

type
  ProfileParameterMetadataParameterRelationMetadata* = ref object of DynamicData
    relationTypes*: seq[string]
    values*: seq[pointer]
    path*: ProfilePropertyPath
    minCount*: int
    maxCount*: int

type
  NasStorageProfile* = ref object of ApplyProfile
    key*: string

type
  VirtualDeviceBusSlotInfo* = ref object of DynamicData
  
type
  AgentManager* = ref object of vmodl.ManagedObject
  
type
  InvalidDatastorePath* = ref object of InvalidDatastore
    datastorePath*: string

type
  HostStorageSystem* = ref object of vim.ExtensibleManagedObject
    storageDeviceInfo*: HostStorageDeviceInfo
    fileSystemVolumeInfo*: HostFileSystemVolumeInfo
    systemFile*: seq[string]
    multipathStateInfo*: HostMultipathStateInfo

type
  OvfDuplicatedPropertyIdExport* = ref object of OvfExport
    fqid*: string

type
  CannotComputeFTCompatibleHosts* = ref object of VmFaultToleranceIssue
    vm*: VirtualMachine
    vmName*: string

type
  NicSettingMismatch* = ref object of CustomizationFault
    numberOfNicsInSpec*: int
    numberOfNicsInVM*: int

type
  ResourcePoolDestroyedEvent* = ref object of ResourcePoolEvent
  
type
  ReadOnlyDisksWithLegacyDestination* = ref object of MigrationFault
    roDiskCount*: int
    timeoutDanger*: bool

type
  VirtualMachineSummary* = ref object of DynamicData
    vm*: VirtualMachine
    runtime*: VirtualMachineRuntimeInfo
    guest*: VirtualMachineGuestSummary
    config*: VirtualMachineConfigSummary
    storage*: VirtualMachineStorageSummary
    quickStats*: VirtualMachineQuickStats
    overallStatus*: ManagedEntityStatus
    customValue*: seq[CustomFieldValue]

type
  ConcurrentAccess* = ref object of VimFault
  
type
  HostStorageOperationalInfo* = ref object of DynamicData
    property*: string
    value*: string

type
  VmBeingCreatedEvent* = ref object of VmEvent
    configSpec*: VirtualMachineConfigSpec

type
  HostUnresolvedVmfsVolumeResolveStatus* = ref object of DynamicData
    resolvable*: bool
    incompleteExtents*: bool
    multipleCopies*: bool

type
  OvfUnknownDeviceBacking* = ref object of OvfHardwareExport
    backing*: VirtualDeviceBackingInfo

type
  HostProfileHostBasedConfigSpec* = ref object of HostProfileConfigSpec
    host*: HostSystem
    profilesToExtract*: seq[string]
    useHostProfileEngine*: bool

type
  VMwareDVSVspanSessionEncapType* {.pure.} = enum
    gre, erspan2, erspan3
type
  ScheduledTaskManager* = ref object of vmodl.ManagedObject
    scheduledTask*: seq[ScheduledTask]
    description*: ScheduledTaskDescription

type
  SoftwarePackage* = ref object of DynamicData
    name*: string
    version*: string
    type*: string
    vendor*: string
    acceptanceLevel*: string
    summary*: string
    description*: string
    referenceURL*: seq[string]
    creationDate*: string
    depends*: seq[Relation]
    conflicts*: seq[Relation]
    replaces*: seq[Relation]
    provides*: seq[string]
    maintenanceModeRequired*: bool
    hardwarePlatformsRequired*: seq[string]
    capability*: SoftwarePackageCapability
    tag*: seq[string]
    payload*: seq[string]

type
  VirtualPCIPassthroughVmiopBackingOption* = ref object of VirtualPCIPassthroughPluginBackingOption
    vgpu*: StringOption
    maxInstances*: int

type
  VStorageObjectSnapshotInfo* = ref object of DynamicData
    snapshots*: seq[VStorageObjectSnapshotInfoVStorageObjectSnapshot]

type
  HostProfile* = ref object of vim.profile.Profile
    validationState*: string
    validationStateUpdateTime*: string
    validationFailureInfo*: HostProfileValidationFailureInfo
    referenceHost*: HostSystem

type
  VMINotSupported* = ref object of DeviceNotSupported
  
type
  HostPortGroupPort* = ref object of DynamicData
    key*: string
    mac*: seq[string]
    type*: string

type
  ClusterProfileConfigInfo* = ref object of ProfileConfigInfo
    complyProfile*: ComplianceProfile

type
  DistributedVirtualSwitchManagerHostDvsFilterSpec* = ref object of DynamicData
    inclusive*: bool

type
  VchaNodeRole* {.pure.} = enum
    active, passive, witness
type
  CryptoSpecDecrypt* = ref object of CryptoSpec
  
type
  ScheduledHardwareUpgradeInfoHardwareUpgradeStatus* {.pure.} = enum
    none, pending, success, failed
type
  FolderFileQuery* = ref object of FileQuery
  
type
  VlanProfile* = ref object of ApplyProfile
  
type
  MissingPowerOnConfiguration* = ref object of VAppConfigFault
  
type
  VsanHostVsanDiskInfo* = ref object of DynamicData
    vsanUuid*: string
    formatVersion*: int

type
  OvfInvalidValueConfiguration* = ref object of OvfInvalidValue
  
type
  PermissionEvent* = ref object of AuthorizationEvent
    entity*: ManagedEntityEventArgument
    principal*: string
    group*: bool

type
  DisableAdminNotSupported* = ref object of HostConfigFault
  
type
  ProfileSimpleExpression* = ref object of ProfileExpression
    expressionType*: string
    parameter*: seq[KeyAnyValue]

type
  VirtualDatacenter* = ref object of vim.ManagedEntity
  
type
  SnapshotLocked* = ref object of SnapshotFault
  
type
  HostMemberRuntimeInfo* = ref object of DynamicData
    host*: HostSystem
    status*: string
    statusDetail*: string
    healthCheckResult*: seq[HostMemberHealthCheckResult]

type
  ScheduledTaskRemovedEvent* = ref object of ScheduledTaskEvent
  
type
  InsufficientMemoryResourcesFault* = ref object of InsufficientResourcesFault
    unreserved*: int64
    requested*: int64

type
  TooManySnapshotLevels* = ref object of SnapshotFault
  
type
  VMwareDvsLacpLoadBalanceAlgorithm* {.pure.} = enum
    srcMac, destMac, srcDestMac, destIpVlan, srcIpVlan, srcDestIpVlan, destTcpUdpPort,
    srcTcpUdpPort, srcDestTcpUdpPort, destIpTcpUdpPort, srcIpTcpUdpPort,
    srcDestIpTcpUdpPort, destIpTcpUdpPortVlan, srcIpTcpUdpPortVlan,
    srcDestIpTcpUdpPortVlan, destIp, srcIp, srcDestIp, vlan, srcPortId
type
  DiagnosticManagerLogHeader* = ref object of DynamicData
    lineStart*: int
    lineEnd*: int
    lineText*: seq[string]

type
  ClusterInitialPlacementAction* = ref object of ClusterAction
    targetHost*: HostSystem
    pool*: ResourcePool

type
  VmHostAffinityRuleViolation* = ref object of VmConfigFault
    vmName*: string
    hostName*: string

type
  NotSupportedHostInHACluster* = ref object of NotSupportedHost
    hostName*: string
    build*: string

type
  OvfNoSpaceOnController* = ref object of OvfUnsupportedElement
    parent*: string

type
  DistributedVirtualSwitchPortConnecteeConnecteeType* {.pure.} = enum
    pnic, vmVnic, hostConsoleVnic, hostVmkVnic
type
  WeeklyTaskScheduler* = ref object of DailyTaskScheduler
    sunday*: bool
    monday*: bool
    tuesday*: bool
    wednesday*: bool
    thursday*: bool
    friday*: bool
    saturday*: bool

type
  VirtualMachineFeatureRequirement* = ref object of DynamicData
    key*: string
    featureName*: string
    value*: string

type
  VirtualFloppyDeviceBackingInfo* = ref object of VirtualDeviceDeviceBackingInfo
  
type
  DrsResourceConfigureFailedEvent* = ref object of HostEvent
    reason*: MethodFault

type
  DvsPortLinkUpEvent* = ref object of DvsEvent
    portKey*: string
    runtimeInfo*: DVPortStatus

type
  OvfMappedOsId* = ref object of OvfImport
    ovfId*: int
    ovfDescription*: string
    targetDescription*: string

type
  VmUuidChangedEvent* = ref object of VmEvent
    oldUuid*: string
    newUuid*: string

type
  OvfUnsupportedDeviceBackingOption* = ref object of OvfSystemFault
    elementName*: string
    instanceId*: string
    deviceName*: string
    backingName*: string

type
  DVSPolicy* = ref object of DynamicData
    autoPreInstallAllowed*: bool
    autoUpgradeAllowed*: bool
    partialUpgradeAllowed*: bool

type
  NoHost* = ref object of HostConnectFault
    name*: string

type
  AnswerFileValidationResultStatus* {.pure.} = enum
    success, needInput, error
type
  CustomizationSysprepFailed* = ref object of CustomizationFailed
    sysprepVersion*: string
    systemVersion*: string

type
  HostVirtualNic* = ref object of DynamicData
    device*: string
    key*: string
    portgroup*: string
    spec*: HostVirtualNicSpec
    port*: HostPortGroupPort

type
  NetDhcpConfigInfo* = ref object of DynamicData
    ipv6*: NetDhcpConfigInfoDhcpOptions
    ipv4*: NetDhcpConfigInfoDhcpOptions

type
  NamespaceLimitReached* = ref object of VimFault
    limit*: int

type
  CustomFieldDefRenamedEvent* = ref object of CustomFieldDefEvent
    newName*: string

type
  SessionTerminatedEvent* = ref object of SessionEvent
    sessionId*: string
    terminatedUsername*: string

type
  PolicyViolatedByValue* = ref object of PolicyViolatedDetail
    callerValue*: pointer
    policyTarget*: string
    policyTargetProperty*: string

type
  ClusterVmToolsMonitoringSettings* = ref object of DynamicData
    enabled*: bool
    vmMonitoring*: string
    clusterSettings*: bool
    failureInterval*: int
    minUpTime*: int
    maxFailures*: int
    maxFailureWindow*: int

type
  VirtualMachineUsageOnDatastore* = ref object of DynamicData
    datastore*: Datastore
    committed*: int64
    uncommitted*: int64
    unshared*: int64

type
  GuestAuthenticationChallenge* = ref object of GuestOperationsFault
    serverChallenge*: GuestAuthentication
    sessionID*: int64

type
  ProfileCreatedEvent* = ref object of ProfileEvent
  
type
  ImageLibraryManagerMediaInfo* = ref object of DynamicData
    name*: string
    type*: string
    description*: string
    keyword*: seq[string]
    version*: string
    label*: seq[string]
    custom*: seq[KeyValue]

type
  TaskScheduler* = ref object of DynamicData
    activeTime*: string
    expireTime*: string

type
  MissingNetworkIpConfig* = ref object of VAppPropertyFault
  
type
  HostProfileValidationState* {.pure.} = enum
    Ready, Running, Failed
type
  HostDiskManager* = ref object of vmodl.ManagedObject
  
type
  RoleEventArgument* = ref object of EventArgument
    roleId*: int
    name*: string

type
  MethodDisabled* = ref object of RuntimeFault
    source*: string

type
  FileTransferInformation* = ref object of DynamicData
    attributes*: GuestFileAttributes
    size*: int64
    url*: string

type
  VirtualE1000eOption* = ref object of VirtualEthernetCardOption
  
type
  VirtualVmxnetOption* = ref object of VirtualEthernetCardOption
  
type
  VirtualMachineDatastoreVolumeOption* = ref object of DynamicData
    fileSystemType*: string
    majorVersion*: int

type
  VirtualMachineMetadataManagerVmMetadataOwnerOwner* {.pure.} = enum
    ComVmwareVsphereHA
type
  SessionManagerServiceRequestSpec* = ref object of DynamicData
  
type
  HostGraphicsConfigSharedPassthruAssignmentPolicy* {.pure.} = enum
    performance, consolidation
type
  HostVirtualSwitchSimpleBridge* = ref object of HostVirtualSwitchBridge
    nicDevice*: string

type
  EnumDescription* = ref object of DynamicData
    key*: string
    tags*: seq[ElementDescription]

type
  VirtualCdromRemoteAtapiBackingOption* = ref object of VirtualDeviceDeviceBackingOption
  
type
  VirtualDeviceFileExtension* {.pure.} = enum
    iso, flp, vmdk, dsk, rdm
type
  EnteredStandbyModeEvent* = ref object of HostEvent
  
type
  InvalidCAMServer* = ref object of ActiveDirectoryFault
    camServer*: string

type
  CannotAccessFile* = ref object of FileFault
  
type
  HostSystemSwapConfigurationDatastoreOption* = ref object of HostSystemSwapConfigurationSystemSwapOption
    datastore*: string

type
  VirtualDiskManagerReparentSpec* = ref object of DynamicData
    childFilename*: string
    childDatacenter*: Datacenter
    parentFilename*: string
    parentDatacenter*: Datacenter
    markParentShared*: bool

type
  HostVffsSpec* = ref object of DynamicData
    devicePath*: string
    partition*: HostDiskPartitionSpec
    majorVersion*: int
    volumeName*: string

type
  FolderFileInfo* = ref object of FileInfo
  
type
  DvsScopeViolated* = ref object of DvsFault
    scope*: seq[ManagedEntity]
    entity*: ManagedEntity

type
  UnlicensedVirtualMachinesEvent* = ref object of LicenseEvent
    unlicensed*: int
    available*: int

type
  VslmRelocateSpec* = ref object of VslmMigrateSpec
  
type
  VAppConfigFault* = ref object of VimFault
  
type
  LicenseRestrictedEvent* = ref object of LicenseEvent
  
type
  StorageDrsPodConfigInfo* = ref object of DynamicData
    enabled*: bool
    ioLoadBalanceEnabled*: bool
    defaultVmBehavior*: string
    loadBalanceInterval*: int
    defaultIntraVmAffinity*: bool
    spaceLoadBalanceConfig*: StorageDrsSpaceLoadBalanceConfig
    ioLoadBalanceConfig*: StorageDrsIoLoadBalanceConfig
    automationOverrides*: StorageDrsAutomationConfig
    rule*: seq[ClusterRuleInfo]
    option*: seq[OptionValue]

type
  OvfUnsupportedElementValue* = ref object of OvfUnsupportedElement
    value*: string

type
  ScsiLunType* {.pure.} = enum
    disk, tape, printer, processor, worm, cdrom, scanner, opticalDevice, mediaChanger,
    communications, storageArrayController, enclosure, unknown
type
  ClusterNetworkConfigSpec* = ref object of DynamicData
    networkPortGroup*: Network
    ipSettings*: CustomizationIPSettings

type
  VMotionNotSupported* = ref object of VMotionInterfaceIssue
  
type
  HostUnresolvedVmfsResolutionSpecVmfsUuidResolution* {.pure.} = enum
    resignature, forceMount
type
  VirtualMachinePowerPolicyProfile* = ref object of DynamicData
    cpuMode*: string
    monitorTimeout*: int
    hardDiskTimeout*: int
    hibernateTimeout*: int
    suspendTimeout*: int
    forcedThrottle*: int
    minProcessorState*: int
    maxProcessorState*: int

type
  DvsEventPortBlockState* {.pure.} = enum
    unset, blocked, unblocked, unknown
type
  HostImageProfileSummary* = ref object of DynamicData
    name*: string
    vendor*: string

type
  HourlyTaskScheduler* = ref object of RecurrentTaskScheduler
    minute*: int

type
  MountError* = ref object of CustomizationFault
    vm*: VirtualMachine
    diskIndex*: int

type
  OvfInvalidPackage* = ref object of OvfFault
    lineNumber*: int

type
  ClusterCreatedEvent* = ref object of ClusterEvent
    parent*: FolderEventArgument

type
  VcAgentUpgradeFailedEvent* = ref object of HostEvent
    reason*: string

type
  VirtualDeviceDeviceBackingOption* = ref object of VirtualDeviceBackingOption
    autoDetectAvailable*: BoolOption

type
  OvfInvalidValueReference* = ref object of OvfInvalidValue
  
type
  GuestWindowsProgramSpec* = ref object of GuestProgramSpec
    startMinimized*: bool

type
  VirtualUSBController* = ref object of VirtualController
    autoConnectDevices*: bool
    ehciEnabled*: bool

type
  CpuIncompatible81EDX* = ref object of CpuIncompatible
    nx*: bool
    ffxsr*: bool
    rdtscp*: bool
    lm*: bool
    other*: bool
    otherOnly*: bool

type
  CustomizationIdentitySettings* = ref object of DynamicData
  
type
  VMotionLicenseExpiredEvent* = ref object of LicenseEvent
  
type
  VirtualMachineConfigOption* = ref object of DynamicData
    version*: string
    description*: string
    guestOSDescriptor*: seq[GuestOsDescriptor]
    guestOSDefaultIndex*: int
    hardwareOptions*: VirtualHardwareOption
    capabilities*: VirtualMachineCapability
    datastore*: DatastoreOption
    defaultDevice*: seq[VirtualDevice]
    supportedMonitorType*: seq[string]
    supportedOvfEnvironmentTransport*: seq[string]
    supportedOvfInstallTransport*: seq[string]
    propertyRelations*: seq[VirtualMachinePropertyRelation]

type
  PrivilegePolicyDef* = ref object of DynamicData
    createPrivilege*: string
    readPrivilege*: string
    updatePrivilege*: string
    deletePrivilege*: string

type
  VAppIPAssignmentInfoProtocols* {.pure.} = enum
    IPv4, IPv6
type
  ExtensionOvfConsumerInfo* = ref object of DynamicData
    callbackUrl*: string
    sectionType*: seq[string]

type
  CheckTestType* {.pure.} = enum
    sourceTests, hostTests, resourcePoolTests, datastoreTests, networkTests
type
  HostIoFilterInfo* = ref object of IoFilterInfo
    available*: bool

type
  DVSOpaqueDataConfigSpec* = ref object of DynamicData
    operation*: string
    keyedOpaqueData*: DVSKeyedOpaqueData

type
  VirtualPCIPassthroughOption* = ref object of VirtualDeviceOption
  
type
  ClusterReconfiguredEvent* = ref object of ClusterEvent
    configChanges*: ChangesInfoEventArgument

type
  ClusterFailoverResourcesAdmissionControlPolicy* = ref object of ClusterDasAdmissionControlPolicy
    cpuFailoverResourcesPercent*: int
    memoryFailoverResourcesPercent*: int
    failoverLevel*: int
    autoComputePercentages*: bool

type
  IndependentDiskVMotionNotSupported* = ref object of MigrationFeatureNotSupported
  
type
  HostInventoryUnreadableEvent* = ref object of Event
  
type
  HostServiceSourcePackage* = ref object of DynamicData
    sourcePackageName*: string
    description*: string

type
  VirtualPCNet32Option* = ref object of VirtualEthernetCardOption
    supportsMorphing*: bool

type
  HostGraphicsInfo* = ref object of DynamicData
    deviceName*: string
    vendorName*: string
    pciId*: string
    graphicsType*: string
    memorySizeInKB*: int64
    vm*: seq[VirtualMachine]

type
  ReplicationVmInProgressFaultActivity* {.pure.} = enum
    fullSync, delta
type
  RunScriptAction* = ref object of Action
    script*: string

type
  CannotChangeVsanClusterUuid* = ref object of VsanFault
  
type
  VmfsDatastoreSingleExtentOption* = ref object of VmfsDatastoreBaseOption
    vmfsExtent*: HostDiskPartitionBlockRange

type
  DatabaseSizeEstimate* = ref object of DynamicData
    size*: int64

type
  HostVFlashManagerVFlashResourceConfigSpec* = ref object of DynamicData
    vffsUuid*: string

type
  UserPasswordChanged* = ref object of HostEvent
    userLogin*: string

type
  ClusterProfile* = ref object of vim.profile.Profile
  
type
  AlarmTriggeringActionTransitionSpec* = ref object of DynamicData
    startState*: ManagedEntityStatus
    finalState*: ManagedEntityStatus
    repeats*: bool

type
  VStorageObjectAssociations* = ref object of DynamicData
    id*: ID
    vmDiskAssociations*: seq[VStorageObjectAssociationsVmDiskAssociations]
    fault*: MethodFault

type
  HostVmciAccessManagerAccessSpec* = ref object of DynamicData
    vm*: VirtualMachine
    services*: seq[string]
    mode*: string

type
  StringPolicy* = ref object of InheritablePolicy
    value*: string

type
  ProfileComponentMetadata* = ref object of DynamicData
    id*: ExtendedElementDescription
    profileCategory*: string
    profileTypeNames*: seq[string]
    profilePaths*: seq[string]

type
  VirtualDiskSeSparseBackingInfo* = ref object of VirtualDeviceFileBackingInfo
    diskMode*: string
    writeThrough*: bool
    uuid*: string
    contentId*: string
    changeId*: string
    parent*: VirtualDiskSeSparseBackingInfo
    deltaDiskFormat*: string
    digestEnabled*: bool
    grainSize*: int
    keyId*: CryptoKeyId

type
  VirtualMachineProfileSpec* = ref object of DynamicData
  
type
  VirtualSoundBlaster16Option* = ref object of VirtualSoundCardOption
  
type
  ProxyServiceRedirectSpecRedirectType* {.pure.} = enum
    permanent, found
type
  HostCpuPowerManagementInfoPolicyType* {.pure.} = enum
    off, staticPolicy, dynamicPolicy
type
  IncompatibleDefaultDevice* = ref object of MigrationFault
    device*: string

type
  DvsFilterOnFailure* {.pure.} = enum
    failOpen, failClosed
type
  HostInternetScsiHbaIscsiIpv6AddressIPv6AddressOperation* {.pure.} = enum
    add, remove
type
  ProfileExecuteResult* = ref object of DynamicData
    status*: string
    configSpec*: HostConfigSpec
    inapplicablePath*: seq[string]
    requireInput*: seq[ProfileDeferredPolicyOptionParameter]
    error*: seq[ProfileExecuteError]

type
  TooManyDisksOnLegacyHost* = ref object of MigrationFault
    diskCount*: int
    timeoutDanger*: bool

type
  DvsImportEvent* = ref object of DvsEvent
    importType*: string

type
  HostStorageDeviceInfo* = ref object of DynamicData
    hostBusAdapter*: seq[HostHostBusAdapter]
    scsiLun*: seq[ScsiLun]
    scsiTopology*: HostScsiTopology
    multipathInfo*: HostMultipathInfo
    plugStoreTopology*: HostPlugStoreTopology
    softwareInternetScsiEnabled*: bool

type
  PortGroupProfile* = ref object of ApplyProfile
    key*: string
    name*: string
    vlan*: VlanProfile
    vswitch*: VirtualSwitchSelectionProfile
    networkPolicy*: NetworkPolicyProfile

type
  KeyValue* = ref object of DynamicData
    key*: string
    value*: string

type
  CustomizationCustomIpV6Generator* = ref object of CustomizationIpV6Generator
    argument*: string

type
  HostVFlashResourceConfigurationResult* = ref object of DynamicData
    devicePath*: seq[string]
    vffs*: HostVffsVolume
    diskConfigurationResult*: seq[HostDiskConfigurationResult]

type
  ClusterAffinityRuleSpec* = ref object of ClusterRuleInfo
    vm*: seq[VirtualMachine]

type
  HealthUpdateInfo* = ref object of DynamicData
    id*: string
    componentType*: string
    description*: string

type
  DasEnabledEvent* = ref object of ClusterEvent
  
type
  HostVirtualNicManager* = ref object of vim.ExtensibleManagedObject
    info*: HostVirtualNicManagerInfo

type
  ToolsImageNotAvailable* = ref object of VmToolsUpgradeFault
  
type
  VchaClusterConfigInfo* = ref object of DynamicData
    failoverNodeInfo1*: FailoverNodeInfo
    failoverNodeInfo2*: FailoverNodeInfo
    witnessNodeInfo*: WitnessNodeInfo
    state*: string

type
  DiskHasPartitions* = ref object of VsanDiskFault
  
type
  NetIpConfigSpec* = ref object of DynamicData
    ipAddress*: seq[NetIpConfigSpecIpAddressSpec]
    dhcp*: NetDhcpConfigSpec
    autoConfigurationEnabled*: bool

type
  NetworkCopyFault* = ref object of FileFault
  
type
  VcAgentUpgradedEvent* = ref object of HostEvent
  
type
  GuestRegValueDwordSpec* = ref object of GuestRegValueDataSpec
    value*: int

type
  DVPortStatusVmDirectPathGen2InactiveReasonNetwork* {.pure.} = enum
    portNptIncompatibleDvs, portNptNoCompatibleNics,
    portNptNoVirtualFunctionsAvailable, portNptDisabledForPort
type
  UserLoginSessionEvent* = ref object of SessionEvent
    ipAddress*: string
    userAgent*: string
    locale*: string
    sessionId*: string

type
  VmGuestOSCrashedEvent* = ref object of VmEvent
  
type
  VirtualMachineNamespaceManagerCreateSpec* = ref object of DynamicData
    namespace*: string
    maxSizeEventsToGuest*: int64
    maxSizeEventsFromGuest*: int64
    maxSizeData*: int64
    accessMode*: VirtualMachineNamespaceManagerAccessMode

type
  CreateTaskAction* = ref object of Action
    taskTypeId*: string
    cancelable*: bool

type
  DVSOpaqueCommandReqSpec* = ref object of DynamicData
    command*: string
    arguments*: DVSOpaqueCommandData

type
  HostLocalFileSystemVolume* = ref object of HostFileSystemVolume
    device*: string

type
  VirtualFloppyOption* = ref object of VirtualDeviceOption
  
type
  OvfInvalidValue* = ref object of OvfAttribute
    value*: string

type
  HostTpmManager* = ref object of vmodl.ManagedObject
  
type
  SwapDatastoreNotWritableOnHost* = ref object of DatastoreNotWritableOnHost
  
type
  BatchResult* = ref object of DynamicData
    result*: string
    hostKey*: string
    ds*: Datastore
    fault*: MethodFault

type
  DistributedVirtualSwitchHostMemberBacking* = ref object of DynamicData
  
type
  VmBeingMigratedEvent* = ref object of VmEvent
    destHost*: HostEventArgument
    destDatacenter*: DatacenterEventArgument
    destDatastore*: DatastoreEventArgument

type
  HostServiceConfig* = ref object of DynamicData
    serviceId*: string
    startupPolicy*: string

type
  SuspendedRelocateNotSupported* = ref object of MigrationFault
  
type
  VirtualDiskAdapterType* {.pure.} = enum
    ide, busLogic, lsiLogic
type
  VasaProviderContainerSpec* = ref object of DynamicData
    vasaProviderInfo*: seq[VimVasaProviderInfo]
    scId*: string
    deleted*: bool

type
  DeploymentInfoServiceInfo* = ref object of DynamicData
    serviceId*: string
    hostId*: string
    ownerId*: string
    version*: string

type
  OvfDuplicatedPropertyIdImport* = ref object of OvfExport
  
type
  HostIpConfigIpV6Address* = ref object of DynamicData
    ipAddress*: string
    prefixLength*: int
    origin*: string
    dadState*: string
    lifetime*: string
    operation*: string

type
  HostPowerSystem* = ref object of vmodl.ManagedObject
    capability*: PowerSystemCapability
    info*: PowerSystemInfo

type
  DVSNameArrayUplinkPortPolicy* = ref object of DVSUplinkPortPolicy
    uplinkPortName*: seq[string]

type
  HostPatchManagerStatusPrerequisitePatch* = ref object of DynamicData
    id*: string
    installState*: seq[string]

type
  HealthSystemRuntime* = ref object of DynamicData
    systemHealthInfo*: HostSystemHealthInfo
    hardwareStatusInfo*: HostHardwareStatusInfo

type
  HostCapabilityVmDirectPathGen2UnsupportedReason* {.pure.} = enum
    hostNptIncompatibleProduct, hostNptIncompatibleHardware, hostNptDisabled
type
  FileAlreadyExists* = ref object of FileFault
  
type
  HostDatastoreSystemVvolDatastoreSpec* = ref object of DynamicData
    name*: string
    scId*: string

type
  VmFailedToShutdownGuestEvent* = ref object of VmEvent
    reason*: MethodFault

type
  HostSnmpSystemAgentLimits* = ref object of DynamicData
    maxReadOnlyCommunities*: int
    maxTrapDestinations*: int
    maxCommunityLength*: int
    maxBufferSize*: int
    capability*: HostSnmpAgentCapability

type
  FirewallProfileRulesetProfile* = ref object of ApplyProfile
    key*: string

type
  VmfsMountFault* = ref object of HostConfigFault
    uuid*: string

type
  HostFibreChannelOverEthernetTargetTransport* = ref object of HostFibreChannelTargetTransport
    vnportMac*: string
    fcfMac*: string
    vlanId*: int

type
  DatastoreAccessible* {.pure.} = enum
    True, False
type
  VAppIPAssignmentInfoIpAllocationPolicy* {.pure.} = enum
    dhcpPolicy, transientPolicy, fixedPolicy, fixedAllocatedPolicy
type
  VmDeployedEvent* = ref object of VmEvent
    srcTemplate*: VmEventArgument

type
  DatacenterConfigInfo* = ref object of DynamicData
    defaultHardwareVersionKey*: string

type
  VirtualMachineDeviceRuntimeInfoVirtualEthernetCardRuntimeStateVmDirectPathGen2InactiveReasonVm*
      {.pure.} = enum
    vmNptIncompatibleGuest, vmNptIncompatibleGuestDriver,
    vmNptIncompatibleAdapterType, vmNptDisabledOrDisconnectedAdapter,
    vmNptIncompatibleAdapterFeatures, vmNptIncompatibleBackingType,
    vmNptInsufficientMemoryReservation,
    vmNptFaultToleranceOrRecordReplayConfigured,
    vmNptConflictingIOChainConfigured, vmNptMonitorBlocks,
    vmNptConflictingOperationInProgress, vmNptRuntimeError, vmNptOutOfIntrVector,
    vmNptVMCIActive
type
  OvfUnsupportedAttributeValue* = ref object of OvfUnsupportedAttribute
    value*: string

type
  AlarmClearedEvent* = ref object of AlarmEvent
    source*: ManagedEntityEventArgument
    entity*: ManagedEntityEventArgument
    from*: string

type
  VirtualHardwareOption* = ref object of DynamicData
    hwVersion*: int
    virtualDeviceOption*: seq[VirtualDeviceOption]
    deviceListReadonly*: bool
    numCPU*: seq[int]
    numCoresPerSocket*: IntOption
    numCpuReadonly*: bool
    memoryMB*: LongOption
    numPCIControllers*: IntOption
    numIDEControllers*: IntOption
    numUSBControllers*: IntOption
    numUSBXHCIControllers*: IntOption
    numSIOControllers*: IntOption
    numPS2Controllers*: IntOption
    licensingLimit*: seq[string]
    numSupportedWwnPorts*: IntOption
    numSupportedWwnNodes*: IntOption
    resourceConfigOption*: ResourceConfigOption
    numNVDIMMControllers*: IntOption
    numTPMDevices*: IntOption

type
  HostUserWorldSwapNotEnabledEvent* = ref object of HostEvent
  
type
  SeSparseVirtualDiskSpec* = ref object of FileBackedVirtualDiskSpec
    grainSizeKb*: int

type
  ExpiredAddonLicense* = ref object of ExpiredFeatureLicense
  
type
  MultipleCertificatesVerifyFaultThumbprintData* = ref object of DynamicData
    port*: int
    thumbprint*: string

type
  VmFaultToleranceConfigIssueWrapper* = ref object of VmFaultToleranceIssue
    entityName*: string
    entity*: ManagedEntity
    error*: MethodFault

type
  HostVMotionManagerDestinationState* = ref object of DynamicData
    dstId*: int
    dstTask*: Task

type
  ClusterTransitionalEVCManagerCheckResult* = ref object of DynamicData
    evcModeKey*: string
    error*: MethodFault
    host*: seq[HostSystem]

type
  NasConnectionLimitReached* = ref object of NasConfigFault
    remoteHost*: string
    remotePath*: string

type
  QuiesceMode* {.pure.} = enum
    application, filesystem, none
type
  InvalidHostName* = ref object of HostConfigFault
  
type
  IscsiFaultVnicInUse* = ref object of IscsiFault
    vnicDevice*: string

type
  OvfConsumerValidationFault* = ref object of VmConfigFault
    extensionKey*: string
    extensionName*: string
    message*: string

type
  HostIncompatibleForFaultTolerance* = ref object of VmFaultToleranceIssue
    hostName*: string
    reason*: string

type
  VirtualAHCIController* = ref object of VirtualSATAController
  
type
  HostIpRouteTableConfig* = ref object of DynamicData
    ipRoute*: seq[HostIpRouteOp]
    ipv6Route*: seq[HostIpRouteOp]

type
  DiagnosticManagerBundleInfo* = ref object of DynamicData
    system*: HostSystem
    url*: string

type
  DrsInjectorWorkloadCorrelationState* {.pure.} = enum
    Correlated, Uncorrelated
type
  VmDateRolledBackEvent* = ref object of VmEvent
  
type
  AlarmReconfiguredEvent* = ref object of AlarmEvent
    entity*: ManagedEntityEventArgument
    configChanges*: ChangesInfoEventArgument

type
  DvsNetworkRuleQualifier* = ref object of DynamicData
    key*: string

type
  HostInternetScsiHbaParamValue* = ref object of OptionValue
    isInherited*: bool

type
  NvdimmInterleaveSetState* {.pure.} = enum
    invalid, active
type
  PerformanceDescription* = ref object of DynamicData
    counterType*: seq[ElementDescription]
    statsType*: seq[ElementDescription]

type
  InvalidLibraryResponse* = ref object of LibraryFault
    reason*: string

type
  ClusterHostGroup* = ref object of ClusterGroupInfo
    host*: seq[HostSystem]

type
  ContainerView* = ref object of vim.view.ManagedObjectView
    container*: ManagedEntity
    type*: seq[string]
    recursive*: bool

type
  WeekOfMonth* {.pure.} = enum
    first, second, third, fourth, last
type
  DVSOpaqueCommandResultInfo* = ref object of DynamicData
    selection*: SelectionSet
    host*: HostSystem
    opaqueResult*: DVSOpaqueCommandData

type
  VMwareDVSHealthCheckCapability* = ref object of DVSHealthCheckCapability
    vlanMtuSupported*: bool
    teamingSupported*: bool

type
  VmDasUpdateErrorEvent* = ref object of VmEvent
  
type
  VirtualLsiLogicControllerOption* = ref object of VirtualSCSIControllerOption
  
type
  HostSystemIdentificationInfo* = ref object of DynamicData
    identifierValue*: string
    identifierType*: ElementDescription

type
  VirtualSCSISharing* {.pure.} = enum
    noSharing, virtualSharing, physicalSharing
type
  VsanUpgradeSystemNetworkPartitionInfo* = ref object of DynamicData
    hosts*: seq[HostSystem]

type
  VmMetadataOpFailedRetry* = ref object of VmMetadataManagerFault
    retryTime*: int

type
  HostCnxFailedEvent* = ref object of HostEvent
  
type
  PreCallbackResultResult* {.pure.} = enum
    ContinueWithOperation, BlockOperation
type
  HostMultipathInfoLogicalUnitStorageArrayTypePolicy* = ref object of DynamicData
    policy*: string

type
  DVSMacLearningPolicy* = ref object of InheritablePolicy
    enabled*: bool
    allowUnicastFlooding*: bool
    limit*: int
    limitPolicy*: string

type
  HostLowLevelProvisioningManagerFileDeleteSpec* = ref object of DynamicData
    fileName*: string
    fileType*: string

type
  HostConfigChangeMode* {.pure.} = enum
    modify, replace
type
  CustomizationFault* = ref object of VimFault
  
type
  TaskFilterSpecRecursionOption* {.pure.} = enum
    self, children, all
type
  FullStorageVMotionNotSupported* = ref object of MigrationFeatureNotSupported
  
type
  HostConnectInfo* = ref object of DynamicData
    serverIp*: string
    inDasCluster*: bool
    host*: HostListSummary
    vm*: seq[VirtualMachineSummary]
    vimAccountNameRequired*: bool
    clusterSupported*: bool
    network*: seq[HostConnectInfoNetworkInfo]
    datastore*: seq[HostDatastoreConnectInfo]
    license*: HostLicenseConnectInfo
    capability*: HostCapability

type
  VmCloneEvent* = ref object of VmEvent
  
type
  HbrObjectInfo* = ref object of DynamicData
    objectType*: string
    managed*: bool
    runningPoint*: bool
    contentID*: int64
    descriptorPath*: string
    parentUri*: string
    policy*: string
    sizeKb*: int64
    allocatedSizeKb*: int64
    unsharedSizeKb*: int64
    totalAllocatedSizeKb*: int64
    tags*: seq[HbrObjectTag]
    dependents*: seq[string]
    nativeSnapshotSupported*: bool
    nativeLinkedClone*: bool

type
  ToolsInstallationInProgress* = ref object of MigrationFault
  
type
  HostUnresolvedVmfsResolutionSpec* = ref object of DynamicData
    extentDevicePath*: seq[string]
    uuidResolution*: string

type
  LicenseSourceUnavailable* = ref object of NotEnoughLicenses
    licenseSource*: LicenseSource

type
  ReplicationDiskConfigFault* = ref object of ReplicationConfigFault
    reason*: string
    vmRef*: VirtualMachine
    key*: int

type
  SharedBusControllerNotSupported* = ref object of DeviceNotSupported
  
type
  VirtualMachineSriovDevicePoolInfo* = ref object of DynamicData
    key*: string

type
  HostOperationCleanupManagerOperationActivity* {.pure.} = enum
    vmotion, nfc, create
type
  DvsFilterConfig* = ref object of InheritablePolicy
    key*: string
    agentName*: string
    slotNumber*: string
    parameters*: DvsFilterParameter
    onFailure*: string

type
  HostPlugStoreTopologyPath* = ref object of DynamicData
    key*: string
    name*: string
    channelNumber*: int
    targetNumber*: int
    lunNumber*: int
    adapter*: HostPlugStoreTopologyAdapter
    target*: HostPlugStoreTopologyTarget
    device*: HostPlugStoreTopologyDevice

type
  VsanPolicySatisfiability* = ref object of DynamicData
    uuid*: string
    isSatisfiable*: bool
    reason*: LocalizableMessage
    cost*: VsanPolicyCost

type
  OperationNotSupportedByGuest* = ref object of GuestOperationsFault
  
type
  VirtualEthernetCardLegacyNetworkBackingOption* = ref object of VirtualDeviceDeviceBackingOption
  
type
  HostDiskPartitionInfo* = ref object of DynamicData
    deviceName*: string
    spec*: HostDiskPartitionSpec
    layout*: HostDiskPartitionLayout

type
  DvsUpgradeAvailableEvent* = ref object of DvsEvent
    productInfo*: DistributedVirtualSwitchProductSpec

type
  PortGroupConnecteeType* {.pure.} = enum
    virtualMachine, systemManagement, host, unknown
type
  NoCompatibleHostWithAccessToDevice* = ref object of NoCompatibleHost
  
type
  GeneralEvent* = ref object of Event
    message*: string

type
  VirtualizationManager* = ref object of vmodl.ManagedObject
  
type
  VmResettingEvent* = ref object of VmEvent
  
type
  VirtualResourcePoolSpec* = ref object of DynamicData
    vrpId*: string
    vrpName*: string
    description*: string
    cpuAllocation*: VrpResourceAllocationInfo
    memoryAllocation*: VrpResourceAllocationInfo
    rpList*: seq[ManagedEntity]
    hubList*: seq[ManagedEntity]
    rootVRP*: bool
    staticVRP*: bool
    changeVersion*: int64

type
  ServiceProfile* = ref object of ApplyProfile
    key*: string

type
  VirtualMachineFileLayoutExDiskUnit* = ref object of DynamicData
    fileKey*: seq[int]

type
  IpContainer* = ref object of IpAddress
    containerId*: string

type
  GuestScreenInfo* = ref object of DynamicData
    width*: int
    height*: int

type
  HostNetworkResourceRuntime* = ref object of DynamicData
    pnicResourceInfo*: seq[HostPnicNetworkResourceInfo]

type
  VsanHostConfigInfo* = ref object of DynamicData
    enabled*: bool
    hostSystem*: HostSystem
    clusterInfo*: VsanHostConfigInfoClusterInfo
    storageInfo*: VsanHostConfigInfoStorageInfo
    networkInfo*: VsanHostConfigInfoNetworkInfo
    faultDomainInfo*: VsanHostFaultDomainInfo

type
  ActiveVMsBlockingEVC* = ref object of EVCConfigFault
    evcMode*: string
    host*: seq[HostSystem]
    hostName*: seq[string]

type
  VmEmigratingEvent* = ref object of VmEvent
  
type
  VirtualTPMOption* = ref object of VirtualDeviceOption
    supportedFirmware*: seq[string]

type
  IscsiFaultVnicHasNoUplinks* = ref object of IscsiFault
    vnicDevice*: string

type
  StoragePlacementAction* = ref object of ClusterAction
    vm*: VirtualMachine
    relocateSpec*: VirtualMachineRelocateSpec
    destination*: Datastore
    spaceUtilBefore*: float32
    spaceDemandBefore*: float32
    spaceUtilAfter*: float32
    spaceDemandAfter*: float32
    ioLatencyBefore*: float32

type
  MigrationEvent* = ref object of VmEvent
    fault*: MethodFault

type
  NetworkDisruptedAndConfigRolledBack* = ref object of VimFault
    host*: string

type
  ComplianceLocator* = ref object of DynamicData
    expressionName*: string
    applyPath*: ProfilePropertyPath

type
  ServiceContent* = ref object of DynamicData
    rootFolder*: Folder
    propertyCollector*: PropertyCollector
    viewManager*: ViewManager
    about*: AboutInfo
    setting*: OptionManager
    userDirectory*: UserDirectory
    sessionManager*: SessionManager
    authorizationManager*: AuthorizationManager
    serviceManager*: ServiceManager
    perfManager*: PerformanceManager
    scheduledTaskManager*: ScheduledTaskManager
    alarmManager*: AlarmManager
    eventManager*: EventManager
    taskManager*: TaskManager
    extensionManager*: ExtensionManager
    customizationSpecManager*: CustomizationSpecManager
    customFieldsManager*: CustomFieldsManager
    accountManager*: HostLocalAccountManager
    diagnosticManager*: DiagnosticManager
    licenseManager*: LicenseManager
    searchIndex*: SearchIndex
    fileManager*: FileManager
    datastoreNamespaceManager*: DatastoreNamespaceManager
    virtualDiskManager*: VirtualDiskManager
    virtualizationManager*: VirtualizationManager
    snmpSystem*: HostSnmpSystem
    vmProvisioningChecker*: VirtualMachineProvisioningChecker
    vmCompatibilityChecker*: VirtualMachineCompatibilityChecker
    ovfManager*: OvfManager
    ipPoolManager*: IpPoolManager
    dvSwitchManager*: DistributedVirtualSwitchManager
    hostProfileManager*: HostProfileManager
    clusterProfileManager*: ClusterProfileManager
    complianceManager*: ProfileComplianceManager
    localizationManager*: LocalizationManager
    storageResourceManager*: StorageResourceManager
    guestOperationsManager*: GuestOperationsManager
    overheadMemoryManager*: OverheadMemoryManager
    certificateManager*: CertificateManager
    ioFilterManager*: IoFilterManager
    vStorageObjectManager*: VStorageObjectManagerBase
    hostSpecManager*: HostSpecificationManager
    cryptoManager*: CryptoManager
    healthUpdateManager*: HealthUpdateManager
    failoverClusterConfigurator*: FailoverClusterConfigurator
    failoverClusterManager*: FailoverClusterManager

type
  HostMultipathInfoLogicalUnit* = ref object of DynamicData
    key*: string
    id*: string
    lun*: ScsiLun
    path*: seq[HostMultipathInfoPath]
    policy*: HostMultipathInfoLogicalUnitPolicy
    storageArrayTypePolicy*: HostMultipathInfoLogicalUnitStorageArrayTypePolicy

type
  GuestRegValueNameSpec* = ref object of DynamicData
    keyName*: GuestRegKeyNameSpec
    name*: string

type
  MemorySnapshotOnIndependentDisk* = ref object of SnapshotFault
  
type
  ResourcePoolRuntimeInfo* = ref object of DynamicData
    memory*: ResourcePoolResourceUsage
    cpu*: ResourcePoolResourceUsage
    overallStatus*: ManagedEntityStatus

type
  OvfConsumerCallbackFault* = ref object of OvfFault
    extensionKey*: string
    extensionName*: string

type
  DvsFilterConfigSpec* = ref object of DvsFilterConfig
    operation*: string

type
  DatacenterCreatedEvent* = ref object of DatacenterEvent
    parent*: FolderEventArgument

type
  HostActiveDirectoryInfoDomainMembershipStatus* {.pure.} = enum
    unknown, ok, noServers, clientTrustBroken, serverTrustBroken, inconsistentTrust,
    otherProblem
type
  VmRelocateFailedEvent* = ref object of VmRelocateSpecEvent
    destHost*: HostEventArgument
    reason*: MethodFault
    destDatacenter*: DatacenterEventArgument
    destDatastore*: DatastoreEventArgument

type
  VmFailedUpdatingSecondaryConfig* = ref object of VmEvent
  
type
  VimAccountPasswordChangedEvent* = ref object of HostEvent
  
type
  HostNasVolumeConfig* = ref object of DynamicData
    changeOperation*: string
    spec*: HostNasVolumeSpec

type
  AlarmStatusChangedEvent* = ref object of AlarmEvent
    source*: ManagedEntityEventArgument
    entity*: ManagedEntityEventArgument
    from*: string
    to*: string

type
  FirewallProfile* = ref object of ApplyProfile
    ruleset*: seq[FirewallProfileRulesetProfile]

type
  PerfCompositeMetric* = ref object of DynamicData
    entity*: PerfEntityMetricBase
    childEntity*: seq[PerfEntityMetricBase]

type
  VirtualParallelPortDeviceBackingInfo* = ref object of VirtualDeviceDeviceBackingInfo
  
type
  FailoverClusterManager* = ref object of vmodl.ManagedObject
    disabledClusterMethod*: seq[string]

type
  VmFaultToleranceStateChangedEvent* = ref object of VmEvent
    oldState*: VirtualMachineFaultToleranceState
    newState*: VirtualMachineFaultToleranceState

type
  IpAddressProfile* = ref object of ApplyProfile
  
type
  HostUnresolvedVmfsExtentUnresolvedReason* {.pure.} = enum
    diskIdMismatch, uuidConflict
type
  NetIpConfigInfo* = ref object of DynamicData
    ipAddress*: seq[NetIpConfigInfoIpAddress]
    dhcp*: NetDhcpConfigInfo
    autoConfigurationEnabled*: bool

type
  VmFaultToleranceInvalidFileBackingDeviceType* {.pure.} = enum
    virtualFloppy, virtualCdrom, virtualSerialPort, virtualParallelPort, virtualDisk
type
  BaseConfigInfoDiskFileBackingInfoProvisioningType* {.pure.} = enum
    thin, eagerZeroedThick, lazyZeroedThick
type
  VirtualPS2ControllerOption* = ref object of VirtualControllerOption
    numKeyboards*: IntOption
    numPointingDevices*: IntOption

type
  LicenseFeatureInfoSourceRestriction* {.pure.} = enum
    unrestricted, served, file
type
  HostVirtualSwitchAutoBridge* = ref object of HostVirtualSwitchBridge
    excludedNicDevice*: seq[string]

type
  PermissionAddedEvent* = ref object of PermissionEvent
    role*: RoleEventArgument
    propagate*: bool

type
  VsanDecomParam* = ref object of DynamicData
    nodeUUID*: string
    scsiDisk*: HostScsiDisk

type
  MethodAlreadyDisabledFault* = ref object of RuntimeFault
    sourceId*: string

type
  HostDeploymentInfo* = ref object of DynamicData
    bootedFromStatelessCache*: bool

type
  VirtualVmxnet2* = ref object of VirtualVmxnet
  
type
  HostProfileManagerMetadataTypes* {.pure.} = enum
    profile, policy, component, category
type
  LicenseDiagnostics* = ref object of DynamicData
    sourceLastChanged*: string
    sourceLost*: string
    sourceLatency*: float32
    licenseRequests*: string
    licenseRequestFailures*: string
    licenseFeatureUnknowns*: string
    opState*: LicenseManagerState
    lastStatusUpdate*: string
    opFailureMessage*: string

type
  VirtualMachineUsbInfo* = ref object of VirtualMachineTargetInfo
    description*: string
    vendor*: int
    product*: int
    physicalPath*: string
    family*: seq[string]
    speed*: seq[string]
    summary*: VirtualMachineSummary

type
  FaultToleranceNotLicensed* = ref object of VmFaultToleranceIssue
    hostName*: string

type
  ThirdPartyLicenseAssignmentFailedReason* {.pure.} = enum
    licenseAssignmentFailed, moduleNotInstalled
type
  ProfileEvent* = ref object of Event
    profile*: ProfileEventArgument

type
  VirtualDiskSparseVer2BackingInfo* = ref object of VirtualDeviceFileBackingInfo
    diskMode*: string
    split*: bool
    writeThrough*: bool
    spaceUsedInKB*: int64
    uuid*: string
    contentId*: string
    changeId*: string
    parent*: VirtualDiskSparseVer2BackingInfo
    keyId*: CryptoKeyId

type
  HostProfilesCustomizationData* = ref object of DynamicData
    customizationsFormat*: string
    entityCustomizations*: seq[HostProfilesEntityCustomizations]

type
  VirtualMachineScsiDiskDeviceInfo* = ref object of VirtualMachineDiskDeviceInfo
    disk*: HostScsiDisk
    transportHint*: string
    lunNumber*: int

type
  HostProfileParameterMapping* = ref object of DynamicData
    id*: string
    data*: HostProfileParameterMappingParameterMappingData

type
  HostVMotionManagerSrcVMotionResult* = ref object of DynamicData
    vmDowntime*: int64
    vmPrecopyStunTime*: int64
    vmPrecopyBandwidth*: int64

type
  VirtualSerialPortPipeBackingOption* = ref object of VirtualDevicePipeBackingOption
    endpoint*: ChoiceOption
    noRxLoss*: BoolOption

type
  FileFault* = ref object of VimFault
    file*: string

type
  HbrManagerReplicationVmInfo* = ref object of DynamicData
    state*: string
    progressInfo*: ReplicationVmProgressInfo
    imageId*: string
    lastError*: MethodFault

type
  EvaluationLicenseSource* = ref object of LicenseSource
    remainingHours*: int64

type
  ConflictingDatastoreFound* = ref object of RuntimeFault
    name*: string
    url*: string

type
  CannotDisableDrsOnClustersWithVApps* = ref object of RuntimeFault
  
type
  OverheadService* = ref object of vmodl.ManagedObject
  
type
  VchaClusterHealth* = ref object of DynamicData
    runtimeInfo*: VchaClusterRuntimeInfo
    healthMessages*: seq[LocalizableMessage]
    additionalInformation*: seq[LocalizableMessage]

type
  HostProfileValidationFailureInfoUpdateType* {.pure.} = enum
    HostBased, Import, Edit, Compose
type
  HostNoHAEnabledPortGroupsEvent* = ref object of HostDasEvent
  
type
  MissingBmcSupport* = ref object of VimFault
  
type
  AgentInstallFailed* = ref object of HostConnectFault
    reason*: string
    statusCode*: int
    installerOutput*: string

type
  ClusterComputeResourceDrmBundleInfo* = ref object of DynamicData
    url*: string
    drmDumpInfo*: ClusterComputeResourceDrmDumpInfo

type
  HostFirewallRuleDirection* {.pure.} = enum
    inbound, outbound
type
  ClusterEVCManager* = ref object of vim.ExtensibleManagedObject
    managedCluster*: ClusterComputeResource
    evcState*: ClusterEVCManagerEVCState

type
  CustomizationLinuxPrep* = ref object of CustomizationIdentitySettings
    hostName*: CustomizationName
    domain*: string
    timeZone*: string
    hwClockUTC*: bool

type
  MigrationResourceWarningEvent* = ref object of MigrationEvent
    dstPool*: ResourcePoolEventArgument
    dstHost*: HostEventArgument

type
  ToolsUnavailable* = ref object of VimFault
  
type
  HostNetStackInstanceSystemStackKey* {.pure.} = enum
    defaultTcpipStack, vmotion, vSphereProvisioning
type
  DVSKeyedOpaqueData* = ref object of InheritablePolicy
    key*: string
    opaqueData*: byte

type
  VirtualParallelPort* = ref object of VirtualDevice
  
type
  InsufficientStandbyResource* = ref object of InsufficientResourcesFault
  
type
  ExtendedElementDescription* = ref object of ElementDescription
    messageCatalogKeyPrefix*: string
    messageArg*: seq[KeyAnyValue]

type
  CryptoManagerKmipClusterStatus* = ref object of DynamicData
    clusterId*: KeyProviderId
    servers*: seq[CryptoManagerKmipServerStatus]
    clientCertInfo*: CryptoManagerKmipCertificateInfo

type
  HostDistributedVirtualSwitchManagerNetworkResourcePoolKey* {.pure.} = enum
    faultTolerance, hbr, iSCSI, management, nfs, virtualMachine, vmotion, vsan, vdp
type
  InvalidTicket* = ref object of VimFault
  
type
  ClusterDrsVmConfigSpec* = ref object of ArrayUpdateSpec
    info*: ClusterDrsVmConfigInfo

type
  MultipathState* {.pure.} = enum
    standby, active, disabled, dead, unknown
type
  DatastoreFileEvent* = ref object of DatastoreEvent
    targetFile*: string
    sourceOfOperation*: string
    succeeded*: bool

type
  ClusterDrsFaultsFaultsByVirtualDisk* = ref object of ClusterDrsFaultsFaultsByVm
    disk*: VirtualDiskId

type
  VirtualDiskFlatVer2BackingOption* = ref object of VirtualDeviceFileBackingOption
    diskMode*: ChoiceOption
    split*: BoolOption
    writeThrough*: BoolOption
    growable*: bool
    hotGrowable*: bool
    uuid*: bool
    thinProvisioned*: BoolOption
    eagerlyScrub*: BoolOption
    deltaDiskFormat*: ChoiceOption
    deltaDiskFormatsSupported*: seq[VirtualDiskDeltaDiskFormatsSupported]

type
  GuestRegistryFault* = ref object of GuestOperationsFault
    windowsSystemErrorCode*: int64

type
  VMwareDvsIpfixCapability* = ref object of DynamicData
    ipfixSupported*: bool
    ipv6ForIpfixSupported*: bool
    observationDomainIdSupported*: bool

type
  HostConfigFault* = ref object of VimFault
  
type
  InvalidDeviceSpec* = ref object of InvalidVmConfig
    deviceIndex*: int

type
  ArrayUpdateSpec* = ref object of DynamicData
    operation*: ArrayUpdateOperation
    removeKey*: pointer

type
  VsanUpgradeSystemNetworkPartitionIssue* = ref object of VsanUpgradeSystemPreflightCheckIssue
    partitions*: seq[VsanUpgradeSystemNetworkPartitionInfo]

type
  HostCnxFailedBadCcagentEvent* = ref object of HostEvent
  
type
  VirtualDiskMode* {.pure.} = enum
    persistent, nonpersistent, undoable, independent_persistent,
    independent_nonpersistent, append
type
  ClusterDasAdmissionResult* = ref object of DynamicData
    pass*: bool
    info*: ClusterDasAdmissionControlInfo
    advancedInfo*: ClusterDasAdvancedRuntimeInfo

type
  GuestMultipleMappings* = ref object of GuestOperationsFault
  
type
  CannotChangeVsanNodeUuid* = ref object of VsanFault
  
type
  ReplicationVmState* {.pure.} = enum
    none, paused, syncing, idle, active, error
type
  VirtualMachineToolsStatus* {.pure.} = enum
    toolsNotInstalled, toolsNotRunning, toolsOld, toolsOk
type
  HostVirtualNicManagerInfo* = ref object of DynamicData
    netConfig*: seq[VirtualNicManagerNetConfig]

type
  ScheduledTaskEmailCompletedEvent* = ref object of ScheduledTaskEvent
    to*: string

type
  HostForceMountedInfo* = ref object of DynamicData
    persist*: bool
    mounted*: bool

type
  ManagedObjectView* = ref object of vim.view.View
    view*: seq[ManagedObject]

type
  VirtualMachineQuickStats* = ref object of DynamicData
    overallCpuUsage*: int
    overallCpuDemand*: int
    guestMemoryUsage*: int
    hostMemoryUsage*: int
    guestHeartbeatStatus*: ManagedEntityStatus
    distributedCpuEntitlement*: int
    distributedMemoryEntitlement*: int
    staticCpuEntitlement*: int
    staticMemoryEntitlement*: int
    privateMemory*: int
    sharedMemory*: int
    swappedMemory*: int
    balloonedMemory*: int
    consumedOverheadMemory*: int
    ftLogBandwidth*: int
    ftSecondaryLatency*: int
    ftLatencyStatus*: ManagedEntityStatus
    compressedMemory*: int64
    uptimeSeconds*: int
    ssdSwappedMemory*: int64

type
  DrsEnteringStandbyModeEvent* = ref object of EnteringStandbyModeEvent
  
type
  CDCInventoryChangeKind* {.pure.} = enum
    created, updated, deleted
type
  VirtualMachineRelocateSpecDiskLocator* = ref object of DynamicData
    diskId*: int
    datastore*: Datastore
    diskMoveType*: string
    diskBackingInfo*: VirtualDeviceBackingInfo
    profile*: seq[VirtualMachineProfileSpec]

type
  GuestAuthAliasInfo* = ref object of DynamicData
    subject*: GuestAuthSubject
    comment*: string

type
  HostNetStackInstance* = ref object of DynamicData
    key*: string
    name*: string
    dnsConfig*: HostDnsConfig
    ipRouteConfig*: HostIpRouteConfig
    requestedMaxNumberOfConnections*: int
    congestionControlAlgorithm*: string
    ipV6Enabled*: bool
    routeTableConfig*: HostIpRouteTableConfig

type
  HostDatastoreSystemVmFileAccessibilityResult* = ref object of DynamicData
    vmId*: string
    accessible*: bool
    error*: MethodFault

type
  ExtensionPrivilegeInfo* = ref object of DynamicData
    privID*: string
    privGroupName*: string

type
  VirtualMachinePowerPolicyCpuMode* {.pure.} = enum
    noProcessorThrottling, adaptiveProcessorThrottling,
    constantProcessorThrottling, degradedProcessorThrottling
type
  NetDhcpConfigSpec* = ref object of DynamicData
    ipv6*: NetDhcpConfigSpecDhcpOptionsSpec
    ipv4*: NetDhcpConfigSpecDhcpOptionsSpec

type
  VirtualMachineVMCIDeviceDirection* {.pure.} = enum
    guest, host, anyDirection
type
  ClusterFailoverHostAdmissionControlInfo* = ref object of ClusterDasAdmissionControlInfo
    hostStatus*: seq[ClusterFailoverHostAdmissionControlInfoHostStatus]

type
  HostSystem* = ref object of vim.ManagedEntity
    runtime*: HostRuntimeInfo
    summary*: HostListSummary
    hardware*: HostHardwareInfo
    capability*: HostCapability
    licensableResource*: HostLicensableResourceInfo
    remediationState*: HostSystemRemediationState
    precheckRemediationResult*: ApplyHostProfileConfigurationSpec
    remediationResult*: ApplyHostProfileConfigurationResult
    complianceCheckState*: HostSystemComplianceCheckState
    complianceCheckResult*: ComplianceResult
    configManager*: HostConfigManager
    config*: HostConfigInfo
    vm*: seq[VirtualMachine]
    datastore*: seq[Datastore]
    network*: seq[Network]
    datastoreBrowser*: HostDatastoreBrowser
    systemResources*: HostSystemResourceInfo
    answerFileValidationState*: AnswerFileStatusResult
    answerFileValidationResult*: AnswerFileStatusResult

type
  ClusterInfraUpdateHaConfigInfoRemediationType* {.pure.} = enum
    QuarantineMode, MaintenanceMode
type
  VirtualController* = ref object of VirtualDevice
    busNumber*: int
    device*: seq[int]

type
  LicenseReservationInfo* = ref object of DynamicData
    key*: string
    state*: LicenseReservationInfoState
    required*: int

type
  InvalidPropertyType* = ref object of VAppPropertyFault
  
type
  VirtualFloppyImageBackingInfo* = ref object of VirtualDeviceFileBackingInfo
  
type
  HostAddedEvent* = ref object of HostEvent
  
type
  HostDiskBlockInfoScsiMapping* = ref object of HostDiskBlockInfoMapping
  
type
  VsanHostConfigInfoNetworkInfo* = ref object of DynamicData
    port*: seq[VsanHostConfigInfoNetworkInfoPortConfig]

type
  GatewayToHostConnectFault* = ref object of GatewayConnectFault
    hostname*: string
    port*: int

type
  ReplicationFault* = ref object of VimFault
  
type
  TaskInProgress* = ref object of VimFault
    task*: Task

type
  HostIncompatibleForRecordReplay* = ref object of VimFault
    hostName*: string
    reason*: string

type
  PolicyViolatedValueNotInRange* = ref object of PolicyViolatedByValue
    policyMinValue*: pointer
    policyMaxValue*: pointer

type
  SnapshotCloneNotSupported* = ref object of SnapshotCopyNotSupported
  
type
  ServiceLocatorNamePassword* = ref object of ServiceLocatorCredential
    username*: string
    password*: string

type
  VirtualMachineProvisioningPolicyFilePolicy* = ref object of DynamicData
    fileType*: string
    policy*: seq[VirtualMachineProvisioningPolicyPolicy]

type
  VirtualEthernetCardLegacyNetworkBackingInfo* = ref object of VirtualDeviceDeviceBackingInfo
  
type
  AccountUpdatedEvent* = ref object of HostEvent
    spec*: HostAccountSpec
    group*: bool
    prevDescription*: string

type
  DVSConfigInfo* = ref object of DynamicData
    uuid*: string
    name*: string
    numStandalonePorts*: int
    numPorts*: int
    maxPorts*: int
    uplinkPortPolicy*: DVSUplinkPortPolicy
    uplinkPortgroup*: seq[DistributedVirtualPortgroup]
    defaultPortConfig*: DVPortSetting
    host*: seq[DistributedVirtualSwitchHostMember]
    productInfo*: DistributedVirtualSwitchProductSpec
    targetInfo*: DistributedVirtualSwitchProductSpec
    extensionKey*: string
    vendorSpecificConfig*: seq[DistributedVirtualSwitchKeyedOpaqueBlob]
    policy*: DVSPolicy
    description*: string
    configVersion*: string
    contact*: DVSContactInfo
    switchIpAddress*: string
    createTime*: string
    networkResourceManagementEnabled*: bool
    defaultProxySwitchMaxNumPorts*: int
    healthCheckConfig*: seq[DVSHealthCheckConfig]
    infrastructureTrafficResourceConfig*: seq[DvsHostInfrastructureTrafficResource]
    netResourcePoolTrafficResourceConfig*: seq[DvsHostInfrastructureTrafficResource]
    networkResourceControlVersion*: string
    vmVnicNetworkResourcePool*: seq[DVSVmVnicNetworkResourcePool]
    pnicCapacityRatioForReservation*: int

type
  CustomizationUnknownFailure* = ref object of CustomizationFailed
  
type
  OvfSystemFault* = ref object of OvfFault
  
type
  AfterStartupTaskScheduler* = ref object of TaskScheduler
    minute*: int

type
  ExtensionManagerExtensionDataUsage* = ref object of DynamicData
    extensionKey*: string
    numKeys*: int64
    size*: int64

type
  IscsiFaultVnicHasWrongUplink* = ref object of IscsiFault
    vnicDevice*: string

type
  HostVmfsVolumeUnmapPriority* {.pure.} = enum
    none, low
type
  StorageDrsPlacementRankVmSpec* = ref object of DynamicData
    vmPlacementSpec*: PlacementSpec
    vmClusters*: seq[ClusterComputeResource]

type
  CustomizationVirtualMachineName* = ref object of CustomizationName
  
type
  FileTooLarge* = ref object of FileFault
    datastore*: string
    fileSize*: int64
    maxFileSize*: int64

type
  HostConfigAppliedEvent* = ref object of HostEvent
  
type
  ScheduledHardwareUpgradeInfo* = ref object of DynamicData
    upgradePolicy*: string
    versionKey*: string
    scheduledHardwareUpgradeStatus*: string
    fault*: MethodFault

type
  VirtualDeviceConnectInfoStatus* {.pure.} = enum
    ok, recoverableError, unrecoverableError, untried
type
  ExtensionManagerIpAllocationUsage* = ref object of DynamicData
    extensionKey*: string
    numAddresses*: int

type
  VmFaultToleranceOpIssuesList* = ref object of VmFaultToleranceIssue
    errors*: seq[MethodFault]
    warnings*: seq[MethodFault]

type
  VirtualMachineToolsRunningStatus* {.pure.} = enum
    guestToolsNotRunning, guestToolsRunning, guestToolsExecutingScripts
type
  HostLoadEsxManagerConfigSpec* = ref object of DynamicData
    enableLoadEsx*: bool
    ignoreRebootPrecheck*: bool

type
  VMwareDVSPortgroupPolicy* = ref object of DVPortgroupPolicy
    vlanOverrideAllowed*: bool
    uplinkTeamingOverrideAllowed*: bool
    securityPolicyOverrideAllowed*: bool
    ipfixOverrideAllowed*: bool

type
  VirtualMachineConfigInfoSwapPlacementType* {.pure.} = enum
    inherit, vmDirectory, hostLocal
type
  OpaqueNetwork* = ref object of vim.Network
    capability*: OpaqueNetworkCapability
    extraConfig*: seq[OptionValue]

type
  CannotEnableVmcpForClusterReason* {.pure.} = enum
    APDTimeoutDisabled, IncompatibleHostVersion
type
  AdminNotDisabled* = ref object of HostConfigFault
  
type
  DpmBehavior* {.pure.} = enum
    manual, automated
type
  VAppEntityConfigInfo* = ref object of DynamicData
    key*: ManagedEntity
    tag*: string
    startOrder*: int
    startDelay*: int
    waitingForGuest*: bool
    startAction*: string
    stopDelay*: int
    stopAction*: string
    destroyWithParent*: bool

type
  ProfileHostProfileEngineHostProfileManagerPolicyMetaArray* = ref object of DynamicData
    policyMeta*: seq[ProfilePolicyMetadata]

type
  AlarmEmailCompletedEvent* = ref object of AlarmEvent
    entity*: ManagedEntityEventArgument
    to*: string

type
  HostShortNameInconsistentEvent* = ref object of HostDasEvent
    shortName*: string
    shortName2*: string

type
  AlarmInfo* = ref object of AlarmSpec
    key*: string
    alarm*: Alarm
    entity*: ManagedEntity
    lastModifiedTime*: string
    lastModifiedUser*: string
    creationEventId*: int

type
  VmFaultToleranceTooManyFtVcpusOnHost* = ref object of InsufficientResourcesFault
    hostName*: string
    maxNumFtVcpus*: int

type
  VolumeEditorError* = ref object of CustomizationFault
  
type
  ToolsImageCopyFailed* = ref object of VmToolsUpgradeFault
  
type
  AnswerFileCreateSpec* = ref object of DynamicData
    validating*: bool

type
  NotEnoughCpus* = ref object of VirtualHardwareCompatibilityIssue
    numCpuDest*: int
    numCpuVm*: int

type
  SingleMac* = ref object of MacAddress
    address*: string

type
  RoleUpdatedEvent* = ref object of RoleEvent
    privilegeList*: seq[string]
    prevRoleName*: string
    privilegesAdded*: seq[string]
    privilegesRemoved*: seq[string]

type
  EVCAdmissionFailedCPUFeaturesForMode* = ref object of EVCAdmissionFailed
    currentEVCModeKey*: string

type
  UserProfile* = ref object of ApplyProfile
    key*: string

type
  VirtualNVDIMM* = ref object of VirtualDevice
    capacityInMB*: int64

type
  PermissionProfile* = ref object of ApplyProfile
    key*: string

type
  HostDiskPartitionLayout* = ref object of DynamicData
    total*: HostDiskDimensionsLba
    partition*: seq[HostDiskPartitionBlockRange]

type
  HostNetworkSecurityPolicy* = ref object of DynamicData
    allowPromiscuous*: bool
    macChanges*: bool
    forgedTransmits*: bool

type
  HostTpmOptionEventDetails* = ref object of HostTpmEventDetails
    optionsFileName*: string
    bootOptions*: seq[byte]

type
  VspanPortgroupTypeChangeFault* = ref object of DvsFault
    portgroupName*: string

type
  ExitMaintenanceModeEvent* = ref object of HostEvent
  
type
  ConfigSpecOperation* {.pure.} = enum
    add, edit, remove
type
  VMwareIpfixConfig* = ref object of DynamicData
    collectorIpAddress*: string
    collectorPort*: int
    observationDomainId*: int64
    activeFlowTimeout*: int
    idleFlowTimeout*: int
    samplingRate*: int
    internalFlowsOnly*: bool

type
  VirtualMachineNamespaceManager* = ref object of vmodl.ManagedObject
  
type
  HostVnicConnectedToCustomizedDVPortEvent* = ref object of HostEvent
    vnic*: VnicPortArgument
    prevPortKey*: string

type
  ComputeResourceConfigSpec* = ref object of DynamicData
    vmSwapPlacement*: string
    spbmEnabled*: bool
    defaultHardwareVersionKey*: string

type
  EntityType* {.pure.} = enum
    distributedVirtualSwitch, distributedVirtualPortgroup
type
  ReadHostResourcePoolTreeFailed* = ref object of HostConnectFault
  
type
  VirtualCdromAtapiBackingOption* = ref object of VirtualDeviceDeviceBackingOption
  
type
  PnicUplinkProfile* = ref object of ApplyProfile
    key*: string

type
  AlarmActionTriggeredEvent* = ref object of AlarmEvent
    source*: ManagedEntityEventArgument
    entity*: ManagedEntityEventArgument

type
  BaseConfigInfoFileBackingInfo* = ref object of BaseConfigInfoBackingInfo
    filePath*: string
    backingObjectId*: string
    parent*: BaseConfigInfoFileBackingInfo
    deltaSizeInMB*: int64

type
  VirtualMachineForkConfigInfo* = ref object of DynamicData
    parentEnabled*: bool
    childForkGroupId*: string
    parentForkGroupId*: string
    childType*: string

type
  AlarmTrigger* = ref object of DynamicData
    triggerNum*: int
    type*: string
    alarmId*: string
    object*: ManagedEntity
    deviceName*: string
    ruleName*: string
    deviceType*: string
    triggerTime*: int64
    fromStatus*: ManagedEntityStatus
    toStatus*: ManagedEntityStatus
    arguments*: seq[KeyAnyValue]

type
  ProxyServiceServiceSpec* = ref object of ProxyServiceEndpointSpec
  
type
  HostReliableMemoryInfo* = ref object of DynamicData
    memorySize*: int64

type
  DrsRuleComplianceEvent* = ref object of VmEvent
  
type
  VirtualMachineIdeDiskDevicePartitionInfo* = ref object of DynamicData
    id*: int
    capacity*: int

type
  ParaVirtualSCSIController* = ref object of VirtualSCSIController
  
type
  HostProfileManagerCompositionResultResultElementStatus* {.pure.} = enum
    success, error
type
  VmAlreadyExistsInDatacenter* = ref object of InvalidFolder
    host*: HostSystem
    hostname*: string
    vm*: seq[VirtualMachine]

type
  HostProfileManagerTaskListRequirement* {.pure.} = enum
    maintenanceModeRequired, rebootRequired
type
  PhysicalNicHintInfo* = ref object of DynamicData
    device*: string
    subnet*: seq[PhysicalNicIpHint]
    network*: seq[PhysicalNicNameHint]
    connectedSwitchPort*: PhysicalNicCdpInfo
    lldpInfo*: LinkLayerDiscoveryProtocolInfo

type
  HostSharedGpuCapabilities* = ref object of DynamicData
    vgpu*: string
    diskSnapshotSupported*: bool
    memorySnapshotSupported*: bool
    suspendSupported*: bool
    migrateSupported*: bool

type
  VirtualSerialPortThinPrintBackingOption* = ref object of VirtualDeviceBackingOption
  
type
  VsanClusterConfigInfoHostDefaultInfo* = ref object of DynamicData
    uuid*: string
    autoClaimStorage*: bool
    checksumEnabled*: bool

type
  DuplicateVsanNetworkInterface* = ref object of VsanFault
    device*: string

type
  DrsBehavior* {.pure.} = enum
    manual, partiallyAutomated, fullyAutomated
type
  PermissionRemovedEvent* = ref object of PermissionEvent
  
type
  DrsExitingStandbyModeEvent* = ref object of ExitingStandbyModeEvent
  
type
  HttpNfcLease* = ref object of vmodl.ManagedObject
    initializeProgress*: int
    transferProgress*: int
    mode*: string
    capabilities*: HttpNfcLeaseCapabilities
    info*: HttpNfcLeaseInfo
    state*: HttpNfcLeaseState
    error*: MethodFault

type
  VmFailedStartingSecondaryEvent* = ref object of VmEvent
    reason*: string

type
  HostActiveDirectorySpec* = ref object of DynamicData
    domainName*: string
    userName*: string
    password*: string
    camServer*: string
    thumbprint*: string
    smartCardAuthenticationEnabled*: bool
    smartCardTrustAnchors*: seq[string]

type
  VirtualMachineFloppyInfo* = ref object of VirtualMachineTargetInfo
  
type
  HostSystemResourceInfo* = ref object of DynamicData
    key*: string
    config*: ResourceConfigSpec
    child*: seq[HostSystemResourceInfo]

type
  VmRequirementsExceedCurrentEVCModeEvent* = ref object of VmEvent
  
type
  EVCModeIllegalByVendor* = ref object of EVCConfigFault
    clusterCPUVendor*: string
    modeCPUVendor*: string

type
  HostIpRouteTableInfo* = ref object of DynamicData
    ipRoute*: seq[HostIpRouteEntry]
    ipv6Route*: seq[HostIpRouteEntry]

type
  DVSConfigSpec* = ref object of DynamicData
    configVersion*: string
    name*: string
    numStandalonePorts*: int
    maxPorts*: int
    uplinkPortPolicy*: DVSUplinkPortPolicy
    uplinkPortgroup*: seq[DistributedVirtualPortgroup]
    defaultPortConfig*: DVPortSetting
    host*: seq[DistributedVirtualSwitchHostMemberConfigSpec]
    extensionKey*: string
    description*: string
    policy*: DVSPolicy
    vendorSpecificConfig*: seq[DistributedVirtualSwitchKeyedOpaqueBlob]
    contact*: DVSContactInfo
    switchIpAddress*: string
    defaultProxySwitchMaxNumPorts*: int
    infrastructureTrafficResourceConfig*: seq[DvsHostInfrastructureTrafficResource]
    netResourcePoolTrafficResourceConfig*: seq[DvsHostInfrastructureTrafficResource]
    networkResourceControlVersion*: string

type
  ClusterInfraUpdateHaConfigInfo* = ref object of DynamicData
    enabled*: bool
    behavior*: string
    moderateRemediation*: string
    severeRemediation*: string
    providers*: seq[string]

type
  VVolVmConfigFileUpdateResultFailedVmConfigFileInfo* = ref object of DynamicData
    targetConfigVVolId*: string
    fault*: MethodFault

type
  CryptoKeyPlain* = ref object of DynamicData
    keyId*: CryptoKeyId
    algorithm*: string
    keyData*: string

type
  VMwareDVSPvlanMapEntry* = ref object of DynamicData
    primaryVlanId*: int
    secondaryVlanId*: int
    pvlanType*: string

type
  NotEnoughLogicalCpus* = ref object of NotEnoughCpus
    host*: HostSystem

type
  VmPoweringOnWithCustomizedDVPortEvent* = ref object of VmEvent
    vnic*: seq[VnicPortArgument]

type
  ProfileEventArgument* = ref object of EventArgument
    profile*: Profile
    name*: string

type
  HostIpConfigIpV6AddressConfigType* {.pure.} = enum
    other, manual, dhcp, linklayer, random
type
  HostTelemetryFilterSpec* = ref object of DynamicData
    whitelist*: seq[string]
    blacklist*: seq[string]

type
  AndAlarmExpression* = ref object of AlarmExpression
    expression*: seq[AlarmExpression]

type
  VmFailedRelayoutOnVmfs2DatastoreEvent* = ref object of VmEvent
  
type
  VsanUpgradeSystemWrongEsxVersionIssue* = ref object of VsanUpgradeSystemPreflightCheckIssue
    hosts*: seq[HostSystem]

type
  NvdimmHealthInfo* = ref object of DynamicData
    healthStatus*: string
    healthInformation*: string
    stateFlagInfo*: seq[string]
    dimmTemperature*: int
    dimmTemperatureThreshold*: int
    spareBlocksPercentage*: int
    spareBlockThreshold*: int
    dimmLifespanPercentage*: int
    esTemperature*: int
    esTemperatureThreshold*: int
    esLifespanPercentage*: int

type
  TooManyDevices* = ref object of InvalidVmConfig
  
type
  VmRelocatedEvent* = ref object of VmRelocateSpecEvent
    sourceHost*: HostEventArgument
    sourceDatacenter*: DatacenterEventArgument
    sourceDatastore*: DatastoreEventArgument

type
  HostLicensableResourceInfo* = ref object of DynamicData
    resource*: seq[KeyAnyValue]

type
  UnlicensedVirtualMachinesFoundEvent* = ref object of LicenseEvent
    available*: int

type
  DailyTaskScheduler* = ref object of HourlyTaskScheduler
    hour*: int

type
  DrsPlacementRequiresVmsInTopologicalOrder* = ref object of VimFault
  
type
  HostProfileParameterMappingParameterMappingData* = ref object of HostProfileMappingData
    isKey*: bool

type
  HostSriovNetworkDevicePoolInfo* = ref object of HostSriovDevicePoolInfo
    switchKey*: string
    switchUuid*: string
    pnic*: seq[PhysicalNic]

type
  VirtualMachineStorageInfo* = ref object of DynamicData
    perDatastoreUsage*: seq[VirtualMachineUsageOnDatastore]
    timestamp*: string

type
  HostPciPassthruSystem* = ref object of vim.ExtensibleManagedObject
    pciPassthruInfo*: seq[HostPciPassthruInfo]
    sriovDevicePoolInfo*: seq[HostSriovDevicePoolInfo]

type
  VsanUpgradeSystem* = ref object of vmodl.ManagedObject
  
type
  InheritablePolicy* = ref object of DynamicData
    inherited*: bool

type
  HostSubSpecificationUpdateEvent* = ref object of HostEvent
    hostSubSpec*: HostSubSpecification

type
  HostProtocolEndpoint* = ref object of DynamicData
    peType*: string
    type*: string
    uuid*: string
    hostKey*: seq[HostSystem]
    storageArray*: string
    nfsServer*: string
    nfsDir*: string
    nfsServerScope*: string
    nfsServerMajor*: string
    nfsServerAuthType*: string
    nfsServerUser*: string
    deviceId*: string

type
  HostApplyProfile* = ref object of ApplyProfile
    memory*: HostMemoryProfile
    storage*: StorageProfile
    network*: NetworkProfile
    datetime*: DateTimeProfile
    firewall*: FirewallProfile
    security*: SecurityProfile
    service*: seq[ServiceProfile]
    option*: seq[OptionProfile]
    userAccount*: seq[UserProfile]
    usergroupAccount*: seq[UserGroupProfile]
    authentication*: AuthenticationProfile

type
  HostVMotionManagerVMotionDiskSpec* = ref object of HostVMotionManagerVMotionDeviceSpec
    parentFilename*: string
    parentShared*: bool
    numLinksToConsolidate*: int

type
  VirtualEthernetCard* = ref object of VirtualDevice
    addressType*: string
    macAddress*: string
    wakeOnLanEnabled*: bool
    resourceAllocation*: VirtualEthernetCardResourceAllocation
    externalId*: string
    uptCompatibilityEnabled*: bool

type
  LicenseEvent* = ref object of Event
  
type
  HostLocalPortCreatedEvent* = ref object of DvsEvent
    hostLocalPort*: DVSHostLocalPortInfo

type
  NvdimmNamespaceType* {.pure.} = enum
    blockNamespace, persistentNamespace
type
  NoVcManagedIpConfigured* = ref object of VAppPropertyFault
  
type
  VirtualMachineTargetInfo* = ref object of DynamicData
    name*: string
    configurationTag*: seq[string]

type
  DatastoreEventArgument* = ref object of EntityEventArgument
    datastore*: Datastore

type
  HostNetworkPolicy* = ref object of DynamicData
    security*: HostNetworkSecurityPolicy
    nicTeaming*: HostNicTeamingPolicy
    offloadPolicy*: HostNetOffloadCapabilities
    shapingPolicy*: HostNetworkTrafficShapingPolicy

type
  CannotAddHostWithFTVmAsStandalone* = ref object of HostConnectFault
  
type
  OvfCpuCompatibilityCheckNotSupported* = ref object of OvfImport
  
type
  VsanPolicyChangeBatch* = ref object of DynamicData
    uuid*: seq[string]
    policy*: string

type
  ClusterSlotPolicy* = ref object of DynamicData
  
type
  GatewayToHostAuthFault* = ref object of GatewayToHostConnectFault
    invalidProperties*: seq[string]
    missingProperties*: seq[string]

type
  DatacenterConfigSpec* = ref object of DynamicData
    defaultHardwareVersionKey*: string

type
  CustomizationIdentification* = ref object of DynamicData
    joinWorkgroup*: string
    joinDomain*: string
    domainAdmin*: string
    domainAdminPassword*: CustomizationPassword

type
  LicenseDataManager* = ref object of vmodl.ManagedObject
    entityLicenseData*: seq[LicenseDataManagerEntityLicenseData]

type
  DVSVendorSpecificConfig* = ref object of InheritablePolicy
    keyValue*: seq[DistributedVirtualSwitchKeyedOpaqueBlob]

type
  ServiceConsolePortGroupProfile* = ref object of PortGroupProfile
    ipConfig*: IpAddressProfile

type
  GuestRegKeySpec* = ref object of DynamicData
    keyName*: GuestRegKeyNameSpec
    classType*: string
    lastWritten*: string

type
  HostOpaqueSwitchPhysicalNicZone* = ref object of DynamicData
    key*: string
    pnicDevice*: seq[string]

type
  AnswerFile* = ref object of DynamicData
    userInput*: seq[ProfileDeferredPolicyOptionParameter]
    createdTime*: string
    modifiedTime*: string

type
  HostPortGroupSpec* = ref object of DynamicData
    name*: string
    vlanId*: int
    vswitchName*: string
    policy*: HostNetworkPolicy

type
  EVCAdmissionFailedCPUModel* = ref object of EVCAdmissionFailed
  
type
  HostIpInconsistentEvent* = ref object of HostEvent
    ipAddress*: string
    ipAddress2*: string

type
  VsanDecommissioningCost* = ref object of DynamicData
    copyDataSize*: int64
    usedDataSize*: int64
    flashReadCacheSize*: int64

type
  VmStaticMacConflictEvent* = ref object of VmEvent
    conflictedVm*: VmEventArgument
    mac*: string

type
  NodeNetworkSpec* = ref object of DynamicData
    ipSettings*: CustomizationIPSettings

type
  ScsiLunVStorageSupportStatus* {.pure.} = enum
    vStorageSupported, vStorageUnsupported, vStorageUnknown
type
  HostAuthenticationManagerInfo* = ref object of DynamicData
    authConfig*: seq[HostAuthenticationStoreInfo]

type
  HostConfigManager* = ref object of DynamicData
    cpuScheduler*: HostCpuSchedulerSystem
    datastoreSystem*: HostDatastoreSystem
    memoryManager*: HostMemorySystem
    storageSystem*: HostStorageSystem
    networkSystem*: HostNetworkSystem
    vmotionSystem*: HostVMotionSystem
    virtualNicManager*: HostVirtualNicManager
    serviceSystem*: HostServiceSystem
    firewallSystem*: HostFirewallSystem
    advancedOption*: OptionManager
    diagnosticSystem*: HostDiagnosticSystem
    autoStartManager*: HostAutoStartManager
    snmpSystem*: HostSnmpSystem
    dateTimeSystem*: HostDateTimeSystem
    patchManager*: HostPatchManager
    hostUpdateProxyManager*: HostHostUpdateProxyManager
    imageConfigManager*: HostImageConfigManager
    bootDeviceSystem*: HostBootDeviceSystem
    firmwareSystem*: HostFirmwareSystem
    healthStatusSystem*: HostHealthStatusSystem
    pciPassthruSystem*: HostPciPassthruSystem
    licenseManager*: LicenseManager
    kernelModuleSystem*: HostKernelModuleSystem
    authenticationManager*: HostAuthenticationManager
    powerSystem*: HostPowerSystem
    cacheConfigurationManager*: HostCacheConfigurationManager
    esxAgentHostManager*: HostEsxAgentHostManager
    iscsiManager*: IscsiManager
    vFlashManager*: HostVFlashManager
    vsanSystem*: HostVsanSystem
    messageBusProxy*: MessageBusProxy
    userDirectory*: UserDirectory
    accountManager*: HostLocalAccountManager
    hostAccessManager*: HostAccessManager
    graphicsManager*: HostGraphicsManager
    vsanInternalSystem*: HostVsanInternalSystem
    certificateManager*: HostCertificateManager
    cryptoManager*: CryptoManager
    nvdimmSystem*: HostNvdimmSystem

type
  GeneralHostInfoEvent* = ref object of GeneralEvent
  
type
  DestinationSwitchFull* = ref object of CannotAccessNetwork
  
type
  FileNameTooLong* = ref object of FileFault
  
type
  VmReconfiguredEvent* = ref object of VmEvent
    configSpec*: VirtualMachineConfigSpec
    configChanges*: ChangesInfoEventArgument

type
  HostFibreChannelOverEthernetHba* = ref object of HostFibreChannelHba
    underlyingNic*: string
    linkInfo*: HostFibreChannelOverEthernetHbaLinkInfo
    isSoftwareFcoe*: bool
    markedForRemoval*: bool

type
  AutoStartDefaults* = ref object of DynamicData
    enabled*: bool
    startDelay*: int
    stopDelay*: int
    waitForHeartbeat*: bool
    stopAction*: string

type
  VmSecondaryAddedEvent* = ref object of VmEvent
  
type
  ClusterDiagnoseResourceAllocationResult* = ref object of DynamicData
    recommendation*: seq[ClusterRecommendation]
    fault*: seq[ClusterDrsFaults]
    entitlement*: seq[ClusterDiagnoseResourceAllocationResultVmStaticEntitlement]

type
  VirtualMachineEmptyProfileSpec* = ref object of VirtualMachineProfileSpec
  
type
  GuestOsDescriptor* = ref object of DynamicData
    id*: string
    family*: string
    fullName*: string
    supportedMaxCPUs*: int
    numSupportedPhysicalSockets*: int
    numSupportedCoresPerSocket*: int
    supportedMinMemMB*: int
    supportedMaxMemMB*: int
    recommendedMemMB*: int
    recommendedColorDepth*: int
    supportedDiskControllerList*: seq[string]
    recommendedSCSIController*: string
    recommendedDiskController*: string
    supportedNumDisks*: int
    recommendedDiskSizeMB*: int
    recommendedCdromController*: string
    supportedEthernetCard*: seq[string]
    recommendedEthernetCard*: string
    supportsSlaveDisk*: bool
    cpuFeatureMask*: seq[HostCpuIdInfo]
    smcRequired*: bool
    supportsWakeOnLan*: bool
    supportsVMI*: bool
    supportsMemoryHotAdd*: bool
    supportsCpuHotAdd*: bool
    supportsCpuHotRemove*: bool
    supportedFirmware*: seq[string]
    recommendedFirmware*: string
    supportedUSBControllerList*: seq[string]
    recommendedUSBController*: string
    supports3D*: bool
    recommended3D*: bool
    smcRecommended*: bool
    ich7mRecommended*: bool
    usbRecommended*: bool
    supportLevel*: string
    supportedForCreate*: bool
    vRAMSizeInKB*: IntOption
    numSupportedFloppyDevices*: int
    wakeOnLanEthernetCard*: seq[string]
    supportsPvscsiControllerForBoot*: bool
    diskUuidEnabled*: bool
    supportsHotPlugPCI*: bool
    supportsSecureBoot*: bool
    defaultSecureBoot*: bool
    persistentMemorySupported*: bool
    supportedMinPersistentMemoryMB*: int64
    supportedMaxPersistentMemoryMB*: int64
    recommendedPersistentMemoryMB*: int64
    persistentMemoryHotAddSupported*: bool
    persistentMemoryHotRemoveSupported*: bool
    persistentMemoryColdGrowthSupported*: bool
    persistentMemoryColdGrowthGranularityMB*: int64
    persistentMemoryHotGrowthSupported*: bool
    persistentMemoryHotGrowthGranularityMB*: int64
    numRecommendedPhysicalSockets*: int
    numRecommendedCoresPerSocket*: int
    vvtdSupported*: BoolOption
    vbsSupported*: BoolOption
    supportsTPM20*: bool

type
  UncustomizableGuest* = ref object of CustomizationFault
    uncustomizableGuestOS*: string

type
  CbrcDigestInfo* = ref object of DynamicData
    digestVersion*: int
    digestBlockSize*: int
    numberHashes*: int
    numberValidHashes*: int
    partitionOffsetEnabled*: bool
    hashCollisionDetectionEnabled*: bool
    hashKeyLength*: int
    journalCoverageArea*: int
    baseDiskCid*: int
    baseDiskPath*: string
    baseDigestPath*: string
    recomputeNeeded*: bool

type
  InsufficientHostMemoryCapacityFault* = ref object of InsufficientHostCapacityFault
    unreserved*: int64
    requested*: int64

type
  PhysicalNicHint* = ref object of DynamicData
    vlanId*: int

type
  HostMemberUplinkHealthCheckResult* = ref object of HostMemberHealthCheckResult
    uplinkPortKey*: string

type
  DistributedVirtualSwitchPortCriteria* = ref object of DynamicData
    connected*: bool
    active*: bool
    uplinkPort*: bool
    scope*: ManagedEntity
    portgroupKey*: seq[string]
    inside*: bool
    portKey*: seq[string]
    host*: seq[HostSystem]

type
  ComputeResourceSummary* = ref object of DynamicData
    totalCpu*: int
    totalMemory*: int64
    numCpuCores*: int16
    numCpuThreads*: int16
    effectiveCpu*: int
    effectiveMemory*: int64
    numHosts*: int
    numEffectiveHosts*: int
    overallStatus*: ManagedEntityStatus

type
  ToolsAutoUpgradeNotSupported* = ref object of VmToolsUpgradeFault
  
type
  HostTpmAttestationInfoAcceptanceStatus* {.pure.} = enum
    notAccepted, accepted
type
  VirtualDeviceURIBackingOptionDirection* {.pure.} = enum
    server, client
type
  SoftwarePackageCapability* = ref object of DynamicData
    liveInstallAllowed*: bool
    liveRemoveAllowed*: bool
    statelessReady*: bool
    overlay*: bool

type
  OvfDuplicateElement* = ref object of OvfElement
  
type
  HostFirewallDefaultPolicy* = ref object of DynamicData
    incomingBlocked*: bool
    outgoingBlocked*: bool

type
  AnswerFileStatusResult* = ref object of DynamicData
    checkedTime*: string
    host*: HostSystem
    status*: string
    error*: seq[AnswerFileStatusError]

type
  AccountRemovedEvent* = ref object of HostEvent
    account*: string
    group*: bool

type
  HostFileSystemVolumeInfo* = ref object of DynamicData
    volumeTypeList*: seq[string]
    mountInfo*: seq[HostFileSystemMountInfo]

type
  PerfInterval* = ref object of DynamicData
    key*: int
    samplingPeriod*: int
    name*: string
    length*: int
    level*: int
    enabled*: bool

type
  ReplicationVmInProgressFault* = ref object of ReplicationVmFault
    requestedActivity*: string
    inProgressActivity*: string

type
  HostMultipathInfo* = ref object of DynamicData
    lun*: seq[HostMultipathInfoLogicalUnit]

type
  VMFSDatastoreExpandedEvent* = ref object of HostEvent
    datastore*: DatastoreEventArgument

type
  VirtualMachineLegacyNetworkSwitchInfo* = ref object of DynamicData
    name*: string

type
  MacAddress* = ref object of NegatableExpression
  
type
  MaintenanceModeFileMove* = ref object of MigrationFault
  
type
  OvfManager* = ref object of vmodl.ManagedObject
    ovfImportOption*: seq[OvfOptionInfo]
    ovfExportOption*: seq[OvfOptionInfo]

type
  PerfMetricSeries* = ref object of DynamicData
    id*: PerfMetricId

type
  DVSCapability* = ref object of DynamicData
    dvsOperationSupported*: bool
    dvPortGroupOperationSupported*: bool
    dvPortOperationSupported*: bool
    compatibleHostComponentProductInfo*: seq[DistributedVirtualSwitchHostProductSpec]
    featuresSupported*: DVSFeatureCapability

type
  VsanUpgradeSystemUpgradeHistoryPreflightFail* = ref object of VsanUpgradeSystemUpgradeHistoryItem
    preflightResult*: VsanUpgradeSystemPreflightCheckResult

type
  HostFileSystemVolume* = ref object of DynamicData
    type*: string
    name*: string
    capacity*: int64

type
  CustomizationPrefixName* = ref object of CustomizationName
    base*: string

type
  PatchMetadataNotFound* = ref object of PatchMetadataInvalid
  
type
  HostCapability* = ref object of DynamicData
    recursiveResourcePoolsSupported*: bool
    cpuMemoryResourceConfigurationSupported*: bool
    rebootSupported*: bool
    shutdownSupported*: bool
    vmotionSupported*: bool
    standbySupported*: bool
    ipmiSupported*: bool
    maxSupportedVMs*: int
    maxRunningVMs*: int
    maxSupportedVcpus*: int
    maxRegisteredVMs*: int
    datastorePrincipalSupported*: bool
    sanSupported*: bool
    nfsSupported*: bool
    iscsiSupported*: bool
    vlanTaggingSupported*: bool
    nicTeamingSupported*: bool
    highGuestMemSupported*: bool
    maintenanceModeSupported*: bool
    suspendedRelocateSupported*: bool
    restrictedSnapshotRelocateSupported*: bool
    perVmSwapFiles*: bool
    localSwapDatastoreSupported*: bool
    unsharedSwapVMotionSupported*: bool
    backgroundSnapshotsSupported*: bool
    preAssignedPCIUnitNumbersSupported*: bool
    screenshotSupported*: bool
    scaledScreenshotSupported*: bool
    storageVMotionSupported*: bool
    vmotionWithStorageVMotionSupported*: bool
    vmotionAcrossNetworkSupported*: bool
    maxNumDisksSVMotion*: int
    hbrNicSelectionSupported*: bool
    vrNfcNicSelectionSupported*: bool
    recordReplaySupported*: bool
    ftSupported*: bool
    replayUnsupportedReason*: string
    replayCompatibilityIssues*: seq[string]
    checkpointFtSupported*: bool
    smpFtSupported*: bool
    ftCompatibilityIssues*: seq[string]
    checkpointFtCompatibilityIssues*: seq[string]
    smpFtCompatibilityIssues*: seq[string]
    maxVcpusPerFtVm*: int
    loginBySSLThumbprintSupported*: bool
    cloneFromSnapshotSupported*: bool
    deltaDiskBackingsSupported*: bool
    perVMNetworkTrafficShapingSupported*: bool
    tpmSupported*: bool
    tpmVersion*: string
    txtEnabled*: bool
    supportedCpuFeature*: seq[HostCpuIdInfo]
    virtualExecUsageSupported*: bool
    storageIORMSupported*: bool
    vmDirectPathGen2Supported*: bool
    vmDirectPathGen2UnsupportedReason*: seq[string]
    vmDirectPathGen2UnsupportedReasonExtended*: string
    supportedVmfsMajorVersion*: seq[int]
    vStorageCapable*: bool
    snapshotRelayoutSupported*: bool
    firewallIpRulesSupported*: bool
    servicePackageInfoSupported*: bool
    maxHostRunningVms*: int
    maxHostSupportedVcpus*: int
    vmfsDatastoreMountCapable*: bool
    eightPlusHostVmfsSharedAccessSupported*: bool
    nestedHVSupported*: bool
    vPMCSupported*: bool
    interVMCommunicationThroughVMCISupported*: bool
    scheduledHardwareUpgradeSupported*: bool
    featureCapabilitiesSupported*: bool
    latencySensitivitySupported*: bool
    storagePolicySupported*: bool
    accel3dSupported*: bool
    reliableMemoryAware*: bool
    multipleNetworkStackInstanceSupported*: bool
    messageBusProxySupported*: bool
    vsanSupported*: bool
    vFlashSupported*: bool
    hostAccessManagerSupported*: bool
    provisioningNicSelectionSupported*: bool
    nfs41Supported*: bool
    nfs41Krb5iSupported*: bool
    turnDiskLocatorLedSupported*: bool
    virtualVolumeDatastoreSupported*: bool
    markAsSsdSupported*: bool
    markAsLocalSupported*: bool
    smartCardAuthenticationSupported*: bool
    pMemSupported*: bool
    pMemSnapshotSupported*: bool
    cryptoSupported*: bool
    oneKVolumeAPIsSupported*: bool
    gatewayOnNicSupported*: bool
    upitSupported*: bool
    cpuHwMmuSupported*: bool
    encryptedVMotionSupported*: bool
    encryptionChangeOnAddRemoveSupported*: bool
    encryptionHotOperationSupported*: bool
    encryptionWithSnapshotsSupported*: bool
    encryptionFaultToleranceSupported*: bool
    encryptionMemorySaveSupported*: bool
    encryptionRDMSupported*: bool
    encryptionVFlashSupported*: bool
    encryptionCBRCSupported*: bool
    encryptionHBRSupported*: bool
    ftEfiSupported*: bool
    unmapMethodSupported*: string
    maxMemMBPerFtVm*: int
    virtualMmuUsageIgnored*: bool
    virtualExecUsageIgnored*: bool
    vmCreateDateSupported*: bool
    vmfs3EOLSupported*: bool
    ftVmcpSupported*: bool

type
  HostCacheConfigurationInfo* = ref object of DynamicData
    key*: Datastore
    swapSize*: int64

type
  Capability* = ref object of DynamicData
    provisioningSupported*: bool
    multiHostSupported*: bool
    userShellAccessSupported*: bool
    supportedEVCMode*: seq[EVCMode]
    networkBackupAndRestoreSupported*: bool
    ftDrsWithoutEvcSupported*: bool

type
  VirtualUSBRemoteClientBackingOption* = ref object of VirtualDeviceRemoteDeviceBackingOption
  
type
  OvfMissingAttribute* = ref object of OvfAttribute
  
type
  ActionType* {.pure.} = enum
    MigrationV1, VmPowerV1, HostPowerV1, IncreaseLimitV1, IncreaseSizeV1,
    IncreaseSharesV1, IncreaseReservationV1, DecreaseOthersReservationV1,
    IncreaseClusterCapacityV1, DecreaseMigrationThresholdV1, HostMaintenanceV1,
    StorageMigrationV1, StoragePlacementV1, PlacementV1, HostInfraUpdateHaV1
type
  HostVMotionManagerReparentSpec* = ref object of DynamicData
    busNumber*: int
    unitNumber*: int
    filename*: string
    transform*: VirtualMachineRelocateTransformation
    diskBackingInfo*: VirtualDeviceBackingInfo
    controllerType*: string
    parentFilename*: string
    parentShared*: bool
    numLinksToConsolidate*: int
    storagePolicy*: string

type
  HostSriovInfo* = ref object of HostPciPassthruInfo
    sriovEnabled*: bool
    sriovCapable*: bool
    sriovActive*: bool
    numVirtualFunctionRequested*: int
    numVirtualFunction*: int
    maxVirtualFunctionSupported*: int

type
  HostVffsVolume* = ref object of HostFileSystemVolume
    majorVersion*: int
    version*: string
    uuid*: string
    extent*: seq[HostScsiDiskPartition]

type
  HttpNfcLeaseCapabilities* = ref object of DynamicData
    pullModeSupported*: bool
    corsSupported*: bool

type
  ExtendedFault* = ref object of VimFault
    faultTypeId*: string
    data*: seq[KeyValue]

type
  HostIpRouteConfig* = ref object of DynamicData
    defaultGateway*: string
    gatewayDevice*: string
    ipV6DefaultGateway*: string
    ipV6GatewayDevice*: string

type
  QuarantineModeFault* = ref object of VmConfigFault
    vmName*: string
    faultType*: string

type
  LicenseAssignmentManagerLicenseFileDescriptor* = ref object of DynamicData
    content*: string
    name*: string
    properties*: seq[KeyAnyValue]

type
  CannotAccessVmDevice* = ref object of CannotAccessVmComponent
    device*: string
    backing*: string
    connected*: bool

type
  DiskNotSupported* = ref object of VirtualHardwareCompatibilityIssue
    disk*: int

type
  VmGuestStandbyEvent* = ref object of VmEvent
  
type
  VirtualMachinePropertyRelation* = ref object of DynamicData
    key*: DynamicProperty
    relations*: seq[DynamicProperty]

type
  VmfsDatastoreAllExtentOption* = ref object of VmfsDatastoreSingleExtentOption
  
type
  VmSmpFaultToleranceTooManyVMsOnHost* = ref object of InsufficientResourcesFault
    hostName*: string
    maxNumSmpFtVms*: int

type
  GuestRegistryKeyAlreadyExists* = ref object of GuestRegistryKeyFault
  
type
  HostCnxFailedNetworkErrorEvent* = ref object of HostEvent
  
type
  ApplicationQuiesceFault* = ref object of SnapshotFault
  
type
  NvdimmGuid* = ref object of DynamicData
    uuid*: string

type
  ClusterVmGroup* = ref object of ClusterGroupInfo
    vm*: seq[VirtualMachine]

type
  KmipClusterInfo* = ref object of DynamicData
    clusterId*: KeyProviderId
    servers*: seq[KmipServerInfo]
    useAsDefault*: bool

type
  VirtualNicManagerNetConfig* = ref object of DynamicData
    nicType*: string
    multiSelectAllowed*: bool
    candidateVnic*: seq[HostVirtualNic]
    selectedVnic*: seq[HostVirtualNic]

type
  MemorySizeNotRecommended* = ref object of VirtualHardwareCompatibilityIssue
    memorySizeMB*: int
    minMemorySizeMB*: int
    maxMemorySizeMB*: int

type
  ThirdPartyLicenseAssignmentFailed* = ref object of RuntimeFault
    host*: HostSystem
    module*: string
    reason*: string

type
  HostEsxAgentHostManagerConfigInfo* = ref object of DynamicData
    agentVmDatastore*: Datastore
    agentVmNetwork*: Network

type
  VirtualKeyboardOption* = ref object of VirtualDeviceOption
  
type
  VsanFault* = ref object of VimFault
  
type
  CustomizationLicenseFilePrintData* = ref object of DynamicData
    autoMode*: CustomizationLicenseDataMode
    autoUsers*: int

type
  GeneralHostWarningEvent* = ref object of GeneralEvent
  
type
  EsxAgentConfigManagerAgentVmState* {.pure.} = enum
    enabled, disabled, unavailable, manuallyEnabled
type
  SDDCBase* = ref object of DynamicData
  
type
  ResourceInUse* = ref object of VimFault
    type*: string
    name*: string

type
  VmPowerOffOnIsolationEvent* = ref object of VmPoweredOffEvent
    isolatedHost*: HostEventArgument

type
  DvsIpPort* = ref object of NegatableExpression
  
type
  ClusterConfigInfoEx* = ref object of ComputeResourceConfigInfo
    dasConfig*: ClusterDasConfigInfo
    dasVmConfig*: seq[ClusterDasVmConfigInfo]
    drsConfig*: ClusterDrsConfigInfo
    drsVmConfig*: seq[ClusterDrsVmConfigInfo]
    rule*: seq[ClusterRuleInfo]
    orchestration*: ClusterOrchestrationInfo
    vmOrchestration*: seq[ClusterVmOrchestrationInfo]
    dpmConfigInfo*: ClusterDpmConfigInfo
    dpmHostConfig*: seq[ClusterDpmHostConfigInfo]
    vsanConfigInfo*: VsanClusterConfigInfo
    vsanHostConfig*: seq[VsanHostConfigInfo]
    group*: seq[ClusterGroupInfo]
    infraUpdateHaConfig*: ClusterInfraUpdateHaConfigInfo
    proactiveDrsConfig*: ClusterProactiveDrsConfigInfo

type
  EncryptionKeyRequired* = ref object of InvalidState
    requiredKey*: seq[CryptoKeyId]

type
  HostDiskMappingOption* = ref object of DynamicData
    physicalPartition*: seq[HostDiskMappingPartitionOption]
    name*: string

type
  VirtualPCIPassthrough* = ref object of VirtualDevice
  
type
  DeltaDiskFormatNotSupported* = ref object of VmConfigFault
    datastore*: seq[Datastore]
    deltaDiskFormat*: string

type
  InvalidBmcRole* = ref object of VimFault
  
type
  OrAlarmExpression* = ref object of AlarmExpression
    expression*: seq[AlarmExpression]

type
  CustomizationUserData* = ref object of DynamicData
    fullName*: string
    orgName*: string
    computerName*: CustomizationName
    productId*: string

type
  VirtualMachineSerialInfo* = ref object of VirtualMachineTargetInfo
  
type
  VchaNodeState* {.pure.} = enum
    up, down
type
  LicenseAssignmentFailedReason* {.pure.} = enum
    keyEntityMismatch, downgradeDisallowed, inventoryNotManageableByVirtualCenter,
    hostsUnmanageableByVirtualCenterWithoutLicenseServer
type
  DvsIpPortContainer* = ref object of DvsIpPort
    containerId*: string

type
  CustomizationSysprepRebootOption* {.pure.} = enum
    reboot, noreboot, shutdown
type
  VirtualMachineFileLayoutSnapshotLayout* = ref object of DynamicData
    key*: VirtualMachineSnapshot
    snapshotFile*: seq[string]

type
  SecondaryVmAlreadyEnabled* = ref object of VmFaultToleranceIssue
    instanceUuid*: string

type
  HostPathSelectionPolicyOption* = ref object of DynamicData
    policy*: ElementDescription

type
  HostNetworkSystem* = ref object of vim.ExtensibleManagedObject
    capabilities*: HostNetCapabilities
    networkInfo*: HostNetworkInfo
    offloadCapabilities*: HostNetOffloadCapabilities
    networkConfig*: HostNetworkConfig
    dnsConfig*: HostDnsConfig
    ipRouteConfig*: HostIpRouteConfig
    consoleIpRouteConfig*: HostIpRouteConfig

type
  PatchSuperseded* = ref object of PatchNotApplicable
    supersede*: seq[string]

type
  ReplicationConfigFault* = ref object of ReplicationFault
  
type
  HostTpmEventLogEntry* = ref object of DynamicData
    pcrIndex*: int
    eventDetails*: HostTpmEventDetails

type
  NoAccessUserEvent* = ref object of SessionEvent
    ipAddress*: string

type
  OvfInvalidVmName* = ref object of OvfUnsupportedPackage
    name*: string

type
  OvfCreateImportSpecResult* = ref object of DynamicData
    importSpec*: ImportSpec
    fileItem*: seq[OvfFileItem]
    warning*: seq[MethodFault]
    error*: seq[MethodFault]

type
  FailToLockFaultToleranceVMs* = ref object of RuntimeFault
    vmName*: string
    vm*: VirtualMachine
    alreadyLockedVm*: VirtualMachine

type
  DisallowedOperationOnFailoverHost* = ref object of RuntimeFault
    host*: HostSystem
    hostname*: string

type
  VirtualMachineRelocateTransformation* {.pure.} = enum
    flat, sparse
type
  VMwareDVSVlanMtuHealthCheckConfig* = ref object of VMwareDVSHealthCheckConfig
  
type
  LockerReconfiguredEvent* = ref object of Event
    oldDatastore*: DatastoreEventArgument
    newDatastore*: DatastoreEventArgument

type
  CustomizationSpecItem* = ref object of DynamicData
    info*: CustomizationSpecInfo
    spec*: CustomizationSpec

type
  CustomizationSpecInfo* = ref object of DynamicData
    name*: string
    description*: string
    type*: string
    changeVersion*: string
    lastUpdateTime*: string

type
  VirtualMachineCloneSpec* = ref object of DynamicData
    location*: VirtualMachineRelocateSpec
    template*: bool
    config*: VirtualMachineConfigSpec
    customization*: CustomizationSpec
    powerOn*: bool
    snapshot*: VirtualMachineSnapshot
    memory*: bool

type
  EVCAdmissionFailedHostSoftwareForMode* = ref object of EVCAdmissionFailed
  
type
  LatencySensitivity* = ref object of DynamicData
    level*: LatencySensitivitySensitivityLevel
    sensitivity*: int

type
  NetDnsConfigSpec* = ref object of DynamicData
    dhcp*: bool
    hostName*: string
    domainName*: string
    ipAddress*: seq[string]
    searchDomain*: seq[string]

type
  VirtualUSBXHCIController* = ref object of VirtualController
    autoConnectDevices*: bool

type
  FcoeConfigFcoeCapabilities* = ref object of DynamicData
    priorityClass*: bool
    sourceMacAddress*: bool
    vlanRange*: bool

type
  IscsiFault* = ref object of VimFault
  
type
  TaskEvent* = ref object of Event
    info*: TaskInfo

type
  LegacyTemplateManager* = ref object of vmodl.ManagedObject
  
type
  IsoImageFileInfo* = ref object of FileInfo
  
type
  HostBlockAdapterTargetTransport* = ref object of HostTargetTransport
  
type
  AuthorizationPrivilege* = ref object of DynamicData
    privId*: string
    onParent*: bool
    name*: string
    privGroupName*: string

type
  DistributedVirtualSwitchManagerHostDvsMembershipFilter* = ref object of DistributedVirtualSwitchManagerHostDvsFilterSpec
    distributedVirtualSwitch*: DistributedVirtualSwitch

type
  HostProfilePolicyMappingPolicyMappingData* = ref object of HostProfileMappingData
  
type
  CbrcManager* = ref object of vmodl.ManagedObject
  
type
  HostHardwareElementStatus* {.pure.} = enum
    Unknown, Green, Yellow, Red
type
  CustomFieldValue* = ref object of DynamicData
    key*: int

type
  ClusterProfileManager* = ref object of vim.profile.ProfileManager
  
type
  GuestAuthentication* = ref object of DynamicData
    interactiveSession*: bool

type
  VStorageObject* = ref object of DynamicData
    config*: VStorageObjectConfigInfo

type
  StorageDrsCannotMoveVmWithMountedCDROM* = ref object of VimFault
  
type
  NoPermissionOnAD* = ref object of ActiveDirectoryFault
  
type
  InvalidDatastoreState* = ref object of InvalidState
    datastoreName*: string

type
  SwitchIpUnset* = ref object of DvsFault
  
type
  HbrManagerVmReplicationCapability* = ref object of DynamicData
    vm*: VirtualMachine
    supportedQuiesceMode*: string
    compressionSupported*: bool
    maxSupportedSourceDiskCapacity*: int64
    minRpo*: int64
    fault*: MethodFault

type
  HostPlacedVirtualNicIdentifier* = ref object of DynamicData
    vm*: VirtualMachine
    vnicKey*: string
    reservation*: int

type
  VMOnVirtualIntranet* = ref object of CannotAccessNetwork
  
type
  GuestOperationsFault* = ref object of VimFault
  
type
  IpPoolIpPoolConfigInfo* = ref object of DynamicData
    subnetAddress*: string
    netmask*: string
    gateway*: string
    range*: string
    dns*: seq[string]
    dhcpServerAvailable*: bool
    ipPoolEnabled*: bool

type
  VirtualVmxnet2Option* = ref object of VirtualVmxnetOption
  
type
  VirtualMachineFaultToleranceType* {.pure.} = enum
    unset, recordReplay, checkpointing
type
  ManagedByInfo* = ref object of DynamicData
    extensionKey*: string
    type*: string

type
  LicenseManagerState* {.pure.} = enum
    initializing, normal, marginal, fault
type
  ProfileApplyProfileProperty* = ref object of DynamicData
    propertyName*: string
    array*: bool
    profile*: seq[ApplyProfile]

type
  AlarmSetting* = ref object of DynamicData
    toleranceRange*: int
    reportingFrequency*: int

type
  VirtualMachineRecordReplayState* {.pure.} = enum
    recording, replaying, inactive
type
  AlreadyUpgraded* = ref object of VimFault
  
type
  HostListSummaryQuickStats* = ref object of DynamicData
    overallCpuUsage*: int
    overallMemoryUsage*: int
    distributedCpuFairness*: int
    distributedMemoryFairness*: int
    availablePMemCapacity*: int
    uptime*: int

type
  StorageIORMConfigSpec* = ref object of DynamicData
    enabled*: bool
    congestionThresholdMode*: string
    congestionThreshold*: int
    percentOfPeakThroughput*: int
    statsCollectionEnabled*: bool
    reservationEnabled*: bool
    statsAggregationDisabled*: bool
    reservableIopsThreshold*: int

type
  DistributedVirtualSwitchHostMemberHostComponentState* {.pure.} = enum
    up, pending, outOfSync, warning, disconnected, down
type
  IncorrectFileType* = ref object of FileFault
  
type
  InvalidEvent* = ref object of VimFault
  
type
  ActionParameter* {.pure.} = enum
    targetName, alarmName, oldStatus, newStatus, triggeringSummary, declaringSummary,
    eventDescription, target, alarm
type
  DvsResourceRuntimeInfo* = ref object of DynamicData
    capacity*: int
    usage*: int
    available*: int
    allocatedResource*: seq[DvsVnicAllocatedResource]
    vmVnicNetworkResourcePoolRuntime*: seq[DvsVmVnicNetworkResourcePoolRuntimeInfo]

type
  VmWwnConflictEvent* = ref object of VmEvent
    conflictedVms*: seq[VmEventArgument]
    conflictedHosts*: seq[HostEventArgument]
    wwn*: int64

type
  ComputeResource* = ref object of vim.ManagedEntity
    resourcePool*: ResourcePool
    host*: seq[HostSystem]
    datastore*: seq[Datastore]
    network*: seq[Network]
    summary*: ComputeResourceSummary
    environmentBrowser*: EnvironmentBrowser
    configurationEx*: ComputeResourceConfigInfo

type
  GuestRegKeyWowSpec* {.pure.} = enum
    WOWNative, WOW32, WOW64
type
  SessionManagerVmomiServiceRequestSpec* = ref object of SessionManagerServiceRequestSpec
    method*: string

type
  ListView* = ref object of vim.view.ManagedObjectView
  
type
  VsanUpgradeSystemMissingHostsInClusterIssue* = ref object of VsanUpgradeSystemPreflightCheckIssue
    hosts*: seq[HostSystem]

type
  PhysicalNicLinkInfo* = ref object of DynamicData
    speedMb*: int
    duplex*: bool

type
  VAppPropertyFault* = ref object of VmConfigFault
    id*: string
    category*: string
    label*: string
    type*: string
    value*: string

type
  UserLogoutSessionEvent* = ref object of SessionEvent
    ipAddress*: string
    userAgent*: string
    callCount*: int64
    sessionId*: string
    loginTime*: string

type
  ClusterVmReadiness* = ref object of DynamicData
    readyCondition*: string
    postReadyDelay*: int

type
  VmFailedToPowerOffEvent* = ref object of VmEvent
    reason*: MethodFault

type
  HostIpConfigIpV6AddressStatus* {.pure.} = enum
    preferred, deprecated, invalid, inaccessible, unknown, tentative, duplicate
type
  HostMemberHealthCheckResult* = ref object of DynamicData
    summary*: string

type
  VmStartRecordingEvent* = ref object of VmEvent
  
type
  OvfDiskOrderConstraint* = ref object of OvfConstraint
  
type
  ClusterUsageSummary* = ref object of DynamicData
    totalCpuCapacityMhz*: int
    totalMemCapacityMB*: int
    cpuReservationMhz*: int
    memReservationMB*: int
    poweredOffCpuReservationMhz*: int
    poweredOffMemReservationMB*: int
    cpuDemandMhz*: int
    memDemandMB*: int
    statsGenNumber*: int64
    cpuEntitledMhz*: int
    memEntitledMB*: int
    poweredOffVmCount*: int
    totalVmCount*: int

type
  VMotionInterfaceIssue* = ref object of MigrationFault
    atSourceHost*: bool
    failedHost*: string
    failedHostEntity*: HostSystem

type
  HostScsiTopologyTarget* = ref object of DynamicData
    key*: string
    target*: int
    lun*: seq[HostScsiTopologyLun]
    transport*: HostTargetTransport

type
  VmFailoverFailed* = ref object of VmEvent
    reason*: MethodFault

type
  VAppPropertyInfo* = ref object of DynamicData
    key*: int
    classId*: string
    instanceId*: string
    id*: string
    category*: string
    label*: string
    type*: string
    typeReference*: string
    userConfigurable*: bool
    defaultValue*: string
    value*: string
    description*: string

type
  IoFilterManager* = ref object of vmodl.ManagedObject
  
type
  VirtualMachineProvisioningPolicyPolicy* = ref object of DynamicData
    opType*: string
    powerState*: string
    changeHost*: bool
    changeStorage*: bool
    changeDatacenter*: bool
    action*: string
    failOnError*: bool

type
  HostVMotionManagerSpec* = ref object of DynamicData
    migrationId*: int64
    srcIp*: string
    dstIp*: string
    streamAddresses*: seq[HostVMotionManagerIpAddressSpec]
    srcUuid*: string
    dstUuid*: string
    priority*: VirtualMachineMovePriority
    unsharedSwap*: bool
    type*: string
    faultToleranceType*: string
    diskLocations*: seq[HostVMotionManagerReparentSpec]
    srcLoggingIp*: string
    dstLoggingIp*: string
    ftPrimaryIp*: string
    ftSecondaryIp*: string
    ftStreamAddresses*: seq[HostVMotionManagerIpAddressSpec]
    srcSSLThumbprint*: string
    dstSSLThumbprint*: string
    srcManagementIp*: string
    dstManagementIp*: string
    srcVmPathName*: string
    dstVmDirPath*: string
    dstVmFileName*: string
    layoutSpec*: seq[HostLowLevelProvisioningManagerSnapshotLayoutSpec]
    deviceChange*: seq[VirtualDeviceConfigSpec]
    encryptionNonce*: int64
    encryptionKey*: string

type
  PowerSystemCapability* = ref object of DynamicData
    availablePolicy*: seq[HostPowerPolicy]

type
  SsdDiskNotAvailable* = ref object of VimFault
    devicePath*: string

type
  DVPortConfigSpec* = ref object of DynamicData
    operation*: string
    key*: string
    name*: string
    scope*: seq[ManagedEntity]
    description*: string
    setting*: DVPortSetting
    configVersion*: string

type
  VmfsDatastoreInfo* = ref object of DatastoreInfo
    maxPhysicalRDMFileSize*: int64
    maxVirtualRDMFileSize*: int64
    vmfs*: HostVmfsVolume
    lun*: seq[VmfsDatastoreInfoScsiLunInfo]

type
  LatencySensitivitySensitivityLevel* {.pure.} = enum
    low, normal, medium, high, custom
type
  HostVMotionManagerIpAddressSpec* = ref object of DynamicData
    srcIp*: string
    dstIp*: string

type
  VirtualDiskOptionVFlashCacheConfigOption* = ref object of DynamicData
    cacheConsistencyType*: ChoiceOption
    cacheMode*: ChoiceOption
    reservationInMB*: LongOption
    blockSizeInKB*: LongOption

type
  AlarmDescription* = ref object of DynamicData
    expr*: seq[TypeDescription]
    stateOperator*: seq[ElementDescription]
    metricOperator*: seq[ElementDescription]
    hostSystemConnectionState*: seq[ElementDescription]
    virtualMachinePowerState*: seq[ElementDescription]
    datastoreConnectionState*: seq[ElementDescription]
    hostSystemPowerState*: seq[ElementDescription]
    virtualMachineGuestHeartbeatStatus*: seq[ElementDescription]
    entityStatus*: seq[ElementDescription]
    action*: seq[TypeDescription]

type
  VcAgentUninstalledEvent* = ref object of HostEvent
  
type
  DrsVmMigratedEvent* = ref object of VmMigratedEvent
  
type
  VMFSDatastoreCreatedEvent* = ref object of HostEvent
    datastore*: DatastoreEventArgument
    datastoreUrl*: string

type
  NoSubjectName* = ref object of VimFault
  
type
  NvdimmNamespaceHealthStatus* {.pure.} = enum
    normal, missing, labelMissing, interleaveBroken, labelInconsistent, bttCorrupt,
    badBlockSize
type
  VirtualEthernetCardNetworkBackingInfo* = ref object of VirtualDeviceDeviceBackingInfo
    network*: Network
    inPassthroughMode*: bool

type
  PatchMetadataCorrupted* = ref object of PatchMetadataInvalid
  
type
  DvsIpPortRange* = ref object of DvsIpPort
    startPortNumber*: int
    endPortNumber*: int

type
  HostBootDevice* = ref object of DynamicData
    key*: string
    description*: string

type
  CryptoKeyResult* = ref object of DynamicData
    keyId*: CryptoKeyId
    success*: bool
    reason*: string

type
  OvfXmlFormat* = ref object of OvfInvalidPackage
    description*: string

type
  ClusterProactiveDrsConfigInfo* = ref object of DynamicData
    enabled*: bool

type
  ClusterPowerOnVmResult* = ref object of DynamicData
    attempted*: seq[ClusterAttemptedVmInfo]
    notAttempted*: seq[ClusterNotAttemptedVmInfo]
    recommendations*: seq[ClusterRecommendation]

type
  GenericVmConfigFault* = ref object of VmConfigFault
    reason*: string

type
  OvfNoSupportedHardwareFamily* = ref object of OvfUnsupportedPackage
    version*: string

type
  DataProviderPropertyPredicate* = ref object of DynamicData
    property*: string
    operator*: string
    comparableValue*: pointer
    comparableList*: seq[pointer]
    ignoreCase*: bool

type
  FcoeConfigFcoeSpecification* = ref object of DynamicData
    underlyingPnic*: string
    priorityClass*: int
    sourceMac*: string
    vlanRange*: seq[FcoeConfigVlanRange]

type
  IscsiFaultVnicAlreadyBound* = ref object of IscsiFault
    vnicDevice*: string

type
  VirtualDiskSeSparseBackingOption* = ref object of VirtualDeviceFileBackingOption
    diskMode*: ChoiceOption
    writeThrough*: BoolOption
    growable*: bool
    hotGrowable*: bool
    uuid*: bool
    deltaDiskFormatsSupported*: seq[VirtualDiskDeltaDiskFormatsSupported]

type
  OvfUnsupportedType* = ref object of OvfUnsupportedPackage
    name*: string
    instanceId*: string
    deviceType*: int

type
  MtuMismatchEvent* = ref object of DvsHealthStatusChangeEvent
  
type
  DrsSoftRuleViolationEvent* = ref object of VmEvent
  
type
  HostMountMode* {.pure.} = enum
    readWrite, readOnly
type
  VmwareDistributedVirtualSwitchTrunkVlanSpec* = ref object of VmwareDistributedVirtualSwitchVlanSpec
    vlanId*: seq[NumericRange]

type
  MigrationResourceErrorEvent* = ref object of MigrationEvent
    dstPool*: ResourcePoolEventArgument
    dstHost*: HostEventArgument

type
  LicenseDowngradeDisallowed* = ref object of NotEnoughLicenses
    edition*: string
    entityId*: string
    features*: seq[KeyAnyValue]

type
  HostNumaNode* = ref object of DynamicData
    typeId*: byte
    cpuID*: seq[int16]
    memoryRangeBegin*: int64
    memoryRangeLength*: int64
    pciId*: seq[string]

type
  SoftwarePackageConstraint* {.pure.} = enum
    equals, lessThan, lessThanEqual, greaterThanEqual, greaterThan
type
  IORMNotSupportedHostOnDatastore* = ref object of VimFault
    datastore*: Datastore
    datastoreName*: string
    host*: seq[HostSystem]

type
  HostVFlashManagerVFlashCacheConfigInfoVFlashModuleConfigOption* = ref object of DynamicData
    vFlashModule*: string
    vFlashModuleVersion*: string
    minSupportedModuleVersion*: string
    cacheConsistencyType*: ChoiceOption
    cacheMode*: ChoiceOption
    blockSizeInKBOption*: LongOption
    reservationInMBOption*: LongOption
    maxDiskSizeInKB*: int64

type
  VStorageObjectConsumptionType* {.pure.} = enum
    disk
type
  VmDiskFileInfo* = ref object of FileInfo
    diskType*: string
    capacityKb*: int64
    hardwareVersion*: int
    controllerType*: string
    diskExtents*: seq[string]
    thin*: bool
    encryption*: VmDiskFileEncryptionInfo

type
  HostTpmAttestationInfo* = ref object of DynamicData
    time*: string
    status*: HostTpmAttestationInfoAcceptanceStatus
    message*: LocalizableMessage

type
  VmBeingClonedNoFolderEvent* = ref object of VmCloneEvent
    destName*: string
    destHost*: HostEventArgument

type
  KernelModuleSectionInfo* = ref object of DynamicData
    address*: int64
    length*: int

type
  ReplicationGroupId* = ref object of DynamicData
    faultDomainId*: FaultDomainId
    deviceGroupId*: DeviceGroupId

type
  HbrDiskMigrationAction* = ref object of ClusterAction
    collectionId*: string
    collectionName*: string
    diskIds*: seq[string]
    source*: Datastore
    destination*: Datastore
    sizeTransferred*: int64
    spaceUtilSrcBefore*: float32
    spaceUtilDstBefore*: float32
    spaceUtilSrcAfter*: float32
    spaceUtilDstAfter*: float32
    ioLatencySrcBefore*: float32
    ioLatencyDstBefore*: float32

type
  HostDatastoreSystemVmfsEventType* {.pure.} = enum
    Create, Expand, Extend, Remove, Upgrade
type
  OvfDeploymentOption* = ref object of DynamicData
    key*: string
    label*: string
    description*: string

type
  ComplianceResult* = ref object of DynamicData
    profile*: Profile
    complianceStatus*: string
    entity*: ManagedEntity
    checkTime*: string
    failure*: seq[ComplianceFailure]

type
  NonVmwareOuiMacNotSupportedHost* = ref object of NotSupportedHost
    hostName*: string

type
  SnapshotCopyNotSupported* = ref object of MigrationFault
  
type
  OvfConsumerPowerOnFault* = ref object of InvalidState
    extensionKey*: string
    extensionName*: string
    description*: string

type
  HostServicePolicy* {.pure.} = enum
    on, automatic, off
type
  CustomizationFixedIpV6* = ref object of CustomizationIpV6Generator
    ipAddress*: string
    subnetMask*: int

type
  VMwareDvsLagIpfixConfig* = ref object of DynamicData
    ipfixEnabled*: bool

type
  VmConfigFileInfo* = ref object of FileInfo
    configVersion*: int
    encryption*: VmConfigFileEncryptionInfo

type
  DestinationVsanDisabled* = ref object of CannotMoveVsanEnabledHost
    destinationCluster*: string

type
  GuestRegistryKeyFault* = ref object of GuestRegistryFault
    keyName*: string

type
  AdminPasswordNotChangedEvent* = ref object of HostEvent
  
type
  NetIpStackInfoEntryType* {.pure.} = enum
    other, invalid, dynamic, manual
type
  DatastoreVVolContainerFailoverPair* = ref object of DynamicData
    srcContainer*: string
    tgtContainer*: string
    vvolMapping*: seq[KeyValue]

type
  HostUnresolvedVmfsResignatureSpec* = ref object of DynamicData
    extentDevicePath*: seq[string]

type
  VirtualDevicePipeBackingOption* = ref object of VirtualDeviceBackingOption
  
type
  DvsPortVendorSpecificStateChangeEvent* = ref object of DvsEvent
    portKey*: string

type
  SessionManagerHttpServiceRequestSpec* = ref object of SessionManagerServiceRequestSpec
    method*: string
    url*: string

type
  ClusterDpmConfigInfo* = ref object of DynamicData
    enabled*: bool
    defaultDpmBehavior*: DpmBehavior
    hostPowerActionRate*: int
    option*: seq[OptionValue]

type
  VirtualSerialPortDeviceBackingInfo* = ref object of VirtualDeviceDeviceBackingInfo
  
type
  HostNvdimmSystem* = ref object of vmodl.ManagedObject
    nvdimmSystemInfo*: NvdimmSystemInfo

type
  DrsStatsManager* = ref object of vmodl.ManagedObject
    injectorWorkload*: seq[DrsInjectorWorkload]
    hostIormStatus*: seq[DrsHostIormStatus]

type
  AlarmScriptFailedEvent* = ref object of AlarmEvent
    entity*: ManagedEntityEventArgument
    script*: string
    reason*: MethodFault

type
  GuestProcessInfo* = ref object of DynamicData
    name*: string
    pid*: int64
    owner*: string
    cmdLine*: string
    startTime*: string
    endTime*: string
    exitCode*: int

type
  HostImageConfigManager* = ref object of vmodl.ManagedObject
  
type
  VirtualVmxnet3* = ref object of VirtualVmxnet
  
type
  VirtualDeviceBackingInfo* = ref object of DynamicData
  
type
  HostNoRedundantManagementNetworkEvent* = ref object of HostDasEvent
  
type
  VirtualMachineFileLayoutExSnapshotLayout* = ref object of DynamicData
    key*: VirtualMachineSnapshot
    dataKey*: int
    memoryKey*: int
    disk*: seq[VirtualMachineFileLayoutExDiskLayout]

type
  ClusterVmOrchestrationSpec* = ref object of ArrayUpdateSpec
    info*: ClusterVmOrchestrationInfo

type
  ProfileMetadataProfileOperationMessage* = ref object of DynamicData
    operationName*: string
    message*: LocalizableMessage

type
  EventDescription* = ref object of DynamicData
    category*: seq[ElementDescription]
    eventInfo*: seq[EventDescriptionEventDetail]
    enumeratedTypes*: seq[EnumDescription]

type
  HostActiveDirectoryAuthenticationCertificateDigest* {.pure.} = enum
    SHA1
type
  ClusterComputeResourceFtCompatibleDatastoresResult* = ref object of DynamicData
    primaryHost*: HostSystem
    compatibleFtMetadataDatastores*: seq[Datastore]
    compatibleFtSecondaryConfigDatastores*: seq[Datastore]
    compatibleFtSecondaryDiskDatastores*: seq[Datastore]

type
  HealthUpdateInfoComponentType* {.pure.} = enum
    Memory, Power, Fan, Network, Storage
type
  InsufficientPerCpuCapacity* = ref object of InsufficientHostCapacityFault
  
type
  VwirePort* = ref object of DynamicData
    port*: DistributedVirtualSwitchPortConnection
    connectee*: DistributedVirtualSwitchPortConnectee

type
  GuestInfo* = ref object of DynamicData
    toolsStatus*: VirtualMachineToolsStatus
    toolsVersionStatus*: string
    toolsVersionStatus2*: string
    toolsRunningStatus*: string
    toolsVersion*: string
    toolsInstallType*: string
    toolsUpdateStatus*: VirtualMachineToolsUpdateStatus
    guestId*: string
    guestFamily*: string
    guestFullName*: string
    hostName*: string
    ipAddress*: string
    net*: seq[GuestNicInfo]
    ipStack*: seq[GuestStackInfo]
    disk*: seq[GuestDiskInfo]
    screen*: GuestScreenInfo
    guestState*: string
    powerPolicy*: VirtualMachinePowerPolicy
    appHeartbeatStatus*: string
    guestKernelCrashed*: bool
    appState*: string
    guestOperationsReady*: bool
    interactiveGuestOperationsReady*: bool
    guestStateChangeSupported*: bool
    generationInfo*: seq[GuestInfoNamespaceGenerationInfo]

type
  DvsPortDeletedEvent* = ref object of DvsEvent
    portKey*: seq[string]

type
  NumPortsProfile* = ref object of ApplyProfile
  
type
  HttpFault* = ref object of VimFault
    statusCode*: int
    statusMessage*: string

type
  HostSpecificationAgent* = ref object of vmodl.ManagedObject
  
type
  SecondaryVmAlreadyDisabled* = ref object of VmFaultToleranceIssue
    instanceUuid*: string

type
  MismatchedBundle* = ref object of VimFault
    bundleUuid*: string
    hostUuid*: string
    bundleBuildNumber*: int
    hostBuildNumber*: int

type
  RDMNotPreserved* = ref object of MigrationFault
    device*: string

type
  HostVFlashManagerVFlashCacheConfigInfo* = ref object of DynamicData
    vFlashModuleConfigOption*: seq[HostVFlashManagerVFlashCacheConfigInfoVFlashModuleConfigOption]
    defaultVFlashModule*: string
    swapCacheReservationInGB*: int64

type
  CustomizationPending* = ref object of CustomizationFault
  
type
  VmSecondaryDisabledEvent* = ref object of VmEvent
  
type
  AutoStartPowerInfo* = ref object of DynamicData
    key*: VirtualMachine
    startOrder*: int
    startDelay*: int
    waitForHeartbeat*: AutoStartWaitHeartbeatSetting
    startAction*: string
    stopDelay*: int
    stopAction*: string

type
  NvdimmSummary* = ref object of DynamicData
    numDimms*: int
    healthStatus*: string
    totalCapacity*: int64
    persistentCapacity*: int64
    blockCapacity*: int64
    availableCapacity*: int64
    numInterleavesets*: int
    numNamespaces*: int

type
  OvfOptionInfo* = ref object of DynamicData
    option*: string
    description*: LocalizableMessage

type
  DVSVmVnicNetworkResourcePool* = ref object of DynamicData
    key*: string
    name*: string
    description*: string
    configVersion*: string
    allocationInfo*: DvsVmVnicResourceAllocation

type
  PlacementSpecPlacementType* {.pure.} = enum
    create, reconfigure, relocate, clone
type
  ProfileHostProfileEngineHostProfileManager* = ref object of vmodl.ManagedObject
  
type
  SnapshotRevertIssue* = ref object of MigrationFault
    snapshotName*: string
    event*: seq[Event]
    errors*: bool

type
  PolicyViolatedValueTooSmall* = ref object of PolicyViolatedByValue
    policyValue*: pointer

type
  GuestFileInfo* = ref object of DynamicData
    path*: string
    type*: string
    size*: int64
    attributes*: GuestFileAttributes

type
  DataProviderBatchQuerySpec* = ref object of DynamicData
    querySpecs*: seq[DataProviderQuerySpec]

type
  VirtualDevicePipeBackingInfo* = ref object of VirtualDeviceBackingInfo
    pipeName*: string

type
  EventHistoryCollector* = ref object of vim.HistoryCollector
    latestPage*: seq[Event]

type
  HostProfileMappingLookupMappingPair* = ref object of DynamicData
    sourcePath*: string
    targetProfilePath*: string

type
  DVPortgroupPolicy* = ref object of DynamicData
    blockOverrideAllowed*: bool
    shapingOverrideAllowed*: bool
    vendorConfigOverrideAllowed*: bool
    livePortMovingAllowed*: bool
    portConfigResetAtDisconnect*: bool
    networkResourcePoolOverrideAllowed*: bool
    trafficFilterOverrideAllowed*: bool

type
  VMwareUplinkLacpPolicy* = ref object of InheritablePolicy
    enable*: BoolPolicy
    mode*: StringPolicy

type
  ClusterDasDataDetails* = ref object of ClusterDasDataSummary
    hostList*: ClusterVersionedStringData
    clusterConfig*: ClusterVersionedBinaryData
    compatList*: ClusterVersionedBinaryData

type
  PolicyViolatedValueNotEqual* = ref object of PolicyViolatedByValue
    policyValue*: pointer

type
  VirtualDiskSpec* = ref object of DynamicData
    diskType*: string
    adapterType*: string

type
  VAppOvfSectionInfo* = ref object of DynamicData
    key*: int
    namespace*: string
    type*: string
    atEnvelopeLevel*: bool
    contents*: string

type
  ClusterComputeResource* = ref object of vim.ComputeResource
    configuration*: ClusterConfigInfo
    recommendation*: seq[ClusterRecommendation]
    drsRecommendation*: seq[ClusterDrsRecommendation]
    migrationHistory*: seq[ClusterDrsMigration]
    actionHistory*: seq[ClusterActionHistory]
    drsFault*: seq[ClusterDrsFaults]

type
  UserSession* = ref object of DynamicData
    key*: string
    userName*: string
    fullName*: string
    loginTime*: string
    lastActiveTime*: string
    locale*: string
    messageLocale*: string
    extensionSession*: bool
    ipAddress*: string
    userAgent*: string
    callCount*: int64

type
  VmSnapshotFileQuery* = ref object of FileQuery
  
type
  HostFeatureVersionInfo* = ref object of DynamicData
    key*: string
    value*: string

type
  SharesInfo* = ref object of DynamicData
    shares*: int
    level*: SharesLevel

type
  PodDiskLocator* = ref object of DynamicData
    diskId*: int
    diskMoveType*: string
    diskBackingInfo*: VirtualDeviceBackingInfo
    profile*: seq[VirtualMachineProfileSpec]

type
  LicenseServerUnavailable* = ref object of VimFault
    licenseServer*: string

type
  HostDateTimeSystemTimeZone* = ref object of DynamicData
    key*: string
    name*: string
    description*: string
    gmtOffset*: int

type
  IsoImageFileQuery* = ref object of FileQuery
  
type
  ClusterDasAdvancedRuntimeInfoVmcpCapabilityInfo* = ref object of DynamicData
    storageAPDSupported*: bool
    storagePDLSupported*: bool

type
  OvfUnsupportedPackage* = ref object of OvfFault
    lineNumber*: int

type
  MacContainer* = ref object of MacAddress
    containerId*: string

type
  DvsFault* = ref object of VimFault
  
type
  HostBootDeviceInfo* = ref object of DynamicData
    bootDevices*: seq[HostBootDevice]
    currentBootDeviceKey*: string

type
  GeneralHostErrorEvent* = ref object of GeneralEvent
  
type
  HostUnresolvedVmfsResolutionResult* = ref object of DynamicData
    spec*: HostUnresolvedVmfsResolutionSpec
    vmfs*: HostVmfsVolume
    fault*: MethodFault

type
  NetIpConfigInfoIpAddress* = ref object of DynamicData
    ipAddress*: string
    prefixLength*: int
    origin*: string
    state*: string
    lifetime*: string

type
  HostFeatureCapability* = ref object of DynamicData
    key*: string
    featureName*: string
    value*: string

type
  VirtualDeviceFileBackingInfo* = ref object of VirtualDeviceBackingInfo
    fileName*: string
    datastore*: Datastore
    backingObjectId*: string

type
  NfcService* = ref object of vmodl.ManagedObject
  
type
  HostSystemDebugManagerProcessInfo* = ref object of DynamicData
    processKey*: string
    uptime*: int64
    virtualMemSize*: int64
    pid*: seq[int64]
    cpuTime*: int64
    cpuPercentage*: int64

type
  InvalidDeviceBacking* = ref object of InvalidDeviceSpec
  
type
  HostVvolVolumeSpecification* = ref object of DynamicData
    maxSizeInMB*: int64
    volumeName*: string
    vasaProviderInfo*: seq[VimVasaProviderInfo]
    storageArray*: seq[VASAStorageArray]
    uuid*: string

type
  CustomizationSysprep* = ref object of CustomizationIdentitySettings
    guiUnattended*: CustomizationGuiUnattended
    userData*: CustomizationUserData
    guiRunOnce*: CustomizationGuiRunOnce
    identification*: CustomizationIdentification
    licenseFilePrintData*: CustomizationLicenseFilePrintData

type
  VirtualMachineVMCIDeviceOptionFilterSpecOption* = ref object of DynamicData
    action*: ChoiceOption
    protocol*: ChoiceOption
    direction*: ChoiceOption
    lowerDstPortBoundary*: LongOption
    upperDstPortBoundary*: LongOption

type
  LicenseExpired* = ref object of NotEnoughLicenses
    licenseKey*: string

type
  NvdimmNamespaceCreateSpec* = ref object of DynamicData
    friendlyName*: string
    blockSize*: int64
    blockCount*: int64
    type*: string
    locationID*: int

type
  HostNetworkConfig* = ref object of DynamicData
    vswitch*: seq[HostVirtualSwitchConfig]
    proxySwitch*: seq[HostProxySwitchConfig]
    portgroup*: seq[HostPortGroupConfig]
    pnic*: seq[PhysicalNicConfig]
    vnic*: seq[HostVirtualNicConfig]
    consoleVnic*: seq[HostVirtualNicConfig]
    dnsConfig*: HostDnsConfig
    ipRouteConfig*: HostIpRouteConfig
    consoleIpRouteConfig*: HostIpRouteConfig
    routeTableConfig*: HostIpRouteTableConfig
    dhcp*: seq[HostDhcpServiceConfig]
    nat*: seq[HostNatServiceConfig]
    ipV6Enabled*: bool
    netStackSpec*: seq[HostNetworkConfigNetStackSpec]

type
  HostVirtualSwitchBeaconConfig* = ref object of DynamicData
    interval*: int

type
  VmMacChangedEvent* = ref object of VmEvent
    adapter*: string
    oldMac*: string
    newMac*: string

type
  MultiWriterNotSupported* = ref object of DeviceNotSupported
  
type
  ProfileMetadataProfileSortSpec* = ref object of DynamicData
    policyId*: string
    parameter*: string

type
  GatewayConnectFault* = ref object of HostConnectFault
    gatewayType*: string
    gatewayId*: string
    gatewayInfo*: string
    details*: LocalizableMessage

type
  SimpleCommand* = ref object of vmodl.ManagedObject
    encodingType*: SimpleCommandEncoding
    entity*: ServiceManagerServiceInfo

type
  UnsharedSwapVMotionNotSupported* = ref object of MigrationFeatureNotSupported
  
type
  GuestProcessManager* = ref object of vmodl.ManagedObject
  
type
  VMwareVspanPort* = ref object of DynamicData
    portKey*: seq[string]
    uplinkPortName*: seq[string]
    wildcardPortConnecteeType*: seq[string]
    vlans*: seq[int]
    ipAddress*: seq[string]

type
  HostHardwareInfo* = ref object of DynamicData
    systemInfo*: HostSystemInfo
    cpuPowerManagementInfo*: HostCpuPowerManagementInfo
    cpuInfo*: HostCpuInfo
    cpuPkg*: seq[HostCpuPackage]
    memorySize*: int64
    numaInfo*: HostNumaInfo
    smcPresent*: bool
    pciDevice*: seq[HostPciDevice]
    cpuFeature*: seq[HostCpuIdInfo]
    biosInfo*: HostBIOSInfo
    reliableMemoryInfo*: HostReliableMemoryInfo
    persistentMemoryInfo*: HostPersistentMemoryInfo

type
  NonADUserRequired* = ref object of ActiveDirectoryFault
  
type
  OvfUnknownEntity* = ref object of OvfSystemFault
    lineNumber*: int

type
  VirtualDeviceConfigSpec* = ref object of DynamicData
    operation*: VirtualDeviceConfigSpecOperation
    fileOperation*: VirtualDeviceConfigSpecFileOperation
    device*: VirtualDevice
    profile*: seq[VirtualMachineProfileSpec]
    backing*: VirtualDeviceConfigSpecBackingSpec

type
  DvsTrafficRuleset* = ref object of DynamicData
    key*: string
    enabled*: bool
    precedence*: int
    rules*: seq[DvsTrafficRule]

type
  SnapshotMoveNotSupported* = ref object of SnapshotCopyNotSupported
  
type
  VirtualDiskOption* = ref object of VirtualDeviceOption
    capacityInKB*: LongOption
    ioAllocationOption*: StorageIOAllocationOption
    vFlashCacheConfigOption*: VirtualDiskOptionVFlashCacheConfigOption

type
  NoLicenseServerConfigured* = ref object of NotEnoughLicenses
  
type
  IpPoolAssociation* = ref object of DynamicData
    network*: Network
    networkName*: string

type
  ClusterDrsVmConfigInfo* = ref object of DynamicData
    key*: VirtualMachine
    enabled*: bool
    behavior*: DrsBehavior

type
  EventFilterSpecByEntity* = ref object of DynamicData
    entity*: ManagedEntity
    recursion*: EventFilterSpecRecursionOption

type
  GuestInfoAppStateType* {.pure.} = enum
    none, appStateOk, appStateNeedReset
type
  DiagnosticManager* = ref object of vmodl.ManagedObject
  
type
  ExtExtendedProductInfo* = ref object of DynamicData
    companyUrl*: string
    productUrl*: string
    managementUrl*: string
    self*: ManagedEntity

type
  VirtualDiskPartitionedRawDiskVer2BackingInfo* = ref object of VirtualDiskRawDiskVer2BackingInfo
    partition*: seq[int]

type
  CustomizationGlobalIPSettings* = ref object of DynamicData
    dnsSuffixList*: seq[string]
    dnsServerList*: seq[string]

type
  NASDatastoreCreatedEvent* = ref object of HostEvent
    datastore*: DatastoreEventArgument
    datastoreUrl*: string

type
  PatchIntegrityError* = ref object of PlatformConfigFault
  
type
  StoragePerformanceSummary* = ref object of DynamicData
    interval*: int
    percentile*: seq[int]
    datastoreReadLatency*: seq[float64]
    datastoreWriteLatency*: seq[float64]
    datastoreVmLatency*: seq[float64]
    datastoreReadIops*: seq[float64]
    datastoreWriteIops*: seq[float64]
    siocActivityDuration*: int

type
  OpaqueNetworkCapability* = ref object of DynamicData
    networkReservationSupported*: bool

type
  ReplicationInfoDiskSettings* = ref object of DynamicData
    key*: int
    diskReplicationId*: string

type
  InvalidPrivilege* = ref object of VimFault
    privilege*: string

type
  UnableToPlaceAtomicVmGroup* = ref object of VimFault
  
type
  HostHasComponentFailureHostComponentType* {.pure.} = enum
    Datastore
type
  DvsTrafficFilterConfigSpec* = ref object of DvsTrafficFilterConfig
    operation*: string

type
  DisallowedChangeByService* = ref object of RuntimeFault
    serviceName*: string
    disallowedChange*: string

type
  PassiveNodeNetworkSpec* = ref object of NodeNetworkSpec
    failoverIpSettings*: CustomizationIPSettings

type
  ScheduledTaskSpec* = ref object of DynamicData
    name*: string
    description*: string
    enabled*: bool
    scheduler*: TaskScheduler
    action*: Action
    notification*: string

type
  HostProfilePolicyOptionMappingPolicyOptionMappingData* = ref object of HostProfileMappingData
  
type
  MultipleSnapshotsNotSupported* = ref object of SnapshotFault
  
type
  HostMountInfo* = ref object of DynamicData
    path*: string
    accessMode*: string
    mounted*: bool
    accessible*: bool
    inaccessibleReason*: string

type
  DatastoreCapacityIncreasedEvent* = ref object of DatastoreEvent
    oldCapacity*: int64
    newCapacity*: int64

type
  HostIpChangedEvent* = ref object of HostEvent
    oldIP*: string
    newIP*: string

type
  VirtualMachineUsbInfoSpeed* {.pure.} = enum
    low, full, high, superSpeed, unknownSpeed
type
  DvsOperationBulkFaultFaultOnHost* = ref object of DynamicData
    host*: HostSystem
    fault*: MethodFault

type
  StorageVMotionNotSupported* = ref object of MigrationFeatureNotSupported
  
type
  VirtualSerialPortDeviceBackingOption* = ref object of VirtualDeviceDeviceBackingOption
  
type
  DatastoreMountPathDatastorePair* = ref object of DynamicData
    oldMountPath*: string
    datastore*: Datastore

type
  OvfConnectedDeviceFloppy* = ref object of OvfConnectedDevice
    filename*: string

type
  DVSFeatureCapability* = ref object of DynamicData
    networkResourceManagementSupported*: bool
    vmDirectPathGen2Supported*: bool
    nicTeamingPolicy*: seq[string]
    networkResourcePoolHighShareValue*: int
    networkResourceManagementCapability*: DVSNetworkResourceManagementCapability
    healthCheckCapability*: DVSHealthCheckCapability
    rollbackCapability*: DVSRollbackCapability
    backupRestoreCapability*: DVSBackupRestoreCapability
    networkFilterSupported*: bool
    macLearningSupported*: bool

type
  RDMNotSupported* = ref object of DeviceNotSupported
  
type
  EventFilterSpecByTime* = ref object of DynamicData
    beginTime*: string
    endTime*: string

type
  VirtualMachineMovePriority* {.pure.} = enum
    lowPriority, highPriority, defaultPriority
type
  VmToolsUpgradeFault* = ref object of VimFault
  
type
  VFlashModuleNotSupported* = ref object of VmConfigFault
    vmName*: string
    moduleName*: string
    reason*: string
    hostName*: string

type
  VmCreatedEvent* = ref object of VmEvent
  
type
  MessageBusProxy* = ref object of vmodl.ManagedObject
  
type
  VirtualDiskRawDiskVer2BackingOption* = ref object of VirtualDeviceDeviceBackingOption
    descriptorFileNameExtensions*: ChoiceOption
    uuid*: bool

type
  MksConnectionLimitReached* = ref object of InvalidState
    connectionLimit*: int

type
  HostServiceSystem* = ref object of vim.ExtensibleManagedObject
    serviceInfo*: HostServiceInfo

type
  FileManager* = ref object of vmodl.ManagedObject
  
type
  DvsRateLimitNetworkRuleAction* = ref object of DvsNetworkRuleAction
    packetsPerSecond*: int

type
  DrsCorrelationPair* = ref object of DynamicData
    key*: int
    datastore*: Datastore

type
  DataProviderResourceItem* = ref object of DynamicData
    propertyValues*: seq[DataProviderOptionalPropertyValue]

type
  HostAuthenticationManager* = ref object of vmodl.ManagedObject
    info*: HostAuthenticationManagerInfo
    supportedStore*: seq[HostAuthenticationStore]

type
  VirtualMachineRuntimeInfoDasProtectionState* = ref object of DynamicData
    dasProtected*: bool

type
  VmFaultToleranceTurnedOffEvent* = ref object of VmEvent
  
type
  StorageDrsCannotMoveManuallyPlacedVm* = ref object of VimFault
  
type
  CustomizationGuiUnattended* = ref object of DynamicData
    password*: CustomizationPassword
    timeZone*: int
    autoLogon*: bool
    autoLogonCount*: int

type
  VirtualSoundCard* = ref object of VirtualDevice
  
type
  LinkProfile* = ref object of ApplyProfile
  
type
  PerfEntityMetricBase* = ref object of DynamicData
    entity*: ManagedObject

type
  NotSupportedHostForVFlash* = ref object of NotSupportedHost
    hostName*: string

type
  VirtualMachineIdeDiskDeviceInfo* = ref object of VirtualMachineDiskDeviceInfo
    partitionTable*: seq[VirtualMachineIdeDiskDevicePartitionInfo]

type
  PassiveNodeDeploymentSpec* = ref object of NodeDeploymentSpec
    failoverIpSettings*: CustomizationIPSettings

type
  VmFaultToleranceInvalidFileBacking* = ref object of VmFaultToleranceIssue
    backingType*: string
    backingFilename*: string

type
  TaskFilterSpecTimeOption* {.pure.} = enum
    queuedTime, startedTime, completedTime
type
  WorkflowStepHandler* = ref object of vmodl.ManagedObject
  
type
  VmAutoRenameEvent* = ref object of VmEvent
    oldName*: string
    newName*: string

type
  ClusterHostRecommendation* = ref object of DynamicData
    host*: HostSystem
    rating*: int

type
  HttpNfcLeaseDatastoreLeaseInfo* = ref object of DynamicData
    datastoreKey*: string
    hosts*: seq[HttpNfcLeaseHostInfo]

type
  HostVFlashManagerVFlashCacheConfigSpec* = ref object of DynamicData
    defaultVFlashModule*: string
    swapCacheReservationInGB*: int64

type
  ProfileApplyProfileElement* = ref object of ApplyProfile
    key*: string

type
  ClusterAction* = ref object of DynamicData
    type*: string
    target*: ManagedObject

type
  MigrationFault* = ref object of VimFault
  
type
  VmBeingDeployedEvent* = ref object of VmEvent
    srcTemplate*: VmEventArgument

type
  FailoverNodeInfo* = ref object of DynamicData
    clusterIpSettings*: CustomizationIPSettings
    failoverIp*: CustomizationIPSettings
    biosUuid*: string

type
  ClusterOrchestrationInfo* = ref object of DynamicData
    defaultVmReadiness*: ClusterVmReadiness

type
  AutoStartWaitHeartbeatSetting* {.pure.} = enum
    yes, no, systemDefault
type
  TaskDescription* = ref object of DynamicData
    methodInfo*: seq[ElementDescription]
    state*: seq[ElementDescription]
    reason*: seq[TypeDescription]

type
  NetIpRouteConfigSpecGatewaySpec* = ref object of DynamicData
    ipAddress*: string
    device*: string

type
  VAppConfigInfo* = ref object of VmConfigInfo
    entityConfig*: seq[VAppEntityConfigInfo]
    annotation*: string
    instanceUuid*: string
    managedBy*: ManagedByInfo

type
  VirtualDeviceConfigSpecFileOperation* {.pure.} = enum
    create, destroy, replace
type
  InvalidDeviceOperation* = ref object of InvalidDeviceSpec
    badOp*: VirtualDeviceConfigSpecOperation
    badFileOp*: VirtualDeviceConfigSpecFileOperation

type
  HostDiskPartitionSpec* = ref object of DynamicData
    partitionFormat*: string
    chs*: HostDiskDimensionsChs
    totalSectors*: int64
    partition*: seq[HostDiskPartitionAttributes]

type
  HostConfigChange* = ref object of DynamicData
  
type
  TooManyNativeClonesOnFile* = ref object of FileFault
  
type
  HostSystemSwapConfigurationSystemSwapOption* = ref object of DynamicData
    key*: int

type
  UsbScanCodeSpec* = ref object of DynamicData
    keyEvents*: seq[UsbScanCodeSpecKeyEvent]

type
  VmfsDatastoreInfoScsiLunInfo* = ref object of DynamicData
    key*: string
    canonicalName*: string
    uuid*: string

type
  KernelModuleInfo* = ref object of DynamicData
    id*: int
    name*: string
    version*: string
    filename*: string
    optionString*: string
    loaded*: bool
    enabled*: bool
    useCount*: int
    readOnlySection*: KernelModuleSectionInfo
    writableSection*: KernelModuleSectionInfo
    textSection*: KernelModuleSectionInfo
    dataSection*: KernelModuleSectionInfo
    bssSection*: KernelModuleSectionInfo

type
  VirtualMachineFileLayout* = ref object of DynamicData
    configFile*: seq[string]
    logFile*: seq[string]
    disk*: seq[VirtualMachineFileLayoutDiskLayout]
    snapshot*: seq[VirtualMachineFileLayoutSnapshotLayout]
    swapFile*: string

type
  HostVfatVolume* = ref object of HostFileSystemVolume
  
type
  VchaClusterMode* {.pure.} = enum
    enabled, disabled, maintenance
type
  OvfConsumerCommunicationError* = ref object of OvfConsumerCallbackFault
    description*: string

type
  ClusterDasVmSettings* = ref object of DynamicData
    restartPriority*: string
    restartPriorityTimeout*: int
    isolationResponse*: string
    vmToolsMonitoringSettings*: ClusterVmToolsMonitoringSettings
    vmComponentProtectionSettings*: ClusterVmComponentProtectionSettings

type
  NotADirectory* = ref object of FileFault
  
type
  VirtualIDEControllerOption* = ref object of VirtualControllerOption
    numIDEDisks*: IntOption
    numIDECdroms*: IntOption

type
  HostNicFailureCriteria* = ref object of DynamicData
    checkSpeed*: string
    speed*: int
    checkDuplex*: bool
    fullDuplex*: bool
    checkErrorPercent*: bool
    percentage*: int
    checkBeacon*: bool

type
  HostNicTeamingPolicy* = ref object of DynamicData
    policy*: string
    reversePolicy*: bool
    notifySwitches*: bool
    rollingOrder*: bool
    failureCriteria*: HostNicFailureCriteria
    nicOrder*: HostNicOrderPolicy

type
  DasAdmissionControlDisabledEvent* = ref object of ClusterEvent
  
type
  StorageDrsPodConfigSpec* = ref object of DynamicData
    enabled*: bool
    ioLoadBalanceEnabled*: bool
    defaultVmBehavior*: string
    loadBalanceInterval*: int
    defaultIntraVmAffinity*: bool
    spaceLoadBalanceConfig*: StorageDrsSpaceLoadBalanceConfig
    ioLoadBalanceConfig*: StorageDrsIoLoadBalanceConfig
    automationOverrides*: StorageDrsAutomationConfig
    rule*: seq[ClusterRuleSpec]
    option*: seq[StorageDrsOptionSpec]

type
  Folder* = ref object of vim.ManagedEntity
    childType*: seq[string]
    childEntity*: seq[ManagedEntity]

type
  HostIpRouteOp* = ref object of DynamicData
    changeOperation*: string
    route*: HostIpRouteEntry

type
  VmFaultToleranceConfigIssueReasonForIssue* {.pure.} = enum
    haNotEnabled, moreThanOneSecondary, recordReplayNotSupported,
    replayNotSupported, templateVm, multipleVCPU, hostInactive,
    ftUnsupportedHardware, ftUnsupportedProduct, missingVMotionNic,
    missingFTLoggingNic, thinDisk, verifySSLCertificateFlagNotSet, hasSnapshots,
    noConfig, ftSecondaryVm, hasLocalDisk, esxAgentVm, video3dEnabled,
    hasUnsupportedDisk, insufficientBandwidth, hasNestedHVConfiguration,
    hasVFlashConfiguration, unsupportedProduct, cpuHvUnsupported,
    cpuHwmmuUnsupported, cpuHvDisabled, hasEFIFirmware, tooManyVCPUs, tooMuchMemory
type
  DisallowedMigrationDeviceAttached* = ref object of MigrationFault
    fault*: MethodFault

type
  DeploymentInfo* = ref object of vmodl.ManagedObject
    pscNodes*: seq[DeploymentInfoServiceInfo]
    hostName*: string

type
  LicenseManagerLicenseInfo* = ref object of DynamicData
    licenseKey*: string
    editionKey*: string
    name*: string
    total*: int
    used*: int
    costUnit*: string
    properties*: seq[KeyAnyValue]
    labels*: seq[KeyValue]

type
  VmFaultToleranceIssue* = ref object of VimFault
  
type
  CannotPowerOffVmInClusterOperation* {.pure.} = enum
    suspend, powerOff, guestShutdown, guestSuspend
type
  DVPortNotSupported* = ref object of DeviceBackingNotSupported
  
type
  HostTpmEventDetails* = ref object of DynamicData
    dataHash*: seq[byte]
    dataHashMethod*: string

type
  VmwareDistributedVirtualSwitch* = ref object of vim.DistributedVirtualSwitch
  
type
  HostDiagnosticSystem* = ref object of vmodl.ManagedObject
    activePartition*: HostDiagnosticPartition

type
  OnceTaskScheduler* = ref object of TaskScheduler
    runAt*: string

type
  LicenseServerAvailableEvent* = ref object of LicenseEvent
    licenseServer*: string

type
  ProfileParameterMetadataRelationType* {.pure.} = enum
    dynamic_relation, extensible_relation, localizable_relation, static_relation,
    validation_relation
type
  DvsVNicProfile* = ref object of ApplyProfile
    key*: string
    ipConfig*: IpAddressProfile

type
  MigrationHostErrorEvent* = ref object of MigrationEvent
    dstHost*: HostEventArgument

type
  DVSOpaqueCommandData* = ref object of DynamicData
    opaqueData*: byte

type
  ScheduledTaskDetail* = ref object of TypeDescription
    frequency*: string

type
  DVPortStatusVmDirectPathGen2InactiveReasonOther* {.pure.} = enum
    portNptIncompatibleHost, portNptIncompatibleConnectee
type
  OvfHardwareExport* = ref object of OvfExport
    device*: VirtualDevice
    vmPath*: string

type
  HostMultipathStateInfoPath* = ref object of DynamicData
    name*: string
    pathState*: string

type
  VirtualSriovEthernetCard* = ref object of VirtualEthernetCard
    allowGuestOSMtuChange*: bool
    sriovBacking*: VirtualSriovEthernetCardSriovBackingInfo

type
  DigestNotSupported* = ref object of DeviceNotSupported
  
type
  DvsMacNetworkRuleQualifier* = ref object of DvsNetworkRuleQualifier
    sourceAddress*: MacAddress
    destinationAddress*: MacAddress
    protocol*: IntExpression
    vlanId*: IntExpression

type
  ClusterIncreaseCpuCapacityAction* = ref object of ClusterAction
    delta*: int
    numCpus*: int

type
  HostInternetScsiHba* = ref object of HostHostBusAdapter
    isSoftwareBased*: bool
    canBeDisabled*: bool
    networkBindingSupport*: HostInternetScsiHbaNetworkBindingSupportType
    discoveryCapabilities*: HostInternetScsiHbaDiscoveryCapabilities
    discoveryProperties*: HostInternetScsiHbaDiscoveryProperties
    authenticationCapabilities*: HostInternetScsiHbaAuthenticationCapabilities
    authenticationProperties*: HostInternetScsiHbaAuthenticationProperties
    digestCapabilities*: HostInternetScsiHbaDigestCapabilities
    digestProperties*: HostInternetScsiHbaDigestProperties
    ipCapabilities*: HostInternetScsiHbaIPCapabilities
    ipProperties*: HostInternetScsiHbaIPProperties
    supportedAdvancedOptions*: seq[OptionDef]
    advancedOptions*: seq[HostInternetScsiHbaParamValue]
    iScsiName*: string
    iScsiAlias*: string
    configuredSendTarget*: seq[HostInternetScsiHbaSendTarget]
    configuredStaticTarget*: seq[HostInternetScsiHbaStaticTarget]
    maxSpeedMb*: int
    currentSpeedMb*: int

type
  OvfUnsupportedDiskProvisioning* = ref object of OvfImport
    diskProvisioning*: string
    supportedDiskProvisioning*: string

type
  VirtualMachineBackupEventInfo* = ref object of DynamicData
    eventType*: string
    code*: int64
    message*: string

type
  HostTpmBootSecurityOptionEventDetails* = ref object of HostTpmEventDetails
    bootSecurityOption*: string

type
  ProfileNumericComparator* {.pure.} = enum
    lessThan, lessThanEqual, equal, notEqual, greaterThanEqual, greaterThan
type
  ClusterDasHostInfo* = ref object of DynamicData
  
type
  DatastoreRenamedOnHostEvent* = ref object of HostEvent
    oldName*: string
    newName*: string

type
  DatastoreHostMount* = ref object of DynamicData
    key*: HostSystem
    mountInfo*: HostMountInfo

type
  OvfUnexpectedElement* = ref object of OvfElement
  
type
  DvsPortLeavePortgroupEvent* = ref object of DvsEvent
    portKey*: string
    portgroupKey*: string
    portgroupName*: string

type
  PhysicalNicConfig* = ref object of DynamicData
    device*: string
    spec*: PhysicalNicSpec

type
  HostMemberSelection* = ref object of SelectionSet
    dvsUuid*: string
    host*: HostSystem

type
  StorageDrsUnableToMoveFiles* = ref object of VimFault
  
type
  StorageIORMDeviceModel* = ref object of DynamicData
    lqSlope*: float64
    lqIntercept*: float64

type
  VsanUpgradeSystemAPIBrokenIssue* = ref object of VsanUpgradeSystemPreflightCheckIssue
    hosts*: seq[HostSystem]

type
  VirtualDiskRawDiskVer2BackingInfo* = ref object of VirtualDeviceDeviceBackingInfo
    descriptorFileName*: string
    uuid*: string
    changeId*: string
    sharing*: string

type
  HostDistributedVirtualSwitchManager* = ref object of vmodl.ManagedObject
    distributedVirtualSwitch*: seq[string]

type
  ServiceLocatorCredential* = ref object of DynamicData
  
type
  FcoeConfigVlanRange* = ref object of DynamicData
    vlanLow*: int
    vlanHigh*: int

type
  VirtualDeviceBusSlotOption* = ref object of DynamicData
    type*: string

type
  OvfNetworkMappingNotSupported* = ref object of OvfImport
  
type
  VmConfigIncompatibleForRecordReplay* = ref object of VmConfigFault
    fault*: MethodFault

type
  AlreadyAuthenticatedSessionEvent* = ref object of SessionEvent
  
type
  DVSContactInfo* = ref object of DynamicData
    name*: string
    contact*: string

type
  DistributedVirtualPortgroupMetaTagName* {.pure.} = enum
    dvsName, portgroupName, portIndex
type
  HostDhcpServiceConfig* = ref object of DynamicData
    changeOperation*: string
    key*: string
    spec*: HostDhcpServiceSpec

type
  VirtualMachineMetadataManagerVmMetadataOp* {.pure.} = enum
    Update, Remove
type
  HostDatastoreConnectInfo* = ref object of DynamicData
    summary*: DatastoreSummary

type
  VirtualSriovEthernetCardSriovBackingInfo* = ref object of VirtualDeviceBackingInfo
    physicalFunctionBacking*: VirtualPCIPassthroughDeviceBackingInfo
    virtualFunctionBacking*: VirtualPCIPassthroughDeviceBackingInfo
    virtualFunctionIndex*: int

type
  EventAlarmExpressionComparisonOperator* {.pure.} = enum
    equals, notEqualTo, startsWith, doesNotStartWith, endsWith, doesNotEndWith
type
  Datacenter* = ref object of vim.ManagedEntity
    vmFolder*: Folder
    hostFolder*: Folder
    datastoreFolder*: Folder
    networkFolder*: Folder
    datastore*: seq[Datastore]
    network*: seq[Network]
    configuration*: DatacenterConfigInfo

type
  VirtualKeyboard* = ref object of VirtualDevice
  
type
  VirtualDiskDeltaDiskFormat* {.pure.} = enum
    redoLogFormat, nativeFormat, seSparseFormat
type
  GuestFileManager* = ref object of vmodl.ManagedObject
  
type
  TooManyWrites* = ref object of VimFault
  
type
  HostNetworkConfigResult* = ref object of DynamicData
    vnicDevice*: seq[string]
    consoleVnicDevice*: seq[string]

type
  InvalidCAMCertificate* = ref object of InvalidCAMServer
  
type
  PrivilegeAvailability* = ref object of DynamicData
    privId*: string
    isGranted*: bool

type
  OvfCreateImportSpecParams* = ref object of OvfManagerCommonParams
    entityName*: string
    hostSystem*: HostSystem
    networkMapping*: seq[OvfNetworkMapping]
    ipAllocationPolicy*: string
    ipProtocol*: string
    propertyMapping*: seq[KeyValue]
    resourceMapping*: seq[OvfResourceMap]
    diskProvisioning*: string
    instantiationOst*: OvfConsumerOstNode

type
  StorageDrsVmConfigSpec* = ref object of ArrayUpdateSpec
    info*: StorageDrsVmConfigInfo

type
  ViewManager* = ref object of vmodl.ManagedObject
    viewList*: seq[View]

type
  HostPciDevice* = ref object of DynamicData
    id*: string
    classId*: int16
    bus*: byte
    slot*: byte
    function*: byte
    vendorId*: int16
    subVendorId*: int16
    vendorName*: string
    deviceId*: int16
    subDeviceId*: int16
    parentBridge*: string
    deviceName*: string

type
  HostVirtualSwitchBridge* = ref object of DynamicData
  
type
  CustomFieldEvent* = ref object of Event
  
type
  OvfParseDescriptorResult* = ref object of DynamicData
    eula*: seq[string]
    network*: seq[OvfNetworkInfo]
    ipAllocationScheme*: seq[string]
    ipProtocols*: seq[string]
    property*: seq[VAppPropertyInfo]
    productInfo*: VAppProductInfo
    annotation*: string
    approximateDownloadSize*: int64
    approximateFlatDeploymentSize*: int64
    approximateSparseDeploymentSize*: int64
    defaultEntityName*: string
    virtualApp*: bool
    deploymentOption*: seq[OvfDeploymentOption]
    defaultDeploymentOption*: string
    entityName*: seq[KeyValue]
    annotatedOst*: OvfConsumerOstNode
    error*: seq[MethodFault]
    warning*: seq[MethodFault]

type
  ScsiLunDurableName* = ref object of DynamicData
    namespace*: string
    namespaceId*: byte
    data*: seq[byte]

type
  ClusterDasAdvancedRuntimeInfo* = ref object of DynamicData
    dasHostInfo*: ClusterDasHostInfo
    vmcpSupported*: ClusterDasAdvancedRuntimeInfoVmcpCapabilityInfo
    heartbeatDatastoreInfo*: seq[DasHeartbeatDatastoreInfo]

type
  HostSnmpDestination* = ref object of DynamicData
    hostName*: string
    port*: int
    community*: string

type
  VirtualCdromIsoBackingInfo* = ref object of VirtualDeviceFileBackingInfo
  
type
  ApplyHostProfileConfigurationSpec* = ref object of ProfileExecuteResult
    host*: HostSystem
    taskListRequirement*: seq[string]
    taskDescription*: seq[LocalizableMessage]
    rebootStateless*: bool
    rebootHost*: bool
    faultData*: MethodFault

type
  HostProfilesEntityCustomizations* = ref object of DynamicData
  
type
  ImportHostProfileCustomizationsResult* = ref object of DynamicData
    status*: string
    entityResults*: seq[ImportHostProfileCustomizationsResultEntityCustomizationsResult]
    importIssues*: ProfileHostHostCustomizationOperationIssues

type
  ConflictingConfigurationConfig* = ref object of DynamicData
    entity*: ManagedEntity
    propertyPath*: string

type
  VirtualUSBUSBBackingInfo* = ref object of VirtualDeviceDeviceBackingInfo
  
type
  InsufficientNetworkCapacity* = ref object of InsufficientResourcesFault
  
type
  VsanUpgradeSystemNotEnoughFreeCapacityIssue* = ref object of VsanUpgradeSystemPreflightCheckIssue
    reducedRedundancyUpgradePossible*: bool

type
  HostNetworkTrafficShapingPolicy* = ref object of DynamicData
    enabled*: bool
    averageBandwidth*: int64
    peakBandwidth*: int64
    burstSize*: int64

type
  VimVasaProvider* = ref object of DynamicData
    uid*: string
    url*: string
    name*: string
    selfSignedCertificate*: string

type
  HostCertificateManager* = ref object of vmodl.ManagedObject
    certificateInfo*: HostCertificateManagerCertificateInfo

type
  CannotAccessVmConfig* = ref object of CannotAccessVmComponent
    reason*: MethodFault

type
  VirtualMachineVFlashModuleInfo* = ref object of VirtualMachineTargetInfo
    vFlashModule*: HostVFlashManagerVFlashCacheConfigInfoVFlashModuleConfigOption

type
  HostVMotionManagerVMotionResult* = ref object of DynamicData
    dstVmId*: int
    vmDowntime*: int64
    vmStunTime*: int64
    vmPagesSrcTime*: int64
    vmNumRemotePageFaults*: int64

type
  HostFirmwareSystem* = ref object of vmodl.ManagedObject
  
type
  VirtualVmxnet3Option* = ref object of VirtualVmxnetOption
  
type
  TaskFilterSpecByTime* = ref object of DynamicData
    timeType*: TaskFilterSpecTimeOption
    beginTime*: string
    endTime*: string

type
  DVSOpaqueDataList* = ref object of DynamicData
    opaqueData*: seq[DVSOpaqueData]

type
  GatewayNotReachable* = ref object of GatewayConnectFault
  
type
  FaultDomainId* = ref object of DynamicData
    id*: string

type
  HostCacheConfigurationManager* = ref object of vmodl.ManagedObject
    cacheConfigurationInfo*: seq[HostCacheConfigurationInfo]

type
  DVSFailureCriteria* = ref object of InheritablePolicy
    checkSpeed*: StringPolicy
    speed*: IntPolicy
    checkDuplex*: BoolPolicy
    fullDuplex*: BoolPolicy
    checkErrorPercent*: BoolPolicy
    percentage*: IntPolicy
    checkBeacon*: BoolPolicy

type
  CustomizationStartedEvent* = ref object of CustomizationEvent
  
type
  ComputeResourceHostSPBMLicenseInfo* = ref object of DynamicData
    host*: HostSystem
    licenseState*: ComputeResourceHostSPBMLicenseInfoHostSPBMLicenseState

type
  HostProfileManagerHostToConfigSpecMap* = ref object of DynamicData
    host*: HostSystem
    configSpec*: AnswerFileCreateSpec

type
  DatastoreFileMovedEvent* = ref object of DatastoreFileEvent
    sourceDatastore*: DatastoreEventArgument
    sourceFile*: string

type
  OvfUnknownDevice* = ref object of OvfSystemFault
    device*: VirtualDevice
    vmName*: string

type
  VchaClusterDeploymentSpec* = ref object of DynamicData
    passiveDeploymentSpec*: PassiveNodeDeploymentSpec
    witnessDeploymentSpec*: NodeDeploymentSpec
    activeVcSpec*: SourceNodeSpec
    activeVcNetworkConfig*: ClusterNetworkConfigSpec

type
  VMotionLinkDown* = ref object of VMotionInterfaceIssue
    network*: string

type
  VirtualDiskLocalPMemBackingInfo* = ref object of VirtualDeviceFileBackingInfo
    diskMode*: string
    uuid*: string
    volumeUUID*: string
    contentId*: string

type
  HostSystemDebugManager* = ref object of vmodl.ManagedObject
  
type
  DistributedVirtualSwitchHostProductSpec* = ref object of DynamicData
    productLineId*: string
    version*: string

type
  AlarmAcknowledgedEvent* = ref object of AlarmEvent
    source*: ManagedEntityEventArgument
    entity*: ManagedEntityEventArgument

type
  NamespaceFull* = ref object of VimFault
    name*: string
    currentMaxSize*: int64
    requiredSize*: int64

type
  HostVMotionNetConfig* = ref object of DynamicData
    candidateVnic*: seq[HostVirtualNic]
    selectedVnic*: HostVirtualNic

type
  SessionManager* = ref object of vmodl.ManagedObject
    sessionList*: seq[UserSession]
    currentSession*: UserSession
    message*: string
    messageLocaleList*: seq[string]
    supportedLocaleList*: seq[string]
    defaultLocale*: string

type
  TemplateUpgradeFailedEvent* = ref object of TemplateUpgradeEvent
    reason*: MethodFault

type
  HostFirewallInfo* = ref object of DynamicData
    defaultPolicy*: HostFirewallDefaultPolicy
    ruleset*: seq[HostFirewallRuleset]

type
  HostSpecification* = ref object of DynamicData
    createdTime*: string
    lastModified*: string
    host*: HostSystem
    subSpecs*: seq[HostSubSpecification]
    changeID*: string

type
  ProxyServiceEndpointSpec* = ref object of DynamicData
    serverNamespace*: string
    accessMode*: string

type
  UplinkPortVlanUntrunkedEvent* = ref object of DvsHealthStatusChangeEvent
  
type
  InfoUpgradeEvent* = ref object of UpgradeEvent
  
type
  CustomizationFailed* = ref object of CustomizationEvent
  
type
  VirtualMachineFlagInfoMonitorType* {.pure.} = enum
    release, debug, stats
type
  FaultTolerancePrimaryConfigInfo* = ref object of FaultToleranceConfigInfo
    secondaries*: seq[VirtualMachine]

type
  VirtualSerialPort* = ref object of VirtualDevice
    yieldOnPoll*: bool

type
  ProfileHostProfileEngineHostProfileManagerProfileMetaArray* = ref object of DynamicData
    profileMeta*: seq[ProfileMetadata]

type
  VirtualIDEController* = ref object of VirtualController
  
type
  VirtualMachineCpuIdInfoSpec* = ref object of ArrayUpdateSpec
    info*: HostCpuIdInfo

type
  HostOpaqueSwitchOpaqueSwitchState* {.pure.} = enum
    up, warning, down
type
  VmDisconnectedEvent* = ref object of VmEvent
  
type
  HostScsiDiskPartition* = ref object of DynamicData
    diskName*: string
    partition*: int

type
  GroupAlarmAction* = ref object of AlarmAction
    action*: seq[AlarmAction]

type
  DvsHostInfrastructureTrafficResource* = ref object of DynamicData
    key*: string
    description*: string
    allocationInfo*: DvsHostInfrastructureTrafficResourceAllocation

type
  InvalidDasConfigArgument* = ref object of InvalidArgument
    entry*: string
    clusterName*: string

type
  VMwareDvsMulticastFilteringMode* {.pure.} = enum
    legacyFiltering, snooping
type
  VMwareDVSTeamingHealthCheckConfig* = ref object of VMwareDVSHealthCheckConfig
  
type
  DvpgRestoreEvent* = ref object of DVPortgroupEvent
  
type
  ProfileManager* = ref object of vmodl.ManagedObject
    profile*: seq[Profile]

type
  ErrorUpgradeEvent* = ref object of UpgradeEvent
  
type
  VsanUpgradeSystemV2ObjectsPresentDuringDowngradeIssue* = ref object of VsanUpgradeSystemPreflightCheckIssue
    uuids*: seq[string]

type
  ImportOperationBulkFault* = ref object of DvsFault
    importFaults*: seq[ImportOperationBulkFaultFaultOnImport]

type
  FileQuery* = ref object of DynamicData
  
type
  VirtualPCIController* = ref object of VirtualController
  
type
  VmConfigFileQuery* = ref object of FileQuery
    filter*: VmConfigFileQueryFilter
    details*: VmConfigFileQueryFlags

type
  SessionManagerHttpServiceRequestSpecMethod* {.pure.} = enum
    httpOptions, httpGet, httpHead, httpPost, httpPut, httpDelete, httpTrace,
    httpConnect
type
  HostPnicNetworkResourceInfo* = ref object of DynamicData
    pnicDevice*: string
    availableBandwidthForVMTraffic*: int64
    unusedBandwidthForVMTraffic*: int64
    placedVirtualNics*: seq[HostPlacedVirtualNicIdentifier]

type
  VirtualMachineForkConfigInfoChildType* {.pure.} = enum
    none, persistent, nonpersistent
type
  ReplicationInvalidOptions* = ref object of ReplicationFault
    options*: string
    entity*: ManagedEntity

type
  LocalDatastoreCreatedEvent* = ref object of HostEvent
    datastore*: DatastoreEventArgument
    datastoreUrl*: string

type
  CryptoManagerKmipServerStatus* = ref object of DynamicData
    name*: string
    status*: ManagedEntityStatus
    connectionStatus*: string
    certInfo*: CryptoManagerKmipCertificateInfo
    clientTrustServer*: bool
    serverTrustClient*: bool

type
  NumVirtualCpusIncompatibleReason* {.pure.} = enum
    recordReplay, faultTolerance
type
  OvfCreateDescriptorResult* = ref object of DynamicData
    ovfDescriptor*: string
    error*: seq[MethodFault]
    warning*: seq[MethodFault]
    includeImageFiles*: bool

type
  DatastoreRenamedEvent* = ref object of DatastoreEvent
    oldName*: string
    newName*: string

type
  HostDatastoreBrowser* = ref object of vmodl.ManagedObject
    datastore*: seq[Datastore]
    supportedType*: seq[FileQuery]

type
  VirtualPCIPassthroughDeviceBackingInfo* = ref object of VirtualDeviceDeviceBackingInfo
    id*: string
    deviceId*: string
    systemId*: string
    vendorId*: int16

type
  SwapDatastoreUnset* = ref object of VimFault
  
type
  GatewayToHostTrustVerifyFault* = ref object of GatewayToHostConnectFault
    verificationToken*: string
    propertiesToVerify*: seq[KeyValue]

type
  MethodDescription* = ref object of Description
    key*: string

type
  VirtualMachineDisplayTopology* = ref object of DynamicData
    x*: int
    y*: int
    width*: int
    height*: int

type
  VmFailedRelayoutEvent* = ref object of VmEvent
    reason*: MethodFault

type
  DasClusterIsolatedEvent* = ref object of ClusterEvent
  
type
  ShrinkDiskFault* = ref object of VimFault
    diskId*: int

type
  HostProfileManagerCompositionValidationResult* = ref object of DynamicData
    results*: seq[HostProfileManagerCompositionValidationResultResultElement]
    errors*: seq[LocalizableMessage]

type
  NoDatastoresConfiguredEvent* = ref object of HostEvent
  
type
  HostSubSpecificationDeleteEvent* = ref object of HostEvent
    subSpecName*: string

type
  VirtualUSBControllerOption* = ref object of VirtualControllerOption
    autoConnectDevices*: BoolOption
    ehciSupported*: BoolOption
    supportedSpeeds*: seq[string]

type
  UnexpectedCustomizationFault* = ref object of CustomizationFault
  
type
  DatastoreNotWritableOnHost* = ref object of InvalidDatastore
    host*: HostSystem

type
  VirtualMachineGuestQuiesceSpec* = ref object of DynamicData
    timeout*: int

type
  GuestProcessNotFound* = ref object of GuestOperationsFault
    pid*: int64

type
  VirtualMachineMetadataManagerVmMetadataResult* = ref object of DynamicData
    vmMetadata*: VirtualMachineMetadataManagerVmMetadata
    error*: MethodFault

type
  ProfileHostProfileEngineHostProfileManagerUserInputArray* = ref object of DynamicData
    userInputPath*: seq[ProfilePropertyPath]

type
  HostLowLevelProvisioningManagerVmMigrationStatus* = ref object of DynamicData
    migrationId*: int64
    type*: string
    source*: bool
    consideredSuccessful*: bool

type
  VirtualSerialPortURIBackingOption* = ref object of VirtualDeviceURIBackingOption
  
type
  InvalidEditionLicense* = ref object of NotEnoughLicenses
    feature*: string

type
  VirtualMachineToolsUpdateStatus* = ref object of DynamicData
    updateRequireReboot*: bool
    updateRequireRebootComponent*: seq[string]

type
  AlarmSnmpCompletedEvent* = ref object of AlarmEvent
    entity*: ManagedEntityEventArgument

type
  InvalidNetworkInType* = ref object of VAppPropertyFault
  
type
  TooManyGuestLogons* = ref object of GuestOperationsFault
  
type
  NumericRange* = ref object of DynamicData
    start*: int
    end*: int

type
  SwitchNotInUpgradeMode* = ref object of DvsFault
  
type
  HttpNfcLeaseInfo* = ref object of DynamicData
    lease*: HttpNfcLease
    entity*: ManagedEntity
    deviceUrl*: seq[HttpNfcLeaseDeviceUrl]
    totalDiskCapacityInKB*: int64
    leaseTimeout*: int
    hostMap*: seq[HttpNfcLeaseDatastoreLeaseInfo]

type
  VirtualMachineProvisioningPolicy* = ref object of DynamicData
    configPolicy*: seq[VirtualMachineProvisioningPolicyConfigPolicy]
    filePolicy*: seq[VirtualMachineProvisioningPolicyFilePolicy]

type
  ScheduledTask* = ref object of vim.ExtensibleManagedObject
    info*: ScheduledTaskInfo

type
  HostCacheConfigurationSpec* = ref object of DynamicData
    datastore*: Datastore
    swapSize*: int64

type
  HostNatServiceSpec* = ref object of DynamicData
    virtualSwitch*: string
    activeFtp*: bool
    allowAnyOui*: bool
    configPort*: bool
    ipGatewayAddress*: string
    udpTimeout*: int
    portForward*: seq[HostNatServicePortForwardSpec]
    nameService*: HostNatServiceNameServiceSpec

type
  LibraryOperation* = ref object of LibraryFault
    details*: LocalizableMessage

type
  HostNonCompliantEvent* = ref object of HostEvent
  
type
  WillResetSnapshotDirectory* = ref object of MigrationFault
  
type
  ClusterProfileConfigServiceCreateSpec* = ref object of ClusterProfileConfigSpec
    serviceType*: seq[string]

type
  VirtualDiskSparseVer2BackingOption* = ref object of VirtualDeviceFileBackingOption
    diskMode*: ChoiceOption
    split*: BoolOption
    writeThrough*: BoolOption
    growable*: bool
    hotGrowable*: bool
    uuid*: bool

type
  VmConfigFault* = ref object of VimFault
  
type
  GeneralVmWarningEvent* = ref object of GeneralEvent
  