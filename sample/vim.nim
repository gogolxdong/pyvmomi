
type
  HostProtocolEndpointPEType* {.pure.} = enum
    block, nas
type
  IoFilterType* {.pure.} = enum
    cache, replication, encryption, compression, inspection, datastoreIoControl,
    dataProvider
type
  LicenseReservationInfoState* {.pure.} = enum
    notUsed, noLicense, unlicensedUse, licensed
type
  HostPatchManagerReason* {.pure.} = enum
    obsoleted, missingPatch, missingLib, hasDependentPatch, conflictPatch,
    conflictLib
type
  HostActiveDirectoryInfoDomainMembershipStatus* {.pure.} = enum
    unknown, ok, noServers, clientTrustBroken, serverTrustBroken, inconsistentTrust,
    otherProblem
type
  ReplicationDiskConfigFaultReasonForFault* {.pure.} = enum
    diskNotFound, diskTypeNotSupported, invalidDiskKey, invalidDiskReplicationId,
    duplicateDiskReplicationId, invalidPersistentFilePath,
    reconfigureDiskReplicationIdNotAllowed
type
  HostDigestInfoDigestMethodType* {.pure.} = enum
    SHA1, MD5, SHA256, SHA384, SHA512, SM3_256
type
  CDCChangeLogCollectorChangeLog* {.pure.} = enum
    inventory, alarmStatus
type
  VsanUpgradeSystemUpgradeHistoryDiskGroupOpType* {.pure.} = enum
    add, remove
type
  LatencySensitivitySensitivityLevel* {.pure.} = enum
    low, normal, medium, high, custom
type
  VirtualMachineFlagInfoVirtualMmuUsage* {.pure.} = enum
    automatic, on, off
type
  NetIpConfigInfoIpAddressStatus* {.pure.} = enum
    preferred, deprecated, invalid, inaccessible, unknown, tentative, duplicate
type
  InternetScsiSnsDiscoveryMethod* {.pure.} = enum
    isnsStatic, isnsDhcp, isnsSlp
type
  HostUnresolvedVmfsExtentUnresolvedReason* {.pure.} = enum
    diskIdMismatch, uuidConflict
type
  NvdimmNamespaceHealthStatus* {.pure.} = enum
    normal, missing, labelMissing, interleaveBroken, labelInconsistent, bttCorrupt,
    badBlockSize
type
  ReplicationVmFaultReasonForFault* {.pure.} = enum
    notConfigured, poweredOff, suspended, poweredOn, offlineReplicating,
    invalidState, invalidInstanceId, closeDiskError, groupExist
type
  NetIpConfigInfoIpAddressOrigin* {.pure.} = enum
    other, manual, dhcp, linklayer, random
type
  VsanHostDecommissionModeObjectAction* {.pure.} = enum
    noAction, ensureObjectAccessibility, evacuateAllData
type
  VmFaultToleranceInvalidFileBackingDeviceType* {.pure.} = enum
    virtualFloppy, virtualCdrom, virtualSerialPort, virtualParallelPort, virtualDisk
type
  BaseConfigInfoDiskFileBackingInfoProvisioningType* {.pure.} = enum
    thin, eagerZeroedThick, lazyZeroedThick
type
  LicenseFeatureInfoSourceRestriction* {.pure.} = enum
    unrestricted, served, file
type
  HostLowLevelProvisioningManagerFileType* {.pure.} = enum
    File, VirtualDisk, Directory
type
  ClusterVmComponentProtectionSettingsStorageVmReaction* {.pure.} = enum
    disabled, warning, restartConservative, restartAggressive, clusterDefault
type
  HostGraphicsInfoGraphicsType* {.pure.} = enum
    basic, shared, direct, sharedDirect
type
  VirtualMachineConfigSpecNpivWwnOp* {.pure.} = enum
    generate, set, remove, extend
type
  CannotUseNetworkReason* {.pure.} = enum
    NetworkReservationNotSupported, MismatchedNetworkPolicies,
    MismatchedDvsVersionOrVendor, VMotionToUnsupportedNetworkType
type
  LinkDiscoveryProtocolConfigProtocolType* {.pure.} = enum
    cdp, lldp
type
  HostProfileManagerMetadataTypes* {.pure.} = enum
    profile, policy, component, category
type
  ThirdPartyLicenseAssignmentFailedReason* {.pure.} = enum
    licenseAssignmentFailed, moduleNotInstalled
type
  HttpNfcLeaseManifestEntryChecksumType* {.pure.} = enum
    sha1, sha256
type
  VMwareUplinkLacpMode* {.pure.} = enum
    active, passive
type
  HostMountMode* {.pure.} = enum
    readWrite, readOnly
type
  HostPowerOperationType* {.pure.} = enum
    powerOn, powerOff
type
  OvfCreateImportSpecParamsDiskProvisioningType* {.pure.} = enum
    monolithicSparse, monolithicFlat, twoGbMaxExtentSparse, twoGbMaxExtentFlat,
    thin, thick, seSparse, eagerZeroedThick, sparse, flat
type
  NotSupportedDeviceForFTDeviceType* {.pure.} = enum
    virtualVmxnet3, paraVirtualSCSIController
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
  BatchResultResult* {.pure.} = enum
    success, fail
type
  SoftwarePackageConstraint* {.pure.} = enum
    equals, lessThan, lessThanEqual, greaterThanEqual, greaterThan
type
  HostProfileManagerCompositionValidationResultResultElementStatus* {.pure.} = enum
    success, error
type
  CDCAlarmChangeKind* {.pure.} = enum
    triggered, retriggered, acknowledged, cleared
type
  ScsiLunDescriptorQuality* {.pure.} = enum
    highQuality, mediumQuality, lowQuality, unknownQuality
type
  VStorageObjectConsumptionType* {.pure.} = enum
    disk
type
  VMotionCompatibilityType* {.pure.} = enum
    cpu, software
type
  VirtualMachineGuestOsFamily* {.pure.} = enum
    windowsGuest, linuxGuest, netwareGuest, solarisGuest, darwinGuestFamily,
    otherGuestFamily
type
  SlpDiscoveryMethod* {.pure.} = enum
    slpDhcp, slpAutoUnicast, slpAutoMulticast, slpManual
type
  HostFileSystemVolumeFileSystemType* {.pure.} = enum
    VMFS, NFS, NFS41, CIFS, vsan, VFFS, VVOL, PMEM, OTHER
type
  HostDatastoreSystemVmfsEventType* {.pure.} = enum
    Create, Expand, Extend, Remove, Upgrade
type
  HostProfileManagerAnswerFileStatus* {.pure.} = enum
    valid, invalid, unknown
type
  HostFirewallRuleProtocol* {.pure.} = enum
    tcp, udp
type
  HostDatastoreSystemDatastoreEventType* {.pure.} = enum
    VvolFastPolling, PreUnmount, FailedUnmount
type
  HostMountInfoInaccessibleReason* {.pure.} = enum
    AllPathsDown_Start, AllPathsDown_Timeout, PermanentDeviceLoss
type
  HostServicePolicy* {.pure.} = enum
    on, automatic, off
type
  VirtualMachineWindowsQuiesceSpecVssBackupContext* {.pure.} = enum
    ctx_auto, ctx_backup, ctx_file_share_backup
type
  HostProfileValidationFailureInfoUpdateType* {.pure.} = enum
    HostBased, Import, Edit, Compose
type
  HostFirewallRuleDirection* {.pure.} = enum
    inbound, outbound
type
  InvalidDasConfigArgumentEntryForInvalidArgument* {.pure.} = enum
    admissionControl, userHeartbeatDs, vmConfig
type
  HostNetStackInstanceSystemStackKey* {.pure.} = enum
    defaultTcpipStack, vmotion, vSphereProvisioning
type
  NetIpStackInfoEntryType* {.pure.} = enum
    other, invalid, dynamic, manual
type
  AffinityType* {.pure.} = enum
    memory, cpu
type
  VirtualMachineConnectionState* {.pure.} = enum
    connected, disconnected, orphaned, inaccessible, invalid
type
  SimpleCommandEncoding* {.pure.} = enum
    CSV, HEX, STRING
type
  FibreChannelPortType* {.pure.} = enum
    fabric, loop, pointToPoint, unknown
type
  HostDistributedVirtualSwitchManagerNetworkResourcePoolKey* {.pure.} = enum
    faultTolerance, hbr, iSCSI, management, nfs, virtualMachine, vmotion, vsan, vdp
type
  CannotMoveFaultToleranceVmMoveType* {.pure.} = enum
    resourcePool, cluster
type
  HostSystemDebugManagerProcessKey* {.pure.} = enum
    hostd
type
  VirtualMachineRelocateDiskMoveOptions* {.pure.} = enum
    moveAllDiskBackingsAndAllowSharing, moveAllDiskBackingsAndDisallowSharing,
    moveChildMostDiskBacking, createNewChildDiskBacking,
    moveAllDiskBackingsAndConsolidate
type
  MultipathState* {.pure.} = enum
    standby, active, disabled, dead, unknown
type
  ClusterDasAamNodeStateDasState* {.pure.} = enum
    uninitialized, initialized, configuring, unconfiguring, running, error,
    agentShutdown, nodeFailed
type
  IscsiPortInfoPathStatus* {.pure.} = enum
    notUsed, active, standBy, lastActive
type
  VmwareDistributedVirtualSwitchPvlanPortType* {.pure.} = enum
    promiscuous, isolated, community
type
  ClusterDasVmSettingsRestartPriority* {.pure.} = enum
    disabled, lowest, low, medium, high, highest, clusterRestartPriority
type
  HttpNfcLeaseState* {.pure.} = enum
    initializing, ready, done, error
type
  NvdimmNvdimmHealthInfoState* {.pure.} = enum
    normal, error
type
  DiagnosticManagerLogFormat* {.pure.} = enum
    plain
type
  QuarantineModeFaultFaultType* {.pure.} = enum
    NoCompatibleNonQuarantinedHost, CorrectionDisallowed, CorrectionImpact
type
  VAppIPAssignmentInfoAllocationSchemes* {.pure.} = enum
    dhcp, ovfenv
type
  VchaClusterState* {.pure.} = enum
    healthy, degraded, isolated
type
  VirtualMachineProvisioningPolicyOpType* {.pure.} = enum
    clone, migrate, createSecondary, createForkChild, instantClone
type
  HostActiveDirectoryAuthenticationCertificateDigest* {.pure.} = enum
    SHA1
type
  ClusterHostInfraUpdateHaModeActionOperationType* {.pure.} = enum
    enterQuarantine, exitQuarantine, enterMaintenance
type
  HealthUpdateInfoComponentType* {.pure.} = enum
    Memory, Power, Fan, Network, Storage
type
  VirtualDiskMode* {.pure.} = enum
    persistent, nonpersistent, undoable, independent_persistent,
    independent_nonpersistent, append
type
  VchaState* {.pure.} = enum
    configured, notConfigured, invalid, prepared
type
  ReplicationVmState* {.pure.} = enum
    none, paused, syncing, idle, active, error
type
  VirtualMachineToolsStatus* {.pure.} = enum
    toolsNotInstalled, toolsNotRunning, toolsOld, toolsOk
type
  HostInternetScsiHbaIscsiIpv6AddressAddressConfigurationType* {.pure.} = enum
    DHCP, AutoConfigured, Static, Other
type
  EntityImportType* {.pure.} = enum
    createEntityWithNewIdentifier, createEntityWithOriginalIdentifier,
    applyToEntitySpecified
type
  CDCInventoryChangeKind* {.pure.} = enum
    created, updated, deleted
type
  HostRuntimeInfoNetStackInstanceRuntimeInfoState* {.pure.} = enum
    inactive, active, deactivating, activating
type
  ClusterDasVmSettingsIsolationResponse* {.pure.} = enum
    none, powerOff, shutdown, clusterIsolationResponse
type
  DayOfWeek* {.pure.} = enum
    sunday, monday, tuesday, wednesday, thursday, friday, saturday
type
  VirtualVmxnet3VrdmaOptionDeviceProtocols* {.pure.} = enum
    rocev1, rocev2
type
  VirtualMachineGuestState* {.pure.} = enum
    running, shuttingDown, resetting, standby, notRunning, unknown
type
  HostSnmpAgentCapability* {.pure.} = enum
    COMPLETE, DIAGNOSTICS, CONFIGURATION
type
  VirtualMachinePowerPolicyCpuMode* {.pure.} = enum
    noProcessorThrottling, adaptiveProcessorThrottling,
    constantProcessorThrottling, degradedProcessorThrottling
type
  PlacementSpecPlacementType* {.pure.} = enum
    create, reconfigure, relocate, clone
type
  VirtualMachineVMCIDeviceDirection* {.pure.} = enum
    guest, host, anyDirection
type
  LicenseFeatureInfoUnit* {.pure.} = enum
    host, cpuCore, cpuPackage, server, vm
type
  VirtualMachinePowerState* {.pure.} = enum
    poweredOff, poweredOn, suspended
type
  ClusterInfraUpdateHaConfigInfoRemediationType* {.pure.} = enum
    QuarantineMode, MaintenanceMode
type
  VirtualMachineFlagInfoVirtualExecUsage* {.pure.} = enum
    hvAuto, hvOn, hvOff
type
  VFlashModuleNotSupportedReason* {.pure.} = enum
    CacheModeNotSupported, CacheConsistencyTypeNotSupported,
    CacheBlockSizeNotSupported, CacheReservationNotSupported, DiskSizeNotSupported
type
  StoragePlacementSpecPlacementType* {.pure.} = enum
    create, reconfigure, relocate, clone
type
  HostSystemRemediationStateState* {.pure.} = enum
    remediationReady, precheckRemediationRunning, precheckRemediationComplete,
    precheckRemediationFailed, remediationRunning, remediationFailed
type
  DistributedVirtualSwitchProductSpecOperationType* {.pure.} = enum
    preInstall, upgrade, notifyAvailableUpgrade, proceedWithUpgrade,
    updateBundleInfo
type
  AgentInstallFailedReason* {.pure.} = enum
    NotEnoughSpaceOnDevice, PrepareToUpgradeFailed, AgentNotRunning,
    AgentNotReachable, InstallTimedout, SignatureVerificationFailed,
    AgentUploadFailed, AgentUploadTimedout, UnknownInstallerError
type
  LicenseManagerLicenseKey* {.pure.} = enum
    esxFull, esxVmtn, esxExpress, san, iscsi, nas, vsmp, backup, vc, vcExpress, esxHost,
    gsxHost, serverHost, drsPower, vmotion, drs, das
type
  HostSystemPowerState* {.pure.} = enum
    poweredOn, poweredOff, standBy, unknown
type
  DasVmPriority* {.pure.} = enum
    disabled, low, medium, high
type
  EventEventSeverity* {.pure.} = enum
    error, warning, info, user
type
  VirtualMachineConfigSpecEncryptedVMotionModes* {.pure.} = enum
    disabled, opportunistic, required
type
  HostDisconnectedEventReasonCode* {.pure.} = enum
    sslThumbprintVerifyFailed, licenseExpired, agentUpgrade, userRequest,
    insufficientLicenses, agentOutOfDate, passwordDecryptFailure, unknown,
    vcVRAMCapacityExceeded
type
  GuestOsDescriptorSupportLevel* {.pure.} = enum
    experimental, legacy, terminated, supported, unsupported, deprecated, techPreview
type
  HostVmfsVolumeUnmapPriority* {.pure.} = enum
    none, low
type
  SharesLevel* {.pure.} = enum
    low, normal, high, custom
type
  VirtualMachinePowerOffBehavior* {.pure.} = enum
    powerOff, revert, prompt, take
type
  VirtualDeviceConnectInfoStatus* {.pure.} = enum
    ok, recoverableError, unrecoverableError, untried
type
  VMwareDVSVspanSessionType* {.pure.} = enum
    mixedDestMirror, dvPortMirror, remoteMirrorSource, remoteMirrorDest,
    encapsulatedRemoteMirrorSource
type
  VirtualMachineToolsRunningStatus* {.pure.} = enum
    guestToolsNotRunning, guestToolsRunning, guestToolsExecutingScripts
type
  VirtualMachineConfigInfoSwapPlacementType* {.pure.} = enum
    inherit, vmDirectory, hostLocal
type
  ImageLibraryManagerMediaType* {.pure.} = enum
    Ovf, Vmdk, Iso, Flp, Cust, Generic
type
  LinkDiscoveryProtocolConfigOperationType* {.pure.} = enum
    none, listen, advertise, both
type
  HostDiskPartitionInfoPartitionFormat* {.pure.} = enum
    gpt, mbr, unknown
type
  VirtualDiskDeltaDiskFormatVariant* {.pure.} = enum
    vmfsSparseVariant, vsanSparseVariant
type
  CannotEnableVmcpForClusterReason* {.pure.} = enum
    APDTimeoutDisabled, IncompatibleHostVersion
type
  IncompatibleHostForVmReplicationIncompatibleReason* {.pure.} = enum
    rpo, netCompression
type
  ProfileExecuteResultStatus* {.pure.} = enum
    success, needInput, error
type
  DpmBehavior* {.pure.} = enum
    manual, automated
type
  HostPatchManagerInstallState* {.pure.} = enum
    hostRestarted, imageActive
type
  HostVirtualNicManagerNicType* {.pure.} = enum
    vmotion, faultToleranceLogging, vSphereReplication, vSphereReplicationNFC,
    management, vsan, vSphereProvisioning, vsanWitness
type
  VsanHostDiskResultState* {.pure.} = enum
    inUse, eligible, ineligible
type
  DiagnosticManagerLogCreator* {.pure.} = enum
    vpxd, vpxa, hostd, serverd, install, vpxClient, recordLog
type
  HostCpuPackageVendor* {.pure.} = enum
    unknown, intel, amd, arm
type
  ClusterPowerOnVmOption* {.pure.} = enum
    OverrideAutomationLevel, ReserveResources
type
  VAppCloneSpecProvisioningType* {.pure.} = enum
    sameAsSource, thin, thick
type
  HostNumericSensorType* {.pure.} = enum
    fan, power, temperature, voltage, other, processor, memory, storage, systemBoard,
    battery, bios, cable, watchdog
type
  NvdimmRangeType* {.pure.} = enum
    volatileRange, persistentRange, controlRange, blockRange,
    volatileVirtualDiskRange, volatileVirtualCDRange, persistentVirtualDiskRange,
    persistentVirtualCDRange
type
  VirtualEthernetCardMacType* {.pure.} = enum
    manual, generated, assigned
type
  VirtualMachineFaultToleranceState* {.pure.} = enum
    notConfigured, disabled, enabled, needSecondary, starting, running
type
  StorageIORMThresholdMode* {.pure.} = enum
    automatic, manual
type
  VirtualMachineToolsVersionStatus* {.pure.} = enum
    guestToolsNotInstalled, guestToolsNeedUpgrade, guestToolsCurrent,
    guestToolsUnmanaged, guestToolsTooOld, guestToolsSupportedOld,
    guestToolsSupportedNew, guestToolsTooNew, guestToolsBlacklisted
type
  GuestInfoAppStateType* {.pure.} = enum
    none, appStateOk, appStateNeedReset
type
  ConfigSpecOperation* {.pure.} = enum
    add, edit, remove
type
  HostSystemConnectionState* {.pure.} = enum
    connected, notResponding, disconnected
type
  ScsiDiskType* {.pure.} = enum
    native512, emulated512, native4k, SoftwareEmulated4k, unknown
type
  EntityType* {.pure.} = enum
    distributedVirtualSwitch, distributedVirtualPortgroup
type
  ResourceType* {.pure.} = enum
    cpu, memory
type
  ClusterInfraUpdateHaConfigInfoBehaviorType* {.pure.} = enum
    Manual, Automated
type
  VMwareDVSVspanSessionEncapType* {.pure.} = enum
    gre, erspan2, erspan3
type
  FileSystemMountInfoVStorageSupportStatus* {.pure.} = enum
    vStorageSupported, vStorageUnsupported, vStorageUnknown
type
  HostHasComponentFailureHostComponentType* {.pure.} = enum
    Datastore
type
  HostInternetScsiHbaDigestType* {.pure.} = enum
    digestProhibited, digestDiscouraged, digestPreferred, digestRequired
type
  PerfSummaryType* {.pure.} = enum
    average, maximum, minimum, latest, summation, none
type
  AlarmFilterSpecAlarmTypeByTrigger* {.pure.} = enum
    triggerTypeAll, triggerTypeEvent, triggerTypeMetric
type
  VchaNodeRole* {.pure.} = enum
    active, passive, witness
type
  HostVMotionManagerVMotionType* {.pure.} = enum
    vmotion, fast_suspend_resume, fault_tolerance, disks_only, memory_mirror,
    instant_clone
type
  ScheduledHardwareUpgradeInfoHardwareUpgradeStatus* {.pure.} = enum
    none, pending, success, failed
type
  HostProfileManagerCompositionResultResultElementStatus* {.pure.} = enum
    success, error
type
  HostStandbyMode* {.pure.} = enum
    entering, exiting, in, none
type
  ManagedEntityStatus* {.pure.} = enum
    gray, green, yellow, red
type
  ProxyServiceAccessMode* {.pure.} = enum
    httpOnly, httpsOnly, httpsWithRedirect, httpAndHttps
type
  VirtualMachineUsbInfoSpeed* {.pure.} = enum
    low, full, high, superSpeed, unknownSpeed
type
  HostOperationCleanupManagerOperationState* {.pure.} = enum
    running, success, failure
type
  ScheduledHardwareUpgradeInfoHardwareUpgradePolicy* {.pure.} = enum
    never, onSoftPowerOff, always
type
  HostProfileManagerTaskListRequirement* {.pure.} = enum
    maintenanceModeRequired, rebootRequired
type
  HostCapabilityFtUnsupportedReason* {.pure.} = enum
    vMotionNotLicensed, missingVMotionNic, missingFTLoggingNic, ftNotLicensed,
    haAgentIssue, unsupportedProduct, cpuHvUnsupported, cpuHwmmuUnsupported,
    cpuHvDisabled
type
  ClusterDasConfigInfoVmMonitoringState* {.pure.} = enum
    vmMonitoringDisabled, vmMonitoringOnly, vmAndAppMonitoring
type
  DasConfigFaultDasConfigFaultReason* {.pure.} = enum
    HostNetworkMisconfiguration, HostMisconfiguration, InsufficientPrivileges,
    NoPrimaryAgentAvailable, Other, NoDatastoresConfigured, CreateConfigVvolFailed,
    VSanNotSupportedOnHost, DasNetworkMisconfiguration
type
  VirtualMachineMovePriority* {.pure.} = enum
    lowPriority, highPriority, defaultPriority
type
  DrsBehavior* {.pure.} = enum
    manual, partiallyAutomated, fullyAutomated
type
  HostIncompatibleForRecordReplayReason* {.pure.} = enum
    product, processor
type
  VMwareDvsLacpLoadBalanceAlgorithm* {.pure.} = enum
    srcMac, destMac, srcDestMac, destIpVlan, srcIpVlan, srcDestIpVlan, destTcpUdpPort,
    srcTcpUdpPort, srcDestTcpUdpPort, destIpTcpUdpPort, srcIpTcpUdpPort,
    srcDestIpTcpUdpPort, destIpTcpUdpPortVlan, srcIpTcpUdpPortVlan,
    srcDestIpTcpUdpPortVlan, destIp, srcIp, srcDestIp, vlan, srcPortId
type
  CustomizationLicenseDataMode* {.pure.} = enum
    perServer, perSeat
type
  HostConfigChangeOperation* {.pure.} = enum
    add, remove, edit, ignore
type
  VirtualMachineNeedSecondaryReason* {.pure.} = enum
    initializing, divergence, lostConnection, partialHardwareFailure, userAction,
    checkpointError, other
type
  EventFilterSpecRecursionOption* {.pure.} = enum
    self, children, all
type
  DisallowedChangeByServiceDisallowedChange* {.pure.} = enum
    hotExtendDisk
type
  VirtualMachinePowerOpType* {.pure.} = enum
    soft, hard, preset
type
  VirtualDeviceConfigSpecOperation* {.pure.} = enum
    add, remove, edit
type
  DistributedVirtualSwitchPortConnecteeConnecteeType* {.pure.} = enum
    pnic, vmVnic, hostConsoleVnic, hostVmkVnic
type
  VAppAutoStartAction* {.pure.} = enum
    none, powerOn, powerOff, guestShutdown, suspend
type
  VirtualDiskSharing* {.pure.} = enum
    sharingNone, sharingMultiWriter
type
  SoftwarePackageVibType* {.pure.} = enum
    bootbank, tools, meta
type
  HostSystemIdentificationInfoIdentifier* {.pure.} = enum
    AssetTag, ServiceTag, OemSpecificString
type
  HostIpConfigIpV6AddressConfigType* {.pure.} = enum
    other, manual, dhcp, linklayer, random
type
  HostInternetScsiHbaChapAuthenticationType* {.pure.} = enum
    chapProhibited, chapDiscouraged, chapPreferred, chapRequired
type
  TaskFilterSpecTimeOption* {.pure.} = enum
    queuedTime, startedTime, completedTime
type
  VirtualMachineStandbyActionType* {.pure.} = enum
    checkpoint, powerOnSuspend
type
  HostCertificateManagerCertificateInfoCertificateStatus* {.pure.} = enum
    unknown, expired, expiring, expiringShortly, expirationImminent, good, revoked
type
  AnswerFileValidationResultStatus* {.pure.} = enum
    success, needInput, error
type
  vslmVStorageObjectControlFlag* {.pure.} = enum
    keepAfterDeleteVm, disableRelocation, enableChangedBlockTracking
type
  GuestOsDescriptorFirmwareType* {.pure.} = enum
    bios, efi, csm
type
  ClusterDasConfigInfoHBDatastoreCandidate* {.pure.} = enum
    userSelectedDs, allFeasibleDs, allFeasibleDsWithUserPreference
type
  VirtualDiskVFlashCacheConfigInfoCacheMode* {.pure.} = enum
    write_thru, write_back
type
  ClusterVmReadinessReadyCondition* {.pure.} = enum
    none, poweredOn, guestHbStatusGreen, appHbStatusGreen, useClusterDefault
type
  VirtualMachineVMCIDeviceProtocol* {.pure.} = enum
    hypervisor, doorbell, queuepair, datagram, stream, anyProtocol
type
  AutoStartWaitHeartbeatSetting* {.pure.} = enum
    yes, no, systemDefault
type
  VirtualMachineMemoryAllocationPolicy* {.pure.} = enum
    swapNone, swapSome, swapMost
type
  VirtualEthernetCardLegacyNetworkDeviceName* {.pure.} = enum
    bridged, nat, hostonly
type
  HostProfileValidationState* {.pure.} = enum
    Ready, Running, Failed
type
  WillLoseHAProtectionResolution* {.pure.} = enum
    svmotion, relocate
type
  GuestFileType* {.pure.} = enum
    file, directory, symlink
type
  HostNasVolumeSecurityType* {.pure.} = enum
    AUTH_SYS, SEC_KRB5, SEC_KRB5I
type
  FtIssuesOnHostHostSelectionType* {.pure.} = enum
    user, vc, drs
type
  VirtualDeviceConfigSpecFileOperation* {.pure.} = enum
    create, destroy, replace
type
  VirtualMachineMetadataManagerVmMetadataOwnerOwner* {.pure.} = enum
    ComVmwareVsphereHA
type
  VirtualMachineProvisioningPolicyAction* {.pure.} = enum
    keep, remove
type
  HostGraphicsConfigSharedPassthruAssignmentPolicy* {.pure.} = enum
    performance, consolidation
type
  HostNumericSensorHealthState* {.pure.} = enum
    unknown, green, yellow, red
type
  VirtualDeviceFileExtension* {.pure.} = enum
    iso, flp, vmdk, dsk, rdm
type
  NvdimmNamespaceType* {.pure.} = enum
    blockNamespace, persistentNamespace
type
  InvalidProfileReferenceHostReason* {.pure.} = enum
    incompatibleVersion, missingReferenceHost
type
  DataProviderFilterLogicalOperator* {.pure.} = enum
    And, Or
type
  HostFeatureVersionKey* {.pure.} = enum
    faultTolerance
type
  HostLockdownMode* {.pure.} = enum
    lockdownDisabled, lockdownNormal, lockdownStrict
type
  VchaClusterMode* {.pure.} = enum
    enabled, disabled, maintenance
type
  ApplyHostProfileConfigurationResultStatus* {.pure.} = enum
    success, failed, reboot_failed, stateless_reboot_failed,
    check_compliance_failed, state_not_satisfied, exit_maintenancemode_failed,
    canceled
type
  VirtualMachineTargetInfoConfigurationTag* {.pure.} = enum
    compliant, clusterWide
type
  StateAlarmOperator* {.pure.} = enum
    isEqual, isUnequal
type
  VirtualMachineVideoCardUse3dRenderer* {.pure.} = enum
    automatic, software, hardware
type
  ScsiLunType* {.pure.} = enum
    disk, tape, printer, processor, worm, cdrom, scanner, opticalDevice, mediaChanger,
    communications, storageArrayController, enclosure, unknown
type
  ArrayUpdateOperation* {.pure.} = enum
    add, remove, edit
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
  HostUnresolvedVmfsResolutionSpecVmfsUuidResolution* {.pure.} = enum
    resignature, forceMount
type
  ComputeResourceHostSPBMLicenseInfoHostSPBMLicenseState* {.pure.} = enum
    licensed, unlicensed, unknown
type
  DvsEventPortBlockState* {.pure.} = enum
    unset, blocked, unblocked, unknown
type
  FileManagerFileType* {.pure.} = enum
    File, VirtualDisk
type
  VirtualMachineHtSharing* {.pure.} = enum
    any, none, internal
type
  CustomizationNetBIOSMode* {.pure.} = enum
    enableNetBIOSViaDhcp, enableNetBIOS, disableNetBIOS
type
  PlacementAffinityRuleRuleScope* {.pure.} = enum
    cluster, host, storagePod, datastore
type
  VirtualDiskRuleSpecRuleType* {.pure.} = enum
    affinity, antiAffinity, disabled
type
  CannotPowerOffVmInClusterOperation* {.pure.} = enum
    suspend, powerOff, guestShutdown, guestSuspend
type
  VMwareDvsLacpApiVersion* {.pure.} = enum
    singleLag, multipleLag
type
  NvdimmNamespaceState* {.pure.} = enum
    invalid, notInUse, inUse
type
  VMwareDVSTeamingMatchStatus* {.pure.} = enum
    iphashMatch, nonIphashMatch, iphashMismatch, nonIphashMismatch
type
  VmDasBeingResetEventReasonCode* {.pure.} = enum
    vmtoolsHeartbeatFailure, appHeartbeatFailure, appImmediateResetRequest,
    vmcpResetApdCleared, guestOsCrashFailure
type
  ProfileParameterMetadataRelationType* {.pure.} = enum
    dynamic_relation, extensible_relation, localizable_relation, static_relation,
    validation_relation
type
  ScsiLunVStorageSupportStatus* {.pure.} = enum
    vStorageSupported, vStorageUnsupported, vStorageUnknown
type
  DVPortStatusVmDirectPathGen2InactiveReasonOther* {.pure.} = enum
    portNptIncompatibleHost, portNptIncompatibleConnectee
type
  PerfStatsType* {.pure.} = enum
    absolute, delta, rate
type
  HostDistributedVirtualSwitchManagerFetchPortOption* {.pure.} = enum
    runtimeInfoOnly, statsOnly, stateBlobOnly
type
  StorageDrsSpaceLoadBalanceConfigSpaceThresholdMode* {.pure.} = enum
    utilization, freeSpace
type
  VAppIPAssignmentInfoProtocols* {.pure.} = enum
    IPv4, IPv6
type
  CheckTestType* {.pure.} = enum
    sourceTests, hostTests, resourcePoolTests, datastoreTests, networkTests
type
  VirtualDiskVFlashCacheConfigInfoCacheConsistencyType* {.pure.} = enum
    strong, weak
type
  ClusterVmComponentProtectionSettingsVmReactionOnAPDCleared* {.pure.} = enum
    none, reset, useClusterDefault
type
  UpgradePolicy* {.pure.} = enum
    manual, upgradeAtPowerCycle
type
  ProfileNumericComparator* {.pure.} = enum
    lessThan, lessThanEqual, equal, notEqual, greaterThanEqual, greaterThan
type
  VmShutdownOnIsolationEventOperation* {.pure.} = enum
    shutdown, poweredOff
type
  DiagnosticPartitionType* {.pure.} = enum
    singleHost, multiHost
type
  ReplicationVmInProgressFaultActivity* {.pure.} = enum
    fullSync, delta
type
  ExternalStatsManagerMetricType* {.pure.} = enum
    CpuActivePct, MemoryNonZeroActiveMb
type
  HostTpmAttestationInfoAcceptanceStatus* {.pure.} = enum
    notAccepted, accepted
type
  VirtualDeviceURIBackingOptionDirection* {.pure.} = enum
    server, client
type
  VirtualDeviceConnectInfoMigrateConnectOp* {.pure.} = enum
    connect, disconnect, unset
type
  PerfFormat* {.pure.} = enum
    normal, csv
type
  DistributedVirtualPortgroupMetaTagName* {.pure.} = enum
    dvsName, portgroupName, portIndex
type
  HostInternetScsiHbaNetworkBindingSupportType* {.pure.} = enum
    notsupported, optional, required
type
  VirtualMachineMetadataManagerVmMetadataOp* {.pure.} = enum
    Update, Remove
type
  VirtualMachineBackupEventInfoBackupEventType* {.pure.} = enum
    reset, requestorError, requestorAbort, providerAbort, snapshotPrepare,
    snapshotCommit, requestorDone, backupManifest, writerError, keepAlive
type
  EventAlarmExpressionComparisonOperator* {.pure.} = enum
    equals, notEqualTo, startsWith, doesNotStartWith, endsWith, doesNotEndWith
type
  VirtualDiskDeltaDiskFormat* {.pure.} = enum
    redoLogFormat, nativeFormat, seSparseFormat
type
  OvfConsumerOstNodeType* {.pure.} = enum
    envelope, virtualSystem, virtualSystemCollection
type
  PhysicalNicVmDirectPathGen2SupportedMode* {.pure.} = enum
    upt
type
  ProxyServiceRedirectSpecRedirectType* {.pure.} = enum
    permanent, found
type
  HostGraphicsConfigGraphicsType* {.pure.} = enum
    shared, sharedDirect
type
  HostCpuPowerManagementInfoPolicyType* {.pure.} = enum
    off, staticPolicy, dynamicPolicy
type
  DvsNetworkRuleDirectionType* {.pure.} = enum
    incomingPackets, outgoingPackets, both
type
  VirtualSerialPortEndPoint* {.pure.} = enum
    client, server
type
  DvsFilterOnFailure* {.pure.} = enum
    failOpen, failClosed
type
  HostInternetScsiHbaIscsiIpv6AddressIPv6AddressOperation* {.pure.} = enum
    add, remove
type
  HostInternetScsiHbaStaticTargetTargetDiscoveryMethod* {.pure.} = enum
    staticMethod, sendTargetMethod, slpMethod, isnsMethod, unknownMethod
type
  VirtualMachineNamespaceManagerDataSpecOpCode* {.pure.} = enum
    updateAlways, updateIfEqual
type
  VirtualAppVAppState* {.pure.} = enum
    started, stopped, starting, stopping
type
  ActionType* {.pure.} = enum
    MigrationV1, VmPowerV1, HostPowerV1, IncreaseLimitV1, IncreaseSizeV1,
    IncreaseSharesV1, IncreaseReservationV1, DecreaseOthersReservationV1,
    IncreaseClusterCapacityV1, DecreaseMigrationThresholdV1, HostMaintenanceV1,
    StorageMigrationV1, StoragePlacementV1, PlacementV1, HostInfraUpdateHaV1
type
  HostCapabilityUnmapMethodSupported* {.pure.} = enum
    priority, fixed, dynamic
type
  HostAccessMode* {.pure.} = enum
    accessNone, accessAdmin, accessNoAccess, accessReadOnly, accessOther
type
  VsanHostHealthState* {.pure.} = enum
    unknown, healthy, unhealthy
type
  VirtualMachineCryptoState* {.pure.} = enum
    unlocked, locked
type
  AnswerFileValidationInfoStatus* {.pure.} = enum
    success, failed, failed_defaults
type
  HostProtocolEndpointProtocolEndpointType* {.pure.} = enum
    scsi, nfs, nfs4x
type
  HostIncompatibleForFaultToleranceReason* {.pure.} = enum
    product, processor
type
  DVPortStatusVmDirectPathGen2InactiveReasonNetwork* {.pure.} = enum
    portNptIncompatibleDvs, portNptNoCompatibleNics,
    portNptNoVirtualFunctionsAvailable, portNptDisabledForPort
type
  DistributedVirtualSwitchNicTeamingPolicyMode* {.pure.} = enum
    loadbalance_ip, loadbalance_srcmac, loadbalance_srcid, failover_explicit,
    loadbalance_loadbased
type
  AlarmTriggerType* {.pure.} = enum
    metric, state, event
type
  DeviceNotSupportedReason* {.pure.} = enum
    host, guest
type
  TaskInfoState* {.pure.} = enum
    queued, running, success, error
type
  ClusterProfileServiceType* {.pure.} = enum
    DRS, HA, DPM, FT
type
  IoFilterOperation* {.pure.} = enum
    install, uninstall, upgrade
type
  EsxAgentConfigManagerAgentVmState* {.pure.} = enum
    enabled, disabled, unavailable, manuallyEnabled
type
  VirtualDiskAdapterType* {.pure.} = enum
    ide, busLogic, lsiLogic
type
  LicenseFeatureInfoState* {.pure.} = enum
    enabled, disabled, optional
type
  AutoStartAction* {.pure.} = enum
    none, systemDefault, powerOn, powerOff, guestShutdown, suspend
type
  HostDasErrorEventHostDasErrorReason* {.pure.} = enum
    configFailed, timeout, communicationInitFailed, healthCheckScriptFailed,
    agentFailed, agentShutdown, isolationAddressUnpingable, other
type
  PerformanceManagerUnit* {.pure.} = enum
    percent, kiloBytes, megaBytes, megaHertz, number, microsecond, millisecond, second,
    kiloBytesPerSecond, megaBytesPerSecond, watt, joule, celsius, teraBytes
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
  VsanHostNodeState* {.pure.} = enum
    error, disabled, agent, master, backup, starting, stopping,
    enteringMaintenanceMode, exitingMaintenanceMode, decommissioning
type
  DiagnosticPartitionStorageType* {.pure.} = enum
    directAttached, networkAttached
type
  LicenseAssignmentFailedReason* {.pure.} = enum
    keyEntityMismatch, downgradeDisallowed, inventoryNotManageableByVirtualCenter,
    hostsUnmanageableByVirtualCenterWithoutLicenseServer
type
  DrsRecommendationReasonCode* {.pure.} = enum
    fairnessCpuAvg, fairnessMemAvg, jointAffin, antiAffin, hostMaint
type
  HostCapabilityVmDirectPathGen2UnsupportedReason* {.pure.} = enum
    hostNptIncompatibleProduct, hostNptIncompatibleHardware, hostNptDisabled
type
  VchaNodeState* {.pure.} = enum
    up, down
type
  HostCryptoState* {.pure.} = enum
    incapable, prepared, safe
type
  RecommendationType* {.pure.} = enum
    V1
type
  AlarmFilterSpecAlarmTypeByEntity* {.pure.} = enum
    entityTypeAll, entityTypeHost, entityTypeVm
type
  CustomizationSysprepRebootOption* {.pure.} = enum
    reboot, noreboot, shutdown
type
  VirtualMachineFlagInfoMonitorType* {.pure.} = enum
    release, debug, stats
type
  DatastoreAccessible* {.pure.} = enum
    True, False
type
  VirtualMachineVMCIDeviceAction* {.pure.} = enum
    allow, deny
type
  VAppIPAssignmentInfoIpAllocationPolicy* {.pure.} = enum
    dhcpPolicy, transientPolicy, fixedPolicy, fixedAllocatedPolicy
type
  HostOperationCleanupManagerCleanupItemType* {.pure.} = enum
    disk, file, dir, vm
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
  VirtualMachineRelocateTransformation* {.pure.} = enum
    flat, sparse
type
  MetricAlarmOperator* {.pure.} = enum
    isAbove, isBelow
type
  HostOpaqueSwitchOpaqueSwitchState* {.pure.} = enum
    up, warning, down
type
  VMwareDvsMulticastFilteringMode* {.pure.} = enum
    legacyFiltering, snooping
type
  QuiesceMode* {.pure.} = enum
    application, filesystem, none
type
  HostDiskPartitionInfoType* {.pure.} = enum
    none, vmfs, linuxNative, linuxSwap, extended, ntfs, vmkDiagnostic, vffs
type
  VirtualPointingDeviceHostChoice* {.pure.} = enum
    autodetect, intellimouseExplorer, intellimousePs2, logitechMouseman,
    microsoft_serial, mouseSystems, mousemanSerial, ps2
type
  HostVmfsVolumeUnmapBandwidthPolicy* {.pure.} = enum
    fixed, dynamic
type
  ClusterDasConfigInfoServiceState* {.pure.} = enum
    disabled, enabled
type
  HostVmciAccessManagerMode* {.pure.} = enum
    grant, replace, revoke
type
  SessionManagerHttpServiceRequestSpecMethod* {.pure.} = enum
    httpOptions, httpGet, httpHead, httpPost, httpPut, httpDelete, httpTrace,
    httpConnect
type
  StorageDrsPodConfigInfoBehavior* {.pure.} = enum
    manual, automated
type
  VsanDiskIssueType* {.pure.} = enum
    nonExist, stampMismatch, unknown
type
  HostHardwareElementStatus* {.pure.} = enum
    Unknown, Green, Yellow, Red
type
  VirtualMachineForkConfigInfoChildType* {.pure.} = enum
    none, persistent, nonpersistent
type
  DistributedVirtualSwitchHostInfrastructureTrafficClass* {.pure.} = enum
    management, faultTolerance, vmotion, virtualMachine, iSCSI, nfs, hbr, vsan, vdp
type
  DrsInjectorWorkloadCorrelationState* {.pure.} = enum
    Correlated, Uncorrelated
type
  NumVirtualCpusIncompatibleReason* {.pure.} = enum
    recordReplay, faultTolerance
type
  VirtualMachineToolsInstallType* {.pure.} = enum
    guestToolsTypeUnknown, guestToolsTypeMSI, guestToolsTypeTar, guestToolsTypeOSP,
    guestToolsTypeOpenVMTools
type
  DataProviderPropertyPredicateComparisonOperator* {.pure.} = enum
    Equal, NotEqual, Greater, GreaterOrEqual, Less, LessOrEqual, In, NotIn, Like, Unset
type
  PhysicalNicResourcePoolSchedulerDisallowedReason* {.pure.} = enum
    userOptOut, hardwareUnsupported
type
  HostFirewallRulePortType* {.pure.} = enum
    src, dst
type
  NvdimmInterleaveSetState* {.pure.} = enum
    invalid, active
type
  HostLowLevelProvisioningManagerReloadTarget* {.pure.} = enum
    currentConfig, snapshotConfig
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
  PlacementAffinityRuleRuleType* {.pure.} = enum
    affinity, antiAffinity, softAffinity, softAntiAffinity
type
  DVSMacLimitPolicyType* {.pure.} = enum
    allow, drop
type
  WeekOfMonth* {.pure.} = enum
    first, second, third, fourth, last
type
  ScsiLunState* {.pure.} = enum
    unknownState, ok, error, off, quiesced, degraded, lostCommunication, timeout
type
  HostReplayUnsupportedReason* {.pure.} = enum
    incompatibleProduct, incompatibleCpu, hvDisabled, cpuidLimitSet, oldBIOS, unknown
type
  VirtualMachineUsbInfoFamily* {.pure.} = enum
    audio, hid, hid_bootable, physical, communication, imaging, printer, storage, hub,
    smart_card, security, video, wireless, bluetooth, wusb, pda, vendor_specific, other,
    unknownFamily
type
  VirtualMachineAppHeartbeatStatusType* {.pure.} = enum
    appStatusGray, appStatusGreen, appStatusRed
type
  VirtualSCSISharing* {.pure.} = enum
    noSharing, virtualSharing, physicalSharing
type
  VirtualMachineBootOptionsNetworkBootProtocolType* {.pure.} = enum
    ipv4, ipv6
type
  VirtualDiskType* {.pure.} = enum
    preallocated, thin, seSparse, rdm, rdmp, raw, delta, sparse2Gb, thick2Gb,
    eagerZeroedThick, sparseMonolithic, flatMonolithic, thick
type
  HostNetStackInstanceCongestionControlAlgorithmType* {.pure.} = enum
    newreno, cubic
type
  DataProviderSortCriterionSortDirection* {.pure.} = enum
    Ascending, Descending
type
  DatastoreSummaryMaintenanceModeState* {.pure.} = enum
    normal, enteringMaintenance, inMaintenance
type
  VirtualMachineConfigInfoNpivWwnType* {.pure.} = enum
    vc, host, external
type
  PreCallbackResultResult* {.pure.} = enum
    ContinueWithOperation, BlockOperation
type
  VirtualMachineFaultToleranceType* {.pure.} = enum
    unset, recordReplay, checkpointing
type
  LicenseManagerState* {.pure.} = enum
    initializing, normal, marginal, fault
type
  ServiceProtocol* {.pure.} = enum
    vimApi, vimWebServices, viImageLibrary, unknown
type
  HostConfigChangeMode* {.pure.} = enum
    modify, replace
type
  NetBIOSConfigInfoMode* {.pure.} = enum
    unknown, enabled, disabled, enabledViaDHCP
type
  VirtualMachineRecordReplayState* {.pure.} = enum
    recording, replaying, inactive
type
  VirtualMachineScsiPassthroughType* {.pure.} = enum
    disk, tape, printer, processor, worm, cdrom, scanner, optical, media, com, raid,
    unknown
type
  DistributedVirtualSwitchNetworkResourceControlVersion* {.pure.} = enum
    version2, version3
type
  TaskFilterSpecRecursionOption* {.pure.} = enum
    self, children, all
type
  DistributedVirtualSwitchHostMemberHostComponentState* {.pure.} = enum
    up, pending, outOfSync, warning, disconnected, down
type
  ActionParameter* {.pure.} = enum
    targetName, alarmName, oldStatus, newStatus, triggeringSummary, declaringSummary,
    eventDescription, target, alarm
type
  HttpNfcLeaseMode* {.pure.} = enum
    pushOrGet, pull
type
  EventCategory* {.pure.} = enum
    info, warning, error, user
type
  VmFailedStartingSecondaryEventFailureReason* {.pure.} = enum
    incompatibleHost, loginFailed, registerVmFailed, migrateFailed
type
  HostOperationCleanupManagerOperationActivity* {.pure.} = enum
    vmotion, nfc, create
type
  VirtualDiskCompatibilityMode* {.pure.} = enum
    virtualMode, physicalMode
type
  GuestRegKeyWowSpec* {.pure.} = enum
    WOWNative, WOW32, WOW64
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
  HostFaultToleranceManagerFaultToleranceType* {.pure.} = enum
    fault_tolerance_using_checkpoints, fault_tolerance_using_recordreplay
type
  HostImageAcceptanceLevel* {.pure.} = enum
    vmware_certified, vmware_accepted, partner, community
type
  PortGroupConnecteeType* {.pure.} = enum
    virtualMachine, systemManagement, host, unknown
type
  ComplianceResultStatus* {.pure.} = enum
    compliant, nonCompliant, unknown, running
type
  VirtualMachineTicketType* {.pure.} = enum
    mks, device, guestControl, dnd, webmks, guestIntegrity
type
  HostPatchManagerIntegrityStatus* {.pure.} = enum
    validated, keyNotFound, keyRevoked, keyExpired, digestMismatch,
    notEnoughSignatures, validationError
type
  HostLicensableResourceKey* {.pure.} = enum
    numCpuPackages, numCpuCores, memorySize, memoryForVms, numVmsStarted,
    numVmsStarting
type
  NetIpStackInfoPreference* {.pure.} = enum
    reserved, low, medium, high
type
  HostIpConfigIpV6AddressStatus* {.pure.} = enum
    preferred, deprecated, invalid, inaccessible, unknown, tentative, duplicate
type
  VirtualMachinePowerPolicyPowerMode* {.pure.} = enum
    batteryPower, acPower
type
  DistributedVirtualPortgroupPortgroupType* {.pure.} = enum
    earlyBinding, lateBinding, ephemeral
type
  ValidateMigrationTestType* {.pure.} = enum
    sourceTests, compatibilityTests, diskAccessibilityTests, resourceTests
type
  ClusterDasFdmAvailabilityState* {.pure.} = enum
    uninitialized, election, master, connectedToMaster,
    networkPartitionedFromMaster, networkIsolated, hostDown, initializationError,
    uninitializationError, fdmUnreachable
type
  VirtualMachineDeviceRuntimeInfoVirtualEthernetCardRuntimeStateVmDirectPathGen2InactiveReasonOther*
      {.pure.} = enum
    vmNptIncompatibleHost, vmNptIncompatibleNetwork
type
    GuestRegValueQwordSpec = object of GuestRegValueDataSpec
    ProfileReferenceHostChangedEvent = object of ProfileEvent
    VirtualDiskManagerDiskUnit = object of DynamicData
    VirtualSCSIController = object of VirtualController
    HostSerialAttachedTargetTransport = object of HostTargetTransport
    ActiveDirectoryProfile = object of ApplyProfile
    NoVmInVApp = object of VAppConfigFault
    IpPool = object of DynamicData
    LicenseKeyEntityMismatch = object of NotEnoughLicenses
    VirtualAppLinkInfo = object of DynamicData
    FaultToleranceConfigSpec = object of DynamicData
    DatacenterEventArgument = object of EntityEventArgument
    TooManyNativeCloneLevels = object of FileFault
    DiskIsNonLocal = object of VsanDiskFault
    TaskFilterSpecByEntity = object of DynamicData
    AllVirtualMachinesLicensedEvent = object of LicenseEvent
    HostPatchManagerResult = object of DynamicData
    AnswerFileUpdateFailed = object of VimFault
    ClusterComplianceCheckedEvent = object of ClusterEvent
    NetworkInaccessible = object of NasConfigFault
    IncorrectHostInformation = object of NotEnoughLicenses
    DvsPortLinkDownEvent = object of DvsEvent
    NetworkRollbackEvent = object of Event
    ExternalStatsManagerTimeValuePair = object of DynamicData
    StructuredCustomizations = object of HostProfilesEntityCustomizations
    VmDasBeingResetEvent = object of VmEvent
    SAMLTokenAuthentication = object of GuestAuthentication
    VirtualDiskRawDiskMappingVer1BackingOption = object of VirtualDeviceDeviceBackingOption
    VirtualHdAudioCard = object of VirtualSoundCard
    VmInstanceUuidAssignedEvent = object of VmEvent
    ScheduledTaskFailedEvent = object of ScheduledTaskEvent
    ClusterComputeResourceFtConfigSpecVerificationResult = object of DynamicData
    VmFailedToSuspendEvent = object of VmEvent
    OvfConsumerOstNode = object of DynamicData
    CbrcDigestRuntimeInfoResult = object of CbrcDigestOperationResult
    NasSessionCredentialConflict = object of NasConfigFault
    VirtualEnsoniq1371 = object of VirtualSoundCard
    VirtualUSBOption = object of VirtualDeviceOption
    DvsHealthStatusChangeEvent = object of HostEvent
    HostDatastoreExistsConnectInfo = object of HostDatastoreConnectInfo
    VmGuestShutdownEvent = object of VmEvent
    HostNasVolumeUserInfo = object of DynamicData
    HostWwnChangedEvent = object of HostEvent
    ProxyServiceLocalTunnelSpec = object of ProxyServiceTunnelSpec
    VirtualMachineConfigSpec = object of DynamicData
    IpRange = object of IpAddress
    OvfUnsupportedSubType = object of OvfUnsupportedPackage
    DvsReconfiguredEvent = object of DvsEvent
    NoDisksToCustomize = object of CustomizationFault
    OvfHardwareCheck = object of OvfImport
    ClusterResourceUsageSummary = object of DynamicData
    NetBIOSConfigInfo = object of DynamicData
    AccountCreatedEvent = object of HostEvent
    LicenseManagerEvaluationInfo = object of DynamicData
    StorageDrsPodSelectionSpec = object of DynamicData
    HostIpConfig = object of DynamicData
    DatastoreRemovedOnHostEvent = object of HostEvent
    IoFilterHostIssue = object of DynamicData
    ProxyServiceRemoteServiceSpec = object of ProxyServiceServiceSpec
    VirtualDeviceOption = object of DynamicData
    RDMNotSupportedOnDatastore = object of VmConfigFault
    OvfWrongElement = object of OvfElement
    VirtualParallelPortFileBackingInfo = object of VirtualDeviceFileBackingInfo
    DvsHostVNicProfile = object of DvsVNicProfile
    HostProfileCompleteConfigSpec = object of HostProfileConfigSpec
    ClusterTransitionalEVCManagerEVCState = object of DynamicData
    HostFibreChannelTargetTransport = object of HostTargetTransport
    MissingLinuxCustResources = object of CustomizationFault
    RawDiskNotSupported = object of DeviceNotSupported
    LicenseDataManagerLicenseData = object of DynamicData
    DrsRecoveredFromFailureEvent = object of ClusterEvent
    PlacementSpec = object of DynamicData
    VmShutdownOnIsolationEvent = object of VmPoweredOffEvent
    UserNotFound = object of VimFault
    VirtualResourcePoolUsage = object of DynamicData
    HostEnterMaintenanceResult = object of DynamicData
    SessionManagerLocalTicket = object of DynamicData
    VirtualE1000Option = object of VirtualEthernetCardOption
    VmStoppingEvent = object of VmEvent
    AuthorizationRole = object of DynamicData
    ProxyServiceTicketTunnelSpec = object of ProxyServiceTunnelSpec
    VsanDecommissioningSatisfiability = object of DynamicData
    IscsiFaultVnicHasActivePaths = object of IscsiFault
    RestrictedByAdministrator = object of RuntimeFault
    UserPrivilegeResult = object of DynamicData
    VirtualMachineRelocateSpec = object of DynamicData
    OvfElementInvalidValue = object of OvfElement
    HostOvercommittedEvent = object of ClusterOvercommittedEvent
    DatacenterRenamedEvent = object of DatacenterEvent
    VirtualSerialPortFileBackingInfo = object of VirtualDeviceFileBackingInfo
    ImportHostAddFailure = object of DvsFault
    VmSuspendingEvent = object of VmEvent
    VmResumingEvent = object of VmEvent
    VmRelayoutSuccessfulEvent = object of VmEvent
    HostAutoStartManagerConfig = object of DynamicData
    VirtualSIOControllerOption = object of VirtualControllerOption
    NsxHostVNicProfile = object of ApplyProfile
    OvfNetworkInfo = object of DynamicData
    AboutInfo = object of DynamicData
    PlacementRankResult = object of DynamicData
    HostInternetScsiHbaDiscoveryProperties = object of DynamicData
    HostStorageSystemDiskLocatorLedResult = object of DynamicData
    InvalidDiskFormat = object of InvalidFormat
    HostProfileConfigSpec = object of ProfileCreateSpec
    Action = object of DynamicData
    VirtualMachineSnapshotInfo = object of DynamicData
    DvsAcceptNetworkRuleAction = object of DvsNetworkRuleAction
    DeviceBackedVirtualDiskSpec = object of VirtualDiskSpec
    ResourcePoolResourceUsage = object of DynamicData
    VirtualMachineConfigSummary = object of DynamicData
    ClusterProfileConfigSpec = object of ClusterProfileCreateSpec
    InvalidFolder = object of VimFault
    VirtualMachineRuntimeInfo = object of DynamicData
    HostDiskPartitionAttributes = object of DynamicData
    HostCnxFailedNoConnectionEvent = object of HostEvent
    ImportHostProfileCustomizationsResultEntityCustomizationsResult = object of DynamicData
    VAppCloneSpec = object of DynamicData
    DvsMergedEvent = object of DvsEvent
    VmSecondaryEnabledEvent = object of VmEvent
    HttpNfcLeaseManifestEntry = object of DynamicData
    CannotPlaceWithoutPrerequisiteMoves = object of VimFault
    ReplicationIncompatibleWithFT = object of ReplicationFault
    InvalidHostConnectionState = object of InvalidHostState
    VmRegisteredEvent = object of VmEvent
    AlarmEmailFailedEvent = object of AlarmEvent
    HostStorageArrayTypePolicyOption = object of DynamicData
    OvfConsumerContext = object of DynamicData
    ClusterDasAdmissionControlInfo = object of DynamicData
    LocalTSMEnabledEvent = object of HostEvent
    EnteringStandbyModeEvent = object of HostEvent
    CryptoSpecShallowRecrypt = object of CryptoSpec
    NoGateway = object of HostConfigFault
    ClusterFailoverLevelAdmissionControlPolicy = object of ClusterDasAdmissionControlPolicy
    PerfEntityMetric = object of PerfEntityMetricBase
    ComplianceProfile = object of DynamicData
    VsanUpgradeSystemUpgradeHistoryDiskGroupOp = object of VsanUpgradeSystemUpgradeHistoryItem
    VirtualMachineWipeResult = object of DynamicData
    VirtualMachinePciPassthroughInfo = object of VirtualMachineTargetInfo
    GuestComponentsOutOfDate = object of GuestOperationsFault
    VirtualFloppyImageBackingOption = object of VirtualDeviceFileBackingOption
    InvalidLicense = object of VimFault
    HostOpaqueNetworkInfo = object of DynamicData
    HostNoAvailableNetworksEvent = object of HostDasEvent
    MissingWindowsCustResources = object of CustomizationFault
    HostSignatureInfo = object of DynamicData
    VMwareDVSHealthCheckConfig = object of DVSHealthCheckConfig
    VmNoNetworkAccessEvent = object of VmEvent
    RDMConversionNotSupported = object of MigrationFault
    DasAgentUnavailableEvent = object of ClusterEvent
    NonPersistentDisksNotSupported = object of DeviceNotSupported
    LockerMisconfiguredEvent = object of Event
    ClusterComputeResourceFtCompatibleHostResult = object of DynamicData
    HostSystemHealthInfo = object of DynamicData
    CustomizationEvent = object of VmEvent
    HostLowLevelProvisioningManagerDiskLayoutSpec = object of DynamicData
    HostDatastoreBrowserSearchResults = object of DynamicData
    HostVMotionManagerVMotionDeviceSpec = object of VirtualDeviceConfigSpec
    StorageDrsCannotMoveFTVm = object of VimFault
    ToolsConfigInfo = object of DynamicData
    VirtualVideoCardOption = object of VirtualDeviceOption
    DisableAlarmExpression = object of AlarmExpression
    SSLDisabledFault = object of HostConnectFault
    MessageBusProxyFault = object of VimFault
    VmCloneFailedEvent = object of VmCloneEvent
    AlarmCreatedEvent = object of AlarmEvent
    MethodActionArgument = object of DynamicData
    HostSnmpConfigSpec = object of DynamicData
    VmClonedEvent = object of VmCloneEvent
    HostNatServicePortForwardSpec = object of DynamicData
    CustomizationName = object of DynamicData
    DvsVnicAllocatedResource = object of DynamicData
    RoleRemovedEvent = object of RoleEvent
    DatastoreCapability = object of DynamicData
    DVPortStatus = object of DynamicData
    CustomizationUnknownIpV6Generator = object of CustomizationIpV6Generator
    VirtualNVDIMMControllerOption = object of VirtualControllerOption
    VirtualMachineCapability = object of DynamicData
    VslmCloneSpec = object of VslmMigrateSpec
    BlockedByFirewall = object of HostConfigFault
    CannotDecryptPasswords = object of CustomizationFault
    GeneralUserEvent = object of GeneralEvent
    ApplyHostProfileConfigurationResult = object of DynamicData
    VirtualPointingDeviceOption = object of VirtualDeviceOption
    ProfilePolicyMetadata = object of DynamicData
    HostStatusChangedEvent = object of ClusterStatusChangedEvent
    VirtualMachineProfileDetailsDiskProfileDetails = object of DynamicData
    QuestionPending = object of InvalidState
    VirtualCdromRemoteAtapiBackingInfo = object of VirtualDeviceRemoteDeviceBackingInfo
    VMwareDVSVspanConfigSpec = object of DynamicData
    ClusterDasConfigInfo = object of DynamicData
    VmDiskFileQueryFlags = object of DynamicData
    ProfileCreateSpec = object of DynamicData
    FaultToleranceNeedsThickDisk = object of MigrationFault
    ClusterEVCManagerEVCState = object of DynamicData
    OvfResourceMap = object of DynamicData
    IscsiFaultVnicHasMultipleUplinks = object of IscsiFault
    NotFound = object of VimFault
    HostUnresolvedVmfsVolume = object of DynamicData
    HostPersistentMemoryInfo = object of DynamicData
    HostDnsConfig = object of DynamicData
    ClusterStatusChangedEvent = object of ClusterEvent
    HostDevice = object of DynamicData
    HostDigestInfo = object of DynamicData
    UserGroupProfile = object of ApplyProfile
    StorageDrsCannotMoveManuallyPlacedSwapFile = object of VimFault
    HAErrorsAtDest = object of MigrationFault
    KeyProviderId = object of DynamicData
    HostInAuditModeEvent = object of HostEvent
    ClusterVmOrchestrationInfo = object of DynamicData
    ClusterProfileCreateSpec = object of ProfileCreateSpec
    VslmCreateSpecRawDiskMappingBackingSpec = object of VslmCreateSpecBackingSpec
    PlatformConfigFault = object of HostConfigFault
    PatchBinariesNotFound = object of VimFault
    VmwareDistributedVirtualSwitchPvlanSpec = object of VmwareDistributedVirtualSwitchVlanSpec
    DisabledMethodRequest = object of DynamicData
    DatacenterMismatchArgument = object of DynamicData
    HostAddFailedEvent = object of HostEvent
    VMwareDVSConfigInfo = object of DVSConfigInfo
    VmSnapshotFileInfo = object of FileInfo
    UserUnassignedFromGroup = object of HostEvent
    VirtualUSBRemoteClientBackingInfo = object of VirtualDeviceRemoteDeviceBackingInfo
    VirtualMachineGuestSummary = object of DynamicData
    VspanDestPortConflict = object of DvsFault
    HostPlugStoreTopologyDevice = object of DynamicData
    ReplicationVmFault = object of ReplicationFault
    DistributedVirtualSwitchManagerDvsProductSpec = object of DynamicData
    DvsPortDisconnectedEvent = object of DvsEvent
    DateTimeProfile = object of ApplyProfile
    HostDiskBlockInfoMapping = object of DynamicData
    EVCModeUnsupportedByHosts = object of EVCConfigFault
    VirtualMachineFlagInfo = object of DynamicData
    HostVirtualSwitchBondBridge = object of HostVirtualSwitchBridge
    ClusterDasFailoverLevelAdvancedRuntimeInfo = object of ClusterDasAdvancedRuntimeInfo
    VsanPolicyCost = object of DynamicData
    VirtualDiskConfigSpec = object of VirtualDeviceConfigSpec
    PosixUserSearchResult = object of UserSearchResult
    ClusterVersionedStringData = object of DynamicData
    MisfeaturedHostsBlockingEVC = object of EVCConfigFault
    StringExpression = object of NegatableExpression
    VirtualDiskFlatVer1BackingInfo = object of VirtualDeviceFileBackingInfo
    DvsGreEncapNetworkRuleAction = object of DvsNetworkRuleAction
    GuestRegValueMultiStringSpec = object of GuestRegValueDataSpec
    VsanHostConfigInfoClusterInfo = object of DynamicData
    HostSecuritySpec = object of DynamicData
    Description = object of DynamicData
    ExternalStatsManagerStatsUpdate = object of DynamicData
    VmMessageEvent = object of VmEvent
    ReplicationVmProgressInfo = object of DynamicData
    DvsPortJoinPortgroupEvent = object of DvsEvent
    RemoteDeviceNotSupported = object of DeviceNotSupported
    VmWwnAssignedEvent = object of VmEvent
    MessageBusProxyInfo = object of DynamicData
    HostNicOrderPolicy = object of DynamicData
    GuestListFileInfo = object of DynamicData
    StorageDrsCannotMoveVmWithNoFilesInLayout = object of VimFault
    ClusterGroupSpec = object of ArrayUpdateSpec
    HostSpecificationRequireEvent = object of HostEvent
    HostHardwareElementInfo = object of DynamicData
    HostMultipathStateInfo = object of DynamicData
    HostNtpConfig = object of DynamicData
    VmEndRecordingEvent = object of VmEvent
    DrsInjectorWorkload = object of DynamicData
    HostInternetScsiHbaIPCapabilities = object of DynamicData
    VirtualSATAController = object of VirtualController
    HostLowLevelProvisioningManagerSnapshotLayoutSpec = object of DynamicData
    DasAgentFoundEvent = object of ClusterEvent
    ClusterPerResourceValue = object of DynamicData
    HostIpRouteConfigSpec = object of HostIpRouteConfig
    CryptoSpecRegister = object of CryptoSpecNoOp
    DvsPortConnectedEvent = object of DvsEvent
    ScsiLunCapabilities = object of DynamicData
    AlarmState = object of DynamicData
    DvsHostJoinedEvent = object of DvsEvent
    WillModifyConfigCpuRequirements = object of MigrationFault
    HostCnxFailedTimeoutEvent = object of HostEvent
    OvfConsumerInvalidSection = object of OvfConsumerCallbackFault
    FaultToleranceDiskSpec = object of DynamicData
    VmConfigIncompatibleForFaultTolerance = object of VmConfigFault
    HostVirtualNicOpaqueNetworkSpec = object of DynamicData
    ProfileProfileStructureProperty = object of DynamicData
    ServiceConsoleReservationInfo = object of DynamicData
    CannotMoveVmWithNativeDeltaDisk = object of MigrationFault
    NoLicenseEvent = object of LicenseEvent
    DatabaseSizeParam = object of DynamicData
    VirtualMachineDefaultPowerOpInfo = object of DynamicData
    EVCUnsupportedByHostSoftware = object of EVCConfigFault
    CannotPowerOffVmInCluster = object of InvalidState
    DvsDropNetworkRuleAction = object of DvsNetworkRuleAction
    HostDasEvent = object of HostEvent
    HostDVSConfigSpec = object of DynamicData
    HostProxySwitchConfig = object of DynamicData
    PerformanceManagerCounterLevelMapping = object of DynamicData
    DataProviderOptionalPropertyValue = object of DynamicData
    VirtualUSBXHCIControllerOption = object of VirtualControllerOption
    CustomizationFixedIp = object of CustomizationIpGenerator
    ProfileConfigInfo = object of DynamicData
    GuestWindowsFileAttributes = object of GuestFileAttributes
    DVSOpaqueDataConfigInfo = object of DynamicData
    HostSystemInfo = object of DynamicData
    SystemEventInfo = object of DynamicData
    AnswerFileOptionsCreateSpec = object of AnswerFileCreateSpec
    VmBeingClonedEvent = object of VmCloneEvent
    MissingIpPool = object of VAppPropertyFault
    VmConfigMissingEvent = object of VmEvent
    VirtualVmxnet = object of VirtualEthernetCard
    VirtualSerialPortPipeBackingInfo = object of VirtualDevicePipeBackingInfo
    VirtualSIOController = object of VirtualController
    FaultToleranceVMConfigSpec = object of DynamicData
    OvfWrongNamespace = object of OvfInvalidPackage
    VirtualMachineVMCIDeviceFilterInfo = object of DynamicData
    ExtendedEvent = object of GeneralEvent
    ComputeResourceEventArgument = object of EntityEventArgument
    VirtualMachineDefaultProfileSpec = object of VirtualMachineProfileSpec
    DiskTooSmall = object of VsanDiskFault
    VirtualMachineDefinedProfileSpec = object of VirtualMachineProfileSpec
    VmUnsupportedStartingEvent = object of VmStartingEvent
    MonthlyByDayTaskScheduler = object of MonthlyTaskScheduler
    SharesOption = object of DynamicData
    LicenseAssignmentManagerLicenseAssignment = object of DynamicData
    VirtualSCSIPassthrough = object of VirtualDevice
    ServiceEndpoint = object of DynamicData
    EventEx = object of Event
    VirtualCdromRemotePassthroughBackingInfo = object of VirtualDeviceRemoteDeviceBackingInfo
    MigrationWarningEvent = object of MigrationEvent
    DvsUpgradeInProgressEvent = object of DvsEvent
    VmResourcePoolMovedEvent = object of VmEvent
    InsufficientDisks = object of VsanDiskFault
    VramLimitLicense = object of NotEnoughLicenses
    VspanPortMoveFault = object of DvsFault
    VStorageObjectSnapshotDetails = object of DynamicData
    VirtualMachineWindowsQuiesceSpec = object of VirtualMachineGuestQuiesceSpec
    HostDatastoreBrowserSearchSpec = object of DynamicData
    PolicyViolatedValueCannotEqual = object of PolicyViolatedByValue
    VASAStorageArray = object of DynamicData
    UplinkPortMtuSupportEvent = object of DvsHealthStatusChangeEvent
    HostVirtualSwitch = object of DynamicData
    VimVasaProviderInfo = object of DynamicData
    BaseConfigInfoDiskFileBackingInfo = object of BaseConfigInfoFileBackingInfo
    LogBundlingFailed = object of VimFault
    WipeDiskFault = object of VimFault
    IntPolicy = object of InheritablePolicy
    LargeRDMConversionNotSupported = object of MigrationFault
    DataProviderSortCriterion = object of DynamicData
    ClusterComputeResourceFtCompatibilityResult = object of DynamicData
    ToolsUpgradeCancelled = object of VmToolsUpgradeFault
    VmUuidAssignedEvent = object of VmEvent
    ToolsConfigInfoToolsLastInstallInfo = object of DynamicData
    CustomizationDhcpIpV6Generator = object of CustomizationIpV6Generator
    StorageDrsRelocateDisabled = object of VimFault
    CustomizationWinOptions = object of CustomizationOptions
    UnsupportedDatastore = object of VmConfigFault
    VMwareDVSTeamingHealthCheckResult = object of HostMemberHealthCheckResult
    WorkflowStepHandlerInfo = object of DynamicData
    VirtualMachineBootOptions = object of DynamicData
    VirtualDevicePciBusSlotInfo = object of VirtualDeviceBusSlotInfo
    FaultToleranceCannotEditMem = object of VmConfigFault
    VmfsDatastoreSpec = object of DynamicData
    NasDatastoreInfo = object of DatastoreInfo
    HostFirewallRulesetRulesetSpec = object of DynamicData
    ResourceNotAvailable = object of VimFault
    VspanPromiscuousPortNotSupported = object of DvsFault
    CustomFieldDefAddedEvent = object of CustomFieldDefEvent
    NotSupportedHost = object of HostConnectFault
    HostBlockHba = object of HostHostBusAdapter
    HostTelemetryPaginationSpec = object of DynamicData
    VirtualParallelPortOption = object of VirtualDeviceOption
    LocalDatastoreInfo = object of DatastoreInfo
    HostSystemReconnectSpec = object of DynamicData
    ServiceLocatorSAMLCredential = object of ServiceLocatorCredential
    UsbScanCodeSpecModifierType = object of DynamicData
    VirtualMachineConsolePreferences = object of DynamicData
    CbrcDigestRuntimeInfo = object of DynamicData
    IpAddress = object of NegatableExpression
    HostParallelScsiHba = object of HostHostBusAdapter
    EsxAgentConfigManagerAgentVmInfo = object of DynamicData
    InventoryHasStandardAloneHosts = object of NotEnoughLicenses
    HostSpecificationUpdateEvent = object of HostEvent
    InvalidIpfixConfig = object of DvsFault
    RDMPointsToInaccessibleDisk = object of CannotAccessVmDisk
    NoPeerHostFound = object of HostPowerOpFailed
    LicenseAssignmentManagerEntityFeaturePair = object of DynamicData
    IncompatibleSetting = object of InvalidArgument
    ClusterDrsFaultsFaultsByVm = object of DynamicData
    OvfConsumerFault = object of OvfConsumerCallbackFault
    VVolHostPE = object of DynamicData
    InvalidIpmiMacAddress = object of VimFault
    VirtualDiskBlocksNotFullyProvisioned = object of DeviceBackingNotSupported
    TaskReasonSchedule = object of TaskReason
    VsanIncompatibleDiskMapping = object of VsanDiskFault
    VmfsDatastoreExpandSpec = object of VmfsDatastoreSpec
    PerfMetricId = object of DynamicData
    DVSNetworkResourcePoolAllocationInfo = object of DynamicData
    CAMServerRefusedConnection = object of InvalidCAMServer
    NamePasswordAuthentication = object of GuestAuthentication
    IscsiMigrationDependency = object of DynamicData
    ProfileDescription = object of DynamicData
    LicenseNonComplianceEvent = object of LicenseEvent
    LicenseDataManagerLicenseKeyEntry = object of DynamicData
    OvfConsumerOvfSection = object of DynamicData
    HostPatchManagerPatchManagerOperationSpec = object of DynamicData
    SoftRuleVioCorrectionDisallowed = object of VmConfigFault
    OpaqueNetworkTargetInfo = object of VirtualMachineTargetInfo
    VirtualMachineFileLayoutEx = object of DynamicData
    VirtualMachineSriovInfo = object of VirtualMachinePciPassthroughInfo
    HostCpuPowerManagementInfo = object of DynamicData
    ClusterConfigSpec = object of DynamicData
    VmMigratedEvent = object of VmEvent
    HostVsanInternalSystemCmmdsQuery = object of DynamicData
    NotAuthenticated = object of NoPermission
    UnsupportedGuest = object of InvalidVmConfig
    StorageIORMConfigOption = object of DynamicData
    StorageDrsSpaceLoadBalanceConfig = object of DynamicData
    VirtualCdromIsoBackingOption = object of VirtualDeviceFileBackingOption
    VmMonitorIncompatibleForFaultTolerance = object of VimFault
    VirtualMachineNetworkInfo = object of VirtualMachineTargetInfo
    ClusterEnterMaintenanceResult = object of DynamicData
    HostPowerOpFailed = object of VimFault
    VmNvramFileInfo = object of FileInfo
    CompositePolicyOption = object of PolicyOption
    VirtualEthernetCardDistributedVirtualPortBackingInfo = object of VirtualDeviceBackingInfo
    VmConfigSpec = object of DynamicData
    ClusterDasVmConfigSpec = object of ArrayUpdateSpec
    CustomizationPassword = object of DynamicData
    DistributedVirtualSwitchManagerHostArrayFilter = object of DistributedVirtualSwitchManagerHostDvsFilterSpec
    HostTpmManagerKeyParams = object of DynamicData
    UsbScanCodeSpecKeyEvent = object of DynamicData
    CustomizationOptions = object of DynamicData
    VirtualPCNet32 = object of VirtualEthernetCard
    DisabledMethodInfo = object of DynamicData
    VFlashCacheHotConfigNotSupported = object of VmConfigFault
    VmMetadataManagerFault = object of VimFault
    VMwareDVSFeatureCapability = object of DVSFeatureCapability
    SSPIChallenge = object of VimFault
    OvfManagerCommonParams = object of DynamicData
    Extension = object of DynamicData
    ProfileProfileStructure = object of DynamicData
    ClusterDrsFaults = object of DynamicData
    HostSystemSwapConfigurationHostLocalSwapOption = object of HostSystemSwapConfigurationSystemSwapOption
    HostHyperThreadScheduleInfo = object of DynamicData
    ClusterDasVmConfigInfo = object of DynamicData
    PhysicalNic = object of DynamicData
    FileBackedVirtualDiskSpec = object of VirtualDiskSpec
    DVSCreateSpec = object of DynamicData
    PatchMetadataInvalid = object of VimFault
    HostComplianceCheckedEvent = object of HostEvent
    DVPortgroupDestroyedEvent = object of DVPortgroupEvent
    VmVnicPoolReservationViolationRaiseEvent = object of DvsEvent
    ClusterVersionedBinaryData = object of DynamicData
    DeviceUnsupportedForVmPlatform = object of InvalidDeviceSpec
    StorageIOAllocationOption = object of DynamicData
    HttpNfcLeaseDeviceUrl = object of DynamicData
    VStorageObjectStateInfo = object of DynamicData
    FaultToleranceConfigInfo = object of DynamicData
    ProfileHostProfileEngineHostProfileEngine = object of DynamicData
    vslmInfrastructureObjectPolicy = object of DynamicData
    HostInternetScsiHbaIPv6Properties = object of DynamicData
    HostTpmManagerEncryptedBlob = object of DynamicData
    NetIpRouteConfigSpec = object of DynamicData
    ScsiLun = object of HostDevice
    NetIpRouteConfigInfo = object of DynamicData
    DatastoreOption = object of DynamicData
    VmRemoteConsoleDisconnectedEvent = object of VmEvent
    VStorageObjectConfigInfo = object of BaseConfigInfo
    RuleViolation = object of VmConfigFault
    VmMaxRestartCountReached = object of VmEvent
    UnrecognizedHost = object of VimFault
    SendEmailAction = object of Action
    InsufficientHostCpuCapacityFault = object of InsufficientHostCapacityFault
    HostLowLevelProvisioningManagerFileReserveSpec = object of DynamicData
    HostCnxFailedBadUsernameEvent = object of HostEvent
    IncompatibleHostForVmReplication = object of ReplicationFault
    OvfCpuCompatibility = object of OvfImport
    EnteredMaintenanceModeEvent = object of HostEvent
    HostActiveDirectory = object of DynamicData
    VirtualMachineQuestionInfo = object of DynamicData
    HostDiskDimensionsLba = object of DynamicData
    HostLocalFileSystemVolumeSpec = object of DynamicData
    DvsPortEnteredPassthruEvent = object of DvsEvent
    NvdimmNamespaceDeleteSpec = object of DynamicData
    DuplicateName = object of VimFault
    HealthStatusChangedEvent = object of Event
    DistributedVirtualSwitchManagerHostContainerFilter = object of DistributedVirtualSwitchManagerHostDvsFilterSpec
    VsanUpgradeSystemUpgradeHistoryItem = object of DynamicData
    DomainNotFound = object of ActiveDirectoryFault
    HostCnxFailedNoLicenseEvent = object of HostEvent
    LicenseSource = object of DynamicData
    MethodAction = object of Action
    ClusterVmHostRuleInfo = object of ClusterRuleInfo
    DVSManagerDvsConfigTarget = object of DynamicData
    VsanHostDiskMapping = object of DynamicData
    VirtualVmxnet3VrdmaOption = object of VirtualVmxnet3Option
    PatchMissingDependencies = object of PatchNotApplicable
    HostProfileAppliedEvent = object of HostEvent
    VspanPortgroupPromiscChangeFault = object of DvsFault
    FaultToleranceNotSameBuild = object of MigrationFault
    PatchAlreadyInstalled = object of PatchNotApplicable
    HostGraphicsConfigDeviceType = object of DynamicData
    VirtualDeviceFileBackingOption = object of VirtualDeviceBackingOption
    ClusterComputeResourceSummary = object of ComputeResourceSummary
    WarningUpgradeEvent = object of UpgradeEvent
    ResourceAllocationInfo = object of DynamicData
    MismatchedVMotionNetworkNames = object of MigrationFault
    CannotAccessLocalSource = object of VimFault
    ConnectedIso = object of OvfExport
    GuestRegValueBinarySpec = object of GuestRegValueDataSpec
    MigrationDisabled = object of MigrationFault
    VmRelayoutUpToDateEvent = object of VmEvent
    VAppOvfSectionSpec = object of ArrayUpdateSpec
    StorageDrsDatacentersCannotShareDatastore = object of VimFault
    StorageDrsHmsMoveInProgress = object of VimFault
    InvalidBundle = object of PlatformConfigFault
    DvpgImportEvent = object of DVPortgroupEvent
    HostAccessControlEntry = object of DynamicData
    DiskChangeInfo = object of DynamicData
    DvsUpgradedEvent = object of DvsEvent
    GuestInfoNamespaceGenerationInfo = object of DynamicData
    VirtualSCSIPassthroughDeviceBackingInfo = object of VirtualDeviceDeviceBackingInfo
    VirtualHdAudioCardOption = object of VirtualSoundCardOption
    HostRemovedEvent = object of HostEvent
    UserInputRequiredParameterMetadata = object of ProfilePolicyOptionMetadata
    VirtualMachineNamespaceManagerEventList = object of DynamicData
    VmDasBeingResetWithScreenshotEvent = object of VmDasBeingResetEvent
    VirtualTPM = object of VirtualDevice
    EVCConfigFault = object of VimFault
    HostProfileManagerHostProfileMetadata = object of DynamicData
    ProfileHostProfileEngineHostInfo = object of DynamicData
    HostInternetScsiHbaAuthenticationCapabilities = object of DynamicData
    ClusterRuleSpec = object of ArrayUpdateSpec
    AnswerFileUpdateFailure = object of DynamicData
    InvalidPowerState = object of InvalidState
    PhysicalNicCdpDeviceCapability = object of DynamicData
    VAppCloneSpecNetworkMappingPair = object of DynamicData
    VirtualSATAControllerOption = object of VirtualControllerOption
    ClusterDrsMigration = object of DynamicData
    HostIntegrityReportQuoteInfo = object of DynamicData
    VmDasResetFailedEvent = object of VmEvent
    HostProfileMappingProfileMappingData = object of HostProfileMappingData
    OvfParseDescriptorParams = object of OvfManagerCommonParams
    VsanHostDiskMapResult = object of DynamicData
    DasConfigFault = object of VimFault
    OvfConstraint = object of OvfInvalidPackage
    VmWwnConflict = object of InvalidVmConfig
    RetrieveVStorageObjSpec = object of DynamicData
    HostStorageElementInfo = object of HostHardwareElementInfo
    VMwareVspanSession = object of DynamicData
    HostDatastoreNameConflictConnectInfo = object of HostDatastoreConnectInfo
    VsanHostDiskMapInfo = object of DynamicData
    VchaNodeRuntimeInfo = object of DynamicData
    LinkDiscoveryProtocolConfig = object of DynamicData
    OvfHostValueNotParsed = object of OvfSystemFault
    StorageIORMInfo = object of DynamicData
    VmTimedoutStartingSecondaryEvent = object of VmEvent
    HostFileSystemMountInfo = object of DynamicData
    InvalidVmConfig = object of VmConfigFault
    ProfileHostProfileEngineHostProfileManagerProfileComponentMetaArray = object of DynamicData
    VmFailedToStandbyGuestEvent = object of VmEvent
    StringOption = object of OptionType
    ClockSkew = object of HostConfigFault
    TemplateBeingUpgradedEvent = object of TemplateUpgradeEvent
    HostSpecificationChangedEvent = object of HostEvent
    StoragePlacementResult = object of DynamicData
    PhysicalNicProfile = object of ApplyProfile
    ExtensionHealthInfo = object of DynamicData
    VirtualUSBRemoteHostBackingOption = object of VirtualDeviceDeviceBackingOption
    ProfilePolicy = object of DynamicData
    GatewayHostNotReachable = object of GatewayToHostConnectFault
    FolderEventArgument = object of EntityEventArgument
    AuthorizationManagerRequiredPermission = object of DynamicData
    VrpResourceAllocationInfo = object of ResourceAllocationInfo
    LicenseServerSource = object of LicenseSource
    DistributedVirtualSwitchManagerHostContainer = object of DynamicData
    VirtualLsiLogicSASController = object of VirtualSCSIController
    HostInternetScsiHbaDiscoveryCapabilities = object of DynamicData
    ResourcePoolEvent = object of Event
    VirtualMachineSriovNetworkDevicePoolInfo = object of VirtualMachineSriovDevicePoolInfo
    EVCAdmissionFailedCPUVendorUnknown = object of EVCAdmissionFailed
    TypeDescription = object of Description
    HostHasComponentFailure = object of VimFault
    VirtualDeviceURIBackingOption = object of VirtualDeviceBackingOption
    VFlashModuleVersionIncompatible = object of VimFault
    DVSRollbackCapability = object of DynamicData
    VirtualBusLogicControllerOption = object of VirtualSCSIControllerOption
    FaultToleranceCpuIncompatible = object of CpuIncompatible
    VMwareUplinkPortOrderPolicy = object of InheritablePolicy
    OvfAttribute = object of OvfInvalidPackage
    PerfProviderSummary = object of DynamicData
    AnswerFileValidationResult = object of DynamicData
    Permission = object of DynamicData
    CustomizationFixedName = object of CustomizationName
    InsufficientGraphicsResourcesFault = object of InsufficientResourcesFault
    HostVMotionInfo = object of DynamicData
    ProfilePolicyOptionMetadata = object of DynamicData
    VirtualPCIPassthroughPluginBackingOption = object of VirtualDeviceBackingOption
    ProfilePropertyPath = object of DynamicData
    HostInternetScsiHbaTargetSet = object of DynamicData
    HostNotInClusterEvent = object of HostDasEvent
    ExtSolutionManagerInfoTabInfo = object of DynamicData
    DVSHostLocalPortInfo = object of DynamicData
    NetIpRouteConfigInfoIpRoute = object of DynamicData
    CustomizationCustomIpGenerator = object of CustomizationIpGenerator
    HostStorageSystemScsiLunResult = object of DynamicData
    HeterogenousHostsBlockingEVC = object of EVCConfigFault
    BackupBlobReadFailure = object of DvsFault
    CollectorAddressUnset = object of DvsFault
    DVSBackupRestoreCapability = object of DynamicData
    VMOnConflictDVPort = object of CannotAccessNetwork
    VirtualHardwareCompatibilityIssue = object of VmConfigFault
    VirtualMachineBootOptionsBootableEthernetDevice = object of VirtualMachineBootOptionsBootableDevice
    OpaqueNetworkSummary = object of NetworkSummary
    DistributedVirtualSwitchHostMemberConfigSpec = object of DynamicData
    VchaClusterNetworkSpec = object of DynamicData
    VirtualDiskInfo = object of DynamicData
    HostHostBusAdapter = object of DynamicData
    NetIpStackInfo = object of DynamicData
    HostNatServiceConfig = object of DynamicData
    VmRestartedOnAlternateHostEvent = object of VmPoweredOnEvent
    VirtualMachineVideoCard = object of VirtualDevice
    OvfMissingHardware = object of OvfImport
    VmLogFileInfo = object of FileInfo
    DrsDisabledOnVm = object of VimFault
    HostWwnConflictEvent = object of HostEvent
    CustomizationAdapterMapping = object of DynamicData
    HostPosixAccountSpec = object of HostAccountSpec
    CannotMoveVsanEnabledHost = object of VsanFault
    HostTargetTransport = object of DynamicData
    OvfFileItem = object of DynamicData
    HostIpConfigIpV6AddressConfiguration = object of DynamicData
    ChangesInfoEventArgument = object of DynamicData
    DVSOpaqueConfigSpec = object of DynamicData
    IDEDiskNotSupported = object of DiskNotSupported
    HostFibreChannelHba = object of HostHostBusAdapter
    HostNatServiceNameServiceSpec = object of DynamicData
    HostListSummary = object of DynamicData
    DistributedVirtualSwitchHostMemberPnicBacking = object of DistributedVirtualSwitchHostMemberBacking
    VmFaultToleranceConfigIssue = object of VmFaultToleranceIssue
    FileBackedPortNotSupported = object of DeviceNotSupported
    HostDateTimeInfo = object of DynamicData
    GatewayNotFound = object of GatewayConnectFault
    VMwareDVSConfigSpec = object of DVSConfigSpec
    DVSSelection = object of SelectionSet
    InvalidSnapshotFormat = object of InvalidFormat
    CannotMoveHostWithFaultToleranceVm = object of VimFault
    StorageDrsConfigSpec = object of DynamicData
    InsufficientNetworkResourcePoolCapacity = object of InsufficientResourcesFault
    VsanNewPolicyBatch = object of DynamicData
    CannotCreateFile = object of FileFault
    HostBIOSInfo = object of DynamicData
    VirtualMachineAffinityInfo = object of DynamicData
    VslmCreateSpecBackingSpec = object of DynamicData
    DVSSummary = object of DynamicData
    VMwareDVSMtuHealthCheckResult = object of HostMemberUplinkHealthCheckResult
    DatastoreSummary = object of DynamicData
    DataProviderResourceModelInfo = object of DynamicData
    PhysCompatRDMNotSupported = object of RDMNotSupported
    AuthMinimumAdminPermission = object of VimFault
    VimVasaProviderStatePerArray = object of DynamicData
    StorageDrsAutomationConfig = object of DynamicData
    StorageDrsIoLoadBalanceConfig = object of DynamicData
    GatewayOperationRefused = object of GatewayConnectFault
    VmfsDatastoreMultipleExtentOption = object of VmfsDatastoreBaseOption
    VmwareUplinkPortTeamingPolicy = object of InheritablePolicy
    TpmTrustNotEstablished = object of TpmFault
    DrsInvocationFailedEvent = object of ClusterEvent
    LargeRDMNotSupportedOnDatastore = object of VmConfigFault
    AlreadyConnected = object of HostConnectFault
    OvfPropertyNetwork = object of OvfProperty
    VirtualMachineFileLayoutExFileInfo = object of DynamicData
    SecondaryVmAlreadyRegistered = object of VmFaultToleranceIssue
    CustomizationCustomName = object of CustomizationName
    VirtualLsiLogicSASControllerOption = object of VirtualSCSIControllerOption
    UpdatedAgentBeingRestartedEvent = object of HostEvent
    InvalidName = object of VimFault
    HostCnxFailedAccountFailedEvent = object of HostEvent
    VslmTagEntry = object of DynamicData
    InUseFeatureManipulationDisallowed = object of NotEnoughLicenses
    VirtualNVDIMMController = object of VirtualController
    HostDiskMappingPartitionOption = object of DynamicData
    LicenseAvailabilityInfo = object of DynamicData
    FaultToleranceSecondaryOpResult = object of DynamicData
    NonVIWorkloadDetectedOnDatastoreEvent = object of DatastoreEvent
    NetDhcpConfigSpecDhcpOptionsSpec = object of DynamicData
    ExpiredEditionLicense = object of ExpiredFeatureLicense
    LocalLicenseSource = object of LicenseSource
    TooManyConcurrentNativeClones = object of FileFault
    VirtualMachineStorageSummary = object of DynamicData
    VmPoweredOffEvent = object of VmEvent
    KmipServerStatus = object of DynamicData
    GlobalMessageChangedEvent = object of SessionEvent
    HostCnxFailedBadVersionEvent = object of HostEvent
    EnvironmentBrowserConfigOptionQuerySpec = object of DynamicData
    TemplateUpgradeEvent = object of Event
    VMotionNotLicensed = object of VMotionInterfaceIssue
    VirtualSerialPortFileBackingOption = object of VirtualDeviceFileBackingOption
    InvalidHostState = object of InvalidState
    ToolsAlreadyUpgraded = object of VmToolsUpgradeFault
    GuestRegKeyRecordSpec = object of DynamicData
    NoActiveHostInCluster = object of InvalidState
    ResourceConfigSpec = object of DynamicData
    AlarmEventArgument = object of EntityEventArgument
    CannotAccessVmDisk = object of CannotAccessVmDevice
    VirtualSoundCardDeviceBackingOption = object of VirtualDeviceDeviceBackingOption
    RestrictedVersion = object of SecurityError
    DistributedVirtualSwitchManagerImportResult = object of DynamicData
    GeneralVmErrorEvent = object of GeneralEvent
    LicenseEntityNotFound = object of VimFault
    VmBeingRelocatedEvent = object of VmRelocateSpecEvent
    VmDeployFailedEvent = object of VmEvent
    VmPrimaryFailoverEvent = object of VmEvent
    FilterInUse = object of ResourceInUse
    InvalidPropertyValue = object of VAppPropertyFault
    OvfPropertyNetworkExport = object of OvfExport
    VvolDatastoreSpec = object of DynamicData
    VirtualDiskId = object of DynamicData
    ClusterFailoverHostAdmissionControlInfoHostStatus = object of DynamicData
    GhostDvsProxySwitchDetectedEvent = object of HostEvent
    CustomizationUnknownName = object of CustomizationName
    DVSManagerDvpgUplinkTeam = object of DynamicData
    VsanUpgradeSystemAutoClaimEnabledOnHostsIssue = object of VsanUpgradeSystemPreflightCheckIssue
    IntExpression = object of NegatableExpression
    HostPatchManagerStatus = object of DynamicData
    CbrcDigestInfoResult = object of CbrcDigestOperationResult
    BoolOption = object of OptionType
    HostResignatureRescanResult = object of DynamicData
    VirtualSriovEthernetCardSriovBackingOption = object of VirtualDeviceBackingOption
    NumVirtualCpusIncompatible = object of VmConfigFault
    HostNetworkResource = object of DynamicData
    DrsWorkloadCharacterization = object of DynamicData
    VirtualEthernetCardNotSupported = object of DeviceNotSupported
    DasHeartbeatDatastoreInfo = object of DynamicData
    VmfsConfigOption = object of DynamicData
    ClusterDasVmcpPrecheckResult = object of DynamicData
    UserSearchResult = object of DynamicData
    HostMultipathInfoPath = object of DynamicData
    ClusterMigrationAction = object of ClusterAction
    HostDatastoreSystemDatastoreResult = object of DynamicData
    CannotModifyConfigCpuRequirements = object of MigrationFault
    ExtendedEventPair = object of DynamicData
    TaskFilterSpec = object of DynamicData
    VirtualSCSIPassthroughOption = object of VirtualDeviceOption
    CustomizationLinuxIdentityFailed = object of CustomizationFailed
    ExternalStatsManagerProviderInfo = object of DynamicData
    AdminDisabled = object of HostConfigFault
    VirtualDiskPartitionedRawDiskVer2BackingOption = object of VirtualDiskRawDiskVer2BackingOption
    ProfileSerializedCreateSpec = object of ProfileCreateSpec
    VirtualMachineDeviceRuntimeInfoVirtualEthernetCardRuntimeState = object of VirtualMachineDeviceRuntimeInfoDeviceRuntimeState
    OptionDef = object of ElementDescription
    ClusterDasHostRecommendation = object of DynamicData
    HostLowLevelProvisioningManagerFileReserveResult = object of DynamicData
    DvsVmVnicResourceAllocation = object of DynamicData
    Event = object of DynamicData
    HostProfilePolicyOptionMapping = object of DynamicData
    HostScsiTopologyInterface = object of DynamicData
    ProxyServiceNamedPipeTunnelSpec = object of ProxyServiceTunnelSpec
    HostAccessRestrictedToManagementServer = object of NotSupported
    CDCAlarmChange = object of DynamicData
    VcAgentUninstallFailedEvent = object of HostEvent
    VirtualMachineImportSpec = object of ImportSpec
    SessionManagerGenericServiceTicket = object of DynamicData
    HostConnectInfoNetworkInfo = object of DynamicData
    VirtualDeviceDeviceBackingInfo = object of VirtualDeviceBackingInfo
    DiskIsLastRemainingNonSSD = object of VsanDiskFault
    OutOfSyncDvsHost = object of DvsEvent
    CannotAddHostWithFTVmToDifferentCluster = object of HostConnectFault
    VMotionNotConfigured = object of VMotionInterfaceIssue
    ReplicationNotSupportedOnHost = object of ReplicationFault
    VirtualCdromOption = object of VirtualDeviceOption
    ProfileExecuteError = object of DynamicData
    LimitExceeded = object of VimFault
    VirtualDeviceRemoteDeviceBackingInfo = object of VirtualDeviceBackingInfo
    HostGetShortNameFailedEvent = object of HostEvent
    HostNumaInfo = object of DynamicData
    DvsSystemTrafficNetworkRuleQualifier = object of DvsNetworkRuleQualifier
    CustomFieldValueChangedEvent = object of CustomFieldEvent
    HostMemorySpec = object of DynamicData
    ClusterDasAamHostInfo = object of ClusterDasHostInfo
    DistributedVirtualSwitchKeyedOpaqueBlob = object of DynamicData
    HostOperationCleanupManagerOperationEntry = object of DynamicData
    OvfConnectedDevice = object of OvfHardwareExport
    HostCnxFailedAlreadyManagedEvent = object of HostEvent
    VmPowerOnDisabled = object of InvalidState
    HostAuthenticationStoreInfo = object of DynamicData
    DatastoreFileDeletedEvent = object of DatastoreFileEvent
    PlacementRankSpec = object of DynamicData
    HostSystemComplianceCheckState = object of DynamicData
    CannotAccessNetwork = object of CannotAccessVmDevice
    HostVMotionCompatibility = object of DynamicData
    CustomizationDhcpIpGenerator = object of CustomizationIpGenerator
    DvsHostStatusUpdated = object of DvsEvent
    HostRuntimeInfoNetworkRuntimeInfo = object of DynamicData
    Tag = object of DynamicData
    TaskReasonAlarm = object of TaskReason
    HostVirtualNicConfig = object of DynamicData
    EVCAdmissionFailedCPUModelForMode = object of EVCAdmissionFailed
    HostDVPortgroupConfigSpec = object of DynamicData
    VmNoCompatibleHostForSecondaryEvent = object of VmEvent
    FileQueryFlags = object of DynamicData
    FcoeFaultPnicHasNoPortSet = object of FcoeFault
    VirtualEthernetCardOpaqueNetworkBackingInfo = object of VirtualDeviceBackingInfo
    FileNotFound = object of FileFault
    HostFeatureMask = object of DynamicData
    ClusterEvent = object of Event
    HostSerialAttachedHba = object of HostHostBusAdapter
    PlacementAffinityRule = object of DynamicData
    NumVirtualCoresPerSocketNotSupported = object of VirtualHardwareCompatibilityIssue
    VmDiskFileEncryptionInfo = object of DynamicData
    VmLimitLicense = object of NotEnoughLicenses
    GuestRegistryKeyParentVolatile = object of GuestRegistryKeyFault
    HostVFlashManagerVFlashResourceConfigInfo = object of DynamicData
    Context = object of DynamicData
    DatacenterMismatch = object of MigrationFault
    PMemDatastoreInfo = object of DatastoreInfo
    VmFaultToleranceTooManyVMsOnHost = object of InsufficientResourcesFault
    FaultToleranceAntiAffinityViolated = object of MigrationFault
    DvsHostInfrastructureTrafficResourceAllocation = object of DynamicData
    NotUserConfigurableProperty = object of VAppPropertyFault
    ProxyServiceTunnelSpec = object of ProxyServiceEndpointSpec
    OvfValidateHostResult = object of DynamicData
    HostDhcpService = object of DynamicData
    HttpNfcLeaseSourceFile = object of DynamicData
    TaskReasonSystem = object of TaskReason
    DVSUplinkPortPolicy = object of DynamicData
    NoCompatibleDatastore = object of VimFault
    HostIpRouteEntry = object of DynamicData
    VirtualPS2Controller = object of VirtualController
    TooManyConsecutiveOverrides = object of VimFault
    VirtualMachineTicket = object of DynamicData
    HostDiagnosticPartitionCreateDescription = object of DynamicData
    ClusterDasAdmissionControlPolicy = object of DynamicData
    TaskTimeoutEvent = object of TaskEvent
    HotSnapshotMoveNotSupported = object of SnapshotCopyNotSupported
    ProfileCategoryMetadata = object of DynamicData
    AuthenticationProfile = object of ApplyProfile
    CpuIncompatible1ECX = object of CpuIncompatible
    IntOption = object of OptionType
    HostLicenseConnectInfo = object of DynamicData
    DrsVmPoweredOnEvent = object of VmPoweredOnEvent
    OvfInvalidValueFormatMalformed = object of OvfInvalidValue
    OvfExport = object of OvfFault
    HostDiagnosticPartition = object of DynamicData
    AlarmRemovedEvent = object of AlarmEvent
    AlreadyBeingManaged = object of HostConnectFault
    ClusterDasPrecheckResult = object of DynamicData
    ServiceManagerServiceInfo = object of DynamicData
    HostDasEnablingEvent = object of HostEvent
    VMFSDatastoreExtendedEvent = object of HostEvent
    VmRemoteConsoleConnectedEvent = object of VmEvent
    ReplicationVmConfigFault = object of ReplicationConfigFault
    DeviceControllerNotSupported = object of DeviceNotSupported
    DrsEnabledEvent = object of ClusterEvent
    SpbmIoFilterInfo = object of DynamicData
    VirtualMachineNetworkShaperInfo = object of DynamicData
    HostConnectFault = object of VimFault
    HostNatService = object of DynamicData
    HostPciPassthruInfo = object of DynamicData
    VirtualMachineCdromInfo = object of VirtualMachineTargetInfo
    VmfsDatastoreBaseOption = object of DynamicData
    DvsPortCreatedEvent = object of DvsEvent
    HostDnsConfigSpec = object of HostDnsConfig
    VirtualEthernetCardResourceAllocation = object of DynamicData
    VmfsDatastoreCreateSpec = object of VmfsDatastoreSpec
    VirtualMachineDatastoreInfo = object of VirtualMachineTargetInfo
    HostCpuIdInfo = object of DynamicData
    CustomFieldDefEvent = object of CustomFieldEvent
    VirtualMachineBootOptionsBootableDiskDevice = object of VirtualMachineBootOptionsBootableDevice
    VsanHostIpConfig = object of DynamicData
    EnteringMaintenanceModeEvent = object of HostEvent
    HostDirectoryStoreInfo = object of HostAuthenticationStoreInfo
    VirtualMachineDeviceRuntimeInfoDeviceRuntimeState = object of DynamicData
    HbrObjectTag = object of DynamicData
    ClusterDasFailoverLevelAdvancedRuntimeInfoVmSlots = object of DynamicData
    UncommittedUndoableDisk = object of MigrationFault
    DVSKeyedOpaqueDataList = object of DynamicData
    VirtualSoundCardDeviceBackingInfo = object of VirtualDeviceDeviceBackingInfo
    InsufficientStandbyMemoryResource = object of InsufficientStandbyResource
    RemoteTSMEnabledEvent = object of HostEvent
    NetworkProfile = object of ApplyProfile
    OptionProfile = object of ApplyProfile
    VirtualMachineMksTicket = object of DynamicData
    HostAdminEnableEvent = object of HostEvent
    HostConnectSpec = object of DynamicData
    VirtualNVDIMMBackingInfo = object of VirtualDeviceFileBackingInfo
    OvfMissingElementNormalBoundary = object of OvfMissingElement
    NoCompatibleHost = object of VimFault
    FormattedHostProfilesCustomizations = object of HostProfilesEntityCustomizations
    HostPlugStoreTopologyTarget = object of DynamicData
    VirtualMachineConfigInfoOverheadInfo = object of DynamicData
    HostInternetScsiHbaSendTarget = object of DynamicData
    VirtualDiskFlatVer1BackingOption = object of VirtualDeviceFileBackingOption
    AlarmEvent = object of Event
    EntityBackupConfig = object of DynamicData
    OvfInvalidValueEmpty = object of OvfInvalidValue
    OvfToXmlUnsupportedElement = object of OvfSystemFault
    HostSriovDevicePoolInfo = object of DynamicData
    VsanHostClusterStatus = object of DynamicData
    VAppPropertySpec = object of ArrayUpdateSpec
    OvfUnsupportedAttribute = object of OvfUnsupportedPackage
    EventArgument = object of DynamicData
    HostEnableAdminFailedEvent = object of HostEvent
    OvfPropertyQualifierDuplicate = object of OvfProperty
    DiagnosticManagerLogDescriptor = object of DynamicData
    CustomizationSpec = object of DynamicData
    VslmCreateSpecDiskFileBackingSpec = object of VslmCreateSpecBackingSpec
    PowerSystemInfo = object of DynamicData
    VmfsDatastoreOption = object of DynamicData
    DatastoreFileCopiedEvent = object of DatastoreFileEvent
    UpdateVirtualMachineFilesResultFailedVmFileInfo = object of DynamicData
    VmMessageErrorEvent = object of VmEvent
    NasVolumeNotMounted = object of NasConfigFault
    HostInternetScsiHbaIPProperties = object of DynamicData
    HostPlugStoreTopology = object of DynamicData
    CannotReconfigureVsanWhenHaEnabled = object of VsanFault
    HostScsiDisk = object of ScsiLun
    SSPIAuthentication = object of GuestAuthentication
    VirtualPointingDeviceBackingOption = object of VirtualDeviceDeviceBackingOption
    VmDiscoveredEvent = object of VmEvent
    HostFlagInfo = object of DynamicData
    HostPowerPolicy = object of DynamicData
    VirtualDiskModeNotSupported = object of DeviceNotSupported
    HostMonitoringStateChangedEvent = object of ClusterEvent
    SnapshotNoChange = object of SnapshotFault
    VStorageObjectAssociationsVmDiskAssociations = object of DynamicData
    VirtualMachineFileLayoutExDiskLayout = object of DynamicData
    InsufficientStorageIops = object of VimFault
    VirtualHardwareVersionNotSupported = object of VirtualHardwareCompatibilityIssue
    HostInternetScsiHbaDigestProperties = object of DynamicData
    CannotUseNetwork = object of VmConfigFault
    InaccessibleDatastore = object of InvalidDatastore
    CustomizationIpGenerator = object of DynamicData
    StorageDrsCannotMoveTemplate = object of VimFault
    DvsUpdateTagNetworkRuleAction = object of DvsNetworkRuleAction
    EVCMode = object of ElementDescription
    StorageDrsConfigInfo = object of DynamicData
    DasDisabledEvent = object of ClusterEvent
    LicenseUsageInfo = object of DynamicData
    PerfMetricIntSeries = object of PerfMetricSeries
    HostIntegrityReportQuoteData = object of DynamicData
    HostParallelScsiTargetTransport = object of HostTargetTransport
    SnapshotMoveFromNonHomeNotSupported = object of SnapshotCopyNotSupported
    SendSNMPAction = object of Action
    InvalidVmState = object of InvalidState
    HostNasVolumeSpec = object of DynamicData
    VmRemovedEvent = object of VmEvent
    VsanHostConfigInfoStorageInfo = object of DynamicData
    PolicyViolatedDetail = object of VimFault
    BoolPolicy = object of InheritablePolicy
    InvalidDasRestartPriorityForFtVm = object of InvalidArgument
    NetworksMayNotBeTheSame = object of MigrationFault
    VirtualDiskSparseVer1BackingOption = object of VirtualDeviceFileBackingOption
    DuplicateDisks = object of VsanDiskFault
    FailToEnableSPBM = object of NotEnoughLicenses
    DrsEnteredStandbyModeEvent = object of EnteredStandbyModeEvent
    VAppCloneSpecResourceMap = object of DynamicData
    HostReconnectionFailedEvent = object of HostEvent
    VirtualMachineInstantCloneSpec = object of DynamicData
    GuestProgramSpec = object of DynamicData
    PolicyViolated = object of RuntimeFault
    OperationDisabledByGuest = object of GuestOperationsFault
    ServiceLocator = object of DynamicData
    DVSNetworkResourceManagementCapability = object of DynamicData
    VmAcquiredTicketEvent = object of VmEvent
    DirectoryNotEmpty = object of FileFault
    VmPodConfigForPlacement = object of DynamicData
    GuestAuthAnySubject = object of GuestAuthSubject
    PatchInstallFailed = object of PlatformConfigFault
    DasHostIsolatedEvent = object of ClusterEvent
    DVPortState = object of DynamicData
    VirtualDeviceBackingOption = object of DynamicData
    VirtualUSBUSBBackingOption = object of VirtualDeviceDeviceBackingOption
    VirtualDeviceURIBackingInfo = object of VirtualDeviceBackingInfo
    HostInternetScsiHbaStaticTarget = object of DynamicData
    StateAlarmExpression = object of AlarmExpression
    DvsEventArgument = object of EntityEventArgument
    StorageRequirement = object of DynamicData
    DeviceNotSupported = object of VirtualHardwareCompatibilityIssue
    GuestRegValueExpandStringSpec = object of GuestRegValueDataSpec
    DvsApplyOperationFault = object of DvsFault
    InvalidLocale = object of VimFault
    NotSupportedHostForVmemFile = object of NotSupportedHost
    NotSupportedHostForVmcp = object of NotSupportedHost
    PhysicalNicIpHint = object of PhysicalNicHint
    VirtualMachineBootOptionsBootableDevice = object of DynamicData
    NetworkEventArgument = object of EntityEventArgument
    OvfNoHostNic = object of OvfUnsupportedPackage
    UnableToPlacePrerequisiteGroup = object of VimFault
    VmFailedMigrateEvent = object of VmEvent
    VmWwnChangedEvent = object of VmEvent
    LeaseFault = object of VimFault
    VirtualFloppyDeviceBackingOption = object of VirtualDeviceDeviceBackingOption
    HostVirtualNicSpec = object of DynamicData
    HostFirewallRulesetIpNetwork = object of DynamicData
    VirtualPCIControllerOption = object of VirtualControllerOption
    NotSupportedHostInCluster = object of NotSupportedHost
    DvsVmVnicNetworkResourcePoolRuntimeInfo = object of DynamicData
    HostConfigSummary = object of DynamicData
    VmReloadFromPathEvent = object of VmEvent
    VmUpgradeCompleteEvent = object of VmEvent
    HostVirtualSwitchSpec = object of DynamicData
    MigrationNotReady = object of MigrationFault
    HostMultipathInfoFixedLogicalUnitPolicy = object of HostMultipathInfoLogicalUnitPolicy
    VmReloadFromPathFailedEvent = object of VmEvent
    ResourcePoolMovedEvent = object of ResourcePoolEvent
    DatastoreDiscoveredEvent = object of HostEvent
    DeviceNotFound = object of InvalidDeviceSpec
    DatastoreIORMReconfiguredEvent = object of DatastoreEvent
    FtIssuesOnHost = object of VmFaultToleranceIssue
    DatastorePrincipalConfigured = object of HostEvent
    LinkLayerDiscoveryProtocolInfo = object of DynamicData
    StorageDrsCannotMoveDiskInMultiWriterMode = object of VimFault
    LocalizationManagerMessageCatalog = object of DynamicData
    ClusterDiagnoseResourceAllocationResultVmStaticEntitlement = object of DynamicData
    VmfsUnmapBandwidthSpec = object of DynamicData
    StorageDrsVmConfigInfo = object of DynamicData
    BadUsernameSessionEvent = object of SessionEvent
    OvfPropertyExport = object of OvfExport
    NetIpStackInfoDefaultRouter = object of DynamicData
    ProfileHostHostCustomizationOperationIssues = object of DynamicData
    VirtualEthernetCardOpaqueNetworkBackingOption = object of VirtualDeviceBackingOption
    CryptoManagerKmipServerCertInfo = object of DynamicData
    InvalidDatastore = object of VimFault
    InvalidIndexArgument = object of InvalidArgument
    InvalidDrsBehaviorForFtVm = object of InvalidArgument
    OvfUnsupportedDeviceBackingInfo = object of OvfSystemFault
    VirtualMachineSoundInfo = object of VirtualMachineTargetInfo
    VirtualMachineNamespaceManagerAccessMode = object of DynamicData
    StorageProfile = object of ApplyProfile
    AlarmTriggeringAction = object of AlarmAction
    HostProfileMapping = object of DynamicData
    AlreadyExists = object of VimFault
    NoClientCertificate = object of VimFault
    NoVirtualNic = object of HostConfigFault
    DisallowedDiskModeChange = object of InvalidDeviceSpec
    VsanHostDecommissionMode = object of DynamicData
    HostLicenseExpiredEvent = object of LicenseEvent
    CryptoSpecDeepRecrypt = object of CryptoSpec
    VirtualMachineNamespaceManagerDataInfo = object of DynamicData
    VmBeingHotMigratedEvent = object of VmEvent
    PerfCounterInfo = object of DynamicData
    AnswerFileValidationResultMap = object of DynamicData
    EntityDisabledMethodInfo = object of DynamicData
    ScheduledTaskCreatedEvent = object of ScheduledTaskEvent
    NegatableExpression = object of DynamicData
    VirtualFloppyRemoteDeviceBackingOption = object of VirtualDeviceRemoteDeviceBackingOption
    ClusterDasFdmHostState = object of DynamicData
    HostDVSPortData = object of DynamicData
    NotEnoughResourcesToStartVmEvent = object of VmEvent
    StoragePodSummary = object of DynamicData
    LicenseDataManagerEntityLicenseData = object of DynamicData
    MemorySizeNotSupportedByDatastore = object of VirtualHardwareCompatibilityIssue
    VirtualSwitchSelectionProfile = object of ApplyProfile
    CannotDeleteFile = object of FileFault
    CbrcVmdkLockFailure = object of VimFault
    DVSMacManagementPolicy = object of InheritablePolicy
    VMwareDVSVlanHealthCheckResult = object of HostMemberUplinkHealthCheckResult
    HostDhcpServiceSpec = object of DynamicData
    EVCAdmissionFailedCPUVendor = object of EVCAdmissionFailed
    IscsiDependencyEntity = object of DynamicData
    MetricAlarmExpression = object of AlarmExpression
    VslmCreateSpec = object of DynamicData
    MacRange = object of MacAddress
    DVSOpaqueData = object of DynamicData
    HostLowLevelProvisioningManagerFileDeleteResult = object of DynamicData
    CannotMoveFaultToleranceVm = object of VimFault
    PerfMetricSeriesCSV = object of PerfMetricSeries
    OperationDisallowedOnHost = object of RuntimeFault
    EVCUnsupportedByHostHardware = object of EVCConfigFault
    ImportSpec = object of DynamicData
    VmEventArgument = object of EntityEventArgument
    InsufficientAgentVmsDeployed = object of InsufficientResourcesFault
    DataProviderFilter = object of DynamicData
    HostDVSPortCloneSpec = object of DynamicData
    VsanUpgradeSystemUpgradeStatus = object of DynamicData
    VirtualMachineProfileRawData = object of DynamicData
    VmPortGroupProfile = object of PortGroupProfile
    PerfEntityMetricCSV = object of PerfEntityMetricBase
    ProxyServiceRemoteTunnelSpec = object of ProxyServiceTunnelSpec
    EventAlarmExpression = object of AlarmExpression
    SnapshotFault = object of VimFault
    AffinityConfigured = object of MigrationFault
    DistributedVirtualSwitchPortConnectee = object of DynamicData
    OutOfBounds = object of VimFault
    HostDatastoreSystemCapabilities = object of DynamicData
    VirtualMachineSnapshotTree = object of DynamicData
    ExtensionEventTypeInfo = object of DynamicData
    InvalidNetworkResource = object of NasConfigFault
    InvalidLogin = object of VimFault
    VirtualMachinePowerPolicy = object of DynamicData
    HostDasEnabledEvent = object of HostEvent
    ClusterHostPowerAction = object of ClusterAction
    CryptoManagerKmipCertificateInfo = object of DynamicData
    InsufficientStandbyCpuResource = object of InsufficientStandbyResource
    NotAFile = object of FileFault
    HostIpmiInfo = object of DynamicData
    VirtualMachineBootOptionsBootableFloppyDevice = object of VirtualMachineBootOptionsBootableDevice
    EsxAgentConfigManagerComputeResourceAgentInfo = object of DynamicData
    ExternalStatsManagerMetricValueMap = object of DynamicData
    DistributedVirtualSwitchPortStatistics = object of DynamicData
    InventoryDescription = object of DynamicData
    VmStartReplayingEvent = object of VmEvent
    OptionValue = object of DynamicData
    ClusterVmComponentProtectionSettings = object of DynamicData
    EntityBackup = object of DynamicData
    EventArgDesc = object of DynamicData
    SelectionSet = object of DynamicData
    VmRelocateSpecEvent = object of VmEvent
    ApplyProfile = object of DynamicData
    HostGatewaySpec = object of DynamicData
    ClusterConfigInfo = object of DynamicData
    HostActiveDirectoryInfo = object of HostDirectoryStoreInfo
    CbrcDigestRecomputeResult = object of CbrcDigestOperationResult
    UnSupportedDatastoreForVFlash = object of UnsupportedDatastore
    FloppyImageFileInfo = object of FileInfo
    DrsHostIormStatus = object of DynamicData
    VirtualMachineVMIROM = object of VirtualDevice
    NumVirtualCpusExceedsLimit = object of InsufficientResourcesFault
    VsanHostRuntimeInfoDiskIssue = object of DynamicData
    HostConfigInfo = object of DynamicData
    HostAccountSpec = object of DynamicData
    HostShutdownEvent = object of HostEvent
    MismatchedNetworkPolicies = object of MigrationFault
    ProfileHostProfileEngineDvPortgroupInfo = object of DynamicData
    TaskFilterSpecByUsername = object of DynamicData
    FaultTolerancePrimaryPowerOnNotAttempted = object of VmFaultToleranceIssue
    VirtualUSBControllerPciBusSlotInfo = object of VirtualDevicePciBusSlotInfo
    HostOperationCleanupManagerCleanupItemEntry = object of DynamicData
    VmMacConflictEvent = object of VmEvent
    DVPortgroupCreatedEvent = object of DVPortgroupEvent
    ScheduledTaskCompletedEvent = object of ScheduledTaskEvent
    IscsiPortInfo = object of DynamicData
    DatacenterEvent = object of Event
    LicenseAssignmentManagerFeatureLicenseAvailability = object of DynamicData
    VsanUpgradeSystemHostsDisconnectedIssue = object of VsanUpgradeSystemPreflightCheckIssue
    DvsServiceConsoleVNicProfile = object of DvsVNicProfile
    HostDiskBlockInfoExtent = object of DynamicData
    EightHostLimitViolated = object of VmConfigFault
    HostProfileManagerExportCustomizationsResult = object of FormattedHostProfilesCustomizations
    VchaClusterConfigSpec = object of DynamicData
    EnvironmentBrowserConfigTargetQuerySpec = object of DynamicData
    VmFaultToleranceVmTerminatedEvent = object of VmEvent
    ReplicationConfigSpec = object of DynamicData
    VirtualMachineMemoryReservationSpec = object of DynamicData
    VmConfigInfo = object of DynamicData
    VchaClusterRuntimeInfo = object of DynamicData
    VmfsAmbiguousMount = object of VmfsMountFault
    TemplateConfigFileInfo = object of VmConfigFileInfo
    ProxyServiceNamedPipeServiceSpec = object of ProxyServiceServiceSpec
    HostOpaqueSwitch = object of DynamicData
    HostIntegrityReport = object of DynamicData
    VirtualMachineParallelInfo = object of VirtualMachineTargetInfo
    HostPMemVolume = object of HostFileSystemVolume
    VmEndReplayingEvent = object of VmEvent
    IncompatibleHostForFtSecondary = object of VmFaultToleranceIssue
    VirtualMachineBootOptionsBootableCdromDevice = object of VirtualMachineBootOptionsBootableDevice
    HostGraphicsConfig = object of DynamicData
    HostVsanInternalSystemDeleteVsanObjectsResult = object of DynamicData
    VirtualDiskAntiAffinityRuleSpec = object of ClusterRuleInfo
    BackupBlobWriteFailure = object of DvsFault
    HostDVSVmwareConfigSpec = object of DynamicData
    DistributedVirtualPort = object of DynamicData
    OvfUnableToExportDisk = object of OvfHardwareExport
    ScheduledTaskDescription = object of DynamicData
    SwapPlacementOverrideNotSupported = object of InvalidVmConfig
    OvfImportFailed = object of OvfImport
    IscsiFaultVnicNotFound = object of IscsiFault
    ProfileHostProfileEngineHostProfileManagerProfileCategoryMetaArray = object of DynamicData
    DvsNetworkRuleAction = object of DynamicData
    PodStorageDrsEntry = object of DynamicData
    RemoveFailed = object of VimFault
    InsufficientHostCapacityFault = object of InsufficientResourcesFault
    GuestPermissionDenied = object of GuestOperationsFault
    DeviceHotPlugNotSupported = object of InvalidDeviceSpec
    VirtualLsiLogicController = object of VirtualSCSIController
    HostLicenseSpec = object of DynamicData
    VMwareDVSVspanCapability = object of DynamicData
    GuestRegValueDataSpec = object of DynamicData
    VMwareDvsLacpGroupSpec = object of DynamicData
    vslmInfrastructureObjectPolicySpec = object of DynamicData
    NoPermissionOnHost = object of HostConnectFault
    StorageVmotionIncompatible = object of VirtualHardwareCompatibilityIssue
    InvalidState = object of VimFault
    VirtualCdromPassthroughBackingOption = object of VirtualDeviceDeviceBackingOption
    VmLogFileQuery = object of FileQuery
    NoCompatibleHardAffinityHost = object of VmConfigFault
    VsanClusterUuidMismatch = object of CannotMoveVsanEnabledHost
    VirtualMachineGuestIntegrityInfo = object of DynamicData
    InvalidIpmiLoginInfo = object of VimFault
    ProfileUpdateFailed = object of VimFault
    DvsHostLeftEvent = object of DvsEvent
    VmFailedToRebootGuestEvent = object of VmEvent
    VimFault = object of MethodFault
    HostMaintenanceSpec = object of DynamicData
    ComplianceFailureComplianceFailureValues = object of DynamicData
    SnapshotDisabled = object of SnapshotFault
    NetworkProfileDnsConfigProfile = object of ApplyProfile
    VirtualParallelPortFileBackingOption = object of VirtualDeviceFileBackingOption
    HostHardwareSummary = object of DynamicData
    ProfileAssociatedEvent = object of ProfileEvent
    DVPortgroupSelection = object of SelectionSet
    IScsiBootFailureEvent = object of HostEvent
    HostNetworkConfigNetStackSpec = object of DynamicData
    VirtualDiskLocalPMemBackingOption = object of VirtualDeviceFileBackingOption
    VirtualAppSummary = object of ResourcePoolSummary
    HostProxySwitchHostLagConfig = object of DynamicData
    ProfileExpressionMetadata = object of DynamicData
    HostConnectionLostEvent = object of HostEvent
    VAppProductSpec = object of ArrayUpdateSpec
    LicenseRestricted = object of NotEnoughLicenses
    VmConfigFileQueryFlags = object of DynamicData
    ModeInfo = object of DynamicData
    HostNasVolume = object of HostFileSystemVolume
    ActiveDirectoryFault = object of VimFault
    HostConfigFailed = object of HostConfigFault
    HostPatchManagerLocator = object of DynamicData
    HostVMotionConfig = object of DynamicData
    HostDiskMappingPartitionInfo = object of DynamicData
    ResourcePoolReconfiguredEvent = object of ResourcePoolEvent
    VirtualControllerOption = object of VirtualDeviceOption
    VirtualCdrom = object of VirtualDevice
    HostProfilePolicyMapping = object of DynamicData
    HostFirewallRule = object of DynamicData
    HostInternetScsiHbaDigestCapabilities = object of DynamicData
    TaskReason = object of DynamicData
    VVolVmConfigFileUpdateResult = object of DynamicData
    VsanDecommissioningBatch = object of DynamicData
    VirtualBusLogicController = object of VirtualSCSIController
    HostPrimaryAgentNotShortNameEvent = object of HostDasEvent
    HostDVSCreateSpec = object of HostDVSConfigSpec
    NetStackInstanceProfile = object of ApplyProfile
    HostFaultToleranceManagerComponentHealthInfo = object of DynamicData
    VirtualSCSIPassthroughDeviceBackingOption = object of VirtualDeviceDeviceBackingOption
    DVSTrafficShapingPolicy = object of InheritablePolicy
    DvsCreatedEvent = object of DvsEvent
    HostSystemSwapConfigurationDisabledOption = object of HostSystemSwapConfigurationSystemSwapOption
    StorageMigrationAction = object of ClusterAction
    TicketedSessionAuthentication = object of GuestAuthentication
    NoAvailableIp = object of VAppPropertyFault
    DrsResourceConfigureSyncedEvent = object of HostEvent
    CannotEnableVmcpForCluster = object of VimFault
    NetIpConfigSpecIpAddressSpec = object of DynamicData
    OvfProperty = object of OvfInvalidPackage
    ClusterGroupInfo = object of DynamicData
    NotSupportedHostForVsan = object of NotSupportedHost
    LongPolicy = object of InheritablePolicy
    ExtensionClientInfo = object of DynamicData
    PreCallbackResult = object of DynamicData
    VirtualMachineDeviceRuntimeInfo = object of DynamicData
    WinNetBIOSConfigInfo = object of NetBIOSConfigInfo
    DistributedVirtualSwitchProductSpec = object of DynamicData
    QuiesceDatastoreIOForHAFailed = object of ResourceInUse
    ClusterAttemptedVmInfo = object of DynamicData
    ClusterNotAttemptedVmInfo = object of DynamicData
    VirtualUSB = object of VirtualDevice
    DvsPortExitedPassthruEvent = object of DvsEvent
    VmDiskFileQuery = object of FileQuery
    DatabaseError = object of RuntimeFault
    VirtualDeviceConnectOption = object of DynamicData
    HostSriovConfig = object of HostPciPassthruConfig
    IoFilterInfo = object of DynamicData
    HostSyncFailedEvent = object of HostEvent
    VirtualSerialPortURIBackingInfo = object of VirtualDeviceURIBackingInfo
    HostServiceInfo = object of DynamicData
    InvalidClientCertificate = object of InvalidLogin
    HostVsanInternalSystemVsanObjectOperationResult = object of DynamicData
    GuestStackInfo = object of DynamicData
    HostIsolationIpPingFailedEvent = object of HostDasEvent
    GuestAuthSubject = object of DynamicData
    VmGuestRebootEvent = object of VmEvent
    StorageIOAllocationInfo = object of DynamicData
    NvdimmInterleaveSetInfo = object of DynamicData
    FailoverLevelRestored = object of ClusterEvent
    HostDiskPartitionBlockRange = object of DynamicData
    CannotChangeHaSettingsForFtSecondary = object of VmFaultToleranceIssue
    PlacementResult = object of DynamicData
    HostPciPassthruConfig = object of DynamicData
    RollbackFailure = object of DvsFault
    HostInternetScsiHbaIscsiIpv6Address = object of DynamicData
    CpuIncompatible = object of VirtualHardwareCompatibilityIssue
    DvsPortUnblockedEvent = object of DvsEvent
    ResourceViolatedEvent = object of ResourcePoolEvent
    UserAssignedToGroup = object of HostEvent
    HostTelemetryInfo = object of DynamicData
    VirtualMachineNamespaceManagerNamespaceInfo = object of DynamicData
    VmSecondaryStartedEvent = object of VmEvent
    ClusterDasData = object of DynamicData
    VmConnectedEvent = object of VmEvent
    PowerOnFtSecondaryFailed = object of VmFaultToleranceIssue
    VmUpgradeFailedEvent = object of VmEvent
    LicenseServerUnavailableEvent = object of LicenseEvent
    HostMemoryProfile = object of ApplyProfile
    VAppNotRunning = object of VmConfigFault
    ID = object of DynamicData
    SSLVerifyFault = object of HostConnectFault
    ProfileExpression = object of DynamicData
    HostScsiTopologyLun = object of DynamicData
    DvsRestoreEvent = object of DvsEvent
    EVCAdmissionFailedHostSoftware = object of EVCAdmissionFailed
    CDCChangeSet = object of DynamicData
    ConfigTarget = object of DynamicData
    MissingController = object of InvalidDeviceSpec
    VsanClusterConfigInfo = object of DynamicData
    ClusterDrsConfigInfo = object of DynamicData
    CustomizationNetworkSetupFailed = object of CustomizationFailed
    DvsFilterParameter = object of DynamicData
    VirtualNVDIMMOption = object of VirtualDeviceOption
    HostMissingNetworksEvent = object of HostDasEvent
    VirtualSerialPortOption = object of VirtualDeviceOption
    DvsUpgradeRejectedEvent = object of DvsEvent
    VmFailedToResetEvent = object of VmEvent
    HostSubSpecification = object of DynamicData
    GuestNicInfo = object of DynamicData
    CannotChangeDrsBehaviorForFtSecondary = object of VmFaultToleranceIssue
    HostRuntimeInfoNetStackInstanceRuntimeInfo = object of DynamicData
    HostInDomain = object of HostConfigFault
    DrsExitStandbyModeFailedEvent = object of ExitStandbyModeFailedEvent
    ResourceAllocationOption = object of DynamicData
    MigrationFeatureNotSupported = object of MigrationFault
    MtuMatchEvent = object of DvsHealthStatusChangeEvent
    PhysicalNicNameHint = object of PhysicalNicHint
    CbrcDeviceBackingNotSupported = object of VmConfigFault
    FileNotWritable = object of FileFault
    HostTpmCommandEventDetails = object of HostTpmEventDetails
    HttpNfcLeaseHostInfo = object of DynamicData
    VmMacAssignedEvent = object of VmEvent
    OvfUnsupportedDeviceExport = object of OvfHardwareExport
    PolicyViolatedValueTooBig = object of PolicyViolatedByValue
    VmUuidConflictEvent = object of VmEvent
    CustomizationSucceeded = object of CustomizationEvent
    HostSslThumbprintInfo = object of DynamicData
    ManagedEntityEventArgument = object of EntityEventArgument
    VnicPortArgument = object of DynamicData
    GuestFileAttributes = object of DynamicData
    DuplicateIpDetectedEvent = object of HostEvent
    InaccessibleVFlashSource = object of VimFault
    OvfConnectedDeviceIso = object of OvfConnectedDevice
    EVCAdmissionFailedVmActive = object of EVCAdmissionFailed
    VirtualMachineProfileDetails = object of DynamicData
    ScheduledTaskEvent = object of Event
    EventAlarmExpressionComparison = object of DynamicData
    DVPortgroupEvent = object of Event
    OvfPropertyType = object of OvfProperty
    VirtualMachineScsiPassthroughInfo = object of VirtualMachineTargetInfo
    ProfileParameterMetadata = object of DynamicData
    HostDiskConfigurationResult = object of DynamicData
    VsanHostMembershipInfo = object of DynamicData
    EventFilterSpecByUsername = object of DynamicData
    HostPlugStoreTopologyPlugin = object of DynamicData
    ResourcePoolSummary = object of DynamicData
    ExtensionTaskTypeInfo = object of DynamicData
    VmStartingEvent = object of VmEvent
    DrsRuleViolationEvent = object of VmEvent
    VirtualParallelPortDeviceBackingOption = object of VirtualDeviceDeviceBackingOption
    HostDiagnosticPartitionCreateSpec = object of DynamicData
    GuestRegistryKeyHasSubkeys = object of GuestRegistryKeyFault
    HostShortNameToIpFailedEvent = object of HostEvent
    VirtualSoundBlaster16 = object of VirtualSoundCard
    VMwareDvsLacpCapability = object of DynamicData
    VirtualSoundCardOption = object of VirtualDeviceOption
    CbrcDeviceSpec = object of DynamicData
    HostProxySwitch = object of DynamicData
    OvfDuplicatedElementBoundary = object of OvfElement
    CustomizationIPSettingsIpV6AddressSpec = object of DynamicData
    HealthUpdate = object of DynamicData
    HostFirewallRulesetIpList = object of DynamicData
    ClusterDestroyedEvent = object of ClusterEvent
    OvfConsumerResult = object of DynamicData
    ClusterProfileCompleteConfigSpec = object of ClusterProfileConfigSpec
    CustomizationAutoIpV6Generator = object of CustomizationIpV6Generator
    HostVvolVolume = object of HostFileSystemVolume
    ServerLicenseExpiredEvent = object of LicenseEvent
    CpuCompatibilityUnknown = object of CpuIncompatible
    VAppIPAssignmentInfo = object of DynamicData
    VmEvent = object of Event
    VirtualUSBRemoteHostBackingInfo = object of VirtualDeviceDeviceBackingInfo
    ProxyServiceLocalServiceSpec = object of ProxyServiceServiceSpec
    LicenseAssignmentManagerEntityArgs = object of DynamicData
    CbrcDigestOperationResult = object of DynamicData
    HostSpecificationOperationFailed = object of VimFault
    HostDiskDimensions = object of DynamicData
    HostHardwareStatusInfo = object of DynamicData
    DVSRuntimeInfo = object of DynamicData
    ProxyServiceRedirectSpec = object of ProxyServiceEndpointSpec
    VirtualAppImportSpec = object of ImportSpec
    VmResourceReallocatedEvent = object of VmEvent
    VasaClientContextSpec = object of DynamicData
    VmMessageWarningEvent = object of VmEvent
    NoPermissionOnNasVolume = object of NasConfigFault
    VirtualDiskFlatVer2BackingInfo = object of VirtualDeviceFileBackingInfo
    RecordReplayDisabled = object of VimFault
    UplinkPortResourceSpec = object of DynamicData
    HostMultipathInfoLogicalUnitPolicy = object of DynamicData
    HostDasDisablingEvent = object of HostEvent
    HostVirtualNicManagerNicTypeSelection = object of DynamicData
    HostProfileSerializedHostProfileSpec = object of ProfileSerializedCreateSpec
    VirtualMachineFileLayoutDiskLayout = object of DynamicData
    CustomFieldDef = object of DynamicData
    PatchNotApplicable = object of VimFault
    HostPortGroupProfile = object of PortGroupProfile
    ResourcePoolCreatedEvent = object of ResourcePoolEvent
    HostUpdateProxyConfigInfo = object of DynamicData
    DrsDisabledEvent = object of ClusterEvent
    FaultToleranceSecondaryConfigInfo = object of FaultToleranceConfigInfo
    FaultToleranceVmNotDasProtected = object of VimFault
    GuestRegistryKeyInvalid = object of GuestRegistryKeyFault
    ImportOperationBulkFaultFaultOnImport = object of DynamicData
    VirtualNVMEControllerOption = object of VirtualControllerOption
    VmFailedToPowerOnEvent = object of VmEvent
    AlarmSnmpFailedEvent = object of AlarmEvent
    CustomizationSysprepText = object of CustomizationIdentitySettings
    VirtualNVMEController = object of VirtualController
    HostAdminDisableEvent = object of HostEvent
    NvdimmDimmInfo = object of DynamicData
    HostInventoryFullEvent = object of LicenseEvent
    VirtualDiskRuleSpec = object of ClusterRuleInfo
    VirtualSriovEthernetCardOption = object of VirtualEthernetCardOption
    DvsPortRuntimeChangeEvent = object of DvsEvent
    StorageDrsOptionSpec = object of ArrayUpdateSpec
    VmNvramFileQuery = object of FileQuery
    AuthorizationDescription = object of DynamicData
    HostWakeOnLanConfig = object of DynamicData
    NoGuestHeartbeat = object of MigrationFault
    VMwareDVSPortSetting = object of DVPortSetting
    NamespaceWriteProtected = object of VimFault
    VmfsDatastoreExtendSpec = object of VmfsDatastoreSpec
    VirtualAHCIControllerOption = object of VirtualSATAControllerOption
    CbrcDigestConfigureResult = object of CbrcDigestOperationResult
    HostServiceTicket = object of DynamicData
    DvsHostWentOutOfSyncEvent = object of DvsEvent
    GuestRegistryValueFault = object of GuestRegistryFault
    EventFilterSpec = object of DynamicData
    ProfileDissociatedEvent = object of ProfileEvent
    VirtualEnsoniq1371Option = object of VirtualSoundCardOption
    OvfMissingElement = object of OvfElement
    ExitingStandbyModeEvent = object of HostEvent
    CheckResult = object of DynamicData
    VmDiskFileQueryFilter = object of DynamicData
    ClusterFixedSizeSlotPolicy = object of ClusterSlotPolicy
    DataProviderBatchResultSet = object of DynamicData
    DistributedVirtualSwitchHostMemberPnicSpec = object of DynamicData
    EventDescriptionEventDetail = object of DynamicData
    HostFirewallRuleset = object of DynamicData
    ProfileRemovedEvent = object of ProfileEvent
    ExtensionResourceInfo = object of DynamicData
    UpdateVirtualMachineFilesResult = object of DynamicData
    DvsMacRewriteNetworkRuleAction = object of DvsNetworkRuleAction
    SessionEvent = object of Event
    GuestAuthNamedSubject = object of GuestAuthSubject
    RollbackEvent = object of DvsEvent
    GuestOperationsUnavailable = object of GuestOperationsFault
    CryptoSpecNoOp = object of CryptoSpec
    UplinkPortMtuNotSupportEvent = object of DvsHealthStatusChangeEvent
    VirtualMachinePciSharedGpuPassthroughInfo = object of VirtualMachineTargetInfo
    ClusterDependencyRuleInfo = object of ClusterRuleInfo
    ClusterEVCManagerCheckResult = object of DynamicData
    HostFileAccess = object of DynamicData
    OvfPropertyQualifierIgnored = object of OvfProperty
    DvsProfile = object of ApplyProfile
    HostProfileValidationFailureInfo = object of DynamicData
    HostProfileAttributeCondition = object of DynamicData
    VMotionLinkCapacityLow = object of VMotionInterfaceIssue
    VmwareDistributedVirtualSwitchVlanIdSpec = object of VmwareDistributedVirtualSwitchVlanSpec
    HostPortGroup = object of DynamicData
    NetIpRouteConfigSpecIpRouteSpec = object of DynamicData
    GuestRegKeyNameSpec = object of DynamicData
    InsufficientVFlashResourcesFault = object of InsufficientResourcesFault
    ExtensionServerInfo = object of DynamicData
    DvsRenamedEvent = object of DvsEvent
    SecurityProfile = object of ApplyProfile
    HostScsiTopology = object of DynamicData
    IscsiFaultVnicIsLastPath = object of IscsiFault
    VsanUpgradeSystemRogueHostsInClusterIssue = object of VsanUpgradeSystemPreflightCheckIssue
    VStorageObjectSnapshotInfoVStorageObjectSnapshot = object of DynamicData
    DvsPortBlockedEvent = object of DvsEvent
    VirtualPCIPassthroughDeviceBackingOption = object of VirtualDeviceDeviceBackingOption
    NonHomeRDMVMotionNotSupported = object of MigrationFeatureNotSupported
    OvfElement = object of OvfInvalidPackage
    ClusterRuleInfo = object of DynamicData
    VirtualMachineMetadataManagerVmMetadata = object of DynamicData
    ScheduledTaskStartedEvent = object of ScheduledTaskEvent
    VirtualMachineNamespaceManagerQueryResult = object of DynamicData
    HostConnectedEvent = object of HostEvent
    VirtualMachineVMCIDevice = object of VirtualDevice
    VsanHostClusterStatusState = object of DynamicData
    DVSInheritedOpaqueData = object of DVSOpaqueData
    DvsTrafficFilterConfig = object of DvsFilterConfig
    VMotionProtocolIncompatible = object of MigrationFault
    CustomFieldDefRemovedEvent = object of CustomFieldDefEvent
    DvsOutOfSyncHostArgument = object of DynamicData
    StoragePlacementSpec = object of DynamicData
    OvfConsumerUndeclaredSection = object of OvfConsumerCallbackFault
    VirtualDeviceConnectInfo = object of DynamicData
    HostInternetScsiHbaAuthenticationProperties = object of DynamicData
    TpmFault = object of VimFault
    HostNewNetworkConnectInfo = object of HostConnectInfoNetworkInfo
    StorageDrsCannotMoveIndependentDisk = object of VimFault
    GenericDrsFault = object of VimFault
    ClusterDasFailoverLevelAdvancedRuntimeInfoSlotInfo = object of DynamicData
    FloatOption = object of OptionType
    NetworkSummary = object of DynamicData
    BaseConfigInfoBackingInfo = object of DynamicData
    VslmMigrateSpec = object of DynamicData
    EntityPrivilege = object of DynamicData
    HostDiskBlockInfoVmfsMapping = object of HostDiskBlockInfoMapping
    HostDiskMappingInfo = object of DynamicData
    VmConfigFileEncryptionInfo = object of DynamicData
    OvfValidateHostParams = object of OvfManagerCommonParams
    CryptoSpecEncrypt = object of CryptoSpec
    DasHostFailedEvent = object of ClusterEvent
    HostCnxFailedNotFoundEvent = object of HostEvent
    CryptoSpec = object of DynamicData
    VvolDatastoreInfo = object of DatastoreInfo
    KmipServerInfo = object of DynamicData
    VirtualMachineMetadataManagerVmMetadataInput = object of DynamicData
    VMwareDvsLacpGroupConfig = object of DynamicData
    VirtualCdromRemotePassthroughBackingOption = object of VirtualDeviceRemoteDeviceBackingOption
    HostVmfsRescanResult = object of DynamicData
    HostDasDisabledEvent = object of HostEvent
    DVPortgroupRenamedEvent = object of DVPortgroupEvent
    ExtSolutionManagerInfo = object of DynamicData
    FcoeFault = object of VimFault
    OvfInternalError = object of OvfSystemFault
    PerformanceStatisticsDescription = object of DynamicData
    FeatureRequirementsNotMet = object of VirtualHardwareCompatibilityIssue
    VmRenamedEvent = object of VmEvent
    VmValidateMaxDevice = object of VimFault
    VirtualEthernetCardDVPortBackingOption = object of VirtualDeviceBackingOption
    CustomFieldStringValue = object of CustomFieldValue
    VirtualMachineCreateChildSpec = object of DynamicData
    FaultToleranceMetaSpec = object of DynamicData
    ClusterActionHistory = object of DynamicData
    ExtendedDescription = object of Description
    ClusterIoFilterInfo = object of IoFilterInfo
    LicenseAssignmentFailed = object of RuntimeFault
    HostProxySwitchSpec = object of DynamicData
    VirtualMachineMemoryReservationInfo = object of DynamicData
    ExtensionFaultTypeInfo = object of DynamicData
    InsufficientStorageSpace = object of InsufficientResourcesFault
    ScheduledTaskEventArgument = object of EntityEventArgument
    DvsOperationBulkFault = object of DvsFault
    ClusterIncreaseAllocationAction = object of ClusterAction
    DvsPortReconfiguredEvent = object of DvsEvent
    InvalidEditionEvent = object of LicenseEvent
    StorageDrsHbrDiskNotMovable = object of VimFault
    HostSystemRemediationState = object of DynamicData
    HostNetCapabilities = object of DynamicData
    ProductComponentInfo = object of DynamicData
    ElementDescription = object of Description
    ProfileChangedEvent = object of ProfileEvent
    GuestRegValueStringSpec = object of GuestRegValueDataSpec
    VMwareDvsLagVlanConfig = object of DynamicData
    VirtualMachineConfigOptionDescriptor = object of DynamicData
    EntityEventArgument = object of EventArgument
    NoDiskSpace = object of FileFault
    HostDvpgNetworkResource = object of HostNetworkResource
    HostListSummaryGatewaySummary = object of DynamicData
    ProfileUpdateFailedUpdateFailure = object of DynamicData
    ParaVirtualSCSIControllerOption = object of VirtualSCSIControllerOption
    DVPortgroupConfigSpec = object of DynamicData
    StaticRouteProfile = object of ApplyProfile
    WitnessNodeInfo = object of DynamicData
    VirtualFloppyRemoteDeviceBackingInfo = object of VirtualDeviceRemoteDeviceBackingInfo
    HostLowLevelProvisioningManagerVmRecoveryInfo = object of DynamicData
    NvdimmSystemInfo = object of DynamicData
    DvsTrafficRule = object of DynamicData
    NoHostSuitableForFtSecondary = object of VmFaultToleranceIssue
    FilesystemQuiesceFault = object of SnapshotFault
    ConflictingConfiguration = object of DvsFault
    VmDasUpdateOkEvent = object of VmEvent
    HostSystemSwapConfiguration = object of DynamicData
    OvfUnsupportedElement = object of OvfUnsupportedPackage
    LicenseFault = object of NotEnoughLicenses
    HostCnxFailedNoAccessEvent = object of HostEvent
    FileLocked = object of FileFault
    InvalidAffinitySettingFault = object of VimFault
    ClusterDasDataSummary = object of ClusterDasData
    ClusterFailoverResourcesAdmissionControlInfo = object of ClusterDasAdmissionControlInfo
    DiskChangeExtent = object of DynamicData
    HostCpuPackage = object of DynamicData
    NasConfigFault = object of HostConfigFault
    NoDiskFound = object of VimFault
    DeviceBackingNotSupported = object of DeviceNotSupported
    HostVmfsSpec = object of DynamicData
    KmipServerSpec = object of DynamicData
    HostProfileManagerCompositionValidationResultResultElement = object of DynamicData
    PowerOnFtSecondaryTimedout = object of Timedout
    DistributedVirtualSwitchHostMember = object of DynamicData
    ScheduledTaskEmailFailedEvent = object of ScheduledTaskEvent
    VmDiskFailedEvent = object of VmEvent
    DistributedVirtualSwitchPortConnection = object of DynamicData
    IscsiFaultPnicInUse = object of IscsiFault
    VsanHostDiskResult = object of DynamicData
    OvfDiskMappingNotFound = object of OvfSystemFault
    ClusterDasFailoverLevelAdvancedRuntimeInfoHostSlots = object of DynamicData
    VspanSameSessionPortConflict = object of DvsFault
    HostService = object of DynamicData
    DatastoreInfo = object of DynamicData
    NoCompatibleSoftAffinityHost = object of VmConfigFault
    ClusterFailoverLevelAdmissionControlInfo = object of ClusterDasAdmissionControlInfo
    MemoryHotPlugNotSupported = object of VmConfigFault
    CannotMoveVmWithDeltaDisk = object of MigrationFault
    VirtualFloppy = object of VirtualDevice
    ScheduledTaskInfo = object of ScheduledTaskSpec
    PerfQuerySpec = object of DynamicData
    NoPermission = object of SecurityError
    HostTpmDigestInfo = object of HostDigestInfo
    TimedOutHostOperationEvent = object of HostEvent
    HostTpmSoftwareComponentEventDetails = object of HostTpmEventDetails
    ReplicationSpec = object of DynamicData
    NodeDeploymentSpec = object of DynamicData
    HostVFlashManagerVFlashConfigInfo = object of DynamicData
    HostVmfsVolume = object of HostFileSystemVolume
    OvfPropertyValue = object of OvfProperty
    HostProfileManagerCompositionResult = object of DynamicData
    HostIpToShortNameFailedEvent = object of HostEvent
    InsufficientFailoverResourcesFault = object of InsufficientResourcesFault
    VspanPortConflict = object of DvsFault
    VirtualDevice = object of DynamicData
    FcoeConfig = object of DynamicData
    HostPortGroupConfig = object of DynamicData
    VirtualDiskDeltaDiskFormatsSupported = object of DynamicData
    LibraryFault = object of VimFault
    GuestRegValueSpec = object of DynamicData
    ClusterAntiAffinityRuleSpec = object of ClusterRuleInfo
    DrsVmotionIncompatibleFault = object of VirtualHardwareCompatibilityIssue
    VRPEditSpec = object of DynamicData
    ClusterDasAamNodeState = object of DynamicData
    DvsLogNetworkRuleAction = object of DvsNetworkRuleAction
    VmMetadataInvalidOwner = object of VmMetadataManagerFault
    TeamingMatchEvent = object of DvsHealthStatusChangeEvent
    HostNetOffloadCapabilities = object of DynamicData
    ProfileCompositePolicyOptionMetadata = object of ProfilePolicyOptionMetadata
    HostConfigSpec = object of DynamicData
    UnsupportedVmxLocation = object of VmConfigFault
    HostFibreChannelOverEthernetHbaLinkInfo = object of DynamicData
    InvalidProfileReferenceHost = object of RuntimeFault
    HostDasOkEvent = object of HostEvent
    CanceledHostOperationEvent = object of HostEvent
    NetDhcpConfigInfoDhcpOptions = object of DynamicData
    RoleEvent = object of AuthorizationEvent
    VirtualPointingDevice = object of VirtualDevice
    LicenseFeatureInfo = object of DynamicData
    VirtualEthernetCardOption = object of VirtualDeviceOption
    HostVFlashManagerVFlashResourceRunTimeInfo = object of DynamicData
    DeviceGroupId = object of DynamicData
    DVSHealthCheckCapability = object of DynamicData
    ProfileHostProfileEngineComplianceManagerExpressionMetaArray = object of DynamicData
    WillLoseHAProtection = object of MigrationFault
    VirtualMachineNamespaceManagerNamespaceInfoNamespaceAllocation = object of DynamicData
    HostDisconnectedEvent = object of HostEvent
    VirtualMachineFileInfo = object of DynamicData
    VspanPortPromiscChangeFault = object of DvsFault
    RecurrentTaskScheduler = object of TaskScheduler
    ServerStartedSessionEvent = object of SessionEvent
    DvsHostBackInSyncEvent = object of DvsEvent
    DistributedVirtualSwitchHostMemberRuntimeState = object of DynamicData
    LongOption = object of OptionType
    VirtualDiskVFlashCacheConfigInfo = object of DynamicData
    MonthlyByWeekdayTaskScheduler = object of MonthlyTaskScheduler
    DistributedVirtualSwitchHostMemberConfigInfo = object of DynamicData
    VMotionAcrossNetworkNotSupported = object of MigrationFeatureNotSupported
    VirtualPCIPassthroughVmiopBackingInfo = object of VirtualPCIPassthroughPluginBackingInfo
    VirtualEthernetCardNetworkBackingOption = object of VirtualDeviceDeviceBackingOption
    VirtualDeviceRemoteDeviceBackingOption = object of VirtualDeviceBackingOption
    StorageDrsHmsUnreachable = object of VimFault
    DeviceUnsupportedForVmVersion = object of InvalidDeviceSpec
    HostUnresolvedVmfsExtent = object of DynamicData
    CustomizationIPSettings = object of DynamicData
    HostProfileManagerCompositionResultResultElement = object of DynamicData
    NetworkBandwidthAllocationInfo = object of ResourceAllocationInfo
    VirtualHardware = object of DynamicData
    DisabledMethodSource = object of DynamicData
    VsanUpgradeSystemPreflightCheckIssue = object of DynamicData
    OvfFault = object of VimFault
    FileInfo = object of DynamicData
    CustomizationGuiRunOnce = object of DynamicData
    PolicyDisallowsOperation = object of PolicyViolatedDetail
    DVPortSetting = object of DynamicData
    MigrationErrorEvent = object of MigrationEvent
    ChoiceOption = object of OptionType
    VirtualMachineNamespaceManagerDataSpec = object of DynamicData
    IpRouteProfile = object of ApplyProfile
    UplinkPortVlanTrunkedEvent = object of DvsHealthStatusChangeEvent
    NetIpStackInfoNetToMedia = object of DynamicData
    VmMaxFTRestartCountReached = object of VmEvent
    GuestDiskInfo = object of DynamicData
    HostTpmAttestationReport = object of DynamicData
    BaseConfigInfo = object of DynamicData
    IpPoolManagerIpAllocation = object of DynamicData
    InvalidOperationOnSecondaryVm = object of VmFaultToleranceIssue
    AlarmFilterSpec = object of DynamicData
    TooManyHosts = object of HostConnectFault
    WakeOnLanNotSupported = object of VirtualHardwareCompatibilityIssue
    HostUpgradeFailedEvent = object of HostEvent
    VmInstanceUuidChangedEvent = object of VmEvent
    NetIpRouteConfigInfoGateway = object of DynamicData
    DVPortgroupConfigInfo = object of DynamicData
    CannotDisconnectHostWithFaultToleranceVm = object of VimFault
    VmMetadataInaccessibleFault = object of VmMetadataManagerFault
    OvfImport = object of OvfFault
    VirtualMachineProvisioningPolicyConfigPolicy = object of DynamicData
    OvfPropertyQualifier = object of OvfProperty
    GhostDvsProxySwitchRemovedEvent = object of HostEvent
    HostCertificateManagerCertificateInfo = object of DynamicData
    ClusterDpmHostConfigSpec = object of ArrayUpdateSpec
    OvfConsumerOstResult = object of OvfConsumerResult
    IscsiStatus = object of DynamicData
    VmHealthMonitoringStateChangedEvent = object of ClusterEvent
    VAppTaskInProgress = object of TaskInProgress
    VmotionInterfaceNotEnabled = object of HostPowerOpFailed
    NoConnectedDatastore = object of VimFault
    AlarmExpression = object of DynamicData
    CannotAccessVmComponent = object of VmConfigFault
    OvfNetworkMapping = object of DynamicData
    IoFilterQueryIssueResult = object of DynamicData
    FaultsByHost = object of DynamicData
    HostPlugStoreTopologyAdapter = object of DynamicData
    FaultsByVM = object of DynamicData
    ExtManagedEntityInfo = object of DynamicData
    SourceNodeSpec = object of DynamicData
    IpHostnameGeneratorError = object of CustomizationFault
    DasAdmissionControlEnabledEvent = object of ClusterEvent
    CustomizationStatelessIpV6Generator = object of CustomizationIpV6Generator
    InvalidController = object of InvalidDeviceSpec
    VirtualPCIPassthroughPluginBackingInfo = object of VirtualDeviceBackingInfo
    DistributedVirtualPortgroupInfo = object of DynamicData
    TeamingMisMatchEvent = object of DvsHealthStatusChangeEvent
    ScsiLunDescriptor = object of DynamicData
    HostDasErrorEvent = object of HostEvent
    VirtualSerialPortThinPrintBackingInfo = object of VirtualDeviceBackingInfo
    DVPortConfigInfo = object of DynamicData
    GuestPosixFileAttributes = object of GuestFileAttributes
    VmSecondaryDisabledBySystemEvent = object of VmEvent
    OvfExportFailed = object of OvfExport
    VsanDiskFault = object of VsanFault
    VmStartingSecondaryEvent = object of VmEvent
    ClusterDpmHostConfigInfo = object of DynamicData
    ComplianceFailure = object of DynamicData
    VmConfigFileQueryFilter = object of DynamicData
    InvalidGuestLogin = object of GuestOperationsFault
    DvsNotAuthorized = object of DvsFault
    TemplateConfigFileQuery = object of VmConfigFileQuery
    HostInventoryFull = object of NotEnoughLicenses
    PlacementAction = object of ClusterAction
    DataProviderResultSet = object of DynamicData
    LegacyNetworkInterfaceInUse = object of CannotAccessNetwork
    NetworkPolicyProfile = object of ApplyProfile
    EVCAdmissionFailedHostDisconnected = object of EVCAdmissionFailed
    MemorySizeNotSupported = object of VirtualHardwareCompatibilityIssue
    DiskIsUSB = object of VsanDiskFault
    NetDnsConfigInfo = object of DynamicData
    SingleIp = object of IpAddress
    MultipleCertificatesVerifyFault = object of HostConnectFault
    AuthorizationEvent = object of Event
    NotSupportedHostForChecksum = object of VimFault
    HostEventArgument = object of EntityEventArgument
    ClusterConfigSpecEx = object of ComputeResourceConfigSpec
    LicenseExpiredEvent = object of Event
    TaskInfo = object of DynamicData
    DvsDestroyedEvent = object of DvsEvent
    MonthlyTaskScheduler = object of DailyTaskScheduler
    ExitStandbyModeFailedEvent = object of HostEvent
    DVSSecurityPolicy = object of InheritablePolicy
    AlarmSpec = object of DynamicData
    VmSuspendedEvent = object of VmEvent
    InvalidKey = object of VimFault
    HostDVSPortDeleteSpec = object of DynamicData
    HostVirtualSwitchConfig = object of DynamicData
    Relation = object of DynamicData
    IscsiFaultVnicNotBound = object of IscsiFault
    LastEventFilterSpec = object of DynamicData
    LicenseEntityAlreadyExists = object of VimFault
    LinuxVolumeNotClean = object of CustomizationFault
    CloneFromSnapshotNotSupported = object of MigrationFault
    VsanHostClusterStatusStateCompletionEstimate = object of DynamicData
    RecoveryEvent = object of DvsEvent
    ResourceConfigOption = object of DynamicData
    UnusedVirtualDiskBlocksNotScrubbed = object of DeviceBackingNotSupported
    VirtualMachineDiskDeviceInfo = object of VirtualMachineTargetInfo
    NumVirtualCpusNotSupported = object of VirtualHardwareCompatibilityIssue
    VmAcquiredMksTicketEvent = object of VmEvent
    DatastoreDuplicatedEvent = object of DatastoreEvent
    DistributedVirtualSwitchManagerCompatibilityResult = object of DynamicData
    UserUpgradeEvent = object of UpgradeEvent
    VirtualPointingDeviceDeviceBackingInfo = object of VirtualDeviceDeviceBackingInfo
    IncorrectHostInformationEvent = object of LicenseEvent
    PolicyUrnInvalid = object of VimFault
    MemoryFileFormatNotSupportedByDatastore = object of UnsupportedDatastore
    VirtualE1000 = object of VirtualEthernetCard
    PerfSampleInfo = object of DynamicData
    MessageBusProxyConfigSpec = object of DynamicData
    ClusterOvercommittedEvent = object of ClusterEvent
    TaskReasonUser = object of TaskReason
    DVSHealthCheckConfig = object of DynamicData
    DvsCopyNetworkRuleAction = object of DvsNetworkRuleAction
    CannotDisableSnapshot = object of VmConfigFault
    DisconnectedHostsBlockingEVC = object of EVCConfigFault
    PerfCounterInfoInt = object of PerfCounterInfo
    HostDiskDimensionsChs = object of DynamicData
    ClusterDrsRecommendation = object of DynamicData
    VsanHostFaultDomainInfo = object of DynamicData
    HostDiskBlockInfo = object of DynamicData
    VirtualMachineConfigInfo = object of DynamicData
    VirtualMachineMetadataManagerVmMetadataOwner = object of DynamicData
    VirtualDiskSparseVer1BackingInfo = object of VirtualDeviceFileBackingInfo
    BaseConfigInfoRawDiskMappingBackingInfo = object of BaseConfigInfoFileBackingInfo
    DistributedVirtualSwitchInfo = object of DynamicData
    NotSupportedDeviceForFT = object of VmFaultToleranceIssue
    HostProfileManagerConfigTaskList = object of DynamicData
    Timedout = object of VimFault
    RoleAddedEvent = object of RoleEvent
    DVPortgroupReconfiguredEvent = object of DVPortgroupEvent
    RebootRequired = object of VimFault
    DVPortSelection = object of SelectionSet
    VirtualVMIROMOption = object of VirtualDeviceOption
    DVSNetworkResourcePool = object of DynamicData
    VmInstanceUuidConflictEvent = object of VmEvent
    HostCpuInfo = object of DynamicData
    HostProfileMappingData = object of DynamicData
    HostCnxFailedCcagentUpgradeEvent = object of HostEvent
    ExpiredFeatureLicense = object of NotEnoughLicenses
    NvdimmNamespaceInfo = object of DynamicData
    InsufficientCpuResourcesFault = object of InsufficientResourcesFault
    DvsEvent = object of Event
    EntityAndComplianceStatus = object of DynamicData
    ApplyStorageRecommendationResult = object of DynamicData
    OptionType = object of DynamicData
    HostCompliantEvent = object of HostEvent
    HostVirtualNicIpRouteSpec = object of DynamicData
    MissingPowerOffConfiguration = object of VAppConfigFault
    IscsiFaultInvalidVnic = object of IscsiFault
    ClusterRecommendation = object of DynamicData
    DvsVmVnicResourcePoolConfigSpec = object of DynamicData
    InvalidNasCredentials = object of NasConfigFault
    StorageDrsIolbDisabledInternally = object of VimFault
    HostSystemSwapConfigurationHostCacheOption = object of HostSystemSwapConfigurationSystemSwapOption
    ComputeResourceConfigInfo = object of DynamicData
    AlarmScriptCompleteEvent = object of AlarmEvent
    ClusterHostInfraUpdateHaModeAction = object of ClusterAction
    OvfCreateDescriptorParams = object of DynamicData
    HostVMotionManagerVMotionNVDIMMSpec = object of HostVMotionManagerVMotionDeviceSpec
    SecondaryVmNotRegistered = object of VmFaultToleranceIssue
    VAppOperationInProgress = object of RuntimeFault
    UnconfiguredPropertyValue = object of InvalidPropertyValue
    HostNumericSensorInfo = object of DynamicData
    CustomizationLinuxOptions = object of CustomizationOptions
    InsufficientResourcesFault = object of VimFault
    HostVirtualNicConnection = object of DynamicData
    VirtualE1000e = object of VirtualEthernetCard
    ResourcePoolQuickStats = object of DynamicData
    StorageDrsDisabledOnVm = object of VimFault
    CDCInventoryChange = object of DynamicData
    HostVsanInternalSystemVsanPhysicalDiskDiagnosticsResult = object of DynamicData
    StorageDrsStaleHmsCollection = object of VimFault
    OvfFile = object of DynamicData
    RetrieveCustomizationsResult = object of StructuredCustomizations
    AlarmAction = object of DynamicData
    HostExtraNetworksEvent = object of HostDasEvent
    DrsDatastoreCorrelation = object of DynamicData
    HostInternetScsiTargetTransport = object of HostTargetTransport
    VirtualDisk = object of VirtualDevice
    DvsFilterPolicy = object of InheritablePolicy
    StorageDrsCannotMoveVmInUserFolder = object of VimFault
    OvfUnsupportedSection = object of OvfUnsupportedElement
    GuestRegistryValueNotFound = object of GuestRegistryValueFault
    AnswerFileSerializedCreateSpec = object of AnswerFileCreateSpec
    NvdimmRegionInfo = object of DynamicData
    VAppProductInfo = object of DynamicData
    PasswordField = object of DynamicData
    VsanHostConfigInfoNetworkInfoPortConfig = object of DynamicData
    VirtualCdromPassthroughBackingInfo = object of VirtualDeviceDeviceBackingInfo
    ClusterFailoverHostAdmissionControlPolicy = object of ClusterDasAdmissionControlPolicy
    VirtualSwitchProfile = object of ApplyProfile
    VAppConfigSpec = object of VmConfigSpec
    VsanUpgradeSystemPreflightCheckResult = object of DynamicData
    StorageDrsCannotMoveSharedDisk = object of VimFault
    DVSOpaqueConfigInfo = object of DynamicData
    DrsExitedStandbyModeEvent = object of ExitedStandbyModeEvent
    HostLocalAuthenticationInfo = object of HostAuthenticationStoreInfo
    VmwareDistributedVirtualSwitchVlanSpec = object of InheritablePolicy
    HostDiskManagerLeaseInfo = object of DynamicData
    DvsSingleIpPort = object of DvsIpPort
    VmfsAlreadyMounted = object of VmfsMountFault
    CannotAddHostWithFTVmToNonHACluster = object of HostConnectFault
    DvsPuntNetworkRuleAction = object of DvsNetworkRuleAction
    PolicyOption = object of DynamicData
    ResourcePoolEventArgument = object of EntityEventArgument
    VirtualMachineConfigInfoDatastoreUrlPair = object of DynamicData
    VirtualDeviceConfigSpecBackingSpec = object of DynamicData
    DvsApplyOperationFaultFaultOnObject = object of DynamicData
    PhysicalNicSpec = object of DynamicData
    ProfileDeferredPolicyOptionParameter = object of DynamicData
    WorkflowStepHandlerResult = object of DynamicData
    ProfileDescriptionSection = object of DynamicData
    VirtualMachineMessage = object of DynamicData
    UnsupportedVimApiVersion = object of VimFault
    HostFirewallConfig = object of DynamicData
    VirtualSCSIControllerOption = object of VirtualControllerOption
    VmPoweredOnEvent = object of VmEvent
    VmOrphanedEvent = object of VmEvent
    HostDateTimeConfig = object of DynamicData
    PermissionUpdatedEvent = object of PermissionEvent
    VirtualVmxnet3Vrdma = object of VirtualVmxnet3
    TemplateUpgradedEvent = object of TemplateUpgradeEvent
    VirtualMachineVMCIDeviceOption = object of VirtualDeviceOption
    EVCAdmissionFailed = object of NotSupportedHostInCluster
    GeneralVmInfoEvent = object of GeneralEvent
    HostDVSPortResetSpec = object of DynamicData
    ExitedStandbyModeEvent = object of HostEvent
    HostNetworkInfo = object of DynamicData
    StorageResourceManagerStorageProfileStatistics = object of DynamicData
    InsufficientFailoverResourcesEvent = object of ClusterEvent
    DVSNetworkResourcePoolConfigSpec = object of DynamicData
    PhysicalNicCdpInfo = object of DynamicData
    VirtualMachineVMCIDeviceFilterSpec = object of DynamicData
    ToolsImageSignatureCheckFailed = object of VmToolsUpgradeFault
    InvalidResourcePoolStructureFault = object of InsufficientResourcesFault
    AnswerFileValidationInfo = object of DynamicData
    PolicyViolatedValueNotInSet = object of PolicyViolatedByValue
    HostProfileMappingLookup = object of DynamicData
    CustomizationIpV6Generator = object of DynamicData
    SnapshotMoveToNonHomeNotSupported = object of SnapshotCopyNotSupported
    CpuHotPlugNotSupported = object of VmConfigFault
    FloppyImageFileQuery = object of FileQuery
    HostFirewallConfigRuleSetConfig = object of DynamicData
    InvalidFormat = object of VmConfigFault
    VirtualDiskRawDiskMappingVer1BackingInfo = object of VirtualDeviceFileBackingInfo
    VsanHostRuntimeInfo = object of DynamicData
    OvfHostResourceConstraint = object of OvfConstraint
    GuestAliases = object of DynamicData
    DatastoreDestroyedEvent = object of DatastoreEvent
    AnswerFileStatusError = object of DynamicData
    SnapshotIncompatibleDeviceInVm = object of SnapshotFault
    WakeOnLanNotSupportedByVmotionNIC = object of HostPowerOpFailed
    VirtualCdromAtapiBackingInfo = object of VirtualDeviceDeviceBackingInfo
    DvsIpNetworkRuleQualifier = object of DvsNetworkRuleQualifier
    ProfileMetadata = object of DynamicData
    SoftRuleVioCorrectionImpact = object of VmConfigFault
    DiskMoveTypeNotSupported = object of MigrationFault
    InaccessibleFTMetadataDatastore = object of InaccessibleDatastore
    UpgradeEvent = object of Event
    ClusterComputeResourceDrmDumpInfo = object of DynamicData
    GuestMappedAliases = object of DynamicData
    CustomizationUnknownIpGenerator = object of CustomizationIpGenerator
    VmVnicPoolReservationViolationClearEvent = object of DvsEvent
    HostRuntimeInfo = object of DynamicData
    DatastoreEvent = object of Event
    HostEvent = object of Event
    HostLoadEsxManagerInfo = object of DynamicData
    MigrationHostWarningEvent = object of MigrationEvent
    NoMaintenanceModeDrsRecommendationForVM = object of VmEvent
    HostDiagnosticPartitionCreateOption = object of DynamicData
    OvfConsumerUndefinedPrefix = object of OvfConsumerCallbackFault
    VMwareDVSPvlanConfigSpec = object of DynamicData
    DataProviderQuerySpec = object of DynamicData
    HostOpaqueNetworkData = object of DynamicData
    HostProfileConfigInfo = object of ProfileConfigInfo
    HostStorageSystemVmfsVolumeResult = object of DynamicData
    NotSupportedHostInDvs = object of NotSupportedHost
    TooManyTickets = object of VimFault
    CryptoKeyId = object of DynamicData
    ScheduledTaskReconfiguredEvent = object of ScheduledTaskEvent
    ProfileCompositeExpression = object of ProfileExpression
    HostOpaqueNetworkResource = object of HostNetworkResource
    VmUpgradingEvent = object of VmEvent
    ProfileParameterMetadataParameterRelationMetadata = object of DynamicData
    NasStorageProfile = object of ApplyProfile
    VirtualDeviceBusSlotInfo = object of DynamicData
    InvalidDatastorePath = object of InvalidDatastore
    OvfDuplicatedPropertyIdExport = object of OvfExport
    CannotComputeFTCompatibleHosts = object of VmFaultToleranceIssue
    NicSettingMismatch = object of CustomizationFault
    ResourcePoolDestroyedEvent = object of ResourcePoolEvent
    ReadOnlyDisksWithLegacyDestination = object of MigrationFault
    VirtualMachineSummary = object of DynamicData
    ConcurrentAccess = object of VimFault
    HostStorageOperationalInfo = object of DynamicData
    VmBeingCreatedEvent = object of VmEvent
    HostUnresolvedVmfsVolumeResolveStatus = object of DynamicData
    OvfUnknownDeviceBacking = object of OvfHardwareExport
    HostProfileHostBasedConfigSpec = object of HostProfileConfigSpec
    SoftwarePackage = object of DynamicData
    VirtualPCIPassthroughVmiopBackingOption = object of VirtualPCIPassthroughPluginBackingOption
    VStorageObjectSnapshotInfo = object of DynamicData
    VMINotSupported = object of DeviceNotSupported
    HostPortGroupPort = object of DynamicData
    ClusterProfileConfigInfo = object of ProfileConfigInfo
    DistributedVirtualSwitchManagerHostDvsFilterSpec = object of DynamicData
    CryptoSpecDecrypt = object of CryptoSpec
    FolderFileQuery = object of FileQuery
    VlanProfile = object of ApplyProfile
    MissingPowerOnConfiguration = object of VAppConfigFault
    VsanHostVsanDiskInfo = object of DynamicData
    OvfInvalidValueConfiguration = object of OvfInvalidValue
    PermissionEvent = object of AuthorizationEvent
    DisableAdminNotSupported = object of HostConfigFault
    ProfileSimpleExpression = object of ProfileExpression
    SnapshotLocked = object of SnapshotFault
    HostMemberRuntimeInfo = object of DynamicData
    ScheduledTaskRemovedEvent = object of ScheduledTaskEvent
    InsufficientMemoryResourcesFault = object of InsufficientResourcesFault
    TooManySnapshotLevels = object of SnapshotFault
    DiagnosticManagerLogHeader = object of DynamicData
    ClusterInitialPlacementAction = object of ClusterAction
    VmHostAffinityRuleViolation = object of VmConfigFault
    NotSupportedHostInHACluster = object of NotSupportedHost
    OvfNoSpaceOnController = object of OvfUnsupportedElement
    WeeklyTaskScheduler = object of DailyTaskScheduler
    VirtualMachineFeatureRequirement = object of DynamicData
    VirtualFloppyDeviceBackingInfo = object of VirtualDeviceDeviceBackingInfo
    DrsResourceConfigureFailedEvent = object of HostEvent
    DvsPortLinkUpEvent = object of DvsEvent
    OvfMappedOsId = object of OvfImport
    VmUuidChangedEvent = object of VmEvent
    OvfUnsupportedDeviceBackingOption = object of OvfSystemFault
    DVSPolicy = object of DynamicData
    NoHost = object of HostConnectFault
    CustomizationSysprepFailed = object of CustomizationFailed
    HostVirtualNic = object of DynamicData
    NetDhcpConfigInfo = object of DynamicData
    NamespaceLimitReached = object of VimFault
    CustomFieldDefRenamedEvent = object of CustomFieldDefEvent
    SessionTerminatedEvent = object of SessionEvent
    PolicyViolatedByValue = object of PolicyViolatedDetail
    ClusterVmToolsMonitoringSettings = object of DynamicData
    VirtualMachineUsageOnDatastore = object of DynamicData
    GuestAuthenticationChallenge = object of GuestOperationsFault
    ProfileCreatedEvent = object of ProfileEvent
    ImageLibraryManagerMediaInfo = object of DynamicData
    TaskScheduler = object of DynamicData
    MissingNetworkIpConfig = object of VAppPropertyFault
    FileTransferInformation = object of DynamicData
    RoleEventArgument = object of EventArgument
    MethodDisabled = object of RuntimeFault
    VirtualE1000eOption = object of VirtualEthernetCardOption
    VirtualVmxnetOption = object of VirtualEthernetCardOption
    VirtualMachineDatastoreVolumeOption = object of DynamicData
    SessionManagerServiceRequestSpec = object of DynamicData
    VirtualCdromRemoteAtapiBackingOption = object of VirtualDeviceDeviceBackingOption
    HostVirtualSwitchSimpleBridge = object of HostVirtualSwitchBridge
    EnumDescription = object of DynamicData
    EnteredStandbyModeEvent = object of HostEvent
    InvalidCAMServer = object of ActiveDirectoryFault
    CannotAccessFile = object of FileFault
    HostSystemSwapConfigurationDatastoreOption = object of HostSystemSwapConfigurationSystemSwapOption
    VirtualDiskManagerReparentSpec = object of DynamicData
    HostVffsSpec = object of DynamicData
    FolderFileInfo = object of FileInfo
    DvsScopeViolated = object of DvsFault
    UnlicensedVirtualMachinesEvent = object of LicenseEvent
    VslmRelocateSpec = object of VslmMigrateSpec
    VAppConfigFault = object of VimFault
    LicenseRestrictedEvent = object of LicenseEvent
    StorageDrsPodConfigInfo = object of DynamicData
    OvfUnsupportedElementValue = object of OvfUnsupportedElement
    VMotionNotSupported = object of VMotionInterfaceIssue
    ClusterNetworkConfigSpec = object of DynamicData
    VirtualMachinePowerPolicyProfile = object of DynamicData
    HostImageProfileSummary = object of DynamicData
    HourlyTaskScheduler = object of RecurrentTaskScheduler
    MountError = object of CustomizationFault
    OvfInvalidPackage = object of OvfFault
    ClusterCreatedEvent = object of ClusterEvent
    VcAgentUpgradeFailedEvent = object of HostEvent
    VirtualDeviceDeviceBackingOption = object of VirtualDeviceBackingOption
    OvfInvalidValueReference = object of OvfInvalidValue
    GuestWindowsProgramSpec = object of GuestProgramSpec
    VirtualUSBController = object of VirtualController
    CpuIncompatible81EDX = object of CpuIncompatible
    CustomizationIdentitySettings = object of DynamicData
    VMotionLicenseExpiredEvent = object of LicenseEvent
    VirtualMachineConfigOption = object of DynamicData
    PrivilegePolicyDef = object of DynamicData
    ExtensionOvfConsumerInfo = object of DynamicData
    HostIoFilterInfo = object of IoFilterInfo
    DVSOpaqueDataConfigSpec = object of DynamicData
    VirtualPCIPassthroughOption = object of VirtualDeviceOption
    ClusterReconfiguredEvent = object of ClusterEvent
    ClusterFailoverResourcesAdmissionControlPolicy = object of ClusterDasAdmissionControlPolicy
    IndependentDiskVMotionNotSupported = object of MigrationFeatureNotSupported
    HostInventoryUnreadableEvent = object of Event
    HostServiceSourcePackage = object of DynamicData
    VirtualPCNet32Option = object of VirtualEthernetCardOption
    HostGraphicsInfo = object of DynamicData
    RunScriptAction = object of Action
    CannotChangeVsanClusterUuid = object of VsanFault
    VmfsDatastoreSingleExtentOption = object of VmfsDatastoreBaseOption
    DatabaseSizeEstimate = object of DynamicData
    HostVFlashManagerVFlashResourceConfigSpec = object of DynamicData
    UserPasswordChanged = object of HostEvent
    AlarmTriggeringActionTransitionSpec = object of DynamicData
    VStorageObjectAssociations = object of DynamicData
    HostVmciAccessManagerAccessSpec = object of DynamicData
    StringPolicy = object of InheritablePolicy
    ProfileComponentMetadata = object of DynamicData
    VirtualDiskSeSparseBackingInfo = object of VirtualDeviceFileBackingInfo
    VirtualMachineProfileSpec = object of DynamicData
    VirtualSoundBlaster16Option = object of VirtualSoundCardOption
    IncompatibleDefaultDevice = object of MigrationFault
    ProfileExecuteResult = object of DynamicData
    TooManyDisksOnLegacyHost = object of MigrationFault
    DvsImportEvent = object of DvsEvent
    HostStorageDeviceInfo = object of DynamicData
    PortGroupProfile = object of ApplyProfile
    KeyValue = object of DynamicData
    CustomizationCustomIpV6Generator = object of CustomizationIpV6Generator
    HostVFlashResourceConfigurationResult = object of DynamicData
    ClusterAffinityRuleSpec = object of ClusterRuleInfo
    HealthUpdateInfo = object of DynamicData
    DasEnabledEvent = object of ClusterEvent
    ToolsImageNotAvailable = object of VmToolsUpgradeFault
    VchaClusterConfigInfo = object of DynamicData
    DiskHasPartitions = object of VsanDiskFault
    NetIpConfigSpec = object of DynamicData
    NetworkCopyFault = object of FileFault
    VcAgentUpgradedEvent = object of HostEvent
    GuestRegValueDwordSpec = object of GuestRegValueDataSpec
    UserLoginSessionEvent = object of SessionEvent
    VmGuestOSCrashedEvent = object of VmEvent
    VirtualMachineNamespaceManagerCreateSpec = object of DynamicData
    CreateTaskAction = object of Action
    DVSOpaqueCommandReqSpec = object of DynamicData
    HostLocalFileSystemVolume = object of HostFileSystemVolume
    VirtualFloppyOption = object of VirtualDeviceOption
    OvfInvalidValue = object of OvfAttribute
    SwapDatastoreNotWritableOnHost = object of DatastoreNotWritableOnHost
    BatchResult = object of DynamicData
    DistributedVirtualSwitchHostMemberBacking = object of DynamicData
    VmBeingMigratedEvent = object of VmEvent
    HostServiceConfig = object of DynamicData
    SuspendedRelocateNotSupported = object of MigrationFault
    VasaProviderContainerSpec = object of DynamicData
    DeploymentInfoServiceInfo = object of DynamicData
    OvfDuplicatedPropertyIdImport = object of OvfExport
    HostIpConfigIpV6Address = object of DynamicData
    DVSNameArrayUplinkPortPolicy = object of DVSUplinkPortPolicy
    HostPatchManagerStatusPrerequisitePatch = object of DynamicData
    HealthSystemRuntime = object of DynamicData
    FileAlreadyExists = object of FileFault
    HostDatastoreSystemVvolDatastoreSpec = object of DynamicData
    VmFailedToShutdownGuestEvent = object of VmEvent
    HostSnmpSystemAgentLimits = object of DynamicData
    FirewallProfileRulesetProfile = object of ApplyProfile
    VmfsMountFault = object of HostConfigFault
    HostFibreChannelOverEthernetTargetTransport = object of HostFibreChannelTargetTransport
    DatacenterConfigInfo = object of DynamicData
    VmDeployedEvent = object of VmEvent
    OvfUnsupportedAttributeValue = object of OvfUnsupportedAttribute
    AlarmClearedEvent = object of AlarmEvent
    VirtualHardwareOption = object of DynamicData
    HostUserWorldSwapNotEnabledEvent = object of HostEvent
    SeSparseVirtualDiskSpec = object of FileBackedVirtualDiskSpec
    ExpiredAddonLicense = object of ExpiredFeatureLicense
    MultipleCertificatesVerifyFaultThumbprintData = object of DynamicData
    VmFaultToleranceConfigIssueWrapper = object of VmFaultToleranceIssue
    HostVMotionManagerDestinationState = object of DynamicData
    ClusterTransitionalEVCManagerCheckResult = object of DynamicData
    NasConnectionLimitReached = object of NasConfigFault
    InvalidHostName = object of HostConfigFault
    IscsiFaultVnicInUse = object of IscsiFault
    OvfConsumerValidationFault = object of VmConfigFault
    HostIncompatibleForFaultTolerance = object of VmFaultToleranceIssue
    VirtualAHCIController = object of VirtualSATAController
    HostIpRouteTableConfig = object of DynamicData
    DiagnosticManagerBundleInfo = object of DynamicData
    VmDateRolledBackEvent = object of VmEvent
    AlarmReconfiguredEvent = object of AlarmEvent
    DvsNetworkRuleQualifier = object of DynamicData
    HostInternetScsiHbaParamValue = object of OptionValue
    PerformanceDescription = object of DynamicData
    InvalidLibraryResponse = object of LibraryFault
    ClusterHostGroup = object of ClusterGroupInfo
    DVSOpaqueCommandResultInfo = object of DynamicData
    VMwareDVSHealthCheckCapability = object of DVSHealthCheckCapability
    VmDasUpdateErrorEvent = object of VmEvent
    VirtualLsiLogicControllerOption = object of VirtualSCSIControllerOption
    HostSystemIdentificationInfo = object of DynamicData
    VsanUpgradeSystemNetworkPartitionInfo = object of DynamicData
    VmMetadataOpFailedRetry = object of VmMetadataManagerFault
    HostCnxFailedEvent = object of HostEvent
    HostMultipathInfoLogicalUnitStorageArrayTypePolicy = object of DynamicData
    DVSMacLearningPolicy = object of InheritablePolicy
    HostLowLevelProvisioningManagerFileDeleteSpec = object of DynamicData
    CustomizationFault = object of VimFault
    HostConnectInfo = object of DynamicData
    FullStorageVMotionNotSupported = object of MigrationFeatureNotSupported
    VmCloneEvent = object of VmEvent
    HbrObjectInfo = object of DynamicData
    ToolsInstallationInProgress = object of MigrationFault
    HostUnresolvedVmfsResolutionSpec = object of DynamicData
    LicenseSourceUnavailable = object of NotEnoughLicenses
    ReplicationDiskConfigFault = object of ReplicationConfigFault
    SharedBusControllerNotSupported = object of DeviceNotSupported
    VirtualMachineSriovDevicePoolInfo = object of DynamicData
    DvsFilterConfig = object of InheritablePolicy
    HostPlugStoreTopologyPath = object of DynamicData
    VsanPolicySatisfiability = object of DynamicData
    OperationNotSupportedByGuest = object of GuestOperationsFault
    VirtualEthernetCardLegacyNetworkBackingOption = object of VirtualDeviceDeviceBackingOption
    HostDiskPartitionInfo = object of DynamicData
    DvsUpgradeAvailableEvent = object of DvsEvent
    NoCompatibleHostWithAccessToDevice = object of NoCompatibleHost
    GeneralEvent = object of Event
    VmResettingEvent = object of VmEvent
    VirtualResourcePoolSpec = object of DynamicData
    ServiceProfile = object of ApplyProfile
    VirtualMachineFileLayoutExDiskUnit = object of DynamicData
    IpContainer = object of IpAddress
    GuestScreenInfo = object of DynamicData
    HostNetworkResourceRuntime = object of DynamicData
    VsanHostConfigInfo = object of DynamicData
    ActiveVMsBlockingEVC = object of EVCConfigFault
    VmEmigratingEvent = object of VmEvent
    VirtualTPMOption = object of VirtualDeviceOption
    IscsiFaultVnicHasNoUplinks = object of IscsiFault
    StoragePlacementAction = object of ClusterAction
    MigrationEvent = object of VmEvent
    NetworkDisruptedAndConfigRolledBack = object of VimFault
    ComplianceLocator = object of DynamicData
    ServiceContent = object of DynamicData
    HostMultipathInfoLogicalUnit = object of DynamicData
    GuestRegValueNameSpec = object of DynamicData
    MemorySnapshotOnIndependentDisk = object of SnapshotFault
    ResourcePoolRuntimeInfo = object of DynamicData
    OvfConsumerCallbackFault = object of OvfFault
    DvsFilterConfigSpec = object of DvsFilterConfig
    DatacenterCreatedEvent = object of DatacenterEvent
    VmRelocateFailedEvent = object of VmRelocateSpecEvent
    VmFailedUpdatingSecondaryConfig = object of VmEvent
    VimAccountPasswordChangedEvent = object of HostEvent
    HostNasVolumeConfig = object of DynamicData
    AlarmStatusChangedEvent = object of AlarmEvent
    FirewallProfile = object of ApplyProfile
    PerfCompositeMetric = object of DynamicData
    VirtualParallelPortDeviceBackingInfo = object of VirtualDeviceDeviceBackingInfo
    VmFaultToleranceStateChangedEvent = object of VmEvent
    IpAddressProfile = object of ApplyProfile
    NetIpConfigInfo = object of DynamicData
    VirtualPS2ControllerOption = object of VirtualControllerOption
    HostVirtualSwitchAutoBridge = object of HostVirtualSwitchBridge
    PermissionAddedEvent = object of PermissionEvent
    VsanDecomParam = object of DynamicData
    MethodAlreadyDisabledFault = object of RuntimeFault
    HostDeploymentInfo = object of DynamicData
    VirtualVmxnet2 = object of VirtualVmxnet
    VirtualMachineUsbInfo = object of VirtualMachineTargetInfo
    LicenseDiagnostics = object of DynamicData
    FaultToleranceNotLicensed = object of VmFaultToleranceIssue
    ProfileEvent = object of Event
    VirtualDiskSparseVer2BackingInfo = object of VirtualDeviceFileBackingInfo
    HostProfilesCustomizationData = object of DynamicData
    VirtualMachineScsiDiskDeviceInfo = object of VirtualMachineDiskDeviceInfo
    HostProfileParameterMapping = object of DynamicData
    HostVMotionManagerSrcVMotionResult = object of DynamicData
    VirtualSerialPortPipeBackingOption = object of VirtualDevicePipeBackingOption
    FileFault = object of VimFault
    HbrManagerReplicationVmInfo = object of DynamicData
    EvaluationLicenseSource = object of LicenseSource
    ConflictingDatastoreFound = object of RuntimeFault
    CannotDisableDrsOnClustersWithVApps = object of RuntimeFault
    AgentInstallFailed = object of HostConnectFault
    VchaClusterHealth = object of DynamicData
    MissingBmcSupport = object of VimFault
    HostNoHAEnabledPortGroupsEvent = object of HostDasEvent
    ClusterComputeResourceDrmBundleInfo = object of DynamicData
    CustomizationLinuxPrep = object of CustomizationIdentitySettings
    MigrationResourceWarningEvent = object of MigrationEvent
    ToolsUnavailable = object of VimFault
    DVSKeyedOpaqueData = object of InheritablePolicy
    VirtualParallelPort = object of VirtualDevice
    InsufficientStandbyResource = object of InsufficientResourcesFault
    ExtendedElementDescription = object of ElementDescription
    CryptoManagerKmipClusterStatus = object of DynamicData
    InvalidTicket = object of VimFault
    ClusterDrsVmConfigSpec = object of ArrayUpdateSpec
    DatastoreFileEvent = object of DatastoreEvent
    ClusterDrsFaultsFaultsByVirtualDisk = object of ClusterDrsFaultsFaultsByVm
    VirtualDiskFlatVer2BackingOption = object of VirtualDeviceFileBackingOption
    GuestRegistryFault = object of GuestOperationsFault
    VMwareDvsIpfixCapability = object of DynamicData
    HostConfigFault = object of VimFault
    InvalidDeviceSpec = object of InvalidVmConfig
    ArrayUpdateSpec = object of DynamicData
    VsanUpgradeSystemNetworkPartitionIssue = object of VsanUpgradeSystemPreflightCheckIssue
    HostCnxFailedBadCcagentEvent = object of HostEvent
    ClusterDasAdmissionResult = object of DynamicData
    GuestMultipleMappings = object of GuestOperationsFault
    CannotChangeVsanNodeUuid = object of VsanFault
    HostVirtualNicManagerInfo = object of DynamicData
    VirtualMachineQuickStats = object of DynamicData
    ScheduledTaskEmailCompletedEvent = object of ScheduledTaskEvent
    HostForceMountedInfo = object of DynamicData
    DrsEnteringStandbyModeEvent = object of EnteringStandbyModeEvent
    VirtualMachineRelocateSpecDiskLocator = object of DynamicData
    GuestAuthAliasInfo = object of DynamicData
    HostNetStackInstance = object of DynamicData
    HostDatastoreSystemVmFileAccessibilityResult = object of DynamicData
    ExtensionPrivilegeInfo = object of DynamicData
    NetDhcpConfigSpec = object of DynamicData
    ClusterFailoverHostAdmissionControlInfo = object of ClusterDasAdmissionControlInfo
    VirtualController = object of VirtualDevice
    InvalidPropertyType = object of VAppPropertyFault
    LicenseReservationInfo = object of DynamicData
    VirtualFloppyImageBackingInfo = object of VirtualDeviceFileBackingInfo
    HostAddedEvent = object of HostEvent
    HostDiskBlockInfoScsiMapping = object of HostDiskBlockInfoMapping
    VsanHostConfigInfoNetworkInfo = object of DynamicData
    GatewayToHostConnectFault = object of GatewayConnectFault
    ReplicationFault = object of VimFault
    TaskInProgress = object of VimFault
    HostIncompatibleForRecordReplay = object of VimFault
    PolicyViolatedValueNotInRange = object of PolicyViolatedByValue
    SnapshotCloneNotSupported = object of SnapshotCopyNotSupported
    ServiceLocatorNamePassword = object of ServiceLocatorCredential
    VirtualMachineProvisioningPolicyFilePolicy = object of DynamicData
    VirtualEthernetCardLegacyNetworkBackingInfo = object of VirtualDeviceDeviceBackingInfo
    AccountUpdatedEvent = object of HostEvent
    DVSConfigInfo = object of DynamicData
    CustomizationUnknownFailure = object of CustomizationFailed
    OvfSystemFault = object of OvfFault
    AfterStartupTaskScheduler = object of TaskScheduler
    ExtensionManagerExtensionDataUsage = object of DynamicData
    IscsiFaultVnicHasWrongUplink = object of IscsiFault
    StorageDrsPlacementRankVmSpec = object of DynamicData
    CustomizationVirtualMachineName = object of CustomizationName
    FileTooLarge = object of FileFault
    HostConfigAppliedEvent = object of HostEvent
    ScheduledHardwareUpgradeInfo = object of DynamicData
    ExtensionManagerIpAllocationUsage = object of DynamicData
    VmFaultToleranceOpIssuesList = object of VmFaultToleranceIssue
    HostLoadEsxManagerConfigSpec = object of DynamicData
    VMwareDVSPortgroupPolicy = object of DVPortgroupPolicy
    AdminNotDisabled = object of HostConfigFault
    VAppEntityConfigInfo = object of DynamicData
    ProfileHostProfileEngineHostProfileManagerPolicyMetaArray = object of DynamicData
    AlarmEmailCompletedEvent = object of AlarmEvent
    HostShortNameInconsistentEvent = object of HostDasEvent
    AlarmInfo = object of AlarmSpec
    VmFaultToleranceTooManyFtVcpusOnHost = object of InsufficientResourcesFault
    VolumeEditorError = object of CustomizationFault
    ToolsImageCopyFailed = object of VmToolsUpgradeFault
    AnswerFileCreateSpec = object of DynamicData
    NotEnoughCpus = object of VirtualHardwareCompatibilityIssue
    SingleMac = object of MacAddress
    RoleUpdatedEvent = object of RoleEvent
    EVCAdmissionFailedCPUFeaturesForMode = object of EVCAdmissionFailed
    UserProfile = object of ApplyProfile
    VirtualNVDIMM = object of VirtualDevice
    PermissionProfile = object of ApplyProfile
    HostDiskPartitionLayout = object of DynamicData
    HostNetworkSecurityPolicy = object of DynamicData
    HostTpmOptionEventDetails = object of HostTpmEventDetails
    VspanPortgroupTypeChangeFault = object of DvsFault
    ExitMaintenanceModeEvent = object of HostEvent
    VMwareIpfixConfig = object of DynamicData
    HostVnicConnectedToCustomizedDVPortEvent = object of HostEvent
    ComputeResourceConfigSpec = object of DynamicData
    ReadHostResourcePoolTreeFailed = object of HostConnectFault
    VirtualCdromAtapiBackingOption = object of VirtualDeviceDeviceBackingOption
    PnicUplinkProfile = object of ApplyProfile
    AlarmActionTriggeredEvent = object of AlarmEvent
    BaseConfigInfoFileBackingInfo = object of BaseConfigInfoBackingInfo
    VirtualMachineForkConfigInfo = object of DynamicData
    AlarmTrigger = object of DynamicData
    ProxyServiceServiceSpec = object of ProxyServiceEndpointSpec
    HostReliableMemoryInfo = object of DynamicData
    DrsRuleComplianceEvent = object of VmEvent
    VirtualMachineIdeDiskDevicePartitionInfo = object of DynamicData
    ParaVirtualSCSIController = object of VirtualSCSIController
    VmAlreadyExistsInDatacenter = object of InvalidFolder
    PhysicalNicHintInfo = object of DynamicData
    HostSharedGpuCapabilities = object of DynamicData
    VirtualSerialPortThinPrintBackingOption = object of VirtualDeviceBackingOption
    VsanClusterConfigInfoHostDefaultInfo = object of DynamicData
    DuplicateVsanNetworkInterface = object of VsanFault
    PermissionRemovedEvent = object of PermissionEvent
    DrsExitingStandbyModeEvent = object of ExitingStandbyModeEvent
    VmFailedStartingSecondaryEvent = object of VmEvent
    HostActiveDirectorySpec = object of DynamicData
    VirtualMachineFloppyInfo = object of VirtualMachineTargetInfo
    HostSystemResourceInfo = object of DynamicData
    VmRequirementsExceedCurrentEVCModeEvent = object of VmEvent
    EVCModeIllegalByVendor = object of EVCConfigFault
    HostIpRouteTableInfo = object of DynamicData
    DVSConfigSpec = object of DynamicData
    ClusterInfraUpdateHaConfigInfo = object of DynamicData
    VVolVmConfigFileUpdateResultFailedVmConfigFileInfo = object of DynamicData
    CryptoKeyPlain = object of DynamicData
    VMwareDVSPvlanMapEntry = object of DynamicData
    NotEnoughLogicalCpus = object of NotEnoughCpus
    VmPoweringOnWithCustomizedDVPortEvent = object of VmEvent
    ProfileEventArgument = object of EventArgument
    HostTelemetryFilterSpec = object of DynamicData
    TooManyDevices = object of InvalidVmConfig
    AndAlarmExpression = object of AlarmExpression
    VmFailedRelayoutOnVmfs2DatastoreEvent = object of VmEvent
    VsanUpgradeSystemWrongEsxVersionIssue = object of VsanUpgradeSystemPreflightCheckIssue
    NvdimmHealthInfo = object of DynamicData
    VmRelocatedEvent = object of VmRelocateSpecEvent
    HostLicensableResourceInfo = object of DynamicData
    UnlicensedVirtualMachinesFoundEvent = object of LicenseEvent
    DailyTaskScheduler = object of HourlyTaskScheduler
    DrsPlacementRequiresVmsInTopologicalOrder = object of VimFault
    HostProfileParameterMappingParameterMappingData = object of HostProfileMappingData
    HostSriovNetworkDevicePoolInfo = object of HostSriovDevicePoolInfo
    VirtualMachineStorageInfo = object of DynamicData
    InheritablePolicy = object of DynamicData
    HostSubSpecificationUpdateEvent = object of HostEvent
    HostProtocolEndpoint = object of DynamicData
    HostApplyProfile = object of ApplyProfile
    HostVMotionManagerVMotionDiskSpec = object of HostVMotionManagerVMotionDeviceSpec
    VirtualEthernetCard = object of VirtualDevice
    LicenseEvent = object of Event
    HostLocalPortCreatedEvent = object of DvsEvent
    NoVcManagedIpConfigured = object of VAppPropertyFault
    VirtualMachineTargetInfo = object of DynamicData
    DatastoreEventArgument = object of EntityEventArgument
    HostNetworkPolicy = object of DynamicData
    CannotAddHostWithFTVmAsStandalone = object of HostConnectFault
    OvfCpuCompatibilityCheckNotSupported = object of OvfImport
    VsanPolicyChangeBatch = object of DynamicData
    ClusterSlotPolicy = object of DynamicData
    GatewayToHostAuthFault = object of GatewayToHostConnectFault
    DatacenterConfigSpec = object of DynamicData
    CustomizationIdentification = object of DynamicData
    DVSVendorSpecificConfig = object of InheritablePolicy
    ServiceConsolePortGroupProfile = object of PortGroupProfile
    GuestRegKeySpec = object of DynamicData
    HostOpaqueSwitchPhysicalNicZone = object of DynamicData
    AnswerFile = object of DynamicData
    HostPortGroupSpec = object of DynamicData
    EVCAdmissionFailedCPUModel = object of EVCAdmissionFailed
    HostIpInconsistentEvent = object of HostEvent
    VsanDecommissioningCost = object of DynamicData
    VmStaticMacConflictEvent = object of VmEvent
    NodeNetworkSpec = object of DynamicData
    HostAuthenticationManagerInfo = object of DynamicData
    HostConfigManager = object of DynamicData
    GeneralHostInfoEvent = object of GeneralEvent
    DestinationSwitchFull = object of CannotAccessNetwork
    FileNameTooLong = object of FileFault
    VmReconfiguredEvent = object of VmEvent
    HostFibreChannelOverEthernetHba = object of HostFibreChannelHba
    AutoStartDefaults = object of DynamicData
    VmSecondaryAddedEvent = object of VmEvent
    ClusterDiagnoseResourceAllocationResult = object of DynamicData
    VirtualMachineEmptyProfileSpec = object of VirtualMachineProfileSpec
    GuestOsDescriptor = object of DynamicData
    UncustomizableGuest = object of CustomizationFault
    CbrcDigestInfo = object of DynamicData
    InsufficientHostMemoryCapacityFault = object of InsufficientHostCapacityFault
    PhysicalNicHint = object of DynamicData
    HostMemberUplinkHealthCheckResult = object of HostMemberHealthCheckResult
    DistributedVirtualSwitchPortCriteria = object of DynamicData
    ComputeResourceSummary = object of DynamicData
    ToolsAutoUpgradeNotSupported = object of VmToolsUpgradeFault
    SoftwarePackageCapability = object of DynamicData
    OvfDuplicateElement = object of OvfElement
    HostFirewallDefaultPolicy = object of DynamicData
    AnswerFileStatusResult = object of DynamicData
    AccountRemovedEvent = object of HostEvent
    HostFileSystemVolumeInfo = object of DynamicData
    PerfInterval = object of DynamicData
    ReplicationVmInProgressFault = object of ReplicationVmFault
    HostMultipathInfo = object of DynamicData
    VMFSDatastoreExpandedEvent = object of HostEvent
    VirtualMachineLegacyNetworkSwitchInfo = object of DynamicData
    MacAddress = object of NegatableExpression
    MaintenanceModeFileMove = object of MigrationFault
    PerfMetricSeries = object of DynamicData
    DVSCapability = object of DynamicData
    VsanUpgradeSystemUpgradeHistoryPreflightFail = object of VsanUpgradeSystemUpgradeHistoryItem
    HostFileSystemVolume = object of DynamicData
    CustomizationPrefixName = object of CustomizationName
    PatchMetadataNotFound = object of PatchMetadataInvalid
    HostCapability = object of DynamicData
    HostCacheConfigurationInfo = object of DynamicData
    Capability = object of DynamicData
    VirtualUSBRemoteClientBackingOption = object of VirtualDeviceRemoteDeviceBackingOption
    OvfMissingAttribute = object of OvfAttribute
    HostVMotionManagerReparentSpec = object of DynamicData
    HostSriovInfo = object of HostPciPassthruInfo
    HostVffsVolume = object of HostFileSystemVolume
    HttpNfcLeaseCapabilities = object of DynamicData
    ExtendedFault = object of VimFault
    HostIpRouteConfig = object of DynamicData
    QuarantineModeFault = object of VmConfigFault
    LicenseAssignmentManagerLicenseFileDescriptor = object of DynamicData
    CannotAccessVmDevice = object of CannotAccessVmComponent
    DiskNotSupported = object of VirtualHardwareCompatibilityIssue
    VmGuestStandbyEvent = object of VmEvent
    VirtualMachinePropertyRelation = object of DynamicData
    VmfsDatastoreAllExtentOption = object of VmfsDatastoreSingleExtentOption
    VmSmpFaultToleranceTooManyVMsOnHost = object of InsufficientResourcesFault
    GuestRegistryKeyAlreadyExists = object of GuestRegistryKeyFault
    HostCnxFailedNetworkErrorEvent = object of HostEvent
    ApplicationQuiesceFault = object of SnapshotFault
    NvdimmGuid = object of DynamicData
    ClusterVmGroup = object of ClusterGroupInfo
    KmipClusterInfo = object of DynamicData
    VirtualNicManagerNetConfig = object of DynamicData
    MemorySizeNotRecommended = object of VirtualHardwareCompatibilityIssue
    ThirdPartyLicenseAssignmentFailed = object of RuntimeFault
    HostEsxAgentHostManagerConfigInfo = object of DynamicData
    VirtualKeyboardOption = object of VirtualDeviceOption
    VsanFault = object of VimFault
    CustomizationLicenseFilePrintData = object of DynamicData
    GeneralHostWarningEvent = object of GeneralEvent
    SDDCBase = object of DynamicData
    ResourceInUse = object of VimFault
    VmPowerOffOnIsolationEvent = object of VmPoweredOffEvent
    DvsIpPort = object of NegatableExpression
    ClusterConfigInfoEx = object of ComputeResourceConfigInfo
    EncryptionKeyRequired = object of InvalidState
    HostDiskMappingOption = object of DynamicData
    VirtualPCIPassthrough = object of VirtualDevice
    DeltaDiskFormatNotSupported = object of VmConfigFault
    InvalidBmcRole = object of VimFault
    OrAlarmExpression = object of AlarmExpression
    CustomizationUserData = object of DynamicData
    VirtualMachineSerialInfo = object of VirtualMachineTargetInfo
    DvsIpPortContainer = object of DvsIpPort
    SecondaryVmAlreadyEnabled = object of VmFaultToleranceIssue
    VirtualMachineFileLayoutSnapshotLayout = object of DynamicData
    HostPathSelectionPolicyOption = object of DynamicData
    PatchSuperseded = object of PatchNotApplicable
    ReplicationConfigFault = object of ReplicationFault
    HostTpmEventLogEntry = object of DynamicData
    NoAccessUserEvent = object of SessionEvent
    OvfInvalidVmName = object of OvfUnsupportedPackage
    OvfCreateImportSpecResult = object of DynamicData
    FailToLockFaultToleranceVMs = object of RuntimeFault
    DisallowedOperationOnFailoverHost = object of RuntimeFault
    VMwareDVSVlanMtuHealthCheckConfig = object of VMwareDVSHealthCheckConfig
    LockerReconfiguredEvent = object of Event
    CustomizationSpecItem = object of DynamicData
    CustomizationSpecInfo = object of DynamicData
    VirtualMachineCloneSpec = object of DynamicData
    EVCAdmissionFailedHostSoftwareForMode = object of EVCAdmissionFailed
    LatencySensitivity = object of DynamicData
    NetDnsConfigSpec = object of DynamicData
    VirtualUSBXHCIController = object of VirtualController
    FcoeConfigFcoeCapabilities = object of DynamicData
    IscsiFault = object of VimFault
    TaskEvent = object of Event
    HostBlockAdapterTargetTransport = object of HostTargetTransport
    IsoImageFileInfo = object of FileInfo
    AuthorizationPrivilege = object of DynamicData
    DistributedVirtualSwitchManagerHostDvsMembershipFilter = object of DistributedVirtualSwitchManagerHostDvsFilterSpec
    HostProfilePolicyMappingPolicyMappingData = object of HostProfileMappingData
    CustomFieldValue = object of DynamicData
    GuestAuthentication = object of DynamicData
    VStorageObject = object of DynamicData
    StorageDrsCannotMoveVmWithMountedCDROM = object of VimFault
    NoPermissionOnAD = object of ActiveDirectoryFault
    InvalidDatastoreState = object of InvalidState
    SwitchIpUnset = object of DvsFault
    HbrManagerVmReplicationCapability = object of DynamicData
    HostPlacedVirtualNicIdentifier = object of DynamicData
    VMOnVirtualIntranet = object of CannotAccessNetwork
    GuestOperationsFault = object of VimFault
    IpPoolIpPoolConfigInfo = object of DynamicData
    VirtualVmxnet2Option = object of VirtualVmxnetOption
    ManagedByInfo = object of DynamicData
    ProfileApplyProfileProperty = object of DynamicData
    AlarmSetting = object of DynamicData
    AlreadyUpgraded = object of VimFault
    HostListSummaryQuickStats = object of DynamicData
    StorageIORMConfigSpec = object of DynamicData
    InvalidEvent = object of VimFault
    IncorrectFileType = object of FileFault
    DvsResourceRuntimeInfo = object of DynamicData
    VmWwnConflictEvent = object of VmEvent
    SessionManagerVmomiServiceRequestSpec = object of SessionManagerServiceRequestSpec
    VsanUpgradeSystemMissingHostsInClusterIssue = object of VsanUpgradeSystemPreflightCheckIssue
    PhysicalNicLinkInfo = object of DynamicData
    VAppPropertyFault = object of VmConfigFault
    UserLogoutSessionEvent = object of SessionEvent
    ClusterVmReadiness = object of DynamicData
    VmFailedToPowerOffEvent = object of VmEvent
    HostMemberHealthCheckResult = object of DynamicData
    VmStartRecordingEvent = object of VmEvent
    OvfDiskOrderConstraint = object of OvfConstraint
    ClusterUsageSummary = object of DynamicData
    VMotionInterfaceIssue = object of MigrationFault
    HostScsiTopologyTarget = object of DynamicData
    VmFailoverFailed = object of VmEvent
    VAppPropertyInfo = object of DynamicData
    VirtualMachineProvisioningPolicyPolicy = object of DynamicData
    HostVMotionManagerSpec = object of DynamicData
    PowerSystemCapability = object of DynamicData
    SsdDiskNotAvailable = object of VimFault
    DVPortConfigSpec = object of DynamicData
    VmfsDatastoreInfo = object of DatastoreInfo
    HostVMotionManagerIpAddressSpec = object of DynamicData
    VirtualDiskOptionVFlashCacheConfigOption = object of DynamicData
    AlarmDescription = object of DynamicData
    VcAgentUninstalledEvent = object of HostEvent
    DrsVmMigratedEvent = object of VmMigratedEvent
    VMFSDatastoreCreatedEvent = object of HostEvent
    NoSubjectName = object of VimFault
    VirtualEthernetCardNetworkBackingInfo = object of VirtualDeviceDeviceBackingInfo
    PatchMetadataCorrupted = object of PatchMetadataInvalid
    DvsIpPortRange = object of DvsIpPort
    HostBootDevice = object of DynamicData
    CryptoKeyResult = object of DynamicData
    OvfXmlFormat = object of OvfInvalidPackage
    ClusterProactiveDrsConfigInfo = object of DynamicData
    ClusterPowerOnVmResult = object of DynamicData
    GenericVmConfigFault = object of VmConfigFault
    OvfNoSupportedHardwareFamily = object of OvfUnsupportedPackage
    DataProviderPropertyPredicate = object of DynamicData
    FcoeConfigFcoeSpecification = object of DynamicData
    IscsiFaultVnicAlreadyBound = object of IscsiFault
    VirtualDiskSeSparseBackingOption = object of VirtualDeviceFileBackingOption
    OvfUnsupportedType = object of OvfUnsupportedPackage
    MtuMismatchEvent = object of DvsHealthStatusChangeEvent
    DrsSoftRuleViolationEvent = object of VmEvent
    VmwareDistributedVirtualSwitchTrunkVlanSpec = object of VmwareDistributedVirtualSwitchVlanSpec
    MigrationResourceErrorEvent = object of MigrationEvent
    LicenseDowngradeDisallowed = object of NotEnoughLicenses
    HostNumaNode = object of DynamicData
    IORMNotSupportedHostOnDatastore = object of VimFault
    HostVFlashManagerVFlashCacheConfigInfoVFlashModuleConfigOption = object of DynamicData
    HostTpmAttestationInfo = object of DynamicData
    VmDiskFileInfo = object of FileInfo
    VmBeingClonedNoFolderEvent = object of VmCloneEvent
    KernelModuleSectionInfo = object of DynamicData
    ReplicationGroupId = object of DynamicData
    HbrDiskMigrationAction = object of ClusterAction
    OvfDeploymentOption = object of DynamicData
    ComplianceResult = object of DynamicData
    NonVmwareOuiMacNotSupportedHost = object of NotSupportedHost
    SnapshotCopyNotSupported = object of MigrationFault
    OvfConsumerPowerOnFault = object of InvalidState
    CustomizationFixedIpV6 = object of CustomizationIpV6Generator
    VMwareDvsLagIpfixConfig = object of DynamicData
    VmConfigFileInfo = object of FileInfo
    DestinationVsanDisabled = object of CannotMoveVsanEnabledHost
    GuestRegistryKeyFault = object of GuestRegistryFault
    AdminPasswordNotChangedEvent = object of HostEvent
    DatastoreVVolContainerFailoverPair = object of DynamicData
    HostUnresolvedVmfsResignatureSpec = object of DynamicData
    VirtualDevicePipeBackingOption = object of VirtualDeviceBackingOption
    DvsPortVendorSpecificStateChangeEvent = object of DvsEvent
    SessionManagerHttpServiceRequestSpec = object of SessionManagerServiceRequestSpec
    ClusterDpmConfigInfo = object of DynamicData
    VirtualSerialPortDeviceBackingInfo = object of VirtualDeviceDeviceBackingInfo
    GuestProcessInfo = object of DynamicData
    AlarmScriptFailedEvent = object of AlarmEvent
    VirtualVmxnet3 = object of VirtualVmxnet
    VirtualDeviceBackingInfo = object of DynamicData
    HostNoRedundantManagementNetworkEvent = object of HostDasEvent
    VirtualMachineFileLayoutExSnapshotLayout = object of DynamicData
    ClusterVmOrchestrationSpec = object of ArrayUpdateSpec
    ProfileMetadataProfileOperationMessage = object of DynamicData
    EventDescription = object of DynamicData
    ClusterComputeResourceFtCompatibleDatastoresResult = object of DynamicData
    InsufficientPerCpuCapacity = object of InsufficientHostCapacityFault
    VwirePort = object of DynamicData
    GuestInfo = object of DynamicData
    DvsPortDeletedEvent = object of DvsEvent
    NumPortsProfile = object of ApplyProfile
    HttpFault = object of VimFault
    SecondaryVmAlreadyDisabled = object of VmFaultToleranceIssue
    MismatchedBundle = object of VimFault
    RDMNotPreserved = object of MigrationFault
    HostVFlashManagerVFlashCacheConfigInfo = object of DynamicData
    CustomizationPending = object of CustomizationFault
    VmSecondaryDisabledEvent = object of VmEvent
    AutoStartPowerInfo = object of DynamicData
    NvdimmSummary = object of DynamicData
    OvfOptionInfo = object of DynamicData
    DVSVmVnicNetworkResourcePool = object of DynamicData
    SnapshotRevertIssue = object of MigrationFault
    PolicyViolatedValueTooSmall = object of PolicyViolatedByValue
    GuestFileInfo = object of DynamicData
    DataProviderBatchQuerySpec = object of DynamicData
    VirtualDevicePipeBackingInfo = object of VirtualDeviceBackingInfo
    HostProfileMappingLookupMappingPair = object of DynamicData
    DVPortgroupPolicy = object of DynamicData
    VMwareUplinkLacpPolicy = object of InheritablePolicy
    ClusterDasDataDetails = object of ClusterDasDataSummary
    PolicyViolatedValueNotEqual = object of PolicyViolatedByValue
    VirtualDiskSpec = object of DynamicData
    VAppOvfSectionInfo = object of DynamicData
    UserSession = object of DynamicData
    VmSnapshotFileQuery = object of FileQuery
    HostFeatureVersionInfo = object of DynamicData
    SharesInfo = object of DynamicData
    PodDiskLocator = object of DynamicData
    LicenseServerUnavailable = object of VimFault
    HostDateTimeSystemTimeZone = object of DynamicData
    IsoImageFileQuery = object of FileQuery
    ClusterDasAdvancedRuntimeInfoVmcpCapabilityInfo = object of DynamicData
    OvfUnsupportedPackage = object of OvfFault
    MacContainer = object of MacAddress
    DvsFault = object of VimFault
    HostBootDeviceInfo = object of DynamicData
    GeneralHostErrorEvent = object of GeneralEvent
    HostUnresolvedVmfsResolutionResult = object of DynamicData
    NetIpConfigInfoIpAddress = object of DynamicData
    HostFeatureCapability = object of DynamicData
    VirtualDeviceFileBackingInfo = object of VirtualDeviceBackingInfo
    HostSystemDebugManagerProcessInfo = object of DynamicData
    InvalidDeviceBacking = object of InvalidDeviceSpec
    HostVvolVolumeSpecification = object of DynamicData
    CustomizationSysprep = object of CustomizationIdentitySettings
    VirtualMachineVMCIDeviceOptionFilterSpecOption = object of DynamicData
    LicenseExpired = object of NotEnoughLicenses
    NvdimmNamespaceCreateSpec = object of DynamicData
    HostNetworkConfig = object of DynamicData
    HostVirtualSwitchBeaconConfig = object of DynamicData
    VmMacChangedEvent = object of VmEvent
    MultiWriterNotSupported = object of DeviceNotSupported
    ProfileMetadataProfileSortSpec = object of DynamicData
    GatewayConnectFault = object of HostConnectFault
    UnsharedSwapVMotionNotSupported = object of MigrationFeatureNotSupported
    VMwareVspanPort = object of DynamicData
    HostHardwareInfo = object of DynamicData
    NonADUserRequired = object of ActiveDirectoryFault
    OvfUnknownEntity = object of OvfSystemFault
    VirtualDeviceConfigSpec = object of DynamicData
    DvsTrafficRuleset = object of DynamicData
    SnapshotMoveNotSupported = object of SnapshotCopyNotSupported
    VirtualDiskOption = object of VirtualDeviceOption
    NoLicenseServerConfigured = object of NotEnoughLicenses
    IpPoolAssociation = object of DynamicData
    ClusterDrsVmConfigInfo = object of DynamicData
    EventFilterSpecByEntity = object of DynamicData
    ExtExtendedProductInfo = object of DynamicData
    VirtualDiskPartitionedRawDiskVer2BackingInfo = object of VirtualDiskRawDiskVer2BackingInfo
    CustomizationGlobalIPSettings = object of DynamicData
    NASDatastoreCreatedEvent = object of HostEvent
    PatchIntegrityError = object of PlatformConfigFault
    StoragePerformanceSummary = object of DynamicData
    OpaqueNetworkCapability = object of DynamicData
    ReplicationInfoDiskSettings = object of DynamicData
    InvalidPrivilege = object of VimFault
    UnableToPlaceAtomicVmGroup = object of VimFault
    DvsTrafficFilterConfigSpec = object of DvsTrafficFilterConfig
    DisallowedChangeByService = object of RuntimeFault
    PassiveNodeNetworkSpec = object of NodeNetworkSpec
    ScheduledTaskSpec = object of DynamicData
    HostProfilePolicyOptionMappingPolicyOptionMappingData = object of HostProfileMappingData
    MultipleSnapshotsNotSupported = object of SnapshotFault
    HostMountInfo = object of DynamicData
    DatastoreCapacityIncreasedEvent = object of DatastoreEvent
    HostIpChangedEvent = object of HostEvent
    DvsOperationBulkFaultFaultOnHost = object of DynamicData
    StorageVMotionNotSupported = object of MigrationFeatureNotSupported
    DatastoreMountPathDatastorePair = object of DynamicData
    VirtualSerialPortDeviceBackingOption = object of VirtualDeviceDeviceBackingOption
    OvfConnectedDeviceFloppy = object of OvfConnectedDevice
    DVSFeatureCapability = object of DynamicData
    RDMNotSupported = object of DeviceNotSupported
    EventFilterSpecByTime = object of DynamicData
    VmToolsUpgradeFault = object of VimFault
    VFlashModuleNotSupported = object of VmConfigFault
    VmCreatedEvent = object of VmEvent
    VirtualDiskRawDiskVer2BackingOption = object of VirtualDeviceDeviceBackingOption
    MksConnectionLimitReached = object of InvalidState
    VirtualMachineRuntimeInfoDasProtectionState = object of DynamicData
    DvsRateLimitNetworkRuleAction = object of DvsNetworkRuleAction
    DrsCorrelationPair = object of DynamicData
    DataProviderResourceItem = object of DynamicData
    VmFaultToleranceTurnedOffEvent = object of VmEvent
    StorageDrsCannotMoveManuallyPlacedVm = object of VimFault
    CustomizationGuiUnattended = object of DynamicData
    VirtualSoundCard = object of VirtualDevice
    LinkProfile = object of ApplyProfile
    PerfEntityMetricBase = object of DynamicData
    NotSupportedHostForVFlash = object of NotSupportedHost
    VirtualMachineIdeDiskDeviceInfo = object of VirtualMachineDiskDeviceInfo
    PassiveNodeDeploymentSpec = object of NodeDeploymentSpec
    VmFaultToleranceInvalidFileBacking = object of VmFaultToleranceIssue
    VmAutoRenameEvent = object of VmEvent
    ClusterHostRecommendation = object of DynamicData
    HttpNfcLeaseDatastoreLeaseInfo = object of DynamicData
    HostVFlashManagerVFlashCacheConfigSpec = object of DynamicData
    ProfileApplyProfileElement = object of ApplyProfile
    ClusterAction = object of DynamicData
    MigrationFault = object of VimFault
    VmBeingDeployedEvent = object of VmEvent
    FailoverNodeInfo = object of DynamicData
    ClusterOrchestrationInfo = object of DynamicData
    TaskDescription = object of DynamicData
    NetIpRouteConfigSpecGatewaySpec = object of DynamicData
    VAppConfigInfo = object of VmConfigInfo
    InvalidDeviceOperation = object of InvalidDeviceSpec
    HostDiskPartitionSpec = object of DynamicData
    HostConfigChange = object of DynamicData
    TooManyNativeClonesOnFile = object of FileFault
    HostSystemSwapConfigurationSystemSwapOption = object of DynamicData
    UsbScanCodeSpec = object of DynamicData
    VmfsDatastoreInfoScsiLunInfo = object of DynamicData
    KernelModuleInfo = object of DynamicData
    VirtualMachineFileLayout = object of DynamicData
    HostVfatVolume = object of HostFileSystemVolume
    OvfConsumerCommunicationError = object of OvfConsumerCallbackFault
    ClusterDasVmSettings = object of DynamicData
    NotADirectory = object of FileFault
    VirtualIDEControllerOption = object of VirtualControllerOption
    HostNicFailureCriteria = object of DynamicData
    HostNicTeamingPolicy = object of DynamicData
    DasAdmissionControlDisabledEvent = object of ClusterEvent
    StorageDrsPodConfigSpec = object of DynamicData
    HostIpRouteOp = object of DynamicData
    DisallowedMigrationDeviceAttached = object of MigrationFault
    LicenseManagerLicenseInfo = object of DynamicData
    VmFaultToleranceIssue = object of VimFault
    DVPortNotSupported = object of DeviceBackingNotSupported
    HostTpmEventDetails = object of DynamicData
    OnceTaskScheduler = object of TaskScheduler
    LicenseServerAvailableEvent = object of LicenseEvent
    DvsVNicProfile = object of ApplyProfile
    MigrationHostErrorEvent = object of MigrationEvent
    DVSOpaqueCommandData = object of DynamicData
    ScheduledTaskDetail = object of TypeDescription
    OvfHardwareExport = object of OvfExport
    HostMultipathStateInfoPath = object of DynamicData
    VirtualSriovEthernetCard = object of VirtualEthernetCard
    DigestNotSupported = object of DeviceNotSupported
    DvsMacNetworkRuleQualifier = object of DvsNetworkRuleQualifier
    ClusterIncreaseCpuCapacityAction = object of ClusterAction
    HostInternetScsiHba = object of HostHostBusAdapter
    OvfUnsupportedDiskProvisioning = object of OvfImport
    VirtualMachineBackupEventInfo = object of DynamicData
    HostTpmBootSecurityOptionEventDetails = object of HostTpmEventDetails
    ClusterDasHostInfo = object of DynamicData
    DatastoreRenamedOnHostEvent = object of HostEvent
    DatastoreHostMount = object of DynamicData
    OvfUnexpectedElement = object of OvfElement
    DvsPortLeavePortgroupEvent = object of DvsEvent
    PhysicalNicConfig = object of DynamicData
    HostMemberSelection = object of SelectionSet
    StorageDrsUnableToMoveFiles = object of VimFault
    StorageIORMDeviceModel = object of DynamicData
    VsanUpgradeSystemAPIBrokenIssue = object of VsanUpgradeSystemPreflightCheckIssue
    VirtualDiskRawDiskVer2BackingInfo = object of VirtualDeviceDeviceBackingInfo
    ServiceLocatorCredential = object of DynamicData
    FcoeConfigVlanRange = object of DynamicData
    VirtualDeviceBusSlotOption = object of DynamicData
    OvfNetworkMappingNotSupported = object of OvfImport
    VmConfigIncompatibleForRecordReplay = object of VmConfigFault
    AlreadyAuthenticatedSessionEvent = object of SessionEvent
    DVSContactInfo = object of DynamicData
    HostDhcpServiceConfig = object of DynamicData
    HostDatastoreConnectInfo = object of DynamicData
    VirtualSriovEthernetCardSriovBackingInfo = object of VirtualDeviceBackingInfo
    VirtualKeyboard = object of VirtualDevice
    HostNetworkConfigResult = object of DynamicData
    TooManyWrites = object of VimFault
    InvalidCAMCertificate = object of InvalidCAMServer
    PrivilegeAvailability = object of DynamicData
    OvfCreateImportSpecParams = object of OvfManagerCommonParams
    StorageDrsVmConfigSpec = object of ArrayUpdateSpec
    HostPciDevice = object of DynamicData
    HostVirtualSwitchBridge = object of DynamicData
    CustomFieldEvent = object of Event
    OvfParseDescriptorResult = object of DynamicData
    ScsiLunDurableName = object of DynamicData
    ClusterDasAdvancedRuntimeInfo = object of DynamicData
    HostSnmpDestination = object of DynamicData
    VirtualCdromIsoBackingInfo = object of VirtualDeviceFileBackingInfo
    ApplyHostProfileConfigurationSpec = object of ProfileExecuteResult
    HostProfilesEntityCustomizations = object of DynamicData
    ImportHostProfileCustomizationsResult = object of DynamicData
    ConflictingConfigurationConfig = object of DynamicData
    VirtualUSBUSBBackingInfo = object of VirtualDeviceDeviceBackingInfo
    InsufficientNetworkCapacity = object of InsufficientResourcesFault
    VsanUpgradeSystemNotEnoughFreeCapacityIssue = object of VsanUpgradeSystemPreflightCheckIssue
    HostNetworkTrafficShapingPolicy = object of DynamicData
    VimVasaProvider = object of DynamicData
    CannotAccessVmConfig = object of CannotAccessVmComponent
    VirtualMachineVFlashModuleInfo = object of VirtualMachineTargetInfo
    HostVMotionManagerVMotionResult = object of DynamicData
    VirtualVmxnet3Option = object of VirtualVmxnetOption
    TaskFilterSpecByTime = object of DynamicData
    DVSOpaqueDataList = object of DynamicData
    GatewayNotReachable = object of GatewayConnectFault
    FaultDomainId = object of DynamicData
    DVSFailureCriteria = object of InheritablePolicy
    CustomizationStartedEvent = object of CustomizationEvent
    ComputeResourceHostSPBMLicenseInfo = object of DynamicData
    HostProfileManagerHostToConfigSpecMap = object of DynamicData
    DatastoreFileMovedEvent = object of DatastoreFileEvent
    OvfUnknownDevice = object of OvfSystemFault
    VchaClusterDeploymentSpec = object of DynamicData
    VMotionLinkDown = object of VMotionInterfaceIssue
    VirtualDiskLocalPMemBackingInfo = object of VirtualDeviceFileBackingInfo
    DistributedVirtualSwitchHostProductSpec = object of DynamicData
    AlarmAcknowledgedEvent = object of AlarmEvent
    NamespaceFull = object of VimFault
    HostVMotionNetConfig = object of DynamicData
    HostFirewallInfo = object of DynamicData
    TemplateUpgradeFailedEvent = object of TemplateUpgradeEvent
    HostSpecification = object of DynamicData
    ProxyServiceEndpointSpec = object of DynamicData
    UplinkPortVlanUntrunkedEvent = object of DvsHealthStatusChangeEvent
    InfoUpgradeEvent = object of UpgradeEvent
    CustomizationFailed = object of CustomizationEvent
    FaultTolerancePrimaryConfigInfo = object of FaultToleranceConfigInfo
    VirtualSerialPort = object of VirtualDevice
    ProfileHostProfileEngineHostProfileManagerProfileMetaArray = object of DynamicData
    VirtualIDEController = object of VirtualController
    VirtualMachineCpuIdInfoSpec = object of ArrayUpdateSpec
    HostScsiDiskPartition = object of DynamicData
    VmDisconnectedEvent = object of VmEvent
    DvsHostInfrastructureTrafficResource = object of DynamicData
    GroupAlarmAction = object of AlarmAction
    InvalidDasConfigArgument = object of InvalidArgument
    VMwareDVSTeamingHealthCheckConfig = object of VMwareDVSHealthCheckConfig
    DvpgRestoreEvent = object of DVPortgroupEvent
    ErrorUpgradeEvent = object of UpgradeEvent
    VsanUpgradeSystemV2ObjectsPresentDuringDowngradeIssue = object of VsanUpgradeSystemPreflightCheckIssue
    ImportOperationBulkFault = object of DvsFault
    FileQuery = object of DynamicData
    VirtualPCIController = object of VirtualController
    VmConfigFileQuery = object of FileQuery
    HostPnicNetworkResourceInfo = object of DynamicData
    ReplicationInvalidOptions = object of ReplicationFault
    LocalDatastoreCreatedEvent = object of HostEvent
    CryptoManagerKmipServerStatus = object of DynamicData
    OvfCreateDescriptorResult = object of DynamicData
    DatastoreRenamedEvent = object of DatastoreEvent
    VirtualPCIPassthroughDeviceBackingInfo = object of VirtualDeviceDeviceBackingInfo
    SwapDatastoreUnset = object of VimFault
    GatewayToHostTrustVerifyFault = object of GatewayToHostConnectFault
    MethodDescription = object of Description
    VirtualMachineDisplayTopology = object of DynamicData
    VmFailedRelayoutEvent = object of VmEvent
    DasClusterIsolatedEvent = object of ClusterEvent
    ShrinkDiskFault = object of VimFault
    HostProfileManagerCompositionValidationResult = object of DynamicData
    NoDatastoresConfiguredEvent = object of HostEvent
    HostSubSpecificationDeleteEvent = object of HostEvent
    VirtualUSBControllerOption = object of VirtualControllerOption
    UnexpectedCustomizationFault = object of CustomizationFault
    DatastoreNotWritableOnHost = object of InvalidDatastore
    VirtualMachineGuestQuiesceSpec = object of DynamicData
    GuestProcessNotFound = object of GuestOperationsFault
    VirtualMachineMetadataManagerVmMetadataResult = object of DynamicData
    ProfileHostProfileEngineHostProfileManagerUserInputArray = object of DynamicData
    HostLowLevelProvisioningManagerVmMigrationStatus = object of DynamicData
    VirtualSerialPortURIBackingOption = object of VirtualDeviceURIBackingOption
    InvalidEditionLicense = object of NotEnoughLicenses
    VirtualMachineToolsUpdateStatus = object of DynamicData
    AlarmSnmpCompletedEvent = object of AlarmEvent
    InvalidNetworkInType = object of VAppPropertyFault
    TooManyGuestLogons = object of GuestOperationsFault
    NumericRange = object of DynamicData
    SwitchNotInUpgradeMode = object of DvsFault
    HttpNfcLeaseInfo = object of DynamicData
    VirtualMachineProvisioningPolicy = object of DynamicData
    HostCacheConfigurationSpec = object of DynamicData
    HostNatServiceSpec = object of DynamicData
    LibraryOperation = object of LibraryFault
    HostNonCompliantEvent = object of HostEvent
    WillResetSnapshotDirectory = object of MigrationFault
    ClusterProfileConfigServiceCreateSpec = object of ClusterProfileConfigSpec
    VirtualDiskSparseVer2BackingOption = object of VirtualDeviceFileBackingOption
    VmConfigFault = object of VimFault
    GeneralVmWarningEvent = object of GeneralEvent
type
    VsanUpgradeSystem = object of ManagedObject
    
    IscsiManager = object of ManagedObject
    
    VirtualMachinePauseManager = object of ManagedObject
    
    IoFilterManager = object of ManagedObject
    
    CertificateManager = object of ManagedObject
    
    HostDiskManager = object of ManagedObject
    
    DistributedVirtualSwitchManager = object of ManagedObject
    
    FailoverClusterManager = object of ManagedObject
      disabledClusterMethod*: seq[string]

    Profile = object of ManagedObject
      config*: ProfileConfigInfo
      description*: ProfileDescription
      name*: string
      createdTime*: string
      modifiedTime*: string
      entity*: seq[ManagedEntity]
      complianceStatus*: string

    LocalizationManager = object of ManagedObject
      catalog*: seq[LocalizationManagerMessageCatalog]

    AuthorizationManager = object of ManagedObject
      privilegeList*: seq[AuthorizationPrivilege]
      roleList*: seq[AuthorizationRole]
      description*: AuthorizationDescription

    StorageResourceManager = object of ManagedObject
    
    PerformanceManager = object of ManagedObject
      description*: PerformanceDescription
      historicalInterval*: seq[PerfInterval]
      perfCounter*: seq[PerfCounterInfo]

    HostLocalAuthentication = object of HostAuthenticationStore
    
    HostSnmpSystem = object of ManagedObject
      configuration*: HostSnmpConfigSpec
      limits*: HostSnmpSystemAgentLimits

    VirtualMachineCompatibilityChecker = object of ManagedObject
    
    ServiceDirectory = object of ManagedObject
      service*: seq[ServiceEndpoint]

    Folder = object of ManagedEntity
      childType*: seq[string]
      childEntity*: seq[ManagedEntity]

    LicenseDataManager = object of ManagedObject
      entityLicenseData*: seq[LicenseDataManagerEntityLicenseData]

    DeploymentInfo = object of ManagedObject
      pscNodes*: seq[DeploymentInfoServiceInfo]
      hostName*: string

    HostFaultToleranceManager = object of ManagedObject
    
    VmwareDistributedVirtualSwitch = object of DistributedVirtualSwitch
    
    HostDiagnosticSystem = object of ManagedObject
      activePartition*: HostDiagnosticPartition

    HostProfileManager = object of ProfileManager
      supportedCustomizationFormats*: seq[ExtendedElementDescription]

    EsxAgentConfigManager = object of ManagedObject
    
    TagPolicyOption = object of ManagedEntity
    
    VirtualMachineBackupAgent = object of ExtensibleManagedObject
    
    OverheadService = object of ManagedObject
    
    OvfConsumer = object of ManagedObject
    
    CDCChangeLogCollector = object of ManagedObject
    
    HostBootDeviceSystem = object of ManagedObject
    
    ClusterEVCManager = object of ExtensibleManagedObject
      managedCluster*: ClusterComputeResource
      evcState*: ClusterEVCManagerEVCState

    EventManager = object of ManagedObject
      description*: EventDescription
      latestEvent*: Event
      maxCollector*: int

    IpPoolManager = object of ManagedObject
    
    ContentLibrary = object of ManagedEntity
    
    HostLoadEsxManager = object of ManagedObject
    
    HostNvdimmSystem = object of ManagedObject
      nvdimmSystemInfo*: NvdimmSystemInfo

    HostDistributedVirtualSwitchManager = object of ManagedObject
      distributedVirtualSwitch*: seq[string]

    DrsStatsManager = object of ManagedObject
      injectorWorkload*: seq[DrsInjectorWorkload]
      hostIormStatus*: seq[DrsHostIormStatus]

    NetworkManager = object of ManagedObject
    
    HostImageConfigManager = object of ManagedObject
    
    CryptoManagerHost = object of CryptoManager
    
    Datastore = object of ManagedEntity
      info*: DatastoreInfo
      summary*: DatastoreSummary
      host*: seq[DatastoreHostMount]
      vm*: seq[VirtualMachine]
      browser*: HostDatastoreBrowser
      capability*: DatastoreCapability
      iormConfiguration*: StorageIORMInfo

    HostHealthStatusSystem = object of ManagedObject
      runtime*: HealthSystemRuntime

    ClusterProfile = object of Profile
    
    HostTelemetryManager = object of ManagedObject
    
    DataProviderResourceModel = object of ManagedObject
    
    HostKernelModuleSystem = object of ManagedObject
    
    ManagedEntity = object of ExtensibleManagedObject
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

    ResourcePlanningManager = object of ManagedObject
    
    HostHostUpdateProxyManager = object of ManagedObject
    
    Datacenter = object of ManagedEntity
      vmFolder*: Folder
      hostFolder*: Folder
      datastoreFolder*: Folder
      networkFolder*: Folder
      datastore*: seq[Datastore]
      network*: seq[Network]
      configuration*: DatacenterConfigInfo

    CustomizationSpecManager = object of ManagedObject
      info*: seq[CustomizationSpecInfo]
      encryptionKey*: seq[byte]

    VcenterVStorageObjectManager = object of VStorageObjectManagerBase
    
    ExtensionManager = object of ManagedObject
      extensionList*: seq[Extension]

    GuestFileManager = object of ManagedObject
    
    OvfManager = object of ManagedObject
      ovfImportOption*: seq[OvfOptionInfo]
      ovfExportOption*: seq[OvfOptionInfo]

    ProfileComplianceManager = object of ManagedObject
    
    ViewManager = object of ManagedObject
      viewList*: seq[View]

    ManagedObjectView = object of View
      view*: seq[ManagedObject]

    VirtualDiskManager = object of ManagedObject
    
    HostSpecificationAgent = object of ManagedObject
    
    ContentLibraryItem = object of ManagedEntity
    
    HostDateTimeSystem = object of ManagedObject
      dateTimeInfo*: HostDateTimeInfo

    InventoryView = object of ManagedObjectView
    
    ProfileHostProfileEngineHostProfileManager = object of ManagedObject
    
    HostSystem = object of ManagedEntity
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

    HostVirtualNicManager = object of ExtensibleManagedObject
      info*: HostVirtualNicManagerInfo

    HostVmciAccessManager = object of ManagedObject
    
    DistributedVirtualSwitch = object of ManagedEntity
      uuid*: string
      capability*: DVSCapability
      summary*: DVSSummary
      config*: DVSConfigInfo
      networkResourcePool*: seq[DVSNetworkResourcePool]
      portgroup*: seq[DistributedVirtualPortgroup]
      runtime*: DVSRuntimeInfo

    HbrManager = object of ManagedObject
    
    HostVStorageObjectManager = object of VStorageObjectManagerBase
    
    HostCertificateManager = object of ManagedObject
      certificateInfo*: HostCertificateManagerCertificateInfo

    EventHistoryCollector = object of HistoryCollector
      latestPage*: seq[Event]

    EnvironmentBrowser = object of ManagedObject
      datastoreBrowser*: HostDatastoreBrowser

    HostDiskManagerLease = object of ManagedObject
    
    HostFirmwareSystem = object of ManagedObject
    
    HealthUpdateManager = object of ManagedObject
    
    ClusterComputeResource = object of ComputeResource
      configuration*: ClusterConfigInfo
      recommendation*: seq[ClusterRecommendation]
      drsRecommendation*: seq[ClusterDrsRecommendation]
      migrationHistory*: seq[ClusterDrsMigration]
      actionHistory*: seq[ClusterActionHistory]
      drsFault*: seq[ClusterDrsFaults]

    HostAuthenticationStore = object of ManagedObject
      info*: HostAuthenticationStoreInfo

    HostMemorySystem = object of ExtensibleManagedObject
      consoleReservationInfo*: ServiceConsoleReservationInfo
      virtualMachineReservationInfo*: VirtualMachineMemoryReservationInfo

    HostLowLevelProvisioningManager = object of ManagedObject
    
    AlarmManager = object of ManagedObject
      defaultExpression*: seq[AlarmExpression]
      description*: AlarmDescription
      lastTriggerId*: int

    HostCacheConfigurationManager = object of ManagedObject
      cacheConfigurationInfo*: seq[HostCacheConfigurationInfo]

    FailoverClusterConfigurator = object of ManagedObject
      disabledConfigureMethod*: seq[string]

    HistoryCollector = object of ManagedObject
      filter*: pointer

    VirtualMachineProvisioningChecker = object of ManagedObject
    
    ServiceManager = object of ManagedObject
      service*: seq[ServiceManagerServiceInfo]

    TagPolicy = object of ManagedEntity
    
    StoragePod = object of Folder
      summary*: StoragePodSummary
      podStorageDrsEntry*: PodStorageDrsEntry

    HostPatchManager = object of ManagedObject
    
    HostSystemDebugManager = object of ManagedObject
    
    HostTpmManager = object of ManagedObject
    
    ClusterTransitionalEVCManager = object of ExtensibleManagedObject
      managedCluster*: ClusterComputeResource
      evcState*: ClusterTransitionalEVCManagerEVCState

    Network = object of ManagedEntity
      summary*: NetworkSummary
      host*: seq[HostSystem]
      vm*: seq[VirtualMachine]

    CryptoManagerHostKMS = object of CryptoManagerHost
    
    ResourcePool = object of ManagedEntity
      summary*: ResourcePoolSummary
      runtime*: ResourcePoolRuntimeInfo
      owner*: ComputeResource
      resourcePool*: seq[ResourcePool]
      vm*: seq[VirtualMachine]
      config*: ResourceConfigSpec
      childConfiguration*: seq[ResourceConfigSpec]

    HostCpuSchedulerSystem = object of ExtensibleManagedObject
      hyperthreadInfo*: HostHyperThreadScheduleInfo

    HostPowerSystem = object of ManagedObject
      capability*: PowerSystemCapability
      info*: PowerSystemInfo

    GuestAuthManager = object of ManagedObject
    
    SessionManager = object of ManagedObject
      sessionList*: seq[UserSession]
      currentSession*: UserSession
      message*: string
      messageLocaleList*: seq[string]
      supportedLocaleList*: seq[string]
      defaultLocale*: string

    NfcService = object of ManagedObject
    
    GuestOperationsManager = object of ManagedObject
      authManager*: GuestAuthManager
      fileManager*: GuestFileManager
      processManager*: GuestProcessManager
      guestWindowsRegistryManager*: GuestWindowsRegistryManager
      aliasManager*: GuestAliasManager

    HostLocalAccountManager = object of ManagedObject
    
    OpaqueNetwork = object of Network
      capability*: OpaqueNetworkCapability
      extraConfig*: seq[OptionValue]

    OverheadMemoryManager = object of ManagedObject
    
    VirtualMachineSnapshot = object of ExtensibleManagedObject
      config*: VirtualMachineConfigInfo
      childSnapshot*: seq[VirtualMachineSnapshot]
      vm*: VirtualMachine

    HostVMotionManager = object of ManagedObject
    
    VirtualMachineMetadataManager = object of ManagedObject
    
    GuestWindowsRegistryManager = object of ManagedObject
    
    HostFirewallSystem = object of ExtensibleManagedObject
      firewallInfo*: HostFirewallInfo

    HostNetworkSystem = object of ExtensibleManagedObject
      capabilities*: HostNetCapabilities
      networkInfo*: HostNetworkInfo
      offloadCapabilities*: HostNetOffloadCapabilities
      networkConfig*: HostNetworkConfig
      dnsConfig*: HostDnsConfig
      ipRouteConfig*: HostIpRouteConfig
      consoleIpRouteConfig*: HostIpRouteConfig

    VirtualApp = object of ResourcePool
      parentFolder*: Folder
      datastore*: seq[Datastore]
      network*: seq[Network]
      vAppConfig*: VAppConfigInfo
      parentVApp*: ManagedEntity
      childLink*: seq[VirtualAppLinkInfo]

    HostStorageSystem = object of ExtensibleManagedObject
      storageDeviceInfo*: HostStorageDeviceInfo
      fileSystemVolumeInfo*: HostFileSystemVolumeInfo
      systemFile*: seq[string]
      multipathStateInfo*: HostMultipathStateInfo

    AgentManager = object of ManagedObject
    
    HostDirectoryStore = object of HostAuthenticationStore
    
    Alarm = object of ExtensibleManagedObject
      info*: AlarmInfo

    VStorageObjectManagerBase = object of ManagedObject
    
    Task = object of ExtensibleManagedObject
      info*: TaskInfo

    SimpleCommand = object of ManagedObject
      encodingType*: SimpleCommandEncoding
      entity*: ServiceManagerServiceInfo

    GuestProcessManager = object of ManagedObject
    
    DatastoreNamespaceManager = object of ManagedObject
    
    View = object of ManagedObject
    
    ProfileManager = object of ManagedObject
      profile*: seq[Profile]

    DiagnosticManager = object of ManagedObject
    
    LegacyTemplateManager = object of ManagedObject
    
    VirtualMachineNamespaceManager = object of ManagedObject
    
    CbrcManager = object of ManagedObject
    
    ClusterProfileManager = object of ProfileManager
    
    ScheduledTaskManager = object of ManagedObject
      scheduledTask*: seq[ScheduledTask]
      description*: ScheduledTaskDescription

    HostProfile = object of Profile
      validationState*: string
      validationStateUpdateTime*: string
      validationFailureInfo*: HostProfileValidationFailureInfo
      referenceHost*: HostSystem

    TaskManager = object of ManagedObject
      recentTask*: seq[Task]
      description*: TaskDescription
      maxCollector*: int

    VirtualMachine = object of ManagedEntity
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

    AntiAffinityGroup = object of ManagedEntity
    
    HostEsxAgentHostManager = object of ManagedObject
      configInfo*: HostEsxAgentHostManagerConfigInfo

    HostAutoStartManager = object of ManagedObject
      config*: HostAutoStartManagerConfig

    ContainerView = object of ManagedObjectView
      container*: ManagedEntity
      type*: seq[string]
      recursive*: bool

    ImageLibraryManager = object of ManagedObject
    
    ServiceInstance = object of ManagedObject
      serverClock*: string
      capability*: Capability
      content*: ServiceContent

    HostDatastoreBrowser = object of ManagedObject
      datastore*: seq[Datastore]
      supportedType*: seq[FileQuery]

    SearchIndex = object of ManagedObject
    
    HostVsanInternalSystem = object of ManagedObject
    
    HostVsanSystem = object of ManagedObject
      config*: VsanHostConfigInfo

    TaskHistoryCollector = object of HistoryCollector
      latestPage*: seq[TaskInfo]

    VRPResourceManager = object of ManagedObject
    
    VirtualDatacenter = object of ManagedEntity
    
    CustomFieldsManager = object of ManagedObject
      field*: seq[CustomFieldDef]

    HostGraphicsManager = object of ExtensibleManagedObject
      graphicsInfo*: seq[HostGraphicsInfo]
      graphicsConfig*: HostGraphicsConfig
      sharedPassthruGpuTypes*: seq[string]
      sharedGpuCapabilities*: seq[HostSharedGpuCapabilities]

    ProxyService = object of ManagedObject
      httpsPort*: int
      httpPort*: int
      endpointList*: seq[ProxyServiceEndpointSpec]

    MessageBusProxy = object of ManagedObject
    
    UserDirectory = object of ManagedObject
      domainList*: seq[string]

    ExternalStatsManager = object of ManagedObject
    
    HttpNfcLease = object of ManagedObject
      initializeProgress*: int
      transferProgress*: int
      mode*: string
      capabilities*: HttpNfcLeaseCapabilities
      info*: HttpNfcLeaseInfo
      state*: HttpNfcLeaseState
      error*: MethodFault

    HostOperationCleanupManager = object of ManagedObject
    
    HostServiceSystem = object of ExtensibleManagedObject
      serviceInfo*: HostServiceInfo

    FileManager = object of ManagedObject
    
    HostSpecificationManager = object of ManagedObject
    
    HostAuthenticationManager = object of ManagedObject
      info*: HostAuthenticationManagerInfo
      supportedStore*: seq[HostAuthenticationStore]

    ComputeResource = object of ManagedEntity
      resourcePool*: ResourcePool
      host*: seq[HostSystem]
      datastore*: seq[Datastore]
      network*: seq[Network]
      summary*: ComputeResourceSummary
      environmentBrowser*: EnvironmentBrowser
      configurationEx*: ComputeResourceConfigInfo

    CryptoManagerKmip = object of CryptoManager
      kmipServers*: seq[KmipClusterInfo]

    GuestAliasManager = object of ManagedObject
    
    ScheduledTask = object of ExtensibleManagedObject
      info*: ScheduledTaskInfo

    HostVMotionSystem = object of ExtensibleManagedObject
      netConfig*: HostVMotionNetConfig
      ipConfig*: HostIpConfig

    HostVFlashManager = object of ManagedObject
      vFlashConfigInfo*: HostVFlashManagerVFlashConfigInfo

    ListView = object of ManagedObjectView
    
    LicenseAssignmentManager = object of ManagedObject
    
    HostActiveDirectoryAuthentication = object of HostDirectoryStore
    
    VirtualizationManager = object of ManagedObject
    
    LicenseManager = object of ManagedObject
      source*: LicenseSource
      sourceAvailable*: bool
      diagnostics*: LicenseDiagnostics
      featureInfo*: seq[LicenseFeatureInfo]
      licensedEdition*: string
      licenses*: seq[LicenseManagerLicenseInfo]
      licenseAssignmentManager*: LicenseAssignmentManager
      evaluation*: LicenseManagerEvaluationInfo

    ProfileHostProfileEngineComplianceManager = object of ManagedObject
    
    ExtensibleManagedObject = object of ManagedObject
      value*: seq[CustomFieldValue]
      availableField*: seq[CustomFieldDef]

    HostDatastoreSystem = object of ManagedObject
      datastore*: seq[Datastore]
      capabilities*: HostDatastoreSystemCapabilities

    OptionManager = object of ManagedObject
      supportedOption*: seq[OptionDef]
      setting*: seq[OptionValue]

    CryptoManager = object of ManagedObject
      enabled*: bool

    HostAccessManager = object of ManagedObject
      lockdownMode*: HostLockdownMode

    WorkflowStepHandler = object of ManagedObject
    
    DistributedVirtualPortgroup = object of Network
      key*: string
      config*: DVPortgroupConfigInfo
      portKeys*: seq[string]

    VasaVvolManager = object of ManagedObject
    
    HostPciPassthruSystem = object of ExtensibleManagedObject
      pciPassthruInfo*: seq[HostPciPassthruInfo]
      sriovDevicePoolInfo*: seq[HostSriovDevicePoolInfo]
