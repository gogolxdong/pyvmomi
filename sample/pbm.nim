
type
  PbmAssociatedPolicyCapabilities* = ref object of DynamicData
    sourceEntity*: PbmServerObjectRef
    policySpec*: VirtualMachineProfileSpec
    hub*: PbmPlacementHub
    canonicalPropertyIds*: seq[PbmCanonicalPropertyId]
    result*: PbmAssociatedPolicyCapabilitiesResult

type
  PbmIncompatibleVendorSpecificRuleSet* = ref object of PbmCapabilityProfilePropertyMismatchFault
  
type
  PbmDefaultCapabilityProfile* = ref object of PbmCapabilityProfile
    vvolType*: seq[string]
    containerId*: string

type
  PbmDefaultProfileAppliesFault* = ref object of PbmCompatibilityCheckFault
  
type
  PbmComplianceProvider* = ref object of pbm.provider.Provider
  
type
  PbmComplianceOperationalStatus* = ref object of DynamicData
    healthy*: bool
    operationETA*: string
    operationProgress*: int64
    transitional*: bool

type
  PbmExtendedElementDescription* = ref object of DynamicData
    label*: string
    summary*: string
    key*: string
    messageCatalogKeyPrefix*: string
    messageArg*: seq[KeyAnyValue]

type
  PbmSystemCreatedProfileType* {.pure.} = enum
    VsanDefaultProfile, VVolDefaultProfile, PmemDefaultProfile,
    VmcManagementProfile
type
  PbmObjectType* {.pure.} = enum
    virtualMachine, virtualMachineAndDisks, virtualDiskId, virtualDiskUUID,
    datastore, host, cluster, unknown
type
  PbmCapabilityProviderInfo* = ref object of DynamicData
    providerUuid*: string
    schemaId*: string

type
  PbmComplianceProviderRegistry* = ref object of vmodl.ManagedObject
  
type
  PbmEntityAssociations* = ref object of DynamicData
    operation*: string
    entity*: PbmServerObjectRef
    policyAssociations*: seq[PbmPolicyAssociation]
    fault*: MethodFault

type
  PbmTask* = ref object of vmodl.ManagedObject
  
type
  PbmRollupComplianceResult* = ref object of DynamicData
    oldestCheckTime*: string
    entity*: PbmServerObjectRef
    overallComplianceStatus*: string
    overallComplianceTaskStatus*: string
    result*: seq[PbmComplianceResult]
    errorCause*: seq[MethodFault]
    profileMismatch*: bool

type
  PbmCapabilityMetadata* = ref object of DynamicData
    id*: PbmCapabilityMetadataUniqueId
    summary*: PbmExtendedElementDescription
    mandatory*: bool
    hint*: bool
    keyId*: string
    allowMultipleConstraints*: bool
    propertyMetadata*: seq[PbmCapabilityPropertyMetadata]

type
  PbmVmOperation* {.pure.} = enum
    CREATE, RECONFIGURE, MIGRATE, CLONE
type
  PbmFaultNotFound* = ref object of PbmFault
  
type
  PbmProviderInfo* = ref object of DynamicData
    uniqueId*: string
    location*: string
    description*: string

type
  PbmCompliancePolicyStatus* = ref object of DynamicData
    expectedValue*: PbmCapabilityInstance
    currentValue*: PbmCapabilityInstance

type
  PbmCapabilityProfilePropertyMismatchFault* = ref object of PbmPropertyMismatchFault
    resourcePropertyInstance*: PbmCapabilityPropertyInstance

type
  PbmProfileQueryProfileResultInternal* = ref object of PbmQueryProfileResult
    defaultPolicy*: bool
    autoRg*: bool

type
  PbmAssociationProviderInfo* = ref object of PbmProviderInfo
    provider*: PbmAssociationProvider

type
  PbmCapabilityMetadataManager* = ref object of vmodl.ManagedObject
  
type
  PbmAssociatedPolicyCapabilitiesResult* = ref object of DynamicData
    effectiveProfileId*: PbmProfileId
    values*: seq[PbmCanonicalPropertyValue]
    fault*: MethodFault

type
  PbmProfileProviderInfo* = ref object of PbmProviderInfo
    profileType*: seq[PbmProfileType]
    provider*: PbmProfileProvider

type
  PbmAssociationMetadata* = ref object of DynamicData
    associableEntityType*: string
    associableProfileType*: string

type
  PbmCapabilityConstraints* = ref object of DynamicData
  
type
  PbmDuplicateName* = ref object of PbmFault
    name*: string

type
  PbmPlacementSolver* = ref object of vmodl.ManagedObject
  
type
  PbmProfileCategoryEnum* {.pure.} = enum
    REQUIREMENT, RESOURCE, DATA_SERVICE_POLICY
type
  PbmDefaultProfileInfo* = ref object of DynamicData
    datastores*: seq[PbmPlacementHub]
    defaultProfile*: PbmProfile

type
  PbmCapabilityProfile* = ref object of PbmProfile
    profileCategory*: string
    resourceType*: PbmProfileResourceType
    constraints*: PbmCapabilityConstraints
    generationId*: int64
    isDefault*: bool
    systemCreatedProfileType*: string
    lineOfService*: string

type
  PbmCapabilitySchema* = ref object of DynamicData
    vendorInfo*: PbmCapabilitySchemaVendorInfo
    namespaceInfo*: PbmCapabilityNamespaceInfo
    lineOfService*: PbmLineOfServiceInfo
    capabilityMetadataPerCategory*: seq[PbmCapabilityMetadataPerCategory]

type
  PbmCapabilityMetadataUniqueId* = ref object of DynamicData
    namespace*: string
    id*: string

type
  PbmAssociationProvider* = ref object of pbm.provider.Provider
  
type
  PbmCapabilityGenericTypeInfo* = ref object of PbmCapabilityTypeInfo
    genericTypeName*: string

type
  PbmProfileDefaultProfileAssociateOp* = ref object of PbmProfileAssociateOp
  
type
  PbmLegacyHubsNotSupported* = ref object of PbmFault
    hubs*: seq[PbmPlacementHub]

type
  PbmPlacementHubFinderInfo* = ref object of PbmProviderInfo
    finderType*: string
    supportedHubType*: string
    finder*: PbmPlacementHubFinder

type
  PbmProfileProviderRegistry* = ref object of vmodl.ManagedObject
  
type
  PbmProfileOperationOutcome* = ref object of DynamicData
    profileId*: PbmProfileId
    fault*: MethodFault

type
  PbmComplianceResultComplianceTaskStatus* {.pure.} = enum
    inProgress, success, failed
type
  PbmPlacementHubSelectionInfo* = ref object of DynamicData
    hub*: PbmPlacementHub
    capacityInfo*: seq[PbmPlacementHubCapacityInfo]

type
  PbmFault* = ref object of MethodFault
  
type
  PbmVmAssociations* = ref object of DynamicData
    operation*: string
    vm*: PbmServerObjectRef
    policyAssociations*: seq[PbmPolicyAssociation]
    fault*: MethodFault

type
  PbmPlacementSubjectAssignment* = ref object of DynamicData
    subject*: PbmPlacementSubject
    hub*: PbmPlacementHub

type
  PbmCapabilityMetadataInfo* = ref object of DynamicData
    resourceType*: string
    capabilitySchema*: seq[PbmCapabilitySchema]

type
  PbmBuiltinGenericType* {.pure.} = enum
    VMW_RANGE, VMW_SET
type
  PbmDatastoreSpaceStatistics* = ref object of DynamicData
    profileId*: string
    physicalTotalInMB*: int64
    physicalFreeInMB*: int64
    physicalUsedInMB*: int64
    logicalLimitInMB*: int64
    logicalFreeInMB*: int64
    logicalUsedInMB*: int64

type
  PbmPlacementHubCapacityInfo* = ref object of DynamicData
    capacityCategory*: string
    percentageRemaining*: int64

type
  PbmProfileFcdDeleteOp* = ref object of PbmProfileDissociateOp
  
type
  PbmCapabilityProfileCreateSpec* = ref object of DynamicData
    name*: string
    description*: string
    category*: string
    resourceType*: PbmProfileResourceType
    constraints*: PbmCapabilityConstraints

type
  PbmDebugManager* = ref object of vmodl.ManagedObject
  
type
  PbmResourceAssociation* = ref object of DynamicData
    profileId*: string
    resourceId*: string

type
  PbmCapabilityTimeSpan* = ref object of DynamicData
    value*: int
    unit*: string

type
  PbmServiceInstanceContent* = ref object of DynamicData
    aboutInfo*: PbmAboutInfo
    sessionManager*: PbmSessionManager
    capabilityMetadataManager*: PbmCapabilityMetadataManager
    profileManager*: PbmProfileProfileManager
    complianceManager*: PbmComplianceManager
    placementSolver*: PbmPlacementSolver
    replicationManager*: PbmReplicationManager

type
  PbmComplianceResult* = ref object of DynamicData
    checkTime*: string
    entity*: PbmServerObjectRef
    profile*: PbmProfileId
    complianceTaskStatus*: string
    complianceStatus*: string
    mismatch*: bool
    violatedPolicies*: seq[PbmCompliancePolicyStatus]
    errorCause*: seq[MethodFault]
    operationalStatus*: PbmComplianceOperationalStatus
    info*: PbmExtendedElementDescription

type
  PbmCapabilityVendorNamespaceInfo* = ref object of DynamicData
    vendorInfo*: PbmCapabilitySchemaVendorInfo
    namespaceInfo*: PbmCapabilityNamespaceInfo

type
  PbmProvider* = ref object of vmodl.ManagedObject
  
type
  PbmProfileAssociateOp* = ref object of PbmProfileChangeAssociationOp
    profile*: PbmProfileId
    diskEntity*: seq[PbmServerObjectRef]
    replicationSpec*: ReplicationSpec
    hub*: PbmPlacementHub

type
  PbmCapabilityConstraintInstance* = ref object of DynamicData
    propertyInstance*: seq[PbmCapabilityPropertyInstance]

type
  PbmServiceInstance* = ref object of vmodl.ManagedObject
    content*: PbmServiceInstanceContent

type
  PbmCompatibilityCheckFault* = ref object of PbmFault
    hub*: PbmPlacementHub

type
  PbmProfileProvider* = ref object of pbm.provider.Provider
  
type
  PbmPlacementMatchingReplicationResources* = ref object of PbmPlacementMatchingResources
    replicationGroup*: seq[ReplicationGroupId]

type
  PbmProfileReconfigOutcome* = ref object of DynamicData
    entity*: PbmServerObjectRef
    taskMoid*: string
    fault*: MethodFault

type
  PbmCapabilityVendorResourceTypeInfo* = ref object of DynamicData
    resourceType*: string
    vendorNamespaceInfo*: seq[PbmCapabilityVendorNamespaceInfo]

type
  PbmComplianceStatus* {.pure.} = enum
    compliant, nonCompliant, unknown, notApplicable, outOfDate
type
  PbmProfileDissociateOp* = ref object of PbmProfileChangeAssociationOp
    profile*: PbmProfileId

type
  PbmFaultProfileStorageFault* = ref object of PbmFault
  
type
  PbmCapabilitySubProfile* = ref object of DynamicData
    name*: string
    capability*: seq[PbmCapabilityInstance]
    forceProvision*: bool

type
  PbmReplicationManager* = ref object of vmodl.ManagedObject
  
type
  PbmProfile* = ref object of DynamicData
    profileId*: PbmProfileId
    name*: string
    description*: string
    creationTime*: string
    createdBy*: string
    lastUpdatedTime*: string
    lastUpdatedBy*: string

type
  PbmResourceInUse* = ref object of PbmFault
    type*: string
    name*: string

type
  PbmFaultInvalidLogin* = ref object of PbmFault
  
type
  PbmAlreadyExists* = ref object of PbmFault
    name*: string

type
  PbmCapabilityDiscreteSet* = ref object of DynamicData
    values*: seq[pointer]

type
  PbmPlacementSubject* = ref object of DynamicData
    subjectType*: string
    subjectId*: string

type
  PbmProfileType* = ref object of DynamicData
    uniqueId*: string

type
  PbmPlacementMatchingResources* = ref object of DynamicData
  
type
  PbmCanonicalPropertyValue* = ref object of DynamicData
    canonicalId*: PbmCanonicalPropertyId
    typeInfo*: PbmCapabilityTypeInfo
    value*: pointer
    fault*: MethodFault

type
  PbmCapabilitySchemaVendorInfo* = ref object of DynamicData
    vendorUuid*: string
    info*: PbmExtendedElementDescription

type
  PbmProfileProfileManager* = ref object of vmodl.ManagedObject
  
type
  PbmCapabilityPropertyMetadata* = ref object of DynamicData
    id*: string
    summary*: PbmExtendedElementDescription
    mandatory*: bool
    type*: PbmCapabilityTypeInfo
    defaultValue*: pointer
    allowedValue*: pointer
    requirementsTypeHint*: string

type
  PbmNonExistentHubs* = ref object of PbmFault
    hubs*: seq[PbmPlacementHub]

type
  PbmComplianceProviderInfo* = ref object of PbmProviderInfo
    metadata*: PbmAssociationMetadata
    provider*: PbmComplianceProvider

type
  PbmPlacementRequirement* = ref object of DynamicData
  
type
  PbmAssociationProviderRegistry* = ref object of vmodl.ManagedObject
  
type
  PbmLineOfServiceInfoLineOfServiceEnum* {.pure.} = enum
    INSPECTION, COMPRESSION, ENCRYPTION, REPLICATION, CACHING, PERSISTENCE,
    DATA_PROVIDER, DATASTORE_IO_CONTROL
type
  PbmCapabilityTimeUnitType* {.pure.} = enum
    SECONDS, MINUTES, HOURS, DAYS, WEEKS, MONTHS, YEARS
type
  PbmCapabilityNamespaceInfo* = ref object of DynamicData
    version*: string
    namespace*: string
    info*: PbmExtendedElementDescription

type
  PbmCapabilityDescription* = ref object of DynamicData
    description*: PbmExtendedElementDescription
    value*: pointer

type
  PbmCapabilityPropertyInstance* = ref object of DynamicData
    id*: string
    operator*: string
    value*: pointer

type
  PbmProfileFcdDetachOp* = ref object of PbmProfileDissociateOp
    vmDiskKey*: seq[PbmServerObjectRef]

type
  PbmAtomFeedProvider* = ref object of pbm.provider.Provider
  
type
  PmemPolicyInfo* = ref object of DynamicData
    profileId*: PbmProfileId
    pmemPolicy*: bool
    fault*: MethodFault

type
  PbmCapabilityRange* = ref object of DynamicData
    min*: pointer
    max*: pointer

type
  PbmProfileResourceType* = ref object of DynamicData
    resourceType*: string

type
  PbmPolicyAssociation* = ref object of DynamicData
    entity*: PbmServerObjectRef
    policySpec*: VirtualMachineProfileSpec
    defaultPolicy*: bool
    hub*: PbmPlacementHub

type
  PbmCanonicalPropertyId* = ref object of DynamicData
    distinguishedId*: string

type
  PbmSessionManager* = ref object of vmodl.ManagedObject
  
type
  PbmCapabilityTypeInfo* = ref object of DynamicData
    typeName*: string

type
  PbmCapabilityMetadataPerCategory* = ref object of DynamicData
    subCategory*: string
    capabilityMetadata*: seq[PbmCapabilityMetadata]

type
  PbmPlacementCapabilityProfileRequirement* = ref object of PbmPlacementRequirement
    profileId*: PbmProfileId

type
  PbmPlacementCapabilityConstraintsRequirement* = ref object of PbmPlacementRequirement
    constraints*: PbmCapabilityConstraints

type
  PbmIofilterInfoFilterType* {.pure.} = enum
    INSPECTION, COMPRESSION, ENCRYPTION, REPLICATION, CACHE, DATAPROVIDER,
    DATASTOREIOCONTROL
type
  PbmPlacementHubFinderRegistry* = ref object of vmodl.ManagedObject
  
type
  PbmPlacementHubFinder* = ref object of pbm.provider.Provider
  
type
  PbmPropertyMismatchFault* = ref object of PbmCompatibilityCheckFault
    capabilityInstanceId*: PbmCapabilityMetadataUniqueId
    requirementPropertyInstance*: PbmCapabilityPropertyInstance

type
  PbmProfileToIofilterMap* = ref object of DynamicData
    key*: PbmProfileId
    iofilters*: seq[PbmIofilterInfo]
    fault*: MethodFault

type
  PbmVaioDataServiceInfo* = ref object of PbmLineOfServiceInfo
  
type
  PbmOperation* {.pure.} = enum
    CREATE, REGISTER, RECONFIGURE, MIGRATE, CLONE
type
  PbmComplianceManager* = ref object of vmodl.ManagedObject
  
type
  PbmAtomFeedQsProviderTye* {.pure.} = enum
    ASSOCIATION, COMPLIANCE, CAPABILITY_METADATA, CAPABILITY_PROFILE,
    REQUIREMENTS_PROFILE
type
  PbmAboutInfo* = ref object of DynamicData
    name*: string
    version*: string
    instanceUuid*: string

type
  PbmProfileResourceTypeEnum* {.pure.} = enum
    STORAGE
type
  PbmProfileId* = ref object of DynamicData
    uniqueId*: string

type
  PbmProfileChangeAssociationOp* = ref object of DynamicData
    entity*: PbmServerObjectRef

type
  PbmPlacementResourceUtilization* = ref object of DynamicData
    name*: PbmExtendedElementDescription
    description*: PbmExtendedElementDescription
    availableBefore*: int64
    availableAfter*: int64
    total*: int64

type
  PbmBuiltinType* {.pure.} = enum
    XSD_LONG, XSD_SHORT, XSD_INTEGER, XSD_INT, XSD_STRING, XSD_BOOLEAN, XSD_DOUBLE,
    XSD_DATETIME, VMW_TIMESPAN, VMW_POLICY
type
  PbmServerObjectRef* = ref object of DynamicData
    objectType*: string
    key*: string
    serverUuid*: string

type
  PbmCapabilityOperator* {.pure.} = enum
    NOT
type
  PbmCapabilitySubProfileWithCandidates* = ref object of PbmCapabilitySubProfile
    candidateHubs*: seq[PbmPlacementHub]

type
  PbmVvolType* {.pure.} = enum
    Config, Data, Swap
type
  PbmPersistenceBasedDataServiceInfo* = ref object of PbmLineOfServiceInfo
    compatiblePersistenceSchemaNamespace*: seq[string]

type
  PbmQueryReplicationGroupResult* = ref object of DynamicData
    object*: PbmServerObjectRef
    replicationGroupId*: ReplicationGroupId
    fault*: MethodFault

type
  PbmLineOfServiceInfo* = ref object of DynamicData
    lineOfService*: string
    name*: PbmExtendedElementDescription
    description*: PbmExtendedElementDescription

type
  PbmIofilterInfo* = ref object of DynamicData
    vibId*: string
    filterType*: string

type
  PbmQueryProfileResult* = ref object of DynamicData
    object*: PbmServerObjectRef
    profileId*: seq[PbmProfileId]
    fault*: MethodFault

type
  PbmDataServiceToPoliciesMap* = ref object of DynamicData
    dataServicePolicy*: PbmProfileId
    parentStoragePolicies*: seq[PbmProfileId]
    fault*: MethodFault

type
  PbmPlacementHubInfo* = ref object of DynamicData
    hub*: PbmPlacementHub
    hubType*: string

type
  PbmCapabilitySubProfileConstraints* = ref object of PbmCapabilityConstraints
    subProfiles*: seq[PbmCapabilitySubProfile]

type
  PbmCapabilityProfileUpdateSpec* = ref object of DynamicData
    name*: string
    description*: string
    constraints*: PbmCapabilityConstraints

type
  PbmPlacementCompatibilityResult* = ref object of DynamicData
    hub*: PbmPlacementHub
    matchingResources*: seq[PbmPlacementMatchingResources]
    howMany*: int64
    utilization*: seq[PbmPlacementResourceUtilization]
    warning*: seq[MethodFault]
    error*: seq[MethodFault]

type
  PbmCapabilityInstance* = ref object of DynamicData
    id*: PbmCapabilityMetadataUniqueId
    constraint*: seq[PbmCapabilityConstraintInstance]

type
  PbmPlacementSolution* = ref object of DynamicData
    subjectAssignment*: seq[PbmPlacementSubjectAssignment]
    cost*: seq[PbmPlacementHubSelectionInfo]

type
  PbmProfileApplyOutcome* = ref object of DynamicData
    profileId*: PbmProfileId
    reconfigOutcome*: seq[PbmProfileReconfigOutcome]
    fault*: MethodFault

type
  PbmPlacementHub* = ref object of DynamicData
    hubType*: string
    hubId*: string
