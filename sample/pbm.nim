
type
  PbmCapabilityOperator* {.pure.} = enum
    NOT
type
  PbmProfileCategoryEnum* {.pure.} = enum
    REQUIREMENT, RESOURCE, DATA_SERVICE_POLICY
type
  PbmBuiltinGenericType* {.pure.} = enum
    VMW_RANGE, VMW_SET
type
  PbmVvolType* {.pure.} = enum
    Config, Data, Swap
type
  PbmVmOperation* {.pure.} = enum
    CREATE, RECONFIGURE, MIGRATE, CLONE
type
  PbmLineOfServiceInfoLineOfServiceEnum* {.pure.} = enum
    INSPECTION, COMPRESSION, ENCRYPTION, REPLICATION, CACHING, PERSISTENCE,
    DATA_PROVIDER, DATASTORE_IO_CONTROL
type
  PbmIofilterInfoFilterType* {.pure.} = enum
    INSPECTION, COMPRESSION, ENCRYPTION, REPLICATION, CACHE, DATAPROVIDER,
    DATASTOREIOCONTROL
type
  PbmCapabilityTimeUnitType* {.pure.} = enum
    SECONDS, MINUTES, HOURS, DAYS, WEEKS, MONTHS, YEARS
type
  PbmOperation* {.pure.} = enum
    CREATE, REGISTER, RECONFIGURE, MIGRATE, CLONE
type
  PbmAtomFeedQsProviderTye* {.pure.} = enum
    ASSOCIATION, COMPLIANCE, CAPABILITY_METADATA, CAPABILITY_PROFILE,
    REQUIREMENTS_PROFILE
type
  PbmProfileResourceTypeEnum* {.pure.} = enum
    STORAGE
type
  PbmComplianceStatus* {.pure.} = enum
    compliant, nonCompliant, unknown, notApplicable, outOfDate
type
  PbmComplianceResultComplianceTaskStatus* {.pure.} = enum
    inProgress, success, failed
type
  PbmBuiltinType* {.pure.} = enum
    XSD_LONG, XSD_SHORT, XSD_INTEGER, XSD_INT, XSD_STRING, XSD_BOOLEAN, XSD_DOUBLE,
    XSD_DATETIME, VMW_TIMESPAN, VMW_POLICY
type
  PbmSystemCreatedProfileType* {.pure.} = enum
    VsanDefaultProfile, VVolDefaultProfile, PmemDefaultProfile,
    VmcManagementProfile
type
  PbmObjectType* {.pure.} = enum
    virtualMachine, virtualMachineAndDisks, virtualDiskId, virtualDiskUUID,
    datastore, host, cluster, unknown
type
    PbmAssociatedPolicyCapabilities = object of DynamicData
    PbmIncompatibleVendorSpecificRuleSet = object of PbmCapabilityProfilePropertyMismatchFault
    PbmDefaultCapabilityProfile = object of PbmCapabilityProfile
    PbmDefaultProfileAppliesFault = object of PbmCompatibilityCheckFault
    PbmComplianceOperationalStatus = object of DynamicData
    PbmExtendedElementDescription = object of DynamicData
    PbmCapabilityProviderInfo = object of DynamicData
    PbmEntityAssociations = object of DynamicData
    PbmRollupComplianceResult = object of DynamicData
    PbmCapabilityMetadata = object of DynamicData
    PbmFaultNotFound = object of PbmFault
    PbmProviderInfo = object of DynamicData
    PbmCompliancePolicyStatus = object of DynamicData
    PbmCapabilityProfilePropertyMismatchFault = object of PbmPropertyMismatchFault
    PbmProfileQueryProfileResultInternal = object of PbmQueryProfileResult
    PbmAssociationProviderInfo = object of PbmProviderInfo
    PbmAssociatedPolicyCapabilitiesResult = object of DynamicData
    PbmProfileProviderInfo = object of PbmProviderInfo
    PbmAssociationMetadata = object of DynamicData
    PbmCapabilityConstraints = object of DynamicData
    PbmDuplicateName = object of PbmFault
    PbmDefaultProfileInfo = object of DynamicData
    PbmCapabilityProfile = object of PbmProfile
    PbmCapabilitySchema = object of DynamicData
    PbmCapabilityMetadataUniqueId = object of DynamicData
    PbmCapabilityGenericTypeInfo = object of PbmCapabilityTypeInfo
    PbmProfileDefaultProfileAssociateOp = object of PbmProfileAssociateOp
    PbmLegacyHubsNotSupported = object of PbmFault
    PbmPlacementHubFinderInfo = object of PbmProviderInfo
    PbmProfileOperationOutcome = object of DynamicData
    PbmPlacementHubSelectionInfo = object of DynamicData
    PbmFault = object of MethodFault
    PbmVmAssociations = object of DynamicData
    PbmPlacementSubjectAssignment = object of DynamicData
    PbmCapabilityMetadataInfo = object of DynamicData
    PbmDatastoreSpaceStatistics = object of DynamicData
    PbmPlacementHubCapacityInfo = object of DynamicData
    PbmProfileFcdDeleteOp = object of PbmProfileDissociateOp
    PbmCapabilityProfileCreateSpec = object of DynamicData
    PbmResourceAssociation = object of DynamicData
    PbmCapabilityTimeSpan = object of DynamicData
    PbmServiceInstanceContent = object of DynamicData
    PbmComplianceResult = object of DynamicData
    PbmCapabilityVendorNamespaceInfo = object of DynamicData
    PbmProfileAssociateOp = object of PbmProfileChangeAssociationOp
    PbmCapabilityConstraintInstance = object of DynamicData
    PbmCompatibilityCheckFault = object of PbmFault
    PbmPlacementMatchingReplicationResources = object of PbmPlacementMatchingResources
    PbmProfileReconfigOutcome = object of DynamicData
    PbmCapabilityVendorResourceTypeInfo = object of DynamicData
    PbmProfileDissociateOp = object of PbmProfileChangeAssociationOp
    PbmFaultProfileStorageFault = object of PbmFault
    PbmCapabilitySubProfile = object of DynamicData
    PbmProfile = object of DynamicData
    PbmResourceInUse = object of PbmFault
    PbmFaultInvalidLogin = object of PbmFault
    PbmAlreadyExists = object of PbmFault
    PbmCapabilityDiscreteSet = object of DynamicData
    PbmPlacementSubject = object of DynamicData
    PbmProfileType = object of DynamicData
    PbmPlacementMatchingResources = object of DynamicData
    PbmCanonicalPropertyValue = object of DynamicData
    PbmCapabilitySchemaVendorInfo = object of DynamicData
    PbmCapabilityPropertyMetadata = object of DynamicData
    PbmNonExistentHubs = object of PbmFault
    PbmComplianceProviderInfo = object of PbmProviderInfo
    PbmPlacementRequirement = object of DynamicData
    PbmCapabilityNamespaceInfo = object of DynamicData
    PbmCapabilityDescription = object of DynamicData
    PbmCapabilityPropertyInstance = object of DynamicData
    PbmProfileFcdDetachOp = object of PbmProfileDissociateOp
    PmemPolicyInfo = object of DynamicData
    PbmCapabilityRange = object of DynamicData
    PbmProfileResourceType = object of DynamicData
    PbmPolicyAssociation = object of DynamicData
    PbmCanonicalPropertyId = object of DynamicData
    PbmCapabilityTypeInfo = object of DynamicData
    PbmCapabilityMetadataPerCategory = object of DynamicData
    PbmPlacementCapabilityProfileRequirement = object of PbmPlacementRequirement
    PbmPlacementCapabilityConstraintsRequirement = object of PbmPlacementRequirement
    PbmPropertyMismatchFault = object of PbmCompatibilityCheckFault
    PbmProfileToIofilterMap = object of DynamicData
    PbmVaioDataServiceInfo = object of PbmLineOfServiceInfo
    PbmAboutInfo = object of DynamicData
    PbmProfileId = object of DynamicData
    PbmProfileChangeAssociationOp = object of DynamicData
    PbmPlacementResourceUtilization = object of DynamicData
    PbmServerObjectRef = object of DynamicData
    PbmCapabilitySubProfileWithCandidates = object of PbmCapabilitySubProfile
    PbmPersistenceBasedDataServiceInfo = object of PbmLineOfServiceInfo
    PbmQueryReplicationGroupResult = object of DynamicData
    PbmLineOfServiceInfo = object of DynamicData
    PbmIofilterInfo = object of DynamicData
    PbmQueryProfileResult = object of DynamicData
    PbmDataServiceToPoliciesMap = object of DynamicData
    PbmPlacementHubInfo = object of DynamicData
    PbmCapabilitySubProfileConstraints = object of PbmCapabilityConstraints
    PbmCapabilityProfileUpdateSpec = object of DynamicData
    PbmPlacementCompatibilityResult = object of DynamicData
    PbmCapabilityInstance = object of DynamicData
    PbmPlacementSolution = object of DynamicData
    PbmProfileApplyOutcome = object of DynamicData
    PbmPlacementHub = object of DynamicData
type
    PbmComplianceProviderRegistry = object of ManagedObject
    
    PbmComplianceProvider = object of PbmProvider
    
    PbmServiceInstance = object of ManagedObject
      content*: PbmServiceInstanceContent

    PbmAssociationProvider = object of PbmProvider
    
    PbmComplianceManager = object of ManagedObject
    
    PbmProfileProvider = object of PbmProvider
    
    PbmSessionManager = object of ManagedObject
    
    PbmPlacementSolver = object of ManagedObject
    
    PbmTask = object of ManagedObject
    
    PbmCapabilityMetadataManager = object of ManagedObject
    
    PbmReplicationManager = object of ManagedObject
    
    PbmAssociationProviderRegistry = object of ManagedObject
    
    PbmProfileProviderRegistry = object of ManagedObject
    
    PbmAtomFeedProvider = object of PbmProvider
    
    PbmDebugManager = object of ManagedObject
    
    PbmPlacementHubFinderRegistry = object of ManagedObject
    
    PbmProvider = object of ManagedObject
    
    PbmPlacementHubFinder = object of PbmProvider
    
    PbmProfileProfileManager = object of ManagedObject
    