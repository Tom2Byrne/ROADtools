from roadtools.roadlib.metadef.basetypes import Edm, Collection
from roadtools.roadlib.metadef.complextypes_ibiza import *

class DirectoryObject(object):
    props = {
        'objectType': Edm.String,
        'objectId': Edm.String,
        'deletionTimestamp': Edm.DateTime,
    }
    rels = [
        'createdOnBehalfOf',
        'createdObjects',
        'manager',
        'directReports',
        'members',
        'transitiveMembers',
        'memberOf',
        'transitiveMemberOf',
        'owners',
        'ownedObjects',
    ]



# class ConditionalAccessPolicy(DirectoryObject):
#     props = {
#         'definition': Collection,
#         'displayName': Edm.String,
#         'isOrganizationDefault': Edm.Boolean,
#         'policyIdentifier': Edm.String,
#     }
#     rels = [
#         'appliesTo',
#     ]


class Group(DirectoryObject):
    props = {
        'objectId': Edm.String,
        'groupId': Edm.String,
        'objectType': Edm.String,
        'displayName': Edm.String,
        'name': Edm.String,
        'description': Edm.String,
        'mail': Edm.String,
        'mailNickname': Edm.String,
        'source': Edm.String,
        'deletionTimestamp': Edm.DateTime,
        'permanentdeletionTimestamp': Edm.DateTime,
        'ownerDisplayNames': Edm.Object,
        'groupTypeDisplayName': Edm.String,
        'membershipType': Edm.String,
        'externalSource': Edm.String,
        'customAttributes': Edm.Object,
        'dirSyncEnabled': Edm.Boolean,
        'lastDirSyncTime': Edm.DateTime,
        'selectedUserIds': Edm.Object,
        'dynamicGroupProperties': Edm.Object,
        'groupType': Edm.String,
        'isExternallyManaged': Edm.Boolean,
        'imageUrl': Edm.String,
        'userType': Edm.String,
        'thumbnailPhotoMediaContentType': Edm.String,
        'hasThumbnail': Edm.Boolean,
        'isUser': Edm.Boolean,
        'isGroup': Edm.Boolean,
        'isGuest': Edm.Boolean,
        'membershipResourceType': Edm.String,
        'membershipRuleType': Edm.String,
        'isDynamic': Edm.Boolean,
        'membershipRule': Edm.String,
        'membershipRuleProcessingState': Edm.String,
        'membershipProcessingStatus': Edm.String,
        'membershipProcessingError': Edm.String,
        'lastMembershipUpdateTime': Edm.DateTime,
        'lastRefreshTime': Edm.DateTime,
    }
    rels = [
        'allowAccessTo',
        'appRoleAssignments',
        'cloudPublicDelegates',
        'eligibleMemberOf',
        'hasAccessTo',
        'managedBy',
        'pendingMembers',
        'scopedAdministratorOf',
        'securedExternalData',
        'settings',
        'endpoints',
    ]




class Policy(DirectoryObject):
    props = {
        'displayName': Edm.String,
        'usersV2': usersV2,
        'templateId': Edm.String,
        'servicePrincipals': Edm.Object,
        'controls': Edm.Object,
        'sessionControls': Edm.Object,
        'conditions': Edm.Object,
        'clientApplications': Edm.Object,
        'clientApps': Edm.Object,
        'clientAppsV2': Edm.Object,
        'deviceState': Edm.Object,
        'namedNetworks': Edm.Object,
        'locations': Edm.Object,
        'time': Edm.Object,
        'signInRiskDetections': Edm.Object,
        'minUserRisk': Edm.Object,
        'minSigninRisk': Edm.Object,
        'servicePrincipalRiskLevels': Edm.Object,
        'isAllProtocolsEnabled': Edm.Boolean,
        'isUsersGroupsV2Enabled': Edm.Boolean,
        'version': Edm.Int32,
        'isFallbackUsed': Edm.Boolean,
        'applyRule': Edm.Boolean,
        'usePolicyState': Edm.Boolean,
        'baselineType': Edm.Int32,
        'policyId': Edm.String,
        'policyName': Edm.String,
        'policyState': Edm.Int32,
        'createdDateTime': Edm.DateTime,
        'modifiedDateTime': Edm.DateTime,
    }

class ServicePrincipal(DirectoryObject):
    props = {
        'objectId': Edm.String,
        'appId': Edm.String,
        'displayName': Edm.String,
        'homePageUrl': Edm.String,
        'appDisplayName': Edm.String,
        'microsoftFirstParty': Edm.Boolean,  
        'logo45Url': Edm.String,
        'ssoConfiguration': Edm.Object,
        'appRoles': Collection,
        'publisherName': Edm.String,
        'tags': Collection,
        'accountEnabled': Edm.Boolean,
        'isSyncInbound': Edm.Boolean,
        'replyUrls': Collection,
        'publisherDisplayName': Edm.String,
        'appType': Edm.Int32
    }

class TenantDetail(DirectoryObject):
    props = {
        'assignedPlans': Collection,
        'authorizedServiceInstance': Collection,
        'city': Edm.String,
        'cloudRtcUserPolicies': Edm.String,
        'companyLastDirSyncTime': Edm.DateTime,
        'companyTags': Collection,
        'compassEnabled': Edm.Boolean,
        'country': Edm.String,
        'countryLetterCode': Edm.String,
        'dirSyncEnabled': Edm.Boolean,
        'displayName': Edm.String,
        'isMultipleDataLocationsForServicesEnabled': Edm.Boolean,
        'marketingNotificationEmails': Collection,
        'postalCode': Edm.String,
        'preferredLanguage': Edm.String,
        'privacyProfile': PrivacyProfile,
        'provisionedPlans': Collection,
        'provisioningErrors': Collection,
        'releaseTrack': Edm.String,
        'replicationScope': Edm.String,
        'securityComplianceNotificationMails': Collection,
        'securityComplianceNotificationPhones': Collection,
        'selfServePasswordResetPolicy': SelfServePasswordResetPolicy,
        'state': Edm.String,
        'street': Edm.String,
        'technicalNotificationMails': Collection,
        'telephoneNumber': Edm.String,
        'tenantType': Edm.String,
        'createdDateTime': Edm.DateTime,
        'verifiedDomains': Collection,
        'windowsCredentialsEncryptionCertificate': Edm.Binary,
    }
    rels = [
        'serviceInfo',
        'trustedCAsForPasswordlessAuth',
    ]



class User(DirectoryObject):
    props = {
        'objectId': Edm.String,
        'objectType': Edm.String,
        'displayName': Edm.String,
        'userPrincipalName': Edm.String,
        'thumbnailPhotoMediaContentType': Edm.String,
        'givenName': Edm.String,
        'surname': Edm.String,
        'mail': Edm.String,
        'dirSyncEnabled': Edm.Boolean,
        'alternativeSecurityIds': Edm.Object,
        'signInNamesInfo': Edm.Object,
        'signInNames': Edm.Object,
        'ownedDevices': Edm.Object,
        'jobTitle': Edm.String,
        'department': Edm.String,
        'displayUserPrincipalName': Edm.String,
        'hasThumbnail': Edm.Boolean,
        'imageUrl': Edm.String,
        'imageDataToUpload': Edm.String,
        'source': Edm.String,
        'sources': Edm.Object,
        'sourceText': Edm.String,
        'userFlags': Edm.String,
        'deletionTimestamp': Edm.String,
        'permanentDeletionTime': Edm.String,
        'alternateEmailAddress': Edm.String,
        'manager': Edm.String,
        'userType': Edm.String,
        'isThumbnailUpdated': Edm.Boolean,
        'isAuthenticationContactInfoUpdated': Edm.Boolean,
        'searchableDeviceKey': Edm.Object,
        'displayEmail': Edm.String,
        'creationType': Edm.String,
        'userState': Edm.String,
        'otherMails': Edm.Object,
        'invitedAsMail': Edm.String,
        'proxyAddresses': Edm.Object,
        'companyName': Edm.String,
        'employeeId': Edm.String,

        # MFA-related properties
        # 'isAdmin': Edm.Boolean,
        # 'isMfaCapable': Edm.Boolean,
        # 'isMfaRegistered': Edm.Boolean,
        # 'isPasswordlessCapable': Edm.Boolean,
        # 'isSsprCapable': Edm.Boolean,
        # 'isSsprEnabled': Edm.Boolean,
        # 'isSsprRegistered': Edm.Boolean,
        # 'isSystemPreferredAuthenticationMethodEnabled': Edm.Boolean,
        # 'lastUpdatedDate': Edm.DateTime,
        # 'methodsRegistered': Edm.Object,
        # 'systemPreferredAuthenticationMethods': Edm.Object,
        # 'userDisplayName': Edm.String,
        # 'userPreferredMethodForSecondaryAuthentication': Edm.String,
    
    }
    rels = [
        
    ]

