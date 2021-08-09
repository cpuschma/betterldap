package betterldap

const (
	ApplicationBindRequest           = 0
	ApplicationBindResponse          = 1
	ApplicationUnbindRequest         = 2
	ApplicationSearchRequest         = 3
	ApplicationSearchResultEntry     = 4
	ApplicationSearchResultDone      = 5
	ApplicationModifyRequest         = 6
	ApplicationModifyResponse        = 7
	ApplicationAddRequest            = 8
	ApplicationAddResponse           = 9
	ApplicationDelRequest            = 10
	ApplicationDelResponse           = 11
	ApplicationModifyDNRequest       = 12
	ApplicationModifyDNResponse      = 13
	ApplicationCompareRequest        = 14
	ApplicationCompareResponse       = 15
	ApplicationAbandonRequest        = 16
	ApplicationSearchResultReference = 19
	ApplicationExtendedRequest       = 23
	ApplicationExtendedResponse      = 24

	// https://datatracker.ietf.org/doc/html/rfc4511#section-4.1.9
	LDAPResultSuccess                      = 0
	LDAPResultOperationsError              = 1
	LDAPResultProtocolError                = 2
	LDAPResultTimeLimitExceeded            = 3
	LDAPResultSizeLimitExceeded            = 4
	LDAPResultCompareFalse                 = 5
	LDAPResultCompareTrue                  = 6
	LDAPResultAuthMethodNotSupported       = 7
	LDAPResultStrongerAuthRequired         = 8
	LDAPResultReferral                     = 10
	LDAPResultAdminLimitExceeded           = 11
	LDAPResultUnavailableCriticalExtension = 12
	LDAPResultConfidentialityRequired      = 13
	LDAPResultSaslBindInProgress           = 14
	LDAPResultNoSuchAttribute              = 16
	LDAPResultUndefinedAttributeType       = 17
	LDAPResultInappropriateMatching        = 18
	LDAPResultConstraintViolation          = 19
	LDAPResultAttributeOrValueExists       = 20
	LDAPResultInvalidAttributeSyntax       = 21
	LDAPResultNoSuchObject                 = 32
	LDAPResultAliasProblem                 = 33
	LDAPResultInvalidDNSyntax              = 34
	LDAPResultAliasDereferencingProblem    = 36
	LDAPResultInappropriateAuthentication  = 48
	LDAPResultInvalidCredentials           = 49
	LDAPResultInsufficientAccessRights     = 50
	LDAPResultBusy                         = 51
	LDAPResultUnavailable                  = 52
	LDAPResultUnwillingToPerform           = 53
	LDAPResultLoopDetect                   = 54
	LDAPResultNamingViolation              = 64
	LDAPResultObjectClassViolation         = 65
	LDAPResultNotAllowedOnNonLeaf          = 66
	LDAPResultNotAllowedOnRDN              = 67
	LDAPResultEntryAlreadyExists           = 68
	LDAPResultObjectClassModsProhibited    = 69
	LDAPResultAffectsMultipleDSAs          = 71

	// LDAP Behera Password Policy Draft 10  = https://tools.ietf.org/html/draft-behera-ldap-password-policy-10)
	BeheraPasswordExpired             = 0
	BeheraAccountLocked               = 1
	BeheraChangeAfterReset            = 2
	BeheraPasswordModNotAllowed       = 3
	BeheraMustSupplyOldPassword       = 4
	BeheraInsufficientPasswordQuality = 5
	BeheraPasswordTooShort            = 6
	BeheraPasswordTooYoung            = 7
	BeheraPasswordInHistory           = 8

	// https://datatracker.ietf.org/doc/html/rfc4511#section-4.5.1
	ScopeBaseObject   = 0
	ScopeSingleLevel  = 1
	ScopeWholeSubtree = 2

	NeverDerefAliases   = 0
	DerefInSearching    = 1
	DerefFindingBaseObj = 2
	DerefAlways         = 3

	// Filter
	FilterAnd             = 0
	FilterOr              = 1
	FilterNot             = 2
	FilterEqualityMatch   = 3
	FilterSubstrings      = 4
	FilterGreaterOrEqual  = 5
	FilterLessOrEqual     = 6
	FilterPresent         = 7
	FilterApproxMatch     = 8
	FilterExtensibleMatch = 9

	FilterSubstringsInitial = 0
	FilterSubstringsAny     = 1
	FilterSubstringsFinal   = 2

	MatchingRuleAssertionMatchingRule = 1
	MatchingRuleAssertionType         = 2
	MatchingRuleAssertionMatchValue   = 3
	MatchingRuleAssertionDNAttributes = 4

	// ControlTypePaging - https://www.ietf.org/rfc/rfc2696.txt
	ControlTypePaging = "1.2.840.113556.1.4.319"
	// ControlTypeBeheraPasswordPolicy - https://tools.ietf.org/html/draft-behera-ldap-password-policy-10
	ControlTypeBeheraPasswordPolicy = "1.3.6.1.4.1.42.2.27.8.5.1"
	// ControlTypeVChuPasswordMustChange - https://tools.ietf.org/html/draft-vchu-ldap-pwd-policy-00
	ControlTypeVChuPasswordMustChange = "2.16.840.1.113730.3.4.4"
	// ControlTypeVChuPasswordWarning - https://tools.ietf.org/html/draft-vchu-ldap-pwd-policy-00
	ControlTypeVChuPasswordWarning = "2.16.840.1.113730.3.4.5"
	// ControlTypeManageDsaIT - https://tools.ietf.org/html/rfc3296
	ControlTypeManageDsaIT = "2.16.840.1.113730.3.4.2"
	// ControlTypeWhoAmI - https://tools.ietf.org/html/rfc4532
	ControlTypeWhoAmI = "1.3.6.1.4.1.4203.1.11.3"

	// ControlTypeMicrosoftNotification - https://msdn.microsoft.com/en-us/library/aa366983(v=vs.85).aspx
	ControlTypeMicrosoftNotification = "1.2.840.113556.1.4.528"
	// ControlTypeMicrosoftShowDeleted - https://msdn.microsoft.com/en-us/library/aa366989(v=vs.85).aspx
	ControlTypeMicrosoftShowDeleted = "1.2.840.113556.1.4.417"
	// ControlTypeMicrosoftServerLinkTTL - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/f4f523a8-abc0-4b3a-a471-6b2fef135481?redirectedfrom=MSDN
	ControlTypeMicrosoftServerLinkTTL = "1.2.840.113556.1.4.2309"
)
