// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The constants in this file were extracted mechanically from
// doc/rfc7863-nfs42.x (the NFSv4.2 XDR description from RFC 7863) plus the
// RFC 8276 extended attribute operations, then renamed to Go style.

package nfsv4

// NFSv4 status codes (nfsstat4).
const (
	OK                       Status = 0     // NFS4_OK
	ErrPerm                  Status = 1     // NFS4ERR_PERM
	ErrNoEnt                 Status = 2     // NFS4ERR_NOENT
	ErrIO                    Status = 5     // NFS4ERR_IO
	ErrNXIO                  Status = 6     // NFS4ERR_NXIO
	ErrAccess                Status = 13    // NFS4ERR_ACCESS
	ErrExist                 Status = 17    // NFS4ERR_EXIST
	ErrXDev                  Status = 18    // NFS4ERR_XDEV
	ErrNotDir                Status = 20    // NFS4ERR_NOTDIR
	ErrIsDir                 Status = 21    // NFS4ERR_ISDIR
	ErrInval                 Status = 22    // NFS4ERR_INVAL
	ErrFBig                  Status = 27    // NFS4ERR_FBIG
	ErrNoSpc                 Status = 28    // NFS4ERR_NOSPC
	ErrROFS                  Status = 30    // NFS4ERR_ROFS
	ErrMLink                 Status = 31    // NFS4ERR_MLINK
	ErrNameTooLong           Status = 63    // NFS4ERR_NAMETOOLONG
	ErrNotEmpty              Status = 66    // NFS4ERR_NOTEMPTY
	ErrDQuot                 Status = 69    // NFS4ERR_DQUOT
	ErrStale                 Status = 70    // NFS4ERR_STALE
	ErrBadHandle             Status = 10001 // NFS4ERR_BADHANDLE
	ErrBadCookie             Status = 10003 // NFS4ERR_BAD_COOKIE
	ErrNotSupp               Status = 10004 // NFS4ERR_NOTSUPP
	ErrTooSmall              Status = 10005 // NFS4ERR_TOOSMALL
	ErrServerFault           Status = 10006 // NFS4ERR_SERVERFAULT
	ErrBadType               Status = 10007 // NFS4ERR_BADTYPE
	ErrDelay                 Status = 10008 // NFS4ERR_DELAY
	ErrSame                  Status = 10009 // NFS4ERR_SAME
	ErrDenied                Status = 10010 // NFS4ERR_DENIED
	ErrExpired               Status = 10011 // NFS4ERR_EXPIRED
	ErrLocked                Status = 10012 // NFS4ERR_LOCKED
	ErrGrace                 Status = 10013 // NFS4ERR_GRACE
	ErrFHExpired             Status = 10014 // NFS4ERR_FHEXPIRED
	ErrShareDenied           Status = 10015 // NFS4ERR_SHARE_DENIED
	ErrWrongSec              Status = 10016 // NFS4ERR_WRONGSEC
	ErrClidInUse             Status = 10017 // NFS4ERR_CLID_INUSE
	ErrResource              Status = 10018 // NFS4ERR_RESOURCE
	ErrMoved                 Status = 10019 // NFS4ERR_MOVED
	ErrNoFileHandle          Status = 10020 // NFS4ERR_NOFILEHANDLE
	ErrMinorVersMismatch     Status = 10021 // NFS4ERR_MINOR_VERS_MISMATCH
	ErrStaleClientID         Status = 10022 // NFS4ERR_STALE_CLIENTID
	ErrStaleStateID          Status = 10023 // NFS4ERR_STALE_STATEID
	ErrOldStateID            Status = 10024 // NFS4ERR_OLD_STATEID
	ErrBadStateID            Status = 10025 // NFS4ERR_BAD_STATEID
	ErrBadSeqID              Status = 10026 // NFS4ERR_BAD_SEQID
	ErrNotSame               Status = 10027 // NFS4ERR_NOT_SAME
	ErrLockRange             Status = 10028 // NFS4ERR_LOCK_RANGE
	ErrSymlink               Status = 10029 // NFS4ERR_SYMLINK
	ErrRestoreFH             Status = 10030 // NFS4ERR_RESTOREFH
	ErrLeaseMoved            Status = 10031 // NFS4ERR_LEASE_MOVED
	ErrAttrNotSupp           Status = 10032 // NFS4ERR_ATTRNOTSUPP
	ErrNoGrace               Status = 10033 // NFS4ERR_NO_GRACE
	ErrReclaimBad            Status = 10034 // NFS4ERR_RECLAIM_BAD
	ErrReclaimConflict       Status = 10035 // NFS4ERR_RECLAIM_CONFLICT
	ErrBadXDR                Status = 10036 // NFS4ERR_BADXDR
	ErrLocksHeld             Status = 10037 // NFS4ERR_LOCKS_HELD
	ErrOpenMode              Status = 10038 // NFS4ERR_OPENMODE
	ErrBadOwner              Status = 10039 // NFS4ERR_BADOWNER
	ErrBadChar               Status = 10040 // NFS4ERR_BADCHAR
	ErrBadName               Status = 10041 // NFS4ERR_BADNAME
	ErrBadRange              Status = 10042 // NFS4ERR_BAD_RANGE
	ErrLockNotSupp           Status = 10043 // NFS4ERR_LOCK_NOTSUPP
	ErrOpIllegal             Status = 10044 // NFS4ERR_OP_ILLEGAL
	ErrDeadlock              Status = 10045 // NFS4ERR_DEADLOCK
	ErrFileOpen              Status = 10046 // NFS4ERR_FILE_OPEN
	ErrAdminRevoked          Status = 10047 // NFS4ERR_ADMIN_REVOKED
	ErrCBPathDown            Status = 10048 // NFS4ERR_CB_PATH_DOWN
	ErrBadIOMode             Status = 10049 // NFS4ERR_BADIOMODE
	ErrBadLayout             Status = 10050 // NFS4ERR_BADLAYOUT
	ErrBadSessionDigest      Status = 10051 // NFS4ERR_BAD_SESSION_DIGEST
	ErrBadSession            Status = 10052 // NFS4ERR_BADSESSION
	ErrBadSlot               Status = 10053 // NFS4ERR_BADSLOT
	ErrCompleteAlready       Status = 10054 // NFS4ERR_COMPLETE_ALREADY
	ErrConnNotBoundToSession Status = 10055 // NFS4ERR_CONN_NOT_BOUND_TO_SESSION
	ErrDelegAlreadyWanted    Status = 10056 // NFS4ERR_DELEG_ALREADY_WANTED
	ErrBackChanBusy          Status = 10057 // NFS4ERR_BACK_CHAN_BUSY
	ErrLayoutTryLater        Status = 10058 // NFS4ERR_LAYOUTTRYLATER
	ErrLayoutUnavailable     Status = 10059 // NFS4ERR_LAYOUTUNAVAILABLE
	ErrNoMatchingLayout      Status = 10060 // NFS4ERR_NOMATCHING_LAYOUT
	ErrRecallConflict        Status = 10061 // NFS4ERR_RECALLCONFLICT
	ErrUnknownLayoutType     Status = 10062 // NFS4ERR_UNKNOWN_LAYOUTTYPE
	ErrSeqMisordered         Status = 10063 // NFS4ERR_SEQ_MISORDERED
	ErrSequencePos           Status = 10064 // NFS4ERR_SEQUENCE_POS
	ErrReqTooBig             Status = 10065 // NFS4ERR_REQ_TOO_BIG
	ErrRepTooBig             Status = 10066 // NFS4ERR_REP_TOO_BIG
	ErrRepTooBigToCache      Status = 10067 // NFS4ERR_REP_TOO_BIG_TO_CACHE
	ErrRetryUncachedRep      Status = 10068 // NFS4ERR_RETRY_UNCACHED_REP
	ErrUnsafeCompound        Status = 10069 // NFS4ERR_UNSAFE_COMPOUND
	ErrTooManyOps            Status = 10070 // NFS4ERR_TOO_MANY_OPS
	ErrOpNotInSession        Status = 10071 // NFS4ERR_OP_NOT_IN_SESSION
	ErrHashAlgUnsupp         Status = 10072 // NFS4ERR_HASH_ALG_UNSUPP
	ErrClientIDBusy          Status = 10074 // NFS4ERR_CLIENTID_BUSY
	ErrPNFSIOHole            Status = 10075 // NFS4ERR_PNFS_IO_HOLE
	ErrSeqFalseRetry         Status = 10076 // NFS4ERR_SEQ_FALSE_RETRY
	ErrBadHighSlot           Status = 10077 // NFS4ERR_BAD_HIGH_SLOT
	ErrDeadSession           Status = 10078 // NFS4ERR_DEADSESSION
	ErrEncrAlgUnsupp         Status = 10079 // NFS4ERR_ENCR_ALG_UNSUPP
	ErrPNFSNoLayout          Status = 10080 // NFS4ERR_PNFS_NO_LAYOUT
	ErrNotOnlyOp             Status = 10081 // NFS4ERR_NOT_ONLY_OP
	ErrWrongCred             Status = 10082 // NFS4ERR_WRONG_CRED
	ErrWrongType             Status = 10083 // NFS4ERR_WRONG_TYPE
	ErrDirDelegUnavail       Status = 10084 // NFS4ERR_DIRDELEG_UNAVAIL
	ErrRejectDeleg           Status = 10085 // NFS4ERR_REJECT_DELEG
	ErrReturnConflict        Status = 10086 // NFS4ERR_RETURNCONFLICT
	ErrDelegRevoked          Status = 10087 // NFS4ERR_DELEG_REVOKED
	ErrPartnerNotSupp        Status = 10088 // NFS4ERR_PARTNER_NOTSUPP
	ErrPartnerNoAuth         Status = 10089 // NFS4ERR_PARTNER_NO_AUTH
	ErrUnionNotSupp          Status = 10090 // NFS4ERR_UNION_NOTSUPP
	ErrOffloadDenied         Status = 10091 // NFS4ERR_OFFLOAD_DENIED
	ErrWrongLFS              Status = 10092 // NFS4ERR_WRONG_LFS
	ErrBadLabel              Status = 10093 // NFS4ERR_BADLABEL
	ErrOffloadNoReqs         Status = 10094 // NFS4ERR_OFFLOAD_NO_REQS
)

var statusNames = map[Status]string{
	0:     "NFS4_OK",
	1:     "NFS4ERR_PERM",
	2:     "NFS4ERR_NOENT",
	5:     "NFS4ERR_IO",
	6:     "NFS4ERR_NXIO",
	13:    "NFS4ERR_ACCESS",
	17:    "NFS4ERR_EXIST",
	18:    "NFS4ERR_XDEV",
	20:    "NFS4ERR_NOTDIR",
	21:    "NFS4ERR_ISDIR",
	22:    "NFS4ERR_INVAL",
	27:    "NFS4ERR_FBIG",
	28:    "NFS4ERR_NOSPC",
	30:    "NFS4ERR_ROFS",
	31:    "NFS4ERR_MLINK",
	63:    "NFS4ERR_NAMETOOLONG",
	66:    "NFS4ERR_NOTEMPTY",
	69:    "NFS4ERR_DQUOT",
	70:    "NFS4ERR_STALE",
	10001: "NFS4ERR_BADHANDLE",
	10003: "NFS4ERR_BAD_COOKIE",
	10004: "NFS4ERR_NOTSUPP",
	10005: "NFS4ERR_TOOSMALL",
	10006: "NFS4ERR_SERVERFAULT",
	10007: "NFS4ERR_BADTYPE",
	10008: "NFS4ERR_DELAY",
	10009: "NFS4ERR_SAME",
	10010: "NFS4ERR_DENIED",
	10011: "NFS4ERR_EXPIRED",
	10012: "NFS4ERR_LOCKED",
	10013: "NFS4ERR_GRACE",
	10014: "NFS4ERR_FHEXPIRED",
	10015: "NFS4ERR_SHARE_DENIED",
	10016: "NFS4ERR_WRONGSEC",
	10017: "NFS4ERR_CLID_INUSE",
	10018: "NFS4ERR_RESOURCE",
	10019: "NFS4ERR_MOVED",
	10020: "NFS4ERR_NOFILEHANDLE",
	10021: "NFS4ERR_MINOR_VERS_MISMATCH",
	10022: "NFS4ERR_STALE_CLIENTID",
	10023: "NFS4ERR_STALE_STATEID",
	10024: "NFS4ERR_OLD_STATEID",
	10025: "NFS4ERR_BAD_STATEID",
	10026: "NFS4ERR_BAD_SEQID",
	10027: "NFS4ERR_NOT_SAME",
	10028: "NFS4ERR_LOCK_RANGE",
	10029: "NFS4ERR_SYMLINK",
	10030: "NFS4ERR_RESTOREFH",
	10031: "NFS4ERR_LEASE_MOVED",
	10032: "NFS4ERR_ATTRNOTSUPP",
	10033: "NFS4ERR_NO_GRACE",
	10034: "NFS4ERR_RECLAIM_BAD",
	10035: "NFS4ERR_RECLAIM_CONFLICT",
	10036: "NFS4ERR_BADXDR",
	10037: "NFS4ERR_LOCKS_HELD",
	10038: "NFS4ERR_OPENMODE",
	10039: "NFS4ERR_BADOWNER",
	10040: "NFS4ERR_BADCHAR",
	10041: "NFS4ERR_BADNAME",
	10042: "NFS4ERR_BAD_RANGE",
	10043: "NFS4ERR_LOCK_NOTSUPP",
	10044: "NFS4ERR_OP_ILLEGAL",
	10045: "NFS4ERR_DEADLOCK",
	10046: "NFS4ERR_FILE_OPEN",
	10047: "NFS4ERR_ADMIN_REVOKED",
	10048: "NFS4ERR_CB_PATH_DOWN",
	10049: "NFS4ERR_BADIOMODE",
	10050: "NFS4ERR_BADLAYOUT",
	10051: "NFS4ERR_BAD_SESSION_DIGEST",
	10052: "NFS4ERR_BADSESSION",
	10053: "NFS4ERR_BADSLOT",
	10054: "NFS4ERR_COMPLETE_ALREADY",
	10055: "NFS4ERR_CONN_NOT_BOUND_TO_SESSION",
	10056: "NFS4ERR_DELEG_ALREADY_WANTED",
	10057: "NFS4ERR_BACK_CHAN_BUSY",
	10058: "NFS4ERR_LAYOUTTRYLATER",
	10059: "NFS4ERR_LAYOUTUNAVAILABLE",
	10060: "NFS4ERR_NOMATCHING_LAYOUT",
	10061: "NFS4ERR_RECALLCONFLICT",
	10062: "NFS4ERR_UNKNOWN_LAYOUTTYPE",
	10063: "NFS4ERR_SEQ_MISORDERED",
	10064: "NFS4ERR_SEQUENCE_POS",
	10065: "NFS4ERR_REQ_TOO_BIG",
	10066: "NFS4ERR_REP_TOO_BIG",
	10067: "NFS4ERR_REP_TOO_BIG_TO_CACHE",
	10068: "NFS4ERR_RETRY_UNCACHED_REP",
	10069: "NFS4ERR_UNSAFE_COMPOUND",
	10070: "NFS4ERR_TOO_MANY_OPS",
	10071: "NFS4ERR_OP_NOT_IN_SESSION",
	10072: "NFS4ERR_HASH_ALG_UNSUPP",
	10074: "NFS4ERR_CLIENTID_BUSY",
	10075: "NFS4ERR_PNFS_IO_HOLE",
	10076: "NFS4ERR_SEQ_FALSE_RETRY",
	10077: "NFS4ERR_BAD_HIGH_SLOT",
	10078: "NFS4ERR_DEADSESSION",
	10079: "NFS4ERR_ENCR_ALG_UNSUPP",
	10080: "NFS4ERR_PNFS_NO_LAYOUT",
	10081: "NFS4ERR_NOT_ONLY_OP",
	10082: "NFS4ERR_WRONG_CRED",
	10083: "NFS4ERR_WRONG_TYPE",
	10084: "NFS4ERR_DIRDELEG_UNAVAIL",
	10085: "NFS4ERR_REJECT_DELEG",
	10086: "NFS4ERR_RETURNCONFLICT",
	10087: "NFS4ERR_DELEG_REVOKED",
	10088: "NFS4ERR_PARTNER_NOTSUPP",
	10089: "NFS4ERR_PARTNER_NO_AUTH",
	10090: "NFS4ERR_UNION_NOTSUPP",
	10091: "NFS4ERR_OFFLOAD_DENIED",
	10092: "NFS4ERR_WRONG_LFS",
	10093: "NFS4ERR_BADLABEL",
	10094: "NFS4ERR_OFFLOAD_NO_REQS",
}

// NFSv4 COMPOUND operation numbers (nfs_opnum4).
// Numbers 72 through 75 are the extended attribute operations from RFC 8276.
const (
	OpAccess             Op = 3
	OpClose              Op = 4
	OpCommit             Op = 5
	OpCreate             Op = 6
	OpDelegPurge         Op = 7
	OpDelegReturn        Op = 8
	OpGetAttr            Op = 9
	OpGetFH              Op = 10
	OpLink               Op = 11
	OpLock               Op = 12
	OpLockT              Op = 13
	OpLockU              Op = 14
	OpLookup             Op = 15
	OpLookupp            Op = 16
	OpNVerify            Op = 17
	OpOpen               Op = 18
	OpOpenAttr           Op = 19
	OpOpenConfirm        Op = 20
	OpOpenDowngrade      Op = 21
	OpPutFH              Op = 22
	OpPutPubFH           Op = 23
	OpPutRootFH          Op = 24
	OpRead               Op = 25
	OpReadDir            Op = 26
	OpReadLink           Op = 27
	OpRemove             Op = 28
	OpRename             Op = 29
	OpRenew              Op = 30
	OpRestoreFH          Op = 31
	OpSaveFH             Op = 32
	OpSecInfo            Op = 33
	OpSetAttr            Op = 34
	OpSetClientID        Op = 35
	OpSetClientIDConfirm Op = 36
	OpVerify             Op = 37
	OpWrite              Op = 38
	OpReleaseLockOwner   Op = 39
	OpBackchannelCtl     Op = 40
	OpBindConnToSession  Op = 41
	OpExchangeID         Op = 42
	OpCreateSession      Op = 43
	OpDestroySession     Op = 44
	OpFreeStateID        Op = 45
	OpGetDirDelegation   Op = 46
	OpGetDeviceInfo      Op = 47
	OpGetDeviceList      Op = 48
	OpLayoutCommit       Op = 49
	OpLayoutGet          Op = 50
	OpLayoutReturn       Op = 51
	OpSecInfoNoName      Op = 52
	OpSequence           Op = 53
	OpSetSSV             Op = 54
	OpTestStateID        Op = 55
	OpWantDelegation     Op = 56
	OpDestroyClientID    Op = 57
	OpReclaimComplete    Op = 58
	OpAllocate           Op = 59
	OpCopy               Op = 60
	OpCopyNotify         Op = 61
	OpDeallocate         Op = 62
	OpIOAdvise           Op = 63
	OpLayoutError        Op = 64
	OpLayoutStats        Op = 65
	OpOffloadCancel      Op = 66
	OpOffloadStatus      Op = 67
	OpReadPlus           Op = 68
	OpSeek               Op = 69
	OpWriteSame          Op = 70
	OpClone              Op = 71
	OpIllegal            Op = 10044
	OpGetXattr           Op = 72
	OpSetXattr           Op = 73
	OpListXattrs         Op = 74
	OpRemoveXattr        Op = 75
)

var opNames = map[Op]string{
	3:     "ACCESS",
	4:     "CLOSE",
	5:     "COMMIT",
	6:     "CREATE",
	7:     "DELEGPURGE",
	8:     "DELEGRETURN",
	9:     "GETATTR",
	10:    "GETFH",
	11:    "LINK",
	12:    "LOCK",
	13:    "LOCKT",
	14:    "LOCKU",
	15:    "LOOKUP",
	16:    "LOOKUPP",
	17:    "NVERIFY",
	18:    "OPEN",
	19:    "OPENATTR",
	20:    "OPEN_CONFIRM",
	21:    "OPEN_DOWNGRADE",
	22:    "PUTFH",
	23:    "PUTPUBFH",
	24:    "PUTROOTFH",
	25:    "READ",
	26:    "READDIR",
	27:    "READLINK",
	28:    "REMOVE",
	29:    "RENAME",
	30:    "RENEW",
	31:    "RESTOREFH",
	32:    "SAVEFH",
	33:    "SECINFO",
	34:    "SETATTR",
	35:    "SETCLIENTID",
	36:    "SETCLIENTID_CONFIRM",
	37:    "VERIFY",
	38:    "WRITE",
	39:    "RELEASE_LOCKOWNER",
	40:    "BACKCHANNEL_CTL",
	41:    "BIND_CONN_TO_SESSION",
	42:    "EXCHANGE_ID",
	43:    "CREATE_SESSION",
	44:    "DESTROY_SESSION",
	45:    "FREE_STATEID",
	46:    "GET_DIR_DELEGATION",
	47:    "GETDEVICEINFO",
	48:    "GETDEVICELIST",
	49:    "LAYOUTCOMMIT",
	50:    "LAYOUTGET",
	51:    "LAYOUTRETURN",
	52:    "SECINFO_NO_NAME",
	53:    "SEQUENCE",
	54:    "SET_SSV",
	55:    "TEST_STATEID",
	56:    "WANT_DELEGATION",
	57:    "DESTROY_CLIENTID",
	58:    "RECLAIM_COMPLETE",
	59:    "ALLOCATE",
	60:    "COPY",
	61:    "COPY_NOTIFY",
	62:    "DEALLOCATE",
	63:    "IO_ADVISE",
	64:    "LAYOUTERROR",
	65:    "LAYOUTSTATS",
	66:    "OFFLOAD_CANCEL",
	67:    "OFFLOAD_STATUS",
	68:    "READ_PLUS",
	69:    "SEEK",
	70:    "WRITE_SAME",
	71:    "CLONE",
	10044: "ILLEGAL",
	72:    "GETXATTR",
	73:    "SETXATTR",
	74:    "LISTXATTRS",
	75:    "REMOVEXATTR",
}

// NFSv4 callback operation numbers (nfs_cb_opnum4).
const (
	CBOpGetAttr            CBOp = 3
	CBOpRecall             CBOp = 4
	CBOpLayoutRecall       CBOp = 5
	CBOpNotify             CBOp = 6
	CBOpPushDeleg          CBOp = 7
	CBOpRecallAny          CBOp = 8
	CBOpRecallableObjAvail CBOp = 9
	CBOpRecallSlot         CBOp = 10
	CBOpSequence           CBOp = 11
	CBOpWantsCancelled     CBOp = 12
	CBOpNotifyLock         CBOp = 13
	CBOpNotifyDeviceID     CBOp = 14
	CBOpOffload            CBOp = 15
	CBOpIllegal            CBOp = 10044
)

var cbOpNames = map[CBOp]string{
	3:     "CB_GETATTR",
	4:     "CB_RECALL",
	5:     "CB_LAYOUTRECALL",
	6:     "CB_NOTIFY",
	7:     "CB_PUSH_DELEG",
	8:     "CB_RECALL_ANY",
	9:     "CB_RECALLABLE_OBJ_AVAIL",
	10:    "CB_RECALL_SLOT",
	11:    "CB_SEQUENCE",
	12:    "CB_WANTS_CANCELLED",
	13:    "CB_NOTIFY_LOCK",
	14:    "CB_NOTIFY_DEVICEID",
	15:    "CB_OFFLOAD",
	10044: "CB_ILLEGAL",
}

// NFSv4 attribute numbers (FATTR4_*).
const (
	AttrSupportedAttrs    Attr = 0
	AttrType              Attr = 1
	AttrFHExpireType      Attr = 2
	AttrChange            Attr = 3
	AttrSize              Attr = 4
	AttrLinkSupport       Attr = 5
	AttrSymlinkSupport    Attr = 6
	AttrNamedAttr         Attr = 7
	AttrFSID              Attr = 8
	AttrUniqueHandles     Attr = 9
	AttrLeaseTime         Attr = 10
	AttrRdAttrError       Attr = 11
	AttrACL               Attr = 12
	AttrACLSupport        Attr = 13
	AttrArchive           Attr = 14
	AttrCanSetTime        Attr = 15
	AttrCaseInsensitive   Attr = 16
	AttrCasePreserving    Attr = 17
	AttrChownRestricted   Attr = 18
	AttrFileHandle        Attr = 19
	AttrFileID            Attr = 20
	AttrFilesAvail        Attr = 21
	AttrFilesFree         Attr = 22
	AttrFilesTotal        Attr = 23
	AttrFSLocations       Attr = 24
	AttrHidden            Attr = 25
	AttrHomogeneous       Attr = 26
	AttrMaxFileSize       Attr = 27
	AttrMaxLink           Attr = 28
	AttrMaxName           Attr = 29
	AttrMaxRead           Attr = 30
	AttrMaxWrite          Attr = 31
	AttrMIMEType          Attr = 32
	AttrMode              Attr = 33
	AttrNoTrunc           Attr = 34
	AttrNumLinks          Attr = 35
	AttrOwner             Attr = 36
	AttrOwnerGroup        Attr = 37
	AttrQuotaAvailHard    Attr = 38
	AttrQuotaAvailSoft    Attr = 39
	AttrQuotaUsed         Attr = 40
	AttrRawDev            Attr = 41
	AttrSpaceAvail        Attr = 42
	AttrSpaceFree         Attr = 43
	AttrSpaceTotal        Attr = 44
	AttrSpaceUsed         Attr = 45
	AttrSystem            Attr = 46
	AttrTimeAccess        Attr = 47
	AttrTimeAccessSet     Attr = 48
	AttrTimeBackup        Attr = 49
	AttrTimeCreate        Attr = 50
	AttrTimeDelta         Attr = 51
	AttrTimeMetadata      Attr = 52
	AttrTimeModify        Attr = 53
	AttrTimeModifySet     Attr = 54
	AttrMountedOnFileID   Attr = 55
	AttrDirNotifDelay     Attr = 56
	AttrDirentNotifDelay  Attr = 57
	AttrDACL              Attr = 58
	AttrSACL              Attr = 59
	AttrChangePolicy      Attr = 60
	AttrFSStatus          Attr = 61
	AttrFSLayoutTypes     Attr = 62
	AttrLayoutHint        Attr = 63
	AttrLayoutTypes       Attr = 64
	AttrLayoutBlkSize     Attr = 65
	AttrLayoutAlignment   Attr = 66
	AttrFSLocationsInfo   Attr = 67
	AttrMDSThreshold      Attr = 68
	AttrRetentionGet      Attr = 69
	AttrRetentionSet      Attr = 70
	AttrRetentEvtGet      Attr = 71
	AttrRetentEvtSet      Attr = 72
	AttrRetentionHold     Attr = 73
	AttrModeSetMasked     Attr = 74
	AttrSuppAttrExclCreat Attr = 75
	AttrFSCharsetCap      Attr = 76
	AttrCloneBlkSize      Attr = 77
	AttrSpaceFreed        Attr = 78
	AttrChangeAttrType    Attr = 79
	AttrSecLabel          Attr = 80
)

var attrNames = map[Attr]string{
	0:  "supported_attrs",
	1:  "type",
	2:  "fh_expire_type",
	3:  "change",
	4:  "size",
	5:  "link_support",
	6:  "symlink_support",
	7:  "named_attr",
	8:  "fsid",
	9:  "unique_handles",
	10: "lease_time",
	11: "rdattr_error",
	12: "acl",
	13: "aclsupport",
	14: "archive",
	15: "cansettime",
	16: "case_insensitive",
	17: "case_preserving",
	18: "chown_restricted",
	19: "filehandle",
	20: "fileid",
	21: "files_avail",
	22: "files_free",
	23: "files_total",
	24: "fs_locations",
	25: "hidden",
	26: "homogeneous",
	27: "maxfilesize",
	28: "maxlink",
	29: "maxname",
	30: "maxread",
	31: "maxwrite",
	32: "mimetype",
	33: "mode",
	34: "no_trunc",
	35: "numlinks",
	36: "owner",
	37: "owner_group",
	38: "quota_avail_hard",
	39: "quota_avail_soft",
	40: "quota_used",
	41: "rawdev",
	42: "space_avail",
	43: "space_free",
	44: "space_total",
	45: "space_used",
	46: "system",
	47: "time_access",
	48: "time_access_set",
	49: "time_backup",
	50: "time_create",
	51: "time_delta",
	52: "time_metadata",
	53: "time_modify",
	54: "time_modify_set",
	55: "mounted_on_fileid",
	56: "dir_notif_delay",
	57: "dirent_notif_delay",
	58: "dacl",
	59: "sacl",
	60: "change_policy",
	61: "fs_status",
	62: "fs_layout_types",
	63: "layout_hint",
	64: "layout_types",
	65: "layout_blksize",
	66: "layout_alignment",
	67: "fs_locations_info",
	68: "mdsthreshold",
	69: "retention_get",
	70: "retention_set",
	71: "retentevt_get",
	72: "retentevt_set",
	73: "retention_hold",
	74: "mode_set_masked",
	75: "suppattr_exclcreat",
	76: "fs_charset_cap",
	77: "clone_blksize",
	78: "space_freed",
	79: "change_attr_type",
	80: "sec_label",
}
