// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package nfsv4

import (
	"bytes"
	"strconv"
	"strings"
	"time"

	"github.com/tailscale/nfsv4/internal/xdr"
)

// attrWords is the number of 32-bit words in an AttrMask, enough for all
// attributes defined through NFSv4.2.
const attrWords = 3

// AttrMask is a set of attributes (an NFSv4 bitmap4).
type AttrMask struct {
	w [attrWords]uint32
}

// MakeAttrMask returns an AttrMask containing attrs.
func MakeAttrMask(attrs ...Attr) AttrMask {
	var m AttrMask
	for _, a := range attrs {
		m.Set(a)
	}
	return m
}

// Has reports whether a is in m.
func (m AttrMask) Has(a Attr) bool {
	if a >= attrWords*32 {
		return false
	}
	return m.w[a/32]&(1<<(a%32)) != 0
}

// Set adds a to m. Attributes beyond the highest one known are ignored.
func (m *AttrMask) Set(a Attr) {
	if a < attrWords*32 {
		m.w[a/32] |= 1 << (a % 32)
	}
}

// Clear removes a from m.
func (m *AttrMask) Clear(a Attr) {
	if a < attrWords*32 {
		m.w[a/32] &^= 1 << (a % 32)
	}
}

// IsEmpty reports whether m is empty.
func (m AttrMask) IsEmpty() bool {
	return m.w == [attrWords]uint32{}
}

// And returns the intersection of m and o.
func (m AttrMask) And(o AttrMask) AttrMask {
	for i := range m.w {
		m.w[i] &= o.w[i]
	}
	return m
}

// AndNot returns m without the attributes in o.
func (m AttrMask) AndNot(o AttrMask) AttrMask {
	for i := range m.w {
		m.w[i] &^= o.w[i]
	}
	return m
}

// Or returns the union of m and o.
func (m AttrMask) Or(o AttrMask) AttrMask {
	for i := range m.w {
		m.w[i] |= o.w[i]
	}
	return m
}

// ContainsAll reports whether every attribute in o is also in m.
func (m AttrMask) ContainsAll(o AttrMask) bool {
	return o.AndNot(m).IsEmpty()
}

// All returns the attributes in m, in increasing order.
func (m AttrMask) All() []Attr {
	var as []Attr
	for a := Attr(0); a < attrWords*32; a++ {
		if m.Has(a) {
			as = append(as, a)
		}
	}
	return as
}

func (m AttrMask) String() string {
	var sb strings.Builder
	sb.WriteByte('{')
	for i, a := range m.All() {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(a.String())
	}
	sb.WriteByte('}')
	return sb.String()
}

// encodeBitmap encodes m as a bitmap4 with no trailing zero words.
func encodeBitmap(e *xdr.Encoder, m AttrMask) {
	n := attrWords
	for n > 0 && m.w[n-1] == 0 {
		n--
	}
	e.Uint32(uint32(n))
	for i := range n {
		e.Uint32(m.w[i])
	}
}

// maxBitmapWords is the maximum number of words accepted in a bitmap4 from
// a client.
const maxBitmapWords = 8

// decodeBitmap decodes a bitmap4, ignoring bits for attributes beyond those
// an AttrMask can hold.
func decodeBitmap(d *xdr.Decoder) AttrMask {
	var m AttrMask
	n := d.ArrayLen(maxBitmapWords, 4)
	for i := range n {
		w := d.Uint32()
		if i < attrWords {
			m.w[i] = w
		}
	}
	return m
}

// Attributes the server computes itself from its configuration, rather
// than asking the FS. These are never passed in the want mask to
// FS.GetAttr.
var serverAttrs = MakeAttrMask(
	AttrSupportedAttrs,
	AttrFHExpireType,
	AttrLinkSupport,
	AttrSymlinkSupport,
	AttrNamedAttr,
	AttrUniqueHandles,
	AttrLeaseTime,
	AttrRdAttrError,
	AttrACLSupport,
	AttrCanSetTime,
	AttrCaseInsensitive,
	AttrCasePreserving,
	AttrChownRestricted,
	AttrFileHandle,
	AttrHomogeneous,
	AttrMaxFileSize,
	AttrMaxLink,
	AttrMaxName,
	AttrMaxRead,
	AttrMaxWrite,
	AttrNoTrunc,
	AttrTimeDelta,
	AttrSuppAttrExclCreat,
	AttrChangeAttrType,
)

// statfsAttrs are the attributes that come from StatFSer.
var statfsAttrs = MakeAttrMask(
	AttrFilesAvail,
	AttrFilesFree,
	AttrFilesTotal,
	AttrSpaceAvail,
	AttrSpaceFree,
	AttrSpaceTotal,
)

// supportedAttrs41 is the set of attributes supported in NFSv4.1.
var supportedAttrs41 = serverAttrs.Or(statfsAttrs).Or(MakeAttrMask(
	AttrType,
	AttrChange,
	AttrSize,
	AttrFSID,
	AttrFileID,
	AttrMode,
	AttrNumLinks,
	AttrOwner,
	AttrOwnerGroup,
	AttrRawDev,
	AttrSpaceUsed,
	AttrTimeAccess,
	AttrTimeCreate,
	AttrTimeMetadata,
	AttrTimeModify,
	AttrMountedOnFileID,
)).AndNot(MakeAttrMask(AttrChangeAttrType))

// supportedAttrs42 is the set of attributes supported in NFSv4.2.
var supportedAttrs42 = supportedAttrs41.Or(MakeAttrMask(AttrChangeAttrType))

func supportedAttrs(minorVersion uint32) AttrMask {
	if minorVersion >= 2 {
		return supportedAttrs42
	}
	return supportedAttrs41
}

// fsAttrs are the filesystem-wide attribute values the server reports,
// derived from the Server configuration.
type fsAttrs struct {
	fhExpireType   uint32
	leaseTime      uint32 // seconds
	maxRead        uint64
	maxName        uint32
	fsid           FSID
	changeAttrType uint32
}

// attrSource holds what's needed to encode an object's attributes.
type attrSource struct {
	fs     *fsAttrs
	minor  uint32
	fh     FileHandle
	attrs  *Attrs
	statfs *FSStat // nil if not needed or unavailable
	rdErr  Status  // for rdattr_error
}

// encodeFattr encodes a fattr4 for the requested attributes that are
// supported. Attributes the FS didn't provide that are optional (such as
// BirthTime) are omitted.
func encodeFattr(e *xdr.Encoder, src *attrSource, req AttrMask) {
	mask := req.And(supportedAttrs(src.minor))
	a := src.attrs
	if a == nil {
		a = new(Attrs)
	}
	if a.BirthTime.IsZero() {
		mask.Clear(AttrTimeCreate)
	}

	encodeBitmap(e, mask)
	lenOff := e.Reserve(4)
	valStart := e.Len()
	for _, at := range mask.All() {
		switch at {
		case AttrSupportedAttrs:
			encodeBitmap(e, supportedAttrs(src.minor))
		case AttrType:
			e.Uint32(uint32(a.Type))
		case AttrFHExpireType:
			e.Uint32(src.fs.fhExpireType)
		case AttrChange:
			e.Uint64(a.Change)
		case AttrSize:
			e.Uint64(a.Size)
		case AttrLinkSupport:
			e.Bool(true)
		case AttrSymlinkSupport:
			e.Bool(true)
		case AttrNamedAttr:
			e.Bool(false)
		case AttrFSID:
			fsid := src.fs.fsid
			if a.FSID != nil {
				fsid = *a.FSID
			}
			e.Uint64(fsid.Major)
			e.Uint64(fsid.Minor)
		case AttrUniqueHandles:
			e.Bool(false)
		case AttrLeaseTime:
			e.Uint32(src.fs.leaseTime)
		case AttrRdAttrError:
			e.Uint32(uint32(src.rdErr))
		case AttrACLSupport:
			e.Uint32(0)
		case AttrCanSetTime:
			e.Bool(false)
		case AttrCaseInsensitive:
			e.Bool(false)
		case AttrCasePreserving:
			e.Bool(true)
		case AttrChownRestricted:
			e.Bool(true)
		case AttrFileHandle:
			e.Opaque(src.fh)
		case AttrFileID:
			e.Uint64(a.FileID)
		case AttrFilesAvail:
			e.Uint64(src.statfs.orZero().FilesAvail)
		case AttrFilesFree:
			e.Uint64(src.statfs.orZero().FilesFree)
		case AttrFilesTotal:
			e.Uint64(src.statfs.orZero().FilesTotal)
		case AttrHomogeneous:
			e.Bool(true)
		case AttrMaxFileSize:
			e.Uint64(1<<63 - 1)
		case AttrMaxLink:
			e.Uint32(1<<31 - 1)
		case AttrMaxName:
			e.Uint32(src.fs.maxName)
		case AttrMaxRead:
			e.Uint64(src.fs.maxRead)
		case AttrMaxWrite:
			e.Uint64(src.fs.maxRead)
		case AttrMode:
			e.Uint32(a.Mode & 0o7777)
		case AttrNoTrunc:
			e.Bool(true)
		case AttrNumLinks:
			n := a.NumLinks
			if n == 0 {
				n = 1
				if a.Type == TypeDir {
					n = 2
				}
			}
			e.Uint32(n)
		case AttrOwner:
			if a.Owner != "" {
				e.String(a.Owner)
			} else {
				e.String(strconv.FormatUint(uint64(a.UID), 10))
			}
		case AttrOwnerGroup:
			if a.Group != "" {
				e.String(a.Group)
			} else {
				e.String(strconv.FormatUint(uint64(a.GID), 10))
			}
		case AttrRawDev:
			e.Uint32(a.RawDev.Major)
			e.Uint32(a.RawDev.Minor)
		case AttrSpaceAvail:
			e.Uint64(src.statfs.orZero().SpaceAvail)
		case AttrSpaceFree:
			e.Uint64(src.statfs.orZero().SpaceFree)
		case AttrSpaceTotal:
			e.Uint64(src.statfs.orZero().SpaceTotal)
		case AttrSpaceUsed:
			if a.SpaceUsed != 0 {
				e.Uint64(a.SpaceUsed)
			} else {
				e.Uint64(a.Size)
			}
		case AttrTimeAccess:
			encodeTime(e, firstNonZeroTime(a.AccessTime, a.ModTime))
		case AttrTimeCreate:
			encodeTime(e, a.BirthTime)
		case AttrTimeDelta:
			e.Int64(0)
			e.Uint32(1)
		case AttrTimeMetadata:
			encodeTime(e, firstNonZeroTime(a.ChangeTime, a.ModTime))
		case AttrTimeModify:
			encodeTime(e, a.ModTime)
		case AttrMountedOnFileID:
			if a.MountedOnFileID != 0 {
				e.Uint64(a.MountedOnFileID)
			} else {
				e.Uint64(a.FileID)
			}
		case AttrSuppAttrExclCreat:
			encodeBitmap(e, AttrMask{})
		case AttrChangeAttrType:
			e.Uint32(src.fs.changeAttrType)
		default:
			panic("unhandled supported attribute " + at.String())
		}
	}
	e.PutUint32At(lenOff, uint32(e.Len()-valStart))
}

func (s *FSStat) orZero() *FSStat {
	if s == nil {
		return &FSStat{}
	}
	return s
}

func firstNonZeroTime(ts ...time.Time) time.Time {
	for _, t := range ts {
		if !t.IsZero() {
			return t
		}
	}
	return time.Time{}
}

// encodeTime encodes t as an nfstime4. The zero time is encoded as the
// Unix epoch.
func encodeTime(e *xdr.Encoder, t time.Time) {
	if t.IsZero() {
		e.Int64(0)
		e.Uint32(0)
		return
	}
	e.Int64(t.Unix())
	e.Uint32(uint32(t.Nanosecond()))
}

// fattrEqual reports whether the attribute values encoded for src match the
// client-provided fattr4 values (used by VERIFY and NVERIFY). It returns
// ErrAttrNotSupp if the client asked about unsupported attributes and
// ErrInval if it included rdattr_error.
func fattrEqual(src *attrSource, mask AttrMask, vals []byte) (bool, Status) {
	if mask.Has(AttrRdAttrError) {
		return false, ErrInval
	}
	if !supportedAttrs(src.minor).ContainsAll(mask) {
		return false, ErrAttrNotSupp
	}
	var e xdr.Encoder
	encodeFattr(&e, src, mask)
	d := xdr.NewDecoder(e.Bytes())
	got := decodeBitmap(d)
	ours := d.Opaque(1 << 20)
	if got != mask {
		// An attribute was omitted (such as time_create when the FS
		// doesn't know it), so the values can't match.
		return false, OK
	}
	return bytes.Equal(ours, vals), OK
}
