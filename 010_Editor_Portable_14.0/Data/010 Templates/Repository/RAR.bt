//------------------------------------------------
//--- 010 Editor v2.0 Binary Template
//
//      File: RAR.bt
//   Authors: Alexander Sherman, Jiaxi Ren
//   Version: 8.1
//   Purpose: Parse RAR archives including 2.x, 3.x, 5.x and SFX RAR files.
//  Category: Archive
// File Mask: *.rar
//  ID Bytes: 52 61 72 21 1A 07 00, 52 61 72 21 1A 07 01 00
//   History:
//   8.1   2022-09-26 G Cazzetta: Uncovered some unknown stuff.
//   8.0   2020-10-28 Jiaxi Ren: Added 5.x support.
//   7.2   2020-06-14 G Cazzetta: Added Unicode name decoding from UnRAR source.
//   7.1   2016-01-28 SweetScape: Updated header for repository submission.
//   7.03  A Sherman: First public release.
//
// RAR archive structures
// Based on TECHNOTE.TXT from the RAR archiver distribution
//------------------------------------------------

LittleEndian();

const string RarSignature = "Rar!" + '\x1A' + '\x07' + '\x00';
const string RarSignatureV5 = "Rar!" + '\x1A' + '\x07' + '\x01' + '\x00';

////////////////

struct RarBlock;
struct FileBlock;
struct SubBlock;
struct OldCommentBlock;
struct OldSubBlock;

struct RarBlockV5;
struct Records;
struct Record;
struct QuickOpenData;
struct DataCache;

struct UnicodeName;
struct UTF8Name;

////////////////

enum <ubyte> HeaderType
{
	MARKER=0x72, ARCHIVE, FILE_OR_DIR, COMMENT_OLD, AV_OLD_1, SUBBLOCK_OLD, RR_OLD, AV_OLD_2, SUBBLOCK, _END_
};

enum <ubyte> HeaderTypeV5 {
	MAIN = 1, FILE, SERVICE, ENCRYPT, END
};

enum <ubyte> RecordType {
	LOCATOR = 1, FILE_ENCRYP = 1, FILE_HASH, FILE_TIME, FILE_VERSION, REDIRECTION, OWNER, SERVICE_DATA
};

////////////////

local uquad iBlockCount = 0;
local uquad iBadCRCCount = 0;

local uquad iSubBlocks = 0;
local uquad iFiles = 0;
local uquad iDirs = 0;
local uquad iComments = 0;
local uquad iUniNames = 0;
local ubyte iMinUnpVer = 255;
local ubyte iMaxUnpVer = 0;
local uquad iTotalUnpSize = 0;

const ubyte MAX_VINT_LEN = 10;

local ubyte isVersionV5 = false;
local ubyte isArchiveEnd = false;

////////////////

enum <ubyte> HostSystem
{
	_MS_DOS, _OS_2, _Win32, _Unix, _Mac_OS, _BeOS
};

enum <char> PackMethod
{
	Store='0', Fastest, Fast, Normal, Good, Best
};

enum <uint16> OldSubType
{
	OS2_EA=0x0100, UnixOwners, MacOS_EA, BeOS_EA, Win32_EA, Stream
};

struct DosFileAttrs
{
	uint32 READONLY : 1;
	uint32 HIDDEN : 1;
	uint32 SYSTEM : 1;
	uint32 VOLUME : 1;
	uint32 DIRECTORY : 1;
	uint32 ARCHIVE : 1;

	uint32 _reserved : 26 <format=hex>;
};

struct WinFileAttrs
{
	uint32 READONLY : 1;
	uint32 HIDDEN : 1;
	uint32 SYSTEM : 1;
	uint32 VOLUME : 1;
	uint32 DIRECTORY : 1;
	uint32 ARCHIVE : 1;
	uint32 DEVICE : 1;
	uint32 NORMAL : 1;
	uint32 TEMPORARY : 1;
	uint32 SPARSE_FILE : 1;
	uint32 REPARSE_POINT : 1;
	uint32 COMPRESSED : 1;
	uint32 OFFLINE : 1;
	uint32 NOT_CONTENT_INDEXED : 1;
	uint32 ENCRYPTED : 1;

	uint32 _reserved : 17 <format=hex>;
};

struct UnixStyleAttrs
{
	uint32 S_IXOTH : 1; // X for other
	uint32 S_IWOTH : 1; // W for other
	uint32 S_IROTH : 1; // R for other

	uint32 S_IXGRP : 1; // X for group
	uint32 S_IWGRP : 1; // W for group
	uint32 S_IRGRP : 1; // R for group

	uint32 S_IXUSR : 1; // X for user
	uint32 S_IWUSR : 1; // W for user
	uint32 S_IRUSR : 1; // R for user

	uint32 _reserved : 23 <format=hex>;
};

struct HeaderFlags
{
	uint16 _reserved : 14 <format=hex>;

	uint16 OLD_VERSION_IGNORE : 1;
	uint16 ADD_SIZE : 1;
};

struct MainHeaderFlags
{
	uint16 ARCHIVE_VOLUME : 1;
	uint16 ARCHIVE_COMMENT : 1;
	uint16 ARCHIVE_LOCKED : 1;
	uint16 ARCHIVE_SOLID : 1;
	uint16 NEW_VOLUME_NAMING : 1;
	uint16 AV_INFO : 1;
	uint16 RECOVERY_RECORD : 1;
	uint16 ENCRYPTED_HEADERS : 1;
	uint16 FIRST_VOLUME : 1;

	uint16 _reserved : 5 <format=hex>;

	uint16 OLD_VERSION_IGNORE : 1;
	uint16 ADD_SIZE : 1;
};

enum <ubyte> FileDictType
{
	_64K, _128K, _256K, _512K, _1024K, _2048K, _4096K, _Directory
};

struct FileHeaderFlags
{
	ubyte PREV_VOLUME : 1;
	ubyte NEXT_VOLUME : 1;
	ubyte PASSWORD_ENCRYPTED : 1;
	ubyte FILE_COMMENT : 1;
	ubyte SOLID : 1;
	FileDictType DICTIONARY : 3;
	ubyte HIGH_SIZE : 1;
	ubyte UNICODE : 1;
	ubyte SALT : 1;
	ubyte FILE_VERSION : 1;
	ubyte EXTENDED_TIME : 1;
	ubyte EXTRA_AREA : 1;
	ubyte OLD_VERSION_IGNORE : 1;
	ubyte ADD_SIZE : 1;
};

void CheckCRC()
{
	local uint16 crcCheck = Checksum(CHECKSUM_CRC32, startof(HeadType), FTell() - startof(HeadType)) & 0xFFFF;
	if (crcCheck != HeadCRC)
	{
		++iBadCRCCount;

		Warning("Header CRC mismatch in Block #%Lu.", iBlockCount);
		Printf("Header CRC mismatch in Block #%Lu: expected CRC is 0x%X, got 0x%X.\n", iBlockCount, crcCheck, HeadCRC);
	}
}

typedef struct
{
	++iBlockCount;

	uint16 HeadCRC <format=hex, fgcolor=cRed>;

	HeaderType HeadType <fgcolor=cGreen>;

	local uint16 _flags = ReadUShort(FTell());

	switch (HeadType) {
	case ARCHIVE:
		MainHeaderFlags HeadFlags;
		break;
	case FILE_OR_DIR:
	case SUBBLOCK:
		FileHeaderFlags HeadFlags;
		break;
	default:
		HeaderFlags HeadFlags;
		break;
	}

	uint16 HeadSize;

	if (HeadType < MARKER || HeadType > _END_)
	{
		Warning("Unknown Header Type (0x%02X) in Block #%Lu.", HeadType, iBlockCount);
		Printf("Unknown Header Type (0x%02X) in Block #%Lu.\n", HeadType, iBlockCount);
	}

	if (HeadSize < 7)
	{
		Warning("Invalid block size (%u) in Block #%Lu.", HeadSize, iBlockCount);
		Printf("Invalid block size (%u) in Block #%Lu.\n", HeadSize, iBlockCount);
		return -1;
	}

	if (HeadFlags.ADD_SIZE)
	{
		if (HeadType == FILE_OR_DIR || HeadType == SUBBLOCK)
			uint32 PackSize;
		else
			uint32 AddSize;
	}
	else
		local uint32 AddSize = 0;

	switch (HeadType) {
	case MARKER:
		break;
	case ARCHIVE:
		uint16 Reserved1;
		uint32 Reserved2;
		CheckCRC();
		if (HeadFlags.ARCHIVE_COMMENT)
			RarBlock MainComment;
		return;
	case FILE_OR_DIR:
		if (HeadFlags.DICTIONARY == 7)
		{
			++iDirs;
			FileBlock Directory;
		}
		else
		{
			++iFiles;
			FileBlock File;
		}
		return;
	case COMMENT_OLD:
		OldCommentBlock Comment;
		return;
	case SUBBLOCK_OLD:
		OldSubBlock OldSub;
		return;
	case SUBBLOCK:
		SubBlock Sub;
		return;
	case AV_OLD_1:
		Printf("*** Old style Authenticity Verification info (RAR v. < 2.60) @ Block #%Lu\n", iBlockCount);
		break;
	case RR_OLD:
		Printf("*** Old style Recovery Record was found (RAR v. 2.x) @ Block #%Lu\n", iBlockCount);
		break;
	case AV_OLD_2:
		Printf("*** Old style Authenticity Verification info (RAR v. 2.60 - 2.90) @ Block #%Lu\n", iBlockCount);
		break;
	case _END_:
		isArchiveEnd = true;
		Printf("*** END Marker block was found @ Block #%Lu\n", iBlockCount);
		break;
	}

	local quad iOfs = HeadSize - (FTell() - startof(HeadCRC));

	if (iOfs > 0)
		ubyte _reserved[iOfs] <format=hex>;

	if (HeadType == RR_OLD || HeadType == _END_)
		CheckCRC();

	if (AddSize != 0)
		ubyte Data[AddSize] <format=hex, fgcolor=cBlue>;
} RarBlock <read=RarBlockRead>;

wstring RarBlockRead(RarBlock &b)
{
	local wstring s = EnumToString(b.HeadType);

	if (b.HeadType == FILE_OR_DIR)
	{
		if (exists(b.Directory))
			s += ": " + (b.HeadFlags.UNICODE ? UnicodeNameRead(b.Directory.FileName) : b.Directory.FileName) + "\\";
		else if (exists(b.File))
			s += ": " + (b.HeadFlags.UNICODE ? UnicodeNameRead(b.File.FileName) : b.File.FileName);
	}
	else if (b.HeadType == SUBBLOCK_OLD)
		s += ": " + EnumToString(b.OldSub.SubType);
	else if (b.HeadType == SUBBLOCK)
		s += ": " + b.Sub.FileName;

	return s;
}

struct FileBlock
{
	uint32 UnpSize;
	HostSystem HostOS;
	uint32 FileCRC <format=hex>;
	DOSTIME FTime;
	DOSDATE FDate;
	ubyte UnpVer;

	if (UnpVer > iMaxUnpVer)
		iMaxUnpVer = UnpVer;

	if (UnpVer < iMinUnpVer)
		iMinUnpVer = UnpVer;

	PackMethod Method;
	uint16 NameSize;

	if (HeadType == FILE_OR_DIR)
	{
		switch (HostOS) {
		case _Win32:
			WinFileAttrs Attr;
			break;
		case _MS_DOS:
		case _Mac_OS:
		case _OS_2:
			DosFileAttrs Attr;
			break;
		case _Unix:
		case _BeOS:
			UnixStyleAttrs Attr;
			break;
		default:
			uint32 Attr <format=hex>;
		}
	}
	else
		uint32 SubHeadFlags <format=hex>;

	local quad FullPackSize = PackSize;
	local quad FullUnpSize = UnpSize;

	if (_flags & 0x0100)
	{
		uint32 HighPackSize;
		uint32 HighUnpSize;

		FullPackSize += (quad)HighPackSize << 32;
		FullUnpSize += (quad)HighUnpSize << 32;
	}

	if (HeadType == FILE_OR_DIR)
		iTotalUnpSize += FullUnpSize;

	if (_flags & 0x0200)
	{
		++iUniNames;

		UnicodeName FileName(NameSize) <fgcolor=cPurple>;
	}
	else
		char FileName[NameSize] <fgcolor=cPurple>;

	if (HeadType == SUBBLOCK)
	{
		++iSubBlocks;

		Printf("*** SubBlock: %s (Block #%Lu)\n", FileName, iBlockCount);
		switch (FileName) {
		case "CMT":
			++iComments;
			Printf("*** Main Comment (RAR v. 3.x) @ Block #%Lu\n", iBlockCount);
			break;
		case "AV":
			Printf("*** Authenticity Verification info (RAR v. 3.x) @ Block #%Lu\n", iBlockCount);
			break;
		case "RR":
			Printf("*** Recovery Record was found (RAR v. 3.x) @ Block #%Lu\n", iBlockCount);
			break;
		case "EA2":
		case "EABE":
		case "ACL":
			Printf("*** Extended Attributes info (RAR v. 3.x) @ Block #%Lu\n", iBlockCount);
			break;
		case "UOW":
			Printf("*** Unix owner/group data (RAR v. 3.x) @ Block #%Lu\n", iBlockCount);
			break;
		case "STM":
			Printf("*** NTFS stream info (RAR v. 3.x) @ Block #%Lu\n", iBlockCount);
			break;
		}

		local quad iOfs = HeadSize - (FTell() - startof(HeadCRC));

		if (_flags & 0x0400)
		{
			iOfs -= 8;

			if (iOfs > 0)
				ubyte _reserved[iOfs] <format=hex>;

			ubyte Salt[8] <format=hex>;
		}
		else
		{
			if (iOfs > 0)
				ubyte _reserved[iOfs] <format=hex>;
		}

		CheckCRC();
	}
	else
	{
		if (_flags & 0x0400)
			ubyte Salt[8] <format=hex>;

		if (_flags & 0x1000)
			ubyte ExtTime[HeadSize - (FTell() - startof(HeadCRC))] <format=hex>;

		CheckCRC();

		if (_flags & 0x0008)
			RarBlock FileComment; // used in RAR v. 2.x
	}

	if (FullPackSize > 0)
		ubyte Data[FullPackSize] <format=hex, fgcolor=cBlue>;
};

typedef FileBlock SubBlock;

////////////////

struct OldCommentBlock
{
	++iComments;

	uint16 UnpSize;
	ubyte UnpVer;
	PackMethod Method;
	uint16 CommCRC <format=hex>;

	CheckCRC();

	Printf("*** Old style CommentBlock (Block #%Lu)\n", iBlockCount);

	local quad iOfs = HeadSize - (FTell() - startof(HeadCRC));

	if (iOfs > 0)
		ubyte Comment[iOfs] <format=hex, fgcolor=cBlue>;
};

struct OldSubBlock
{
	++iSubBlocks;

	OldSubType SubType;
	ubyte Reserved;

	Printf("*** Old style SubBlock: %u (Block #%Lu)\n", SubType, iBlockCount);
	switch (SubType) {
	case OS2_EA:
	case MacOS_EA:
	case BeOS_EA:
	case Win32_EA:
		Printf("*** Old style Extended Attributes info (RAR v. 2.x) @ Block #%Lu\n", iBlockCount);
		break;
	case UnixOwners:
		Printf("*** Old style Unix owner/group data (RAR v. 2.x) @ Block #%Lu\n", iBlockCount);
		break;
	case Stream:
		Printf("*** Old style NTFS stream info (RAR v. 2.x) @ Block #%Lu\n", iBlockCount);
		break;
	}

	local quad iOfs = HeadSize - (FTell() - startof(HeadCRC));

	if (iOfs > 0)
		ubyte _reserved[iOfs] <format=hex>;

	CheckCRC();

	if (AddSize != 0)
		ubyte Data[AddSize] <format=hex, fgcolor=cBlue>;
};

//////////////////////////////////////////////////
// LEB128 stuff (taken from DEX.bt)
//////////////////////////////////////////////////

// struct to read a uleb128 value. uleb128's are a variable-length encoding for
// a 32 bit value. some of the uleb128/sleb128 code was adapted from dalvik's
// libdex/Leb128.h and Wikipedia.

typedef struct {
	ubyte val <comment="uleb128 element">;

	while (val > 0x7F) {
		ubyte val <comment="uleb128 element">;
	}
} uleb128 <read=ULeb128Read, write=ULeb128Write, comment="Unsigned little-endian base 128 value">;

// get the actual uint value of the uleb128
uquad uleb128_value(uleb128 &u) {
	local uquad result = 0;
	local ubyte cur, i = 0;

	for (cur = u.val[i]; cur > 0x7F; cur = u.val[++i]) {
		result += (uquad)(cur & 0x7F) << (i * 7);
	}

	result += (uquad)(cur & 0x7F) << (i * 7);

	return result;
}

string ULeb128Read(uleb128 &u) {
	local string s;
	SPrintf(s, "%Lu", uleb128_value(u));
	return s;
}

void ULeb128Write(uleb128 &u, string s) {
	// Store up to 64 bit integers, resulting in 10 bytes maximum.
	local ubyte buffer[MAX_VINT_LEN];
	local ubyte low;

	local uquad value;
	SScanf(s, "%Lu", value);

	local ubyte size = 0;

	low = value & 0x7F;
	value >>= 7;

	while (value != 0) {
		buffer[size++] = low | 0x80;

		low = value & 0x7F;
		value >>= 7;
	}

	buffer[size++] = low;

	ReplaceBytes(buffer, size, startof(u), sizeof(u));
}

void ReplaceBytes(const uchar buffer[], int size, int64 pos, int n) {
	if (n != size) {
		local int d = size - n;

		if (d > 0) {
			InsertBytes(pos + n, d);
		} else {
			DeleteBytes(pos + size, -d);
		}
	}

	WriteBytes(buffer, pos, size);
}

////////////////

// Archive v5 block format
typedef struct {
	local uquad size;
	local uquad type;
	local uquad flags;

	++iBlockCount;

	uint32 HEAD_CRC <format=hex, fgcolor=cRed, comment="CRC32 of header">;

	uleb128 HeadSize <comment="Size of header data">;
	size = uleb128_value(HeadSize);

	uleb128 HeadType <fgcolor=cGreen, comment="Type of archive header">;
	type = uleb128_value(HeadType);

	local uint32 crcCheck = Checksum(CHECKSUM_CRC32, startof(HeadSize), size + sizeof(HeadSize));
	if (crcCheck != HEAD_CRC) {
		Warning("Header CRC mismatch in Block #%Lu.", iBlockCount);
		Printf("Header CRC mismatch in Block #%Lu: expected CRC is 0x%X, got 0x%X.\n", iBlockCount, crcCheck, HEAD_CRC);
		++iBadCRCCount;
	}

	uleb128 HeadFlags <comment="Flags of archive header">;

	switch (type) {
		case MAIN:
			if (uleb128_value(HeadFlags) & 0x0001) {
				uleb128 ExtraSize <comment="Size of extra area">;
			}

			uleb128 ArchiveFlags <comment="Archive flags">;
			flags = uleb128_value(ArchiveFlags);

			if (flags & 0x0002) {
				uleb128 VolumeNumber <read=VolumeNumberRead, comment="Volume number">;
			}

			if (flags & 0x0008) {
				Printf("Recovery Record is present.\n");
			}

			if (exists(ExtraSize) && uleb128_value(ExtraSize) > 0) {
				Records records(this);
			}

			Printf("It is a %s, %s, %s RARv5 archive.\n",
				(flags & 0x0010) > 0 ? "LOCKED" : "non-locked",
				(flags & 0x0004) > 0 ? "SOLID" : "regular",
				(flags & 0x0001) > 0 ? "VOLUME'd" : "single-part");

			break;
		case ENCRYPT:
			uleb128 EncryptionVersion <comment="Version of encryption algorithm">;

			uleb128 EncryptionFlags <comment="Flags of encryption">;

			ubyte KDFCount <comment="KDF count">;

			ubyte Salt[16] <format=hex, comment="Salt value">;

			if (uleb128_value(EncryptionFlags) & 0x0001) {
				ubyte Value[12] <format=hex, comment="Check value">;
			}

			Warning("It's an encrypted archive. Cannot proceed, exiting...");

			return -2;
		case END:
			uleb128 EndFlags <comment="End of archive flags">;

			if (uleb128_value(EndFlags) & 0x0001) {
				Printf("Archive is a part of multivolume set.\n");
			} else {
				Printf("Archive is the last part.\n");
			}

			isArchiveEnd = true;
			break;
		case FILE:
		case SERVICE:
			flags = uleb128_value(HeadFlags);

			if (flags & 0x0001) {
				uleb128 ExtraSize <comment="Size of extra area">;
			}

			if (flags & 0x0002) {
				uleb128 DataSize <comment="Size of data area">;;
			}

			uleb128 FileFlags <comment="File flags">;
			flags = uleb128_value(FileFlags);

			uleb128 UnpackedSize <comment="Unpacked size">;

			uleb128 Attributes <comment="File attributes">;

			if (flags & 0x0002) {
				time_t mtime <comment="File modification time">;
			}

			if (flags & 0x0004) {
				uint32 DataCRC32 <format=hex, comment="CRC32 of data">;
			}

			uleb128 CompressionInfo <comment="Compression information">;

			uleb128 OS <read=OSRead, comment="OS info">;

			uleb128 NameLength <comment="Name length">;

			if (type == FILE) {
				UTF8Name Name(uleb128_value(NameLength)) <fgcolor=cPurple, comment="Name">;
			} else {
				char Name[uleb128_value(NameLength)] <fgcolor=cPurple, comment="Name">;
			}

			if (exists(ExtraSize) && uleb128_value(ExtraSize) > 0) {
				Records records(this);
			}

			size = uleb128_value(DataSize);
			if (exists(DataSize) && size > 0) {
				if (type == SERVICE && Strncmp(Name, "QO", 2) == 0) {
					QuickOpenData caches(this);
				} else {
					ubyte DataArea[size] <format=hex, fgcolor=cBlue, comment="Data area">;
				}
			}
			break;
		default:
			flags = uleb128_value(HeadFlags);

			if (flags & 0x0001) {
				uleb128 ExtraSize <comment="Size of extra area">;
			}

			if (flags & 0x0002) {
				uleb128 DataSize <comment="Size of data area">;;
			}

			size -= FTell() - startof(HeadType);
			if (size > 0) {
				ubyte _reservedFields[size] <format=hex, comment="Fields specific for block type">;
			}

			if (exists(ExtraSize) && uleb128_value(ExtraSize) > 0) {
				Records records(this);
			}

			size = uleb128_value(DataSize);
			if (exists(DataSize) && size > 0) {
				ubyte DataArea[size] <format=hex, fgcolor=cBlue, comment="Data area">;
			}
			break;
	}
} RarBlockV5 <read=RarBlockV5Read>;

wstring RarBlockV5Read(RarBlockV5 &block) {
	local wstring s;
	local uquad type = uleb128_value(block.HeadType);

	switch (type) {
		case MAIN:
			s = "Main";
			break;
		case FILE:
			s = "File";
			break;
		case SERVICE:
			s = "Service";
			if (Strncmp(block.Name, "CMT", 3) == 0) {
				s += " (Archive comment)";
			} else if (Strncmp(block.Name, "QO", 2) == 0) {
				s += " (Quick open)";
			} else if (Strncmp(block.Name, "ACL", 3) == 0) {
				s += " (NTFS ACL)";
			} else if (Strncmp(block.Name, "STM", 3) == 0) {
				s += " (NTFS streams)";
			} else if (Strncmp(block.Name, "RR", 2) == 0) {
				s += " (Recovery record)";
			}
			break;
		case ENCRYPT:
			s = "Encryption";
			break;
		case END:
			s = "End";
			break;
		default:
			s = "Unknown";
			break;
	}
	s += " block";

	if (type == FILE) {
		s += ": " + UTF8NameRead(block.Name);
		if (uleb128_value(block.FileFlags) & 0x0001)
			s += "/";
	}
	return s;
}

string VolumeNumberRead(uleb128 &u) {
	local string s;
	SPrintf(s, "Volume number: %Lu", uleb128_value(u) + 1);
	return s;
}

string OSRead(uleb128 &u) {
	local string s;

	switch (uleb128_value(u)) {
		case 0:
			s = "Windows";
			break;
		case 1:
			s = "Unix";
			break;
		default:
			s = "Unknown OS";
			break;
	}

	return s;
}

struct Records (RarBlockV5 &block) {
	local uquad RemainingSize = uleb128_value(block.ExtraSize);

	while (RemainingSize != 0) {
		Record record(uleb128_value(block.HeadType));
		RemainingSize -= sizeof(record);
	}
};

// Extra record
typedef struct (ubyte block) {
	local uquad size;
	local uquad flags;

	local string RecordName;
	uleb128 Size <comment="Record size">;
	uleb128 Type <comment="Record type">;

	local uquad type = uleb128_value(Type);

	switch (block) {
		case MAIN:
			if (type == LOCATOR) {
				RecordName = "Locator";
				uleb128 Flags <comment="Record flags">;
				flags = uleb128_value(Flags);

				if (flags & 0x0001) {
					uleb128 QuickOpenOffset <comment="Quick open offset">;
					Printf("Quick open record offset is present.\n");
				}

				if (flags & 0x0002) {
					uleb128 RecoveryRecordOffset <comment="Recovery record offset">;
					Printf("Recovery record offset is present.\n");
				}
			} else {
				RecordName = "Unknown";

				size = uleb128_value(Size) - (FTell() - startof(Type));
				if (size > 0) {
					ubyte Data[size] <format=hex, fgcolor=cBlue, comment="Record data">;
				}
			}
			break;
		case FILE:
		case SERVICE:
			if (type == FILE_ENCRYP) {
				RecordName = "File encryption";
				uleb128 EncryptionVersion <comment="Version of encryption algorithm">;

				uleb128 EncryptionFlags <comment="Flags of encryption">;

				ubyte KDFCount <comment="KDF count">;

				ubyte Salt[16] <format=hex, comment="Salt value">;

				ubyte IV[16] <format=hex, comment="AES-256 initialization vector">;

				if (uleb128_value(EncryptionFlags) & 0x0001) {
					ubyte CheckValue[12] <format=hex, comment="Check value">;
				}
			} else if (type == FILE_HASH) {
				RecordName = "File hash";
				uleb128 HashType <comment="Hash type">;

				if (uleb128_value(HashType) == 0) {
					// BLAKE2sp
					ubyte HashData[32] <format=hex, fgcolor=cBlue, comment="Hash data">;
				} else {
					size = uleb128_value(Size) - (FTell() - startof(Type));
					if (size > 0) {
						ubyte HashData[size] <format=hex, fgcolor=cBlue, comment="Hash data">;
					}

					Warning("Unknown hash function here.");
				}
			} else if (type == FILE_TIME) {
				RecordName = "File time";
				uleb128 Flags <comment="File time flags">;
				flags = uleb128_value(Flags);

				if (flags & 0x0002) {
					Printf("Modification time is present.\n");
					if (flags & 0x0001) {
						time_t mtime <comment="Modification time">;
					} else {
						FILETIME mtime <comment="Modification time">;
					}
				}

				if (flags & 0x0004) {
					Printf("Creation time is present.\n");
					if (flags & 0x0001) {
						time_t ctime <comment="Creation time">;
					} else {
						FILETIME ctime <comment="Creation time">;
					}
				}

				if (flags & 0x0008) {
					Printf("Last access time is present.\n");
					if (flags & 0x0001) {
						time_t atime <comment="Last access time">;
					} else {
						FILETIME atime <comment="Last access time">;
					}
				}

				if (!(~flags & 0x0013)) {
					uint32 mtime_nano <comment="mtime nanoseconds">;
				}

				if (!(~flags & 0x0015)) {
					uint32 ctime_nano <comment="ctime nanoseconds">;
				}

				if (!(~flags & 0x0019)) {
					uint32 atime_nano <comment="atime nanoseconds">;
				}
			} else if (type == FILE_VERSION) {
				RecordName = "File version";
				uleb128 Flags <comment="File version flags">;

				uleb128 Version <comment="File version number">;
			} else if (type == REDIRECTION) {
				RecordName = "File system redirection";
				uleb128 RedirectionType <read=RedirectionRead, comment="Redirection type">;

				uleb128 Flags <comment="File redirection flags">;

				uleb128 NameLength <comment="Length of link target name">;

				UTF8Name Name(uleb128_value(NameLength)) <fgcolor=cPurple, comment="Name">;
			} else if (type == OWNER) {
				RecordName = "Unix owner record";
				uleb128 Flags <comment="Unix owner flags">;
				flags = uleb128_value(Flags);

				if (flags & 0x0001) {
					uleb128 UserNameLength <comment="User name length">;
					UTF8Name UserName(uleb128_value(UserNameLength)) <fgcolor=cPurple, comment="User name">;
				}

				if (flags & 0x0002) {
					uleb128 GroupNameLength <comment="Group name length">;
					UTF8Name GroupName(uleb128_value(GroupNameLength)) <fgcolor=cPurple, comment="Group name">;
				}

				if (flags & 0x0004) {
					uleb128 UserID <comment="User ID">;
				}

				if (flags & 0x0008) {
					uleb128 GroupID <comment="Group ID">;
				}
			} else if (type == SERVICE_DATA) {
				RecordName = "Service data";

				ubyte Data[uleb128_value(Size) - (FTell() - startof(Type))] <format=hex, fgcolor=cBlue, comment="Record data">;
			} else {
				RecordName = "Unknown";

				size = uleb128_value(Size) - (FTell() - startof(Type));
				if (size > 0) {
					ubyte Data[size] <format=hex, fgcolor=cBlue, comment="Record data">;
				}
			}
			break;
		default:
			RecordName = "Unknown";

			size = uleb128_value(Size) - (FTell() - startof(Type));
			if (size > 0) {
				ubyte Data[size] <format=hex, fgcolor=cBlue, comment="Record data">;
			}
			break;
	}
} Record <read=RecordRead>;

string RecordRead(Record &record) {
	return record.RecordName + " record";
}

string RedirectionRead(uleb128 &u) {
	local string s;
	local uquad type = uleb128_value(u);

	switch (type) {
		case 0x0001:
			s = "Unix symlink";
			break;
		case 0x0002:
			s = "Windows symlink";
			break;
		case 0x0003:
			s = "Windows junction";
			break;
		case 0x0004:
			s = "Hard link";
			break;
		case 0x0005:
			s = "File copy";
			break;
		default:
			s = "Unknown redirection type";
			break;
	}

	return s;
}

struct QuickOpenData (RarBlockV5 &block) {
	local uquad RemainingSize = uleb128_value(block.DataSize);

	while (RemainingSize != 0) {
		DataCache cache;
		RemainingSize -= sizeof(cache);
	}
};

// Data cache structure of quick open data
struct DataCache {
	uint32 CRC32 <format=hex, comment="CRC32 of data cache">;

	uleb128 Size <comment="Structure size">;

	local uint32 crcCheck = Checksum(CHECKSUM_CRC32, startof(Size), uleb128_value(Size) + sizeof(Size)) & 0xFFFFFFFF;
	if (crcCheck != CRC32) {
		Warning("DataCache CRC mismatch in Block #%Lu.", iBlockCount);
		Printf("DataCache CRC mismatch in Block #%Lu: expected CRC is 0x%X, got 0x%X.\n", iBlockCount, crcCheck, CRC32);
		++iBadCRCCount;
	}

	uleb128 Flags <comment="Structure flags">;

	uleb128 Offset <comment="Data offset">;

	uleb128 DataSize <comment="Data size">;

	ubyte Data[uleb128_value(DataSize)] <format=hex, fgcolor=cBlue, comment="Archive data">;
};

////////////////

typedef struct (uint16 NameSize)
{
	char String[NameSize];
} UnicodeName <read=UnicodeNameRead>;

typedef struct (uint16 NameSize)
{
	char String[NameSize];
} UTF8Name <read=UTF8NameRead>;

wstring DecodeFileName(char Name[], ubyte EncName[], quad EncSize)
{
	local wstring NameW = "";

	local quad EncPos = 0;
	local quad DecPos = 0;

	local ubyte HighByte = EncName[EncPos++];

	local ubyte Flags = 0;
	local uint32 FlagBits = 0;

	local int Length;
	local ubyte Correction;

	while (EncPos < EncSize)
	{
		if (FlagBits == 0)
		{
			Flags = EncName[EncPos++];
			FlagBits = 8;
		}

		FlagBits -= 2;
		switch ((Flags >> FlagBits) & 0x03) {
		case 0:
			NameW += (char)EncName[EncPos++];
			++DecPos;
			break;
		case 1:
			NameW += ((wchar_t)HighByte << 8) | EncName[EncPos++];
			++DecPos;
			break;
		case 2:
			NameW += ((wchar_t)EncName[EncPos+1] << 8) | EncName[EncPos];
			EncPos += 2;
			++DecPos;
			break;
		case 3:
			Length = EncName[EncPos++];
			if ((Length & 0x80) != 0)
			{
				Correction = EncName[EncPos++];
				for (Length = (Length & 0x7F) + 2; Length > 0; --Length)
					NameW += ((wchar_t)HighByte << 8) | ((ubyte)Name[DecPos++] + Correction);
			}
			else
			{
				for (Length += 2; Length > 0; --Length)
					NameW += Name[DecPos++];
			}
			break;
		}
	}

	return NameW;
}

wstring UnicodeNameRead(UnicodeName &data)
{
	local wstring NameW;

	local uquad iLength = Strlen(data.String);
	if (sizeof(data) == iLength)
		NameW = StringToWString(data.String, CHARSET_UTF8);
	else
	{
		local ubyte EncName[sizeof(data) - (iLength + 1)];
		Memcpy(EncName, data.String, sizeof(EncName), 0, iLength + 1);
		NameW = DecodeFileName(data.String, EncName, sizeof(EncName));
	}

	return NameW;
}

wstring UTF8NameRead(UTF8Name &data)
{
	return StringToWString(data.String, CHARSET_UTF8);
}

////////////////

local quad SignaturePos = FindFirst(RarSignatureV5);

if (SignaturePos >= 0)
{
	isVersionV5 = true;
	if (SignaturePos > 0)
		ubyte SFX[SignaturePos] <format=hex, fgcolor=cSilver, comment="Self-extracting module">;
	FSeek(SignaturePos);
}
else
{
	SignaturePos = FindFirst(RarSignature);
	if (SignaturePos >= 0)
	{
		if (SignaturePos > 0)
			ubyte SFX[SignaturePos] <format=hex, fgcolor=cSilver, comment="Self-extracting module">;
		FSeek(SignaturePos);
	}
	else
	{
		Warning("Not a RAR archive!");
		return -1;
	}
}

//Warning("RAR signature found at 0x%08X.", SignaturePos);
Printf("RAR signature found at 0x%08X.\n", SignaturePos);

if (!isVersionV5)
{
	RarBlock Marker;

	RarBlock ArcHeader;
	if (ArcHeader.HeadType != ARCHIVE)
	{
		Warning("Main archive header is either bad or missing!");
		return -2;
	}
	else
	{
		Printf("It is a %s%s, %s, %s RAR archive with %s naming.\n",
			SignaturePos > 0 ? "self-extracting, " : "",
			ArcHeader.HeadFlags.ARCHIVE_LOCKED ? "LOCKED" : "non-locked",
			ArcHeader.HeadFlags.ARCHIVE_SOLID ? "SOLID" : "regular",
			ArcHeader.HeadFlags.ARCHIVE_VOLUME ? "VOLUME'd" : "single-part",
			ArcHeader.HeadFlags.NEW_VOLUME_NAMING ? "NEW-STYLE" : "old-style");

		if (ArcHeader.HeadFlags.ARCHIVE_COMMENT)
			Printf("Main comment is present.\n");
		if (ArcHeader.HeadFlags.AV_INFO)
			Printf("Old style Authenticity Verification is present.\n");
		if (ArcHeader.HeadFlags.RECOVERY_RECORD)
			Printf("Recovery Record is present.\n");

		if (ArcHeader.HeadFlags.ENCRYPTED_HEADERS)
		{
			Printf("It's an encrypted archive. Cannot proceed, exiting...\n");
			return -3;
		}
	}

	while (!FEof() && !isArchiveEnd)
		RarBlock Block;

	if (iFiles || iDirs)
	{
		Printf("Version to unpack: %u.%u\n", iMaxUnpVer / 10, iMaxUnpVer % 10);
		if (iMinUnpVer != iMaxUnpVer)
			Printf("Some data can also be retrieved by an earlier version of %u.%u.\n", iMinUnpVer / 10, iMinUnpVer % 10);
	}

	Printf("Files: %Lu, Dirs: %Lu, Comments: %Lu, SubBlocks: %Lu, Unpacked Size: %Lu\n", iFiles, iDirs, iComments, iSubBlocks, iTotalUnpSize);
	Printf("Unicode Names: %Lu\n", iUniNames);
}
else
{
	// Signature
	ubyte Signature[8] <format=hex, fgcolor=cAqua, comment="Signature">;

	// Archive v5 Layout
	while (!FEof() && !isArchiveEnd) {
		RarBlockV5 Block;
	}

	local quad ExtraSize = FileSize() - FTell();

	if (ExtraSize > 0) {
		ubyte ExtraInfo[ExtraSize] <format=hex, fgcolor=cSilver, comment="Extra information">;
	}
}

if (iBadCRCCount != 0)
	Printf("%Lu blocks corrupted.\n", iBadCRCCount);
Printf("Done. %Lu blocks processed.\n", iBlockCount);
