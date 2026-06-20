//using Marina;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace Marina
{
public partial class PEBinary
{
    #region Models

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_DOS_HEADER
    {
        public ushort e_magic;     // MZ
        public ushort e_cblp;
        public ushort e_cp;
        public ushort e_crlc;
        public ushort e_cparhdr;
        public ushort e_minalloc;
        public ushort e_maxalloc;
        public ushort e_ss;
        public ushort e_sp;
        public ushort e_csum;
        public ushort e_ip;
        public ushort e_cs;
        public ushort e_lfarlc;
        public ushort e_ovno;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public ushort[] e_res;
        public ushort e_oemid;
        public ushort e_oeminfo;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
        public ushort[] e_res2;
        public int e_lfanew;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_FILE_HEADER
    {
        public ushort Machine;
        public ushort NumberOfSections;
        public uint TimeDateStamp;
        public uint PointerToSymbolTable;
        public uint NumberOfSymbols;
        public ushort SizeOfOptionalHeader;
        public ushort Characteristics;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_OPTIONAL_HEADER32
    {
        public ushort Magic;            // 0x10B
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public uint BaseOfData;
        public uint ImageBase;
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public ushort Subsystem;
        public ushort DllCharacteristics;
        public uint SizeOfStackReserve;
        public uint SizeOfStackCommit;
        public uint SizeOfHeapReserve;
        public uint SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public IMAGE_DATA_DIRECTORY[] DataDirectory;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_OPTIONAL_HEADER64
    {
        public ushort Magic;            // 0x20B
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public ulong ImageBase;
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public ushort Subsystem;
        public ushort DllCharacteristics;
        public ulong SizeOfStackReserve;
        public ulong SizeOfStackCommit;
        public ulong SizeOfHeapReserve;
        public ulong SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public IMAGE_DATA_DIRECTORY[] DataDirectory;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_DATA_DIRECTORY
    {
        public uint VirtualAddress;
        public uint Size;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_SECTION_HEADER
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] Name;
        public uint VirtualSize;
        public uint VirtualAddress;
        public uint SizeOfRawData;
        public uint PointerToRawData;
        public uint PointerToRelocations;
        public uint PointerToLinenumbers;
        public ushort NumberOfRelocations;
        public ushort NumberOfLinenumbers;
        public uint Characteristics;

        public string SectionName {
get
{
return Encoding.UTF8.GetString(Name).TrimEnd('\0');
}
}

    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_IMPORT_DESCRIPTOR
    {
        public uint OriginalFirstThunk;   // RVA to INT
        public uint TimeDateStamp;
        public uint ForwarderChain;
        public uint Name;                 // RVA to ASCII dll name
        public uint FirstThunk;           // RVA to IAT
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_EXPORT_DIRECTORY
    {
        public uint Characteristics;
        public uint TimeDateStamp;
        public ushort MajorVersion;
        public ushort MinorVersion;
        public uint Name;
        public uint Base;
        public uint NumberOfFunctions;
        public uint NumberOfNames;
        public uint AddressOfFunctions;
        public uint AddressOfNames;
        public uint AddressOfNameOrdinals;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_BASE_RELOCATION
    {
        public uint VirtualAddress;
        public uint SizeOfBlock;
    }

    // Delay-load descriptor (WINNT.H)
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_DELAYLOAD_DESCRIPTOR
    {
        public uint AllAttributes;
        public uint DllNameRVA;
        public uint ModuleHandleRVA;
        public uint ImportAddressTableRVA;
        public uint DelayImportNameTableRVA;
        public uint BoundDelayImportTableRVA;
        public uint UnloadInformationTableRVA;
        public uint TimeDateStamp;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_TLS_DIRECTORY32
    {
        public uint StartAddressOfRawData;
        public uint EndAddressOfRawData;
        public uint AddressOfIndex;
        public uint AddressOfCallBacks;
        public uint SizeOfZeroFill;
        public uint Characteristics;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_TLS_DIRECTORY64
    {
        public ulong StartAddressOfRawData;
        public ulong EndAddressOfRawData;
        public ulong AddressOfIndex;
        public ulong AddressOfCallBacks;
        public uint SizeOfZeroFill;
        public uint Characteristics;
    }

    // Resources
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_RESOURCE_DIRECTORY
    {
        public uint Characteristics;
        public uint TimeDateStamp;
        public ushort MajorVersion;
        public ushort MinorVersion;
        public ushort NumberOfNamedEntries;
        public ushort NumberOfIdEntries;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_RESOURCE_DIRECTORY_ENTRY
    {
        public uint Name;          // high bit: name string
        public uint OffsetToData;  // high bit: points to a directory
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_RESOURCE_DATA_ENTRY
    {
        public uint OffsetToData;   // RVA
        public uint Size;
        public uint CodePage;
        public uint Reserved;
    }

    // Domain classes
    public class ImportDescriptor
    {
        public string DLLName { get; set; }
        public List<ImportEntry> Entries { get
        	{
        		return _Entries;
        	}
        }
        
        List<ImportEntry> _Entries = new List<ImportEntry>();
    }

    public class DelayImportDescriptor
    {
        public uint Attributes { get; set; }
        public string DllName { get; set; }
        public List<ImportEntry> Entries {
        	get
        	{
        	return _Entries;
        	}
        	
        	}
        
        List<ImportEntry> _Entries = new List<ImportEntry>();
        
    }

    public class ImportEntry
    {
        public bool ByOrdinal { get; set; }
        public ushort Ordinal { get; set; }   // if by ordinal
        public string Name { get; set; }      // if by name
        public uint Hint { get; set; }        // hint (name imports)
        public uint IATRVA { get; set; }      // where the loader writes the function ptr
        public uint OriginalThunkRVA { get; set; }
    }

    public class ExportEntry
    {
        public string Name { get; set; }
        public ushort Ordinal { get; set; }
        public uint AddressRva { get; set; }
    }

    public class BaseRelocBlock
    {
        public uint VirtualAddress { get; set; }
        public uint SizeOfBlock { get; set; }
        public List<ushort> TypeOffsetList
        { get
        	{
        	return _TypeOffsetList;
        	}
        }
        
        List<ushort> _TypeOffsetList = new List<ushort>();
    }

    public class TLSDirectory
    {
        public ulong StartAddressOfRawData { get; set; }
        public ulong EndAddressOfRawData { get; set; }
        public ulong AddressOfIndex { get; set; }
        public ulong AddressOfCallBacks { get; set; }
        public uint SizeOfZeroFill { get; set; }
        public uint Characteristics { get; set; }
        public List<uint> CallbackRVAs {
        	get
        	{
        	return _CallbackRVAs;
        	}

        	set
        	{
        	_CallbackRVAs = value;
        	}
        }  // RVAs in image
        
        List<uint> _CallbackRVAs = new List<uint>(); // RVAs in image
    }

    public class ResourceDirectory
    {
        public uint Characteristics { get; set; }
        public uint TimeDateStamp { get; set; }
        public ushort MajorVersion { get; set; }
        public ushort MinorVersion { get; set; }
        public ushort NumberOfNamedEntries { get; set; }
        public ushort NumberOfIdEntries { get; set; }
        public List<ResourceEntry> Entries {
        	
        	get
        	{
        	return _Entries;
        	}
        	
        	set
        	{
        	_Entries = value;
        	}
        
        }
        
        List<ResourceEntry> _Entries = new List<ResourceEntry>();
    }

    public class ResourceEntry
    {
        public ushort? Id { get; set; }   // if ID
        public string Name { get; set; }   // if named
        public ResourceDirectory Subdirectory { get; set; } // if directory
        public ResourceDataEntry DataEntry { get; set; }    // if leaf
    }

    public class ResourceDataEntry
    {
        public uint DataRVA { get; set; }
        public uint Size { get; set; }
        public uint CodePage { get; set; }
    }

    #endregion
}

}
