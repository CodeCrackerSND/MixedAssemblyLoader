using Marina;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace Marina
{
public partial class PEBinary
{
    // Publicly visible parsed blobs, keep these stable for callers.
    public byte[] Data { get; private set; }
    public IMAGE_DOS_HEADER DosHeader { get; private set; }
    public IMAGE_FILE_HEADER FileHeader { get; private set; }

    // Exactly one of these will be populated.
    public IMAGE_OPTIONAL_HEADER32? OptionalHeader32 { get; private set; }
    public IMAGE_OPTIONAL_HEADER64? OptionalHeader64 { get; private set; }

    // Section table (disk headers)
    public List<IMAGE_SECTION_HEADER> SectionHeaders {
    	get
    	{
    	return _SectionHeaders;
    	}
    	
    		private set
    		{
    		 _SectionHeaders = value;
    		}
    
    }
    
	List<IMAGE_SECTION_HEADER> _SectionHeaders = new List<IMAGE_SECTION_HEADER>();
	
    // Parsed directories / tables
    public List<ImportDescriptor> Imports {
    	get
    	{
    	return _Imports;
    	}
    	private set
    	{
    	_Imports = value;
    	}
    }
    
    List<ImportDescriptor> _Imports = new List<ImportDescriptor>();
    
    public List<ExportEntry> Exports
    { 
    	get
    	{
    	return _Exports;
    	}
    	private set
    	{
    	 _Exports = value;
    	}
    }
    
    List<ExportEntry> _Exports = new List<ExportEntry>();
    
    public List<BaseRelocBlock> BaseRelocations
    { 
    	get
    	{
    	return _BaseRelocations;
    	}
    	private set
    	{
    	 _BaseRelocations = value;
    	}
    }
    
    List<BaseRelocBlock> _BaseRelocations = new List<BaseRelocBlock>();
    
    public List<DelayImportDescriptor> DelayImports
    { 
    	get
    	{
    	return _DelayImports;
    	}
    	
    	private set
    	{
    	_DelayImports = value;
    	}
    }
    
    
    List<DelayImportDescriptor> _DelayImports = new List<DelayImportDescriptor>();
    	
    public TLSDirectory TLS
    { 
    	get
    	{
    	return _TLS;
    	}
    	private set
    	{
    	_TLS = value;
    	}
    }
    
    TLSDirectory _TLS = null;
    	
    public ResourceDirectory Resources
    { 
    	get
    	{
    	return _Resources;
    	}
    	private set
    	{
    	_Resources = value;
    	}
    }

    ResourceDirectory _Resources = null;
    
    // Built, mapped image (headers + sections, after we map it in memory)
    public byte[] Image
    {
    	get
    	{
    	return _Image;
    	}
    	private set
    	{
    	_Image = value;
    	}
    }

    byte[] _Image = null;
    
    // Convenience summary properties
    public bool Is64Bit {
get
{
return OptionalHeader64.HasValue;
}
}

    public ulong ImageBase {
get
{
	if (OptionalHeader64!=null&&OptionalHeader64.HasValue)
		return OptionalHeader64.Value.ImageBase;
	else if (OptionalHeader32!=null&&OptionalHeader32.HasValue)
		return OptionalHeader32.Value.ImageBase;

	return 0UL;
}
}

    public uint SizeOfImage {
get
{
	if (OptionalHeader64!=null&&OptionalHeader64.HasValue)
		return OptionalHeader64.Value.SizeOfImage;
	else if (OptionalHeader32!=null&&OptionalHeader32.HasValue)
		return OptionalHeader32.Value.SizeOfImage;

	return 0U;
	
//return OptionalHeader64?.SizeOfImage ?? OptionalHeader32?.SizeOfImage ?? 0U;
}
}

    public uint AddressOfEntryPoint {
get
{
	if (OptionalHeader64!=null&&OptionalHeader64.HasValue)
		return OptionalHeader64.Value.AddressOfEntryPoint;
	
	if (OptionalHeader32!=null&&OptionalHeader32.HasValue)
		return OptionalHeader32.Value.AddressOfEntryPoint;
	
	return 0U;
}
}


    private const ushort IMAGE_FILE_DLL = 0x2000;
    public bool IsDll {
get
{
return (FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;
}
}



    // ctor: read file and attempt parse
    public PEBinary(string filePath)
    {
        if (!File.Exists(filePath))
            throw new FileNotFoundException("File not found", filePath);

        try
        {
            Data = File.ReadAllBytes(filePath);
        }
        catch
        {
            // File.ReadAllBytes throws an exception for extremely large files on some runtimes
            throw new Exception("The file exceeds the maximum size allowed by File.ReadAllBytes(). Please choose a smaller file.");
        }

        TryParse();
    }

    private void TryParse()
    {
        // DOS header 
        DosHeader = Helpers.FromBytes<IMAGE_DOS_HEADER>(Data, 0);
        if (DosHeader.e_magic != 0x5A4D) // 'MZ'
            throw new Exception("Not a valid PE file (missing MZ header).");

        // NT header signature 
        int ntHdrOffset = DosHeader.e_lfanew;
        if (ntHdrOffset <= 0 || ntHdrOffset + 4 > Data.Length) throw new Exception("Invalid e_lfanew.");
        uint ntSignature = BitConverter.ToUInt32(Data, ntHdrOffset);
        if (ntSignature != 0x00004550) // 'PE\0\0'
            throw new Exception("Invalid NT Header signature.");

        // File header 
        int fileHdrOffset = ntHdrOffset + 4;
        FileHeader = Helpers.FromBytes<IMAGE_FILE_HEADER>(Data, fileHdrOffset);

        // Optional header 
        int optHdrOffset = fileHdrOffset + Marshal.SizeOf(typeof(IMAGE_FILE_HEADER));
        ushort optMagic = BitConverter.ToUInt16(Data, optHdrOffset);
        if (optMagic == 0x10b)
        {
            OptionalHeader32 = Helpers.FromBytes<IMAGE_OPTIONAL_HEADER32>(Data, optHdrOffset);
        }
        else if (optMagic == 0x20b)
        {
            OptionalHeader64 = Helpers.FromBytes<IMAGE_OPTIONAL_HEADER64>(Data, optHdrOffset);
        }
        else
        {
            throw new Exception("Unknown Optional Header Magic.");
        }

        // Section headers 
        int optionalHdrSize = FileHeader.SizeOfOptionalHeader;
        int secTableOffset = optHdrOffset + optionalHdrSize;
        int secEntrySize = Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER));
        SectionHeaders.Clear();

        // do not assume the file is perfectly formed, jesus have I seen some things over the years.
        for (int i = 0; i < FileHeader.NumberOfSections; i++)
        {
            int entryOffset = secTableOffset + i * secEntrySize;
            if (entryOffset + secEntrySize > Data.Length) break;
            var section = Helpers.FromBytes<IMAGE_SECTION_HEADER>(Data, entryOffset);
            SectionHeaders.Add(section);
        }

        // parse data directories (exports, imports, relocs, resources)
        ParseDataDirectoriesAndTables();
    }


    #region Data directory indices

    private const int DD_EXPORT = 0;
    private const int DD_IMPORT = 1;
    private const int DD_RESOURCE = 2;
    private const int DD_EXCEPTION = 3;
    private const int DD_SECURITY = 4;
    private const int DD_BASERELOC = 5;
    private const int DD_DEBUG = 6;
    private const int DD_ARCH = 7;
    private const int DD_GLOBALPTR = 8;
    private const int DD_TLS = 9;
    private const int DD_LOAD_CONFIG = 10;
    private const int DD_BOUND_IMPORT = 11;
    private const int DD_IAT = 12;
    private const int DD_DELAY_IMPORT = 13;
    private const int DD_COM_DESCRIPTOR = 14;

    // Grab data directory array in a neutral way
    private IMAGE_DATA_DIRECTORY[] GetDirectories()
    {
        if (OptionalHeader32.HasValue) return OptionalHeader32.Value.DataDirectory;
        return OptionalHeader64.Value.DataDirectory;
    }

    private uint GetSizeOfHeaders()
    {
    	if (OptionalHeader32!=null&&OptionalHeader32.HasValue)
    		return OptionalHeader32.Value.SizeOfHeaders;
    	else if (OptionalHeader64!=null&&OptionalHeader64.HasValue)
        return OptionalHeader64.Value.SizeOfHeaders;
    		
    	return 0U;
    }

    private void ParseDataDirectoriesAndTables()
    {
        var dirs = GetDirectories();

        if (dirs.Length > DD_EXPORT && dirs[DD_EXPORT].VirtualAddress != 0)
            ParseExportTable(dirs[DD_EXPORT].VirtualAddress, dirs[DD_EXPORT].Size);

        if (dirs.Length > DD_IMPORT && dirs[DD_IMPORT].VirtualAddress != 0)
            ParseImportTable(dirs[DD_IMPORT].VirtualAddress, dirs[DD_IMPORT].Size);

        if (dirs.Length > DD_BASERELOC && dirs[DD_BASERELOC].VirtualAddress != 0)
            ParseBaseRelocations(dirs[DD_BASERELOC].VirtualAddress, dirs[DD_BASERELOC].Size);

        if (dirs.Length > DD_DELAY_IMPORT && dirs[DD_DELAY_IMPORT].VirtualAddress != 0)
            ParseDelayImports(dirs[DD_DELAY_IMPORT].VirtualAddress, dirs[DD_DELAY_IMPORT].Size);

        if (dirs.Length > DD_TLS && dirs[DD_TLS].VirtualAddress != 0)
            ParseTLS(dirs[DD_TLS].VirtualAddress, dirs[DD_TLS].Size);

        if (dirs.Length > DD_RESOURCE && dirs[DD_RESOURCE].VirtualAddress != 0)
            ParseResources(dirs[DD_RESOURCE].VirtualAddress, dirs[DD_RESOURCE].Size);
    }

    #endregion
}

}
