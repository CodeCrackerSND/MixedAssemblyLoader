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
    #region Resources

    // resources are stored in a tree-like structure
    // we need to recursively parse directories and entries
    // each directory has named/id entries and points to either subdirectories or data entries
    // data entries point to the actual resource data
    private void ParseResources(uint rva, uint size)
    {
        int baseOff = RvaToOffset(rva);
        if (baseOff < 0) return;

        // the resource directory functions work in the "resource RVA space", which is
        // self-relative: child offsets are relative to the directory's RVA.
        Resources = ParseResourceDirectory(rva, baseOff, 0);
    }

    private ResourceDirectory ParseResourceDirectory(uint dirRva, int dirBaseOff, int level)
    {
        var dir = Helpers.FromBytes<IMAGE_RESOURCE_DIRECTORY>(Data, dirBaseOff);
        int entryCount = dir.NumberOfNamedEntries + dir.NumberOfIdEntries;
        var rd = new ResourceDirectory
        {
            Characteristics = dir.Characteristics,
            TimeDateStamp = dir.TimeDateStamp,
            MajorVersion = dir.MajorVersion,
            MinorVersion = dir.MinorVersion,
            NumberOfNamedEntries = dir.NumberOfNamedEntries,
            NumberOfIdEntries = dir.NumberOfIdEntries,
            Entries = new List<ResourceEntry>()
        };

        int entryOff = dirBaseOff + Marshal.SizeOf(typeof(IMAGE_RESOURCE_DIRECTORY));
        int entrySize = Marshal.SizeOf(typeof(IMAGE_RESOURCE_DIRECTORY_ENTRY));

        for (int i = 0; i < entryCount; i++)
        {
            int off = entryOff + i * entrySize;
            if (off + entrySize > Data.Length) break;
            var e = Helpers.FromBytes<IMAGE_RESOURCE_DIRECTORY_ENTRY>(Data, off);
            var re = new ResourceEntry();

            bool nameIsString = (e.Name & 0x80000000) != 0;
            if (nameIsString)
            {
                // name is stored as RVA relative to the resource directory tree base (dirRva)
                uint nameRva = (e.Name & 0x7FFFFFFF) + (dirRva);
                re.Name = ReadUnicodeResourceString(nameRva);
            }
            else
            {
                re.Id = (ushort)(e.Name & 0xFFFF);
            }

            bool isDir = (e.OffsetToData & 0x80000000) != 0;
            uint childRva = (e.OffsetToData & 0x7FFFFFFF) + (dirRva);
            int childOff = RvaToOffset(childRva);

            if (isDir)
            {
                if (childOff >= 0)
                    re.Subdirectory = ParseResourceDirectory(childRva, childOff, level + 1);
            }
            else
            {
                if (childOff >= 0)
                {
                    var dataEntry = Helpers.FromBytes<IMAGE_RESOURCE_DATA_ENTRY>(Data, childOff);
                    re.DataEntry = new ResourceDataEntry
                    {
                        DataRVA = dataEntry.OffsetToData,
                        Size = dataEntry.Size,
                        CodePage = dataEntry.CodePage
                    };
                }
            }

            rd.Entries.Add(re);
        }

        return rd;
    }

    private string ReadUnicodeResourceString(uint rva)
    {
        int off = RvaToOffset(rva);
        if (off < 0 || off + 2 > Data.Length) return null;
        ushort len = BitConverter.ToUInt16(Data, off);
        int bytes = len * 2;
        if (off + 2 + bytes > Data.Length) return null;
        return Encoding.Unicode.GetString(Data, off + 2, bytes);
    }

    /// <summary>
    /// Convenience: fetch raw bytes for a resource at a path like (type, name, lang).
    /// Passing null for a key is treated as "skip level by index" (not implemented).
    /// Returns null if not found.
    /// </summary>
    public byte[] GetResourceData(object typeKey, object nameKey, object langKey)
    {
        if (Resources == null) return null;
        
        var typeNode = FindResourceChild(Resources, typeKey);
        if (typeNode==null)
        	return null;
        if (typeNode.Subdirectory == null) return null;
        
        var nameNode = FindResourceChild(typeNode.Subdirectory, nameKey);
        if (nameNode==null)
        	return null;
        if (nameNode.Subdirectory == null) return null;
        
        var langNode = FindResourceChild(nameNode.Subdirectory, langKey);
        if (langNode==null)
        	return null;
        if (langNode.DataEntry == null) return null;

        int off = RvaToOffset(langNode.DataEntry.DataRVA);
        if (off < 0) return null;
        int size = (int)Math.Min((uint)langNode.DataEntry.Size, (uint)Math.Max(0, Data.Length - off));
        var buf = new byte[size];
        Array.Copy(Data, off, buf, 0, size);
        return buf;
    }

    private ResourceEntry FindResourceChild(ResourceDirectory dir, object key)
    {
        foreach (var e in dir.Entries)
        {
            if (key is ushort)
            {
            	ushort id = (ushort)key;
                if (e.Id.HasValue && e.Id.Value == id) return e;
            }
            else if (key is string)
            {
            	string s = key as string;
                if (e.Name != null && string.Equals(e.Name, s, StringComparison.OrdinalIgnoreCase)) return e;
            }
        }
        return null;
    }

    #endregion
}

}
