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
    #region IMPORTS

    private void ParseImportTable(uint importTableRva, uint importTableSize)
    {
        Imports.Clear();
        int descSize = Marshal.SizeOf(typeof(IMAGE_IMPORT_DESCRIPTOR));
        int tableOffset = RvaToOffset(importTableRva);
        if (tableOffset < 0) return;

        int cur = tableOffset;

        while (cur + descSize <= Data.Length)
        {
            IMAGE_IMPORT_DESCRIPTOR desc = Helpers.FromBytes<IMAGE_IMPORT_DESCRIPTOR>(Data, cur);

            // All-zero descriptor => end of table.
            if (desc.OriginalFirstThunk == 0 && desc.Name == 0 && desc.FirstThunk == 0 &&
                desc.TimeDateStamp == 0 && desc.ForwarderChain == 0)
                break;

            var importDesc = new ImportDescriptor();
            importDesc.DLLName = ReadAsciiStringAtRva(desc.Name) ?? string.Empty;

            // Some files omit OriginalFirstThunk, so use FirstThunk as fallback.
            uint sourceThunkRva = desc.OriginalFirstThunk != 0 ? desc.OriginalFirstThunk : desc.FirstThunk;
            int thunkOffset = RvaToOffset(sourceThunkRva);

            if (thunkOffset >= 0)
            {
                if (Is64Bit)
                {
                    int pos = thunkOffset;
                    while (pos + 8 <= Data.Length)
                    {
                        ulong entry = BitConverter.ToUInt64(Data, pos);
                        if (entry == 0) break;

                        var ie = new ImportEntry
                        {
                            IATRVA = desc.FirstThunk + (uint)(pos - thunkOffset),
                            OriginalThunkRVA = sourceThunkRva + (uint)(pos - thunkOffset)
                        };

                        const ulong ORD64 = 0x8000000000000000UL;
                        if ((entry & ORD64) != 0)
                        {
                            ie.ByOrdinal = true;
                            ie.Ordinal = (ushort)(entry & 0xFFFF);
                        }
                        else
                        {
                            int hintOff = RvaToOffset((uint)entry);
                            int nameOff = RvaToOffset((uint)entry + 2);
                            if (hintOff >= 0) ie.Hint = BitConverter.ToUInt16(Data, hintOff);
                            if (nameOff >= 0) ie.Name = ReadAsciiStringAtOffset(nameOff);
                            ie.ByOrdinal = false;
                        }

                        importDesc.Entries.Add(ie);
                        pos += 8;
                    }
                }
                else
                {
                    int pos = thunkOffset;
                    while (pos + 4 <= Data.Length)
                    {
                        uint entry = BitConverter.ToUInt32(Data, pos);
                        if (entry == 0) break;

                        var ie = new ImportEntry
                        {
                            IATRVA = desc.FirstThunk + (uint)(pos - thunkOffset),
                            OriginalThunkRVA = sourceThunkRva + (uint)(pos - thunkOffset)
                        };

                        const uint ORD32 = 0x80000000U;
                        if ((entry & ORD32) != 0)
                        {
                            ie.ByOrdinal = true;
                            ie.Ordinal = (ushort)(entry & 0xFFFF);
                        }
                        else
                        {
                            int hintOff = RvaToOffset(entry);
                            int nameOff = RvaToOffset(entry + 2);
                            if (hintOff >= 0) ie.Hint = BitConverter.ToUInt16(Data, hintOff);
                            if (nameOff >= 0) ie.Name = ReadAsciiStringAtOffset(nameOff);
                            ie.ByOrdinal = false;
                        }

                        importDesc.Entries.Add(ie);
                        pos += 4;
                    }
                }
            }

            Imports.Add(importDesc);
            cur += descSize;
        }
    }

    // read an ASCII string given a direct file offset (not RVA).
    private string ReadAsciiStringAtOffset(int off)
    {
        if (off < 0 || off >= Data.Length) return null;
        int pos = off;
        var sb = new StringBuilder();
        while (pos < Data.Length && Data[pos] != 0)
        {
            sb.Append((char)Data[pos]);
            pos++;
        }
        return sb.ToString();
    }

    #endregion

    #region D-LOAD IMPORTS

    // this is similar to regular imports but has its own table format
    // Aaaalso, these technically are regular imports but loaded on-demand by the loader.
    private void ParseDelayImports(uint rva, uint size)
    {
        DelayImports.Clear();
        int baseOffset = RvaToOffset(rva);
        if (baseOffset < 0) return;
        int descSize = Marshal.SizeOf(typeof(IMAGE_DELAYLOAD_DESCRIPTOR));

        int cur = baseOffset;
        while (cur + descSize <= Data.Length)
        {
            var d = Helpers.FromBytes<IMAGE_DELAYLOAD_DESCRIPTOR>(Data, cur);

            // A table of zeros indicates termination.
            if (d.AllAttributes == 0 && d.DllNameRVA == 0 && d.ModuleHandleRVA == 0 &&
                d.ImportAddressTableRVA == 0 && d.DelayImportNameTableRVA == 0)
                break;

            var dd = new DelayImportDescriptor
            {
                Attributes = d.AllAttributes,
                DllName = ReadAsciiStringAtRva(d.DllNameRVA) ?? string.Empty
            };

            uint nameTblRva = d.DelayImportNameTableRVA;
            if (nameTblRva != 0)
            {
                int thunkOffset = RvaToOffset(nameTblRva);
                if (thunkOffset >= 0)
                {
                    if (Is64Bit)
                    {
                        int pos = thunkOffset;
                        while (pos + 8 <= Data.Length)
                        {
                            ulong entry = BitConverter.ToUInt64(Data, pos);
                            if (entry == 0) break;

                            var ie = new ImportEntry
                            {
                                IATRVA = d.ImportAddressTableRVA + (uint)(pos - thunkOffset),
                                OriginalThunkRVA = nameTblRva + (uint)(pos - thunkOffset)
                            };

                            const ulong ORD64 = 0x8000000000000000UL;
                            if ((entry & ORD64) != 0)
                            {
                                ie.ByOrdinal = true; ie.Ordinal = (ushort)(entry & 0xFFFF);
                            }
                            else
                            {
                                int hintOff = RvaToOffset((uint)entry);
                                int nameOff = RvaToOffset((uint)entry + 2);
                                if (hintOff >= 0) ie.Hint = BitConverter.ToUInt16(Data, hintOff);
                                if (nameOff >= 0) ie.Name = ReadAsciiStringAtOffset(nameOff);
                                ie.ByOrdinal = false;
                            }

                            dd.Entries.Add(ie);
                            pos += 8;
                        }
                    }
                    else
                    {
                        int pos = thunkOffset;
                        while (pos + 4 <= Data.Length)
                        {
                            uint entry = BitConverter.ToUInt32(Data, pos);
                            if (entry == 0) break;

                            var ie = new ImportEntry
                            {
                                IATRVA = d.ImportAddressTableRVA + (uint)(pos - thunkOffset),
                                OriginalThunkRVA = nameTblRva + (uint)(pos - thunkOffset)
                            };

                            const uint ORD32 = 0x80000000U;
                            if ((entry & ORD32) != 0)
                            {
                                ie.ByOrdinal = true; ie.Ordinal = (ushort)(entry & 0xFFFF);
                            }
                            else
                            {
                                int hintOff = RvaToOffset(entry);
                                int nameOff = RvaToOffset(entry + 2);
                                if (hintOff >= 0) ie.Hint = BitConverter.ToUInt16(Data, hintOff);
                                if (nameOff >= 0) ie.Name = ReadAsciiStringAtOffset(nameOff);
                                ie.ByOrdinal = false;
                            }

                            dd.Entries.Add(ie);
                            pos += 4;
                        }
                    }
                }
            }

            DelayImports.Add(dd);
            cur += descSize;
        }
    }

    #endregion
}

}
