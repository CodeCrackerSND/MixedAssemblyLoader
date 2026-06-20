////using Marina;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace Marina
{
public partial class PEBinary
{
    #region Exports

    // self-explanatory
    private void ParseExportTable(uint exportTableRva, uint exportTableSize)
    {
        Exports.Clear();
        int dirFileOffset = RvaToOffset(exportTableRva);
        if (dirFileOffset < 0) return;
        if (dirFileOffset + Marshal.SizeOf(typeof(IMAGE_EXPORT_DIRECTORY)) > Data.Length) return;

        IMAGE_EXPORT_DIRECTORY ed = Helpers.FromBytes<IMAGE_EXPORT_DIRECTORY>(Data, dirFileOffset);

        int funcsOff = RvaToOffset(ed.AddressOfFunctions);
        int namesOff = RvaToOffset(ed.AddressOfNames);
        int ordsOff = RvaToOffset(ed.AddressOfNameOrdinals);

        if (funcsOff < 0 || namesOff < 0 || ordsOff < 0) return;

        for (uint i = 0; i < ed.NumberOfNames; i++)
        {
            uint nameRva = BitConverter.ToUInt32(Data, namesOff + (int)(i * 4));
            int nameOff = RvaToOffset(nameRva);
            if (nameOff < 0) continue;
            string name = ReadAsciiStringAtRva(nameRva);

            ushort ordinalIndex = BitConverter.ToUInt16(Data, ordsOff + (int)(i * 2));
            uint funcRva = BitConverter.ToUInt32(Data, funcsOff + (int)(ordinalIndex * 4));

            Exports.Add(new ExportEntry
            {
                Name = name,
                Ordinal = (ushort)(ed.Base + ordinalIndex),
                AddressRva = funcRva
            });
        }
    }

    #endregion
}

}