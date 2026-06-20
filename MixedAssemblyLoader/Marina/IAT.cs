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
    #region IAT Emu

    public delegate ulong ImportResolver(string dllName, string functionNameOrNull, ushort? ordinalOrNull);

    /// <summary>
    /// Resolve imports via the provided resolver and write pointers into the image IAT.
    /// Handles both regular imports and delay-load tables.
    /// </summary>
    public void EmulateIATWrite(ImportResolver resolver)
    {
        if (Image == null) throw new InvalidOperationException("Call BuildImageBuffer() first.");
        if (resolver == null) throw new ArgumentNullException("ImportResolver");

        // Regular imports
        foreach (var imp in Imports)
        {
            foreach (var ent in imp.Entries)
            {
                ulong resolved = ent.ByOrdinal
                    ? resolver(imp.DLLName, null, ent.Ordinal)
                    : resolver(imp.DLLName, ent.Name, null);

                WritePointerToImage(ent.IATRVA, resolved);
            }
        }

        // Delay-load imports
        foreach (var dp in DelayImports)
        {
            foreach (var ent in dp.Entries)
            {
                ulong resolved = ent.ByOrdinal
                    ? resolver(dp.DllName, null, ent.Ordinal)
                    : resolver(dp.DllName, ent.Name, null);

                WritePointerToImage(ent.IATRVA, resolved);
            }
        }
    }

    private void WritePointerToImage(uint rva, ulong value)
    {
        int idx = RvaToImageIndex(rva);
        if (idx < 0) return;

        if (Is64Bit)
        {
            if (idx + 8 <= Image.Length) WriteUInt64(Image, idx, value);
        }
        else
        {
            if (idx + 4 <= Image.Length) WriteUInt32(Image, idx, (uint)value);
        }
    }

    #endregion
}

}