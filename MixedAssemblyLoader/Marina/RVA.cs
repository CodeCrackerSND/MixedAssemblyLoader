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
    #region RVA helpers

    /// <summary>
    /// Convert RVA -> file offset in Data[].
    /// Returns -1 for invalid/unmapped RVA (like .bss).
    /// This function errs on the side of safety rather than optimism, hehe
    /// </summary>
    public int RvaToOffset(uint rva)
    {
        uint hdrSize = GetSizeOfHeaders();

        // If the RVA is within headers, it's a direct mapping (if file contains that many bytes)
        if (rva < hdrSize)
        {
            // ensure we don't return an offset beyond the file
            if (rva >= Data.Length) return -1;
            return (int)rva;
        }

        // Otherwise, find the section that contains this RVA.
        foreach (var s in SectionHeaders)
        {
            uint secVa = s.VirtualAddress;
            uint secVirtualSize = s.VirtualSize;  // size in memory
            uint secRawSize = s.SizeOfRawData;    // size on disk

            // If the RVA is within the memory area of the section
            if (rva >= secVa && rva < secVa + secVirtualSize)
            {
                uint offsetInSection = rva - secVa;

                // If offset falls into uninitialized (virtual-only) tail, there is no file data.
                if (offsetInSection >= secRawSize)
                {
                    return -1;
                }

                int fileOff = (int)(s.PointerToRawData + offsetInSection);

                // Sanity check
                if (fileOff < 0 || fileOff + (secRawSize - offsetInSection) > Data.Length)
                {
                    return -1;
                }

                return fileOff;
            }
        }

        // Not found in any section, invalid RVA.
        return -1;
    }

    // Read a null-terminated ASCII string from file using an RVA.
    // Returns null on error.
    private string ReadAsciiStringAtRva(uint rva)
    {
        int off = RvaToOffset(rva);
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
}

}
