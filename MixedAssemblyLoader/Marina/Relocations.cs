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
    #region Base Reloc

    // this is a bit more involved
    // we are essentially reading blocks of relocations
    // each block has a header and then a list of type/offset entries
    // we store them in BaseRelocations list for later processing
    private void ParseBaseRelocations(uint baseRelocRva, uint baseRelocSize)
    {
        BaseRelocations.Clear();
        int curOff = RvaToOffset(baseRelocRva);
        if (curOff < 0) return;
        int endOff = curOff + (int)baseRelocSize;

        while (curOff + Marshal.SizeOf(typeof(IMAGE_BASE_RELOCATION)) <= Data.Length && curOff < endOff)
        {
            IMAGE_BASE_RELOCATION hdr = Helpers.FromBytes<IMAGE_BASE_RELOCATION>(Data, curOff);
            if (hdr.SizeOfBlock == 0) break;

            var block = new BaseRelocBlock { VirtualAddress = hdr.VirtualAddress, SizeOfBlock = hdr.SizeOfBlock };
            int entriesStart = curOff + Marshal.SizeOf(typeof(IMAGE_BASE_RELOCATION));
            int entriesCount = ((int)hdr.SizeOfBlock - Marshal.SizeOf(typeof(IMAGE_BASE_RELOCATION))) / 2;

            for (int i = 0; i < entriesCount; i++)
            {
                if (entriesStart + i * 2 + 2 > Data.Length) break;
                ushort entry = BitConverter.ToUInt16(Data, entriesStart + i * 2);
                block.TypeOffsetList.Add(entry);
            }

            BaseRelocations.Add(block);
            curOff += (int)hdr.SizeOfBlock;
        }
    }

    /// <summary>
    /// Apply relocations into Image[] if newBase != ImageBase.
    /// You must call BuildImageBuffer() first.
    /// </summary>
    public void ApplyRelocations(ulong newBase)
    {
        if (Image == null) throw new InvalidOperationException("Call BuildImageBuffer() first.");
        if (newBase == ImageBase) return; // nothing to patch

        long delta = unchecked((long)(newBase - ImageBase));

        foreach (var block in BaseRelocations)
        {
            uint pageRva = block.VirtualAddress;
            foreach (ushort entry in block.TypeOffsetList)
            {
                int type = (entry >> 12) & 0xF;
                int offset = entry & 0x0FFF;
                uint fixRva = pageRva + (uint)offset;
                int imgIdx = RvaToImageIndex(fixRva);
                if (imgIdx < 0) continue;

                switch (type)
                {
                    case 0: // ABSOLUTE: padding, skip.
                        break;

                    case 3: // HIGHLOW (32-bit patch)
                        if (imgIdx + 4 <= Image.Length)
                        {
                            int orig = BitConverter.ToInt32(Image, imgIdx);
                            int patched = unchecked(orig + (int)delta);
                            WriteInt32(Image, imgIdx, patched);
                        }
                        break;

                    case 10: // DIR64 (64-bit)
                        if (imgIdx + 8 <= Image.Length)
                        {
                            long orig = BitConverter.ToInt64(Image, imgIdx);
                            long patched = unchecked(orig + delta);
                            WriteInt64(Image, imgIdx, patched);
                        }
                        break;

                    case 1: // HIGH (rare): add high 16 bits of delta
                        if (imgIdx + 2 <= Image.Length)
                        {
                            short orig = BitConverter.ToInt16(Image, imgIdx);
                            short patched = (short)(orig + ((delta >> 16) & 0xFFFF));
                            WriteInt16(Image, imgIdx, patched);
                        }
                        break;

                    case 2: // LOW (rare): add low 16 bits
                        if (imgIdx + 2 <= Image.Length)
                        {
                            short orig = BitConverter.ToInt16(Image, imgIdx);
                            short patched = (short)(orig + (delta & 0xFFFF));
                            WriteInt16(Image, imgIdx, patched);
                        }
                        break;

                    default:
                        // Ignore exotic relocation types for now. Most userland binaries won't need them.
                        break;
                }
            }
        }
    }

    #endregion
}

}
