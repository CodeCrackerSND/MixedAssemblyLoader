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
    #region TLS

    // ahem, this one too is a bit involved
    // we need to read the TLS directory and then read the callback list
    // The callback list==null-terminated and contains either RVAs or VAs.
    private void ParseTLS(uint rva, uint size)
    {
        int off = RvaToOffset(rva);
        if (off < 0) return;

        if (Is64Bit)
        {
            if (off + Marshal.SizeOf(typeof(IMAGE_TLS_DIRECTORY64)) > Data.Length) return;
            var t = Helpers.FromBytes<IMAGE_TLS_DIRECTORY64>(Data, off);
            TLS = new TLSDirectory
            {
                StartAddressOfRawData = t.StartAddressOfRawData,
                EndAddressOfRawData = t.EndAddressOfRawData,
                AddressOfIndex = t.AddressOfIndex,
                AddressOfCallBacks = t.AddressOfCallBacks,
                SizeOfZeroFill = t.SizeOfZeroFill,
                Characteristics = t.Characteristics,
                CallbackRVAs = ReadTLSCallbacks(t.AddressOfCallBacks)
            };
        }
        else
        {
            if (off + Marshal.SizeOf(typeof(IMAGE_TLS_DIRECTORY32)) > Data.Length) return;
            var t = Helpers.FromBytes<IMAGE_TLS_DIRECTORY32>(Data, off);
            TLS = new TLSDirectory
            {
                StartAddressOfRawData = t.StartAddressOfRawData,
                EndAddressOfRawData = t.EndAddressOfRawData,
                AddressOfIndex = t.AddressOfIndex,
                AddressOfCallBacks = t.AddressOfCallBacks,
                SizeOfZeroFill = t.SizeOfZeroFill,
                Characteristics = t.Characteristics,
                CallbackRVAs = ReadTLSCallbacks(t.AddressOfCallBacks)
            };
        }
    }

    private List<uint> ReadTLSCallbacks(ulong addressOfCallbacksVA)
    {
        // The field in the TLS directory may contain either VA or RVA.
        // If VA, convert to RVA by subtracting ImageBase; otherwise treat as RVA directly.
        if (addressOfCallbacksVA == 0) return new List<uint>();

        ulong callbacksVa = addressOfCallbacksVA;
        if (callbacksVa >= ImageBase)
        {
            ulong rva64 = callbacksVa - ImageBase;
            if (rva64 > uint.MaxValue) return new List<uint>();
            uint callbacksRva = (uint)rva64;
            int off = RvaToOffset(callbacksRva);
            return ReadTLSCallbacksAtOffset(off);
        }
        else
        {
            // Some builders store RVA here; try that.
            uint callbacksRva = (uint)callbacksVa;
            int off = RvaToOffset(callbacksRva);
            return ReadTLSCallbacksAtOffset(off);
        }
    }

    private List<uint> ReadTLSCallbacksAtOffset(int off)
    {
        var list = new List<uint>();
        if (off < 0) return list;

        if (Is64Bit)
        {
            int cur = off;
            while (cur + 8 <= Data.Length)
            {
                ulong va = BitConverter.ToUInt64(Data, cur);
                if (va == 0) break;
                if (va >= ImageBase && (va - ImageBase) <= uint.MaxValue)
                    list.Add((uint)(va - ImageBase));
                cur += 8;
            }
        }
        else
        {
            int cur = off;
            while (cur + 4 <= Data.Length)
            {
                uint va = BitConverter.ToUInt32(Data, cur);
                if (va == 0) break;
                if (va >= (uint)ImageBase)
                    list.Add(va - (uint)ImageBase);
                cur += 4;
            }
        }

        return list;
    }

    #endregion
}

}
