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
    #region BUILD IMAGE (headers + sections)

    public byte[] BuildImageBuffer()
    {
        uint imageSize = SizeOfImage;
        if (imageSize == 0) throw new Exception("SizeOfImage is zero, cannot build image.");

        var mapped = new byte[imageSize];

        // Copy the headers (but don't exceed the file's length).
        uint hdrSize = GetSizeOfHeaders();
        int copyLen = (int)Math.Min(hdrSize == 0 ? (uint)Data.Length : hdrSize, (uint)Data.Length);
        Array.Copy(Data, 0, mapped, 0, copyLen);

        // Copy sections into their virtual addresses inside the image buffer.
        foreach (var sec in SectionHeaders)
        {
            if (sec.SizeOfRawData == 0) continue;

            int srcOffset = (int)sec.PointerToRawData;
            if (srcOffset < 0 || srcOffset >= Data.Length) continue;

            int dstOffset = (int)sec.VirtualAddress;
            // We copy up to the lesser of raw size and virtual size.
            uint bytesToCopy = Math.Min(sec.SizeOfRawData, sec.VirtualSize);

            // Oppsie check: don't read past the file.
            if (srcOffset + bytesToCopy > Data.Length)
                bytesToCopy = (uint)Math.Max(0, Data.Length - srcOffset);

            // Opsie check v2: don't write past the image buffer either.
            if (dstOffset + bytesToCopy > mapped.Length)
                bytesToCopy = (uint)Math.Max(0, mapped.Length - dstOffset);

            if (bytesToCopy > 0)
                Array.Copy(Data, srcOffset, mapped, dstOffset, (int)bytesToCopy);

            // If virtual size is larger than raw size, zero the remainder (BSS-like).
            if (sec.VirtualSize > sec.SizeOfRawData)
            {
                int padStart = dstOffset + (int)sec.SizeOfRawData;
                int padLen = (int)Math.Min((ulong)(sec.VirtualSize - sec.SizeOfRawData), (ulong)(mapped.Length - padStart));
                if (padStart >= 0 && padLen > 0 && padStart + padLen <= mapped.Length)
                    Array.Clear(mapped, padStart, padLen);
            }
        }

        Image = mapped; // keep a reference for further patching
        return mapped;
    }

    // Convert an RVA relative to the mapped image produced by BuildImageBuffer() into an index
    private int RvaToImageIndex(uint rva)
    {
        if (Image == null) throw new InvalidOperationException("Call BuildImageBuffer() first.");
        if (rva >= Image.Length) return -1;
        return (int)rva;
    }

    /// <summary>
    /// A tiny resolver cache used by the DefaultWin32Resolver so we don't call LoadLibrary repeatedly.
    /// Not thread-safe intentionally since this is for tooling, not a high-concurrency server.
    /// </summary>
    private static Dictionary<string, IntPtr> _resolverModuleCache = new Dictionary<string, IntPtr>(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Default resolver: LoadLibraryA + GetProcAddress.
    /// Returns 0 when resolution fails.
    /// </summary>
    public static ulong DefaultWin32Resolver(string dllName, string functionName, ushort? ordinal)
    {
        IntPtr hMod;
        if (!_resolverModuleCache.TryGetValue(dllName, out hMod))
        {
            hMod = Native.LoadLibraryA(dllName);
            if (hMod == IntPtr.Zero)
            {
                // intentional silence: callers may expect missing imports in some analysis scenarios.
                return 0;
            }
            _resolverModuleCache[dllName] = hMod;
        }

        IntPtr pFn = IntPtr.Zero;
        if (functionName != null)
        {
            pFn = Native.GetProcAddress(hMod, functionName);
        }
        else if (ordinal.HasValue)
        {
            // GetProcAddress accepts ordinals as IntPtr on Win32.
            pFn = Native.GetProcAddress(hMod, (IntPtr)ordinal.Value);
        }

        return (ulong)pFn;
    }

    /// <summary>
    /// Free everything in the static resolver cache. Best-effort.
    /// </summary>
    public static void ClearResolverCache()
    {
        foreach (var kv in _resolverModuleCache)
        {
            Native.FreeLibrary(kv.Value);
        }
        _resolverModuleCache.Clear();
    }

    #endregion
}

}