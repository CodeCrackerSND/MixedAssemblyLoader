//using Marina;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Linq.Expressions;

namespace Marina
{
	public static class NameOf
{
    // property / field
    public static string Get<T>(Expression<Func<T>> expr)
    {
        return ((MemberExpression)expr.Body).Member.Name;
    }

    // method
    public static string Get(Expression<Action> expr)
    {
        return ((MethodCallExpression)expr.Body).Method.Name;
    }

    // type
    public static string Get<T>()
    {
        return typeof(T).Name;
    }
}

public partial class PEBinary
{
    #region EXECUTION & LOADING

    /// <summary>
    /// Crux of the logic:
    /// 1) Build a mapped image (managed).
    /// 2) Allocate RWX native memory.
    /// 3) Apply relocations for the chosen native base.
    /// 4) Resolve imports and write into the IAT(s).
    /// 5) Copy image to native memory and return its base address.
    /// 
    /// This intentionally mirrors Windows loader steps roughly, don't expect perfect parity, I am not a god
    /// </summary>
    public IntPtr LoadImage(ImportResolver resolver)
    {
        if (resolver == null) throw new ArgumentNullException("ImportResolver");

        // build a mapped image buffer we can patch.
        BuildImageBuffer(); // side-effect: sets this.Image
        if (this.Image == null) throw new InvalidOperationException("BuildImageBuffer() failed.");

        // allocate native executable memory (RWX for simplicity).
        IntPtr nativeBase = Native.VirtualAlloc(
            IntPtr.Zero,
            (UIntPtr)this.Image.Length,
            Native.MEM_COMMIT | Native.MEM_RESERVE,
            Native.PAGE_EXECUTE_READ_WRITE
        );

        if (nativeBase == IntPtr.Zero)
            throw new Exception("Failed to allocate executable memory.");

        // apply relocations to the in-memory image (Image[]), using the newly chosen base.
        ApplyRelocations((ulong)nativeBase);

        // resolve imports (both regular and delay-load) and write addresses into IAT.
        EmulateIATWrite(resolver);

        // copy patched image into native memory.
        Marshal.Copy(this.Image, 0, nativeBase, this.Image.Length);

        return nativeBase;
    }

    /// <summary>
    /// Execute TLS callbacks (if any). Must be invoked before the module's entry point.
    /// This mirrors what the real loader does: callbacks are invoked in the loader's context.
    /// </summary>
    private void ExecuteTLSCallbacks(IntPtr nativeBase)
    {
        if (TLS == null || TLS.CallbackRVAs.Count == 0)
            return;

        foreach (uint rva in TLS.CallbackRVAs)
        {
            if (rva == 0) continue;
            IntPtr pCallback = IntPtr.Add(nativeBase, (int)rva);
            var cb = Marshal.GetDelegateForFunctionPointer<Native.DllMain>(pCallback);

            // DLL_PROCESS_ATTACH semantics.
            cb(nativeBase, Native.DLL_PROCESS_ATTACH, IntPtr.Zero);
        }
    }

    /// <summary>
    /// Execute an already-loaded image.
    /// - TLS callbacks are invoked.
    /// - For DLLs: DllMain(ATTACH) is called inline on current thread.
    /// - For EXEs: entry point is launched in a new thread (optionally waited upon).
    /// Returns thread handle for EXE threads, IntPtr.Zero for DLLs or on failure.
    /// </summary>
    public IntPtr ExecuteLoadedImage(IntPtr nativeBase, bool waitForThread)
    {
        if (nativeBase == IntPtr.Zero)
            throw new ArgumentException("nativeBase cannot be zero.");

        // TLS callbacks
        ExecuteTLSCallbacks(nativeBase);

        // Entry point RVA
        uint entryRva = AddressOfEntryPoint;
        if (entryRva == 0)
            return IntPtr.Zero;

        IntPtr pEntry = IntPtr.Add(nativeBase, (int)entryRva);

        if (IsDll)
        {
            // Call DllMain(ATTACH) in the current thread.
            var dllMain = Marshal.GetDelegateForFunctionPointer<Native.DllMain>(pEntry);
            dllMain(nativeBase, Native.DLL_PROCESS_ATTACH, IntPtr.Zero);
            return IntPtr.Zero;
        }
        else
        {
            // Launch EXE entry point in a new thread (signature matches CreateThread style).
            uint _ = 0;
            IntPtr hThread = Native.CreateThread(
                IntPtr.Zero, 0,
                pEntry,
                IntPtr.Zero, // no lpParameter
                0,           // run immediately
                out _
            );

            if (waitForThread && hThread != IntPtr.Zero)
            {
                Native.WaitForSingleObject(hThread, Native.INFINITE);
                Native.CloseHandle(hThread);
                return IntPtr.Zero;
            }

            return hThread;
        }
    }

    /// <summary>
    /// Unload an image previously allocated via LoadImage.
    /// Calls DllMain(DETACH) if appropriate and then frees memory.
    /// This is best-effort; swallow exceptions during DllMain to avoid leaving process in a bad state.
    /// </summary>
    public void UnloadImage(IntPtr nativeBase)
    {
        if (nativeBase == IntPtr.Zero) return;

        if (IsDll && AddressOfEntryPoint != 0)
        {
            try
            {
                IntPtr pEntry = IntPtr.Add(nativeBase, (int)AddressOfEntryPoint);
                var dllMain = Marshal.GetDelegateForFunctionPointer<Native.DllMain>(pEntry);
                dllMain(nativeBase, Native.DLL_PROCESS_DETACH, IntPtr.Zero);
            }
            catch
            {
                // Best-effort cleanup; swallow and proceed to free memory.
            }
        }

        Native.VirtualFree(nativeBase, UIntPtr.Zero, Native.MEM_RELEASE);
    }

    #endregion
}

}
