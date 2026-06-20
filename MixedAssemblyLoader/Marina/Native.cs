using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Marina
{
/// <summary>
/// Defines native Win32 functions and constants for process memory manipulation.
/// </summary>
public static class Native
{
    // Memory
    public const uint MEM_COMMIT = 0x1000;
    public const uint MEM_RESERVE = 0x2000;
    public const uint PAGE_EXECUTE_READ_WRITE = 0x40;
    public const uint MEM_RELEASE = 0x8000;

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAlloc(
        IntPtr lpAddress,
        UIntPtr dwSize,
        uint flAllocationType,
        uint flProtect
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualFree(
        IntPtr lpAddress,
        UIntPtr dwSize,
        uint dwFreeType
    );

    // Modules
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, IntPtr procOrdinal);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    public static extern IntPtr LoadLibraryA(string lpFileName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool FreeLibrary(IntPtr hModule);

    // Threading
    public const uint DLL_PROCESS_ATTACH = 1;
    public const uint DLL_PROCESS_DETACH = 0;
    public const uint INFINITE = 0xFFFFFFFF;

    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateThread(
        IntPtr lpThreadAttributes,
        uint dwStackSize,
        IntPtr lpStartAddress,
        IntPtr lpParameter,
        uint dwCreationFlags,
        out uint lpThreadId
    );

    [DllImport("kernel32.dll")]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);

    // Delegate for DLL Entry Points (and TLS Callbacks)
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate bool DllMain(IntPtr hinstDLL, uint fdwReason, IntPtr lpvReserved);

    // Delegate for EXE Entry Points
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate void ExeMain();
}

}
