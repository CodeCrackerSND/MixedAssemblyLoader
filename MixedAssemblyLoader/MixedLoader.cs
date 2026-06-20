/*
 * Created by SharpDevelop.
 * User: CodeCracker
 * Date: 3/4/2017
 * Time: 7:55 PM
 * 
 * To change this template use Tools | Options | Coding | Edit Standard Headers.
 */
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Collections;
using System.Text;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Forms;
using System.Diagnostics;
// https://github.com/ApparentlyPlus/Marina
using Marina;

namespace MixedAssemblyLoader
{
	
	public static class DotNetAssemblyInfo
	{
		
		private const uint COMIMAGE_FLAGS_ILONLY = 0x00000001;
		private const uint COMIMAGE_FLAGS_32BITREQUIRED = 0x00000002;
		
		public static bool IsMixedModeAssembly(string fileName)
		{
			FileStream fs = null;
			BinaryReader br = null;

			try
			{
				fs = new FileStream(fileName, FileMode.Open, FileAccess.Read);
				br = new BinaryReader(fs);

				// DOS header -> e_lfanew
				fs.Position = 0x3C;
				int peOffset = br.ReadInt32();

				// PE Optional Header Magic
				fs.Position = peOffset + 0x18;
				ushort magic = br.ReadUInt16();

				bool pe32Plus = (magic == 0x20B);

				// CLI Header Data Directory (entry #14)
				long cliDirOffset;

				if (pe32Plus)
					cliDirOffset = peOffset + 0x18 + 0x70 + (14 * 8);
				else
					cliDirOffset = peOffset + 0x18 + 0x60 + (14 * 8);

				fs.Position = cliDirOffset;

				uint cliRva = br.ReadUInt32();
				uint cliSize = br.ReadUInt32();

				if (cliRva == 0)
					return false; // Native assembly

				// Number of sections
				fs.Position = peOffset + 6;
				ushort numberOfSections = br.ReadUInt16();

				long sectionTable;

				if (pe32Plus)
					sectionTable = peOffset + 0x108;
				else
					sectionTable = peOffset + 0xF8;

				uint cliFileOffset = 0;

				int i;
				for (i = 0; i < numberOfSections; i++)
				{
					fs.Position = sectionTable + (i * 40) + 12;

					uint virtualAddress = br.ReadUInt32();
					uint sizeOfRawData = br.ReadUInt32();
					uint pointerToRawData = br.ReadUInt32();

					if (cliRva >= virtualAddress &&
					    cliRva < virtualAddress + sizeOfRawData)
					{
						cliFileOffset =
							pointerToRawData +
							(cliRva - virtualAddress);

						break;
					}
				}

				if (cliFileOffset == 0)
					return false;

				// IMAGE_COR20_HEADER.Flags
				fs.Position = cliFileOffset + 16;

				uint corFlags = br.ReadUInt32();

				bool ilOnly =
					(corFlags & COMIMAGE_FLAGS_ILONLY) != 0;

				return !ilOnly;
			}
			finally
			{
				if (br != null)
					br.Close();

				if (fs != null)
					fs.Close();
			}
		}
		
		public static bool Is32BitsAssembly(string fileName)
		{
			FileStream fs = null;
			BinaryReader br = null;

			try
			{
				fs = new FileStream(fileName, FileMode.Open, FileAccess.Read);
				br = new BinaryReader(fs);

				// DOS header -> e_lfanew
				fs.Position = 0x3C;
				int peOffset = br.ReadInt32();

				// PE Optional Header Magic
				fs.Position = peOffset + 0x18;
				ushort magic = br.ReadUInt16();

				bool pe32Plus = (magic == 0x20B);

				// CLI Header Data Directory (entry #14)
				long cliDirOffset;

				if (pe32Plus)
					cliDirOffset = peOffset + 0x18 + 0x70 + (14 * 8);
				else
					cliDirOffset = peOffset + 0x18 + 0x60 + (14 * 8);

				fs.Position = cliDirOffset;

				uint cliRva = br.ReadUInt32();
				uint cliSize = br.ReadUInt32();

				if (cliRva == 0)
					return false; // Native assembly

				// Number of sections
				fs.Position = peOffset + 6;
				ushort numberOfSections = br.ReadUInt16();

				long sectionTable;

				if (pe32Plus)
					sectionTable = peOffset + 0x108;
				else
					sectionTable = peOffset + 0xF8;

				uint cliFileOffset = 0;

				int i;
				for (i = 0; i < numberOfSections; i++)
				{
					fs.Position = sectionTable + (i * 40) + 12;

					uint virtualAddress = br.ReadUInt32();
					uint sizeOfRawData = br.ReadUInt32();
					uint pointerToRawData = br.ReadUInt32();

					if (cliRva >= virtualAddress &&
					    cliRva < virtualAddress + sizeOfRawData)
					{
						cliFileOffset =
							pointerToRawData +
							(cliRva - virtualAddress);

						break;
					}
				}

				if (cliFileOffset == 0)
					return false;

				// IMAGE_COR20_HEADER.Flags
				fs.Position = cliFileOffset + 16;

				uint corFlags = br.ReadUInt32();

				bool is32Bits =
					(corFlags & COMIMAGE_FLAGS_32BITREQUIRED) != 0;

				return is32Bits;
			}
			finally
			{
				if (br != null)
					br.Close();

				if (fs != null)
					fs.Close();
			}
		}
		
	}
	
	/// <summary>
	/// Description of MixedLoader.
	/// </summary>
	public class MixedLoader
	{

		public static void Main(string[] args)
		{
			
			string filename = "C:\\NoFuser\\NoFuserEx.exe";
			//filename = "C:\\mixedtest\\BamlRenamer.exe";
			//filename = "C:\\conf\\StringTest.exe";
			//filename = "C:\\conf\\CrackMe - ConfuserEX.exe";
			filename = "D:\\x64\\CrackMex64_nonil.exe";
			
			Assembly asm = MixedLoader.LoadMixedAssembly(filename, false);
			if (asm != null)
				Console.WriteLine("Success!");
			Console.ReadKey(true);
		}

		[DllImport("kernel32.dll")]
		static extern IntPtr GetModuleHandle(string lpModuleName);

		[DllImport("kernel32", CharSet=CharSet.Ansi, ExactSpelling=true, SetLastError=true)]
		static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
		
		[DllImport("kernel32.dll")]
		static extern IntPtr LoadLibrary(string lib);
		
		[StructLayout(LayoutKind.Sequential)]
		private struct ExeContext
		{
			public IntPtr lib;
			public IntPtr func;
			public void ExecuteExe()
			{
				ExecuteEXE execute = (ExecuteEXE) Marshal.GetDelegateForFunctionPointer(this.func, typeof(ExecuteEXE));
				int result = execute(this.lib);
			}
		}

		[StructLayout(LayoutKind.Sequential)]
		private struct DllContext
		{
			public IntPtr lib;
			public IntPtr func;
			public int dwReason;
			public IntPtr lpReserved;
			public bool fFromThunk;
			public void ExecuteDll()
			{
				// dllContext.dwReason = 1;  // DLL_PROCESS_ATTACH
				// dllContext.fFromThunk = false;

				ExecuteDLL execute_dll = (ExecuteDLL) Marshal.GetDelegateForFunctionPointer(this.func, typeof(ExecuteDLL));
				int result = execute_dll(this.lib,dwReason,lpReserved,fFromThunk);
				// result -2146233072 (0x80131510)
				
			}
		}
		
		[StructLayout(LayoutKind.Sequential)]
		private struct DllContextx64
		{
			public IntPtr lib;
			public IntPtr func;
			public int dwReason;
			public IntPtr lpReserved;
			public bool fFromThunk;
			public void ExecuteDll()
			{
				// dllContext.dwReason = 1;  // DLL_PROCESS_ATTACH
				// dllContext.fFromThunk = false;
				ExecuteDLL_X64 execute_dll64 = (ExecuteDLL_X64) Marshal.GetDelegateForFunctionPointer(this.func, typeof(ExecuteDLL_X64));
				//lib = IntPtr.Zero;
				int result = execute_dll64(this.lib,dwReason,lpReserved,fFromThunk);

				
			}
		}
		
		[UnmanagedFunctionPointer(System.Runtime.InteropServices.CallingConvention.StdCall)]
		private delegate int ExecuteEXE(IntPtr hInst);

		[UnmanagedFunctionPointer(System.Runtime.InteropServices.CallingConvention.StdCall)]
		private delegate int ExecuteDLL(IntPtr hInst, int dwReason, IntPtr lpReserved,bool fFromThunk);

		[UnmanagedFunctionPointer(System.Runtime.InteropServices.CallingConvention.StdCall)]
		private delegate int ExecuteDLL_X64(IntPtr hInst, int dwReason, IntPtr lpReserved,bool fFromThunk);
		
		/*
    // For use inside LoadLibrary callback
    friend HRESULT ExecuteDLLForAttach(HINSTANCE hInst,
                                       DWORD dwReason,
                                       LPVOID lpReserved,
									   BOOL fFromThunk);
		 */
		
		[DllImport("kernel32.dll", SetLastError=true)]
		static extern IntPtr VirtualAlloc(IntPtr lpAddress, int dwSize,
		                                  AllocationType flAllocationType, MemoryProtection flProtect);
		
		[Flags()]
		public enum AllocationType:uint
		{
			COMMIT=0x1000,
			RESERVE=0x2000,
			RESET=0x80000,
			LARGE_PAGES=0x20000000,
			PHYSICAL=0x400000,
			TOP_DOWN=0x100000,
			WRITE_WATCH=0x200000
		}

		[Flags()]
		public enum MemoryProtection:uint
		{
			EXECUTE=0x10,
			EXECUTE_READ=0x20,
			EXECUTE_READWRITE=0x40,
			EXECUTE_WRITECOPY=0x80,
			NOACCESS=0x01,
			READONLY=0x02,
			READWRITE=0x04,
			WRITECOPY=0x08,
			GUARD_Modifierflag=0x100,
			NOCACHE_Modifierflag = 0x200,
			WRITECOMBINE_Modifierflag = 0x400
		}
		
		static IntPtr DetourOriginalAddress(IntPtr originalAddress, int parameters_count)
		{  // fast call convention from stdcall convention
			MemoryStream ms = new MemoryStream();
			ms.WriteByte(0x58); // pop eax - store the ret addr

			if (parameters_count > 0)
				ms.WriteByte(0x59); // pop ecx - first parameter

			if (parameters_count > 1)
				ms.WriteByte(0x5A);   // pop edx - second parameter

			ms.WriteByte(0x50); // push eax - retrieve ret addr

			//jump to the original function
			ms.WriteByte(0x68); // push ...
			byte[] original_address = BitConverter.GetBytes((uint)originalAddress);
			ms.Write(original_address,0,original_address.Length);
			ms.WriteByte(0xC3); // ret

			byte[] asmbytes = ms.ToArray();

			IntPtr allocatedPointer = VirtualAlloc(IntPtr.Zero, asmbytes.Length, AllocationType.RESERVE | AllocationType.COMMIT, MemoryProtection.EXECUTE_READWRITE);
			Marshal.Copy(asmbytes, 0, allocatedPointer, asmbytes.Length);

			return allocatedPointer;
		}
		
		
		static IntPtr DetourOriginalAddress64(IntPtr originalAddress, int parameters_count)
		{  // fast call convention from stdcall convention
			MemoryStream ms = new MemoryStream();
			//ms.WriteByte(0x58); // pop eax - store the ret addr

			//if (parameters_count > 0)
			//	ms.WriteByte(0x59); // pop ecx - first parameter

			//if (parameters_count > 1)
			//	ms.WriteByte(0x5A);   // pop edx - second parameter

			//ms.WriteByte(0x50); // push eax - retrieve ret addr

			//488bc4          mov     rax,rsp
			
			byte[] registerOnStack =
			{
				0x48, 0x8B, 0xC4,  // mov     rax,rsp
				0x48, 0x83, 0xEC, 0x58,  // sub     rsp,58h
				0x48, 0x89, 0x88, 0xD8, 0xFF, 0xFF, 0xFF,  // mov     qword ptr [rax-28h],rcx
				0x89, 0x90, 0xE0, 0xFF, 0xFF, 0xFF,  // mov     dword ptr [rax-20h],edx
				0x4C, 0x89, 0x80, 0xE8, 0xFF, 0xFF, 0xFF,  // mov     qword ptr [rax-18h],r8
				0x83, 0xA0, 0xF0, 0xFF, 0xFF, 0xFF, 0x00,  // and     dword ptr [rax-10h],0
				0x83, 0xA0, 0xC8, 0xFF, 0xFF, 0xFF, 0x00,  // and     dword ptr [rax-38h],0
				0x45, 0x33, 0xC9,  // xor     r9d,r9d
			};
			
			//jump to the original function
			ms.WriteByte(0x48); // mov rax, value
			ms.WriteByte(0xB8); // mov rax, value
			
			// 00000000662014EC <powerdvd.OptionalH | 48:B8 C9E7D0B11C000000        | mov rax,1CB1D0E7C9
			// 00000000662014F6                     | 50                            | push rax
			// 00000000662014F7                     | C3                            | ret
			
			byte[] original_address = BitConverter.GetBytes((long)originalAddress);
			ms.Write(original_address,0,original_address.Length);
			ms.WriteByte(0x50); // push rax
			ms.WriteByte(0xC3); // ret

			byte[] asmbytes = ms.ToArray();

			IntPtr allocatedPointer = VirtualAlloc(IntPtr.Zero, asmbytes.Length, AllocationType.RESERVE | AllocationType.COMMIT, MemoryProtection.EXECUTE_READWRITE);
			Marshal.Copy(asmbytes, 0, allocatedPointer, asmbytes.Length);

			return allocatedPointer;
		}
		
		public static unsafe IntPtr GetCallTarget_x64(byte* pInstr)
		{
			// CALL rel32 = E8 xx xx xx xx
			if (pInstr[0] != 0xE8)
				return IntPtr.Zero;

			// read signed 32-bit offset
			int rel = *(int*)(pInstr + 1);

			// address after instruction (5 bytes)
			long next = (long)pInstr + 5;

			long target = next + rel;

			return new IntPtr(target);
			
		}
		
		
		public static IntPtr optionalHeader;
		
		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern bool VirtualProtect(
			IntPtr lpAddress,
			UIntPtr dwSize,
			uint flNewProtect,
			out uint lpflOldProtect);
		
		const uint PAGE_READWRITE = 0x04;
		const uint PAGE_EXECUTE_READWRITE = 0x40;
		
		public static void PatchEntryPoint(IntPtr baseAddress, int newEntryPointRva)
		{
			// e_lfanew is at offset 0x3C in IMAGE_DOS_HEADER
			int e_lfanew = Marshal.ReadInt32(baseAddress, 0x3C);

			IntPtr ntHeaders = IntPtr.Add(baseAddress, e_lfanew);

			// Verify PE signature ("PE\0\0")
			uint signature = (uint)Marshal.ReadInt32(ntHeaders);
			if (signature != 0x4550)
				throw new InvalidOperationException("Invalid PE header.");

			// IMAGE_FILE_HEADER starts after signature (4 bytes)
			// Optional Header starts after FILE_HEADER (20 bytes)
			optionalHeader = IntPtr.Add(ntHeaders, 4 + 20);

			// AddressOfEntryPoint offset:
			// PE32  : 0x10 from OptionalHeader start
			// PE32+ : 0x10 from OptionalHeader start
			int entryPointRva = Marshal.ReadInt32(optionalHeader, 0x10);
			
			UIntPtr size = (UIntPtr)0x4;
			
			IntPtr addressOfEntryPointField =
				IntPtr.Add(baseAddress, e_lfanew + 4 + 20 + 0x10);
			
			uint oldProtect;
			bool ok = VirtualProtect(
				addressOfEntryPointField,
				size,
				PAGE_READWRITE,
				out oldProtect);
			
			Marshal.WriteInt32(addressOfEntryPointField, newEntryPointRva);
			
			ok = VirtualProtect(
				addressOfEntryPointField,
				size,
				oldProtect,
				out oldProtect);
			
		}
		public static int GetEntryPointAddress(IntPtr baseAddress)
		{
			
			// e_lfanew is at offset 0x3C in IMAGE_DOS_HEADER
			int e_lfanew = Marshal.ReadInt32(baseAddress, 0x3C);

			IntPtr ntHeaders = IntPtr.Add(baseAddress, e_lfanew);

			// Verify PE signature ("PE\0\0")
			uint signature = (uint)Marshal.ReadInt32(ntHeaders);
			if (signature != 0x4550)
				throw new InvalidOperationException("Invalid PE header.");

			// IMAGE_FILE_HEADER starts after signature (4 bytes)
			// Optional Header starts after FILE_HEADER (20 bytes)
			optionalHeader = IntPtr.Add(ntHeaders, 4 + 20);

			// AddressOfEntryPoint offset:
			// PE32  : 0x10 from OptionalHeader start
			// PE32+ : 0x10 from OptionalHeader start
			int entryPointRva = Marshal.ReadInt32(optionalHeader, 0x10);

			return entryPointRva;
		}
		
		public static int NewEntryPointRva = 0;
		
		const int PROCESS_VM_READ = 0x0010;
		const int PROCESS_QUERY_INFORMATION = 0x0400;

		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern bool ReadProcessMemory(
			IntPtr hProcess,
			IntPtr lpBaseAddress,
			byte[] lpBuffer,
			int dwSize,
			out IntPtr lpNumberOfBytesRead);
		
		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern IntPtr OpenProcess(
			int dwDesiredAccess,
			bool bInheritHandle,
			int dwProcessId);
		
		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern bool CloseHandle(IntPtr hObject);
		
		public static IntPtr GetSuitableEmptyPlace(IntPtr hProcess, IntPtr imageBase)
		{
			NewEntryPointRva = 0;
			int e_lfanew = Marshal.ReadInt32(imageBase, 0x3C);

			IntPtr ntHeaders = IntPtr.Add(imageBase, e_lfanew);

			// Verify PE signature
			if ((uint)Marshal.ReadInt32(ntHeaders) != 0x4550)
				throw new Exception("Invalid PE");

			ushort numberOfSections =
				(ushort)Marshal.ReadInt16(ntHeaders, 6);
			
			if (numberOfSections==0)
				return IntPtr.Zero;

			ushort sizeOfOptionalHeader =
				(ushort)Marshal.ReadInt16(ntHeaders, 20);

			IntPtr sectionHeader =
				IntPtr.Add(ntHeaders, 24 + sizeOfOptionalHeader);

			// long highestEnd = 0;

			//const uint IMAGE_SCN_MEM_EXECUTE = 0x20000000;
			
			//for (int i = 0; i < numberOfSections; i++)
			// {
			IntPtr section =
				IntPtr.Add(sectionHeader, 0 * 40);  // first section

			uint virtualSize =
				(uint)Marshal.ReadInt32(section, 8);

			uint virtualAddress =
				(uint)Marshal.ReadInt32(section, 12);

			//uint characteristics =
			//    (uint)Marshal.ReadInt32(section, 36);

			//if ((characteristics & IMAGE_SCN_MEM_EXECUTE) == 0)
			//    continue;

			//long SectionEnd =
			
			long PosGoodPlacelong = imageBase.ToInt64() + virtualAddress + virtualSize-16;
			IntPtr PosGoodPlaceIntrPtr = new IntPtr(PosGoodPlacelong);
			byte[] buffer = new byte[16];

			IntPtr bytesRead;
			bool ok = ReadProcessMemory(
				hProcess,
				PosGoodPlaceIntrPtr,
				buffer,
				buffer.Length,
				out bytesRead);
			
			if (ok&&bytesRead.ToInt32()==16)
			{
				
				bool AllZeros = true;
				for (int i=0;i<buffer.Length;i++)
				{
					if (buffer[i]!=0)
					{
						AllZeros = false;
						break;
					}
					
				}
				
				if (AllZeros)
				{
					uint oldProtect;
					ok = VirtualProtect(
						PosGoodPlaceIntrPtr,
						(UIntPtr)0x1,
						PAGE_EXECUTE_READWRITE,
						out oldProtect);
					if (ok)
					{
						Marshal.WriteByte(PosGoodPlaceIntrPtr, 0xC3);
						if (Marshal.ReadByte(PosGoodPlaceIntrPtr)==0xC3)
						{
							long EntryPointVA = PosGoodPlaceIntrPtr.ToInt64();
							EntryPointVA -= imageBase.ToInt64();
							NewEntryPointRva = (int)EntryPointVA;
						}
					}
					
				}
				
			}

			//long end =
			//    start + virtualSize;

			//if (end > highestEnd)
			//     highestEnd = end;
			//}

			return new IntPtr(0);
		}
		
		public static unsafe Assembly LoadMixedAssembly_x64(AssemblyName rassemblyName, IntPtr lib, IntPtr mscorwks_Address, byte* ptr, bool is_last_fr,bool is_fr4, bool ExecuteExe)
		{

			//Console.WriteLine("press any key to continue!");
			//Console.ReadKey();
			
			/*
00007FFF9FB08ABD                     | 90                            | nop                                                                                                                                                                                                        |
00007FFF9FB08ABE                     | 48:8D4424 60                  | lea rax,qword ptr ss:[rsp+60]                                                                                                                                                                              |
00007FFF9FB08AC3                     | 48:898424 A0000000            | mov qword ptr ss:[rsp+A0],rax                                                                                                                                                                              |
00007FFF9FB08ACB                     | 45:8BCE                       | mov r9d,r14d                                                                                                                                                                                               |
00007FFF9FB08ACE                     | 4C:8B8424 20010000            | mov r8,qword ptr ss:[rsp+120]                                                                                                                                                                              |
00007FFF9FB08AD6                     | 41:8BD5                       | mov edx,r13d                                                                                                                                                                                               |
00007FFF9FB08AD9                     | 48:8B8C24 10010000            | mov rcx,qword ptr ss:[rsp+110]                                                                                                                                                                             |
00007FFF9FB08AE1                     | E8 7E020000                   | call clr.7FFF9FB08D64                                                                                                                                                                                      |
00007FFF9FB08AE6                     | 8BF8                          | mov edi,eax                                                                                                                                                                                                |
00007FFF9FB08AE8                     | 894424 30                     | mov dword ptr ss:[rsp+30],eax                                                                                                                                                                              |
00007FFF9FB08AEC                     | 48:8D4C24 60                  | lea rcx,qword ptr ss:[rsp+60]                                                                                                                                                                              |

Thread ID                     Address           To                From                   Size     Party     Comment
3092
                              0000005DD53FF398  00007FFF9FB0B291  00007FFF9FB08AAB       60       System    clr.CorDllMainForThunk+30B
                              0000005DD53FF3F8  00007FFF4019DF1D  00007FFF9FB0B291       8        User      clr._CorDllMain+31
                              0000005DD53FF400  0000000000000000  00007FFF4019DF1D                User      00007FFF4019DF1D

Here calls entry point address => no 0 check so it chruses
00007FFF96398E0B                     | 90                            | nop                                                                                                                                                                                                        |
00007FFF96398E0C                     | 48:8D95 B0FFFFFF              | lea rdx,qword ptr ss:[rbp-50] |
00007FFF96398E13                     | 48:8BCE                       | mov rcx,rsi                                                                                                                                                                                                | rcx:COM+_Entry_Point, rsi:COM+_Entry_Point
00007FFF96398E16                     | E8 0900D5FF                   | call clr.7FFF960E8E24    |

			 */
			if (lib==null)
				return null;
			
			int entrypoint = GetEntryPointAddress(lib);
			if (entrypoint==0)
			{
				IntPtr hProcess = OpenProcess(
					PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
					false,
					Process.GetCurrentProcess().Id);
				
				IntPtr newPlace = GetSuitableEmptyPlace(hProcess, lib);
				if (newPlace!=IntPtr.Zero&&newPlace.ToInt64()!=0&&NewEntryPointRva!=0)
					PatchEntryPoint(lib, NewEntryPointRva);
				
				if (hProcess!=null&&hProcess!=IntPtr.Zero)
					CloseHandle(hProcess);
			}
			
			IntPtr oldCorAddress = (IntPtr)ptr;
			bool is_last_fr_load_dll = false;
			bool CallDirect = false;
			IntPtr CallDirectAddress = IntPtr.Zero;
			int max_code_len = 1024;  // maximum 1 KB
			int current_code_len = 0;
			IntPtr funcptr = IntPtr.Zero;
			
			IntPtr CorExeMainInternal = IntPtr.Zero;
			IntPtr clr_ExecuteEXE = IntPtr.Zero;
			if (!is_fr4)  // if is framework 2
			{
				current_code_len = 0;

				while (true)
				{
					ptr++;
					current_code_len++;

					/* For ExecuteEXE
6cc76fde 50              push    eax
6cc76fdf e887000000      call    mscorwks!ExecuteEXE (6cc7706b)
6cc76fe4 3bc3            cmp     eax,ebx
6cc76fe6 0f84cb590f00    je      mscorwks!_CorExeMain+0x160 (6cd6c9b7)
					 */
					if (ExecuteExe&&(ptr[0] == 0xe8) && (*((ptr - 1)) == 0x50) && (ptr[5] == 0x3b) && ((ptr + 5)[1] == 0xc3))
						break;


					/* 6cd18a36 56              push    esi
   6cd18a37 ff7510          push    dword ptr [ebp+10h]
   6cd18a3a ff750c          push    dword ptr [ebp+0Ch]
   6cd18a3d ff7508          push    dword ptr [ebp+8]
   6cd18a40 e8fafeffff      call    mscorwks!ExecuteDLL (6cd1893f)
   
   https://github.com/fixdpt/shared-source-cli-2.0/blob/master/clr/src/vm/ceemain.cpp:
   This is the call point to make a DLL that is already loaded into our address space run
   BOOL STDMETHODCALLTYPE ExecuteDLL(HINSTANCE hInst,
                                  DWORD dwReason,
                                  LPVOID lpReserved,
                                  BOOL fFromThunk)

BOOL STDMETHODCALLTYPE _CorDllMain (
   [in] HINSTANCE hInst,
   [in] DWORD     dwReason,
   [in] LPVOID    lpReserved
);
   
					 */
					if (!ExecuteExe&&(ptr[0] == 0xe8) && (*((ptr - 3)) == 0xFF) && (*((ptr - 6)) == 0xFF) && (*((ptr - 9)) == 0xFF))
						break;
					
					if (current_code_len==max_code_len)
					{
						string constructed_error = "Failed to find mscorwks!";
						if (ExecuteExe)
							constructed_error = constructed_error+"ExecuteEXE";
						else
							constructed_error = constructed_error+"ExecuteDLL";
						MessageBox.Show(constructed_error);
						return null;
					}
					


				}
				

			}
			
			else  // if is framework 4.0
			{
				
				current_code_len = 0;
				while (true)
				{
					ptr++;
					current_code_len++;

					/* Code for exe (Execute = true):
For exes (Execute = true) is this:
6606aef0 33c0            xor     eax,eax
6606aef2 8945e0          mov     dword ptr [ebp-20h],eax
6606aef5 8945e4          mov     dword ptr [ebp-1Ch],eax
6606aef8 8945fc          mov     dword ptr [ebp-4],eax
6606aefb e8e420f8ff      call    clr!_CorExeMainInternal (65fecfe4)
6606af00 c745fcfeffffff  mov     dword ptr [ebp-4],0FFFFFFFEh

 
clr!_CorExeMain fr 4.8
73dadf70 6a14            push    14h
73dadf72 68a8dfda73      push    offset clr!`dynamic atexit destructor for 'AppDataPathHolder''+0x27e0 (73dadfa8)
73dadf77 e8a430e5ff      call    clr!_SEH_prolog4 (73c01020)
73dadf7c 33c0            xor     eax,eax
73dadf7e 8985e0ffffff    mov     dword ptr [ebp-20h],eax
73dadf84 8985e4ffffff    mov     dword ptr [ebp-1Ch],eax
73dadf8a 8985fcffffff    mov     dword ptr [ebp-4],eax
73dadf90 e81b460000      call    clr!_CorExeMainInternal (73db25b0)
73dadf95 c785fcfffffffeffffff mov dword ptr [ebp-4],0FFFFFFFEh

					 */
					
					
					/*
00007ffa`11ee85f0 4883ec38        sub     rsp,38h
00007ffa`11ee85f4 488364244000    and     qword ptr [rsp+40h],0
00007ffa`11ee85fa 8364242000      and     dword ptr [rsp+20h],0
00007ffa`11ee85ff e8d8eaffff      call    clr!_CorExeMainInternal (00007ffa`11ee70dc)
00007ffa`11ee8604 eb01            jmp     clr!CorExeMain+0x33 (00007ffa`11ee8607)
00007ffa`11ee8606 cc              int     3
00007ffa`11ee8607 33c0            xor     eax,eax
00007ffa`11ee8609 4883c438        add     rsp,38h
00007ffa`11ee860d c3              ret
00007ffa`11ee860e 90              nop
00007ffa`11ee860f 90              nop
					 */
					if (ExecuteExe&&(ptr[0] == 0xe8) && (*((ptr - 5)) == 0x83) && (*((ptr - 4)) == 0x64) && (ptr[5] == 0xEB))
					{
						CorExeMainInternal = GetCallTarget_x64(ptr);
						if (CorExeMainInternal!=IntPtr.Zero)
							break;
						
					}
					
					/*if (ExecuteExe&&(ptr[0] == 0xe8) &&  // call
					    ((*((ptr - 3)) == 0x89) && (*((ptr - 2)) == 0x45) && (*((ptr - 1)) == 0xfc))
					    ||((*((ptr - 6)) == 0x89) && (*((ptr - 5)) == 0x85)&&(*((uint*)(ptr-4))==0x0FFFFFFFC))
					    && (ptr[5] == 0xc7) && (((ptr + 5)[1] == 0x45)||((ptr + 5)[1] == 0x85))
					    && ((ptr + 5)[2] == 0xfc))
						break;
					 */
					/* Code for dll (Execute = false):
66188055 56              push    esi
66188056 52              push    edx
66188057 51              push    ecx
66188058 50              push    eax
66188059 e8ad50fbff      call    clr!ExecuteDLL (6613d10b)
6618805e 8945e0          mov     dword ptr [ebp-20h],eax
...
68A60CFF    C745 FC FEFFFFF>MOV DWORD PTR SS:[EBP-0x4],-0x2
					 */
					//if (!ExecuteExe&&(ptr[0] == 0xe8) && ((*((ptr - 1))&0xF0) == 0x50) && ((*((ptr - 2))&0xF0) == 0x50)&&
					// (ptr[5] == 0x89) && (((ptr + 5)[1] == 0x45) || ((ptr + 5)[1] == 0x85)))
					//break;

					/*
    clr!CorDllMain: Framework 4.8
00007ffa`1cd2b260 488bc4          mov     rax,rsp
00007ffa`1cd2b263 4883ec58        sub     rsp,58h
00007ffa`1cd2b267 488988d8ffffff  mov     qword ptr [rax-28h],rcx
00007ffa`1cd2b26e 8990e0ffffff    mov     dword ptr [rax-20h],edx
00007ffa`1cd2b274 4c8980e8ffffff  mov     qword ptr [rax-18h],r8
00007ffa`1cd2b27b 83a0f0ffffff00  and     dword ptr [rax-10h],0
00007ffa`1cd2b282 83a0c8ffffff00  and     dword ptr [rax-38h],0
00007ffa`1cd2b289 4533c9          xor     r9d,r9d
00007ffa`1cd2b28c e87fd6ffff      call    clr!ExecuteDLL (00007ffa`1cd28910)
00007ffa`1cd2b291 89442448        mov     dword ptr [rsp+48h],eax
00007ffa`1cd2b295 eb20            jmp     clr!CorDllMain+0x48 (00007ffa`1cd2b2b7)
00007ffa`1cd2b297 817c2420fd0000c0 cmp     dword ptr [rsp+20h],0C00000FDh
00007ffa`1cd2b29f 7512            jne     clr!CorDllMain+0x44 (00007ffa`1cd2b2b3)
00007ffa`1cd2b2a1 e8ba8dbcff      call    clr!GetThread (00007ffa`1c8f4060)
00007ffa`1cd2b2a6 4885c0          test    rax,rax
00007ffa`1cd2b2a9 7408            je      clr!CorDllMain+0x44 (00007ffa`1cd2b2b3)
00007ffa`1cd2b2ab 488bc8          mov     rcx,rax
00007ffa`1cd2b2ae e86d250300      call    clr!Thread::RestoreGuardPage (00007ffa`1cd5d820)
00007ffa`1cd2b2b3 8b442448        mov     eax,dword ptr [rsp+48h]
00007ffa`1cd2b2b7 4883c458        add     rsp,58h
00007ffa`1cd2b2bb c3              ret

					 */
					if (!ExecuteExe&&(ptr[0] == 0xe8) && ((*((ptr - 3))) == 0x45)  && ((*((ptr - 2))) == 0x33)&& ((*((ptr - 1))) == 0xC9)&&
					    (ptr[5] == 0x89)&& ((((ptr + 5)[1] == 0x45)|| (((ptr + 5)[1] == 0x44)))))
					{  //
						CallDirectAddress = GetCallTarget_x64(ptr);
						if (CallDirectAddress!=IntPtr.Zero)
						{
							CallDirect = true;
							break;
						}
						
					}
					
					if (current_code_len==max_code_len)
					{
						string constructed_error = "Failed to find clr!";
						if (ExecuteExe)
							constructed_error = constructed_error+"_CorExeMainInternal";
						else
							constructed_error = constructed_error+"ExecuteDLL";
						MessageBox.Show(constructed_error);
						return null;
					}
					

				}

				// MessageBox.Show((((uint)ptr).ToString(("X8"))));
				
				if (CorExeMainInternal!=IntPtr.Zero)
				{
					ptr = (byte*)CorExeMainInternal;
					while (true)
					{
						ptr++;
						current_code_len++;
						
/*
00007ffa`11ee7181 33c9            xor     ecx,ecx
00007ffa`11ee7183 ff1587c36300    call    qword ptr [clr!_imp_GetModuleHandleW (00007ffa`12523510)]
00007ffa`11ee7189 488bc8          mov     rcx,rax
00007ffa`11ee718c e87f140000      call    clr!ExecuteEXE (00007ffa`11ee8610)
00007ffa`11ee7191 85c0            test    eax,eax
00007ffa`11ee7193 0f849c872800    je      clr!_CorExeMainInternal+0x288859 (00007ffa`1216f935)
*/
						
						
						if (ExecuteExe&&(ptr[0] == 0xe8) && (*((ptr - 3)) == 0x48)&&(*((ptr - 2)) == 0x8b)&&(*((ptr - 1)) == 0xC8) && (ptr[5] == 0x85) && ((ptr + 5)[1] == 0xc0))
						{
						clr_ExecuteEXE =  GetCallTarget_x64(ptr);
						if (clr_ExecuteEXE!=IntPtr.Zero)
							break;
						
						}
						if (current_code_len==max_code_len)
						{
							MessageBox.Show("Failed to find clr!ExecuteEXE");
							return null;
						}
					}
				}
				else if (!CallDirect)
				{
					current_code_len = 0;
					max_code_len = 1024; // 1KB for this search!
					
					ptr++;
					ptr = (byte*) ((ptr + *(((uint*) ptr))) + 4);  // clr!_CorExeMainInternal address


					/*
79298A85    53              PUSH EBX
79298A86    FF15 6C121479   CALL DWORD PTR DS:[7914126C]   ; KERNEL32.GetModuleHandleW - SHOULD NOT BE CHECKED!
79298A8C    50              PUSH EAX       ; byte ok for checking!
79298A8D    E8 AA000000     CALL 79298B3C  ; clr.79298B3C - THIS IS THE CALL!
79298A92    3BC3            CMP EAX,EBX    ; ok for checking!
79298A94    0F84 24350800   JE 7931BFBE    ; clr.7931BFBE - first byte checked!

7135D08D    53              PUSH EBX
7135D08E    FF15 6C122771   CALL DWORD PTR DS:[7127126C]             ; KERNEL32.GetModuleHandleW
7135D094    50              PUSH EAX
7135D095    E8 AA000000     CALL 7135D144                            ; clr.7135D144
7135D09A    3BC3            CMP EAX,EBX
7135D09C    0F84 74E50E00   JE 7144B616                              ; clr.7144B616
7135D0A2    895D DC         MOV DWORD PTR SS:[EBP-24],EBX

On new version:
5D53869A    803D 0CE3A65D 0>CMP BYTE PTR DS:[5DA6E30C],0
5D5386A1    0F85 BD8C0700   JNZ 5D5B1364                             ; clr.5D5B1364
5D5386A7    C645 FC 04      MOV BYTE PTR SS:[EBP-4],4
5D5386AB    6A 00           PUSH 0
5D5386AD    FF15 C401A85D   CALL DWORD PTR DS:[5DA801C4]             ; KERNEL32.GetModuleHandleW
5D5386B3    8BC8            MOV ECX,EAX
5D5386B5    E8 2F080000     CALL 5D538EE9                            ; clr.5D538EE9
5D5386BA    85C0            TEST EAX,EAX
5D5386BC    0F84 C38C0700   JE 5D5B1385                              ; clr.5D5B1385
 
					 */
					
					if (ExecuteExe)
					{  // clr!ExecuteEXE
						while ((((((ptr[0] != 0xe8) || (*((ptr - 1)) != 0x050))) || ((ptr[5] != 0x3b) || ((ptr + 5)[1] != 0xc3))) || ((ptr + 5)[2] != 15))&&
						       (((((ptr[0] != 0xe8) || (*((ptr - 2)) != 0x8B) || (*((ptr - 1)) != 0xC8))) || ((ptr[5] != 0x85) || ((ptr + 5)[1] != 0xc0))) || ((ptr + 5)[2] != 0x0F)))
						{
							ptr++;
						}
						
						byte test1 = (*((ptr - 1)));
						byte test2 = (*((ptr - 2)));
						if (*((ptr - 1))==0x0C8&&*((ptr - 2))==0x8B)
							is_last_fr = true;
						
					}
					else  // if ExecuteExe=false - dll mode
					{  // clr!ExecuteDLLForAttach

						current_code_len = 0;
						
						while(true)
						{
							ptr++;
							current_code_len++;
							if ((ptr[0] == 0xe8) && ((*((ptr - 1))&0xF0) == 0x050) && (*((ptr - 4)) == 0x0FF) && (*((ptr - 7)) == 0x0FF) && (*((ptr - 10)) == 0x0FF))
							{
								break;
							}
							
							/*if ((ptr[0] == 0xe8) && (*(ptr - 2) == 0x08B) && (*((ptr - 1)) == 0x0C8))  // &&((ptr[1]&0xF0) == 0x080)
	{
	Console.WriteLine("Sheet");
	is_last_fr_load_dll = true;
	break;
	}
							 */
							if (ptr[0] == 0xe8 && ((*(ptr - 6) == 0x08B) && (*((ptr - 5)) == 0x08d))||  // 72ddc674 8b8ddcffffff  mov     ecx,dword ptr [ebp-24h]
							    ((*(ptr - 12) == 0x08B) && (*((ptr - 1)) == 0x095))&&  // 8b95e4ffffff    mov     edx,dword ptr [ebp-1Ch]
							    ptr[5]==0x8B && ptr[6]==0xF0)  // MOV ESI,EAX
							{
								is_last_fr_load_dll = true;
								break;
							}
							
							if (ptr[0] == 0xe8 && ((*(ptr - 3) == 0x08B) && (*((ptr - 2)) == 0x04D))||
							    ((*(ptr - 6) == 0x08B) && (*((ptr - 5)) == 0x08D))&&
							    ptr[5]==0x85 && ptr[6]==0xF0)
							{
								is_last_fr_load_dll = true;
								break;
							}

							/*
732BC612    8BC8            MOV ECX,EAX
732BC614    E8 C8ADF9FF     CALL 732573E1                            ; clr.732573E1
732BC619    8985 ECFFFFFF   MOV DWORD PTR SS:[EBP-0x14],EAX
732BC61F    85C0            TEST EAX,EAX
732BC621    0F88 DBC90F00   JS 733B9002                              ; clr.733B9002

 
732BC64D    C685 FCFFFFFF 0>MOV BYTE PTR SS:[EBP-0x4],0x1
732BC654    C685 FCFFFFFF 0>MOV BYTE PTR SS:[EBP-0x4],0x2
732BC65B    8BC1            MOV EAX,ECX
732BC65D    8985 D8FFFFFF   MOV DWORD PTR SS:[EBP-0x28],EAX
732BC663    C685 FCFFFFFF 0>MOV BYTE PTR SS:[EBP-0x4],0x3
732BC66A    57              PUSH EDI
732BC66B    FF75 08         PUSH DWORD PTR SS:[EBP+0x8]
732BC66E    8B95 E4FFFFFF   MOV EDX,DWORD PTR SS:[EBP-0x1C]
732BC674    8B8D DCFFFFFF   MOV ECX,DWORD PTR SS:[EBP-0x24]
732BC67A    E8 07FEFFFF     CALL 732BC486                            ; clr.732BC486
732BC67F    8BF0            MOV ESI,EAX

or
68988038    8B4D DC         MOV ECX,DWORD PTR SS:[EBP-0x24]
6898803B    E8 FEFDFFFF     CALL 68987E3E                            ; clr.68987E3E
68988040    8BF0            MOV ESI,EAX
68988042    8975 EC         MOV DWORD PTR SS:[EBP-0x14],ESI
68988045    C645 FC 02      MOV BYTE PTR SS:[EBP-0x4],0x2

72ddc64d c685fcffffff01  mov     byte ptr [ebp-4],1
72ddc654 c685fcffffff02  mov     byte ptr [ebp-4],2
72ddc65b 8bc1            mov     eax,ecx
72ddc65d 8985d8ffffff    mov     dword ptr [ebp-28h],eax
72ddc663 c685fcffffff03  mov     byte ptr [ebp-4],3
72ddc66a 57              push    edi
72ddc66b ff7508          push    dword ptr [ebp+8]
72ddc66e 8b95e4ffffff    mov     edx,dword ptr [ebp-1Ch]
72ddc674 8b8ddcffffff    mov     ecx,dword ptr [ebp-24h]
72ddc67a e807feffff      call    clr!ExecuteDLLForAttach (72ddc486)
72ddc67f 8bf0            mov     esi,eax
							 */

							
							
							if (current_code_len==max_code_len)
							{
								MessageBox.Show("Failed to find clr!ExecuteDLLForAttach");
								return null;
							}
							
						}

					}
					// MessageBox.Show((((uint)ptr).ToString(("X8"))));

					
					/* For exes (Execute = true) is this:
6603d089 c645fc04        mov     byte ptr [ebp-4],4
6603d08d 53              push    ebx
6603d08e ff156c12f565    call    dword ptr [clr!_imp__GetModuleHandleW (65f5126c)]
6603d094 50              push    eax
6603d095 e8aa000000      call    clr!ExecuteEXE (6603d144)
6603d09a 3bc3            cmp     eax,ebx
6603d09c 0f8474e50e00    je      clr!_CorExeMainInternal+0x1a3 (6612b616)

For dll:
633bd1c5 ff7514          push    dword ptr [ebp+14h]
633bd1c8 ff7510          push    dword ptr [ebp+10h]
633bd1cb ff750c          push    dword ptr [ebp+0Ch]
633bd1ce 53              push    ebx
633bd1cf e83c000000      call    clr!ExecuteDLLForAttach (633bd210)
633bd1d4 8945e8          mov     dword ptr [ebp-18h],eax
633bd1d7 c645fc02        mov     byte ptr [ebp-4],2

68988031    57              PUSH EDI
68988032    FF75 08         PUSH DWORD PTR SS:[EBP+0x8]
68988035    8B55 E4         MOV EDX,DWORD PTR SS:[EBP-0x1C]
68988038    8B4D DC         MOV ECX,DWORD PTR SS:[EBP-0x24]
6898803B    E8 FEFDFFFF     CALL 68987E3E                            ; clr.68987E3E
68988040    8BF0            MOV ESI,EAX
68988042    8975 EC         MOV DWORD PTR SS:[EBP-0x14],ESI
68988045    C645 FC 02      MOV BYTE PTR SS:[EBP-0x4],0x2

0x732BC614
// 0x732573E1

					 */

					

				}
				
				
				ptr++;
				funcptr = (IntPtr) (((ptr + *(((uint*) ptr)))) + 4);
			}

			Thread t = null;
			if (ExecuteExe)
			{

				ExeContext exeContext = new ExeContext();
				exeContext.lib = lib;
				if (clr_ExecuteEXE!=IntPtr.Zero)
				exeContext.func = clr_ExecuteEXE; //funcptr;
				/*if (is_last_fr)
				{
					int paramCount = 1;
					exeContext.func = DetourOriginalAddress(exeContext.func, paramCount);
				}
				*/
				t = new System.Threading.Thread(new System.Threading.ThreadStart(exeContext.ExecuteExe));

			}
			else
			{
				DllContextx64 dllContext64 = new DllContextx64();
				dllContext64.lib = lib;
				if (CallDirectAddress!=IntPtr.Zero)
					dllContext64.func = (IntPtr)oldCorAddress;
				else if (funcptr!=IntPtr.Zero)
					dllContext64.func = funcptr;
				dllContext64.dwReason = 1;  // DLL_PROCESS_ATTACH
				dllContext64.fFromThunk = false;

				// Read EntryPoint value from PE header C#
				
				//int paramCount = 4;
				//dllContext64.func = DetourOriginalAddress64(dllContext64.func, paramCount);
				
				//dllContext.func = (IntPtr)0x732bc486;

				/*
				if (is_last_fr_load_dll)
				{
					int paramCount = 4;
					dllContext.func = DetourOriginalAddress(dllContext.func, paramCount);

				}
				 */
				t = new System.Threading.Thread(new System.Threading.ThreadStart(dllContext64.ExecuteDll));
			}
			t.SetApartmentState(ApartmentState.STA);
			t.Start();

			while (t.IsAlive)
			{
				System.Windows.Forms.Application.DoEvents();
			}

			Assembly assembly = null;
			// Old stupid code: removed
			/*
Assembly[] assemblies = AppDomain.CurrentDomain.GetAssemblies();
for (int i=0;i<assemblies.Length;i++)
{
if (assemblies[i].FullName==rassemblyName.FullName)
{
assembly = assemblies[i];
break;
}
}
			 */

			// This code before won't load managed assemblies - assemblies with "IL only" flag set
			// mixed mode assemblies are already loaded,
			// managed assemblies will be loaded by Assembly.Load
			assembly = Assembly.Load(rassemblyName);

			if (assembly==null)
			{
				MessageBox.Show("Failed to load the assembly!");
				return null;
			}
			return assembly;
			
		}
		
		public static unsafe Assembly LoadMixedAssembly_Main(AssemblyName rassemblyName, IntPtr lib, bool ExecuteExe)
		{
			
			string MainFunctionName = "_CorDllMain";
			if (ExecuteExe)  // is true the exe will be executed!
				MainFunctionName = "_CorExeMain";

			//clr!_CorExeMain
			//clr!_CorExeMainInternal

			
			bool is_last_fr = false;
			bool is_fr4 = false;
			bool is_last_fr_load_dll = false;
			
			int max_code_len = 1024;  // maximum 1 KB
			int current_code_len = 0;

			byte* ptr = (byte*)0;
			IntPtr mscorwks_Address = LoadLibrary("mscorwks.dll");
			if (mscorwks_Address==IntPtr.Zero)
			{
				mscorwks_Address = LoadLibrary("clr.dll");
				is_fr4 = true;
			}
			string textToPrint1 = "_Cor lib address is "+((ulong)mscorwks_Address).ToString("X16")+"\r\n";
			if (GetConsoleWindow() != IntPtr.Zero)
				Console.Write(textToPrint1);
			else
				Logs += textToPrint1;
			
			// mscorwks!_CorDllMain
			ptr = (byte*) GetProcAddress(mscorwks_Address, MainFunctionName).ToPointer();
			if ((uint)ptr==0)
			{
				MessageBox.Show("Failed to find mscorwks."+MainFunctionName+" or clr."+MainFunctionName+" !");
				return null;
			}
			string textToPrint2 = "_Cor proc address is "+((ulong)ptr).ToString("X16")+"\r\n";
			if (GetConsoleWindow() != IntPtr.Zero)
				Console.Write(textToPrint2);
			else
				Logs += textToPrint2;

			if (IntPtr.Size == 8)
				return LoadMixedAssembly_x64(rassemblyName, lib, mscorwks_Address, ptr, is_last_fr,is_fr4, ExecuteExe);
			
			if (!is_fr4)  // if is framework 2
			{
				current_code_len = 0;

				while (true)
				{
					ptr++;
					current_code_len++;

					/* For ExecuteEXE
6cc76fde 50              push    eax
6cc76fdf e887000000      call    mscorwks!ExecuteEXE (6cc7706b)
6cc76fe4 3bc3            cmp     eax,ebx
6cc76fe6 0f84cb590f00    je      mscorwks!_CorExeMain+0x160 (6cd6c9b7)
					 */
					if (ExecuteExe&&(ptr[0] == 0xe8) && (*((ptr - 1)) == 0x50) && (ptr[5] == 0x3b) && ((ptr + 5)[1] == 0xc3))
						break;


					/* 6cd18a36 56              push    esi
   6cd18a37 ff7510          push    dword ptr [ebp+10h]
   6cd18a3a ff750c          push    dword ptr [ebp+0Ch]
   6cd18a3d ff7508          push    dword ptr [ebp+8]
   6cd18a40 e8fafeffff      call    mscorwks!ExecuteDLL (6cd1893f)
   
   https://github.com/fixdpt/shared-source-cli-2.0/blob/master/clr/src/vm/ceemain.cpp:
   This is the call point to make a DLL that is already loaded into our address space run
   BOOL STDMETHODCALLTYPE ExecuteDLL(HINSTANCE hInst,
                                  DWORD dwReason,
                                  LPVOID lpReserved,
                                  BOOL fFromThunk)

BOOL STDMETHODCALLTYPE _CorDllMain (
   [in] HINSTANCE hInst,
   [in] DWORD     dwReason,
   [in] LPVOID    lpReserved
);
   
					 */
					if (!ExecuteExe&&(ptr[0] == 0xe8) && (*((ptr - 3)) == 0xFF) && (*((ptr - 6)) == 0xFF) && (*((ptr - 9)) == 0xFF))
						break;
					

					
					if (current_code_len==max_code_len)
					{
						string constructed_error = "Failed to find mscorwks!";
						if (ExecuteExe)
							constructed_error = constructed_error+"ExecuteEXE";
						else
							constructed_error = constructed_error+"ExecuteDLL";
						MessageBox.Show(constructed_error);
						return null;
					}
					


				}
				

			}
			
			else  // if is framework 4.0
			{
				
				current_code_len = 0;
				while (true)
				{
					ptr++;
					current_code_len++;

					/* Code for exe (Execute = true):
For exes (Execute = true) is this:
6606aef0 33c0            xor     eax,eax
6606aef2 8945e0          mov     dword ptr [ebp-20h],eax
6606aef5 8945e4          mov     dword ptr [ebp-1Ch],eax
6606aef8 8945fc          mov     dword ptr [ebp-4],eax
6606aefb e8e420f8ff      call    clr!_CorExeMainInternal (65fecfe4)
6606af00 c745fcfeffffff  mov     dword ptr [ebp-4],0FFFFFFFEh

 
clr!_CorExeMain fr 4.8
73dadf70 6a14            push    14h
73dadf72 68a8dfda73      push    offset clr!`dynamic atexit destructor for 'AppDataPathHolder''+0x27e0 (73dadfa8)
73dadf77 e8a430e5ff      call    clr!_SEH_prolog4 (73c01020)
73dadf7c 33c0            xor     eax,eax
73dadf7e 8985e0ffffff    mov     dword ptr [ebp-20h],eax
73dadf84 8985e4ffffff    mov     dword ptr [ebp-1Ch],eax
73dadf8a 8985fcffffff    mov     dword ptr [ebp-4],eax
73dadf90 e81b460000      call    clr!_CorExeMainInternal (73db25b0)
73dadf95 c785fcfffffffeffffff mov dword ptr [ebp-4],0FFFFFFFEh

					 */
					
					//if (ExecuteExe&&(ptr[0] == 0xe8) && (*((ptr - 3)) == 0x89) && (*((ptr - 2)) == 0x45) && (*((ptr - 1)) == 0xfc) && (ptr[5] == 0xc7) && ((ptr + 5)[1] == 0x45) && ((ptr + 5)[2] == 0xfc))
					//break;

					if (ExecuteExe&&(ptr[0] == 0xe8) &&  // call
					    ((*((ptr - 3)) == 0x89) && (*((ptr - 2)) == 0x45) && (*((ptr - 1)) == 0xfc))
					    ||((*((ptr - 6)) == 0x89) && (*((ptr - 5)) == 0x85)&&(*((uint*)(ptr-4))==0x0FFFFFFFC))
					    && (ptr[5] == 0xc7) && (((ptr + 5)[1] == 0x45)||((ptr + 5)[1] == 0x85))
					    && ((ptr + 5)[2] == 0xfc))
						break;
					
					/* Code for dll (Execute = false):
66188055 56              push    esi
66188056 52              push    edx
66188057 51              push    ecx
66188058 50              push    eax
66188059 e8ad50fbff      call    clr!ExecuteDLL (6613d10b)
6618805e 8945e0          mov     dword ptr [ebp-20h],eax
...
68A60CFF    C745 FC FEFFFFF>MOV DWORD PTR SS:[EBP-0x4],-0x2
					 */
					if (!ExecuteExe&&(ptr[0] == 0xe8) && ((*((ptr - 1))&0xF0) == 0x50) && ((*((ptr - 2))&0xF0) == 0x50)&&
					    (ptr[5] == 0x89) && (((ptr + 5)[1] == 0x45) || ((ptr + 5)[1] == 0x85)))
						break;
					
					if (current_code_len==max_code_len)
					{
						string constructed_error = "Failed to find clr!";
						if (ExecuteExe)
							constructed_error = constructed_error+"_CorExeMainInternal";
						else
							constructed_error = constructed_error+"ExecuteDLL";
						MessageBox.Show(constructed_error);
						return null;
					}
					

				}

				current_code_len = 0;
				max_code_len = 1024; // 1KB for this search!

				// MessageBox.Show((((uint)ptr).ToString(("X8"))));

				ptr++;
				ptr = (byte*) ((ptr + *(((uint*) ptr))) + 4);  // clr!_CorExeMainInternal address


				/*
79298A85    53              PUSH EBX
79298A86    FF15 6C121479   CALL DWORD PTR DS:[7914126C]   ; KERNEL32.GetModuleHandleW - SHOULD NOT BE CHECKED!
79298A8C    50              PUSH EAX       ; byte ok for checking!
79298A8D    E8 AA000000     CALL 79298B3C  ; clr.79298B3C - THIS IS THE CALL!
79298A92    3BC3            CMP EAX,EBX    ; ok for checking!
79298A94    0F84 24350800   JE 7931BFBE    ; clr.7931BFBE - first byte checked!

7135D08D    53              PUSH EBX
7135D08E    FF15 6C122771   CALL DWORD PTR DS:[7127126C]             ; KERNEL32.GetModuleHandleW
7135D094    50              PUSH EAX
7135D095    E8 AA000000     CALL 7135D144                            ; clr.7135D144
7135D09A    3BC3            CMP EAX,EBX
7135D09C    0F84 74E50E00   JE 7144B616                              ; clr.7144B616
7135D0A2    895D DC         MOV DWORD PTR SS:[EBP-24],EBX

On new version:
5D53869A    803D 0CE3A65D 0>CMP BYTE PTR DS:[5DA6E30C],0
5D5386A1    0F85 BD8C0700   JNZ 5D5B1364                             ; clr.5D5B1364
5D5386A7    C645 FC 04      MOV BYTE PTR SS:[EBP-4],4
5D5386AB    6A 00           PUSH 0
5D5386AD    FF15 C401A85D   CALL DWORD PTR DS:[5DA801C4]             ; KERNEL32.GetModuleHandleW
5D5386B3    8BC8            MOV ECX,EAX
5D5386B5    E8 2F080000     CALL 5D538EE9                            ; clr.5D538EE9
5D5386BA    85C0            TEST EAX,EAX
5D5386BC    0F84 C38C0700   JE 5D5B1385                              ; clr.5D5B1385
 
				 */
				
				if (ExecuteExe)
				{  // clr!ExecuteEXE
					while ((((((ptr[0] != 0xe8) || (*((ptr - 1)) != 0x050))) || ((ptr[5] != 0x3b) || ((ptr + 5)[1] != 0xc3))) || ((ptr + 5)[2] != 15))&&
					       (((((ptr[0] != 0xe8) || (*((ptr - 2)) != 0x8B) || (*((ptr - 1)) != 0xC8))) || ((ptr[5] != 0x85) || ((ptr + 5)[1] != 0xc0))) || ((ptr + 5)[2] != 0x0F)))
					{
						ptr++;
					}
					
					byte test1 = (*((ptr - 1)));
					byte test2 = (*((ptr - 2)));
					if (*((ptr - 1))==0x0C8&&*((ptr - 2))==0x8B)
						is_last_fr = true;
					
				}
				else  // if ExecuteExe=false - dll mode
				{  // clr!ExecuteDLLForAttach

					current_code_len = 0;
					
					while(true)
					{
						ptr++;
						current_code_len++;
						if ((ptr[0] == 0xe8) && ((*((ptr - 1))&0xF0) == 0x050) && (*((ptr - 4)) == 0x0FF) && (*((ptr - 7)) == 0x0FF) && (*((ptr - 10)) == 0x0FF))
						{
							break;
						}
						
						/*if ((ptr[0] == 0xe8) && (*(ptr - 2) == 0x08B) && (*((ptr - 1)) == 0x0C8))  // &&((ptr[1]&0xF0) == 0x080)
	{
	Console.WriteLine("Sheet");
	is_last_fr_load_dll = true;
	break;
	}
						 */
						if (ptr[0] == 0xe8 && ((*(ptr - 6) == 0x08B) && (*((ptr - 5)) == 0x08d))||  // 72ddc674 8b8ddcffffff  mov     ecx,dword ptr [ebp-24h]
						    ((*(ptr - 12) == 0x08B) && (*((ptr - 1)) == 0x095))&&  // 8b95e4ffffff    mov     edx,dword ptr [ebp-1Ch]
						    ptr[5]==0x8B && ptr[6]==0xF0)  // MOV ESI,EAX
						{
							is_last_fr_load_dll = true;
							break;
						}
						
						if (ptr[0] == 0xe8 && ((*(ptr - 3) == 0x08B) && (*((ptr - 2)) == 0x04D))||
						    ((*(ptr - 6) == 0x08B) && (*((ptr - 5)) == 0x08D))&&
						    ptr[5]==0x85 && ptr[6]==0xF0)
						{
							is_last_fr_load_dll = true;
							break;
						}

						/*
732BC612    8BC8            MOV ECX,EAX
732BC614    E8 C8ADF9FF     CALL 732573E1                            ; clr.732573E1
732BC619    8985 ECFFFFFF   MOV DWORD PTR SS:[EBP-0x14],EAX
732BC61F    85C0            TEST EAX,EAX
732BC621    0F88 DBC90F00   JS 733B9002                              ; clr.733B9002

 
732BC64D    C685 FCFFFFFF 0>MOV BYTE PTR SS:[EBP-0x4],0x1
732BC654    C685 FCFFFFFF 0>MOV BYTE PTR SS:[EBP-0x4],0x2
732BC65B    8BC1            MOV EAX,ECX
732BC65D    8985 D8FFFFFF   MOV DWORD PTR SS:[EBP-0x28],EAX
732BC663    C685 FCFFFFFF 0>MOV BYTE PTR SS:[EBP-0x4],0x3
732BC66A    57              PUSH EDI
732BC66B    FF75 08         PUSH DWORD PTR SS:[EBP+0x8]
732BC66E    8B95 E4FFFFFF   MOV EDX,DWORD PTR SS:[EBP-0x1C]
732BC674    8B8D DCFFFFFF   MOV ECX,DWORD PTR SS:[EBP-0x24]
732BC67A    E8 07FEFFFF     CALL 732BC486                            ; clr.732BC486
732BC67F    8BF0            MOV ESI,EAX

or
68988038    8B4D DC         MOV ECX,DWORD PTR SS:[EBP-0x24]
6898803B    E8 FEFDFFFF     CALL 68987E3E                            ; clr.68987E3E
68988040    8BF0            MOV ESI,EAX
68988042    8975 EC         MOV DWORD PTR SS:[EBP-0x14],ESI
68988045    C645 FC 02      MOV BYTE PTR SS:[EBP-0x4],0x2

72ddc64d c685fcffffff01  mov     byte ptr [ebp-4],1
72ddc654 c685fcffffff02  mov     byte ptr [ebp-4],2
72ddc65b 8bc1            mov     eax,ecx
72ddc65d 8985d8ffffff    mov     dword ptr [ebp-28h],eax
72ddc663 c685fcffffff03  mov     byte ptr [ebp-4],3
72ddc66a 57              push    edi
72ddc66b ff7508          push    dword ptr [ebp+8]
72ddc66e 8b95e4ffffff    mov     edx,dword ptr [ebp-1Ch]
72ddc674 8b8ddcffffff    mov     ecx,dword ptr [ebp-24h]
72ddc67a e807feffff      call    clr!ExecuteDLLForAttach (72ddc486)
72ddc67f 8bf0            mov     esi,eax
						 */

						
						
						if (current_code_len==max_code_len)
						{
							MessageBox.Show("Failed to find clr!ExecuteDLLForAttach");
							return null;
						}
						
					}

				}
				// MessageBox.Show((((uint)ptr).ToString(("X8"))));

				
				/* For exes (Execute = true) is this:
6603d089 c645fc04        mov     byte ptr [ebp-4],4
6603d08d 53              push    ebx
6603d08e ff156c12f565    call    dword ptr [clr!_imp__GetModuleHandleW (65f5126c)]
6603d094 50              push    eax
6603d095 e8aa000000      call    clr!ExecuteEXE (6603d144)
6603d09a 3bc3            cmp     eax,ebx
6603d09c 0f8474e50e00    je      clr!_CorExeMainInternal+0x1a3 (6612b616)

For dll:
633bd1c5 ff7514          push    dword ptr [ebp+14h]
633bd1c8 ff7510          push    dword ptr [ebp+10h]
633bd1cb ff750c          push    dword ptr [ebp+0Ch]
633bd1ce 53              push    ebx
633bd1cf e83c000000      call    clr!ExecuteDLLForAttach (633bd210)
633bd1d4 8945e8          mov     dword ptr [ebp-18h],eax
633bd1d7 c645fc02        mov     byte ptr [ebp-4],2

68988031    57              PUSH EDI
68988032    FF75 08         PUSH DWORD PTR SS:[EBP+0x8]
68988035    8B55 E4         MOV EDX,DWORD PTR SS:[EBP-0x1C]
68988038    8B4D DC         MOV ECX,DWORD PTR SS:[EBP-0x24]
6898803B    E8 FEFDFFFF     CALL 68987E3E                            ; clr.68987E3E
68988040    8BF0            MOV ESI,EAX
68988042    8975 EC         MOV DWORD PTR SS:[EBP-0x14],ESI
68988045    C645 FC 02      MOV BYTE PTR SS:[EBP-0x4],0x2

0x732BC614
// 0x732573E1

				 */

				

			}
			
			ptr++;
			IntPtr funcptr = (IntPtr) (((ptr + *(((uint*) ptr)))) + 4);
			
			
			Thread t = null;
			if (ExecuteExe)
			{

				ExeContext exeContext = new ExeContext();
				exeContext.lib = lib;
				exeContext.func = funcptr;
				if (is_last_fr)
				{
					int paramCount = 1;
					exeContext.func = DetourOriginalAddress(exeContext.func, paramCount);
				}

				t = new System.Threading.Thread(new System.Threading.ThreadStart(exeContext.ExecuteExe));

			}
			else
			{
				DllContext dllContext = new DllContext();
				dllContext.lib = lib;
				dllContext.func = funcptr;
				dllContext.dwReason = 1;  // DLL_PROCESS_ATTACH
				dllContext.fFromThunk = false;

				//dllContext.func = (IntPtr)0x732bc486;

				
				if (is_last_fr_load_dll)
				{
					int paramCount = 4;
					dllContext.func = DetourOriginalAddress(dllContext.func, paramCount);

				}

				t = new System.Threading.Thread(new System.Threading.ThreadStart(dllContext.ExecuteDll));
			}
			t.SetApartmentState(ApartmentState.STA);
			t.Start();

			while (t.IsAlive)
			{
				System.Windows.Forms.Application.DoEvents();
			}

			Assembly assembly = null;
			// Old stupid code: removed
			/*
Assembly[] assemblies = AppDomain.CurrentDomain.GetAssemblies();
for (int i=0;i<assemblies.Length;i++)
{
if (assemblies[i].FullName==rassemblyName.FullName)
{
assembly = assemblies[i];
break;
}
}
			 */

			// This code before won't load managed assemblies - assemblies with "IL only" flag set
			// mixed mode assemblies are already loaded,
			// managed assemblies will be loaded by Assembly.Load
			assembly = Assembly.Load(rassemblyName);

			if (assembly==null)
			{
				MessageBox.Show("Failed to load the assembly!");
				return null;
			}
			return assembly;
			
		}
		
		public static string Logs = "";
		
		// Adaptor methods here:
		public static Assembly LoadMixedAssembly(string ifilename)
		{
			return LoadMixedAssembly(ifilename,false);
		}
		
		[DllImport("kernel32.dll")]
		static extern IntPtr GetConsoleWindow();
		
		public static unsafe Assembly LoadMixedAssembly(string ifilename, bool ExecuteExe)
		{
			
			string textToPrint0 = "Mixed assembly loader!\r\n";
			if (GetConsoleWindow() != IntPtr.Zero)
				Console.Write(textToPrint0);
			else
				Logs = textToPrint0;
			
			if (IntPtr.Size==8&&DotNetAssemblyInfo.Is32BitsAssembly(ifilename))
			{
				string Error1 = "A 64 bits process can't load an 32 bits assembly";
				if (GetConsoleWindow() != IntPtr.Zero)
					Console.Write(Error1);
				else
					Logs += Error1;
				
				return null;
			}
			else if (IntPtr.Size==4&&!DotNetAssemblyInfo.Is32BitsAssembly(ifilename))
			{
				string Error2 = "A 32 bits process can't load an assembly 64 bits assembly";
				if (GetConsoleWindow() != IntPtr.Zero)
					Console.Write(Error2);
				else
					Logs += Error2;
				
				return null;
			}
			//byte[] asm_bytes = File.ReadAllBytes(ifilename);
			//IntPtr ptr = IntPtr.Zero;

			AssemblyName rassemblyName = null;
			try
			{
				rassemblyName = AssemblyName.GetAssemblyName(ifilename);
			}
			catch(Exception exc)
			{
				Console.WriteLine(exc.ToString());
				return null;
			}
			if (rassemblyName==null)
				return null;

			if (!DotNetAssemblyInfo.IsMixedModeAssembly(ifilename))
			{
				Logs += "\r\nNon mixed mode assembly detected!";
				try
				{
					Assembly assembly = Assembly.Load(rassemblyName);
					if (assembly==null)
					{
						MessageBox.Show("Failed to load the assembly!");
						return null;
					}
					if (GetConsoleWindow() != IntPtr.Zero)
						Console.WriteLine(Logs);
					
					return assembly;
				}
				catch(Exception exc)
				{
					Logs += "\r\n"+exc.ToString();
					if (GetConsoleWindow() != IntPtr.Zero)
						Console.WriteLine(Logs);
					
					return null;
				}
			}
			Logs += "\r\nMixed mode assembly detected!";
			IntPtr lib = LoadLibrary(ifilename);  // load assembly
			if (lib==IntPtr.Zero)
			{
				PEBinary pe = new PEBinary(ifilename);
				
				string archLog = String.Format("[+] Parsed. Arch: {0}, Type: {1}", pe.Is64Bit ? "x64" : "x86", pe.IsDll ? "DLL" : "EXE");
				if (GetConsoleWindow() != IntPtr.Zero)
					Console.WriteLine(archLog);
				else
					Logs += archLog+"\r\n";
				
				// Load the image into executable memory
				// This runs BuildImageBuffer, VirtualAlloc, ApplyRelocations, and EmulateIATWrite
				lib = pe.LoadImage(PEBinary.DefaultWin32Resolver);
				
				//Assembly asm1 = Assembly.LoadFrom(ifilename);
			}
			
			if (lib==IntPtr.Zero)
			{
				string LoadLibraryError = "Failed to load the assembly "+ifilename+" by any way!";
				if (GetConsoleWindow() != IntPtr.Zero)
					Console.WriteLine(LoadLibraryError);
				else
					Logs += LoadLibraryError+"\r\n";
				
				return null;
			}
			
			Assembly asm = LoadMixedAssembly_Main(rassemblyName,lib,ExecuteExe);
			if (GetConsoleWindow() != IntPtr.Zero)
				Console.WriteLine(Logs);
			
			return asm;
			

		}

		
		
	}
}
