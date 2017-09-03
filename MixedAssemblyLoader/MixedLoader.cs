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

namespace MixedAssemblyLoader
{
	/// <summary>
	/// Description of MixedLoader.
	/// </summary>
	public class MixedLoader
	{

		public static void Main(string[] args)
		{
			Console.WriteLine("Mixed assembly loader!");
			string filename = "D:\\Cracking\\a.exe";
			Assembly asm = MixedLoader.LoadMixedAssembly(filename,false);
			//Console.ReadKey(true);
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

    
    }
}
	
[UnmanagedFunctionPointer(System.Runtime.InteropServices.CallingConvention.StdCall)]
private delegate int ExecuteEXE(IntPtr hInst);

[UnmanagedFunctionPointer(System.Runtime.InteropServices.CallingConvention.StdCall)]
private delegate int ExecuteDLL(IntPtr hInst, int dwReason, IntPtr lpReserved,bool fFromThunk);

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
  
  		public static unsafe Assembly LoadMixedAssembly(AssemblyName rassemblyName, IntPtr lib, bool ExecuteExe)
		{

string MainFunctionName = "_CorDllMain";
if (ExecuteExe)  // is true the exe will be executed!
MainFunctionName = "_CorExeMain";

int max_code_len = 1024;  // maximum 1 KB
int current_code_len = 0;
		
		bool is_last_fr = false;
		bool is_fr4 = false;
		bool is_last_fr_load_dll = false;
		
		byte* ptr = (byte*)0;
        IntPtr mscorwks_Address = LoadLibrary("mscorwks.dll");
        if (mscorwks_Address==IntPtr.Zero)
        {
        mscorwks_Address = LoadLibrary("clr.dll");
        is_fr4 = true;
        }
        // mscorwks!_CorDllMain
        ptr = (byte*) GetProcAddress(mscorwks_Address, MainFunctionName).ToPointer();
        if ((uint)ptr==0)
        {
        MessageBox.Show("Failed to find mscorwks."+MainFunctionName+" or clr."+MainFunctionName+" !");
        return null;
        }

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
*/
	if (ExecuteExe&&(ptr[0] == 0xe8) && (*((ptr - 3)) == 0x89) && (*((ptr - 2)) == 0x45) && (*((ptr - 1)) == 0xfc) && (ptr[5] == 0xc7) && ((ptr + 5)[1] == 0x45) && ((ptr + 5)[2] == 0xfc))
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
     (ptr[5] == 0x89) && ((ptr + 5)[1] == 0x45)&&(ptr[8] == 0xc7) && ((ptr + 8)[1] == 0x45))
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
	
	if ((ptr[0] == 0xe8) && (*(ptr - 3) == 0x08B) && (*((ptr - 6)) == 0x08B) && (*((ptr - 9)) == 0x0FF))  // &&((ptr[1]&0xF0) == 0x080)
	{
	is_last_fr_load_dll = true;
	break;
	}
	
	if (current_code_len==max_code_len)
    {
    MessageBox.Show("Failed to find clr!ExecuteDLLForAttach");
    return null;
    }
	
	}

		}
		

        
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
  		
  		// Adaptor methods here:
  		public static Assembly LoadMixedAssembly(string ifilename)
		{
  		return LoadMixedAssembly(ifilename,false);
  		}
  		
		public static unsafe Assembly LoadMixedAssembly(string ifilename, bool ExecuteExe)
		{

byte[] asm_bytes = File.ReadAllBytes(ifilename);
IntPtr ptr = IntPtr.Zero;


AssemblyName rassemblyName = null;
try
{
rassemblyName = AssemblyName.GetAssemblyName(ifilename);
}
catch(Exception exc)
{
return null;
}
if (rassemblyName==null)
return null;

    	IntPtr lib = LoadLibrary(ifilename);  // load assembly
    	return LoadMixedAssembly(rassemblyName,lib,ExecuteExe);

		}

		
	
	}
}
