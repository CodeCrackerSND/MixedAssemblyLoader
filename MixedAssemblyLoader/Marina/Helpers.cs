using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
//using static System.Runtime.InteropServices.JavaScript.JSType;

namespace Marina
{
    public static class Helpers
    {
        // Helper function to read a structure of type T from bytes starting at the given offset.
        public static T FromBytes<T>(byte[] Data, int offset) where T : struct
        {
            int size = Marshal.SizeOf(typeof(T));
            byte[] bytes = new byte[size];
            Buffer.BlockCopy(Data, offset, bytes, 0, size);
            GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            T result = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();
            return result;
        }

        /*
        // Print the banner cus it's kewl
        public static void PrintBanner()
        {
            Console.Title = "Marina PE Loader v1.0";
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine(@"
███╗   ███╗ █████╗ ██████╗ ██╗███╗  ██╗ █████╗   ██╗   ██╗  ███╗      █████╗ 
████╗ ████║██╔══██╗██╔══██╗██║████╗ ██║██╔══██╗  ██║   ██║ ████║     ██╔══██╗
██╔████╔██║███████║██████╔╝██║██╔██╗██║███████║  ╚██╗ ██╔╝██╔██║     ██║  ██║
██║╚██╔╝██║██╔══██║██╔══██╗██║██║╚████║██╔══██║   ╚████╔╝ ╚═╝██║     ██║  ██║
██║ ╚═╝ ██║██║  ██║██║  ██║██║██║ ╚███║██║  ██║    ╚██╔╝  ███████╗██╗╚█████╔╝
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚══╝╚═╝  ╚═╝     ╚═╝   ╚══════╝╚═╝ ╚════╝ ");
            Console.ResetColor();
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Yellow;

            Console.WriteLine("[~] Marina is an educational Windows PE loader (manual mapping demo)");
            Console.WriteLine("[~] Named in memory of my grandmother, Marina (RIP 2020)");
            Console.WriteLine("[~] Handles only simple PE files, nothing fancy here.");
            Console.WriteLine("[~] For a demo and usage, see the GitHub README.");
            Console.WriteLine("[~] If you hit an access violation, the PE is likely too complex.");
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("[+] Author: ApparentlyPlus (Chatzikallias Panagiotis)");
            Console.WriteLine();
            Console.ResetColor();
            Console.WriteLine(new string('-', 80));
            Console.WriteLine();
        }
        */
    }
}
