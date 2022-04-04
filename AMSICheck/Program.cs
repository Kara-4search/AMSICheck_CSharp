using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace AMSICheck
{
    public class Program
    {
        byte[] egg64 = new byte[] {
                    0x4C, 0x8B, 0xDC,       // mov     r11,rsp
                    0x49, 0x89, 0x5B, 0x08, // mov     qword ptr [r11+8],rbx
                    0x49, 0x89, 0x6B, 0x10, // mov     qword ptr [r11+10h],rbp
                    0x49, 0x89, 0x73, 0x18, // mov     qword ptr [r11+18h],rsi
                    0x57,                   // push    rdi
                    0x41, 0x56,             // push    r14
                    0x41, 0x57,             // push    r15
                    0x48, 0x83, 0xEC, 0x70  // sub     rsp,70h
        };
        byte[] egg86 = new byte[] {
                    0x8B, 0xFF,             // mov     edi,edi
                    0x55,                   // push    ebp
                    0x8B, 0xEC,             // mov     ebp,esp
                    0x83, 0xEC, 0x18,       // sub     esp,18h
                    0x53,                   // push    ebx
                    0x56                    // push    esi
        };

        [DllImport("kernel32")]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32")]
        private static extern IntPtr LoadLibrary(string name);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern Boolean NtReadVirtualMemory(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            IntPtr Buffer,
            UInt32 NumberOfBytesToRead,
            ref UInt32 liRet
        );

        [DllImport("kernel32.dll")]
        public static extern void RtlZeroMemory(
            IntPtr pBuffer,
            int length
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();


        private static bool is64Bit()
        {
            bool is64Bit = true;

            if (IntPtr.Size == 4)
                is64Bit = false;

            return is64Bit;
        }

        public static void functionCheck(byte[] egg, string dllname, string funcname)
        {
            IntPtr hModule = LoadLibrary(dllname);
            IntPtr function_address = GetProcAddress(hModule, funcname);
            IntPtr current_process_handle = GetCurrentProcess();

            int egg_length = egg.Length;
            uint liRet = 0;

            IntPtr buffer_array_address = Marshal.AllocHGlobal(egg_length);
            RtlZeroMemory(buffer_array_address, egg_length);


            Boolean result = NtReadVirtualMemory(
                current_process_handle,
                function_address,
                buffer_array_address,
                (UInt32)egg_length,
                ref liRet
            );

            byte[] CheckArray = new byte[egg_length];
            byte temp;

            for (int count = 0; count < egg_length; count++)
            {
                temp = Marshal.ReadByte(buffer_array_address, count);
                CheckArray[count] = temp;
            }


            if (CompareArray(CheckArray, egg))
            {
                Console.WriteLine("Yes");
            }
            else
            {
                Console.WriteLine("No");
            }

        }

        public static bool CompareArray(byte[] bt1, byte[] bt2)
        {
            var len1 = bt1.Length;
            var len2 = bt2.Length;
            if (len1 != len2)
            {
                return false;
            }
            for (var i = 0; i < len1; i++)
            {
                if (bt1[i] != bt2[i])
                    return false;
            }
            return true;
        }
        public static void start()
        {
            new Program();
        }

        public Program()
        {
            if (is64Bit())
            {
                // Patch("amsi.dll", "DllCanUnloadNow", egg64, patch64);
                functionCheck(egg64, "amsi.dll", "AmsiScanBuffer");
            }
            else
            {
                // Patch("amsi.dll", "DllCanUnloadNow", egg86, patch86);
            }
        }

        static void Main(string[] args)
        {
            new Program();

        }
    }
}
