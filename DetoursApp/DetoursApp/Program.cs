using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using System.Threading;
using System.Management;
using System.ServiceProcess;

namespace DetoursApp
{
    class Program
    {
        public static void ExecuteCommandSync(string command)
        {
            try
            {
                // create the ProcessStartInfo using "cmd" as the program to be run,
                // and "/c " as the parameters.
                // Incidentally, /c tells cmd that we want it to execute the command that follows,
                // and then exit.
                System.Diagnostics.ProcessStartInfo procStartInfo =
                    new System.Diagnostics.ProcessStartInfo("cmd", "/c " + command);

                // The following commands are needed to redirect the standard output.
                // This means that it will be redirected to the Process.StandardOutput StreamReader.
                procStartInfo.RedirectStandardOutput = true;
                procStartInfo.UseShellExecute = false;
                // Do not create the black window.
                procStartInfo.CreateNoWindow = true;
                // Now we create a process, assign its ProcessStartInfo and start it
                System.Diagnostics.Process proc = new System.Diagnostics.Process();
                proc.StartInfo = procStartInfo;
                proc.Start();
                // Get the output into a string
                string result = proc.StandardOutput.ReadToEnd();
                // Display the command output.
                Console.WriteLine(result);
            }
            catch (Exception ex)
            {
                System.Console.WriteLine(ex.Message);
            }
        }

        private static uint GetProcessIDByServiceName(string serviceName)
        {
            uint processId = 0;
            string qry = "SELECT PROCESSID FROM WIN32_SERVICE WHERE NAME = '" + serviceName + "'";
            System.Management.ManagementObjectSearcher searcher = new System.Management.ManagementObjectSearcher(qry);
            foreach (System.Management.ManagementObject mngntObj in searcher.Get())
            {
                processId = (uint)mngntObj["PROCESSID"];
            }
            return processId;
        }

        private static uint GetProcessIDByServiceDisplayName(string serviceDisplayName)
        {
            uint processId = 0;
            string qry = "SELECT PROCESSID FROM WIN32_SERVICE WHERE DISPLAYNAME = '" + serviceDisplayName + "'";
            System.Management.ManagementObjectSearcher searcher = new System.Management.ManagementObjectSearcher(qry);
            foreach (System.Management.ManagementObject mngntObj in searcher.Get())
            {
                processId = (uint)mngntObj["PROCESSID"];
            }
            return processId;
        }

        private static List<System.ServiceProcess.ServiceController> GetRunningServices()
        {
            System.ServiceProcess.ServiceController[] services = System.ServiceProcess.ServiceController.GetServices();
            List<System.ServiceProcess.ServiceController> running = new List<System.ServiceProcess.ServiceController>();

            foreach (System.ServiceProcess.ServiceController item in services)
            {
                if (item.Status == System.ServiceProcess.ServiceControllerStatus.Running)
                {
                    running.Add(item);
                }
            }
            return running;
        }


        /*
        [DllImport("DetoursDll.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern void DetourAttachSleepFunc();

        [DllImport("DetoursDll.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern void DetourAttachThumbnailGenerationFunc();

        [DllImport("DetoursDll.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern void DetourDetachThumbnailGenerationFunc();
        */
        static void Main(string[] args)
        {
            // Thread.Sleep(5000);
            // DetourAttachSleepFunc();

            // DetourAttachThumbnailGenerationFunc();

            // ExecuteCommandSync("E:\\Detours\\DllInjector\\DllInjector.exe");
            System.Console.WriteLine("Pserv process id: " + GetProcessIDByServiceDisplayName("PServ").ToString());
            System.Console.WriteLine("application done");
            System.Console.ReadKey(true);
        }
    }
}
