using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Ogamat.AuditProvider.Examples
{
    class Program
    {
        public static string EventLogName = "Log App Test";
        static void Main(string[] args)
        {
            RegisterEventSource();
            UseAuditProvider();
            UnRegisterEventSource();
        }


        private static void RegisterEventSource()
        {
            EventSourceInstaller.InstallSecurityEventSource(
                    EventLogName,
                    null, //@"D:\Auditing\SampleApplication\SampleMessageFile.DLL",
                    null,
                    null,                    
                    Assembly.GetEntryAssembly().Location, //@"D:\Auditing\SampleApplication\Ogamat.AuditProvider.Examples.exe",
                    false);
        }

        private static void UseAuditProvider()
        {
            SamplePolicy policy = new SamplePolicy();
            SampleProvider provider = new SampleProvider(policy);
            Guid instanceId = Guid.NewGuid();

            Boolean isCanceled = false;
            Console.CancelKeyPress += (object sender, ConsoleCancelEventArgs e) => { isCanceled = true; e.Cancel = true; };

            provider.AuditApplicationInitialization(instanceId);
            while (!isCanceled)
            {
                provider.AuditAuthenticationSuccess("log entry");
                Console.WriteLine("Logged new entry. Press CTRL+C to stop ...");
                Thread.Sleep(1000);                
            }
            provider.AuditApplicationTermination(instanceId);
        }

        private static void UnRegisterEventSource()
        {
            EventSourceInstaller.UninstallSecurityEventSource(EventLogName);
        }
    }
}
