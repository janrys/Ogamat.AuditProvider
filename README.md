# Ogamat.AuditProvider
.Net audit provider for managing and logging into windows event logs (security log, application log)

## How-to:

Write your own implementation of Ogamat.AuditProvider.AuditProvider class. You need to provide

**Policy** = your own implementation of Ogamat.AuditProvider.AuditPolicy to allow logging specific event ids

**EventLogName** = string, name of the event log

**LogLocation** = enum (application log or security log)

Add methods for logging specififc events. Example:

    public class SampleProvider : AuditProvider
    {
        public SampleProvider(SamplePolicy policy)
            : base(policy, "SampleAppEventLog", LogLocation.SecurityLog)
        {
        }

        public void AuditApplicationInitialization(Guid instanceId)
        {
            ReportAudit(1, true, instanceId);
        }

        public void AuditApplicationTermination(Guid instanceId)
        {
            ReportAudit(2, true, instanceId);
        }
    }


Security event source registration:

    EventSourceInstaller.InstallSecurityEventSource(
                    EventLogName,
                    null,
                    null,
                    null,                    
                    Assembly.GetEntryAssembly().Location,
                    false);

You need to set special policies to use security event log (use secpol.msc Microsoft Management Console):

    Local Policies / Audit Policy / Audit object access = Success, Failure 
    Local Policies / User Rights Assignment / Manage auditing and security log
    Local Policies / User Rights Assignment / Generate security audits

and you must be an administrator to register security event source.

Based on article and source code from MSDN Magazine written by Mark Novak from Microsoft
