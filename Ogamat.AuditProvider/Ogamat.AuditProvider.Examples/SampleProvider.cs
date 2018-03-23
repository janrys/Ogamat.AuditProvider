using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ogamat.AuditProvider.Examples
{
    public class SampleProvider : AuditProvider
    {
        public SampleProvider(SamplePolicy policy)
            : base(policy, Program.EventLogName, LogLocation.SecurityLog)
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

        public void AuditAuthenticationSuccess(string userName)
        {
            ReportAudit(3, true, userName);
        }

        public void AuditAuthenticationFailure(string userName)
        {
            ReportAudit(4, false, userName);
        }

        public void AuditAuthorizationSuccess(string userName, string objectName)
        {
            ReportAudit(5, true, userName, objectName);
        }

        public void AuditAuthorizationFailure(string userName, string objectName)
        {
            ReportAudit(6, false, userName, objectName);
        }
    }
}
