using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ogamat.AuditProvider
{
    public abstract class AuditPolicy
    {
        public abstract bool IsEventEnabled(int eventId);
    }
}
