using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ogamat.AuditProvider.Examples
{
    public class SamplePolicy : AuditPolicy
    {
        private bool[] state = new bool[6];
        

        public SamplePolicy()
        {
            // Initialization and termination audits are always enabled
            state[0] = true;
            state[1] = true;            
        }

        public override bool IsEventEnabled(int eventId)
        {
            lock (this) { return state[eventId - 1]; }
        }

        public bool AuthenticationSuccessEnabled
        {
            get { lock (this) { return state[2]; } }
            set { lock (this) { state[2] = value; } }
        }

        public bool AuthenticationFailureEnabled
        {
            get { lock (this) { return state[3]; } }
            set { lock (this) { state[3] = value; } }
        }

        public bool AuthorizationSuccessEnabled
        {
            get { lock (this) { return state[4]; } }
            set { lock (this) { state[4] = value; } }
        }

        public bool AuthorizationFailureEnabled
        {
            get { lock (this) { return state[5]; } }
            set { lock (this) { state[5] = value; } }
        }
    }
}
