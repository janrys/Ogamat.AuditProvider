using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ogamat.AuditProvider
{
    public sealed class SourceNameValidator
    {
        //
        // This class contains static methods only.  Add a constructor
        // below to prevent the compiler from generating a default constructor
        //

        private SourceNameValidator()
        {
        }

        public static bool IsSourceNameValid(string sourceName)
        {
            if (sourceName == null)
            {
                throw new ArgumentNullException(nameof(sourceName));
            }

            if (sourceName.Length == 0 || sourceName.Length > 255)
            {
                return false;
            }

            if (sourceName.IndexOf(';') >= 0)
            {
                return false;
            }

            if (sourceName[0] == '\\')
            {
                return false;
            }

            if (sourceName.ToUpper(CultureInfo.InvariantCulture).Equals("SECURITY"))
            {
                return false;
            }

            return true;
        }
    }
}
