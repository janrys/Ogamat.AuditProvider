using Microsoft.Win32;
using Ogamat.AuditProvider.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Ogamat.AuditProvider
{
    using Win32Exception = System.ComponentModel.Win32Exception;

    public sealed class EventSourceInstaller
    {
        static readonly string ApplicationKey = @"SYSTEM\CurrentControlSet\Services\EventLog\Application";

        //
        // The class contains static methods only
        // This declaration prevents the compiler from generating
        // a default constructor
        //

        private EventSourceInstaller()
        {
        }

        /// <summary>
        /// Register event log source
        /// </summary>
        /// <param name="sourceName">Name of the security event source</param>
        /// <param name="eventMessageFile">Full path to a resource DLL to interpret events in event viewer (optional)</param>
        /// <param name="eventSourceXmlSchemaFile"></param>
        /// <param name="eventAccessStringsFile"></param>
        /// <param name="executableImagePath">Full path to the executable file that is authorized to generate messages under this source name  (optional)</param>
        /// <param name="allowMultipleInstances">Flag indicating whether multiple instances of the process can log under this source name simultaneously</param>
        public static void InstallSecurityEventSource(
            string sourceName,
            string eventMessageFile,
            string eventSourceXmlSchemaFile,
            string eventAccessStringsFile,
            string executableImagePath,
            bool allowMultipleInstances)
        {
            if (sourceName == null)
            {
                throw new ArgumentNullException(nameof(sourceName));
            }

            if (!SourceNameValidator.IsSourceNameValid(sourceName))
            {
                throw new ArgumentException("Invalid event source name", nameof(sourceName));
            }

            try
            {
                Win32Native.AUTHZ_SOURCE_SCHEMA_REGISTRATION schema = new Win32Native.AUTHZ_SOURCE_SCHEMA_REGISTRATION();
                schema.dwFlags = allowMultipleInstances ? (uint)1 : (uint)0;
                schema.eventSourceName = sourceName;
                schema.eventMessageFile = eventMessageFile;
                schema.eventSourceXmlSchemaFile = eventSourceXmlSchemaFile;
                schema.eventAccessStringsFile = eventAccessStringsFile;
                schema.executableImagePath = executableImagePath;
                schema.pReserved = IntPtr.Zero;
                schema.dwObjectTypeNameCount = 0;
                schema.objectTypeNames.dwOffset = 0;
                schema.objectTypeNames.szObjectTypeName = null;

                if (false == Win32Native.AuthzInstallSecurityEventSource(0, schema))
                {
                    int error = Marshal.GetLastWin32Error();

                    if (error == Win32Native.ERROR_NOT_ENOUGH_MEMORY)
                    {
                        throw new OutOfMemoryException();
                    }
                    else if (error == Win32Native.ERROR_ACCESS_DENIED)
                    {
                        throw new UnauthorizedAccessException();
                    }
                    else if (error == Win32Native.ERROR_OBJECT_ALREADY_EXISTS)
                    {
                        throw new InvalidOperationException("Event source already exists");
                    }
                    else
                    {
                        throw new Win32Exception(error);
                    }
                }
            }
            catch (EntryPointNotFoundException)
            {
                throw new NotSupportedException("Platform not supported");
            }
        }

        public static void InstallApplicationEventSource(string sourceName, string eventMessageFile, string parameterMessageFile)
        {
            if (sourceName == null)
            {
                throw new ArgumentNullException(nameof(sourceName));
            }

            if (!SourceNameValidator.IsSourceNameValid(sourceName))
            {
                throw new ArgumentException("Invalid event source name", nameof(sourceName));
            }

            RegistryKey rkApplication = null;
            RegistryKey rkSource = null;

            try
            {
                rkApplication = Registry.LocalMachine.OpenSubKey(ApplicationKey, true);

                //
                // Cheap and dirty check for duplicates
                // Do it to be consistent with the security log installation logic
                // even if it means using a non-thread-safe method of doing so
                //

                rkSource = rkApplication.OpenSubKey(sourceName, true);

                if (rkSource != null)
                {
                    throw new InvalidOperationException("Event source already exists");
                }

                rkSource = rkApplication.CreateSubKey(sourceName);

                if (eventMessageFile != null)
                {
                    rkSource.SetValue("EventMessageFile", eventMessageFile /* , RegistryValueKind.ExpandString */ );
                }

                if (parameterMessageFile != null)
                {
                    rkSource.SetValue("ParameterMessageFile", parameterMessageFile /* , RegistryValueKind.ExpandString */ );
                }

                rkSource.SetValue("TypesSupported", 0x18);
            }
            finally
            {
                if (rkSource != null)
                {
                    rkSource.Close();
                }

                if (rkApplication != null)
                {
                    rkApplication.Close();
                }
            }
        }

        public static void UninstallSecurityEventSource(string sourceName)
        {
            if (sourceName == null)
            {
                throw new ArgumentNullException(nameof(sourceName));
            }

            if (!SourceNameValidator.IsSourceNameValid(sourceName))
            {
                throw new ArgumentException("Invalid event source name", nameof(sourceName));
            }

            try
            {
                if (false == Win32Native.AuthzUninstallSecurityEventSource(0, sourceName))
                {
                    int error = Marshal.GetLastWin32Error();

                    if (error == Win32Native.ERROR_NOT_ENOUGH_MEMORY)
                    {
                        throw new OutOfMemoryException();
                    }
                    else if (error == Win32Native.ERROR_ACCESS_DENIED)
                    {
                        throw new UnauthorizedAccessException();
                    }
                    else if (error == Win32Native.ERROR_FILE_NOT_FOUND)
                    {
                        // swallow this exception
                        error = 0;
                    }
                    else
                    {
                        throw new Win32Exception(error);
                    }
                }
            }
            catch (EntryPointNotFoundException)
            {
                throw new NotSupportedException("Platform not supported");
            }
        }

        public static void UninstallApplicationEventSource(string sourceName)
        {
            if (sourceName == null)
            {
                throw new ArgumentNullException(nameof(sourceName));
            }

            if (!SourceNameValidator.IsSourceNameValid(sourceName))
            {
                throw new ArgumentException("Invalid event source name", nameof(sourceName));
            }

            RegistryKey rkApplication = null;

            try
            {
                rkApplication = Registry.LocalMachine.OpenSubKey(ApplicationKey, true);
                rkApplication.DeleteSubKey(sourceName, false);
            }
            finally
            {
                if (rkApplication != null)
                {
                    rkApplication.Close();
                }
            }
        }
    }
}
