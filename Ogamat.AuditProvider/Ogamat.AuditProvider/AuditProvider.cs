using Ogamat.AuditProvider.Win32;
using System;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Ogamat.AuditProvider
{
    /// <summary>
    /// Base class for audit logging
    /// For logging to security log you mast set policies: 
    /// Local Policies / Audit Policy / Audit object access = Success, Failure 
    /// Local Policies / User Rights Assignment / Manage auditing and security log
    /// Local Policies / User Rights Assignment / Generate security audits
    /// </summary>
    public abstract class AuditProvider : IDisposable
    {
        static HybridDictionary mapper = new HybridDictionary();

        IntPtr securityLogHandle = IntPtr.Zero;
        IntPtr applicationLogHandle = IntPtr.Zero;
        readonly AuditPolicy auditPolicy;
        bool disposed = false;

        public static readonly int MaximumNumberOfParameters = 32;

        static AuditProvider()
        {
            mapper.Add(typeof(string), AUDIT_PARAM_TYPE.APT_String);
            mapper.Add(typeof(uint), AUDIT_PARAM_TYPE.APT_Ulong);
            /*
                        mapper.Add( typeof( SecurityIdentifier ), AUDIT_PARAM_TYPE.APT_Sid );
            */
            mapper.Add(typeof(Guid), AUDIT_PARAM_TYPE.APT_Guid);
            mapper.Add(typeof(DateTime), AUDIT_PARAM_TYPE.APT_Time);
            mapper.Add(typeof(UInt64), AUDIT_PARAM_TYPE.APT_Int64);
        }

        protected AuditProvider(AuditPolicy auditPolicy, string sourceName, LogLocation location)
        {
            if (auditPolicy == null)
            {
                throw new ArgumentNullException(nameof(auditPolicy));
            }

            if (sourceName == null)
            {
                throw new ArgumentNullException(nameof(sourceName));
            }

            if (!SourceNameValidator.IsSourceNameValid(sourceName))
            {
                throw new ArgumentException("Invalid event source name", nameof(sourceName));
            }

            if (location != LogLocation.ApplicationLog &&
                location != LogLocation.SecurityLog)
            {
                throw new ArgumentOutOfRangeException(nameof(location), "Invalid enum");
            }

            this.auditPolicy = auditPolicy;

            if (location == LogLocation.SecurityLog)
            {
                Privilege privilege = new Privilege(Privilege.Audit);

                try
                {
                    privilege.Enable();

                    if (false == Win32Native.AuthzRegisterSecurityEventSource(0, sourceName, ref this.securityLogHandle))
                    {
                        int error = Marshal.GetLastWin32Error();

                        if (error == Win32Native.ERROR_NOT_ENOUGH_MEMORY)
                        {
                            throw new OutOfMemoryException();
                        }
                        else if (error == Win32Native.ERROR_INVALID_PARAMETER)
                        {
                            // Marshaling failed!
                            throw new Win32Exception(error);
                        }
                        else if (error == Win32Native.ERROR_ACCESS_DENIED)
                        {
                            throw new UnauthorizedAccessException();
                        }
                        else if (error == Win32Native.ERROR_PRIVILEGE_NOT_HELD)
                        {
                            // Privilege should be enabled by now!
                            throw new PrivilegeNotHeldException(Privilege.Audit);
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
                finally
                {
                    privilege.Revert();
                }
            }
            else // application log
            {
                this.applicationLogHandle = Win32Native.RegisterEventSource(null, sourceName);

                if (this.applicationLogHandle.Equals(IntPtr.Zero))
                {
                    int error = Marshal.GetLastWin32Error();

                    if (error == Win32Native.ERROR_NOT_ENOUGH_MEMORY)
                    {
                        throw new OutOfMemoryException();
                    }
                    else if (error == Win32Native.ERROR_INVALID_PARAMETER)
                    {
                        // Marshaling failed!
                        throw new Win32Exception(error);
                    }
                    else if (error == Win32Native.ERROR_ACCESS_DENIED)
                    {
                        throw new UnauthorizedAccessException();
                    }
                    else
                    {
                        throw new Win32Exception(error);
                    }
                }
            }
        }

        ~AuditProvider()
        {
            Dispose(false);
        }

        private void WriteToSecurityLog(int auditId, bool success, params object[] parameters)
        {
            ThrowIfDisposed();

            //
            // Report the event
            //

            IntPtr paramArray = IntPtr.Zero;
            GCHandle[] handleArray = null;

            try
            {
                if (parameters.Length > 0)
                {
                    handleArray = new GCHandle[parameters.Length + 1];
                    int j = 0;
                    handleArray[j] = GCHandle.Alloc(new byte[Marshal.SizeOf(typeof(Win32Native.AUDIT_PARAM)) * parameters.Length], GCHandleType.Pinned);
                    paramArray = handleArray[j].AddrOfPinnedObject();
                    j++;

                    for (int i = 0; i < parameters.Length; i++)
                    {
                        Win32Native.AUDIT_PARAM paramArrayElement = new Win32Native.AUDIT_PARAM();
                        paramArrayElement.Flags = 0;
                        paramArrayElement.Length = 0;

                        System.Type type = parameters[i].GetType();

                        if (type == typeof(String))
                        {
                            paramArrayElement.Type = (uint)AUDIT_PARAM_TYPE.APT_String;
                            handleArray[j] = GCHandle.Alloc((parameters[i] as string), GCHandleType.Pinned);
                            paramArrayElement.Data0 = handleArray[j].AddrOfPinnedObject();
                            paramArrayElement.Data1 = IntPtr.Zero;
                            j++;
                        }
                        else if (type == typeof(uint) ||
                            type == typeof(ushort) ||
                            type == typeof(byte) ||
                            type == typeof(int) ||
                            type == typeof(short) ||
                            type == typeof(sbyte))
                        {
                            paramArrayElement.Type = (uint)AUDIT_PARAM_TYPE.APT_Ulong;
                            paramArrayElement.Data0 = new IntPtr((int)parameters[i]);
                            paramArrayElement.Data1 = IntPtr.Zero;
                        }
                        /*
                                                else if ( type == typeof( SecurityIdentifier ))
                                                {
                                                    SecurityIdentifier sid = parameters[i] as SecurityIdentifier;
                                                    byte[] binaryForm = new byte[sid.BinaryLength];
                                                    sid.GetBinaryForm( binaryForm, 0 );

                                                    paramArrayElement.Type = ( uint )AUDIT_PARAM_TYPE.APT_Sid;
                                                    // Can use BinaryForm property if inside of BCL
                                                    handleArray[j] = GCHandle.Alloc( binaryForm, GCHandleType.Pinned );
                                                    paramArrayElement.Data0 = handleArray[j].AddrOfPinnedObject();
                                                    paramArrayElement.Data1 = IntPtr.Zero;
                                                    j++;
                                                }
                        */
                        else if (type == typeof(Guid))
                        {
                            paramArrayElement.Type = (uint)AUDIT_PARAM_TYPE.APT_Guid;
                            handleArray[j] = GCHandle.Alloc(((Guid)parameters[i]).ToByteArray(), GCHandleType.Pinned);
                            paramArrayElement.Data0 = handleArray[j].AddrOfPinnedObject();
                            paramArrayElement.Data1 = IntPtr.Zero;
                            j++;
                        }
                        else if (type == typeof(DateTime))
                        {
                            paramArrayElement.Type = (uint)AUDIT_PARAM_TYPE.APT_Time;
                            paramArrayElement.Data0 = new IntPtr((int)(((DateTime)parameters[i]).ToFileTime() & 0xFFFFFFFF));
                            paramArrayElement.Data1 = new IntPtr((int)((((DateTime)parameters[i]).ToFileTime() >> 32) & 0xFFFFFFFF));
                        }
                        // Add LogonId and Luid support, if necessary
                        else if (type == typeof(Int64) ||
                            type == typeof(UInt64))
                        {
                            paramArrayElement.Type = (uint)AUDIT_PARAM_TYPE.APT_Int64;
                            paramArrayElement.Data0 = new IntPtr((int)((uint)parameters[i]) & 0xFFFFFFFF);
                            paramArrayElement.Data1 = new IntPtr((int)(((int)parameters[i] >> 32) & 0xFFFFFFFF));
                        }
                        else
                        {
                            throw new ArgumentException("Type unsuitable for auditing", nameof(parameters));
                        }

                        //
                        // Marshal the structure into the parameters array
                        //

                        Marshal.StructureToPtr(paramArrayElement, new IntPtr(paramArray.ToInt64() + i * Marshal.SizeOf(typeof(Win32Native.AUDIT_PARAM))), false);
                    }
                }

                Win32Native.AUDIT_PARAMS auditParams = new Win32Native.AUDIT_PARAMS();
                auditParams.Length = 0;
                auditParams.Flags = success ? Win32Native.APF_AuditSuccess : Win32Native.APF_AuditFailure;
                unchecked { auditParams.Count = (ushort)parameters.Length; }
                auditParams.Parameters = paramArray;

                if (false == Win32Native.AuthzReportSecurityEventFromParams(0, this.securityLogHandle, (uint)auditId, null, auditParams))
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
                    else if (error == Win32Native.ERROR_INVALID_PARAMETER)
                    {
                        // Marshaling failed!
                        throw new Win32Exception(error);
                    }
                    else
                    {
                        throw new Win32Exception(error);
                    }
                }
            }
            finally
            {
                if (handleArray != null)
                {
                    for (int i = 0; i < handleArray.Length; i++)
                    {
                        if (handleArray[i].IsAllocated)
                        {
                            handleArray[i].Free();
                        }
                    }
                }
            }
        }

        private void WriteToApplicationLog(int auditId, bool success, params object[] parameters)
        {
            ThrowIfDisposed();

            //
            // Report the event
            //

            IntPtr[] paramArray = null;
            GCHandle[] handleArray = null;

            try
            {
                if (parameters.Length > 0)
                {
                    handleArray = new GCHandle[parameters.Length];
                    paramArray = new IntPtr[parameters.Length];

                    for (int i = 0; i < parameters.Length; i++)
                    {
                        handleArray[i] = GCHandle.Alloc(parameters[i].ToString(), GCHandleType.Pinned);
                        paramArray[i] = handleArray[i].AddrOfPinnedObject();
                    }
                }

                const ushort successFlag = 0x08;
                const ushort failureFlag = 0x10;

                if (false == Win32Native.ReportEvent(
                        this.applicationLogHandle,
                        success ? successFlag : failureFlag,
                        0, // no category
                        auditId,
                        null,
                        (ushort)parameters.Length,
                        0,
                        paramArray,
                        null))
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
                    else if (error == Win32Native.ERROR_INVALID_PARAMETER)
                    {
                        throw new Win32Exception(error);
                    }
                    else
                    {
                        throw new Win32Exception(error);
                    }
                }
            }
            finally
            {
                for (int i = 0; i < handleArray.Length; i++)
                {
                    if (handleArray[i].IsAllocated)
                    {
                        handleArray[i].Free();
                    }
                }
            }
        }

        protected void ReportAudit(int auditId, bool success, params object[] parameters)
        {
            //
            // Unless the event is enabled, bail out now
            //

            if (!this.auditPolicy.IsEventEnabled(auditId))
            {
                return;
            }

            //
            // Validate the parameters
            //

            if (parameters != null)
            {
                if (parameters.Length > MaximumNumberOfParameters)
                {
                    throw new ArgumentOutOfRangeException(nameof(parameters), "Invalid array length (greater than" + MaximumNumberOfParameters + ")");
                }

                foreach (object o in parameters)
                {
                    if (!mapper.Contains(o.GetType()))
                    {
                        throw new ArgumentException("Type unsuitable for auditing", nameof(parameters));
                    }
                }
            }

            if (!this.securityLogHandle.Equals(IntPtr.Zero))
            {
                WriteToSecurityLog(auditId, success, parameters);
            }
            else if (!this.applicationLogHandle.Equals(IntPtr.Zero))
            {
                WriteToApplicationLog(auditId, success, parameters);
            }
        }

        private void ThrowIfDisposed()
        {
            if (this.disposed)
            {
                throw new ObjectDisposedException(null);
            }
        }

        public void Dispose()
        {
            this.Dispose(true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool disposing)
        {
            if (!this.disposed)
            {
                if (!this.securityLogHandle.Equals(IntPtr.Zero))
                {
                    Win32Native.AuthzUnregisterSecurityEventSource(0, this.securityLogHandle);
                }
                if (!this.applicationLogHandle.Equals(IntPtr.Zero))
                {
                    Win32Native.DeregisterEventSource(this.applicationLogHandle);
                }
                this.disposed = true;
            }
        }
    }
}
