namespace Ogamat.AuditProvider.Win32
{
    using System;
    using System.Security;
    using System.Security.Principal;
    using System.Text;
    using System.Configuration.Assemblies;
    using System.Runtime.Remoting;
    using System.Runtime.InteropServices;
    using System.Threading;

    using BOOL = System.Int32;
    using DWORD = System.UInt32;
    using ULONG = System.UInt32;

    [Flags]
    internal enum TokenAccessLevels
    {
        AssignPrimary = 0x00000001,
        Duplicate = 0x00000002,
        Impersonate = 0x00000004,
        Query = 0x00000008,
        QuerySource = 0x00000010,
        AdjustPrivileges = 0x00000020,
        AdjustGroups = 0x00000040,
        AdjustDefault = 0x00000080,
        AdjustSessionId = 0x00000100,

        Read = 0x00020000 | Query,

        Write = 0x00020000 | AdjustPrivileges | AdjustGroups | AdjustDefault,

        AllAccess = 0x000F0000 |
            AssignPrimary |
            Duplicate |
            Impersonate |
            Query |
            QuerySource |
            AdjustPrivileges |
            AdjustGroups |
            AdjustDefault |
            AdjustSessionId,

        MaximumAllowed = 0x02000000
    }

    [SuppressUnmanagedCodeSecurityAttribute()]
    internal sealed class Win32Native
    {
        internal const uint SE_PRIVILEGE_DISABLED = 0x00000000;
        internal const uint SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001;
        internal const uint SE_PRIVILEGE_ENABLED = 0x00000002;
        internal const uint SE_PRIVILEGE_USED_FOR_ACCESS = 0x80000000;

        internal enum SecurityImpersonationLevel
        {
            Anonymous = 0,
            Identification = 1,
            Impersonation = 2,
            Delegation = 3,
        }

        internal enum TokenType : int
        {
            Primary = 1,
            Impersonation = 2,
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct LUID
        {
            internal uint LowPart;
            internal uint HighPart;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct LUID_AND_ATTRIBUTES
        {
            internal LUID Luid;
            internal uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct TOKEN_PRIVILEGE
        {
            internal uint PrivilegeCount;
            internal LUID_AND_ATTRIBUTES Privilege;
        }

        // Error codes from WinError.h
        internal const int ERROR_SUCCESS = 0x0;
        internal const int ERROR_INVALID_FUNCTION = 0x1;
        internal const int ERROR_FILE_NOT_FOUND = 0x2;
        internal const int ERROR_PATH_NOT_FOUND = 0x3;
        internal const int ERROR_ACCESS_DENIED = 0x5;
        internal const int ERROR_INVALID_HANDLE = 0x6;
        internal const int ERROR_NOT_ENOUGH_MEMORY = 0x8;
        internal const int ERROR_INVALID_DRIVE = 0xf;
        internal const int ERROR_NO_MORE_FILES = 0x12;
        internal const int ERROR_NOT_READY = 0x15;
        internal const int ERROR_BAD_LENGTH = 0x18;
        internal const int ERROR_SHARING_VIOLATION = 0x20;
        internal const int ERROR_NOT_SUPPORTED = 0x32;
        internal const int ERROR_FILE_EXISTS = 0x50;
        internal const int ERROR_INVALID_PARAMETER = 0x57;
        internal const int ERROR_CALL_NOT_IMPLEMENTED = 0x78;
        internal const int ERROR_INSUFFICIENT_BUFFER = 0x7A;
        internal const int ERROR_INVALID_NAME = 0x7B;
        internal const int ERROR_BAD_PATHNAME = 0xA1;
        internal const int ERROR_ALREADY_EXISTS = 0xB7;
        internal const int ERROR_ENVVAR_NOT_FOUND = 0xCB;
        internal const int ERROR_FILENAME_EXCED_RANGE = 0xCE;  // filename too long.
        internal const int ERROR_MORE_DATA = 0xEA;
        internal const int ERROR_OPERATION_ABORTED = 0x3E3;  // 995
        internal const int ERROR_NO_TOKEN = 0x3f0;
        internal const int ERROR_DLL_INIT_FAILED = 0x45A;
        internal const int ERROR_NON_ACCOUNT_SID = 0x4E9;
        internal const int ERROR_NOT_ALL_ASSIGNED = 0x514;
        internal const int ERROR_UNKNOWN_REVISION = 0x519;
        internal const int ERROR_INVALID_OWNER = 0x51B;
        internal const int ERROR_INVALID_PRIMARY_GROUP = 0x51C;
        internal const int ERROR_NO_SUCH_PRIVILEGE = 0x521;
        internal const int ERROR_PRIVILEGE_NOT_HELD = 0x522;
        internal const int ERROR_NONE_MAPPED = 0x534;
        internal const int ERROR_INVALID_ACL = 0x538;
        internal const int ERROR_INVALID_SID = 0x539;
        internal const int ERROR_INVALID_SECURITY_DESCR = 0x53A;
        internal const int ERROR_BAD_IMPERSONATION_LEVEL = 0x542;
        internal const int ERROR_CANT_OPEN_ANONYMOUS = 0x543;
        internal const int ERROR_NO_SECURITY_ON_OBJECT = 0x546;
        internal const int ERROR_TRUSTED_RELATIONSHIP_FAILURE = 0x6FD;
        internal const int ERROR_OBJECT_ALREADY_EXISTS = 0x1392;

        // Error codes from ntstatus.h
        internal const uint STATUS_SOME_NOT_MAPPED = 0x00000107;
        internal const uint STATUS_NO_MEMORY = 0xC0000017;
        internal const uint STATUS_NONE_MAPPED = 0xC0000073;
        internal const uint STATUS_INSUFFICIENT_RESOURCES = 0xC000009A;
        internal const uint STATUS_ACCESS_DENIED = 0xC0000022;

        // From WinStatus.h
        internal const int STATUS_ACCOUNT_RESTRICTION = unchecked((int)0xC000006E);

        //
        // AUTHZ stuff
        //

        internal const String KERNEL32 = "kernel32.dll";
        internal const String AUTHZ = "authz.dll";
        internal const String ADVAPI32 = "advapi32.dll";
        internal const String SECUR32 = "secur32.dll";

        internal const uint APF_AuditFailure = 0;
        internal const uint APF_AuditSuccess = 1;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal class AUDIT_PARAM
        {
            internal uint Type; // AUDIT_PARAM_TYPE
            internal uint Length; // unused
            internal uint Flags; // unused
            internal IntPtr Data0;
            internal IntPtr Data1;
        };

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal class AUDIT_PARAMS
        {
            internal uint Length;         // size in bytes
            internal uint Flags;          // currently unused
            internal ushort Count;          // number of parameters
            internal IntPtr Parameters;     // Parameter array
        };

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct AUTHZ_REGISTRATION_OBJECT_TYPE_NAME_OFFSET
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            internal string szObjectTypeName;
            internal DWORD dwOffset;
        };

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal class AUTHZ_SOURCE_SCHEMA_REGISTRATION
        {
            internal DWORD dwFlags;
            [MarshalAs(UnmanagedType.LPWStr)]
            internal string eventSourceName;
            [MarshalAs(UnmanagedType.LPWStr)]
            internal string eventMessageFile;
            [MarshalAs(UnmanagedType.LPWStr)]
            internal string eventSourceXmlSchemaFile;
            [MarshalAs(UnmanagedType.LPWStr)]
            internal string eventAccessStringsFile;
            [MarshalAs(UnmanagedType.LPWStr)]
            internal string executableImagePath;
            internal IntPtr pReserved;
            internal DWORD dwObjectTypeNameCount;
            internal AUTHZ_REGISTRATION_OBJECT_TYPE_NAME_OFFSET objectTypeNames;
        }

        [DllImport(AUTHZ, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool AuthzUnregisterSecurityEventSource(
            DWORD dwFlags,
            [In, Out] IntPtr providerHandle);

        [DllImport(AUTHZ, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool AuthzRegisterSecurityEventSource(
            DWORD dwFlags,
            [MarshalAs(UnmanagedType.LPWStr)] string szEventSourceName,
            [In, Out] ref IntPtr ProviderHandle);

        [DllImport(AUTHZ, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool AuthzReportSecurityEventFromParams(
            uint dwFlags,
            IntPtr providerHandle,
            uint auditId,
            byte[] securityIdentifier,
            AUDIT_PARAMS auditParams);

        [DllImport(AUTHZ, CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool AuthzInstallSecurityEventSource(
            uint dwFlags,
            AUTHZ_SOURCE_SCHEMA_REGISTRATION pRegistration);

        [DllImport(AUTHZ, CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool AuthzUninstallSecurityEventSource(
            uint dwFlags,
            [MarshalAs(UnmanagedType.LPWStr)] string eventSourceName);

        //
        // Eventlog stuff
        //

        [DllImport(
            ADVAPI32,
            EntryPoint = "RegisterEventSourceW",
            CharSet = CharSet.Auto,
            SetLastError = true)]
        internal static extern IntPtr RegisterEventSource(
            [MarshalAs(UnmanagedType.LPWStr)] string uncServerName,
            [MarshalAs(UnmanagedType.LPWStr)] string sourceName);

        [DllImport(ADVAPI32, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool DeregisterEventSource(
            IntPtr handle);

        [DllImport(
            ADVAPI32,
            EntryPoint = "ReportEventW",
            CharSet = CharSet.Auto,
            SetLastError = true)]
        internal static extern bool ReportEvent(
            IntPtr handle,
            ushort type,
            ushort category,
            int eventId,
            byte[] userSid,
            ushort numStrings,
            int dataSize,
            IntPtr[] strings,
            byte[] rawData);

        //
        // Other
        //

        [DllImport(
            ADVAPI32,
            EntryPoint = "LookupPrivilegeValueW",
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        internal static extern
        bool LookupPrivilegeValue(
            [In]     string lpSystemName,
            [In]     string lpName,
            [In, Out] ref LUID Luid);

        [DllImport(ADVAPI32, CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern
        bool OpenThreadToken(
            [In]     IntPtr ThreadHandle,
            [In]     TokenAccessLevels DesiredAccess,
            [In]     bool OpenAsSelf,
            [In, Out] ref IntPtr TokenHandle);

        [DllImport(ADVAPI32, CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern
        bool OpenProcessToken(
            [In]     IntPtr ProcessHandle,
            [In]     TokenAccessLevels DesiredAccess,
            [In, Out] ref IntPtr TokenHandle);

        [DllImport(KERNEL32, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern
        IntPtr GetCurrentThread();

        [DllImport(KERNEL32, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern
        IntPtr GetCurrentProcess();

        [DllImport(ADVAPI32, CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern
        bool AdjustTokenPrivileges(
            [In]     IntPtr TokenHandle,
            [In]     bool DisableAllPrivileges,
            [In]     ref TOKEN_PRIVILEGE NewState,
            [In]     uint BufferLength,
            [In, Out] ref TOKEN_PRIVILEGE PreviousState,
            [In, Out] ref uint ReturnLength);

        [DllImport(ADVAPI32, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern
        bool DuplicateTokenEx(
            [In]     IntPtr ExistingTokenHandle,
            [In]     TokenAccessLevels DesiredAccess,
            [In]     IntPtr TokenAttributes,
            [In]     SecurityImpersonationLevel ImpersonationLevel,
            [In]     TokenType TokenType,
            [In, Out] ref IntPtr DuplicateTokenHandle);

        [DllImport(ADVAPI32, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern
        bool SetThreadToken(
            [In]     IntPtr Thread,
            [In]     IntPtr Token);

        [DllImport(ADVAPI32, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern
        bool RevertToSelf();
    }
}
