namespace Ogamat.AuditProvider
{
    enum AUDIT_PARAM_TYPE
    {
        //
        // NULL terminated string 
        //

        APT_String = 2,

        //
        // unsigned long
        //

        APT_Ulong = 3,
        /*
                //
                // SID
                //

                APT_Sid = 5,
        */
        //
        // Guid
        //

        APT_Guid = 9,

        //
        // Time (FILETIME)
        //

        APT_Time = 10,

        //
        // ULONGLONG
        // 

        APT_Int64 = 11,
    };
}
