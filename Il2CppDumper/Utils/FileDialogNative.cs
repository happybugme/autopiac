using System;
using System.Runtime.InteropServices;

namespace Il2CppDumper
{
    static class FileDialogNative
    {
        [ComImport]
        [ClassInterface(ClassInterfaceType.None)]
        [TypeLibType(TypeLibTypeFlags.FCanCreate)]
        [Guid(CLSIDGuid.FileOpenDialog)]
        internal class FileOpenDialogRCW
        { }

        internal class IIDGuid
        {
            private IIDGuid() { } // Avoid FxCop violation AvoidUninstantiatedInternalClasses
            // IID GUID strings for relevant COM interfaces
            internal const st