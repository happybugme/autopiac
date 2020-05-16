using System;

namespace Il2CppDumper
{
    [AttributeUsage(AttributeTargets.Field, AllowMultiple = true)]
    class VersionAttribute : Attribute
    {
        public double Min { get; s