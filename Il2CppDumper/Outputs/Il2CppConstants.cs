﻿namespace Il2CppDumper
{
    class Il2CppConstants
    {
        /*
         * Field Attributes (21.1.5).
         */
        public const int FIELD_ATTRIBUTE_FIELD_ACCESS_MASK = 0x0007;
        public const int FIELD_ATTRIBUTE_COMPILER_CONTROLLED = 0x0000;
        public const int FIELD_ATTRIBUTE_PRIVATE = 0x0001;
        public const int FIELD_ATTRIBUTE_FAM_AND_ASSEM = 0x0002;
        public const int FIELD_ATTRIBUTE_ASSEMBLY = 0x0003;
        public const int FIELD_ATTRIBUTE_FAMILY = 0x0004;
        public const int FIELD_ATTRIBUTE_FAM_OR_ASSEM = 0x0005;
        public const int FIELD_ATTRIBUTE_PUBLIC = 0x0006;

        public const int FIELD_ATTRIBUTE_STATIC = 0x0010;
        public const int FIELD_ATTRIBUTE_INIT_ONLY = 0x0020;
        public const int FIELD_ATTRIBUTE_LITERAL = 0x0040;

        /*
         * Method Attributes (22.1.9)
         */
        public const int METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK = 0x0007;
        public const int METHOD_ATTRIBUTE_COMPILER_CONTROLLED = 0x0000;
        public const int METHOD_ATTRIBUTE_PRIVATE = 