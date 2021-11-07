using System;
using System.Text;

namespace Il2CppDumper
{
    static class HexExtensions
    {
        public static string HexToBin(this byte b)
        {
            return Convert.ToString(b, 2).PadLeft(8, '0');
        }

        public static string HexToBin(this byte[