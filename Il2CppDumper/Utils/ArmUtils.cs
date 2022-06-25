
﻿using System;

namespace Il2CppDumper
{
    static class ArmUtils
    {
        public static uint DecodeMov(byte[] asm)
        {
            var low = (ushort)(asm[2] + ((asm[3] & 0x70) << 4) + ((asm[1] & 0x04) << 9) + ((asm[0] & 0x0f) << 12));