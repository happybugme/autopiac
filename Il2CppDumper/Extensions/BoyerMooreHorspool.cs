
﻿using System;
using System.Collections.Generic;

namespace Il2CppDumper
{
    static class BoyerMooreHorspool
    {
        public static IEnumerable<int> Search(this byte[] source, byte[] pattern)
        {
            if (source == null)
            {
                throw new ArgumentNullException(nameof(source));
            }

            if (pattern == null)
            {
                throw new ArgumentNullException(nameof(pattern));