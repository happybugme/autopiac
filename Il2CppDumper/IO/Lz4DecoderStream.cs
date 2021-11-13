
﻿#define CHECK_ARGS
#define CHECK_EOF
//#define LOCAL_SHADOW

using System;
using System.IO;

namespace Il2CppDumper
{
    public class Lz4DecoderStream : Stream
    {
        public Lz4DecoderStream(Stream input, long inputLength = long.MaxValue)
        {
            Reset(input, inputLength);
        }

        private void Reset(Stream input, long inputLength = long.MaxValue)
        {
            this.inputLength = inputLength;
            this.input = input;

            phase = DecodePhase.ReadToken;

            decodeBufferPos = 0;

            litLen = 0;
            matLen = 0;
            matDst = 0;

            inBufPos = DecBufLen;
            inBufEnd = DecBufLen;
        }

        protected override void Dispose(bool disposing)
        {
            try
            {
                if (disposing && input != null)
                {
                    input.Close();
                }
                input = null;
                decodeBuffer = null;
            }
            finally
            {
                base.Dispose(disposing);
            }
        }

        private long inputLength;
        private Stream input;

        //because we might not be able to match back across invocations,
        //we have to keep the last window's worth of bytes around for reuse
        //we use a circular buffer for this - every time we write into this
        //buffer, we also write the same into our output buffer

        private const int DecBufLen = 0x10000;
        private const int DecBufMask = 0xFFFF;

        private const int InBufLen = 128;

        private byte[] decodeBuffer = new byte[DecBufLen + InBufLen];
        private int decodeBufferPos, inBufPos, inBufEnd;

        //we keep track of which phase we're in so that we can jump right back
        //into the correct part of decoding

        private DecodePhase phase;

        private enum DecodePhase
        {
            ReadToken,
            ReadExLiteralLength,
            CopyLiteral,
            ReadOffset,
            ReadExMatchLength,
            CopyMatch,
        }

        //state within interruptable phases and across phase boundaries is
        //kept here - again, so that we can punt out and restart freely

        private int litLen, matLen, matDst;

        public override int Read(byte[] buffer, int offset, int count)
        {
#if CHECK_ARGS
            if (buffer == null)
                throw new ArgumentNullException("buffer");
            if (offset < 0 || count < 0 || buffer.Length - count < offset)
                throw new ArgumentOutOfRangeException();

            if (input == null)
                throw new InvalidOperationException();
#endif
            int nRead, nToRead = count;

            var decBuf = decodeBuffer;

            //the stringy gotos are obnoxious, but their purpose is to
            //make it *blindingly* obvious how the state machine transitions
            //back and forth as it reads - remember, we can yield out of
            //this routine in several places, and we must be able to re-enter
            //and pick up where we left off!

#if LOCAL_SHADOW
			var phase = this.phase;
			var inBufPos = this.inBufPos;
			var inBufEnd = this.inBufEnd;
#endif
            switch (phase)
            {
                case DecodePhase.ReadToken:
                    goto readToken;

                case DecodePhase.ReadExLiteralLength:
                    goto readExLiteralLength;

                case DecodePhase.CopyLiteral:
                    goto copyLiteral;

                case DecodePhase.ReadOffset:
                    goto readOffset;

                case DecodePhase.ReadExMatchLength:
                    goto readExMatchLength;

                case DecodePhase.CopyMatch:
                    goto copyMatch;
            }

        readToken:
            int tok;
            if (inBufPos < inBufEnd)
            {
                tok = decBuf[inBufPos++];
            }
            else
            {
#if LOCAL_SHADOW
				this.inBufPos = inBufPos;
#endif

                tok = ReadByteCore();
#if LOCAL_SHADOW
				inBufPos = this.inBufPos;
				inBufEnd = this.inBufEnd;
#endif
#if CHECK_EOF
                if (tok == -1)
                    goto finish;
#endif
            }

            litLen = tok >> 4;
            matLen = (tok & 0xF) + 4;

            switch (litLen)
            {
                case 0:
                    phase = DecodePhase.ReadOffset;
                    goto readOffset;

                case 0xF:
                    phase = DecodePhase.ReadExLiteralLength;