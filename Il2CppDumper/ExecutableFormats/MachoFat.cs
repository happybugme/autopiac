using System.Buffers.Binary;
using System.IO;

namespace Il2CppDumper
{
    public sealed class MachoFat : BinaryStream
    {
        public Fat[] fats;

        public MachoFat(Stream stream) : base(stream)
        {
            Position += 4;
            var size = BinaryPrimitives.ReadInt32BigEndian(ReadBytes