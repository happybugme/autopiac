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
            var size = BinaryPrimitives.ReadInt32BigEndian(ReadBytes(4));
            fats = new Fat[size];
            for (var i = 0; i < size; i++)
            {
                Position += 8;
                fats[i] = new Fat
                {
                    offset = BinaryPrimitives.ReadUInt32BigEndian(ReadBytes(4)),
                    size = BinaryPrimitives.ReadUInt32BigEndian(ReadBytes(4))
                };
                Position 