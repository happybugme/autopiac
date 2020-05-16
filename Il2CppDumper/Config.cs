namespace Il2CppDumper
{
    public class Config
    {
        public bool DumpMethod { get; set; } = true;
        public bool DumpField { get; set; } = true;
        public bool DumpProperty { get; set; } = false;
        public bool DumpAttribute { get; set; } = false;
        public bool DumpFieldOffset { get; set; }