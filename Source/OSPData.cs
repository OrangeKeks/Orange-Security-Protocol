
namespace Orange.Security.Protocol
{
    public class OSPData : IDisposable
    {
        public object Source { get; private set; }

        public long Length { get; }

        private NativeBytes localBuffer = null!;
        public Memory<byte> AsMemory(long start, int length)
        {
            if (Source is NativeBytes nativeBytes)
            {
                return nativeBytes.AsMemory(start, length);
            }
            else if (Source is Stream stream)
            {
                if (localBuffer == null) localBuffer = new NativeBytes(length);
                else if (localBuffer.Length != length) { localBuffer.Dispose(); localBuffer = new NativeBytes(length); }
                
                stream.Position = start;
                Memory<byte> local = localBuffer!.AsMemory();
                stream.ReadExactly(local.Span);


                return local;
            }
            else if (Source is Memory<byte> memory)
            {
                return memory.Slice((int)start, length);
            }
            else if (Source is IOSPDataVariable variable)
            {
                return variable.AsMemory(start, length);
            }
            throw new NotImplementedException();
        }
        public Memory<byte> AsMemory(long start)
        {
            if (Source is NativeBytes nativeBytes)
            {

                return nativeBytes.AsMemory(start, (int)(nativeBytes.Length - start));
            }
            else if (Source is Stream stream)
            {
                localBuffer = new NativeBytes(stream.Length - start);
                stream.Position = start;
                Memory<byte> local = localBuffer.AsMemory();
                stream.ReadExactly(local.Span);
                return local;
            }
            else if (Source is Memory<byte> memory)
            {
                return memory.Slice((int)start);
            }
            else if (Source is IOSPDataVariable variable)
            {
                return variable.AsMemory(start);
            }
            throw new NotImplementedException();
        }
        public Memory<byte> AsMemory()
        {
            if (Source is NativeBytes nativeBytes)
            {

                return nativeBytes.AsMemory();
            }
            else if (Source is Stream stream)
            {
                localBuffer = new NativeBytes(stream.Length);
                stream.Position = 0;
                Memory<byte> local = localBuffer.AsMemory();
                stream.ReadExactly(local.Span);
                return local;
            }
            else if (Source is Memory<byte> memory)
            {
                return memory;
            }
            else if (Source is IOSPDataVariable variable)
            {
                return variable.AsMemory();
            }
            throw new NotImplementedException();
        }

        public OSPData(Memory<byte> span) { Source = span; Length = span.Length; }
        public OSPData(Stream streamSeek)
        {
            if (!streamSeek.CanSeek) throw new ArgumentException("Длина Stream должна быть известна.");

            Source = streamSeek;
            Length = streamSeek.Length;
        }
        public OSPData(NativeBytes nativeBytes) { Source = nativeBytes; Length = nativeBytes.Length; }


        public OSPData(byte[] bytes) { Source = bytes.AsMemory(); Length = bytes.Length; }


        public OSPData(IOSPDataVariable AnotherData) { Source = AnotherData; Length = AnotherData.Length; }


        bool _disposed = false;
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        public void ClearSource()
        {
            if (Source is NativeBytes nativeBytes)
            {
                nativeBytes.Dispose();
            }
            else if (Source is Stream stream)
            {
                stream.Dispose();
            }
            else if (Source is IOSPDataVariable another)
            {
                if (another.IsClearable) another.ClearOrDispose();
            }

        }
        public void Dispose(bool disposing)
        {
            if (_disposed) return;

            if (disposing)
            {
                if (localBuffer != null) localBuffer.Dispose();
                Source = null!;
            }




            _disposed = true;
        }
        ~OSPData() => Dispose(false);
    }

    public interface IOSPDataVariable
    {
        public Memory<byte> AsMemory();

        public Memory<byte> AsMemory(long Start);

        public Memory<byte> AsMemory(long Start, int Length);

        public void ClearOrDispose();

        public bool IsClearable { get; }

        public long Length { get; }
    }
    
}
