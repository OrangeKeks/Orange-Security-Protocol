using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;

namespace Orange.Security.Protocol
{
    static internal class GlobalTools
    {
        public static System.Timers.Timer StartTimer(ushort interval, Action action)
        {
            System.Timers.Timer timer = new(interval);

            timer.Elapsed += async (sender, e) => { action.Invoke(); timer.Dispose(); };

            timer.AutoReset = false;

            timer.Start();

            return timer;
        }
        public static OSPHeaderRequest MakeRequestFromResponse(Memory<byte> dataM, IPEndPoint ip)
        {

            Span<byte> data = dataM.Span;
            int pos = 0;
            uint numeric = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(pos)); pos += 4;
            OSPMessageType type = (OSPMessageType)data[pos++];
            long dataLength = BinaryPrimitives.ReadInt64LittleEndian(data.Slice(pos)); pos += 8;
            uint uniID = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(pos)); pos += 4;
            OSPStatusCode code = (OSPStatusCode)data[pos++];
            bool isFramed = data[pos++] != 0;



            OSPHeaderRequest requestHeader = new OSPHeaderRequest()
            {
                NumericID = numeric,
                MessageType = type,
                DataLength = dataLength,
                UniID = uniID,
                MessageStatus = code,
                IPEndPoint = ip,
                IsFramed = isFramed,
                Description = dataM.Span.Slice(pos).ToArray()

            };
            


            return requestHeader;

        }

        public static OSPHeaderFrame MakeFrameFromResponse(ReadOnlySpan<byte> data)
        {
            int pos = 0;
            uint numeric = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(pos)); pos += 4;
            OSPMessageType type = (OSPMessageType)data[pos++];
            uint uniID = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(pos)); pos += 4;
            int maxFrame = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(pos)); pos += 4;
            int currentFrame = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(pos)); pos += 4;




            return new OSPHeaderFrame()
            {
                NumericID = numeric,
                MessageType = type,

                UniID = uniID,
                MaxFrame = maxFrame,
                CurrentFrame = currentFrame,

                IsFramed = true,


            };

        }
        public static OSPSystemHeader MakeSystemHeader(ReadOnlyMemory<byte> dataM)
        {

            int pos = 0;
            ReadOnlySpan<byte> data = dataM.Span;


            uint numeric = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(pos)); pos += 4;
            byte command = data[pos]; pos += 1;





            OSPSystemHeader header = new OSPSystemHeader();
            header.NumericID = numeric;
            header.Command = command;
            if (pos >= dataM.Length) header.Data = null;
            else header.Data = dataM.Slice(pos).ToArray();
            return header;

        }



        public static NativeBytes MakeHeaderRequestWithData(ReadOnlyMemory<byte>? description, OSPStatusCode code, uint NumericID, OSPMessageType type, Tools _tools, Memory<byte>? data, bool isFramed, uint uniID, long body_length = 0)
        {
            long bodyLength = 0;
            if (data.HasValue) bodyLength = data.Value.Length;
            else if (body_length != 0) bodyLength = body_length;


            int headerSize = 4 + 1 + 8 + 4 + 1 + 1;
            if (description != null) headerSize += description.Value.Length;
            int currentSize = 16 + 5 + (16 + headerSize);
            if (data.HasValue && data?.Length > 0)
            {

                currentSize += data.Value.Length + 16;

            }

            NativeBytes bs = new NativeBytes(currentSize);

            Span<byte> span = bs.AsWritableSpan();

            Span<byte> systemInfo = span.Slice(16, 5);
            BinaryPrimitives.WriteUInt32LittleEndian(systemInfo.Slice(0, 4), (uint)headerSize);
            systemInfo[4] = 0x01;
            Span<byte> systemTag = stackalloc byte[16];

            _tools.Encrypt(systemInfo, systemTag);

            systemTag.CopyTo(span.Slice(0));
            int pos = 16 + 5 + 16;

            BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(pos), NumericID); pos += 4;
            span[pos++] = (byte)type;
            BinaryPrimitives.WriteInt64LittleEndian(span.Slice(pos), bodyLength); pos += 8;
            BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(pos), uniID); pos += 4;

            span[pos++] = (byte)code;
            span[pos++] = (byte)(isFramed ? 1 : 0);
            if (description != null) { description.Value.Span.CopyTo(span.Slice(pos)); pos += description.Value.Length; }
            
            Span<byte> tag = stackalloc byte[16];
            _tools.Encrypt(span.Slice(16 + 5 + 16, headerSize), tag);
            tag.CopyTo(span.Slice(16 + 5));

            if (data.HasValue && data?.Length > 0)
            {
                int dataPos = headerSize + 16 + 5 + 16;

                Span<byte> dataTag = stackalloc byte[16];

                _tools.Encrypt(data.Value.Span, dataTag);

                data.Value.Span.CopyTo(span.Slice(dataPos + 16));
                dataTag.CopyTo(span.Slice(dataPos));

            }


            return bs;

        }
        public static void MakeHeaderFrame(uint NumericID, OSPMessageType _type, Tools _tools, int maxFrame, int currentFrame, uint uniID, NativeBytes buffer)
        {




            int headerSize = 4 + 1 + 4 + 4 + 4;
            int currentSize = 16 + 5 + (16 + headerSize);


            

            Span<byte> span = buffer.AsWritableSpan(0, currentSize);


            Span<byte> systemInfo = span.Slice(16, 5);
            BinaryPrimitives.WriteUInt32LittleEndian(systemInfo.Slice(0, 4), (uint)headerSize);
            systemInfo[4] = 0x00;
            Span<byte> systemTag = stackalloc byte[16];

            _tools.Encrypt(systemInfo, systemTag);

            systemTag.CopyTo(span.Slice(0));




            int pos = 16 + 5 + 16;

            BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(pos), NumericID); pos += 4;
            span[pos++] = (byte)_type;
            BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(pos), uniID); pos += 4;
            BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(pos), (uint)maxFrame); pos += 4;
            BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(pos), (uint)currentFrame); pos += 4;


            Span<byte> tag = stackalloc byte[16];
            _tools.Encrypt(span.Slice(16 + 5 + 16), tag);

            tag.CopyTo(span.Slice(16 + 5));

          

        }

        public static NativeBytes MakeSystemHeaderWith(uint NumericID, byte command, NativeBytes? data, Tools _tools)
        {
            int headerSize = 4 + 1;
            if (data != null) headerSize += (int)data.Length;
            int currentSize = 16 + 5 + (16 + headerSize);


            NativeBytes bs = new NativeBytes(currentSize);

            Span<byte> span = bs.AsWritableSpan();


            Span<byte> systemInfo = span.Slice(16, 5);
            BinaryPrimitives.WriteUInt32LittleEndian(systemInfo.Slice(0, 4), (uint)headerSize);
            systemInfo[4] = 0x02;
            Span<byte> systemTag = stackalloc byte[16];

            _tools.Encrypt(systemInfo, systemTag);

            systemTag.CopyTo(span.Slice(0));




            int pos = 16 + 5 + 16;

            BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(pos), NumericID); pos += 4;
            span[pos++] = (byte)command;
            if (data != null)
            {

                data.AsSpan().CopyTo(span.Slice(pos));
                pos += (int)data.Length;
            }




            Span<byte> tag = stackalloc byte[16];
            _tools.Encrypt(span.Slice(16 + 5 + 16), tag);

            tag.CopyTo(span.Slice(16 + 5));

            return bs;





        }

    }

    internal class Tools : IDisposable
    {

       
        public byte[] Key = null!;
        public ECDiffieHellman _ecndhe = null!;

        private ulong _sendNonce;
        private ulong _recvNonce;

        private readonly object _sendLock = new object();
        private readonly object _recvLock = new object();

        private AesGcm aesGcmEncrypt = null!;
        private AesGcm aesGcmDecrypt = null!;
        public Tools(bool isClient)
        {

           

            if (isClient)
            {
                _sendNonce = 1;
                _recvNonce = 0;
            }
            else
            {
                _sendNonce = 0;
                _recvNonce = 1;
            }
        }


        public void Encrypt(Span<byte> data, Span<byte> tag)
        {
            if (aesGcmEncrypt == null) aesGcmEncrypt = new AesGcm(Key, 16);
            Span<byte> nonce = stackalloc byte[12];
            nonce.Clear();

            lock (_sendLock)
            {

                BinaryPrimitives.WriteUInt64BigEndian(nonce.Slice(4), (ulong)_sendNonce);

                _sendNonce += 2;

                aesGcmEncrypt.Encrypt(nonce, data, data, tag);


            }
         
        }

        public void Decrypt(Span<byte> ciphertext, Span<byte> tag)
        {
            if (aesGcmDecrypt == null) aesGcmDecrypt = new AesGcm(Key, 16);

            Span<byte> nonce = stackalloc byte[12];
            nonce.Clear();

            lock (_recvLock)
            {

                BinaryPrimitives.WriteUInt64BigEndian(nonce.Slice(4), (ulong)_recvNonce);

                _recvNonce += 2;

                aesGcmDecrypt.Decrypt(nonce, ciphertext, tag, ciphertext);
            }



          
        }

        public void Dispose()
        {


            if (aesGcmDecrypt != null)
            {
                aesGcmDecrypt.Dispose();
            }
            if (aesGcmEncrypt != null)
            {
                aesGcmEncrypt.Dispose();
            }
            _ecndhe.Dispose();
            if (Key != null) Array.Clear(Key, 0, Key.Length);
            _sendNonce = default;
            _recvNonce = default;
            GC.SuppressFinalize(this);
        }

    }
}


