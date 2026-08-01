using System.Buffers;
using System.Collections;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Orange.Security.Protocol
{


    public class OSPSegment
    {
        /// <summary>
        /// Создаёт отрезок.
        /// </summary>
        /// <param name="min">Минимальное число</param>
        /// <param name="max">Максимальное число (включительно)</param>
        public OSPSegment(int min, int max)
        {
            Min = min;
            Max = max;
        }

        /// <summary>
        /// Начальная точка.
        /// </summary>
        public readonly int Min;
        /// <summary>
        /// Конечная точка.
        /// </summary>
        public readonly int Max;
    }

    /// <summary>
    /// Класс для исключений OSP.
    /// </summary>
    public class OSPException : Exception
    {
        public OSPException() { }

        public OSPException(string message) : base(message) { }

        public OSPException(string message, Exception innerException)
            : base(message, innerException) { }

        
    }

    public delegate Task<OSPServerAnswer> OSPMessageHandler(OSPMessageEventArgs Arguments);
    public delegate Task OSPFrameHandler(ReadOnlyMemory<byte> Data, OSPHeaderRequest Request, double Progress);


    internal sealed unsafe class OSPMemoryManager : MemoryManager<byte>
    {
        private byte* _ptr;
        private int _length;

        public OSPMemoryManager(byte* ptr, int length)
        {
            _ptr = ptr;
            _length = length;
        }

        public void Update(byte* ptr, int length)
        {
            _ptr = ptr;
            _length = length;
        }

        public override Span<byte> GetSpan() => new Span<byte>(_ptr, _length);

        public override MemoryHandle Pin(int elementIndex = 0) => new MemoryHandle(_ptr + elementIndex);

        public override void Unpin() { }

        protected override void Dispose(bool disposing) { }
    }

    
    /// <summary>
    /// Класс для использования нативной памяти.
    /// </summary>
    public unsafe class NativeBytes : IDisposable, IEnumerable<byte>
    {
        private byte* _ptr;
        private readonly long _length;
        private bool _disposed;


        private long _position = 0;
        public long Position => _position;

        public long Length => _length;


        private readonly OSPMemoryManager _sliceManager = new OSPMemoryManager(null, 0);

        private readonly bool _warnGC = false;

        public NativeBytes(long Length, bool WarnGC = false)
        {
            if (Length < 0) throw new ArgumentOutOfRangeException(nameof(Length));

            _length = Length;
            _ptr = (byte*)NativeMemory.Alloc((nuint)Length);
            


            if (Length <= int.MaxValue)
            {
                _sliceManager.Update(_ptr, (int)Length);
            }

            _warnGC = WarnGC;

            if (_warnGC) GC.AddMemoryPressure(_length);

            
        }
        

        public void Write(ReadOnlySpan<byte> buffer)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(NativeBytes));


            if (_position + buffer.Length > _length)
                throw new InvalidOperationException("Буфер переполнен. Недостаточно места для записи.");


            Span<byte> destination = new Span<byte>(_ptr + _position, buffer.Length);


            buffer.CopyTo(destination);


            _position += buffer.Length;
        }
        public ReadOnlySpan<byte> AsSpan(long start, int length)
        {

            if (start + length > _length) throw new IndexOutOfRangeException();

            return new ReadOnlySpan<byte>(_ptr + start, length);



        }
        public ReadOnlySpan<byte> AsSpan()
        {
            if (_length > int.MaxValue) throw new InvalidOperationException("Размер массива больше максимального размера Span.");
            if (_disposed) throw new ObjectDisposedException(nameof(NativeBytes));
            return new ReadOnlySpan<byte>(_ptr, (int)_length);
        }

        public Span<byte> AsWritableSpan()
        {
            if (_disposed) throw new ObjectDisposedException(nameof(NativeBytes));
            if (_length > int.MaxValue) throw new InvalidOperationException("Размер слишком велик для Span.");

            return new Span<byte>(_ptr, (int)_length);
        }
        public Span<byte> AsWritableSpan(long start, int length)
        {

            if (start + length > _length) throw new IndexOutOfRangeException();

            return new Span<byte>(_ptr + start, length);



        }

        public Memory<byte> AsMemory()
        {
            if (_disposed) throw new ObjectDisposedException(nameof(NativeBytes));
            if (_length <= int.MaxValue)
            {
                return _sliceManager.Memory;
                
            }
            else throw new InvalidOperationException();



        }
        public Memory<byte> AsMemory(long start, int length)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(NativeBytes));
            if (start < 0 || start + length > _length) throw new ArgumentOutOfRangeException();

            _sliceManager.Update(_ptr + start, length);
            return _sliceManager.Memory;
        }


        public byte this[long index]
        {
            
            get
            {
                if ((ulong)index >= (ulong)_length) throw new IndexOutOfRangeException();
                return _ptr[index];
            }
            
            set
            {
                if ((ulong)index >= (ulong)_length) throw new IndexOutOfRangeException();
                _ptr[index] = value;
            }
        }





        public void Clear()
        {
            if (_disposed) throw new ObjectDisposedException(nameof(NativeBytes));
            if (_ptr != null)
            {
                NativeMemory.Clear(_ptr, (nuint)_length);
            }

        }

        public void Dispose()
        {
            if (!_disposed)
            {
                Clear();
                if (_ptr != null)
                {
                    NativeMemory.Free(_ptr);
                    _ptr = null;
                }
                _disposed = true;
                GC.SuppressFinalize(this);
                if (_warnGC) GC.RemoveMemoryPressure(_length);
            }
        }

        ~NativeBytes() => Dispose();


        public IEnumerator<byte> GetEnumerator()
        {
            for (long i = 0; i < _length; i++) yield return this[i];
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }


    /// <summary>
    /// Статус-коды для сообщений, которые использует сервер при отправке ответа. Содержит лишь самые базовые статус-коды. 
    /// </summary>
    public enum OSPStatusCode : byte
    {
        /// <summary>
        /// Отсутствующий статус-код.
        /// </summary>
        None,
        /// <summary>
        /// OK.
        /// </summary>
        OK,
        /// <summary>
        /// Успех
        /// </summary>
        Success,
        /// <summary>
        /// Ошибка
        /// </summary>
        Error,
        /// <summary>
        /// Доступ запрещён
        /// </summary>
        Forbidden,
        /// <summary>
        /// Не найдено
        /// </summary>
        NotFound,
        /// <summary>
        /// Не осуществлено
        /// </summary>
        NotImplemented,
        /// <summary>
        /// Плохой/неудачный запрос
        /// </summary>
        BadRequest

    }


    /// <summary>
    /// Статический класс, в котором находятся вспомогательные функции для работы с библиотекой.
    /// </summary>
    public static class OSPTools
    {
        /// <summary>
        /// Генерирует пару ECDSA-ключей nistP256. Эти ключи можно использовать для подписи.
        /// </summary>
        /// <returns>BASE64-X509 публичный ключ и BASE64-PKCS8 приватный ключ</returns>
        public static (string PublicX509Key, string PrivatePKCS8Key) GenerateECDSAMasterKeys()
        {
            using var ecdha = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            
            return (
                Convert.ToBase64String(ecdha.ExportSubjectPublicKeyInfo()),
                Convert.ToBase64String(ecdha.ExportPkcs8PrivateKey())
            );
        }

    }
    internal enum OSPMessageType : byte
    {
        AnswerFromServer,
        RequestFromServer,
        RequestFromClient,
        FrameFromClient,
        FrameFromServer
    }


    /// <summary>
    /// Родительский класс, хранящий базовые настройки для сервера и клиента.
    /// </summary>
    public class OSPSettings
    {
        /// <summary>
        /// Диапазон значений для размера одного сегмента во время рукопожатия.
        /// </summary>
        public OSPSegment HandshakeSegmentSize { get; set; } = new OSPSegment(50, 200);

        /// <summary>
        /// Диапазон значений интервала для задержки между отправками сегментов во время рукопожатия.
        /// </summary>
        public OSPSegment HandshakeSegmentInterval { get; set; } = new OSPSegment(5, 50);

        /// <summary>
        /// Низкоуровневый параметр TCP-соединения.
        /// </summary>
        public int SendBufferSize { get; set; } = 1048576;


        /// <summary>
        /// Низкоуровневый параметр TCP-соединения.
        /// </summary>
        public int ReceiveBufferSize { get; set; } = 1048576;

        /// <summary>
        /// Максимально возможная длина заголовка.
        /// </summary>
        public int MaxReceiveHeaderLength { get; set; } = 2048;

        /// <summary>
        /// Таймер на приём данных, по истечению которого соединение разорвётся.
        /// </summary>
        public int InactiveReceiveTimeoutSeconds { get; set; } = 30;

        /// <summary>
        /// Таймер на отправку данных, по истечению которого соединение разорвётся.
        /// </summary>
        public int InactiveSendingTimeoutSeconds { get; set; } = 5;

        /// <summary>
        /// Скорость сети на приём в мегабитах в секунду. Нулевое значение - неограниченно.
        /// </summary>
        public double DefaultIngressBitrateMbps { get; set; } = 0;

        /// <summary>
        /// Скорость сети на отдачу в мегабитах в секунду. Нулевое значение - неограниченно.
        /// </summary>
        public double DefaultEgressBitrateMbps { get; set; } = 0;

        /// <summary>
        /// Таймер, после которого получение отменённого пакета будет недопустимым. Значение в миллисекундах.
        /// </summary>
        public ushort CancellationPacketTimeout { get; set; } = 10000; // 10 seconds
    }

    /// <summary>
    /// Класс, хранящий настройки для клиента.
    /// </summary>
    public class OSPClientSettings : OSPSettings
    {
        /// <summary>
        /// Интервал между пинг-пакетами в миллисекундах. Если сервер не принимает пинг-пакеты с такой скоростью, то интервал скорректируется автоматически. Нулевое значение - пинг-пакеты отключены.
        /// </summary>
        public ushort PingInvervalMilliseconds { get; set; } = 0;
        
    }


    /// <summary>
    /// Класс, хранящий настройки для сервера.
    /// </summary>
    public class OSPServerSettings : OSPSettings
    {

        /// <summary>
        /// Максимальная длина полезной нагрузки, которая не подвергнется фрагментации.
        /// </summary>
        public int FramingThreshold { get; set; } = 196608;

        /// <summary>
        /// Размер одного кадра данных при их фрагментации.
        /// </summary>
        public int FrameSize { get; set; } = 196608;

        /// <summary>
        /// Максимальное количество клиентов, подключенных к серверу. При перевесе не пропускает новых клиентов, закрывая соединение с ними. Нулевое значение - неограниченно.
        /// </summary>
        public int MaxClients { get; set; } = 0;

        /// <summary>
        /// Максимально возможная длина полезной нагрузки. При выходе за порог соединение закрывается.
        /// </summary>
        public long MaxReceiveDataLength { get; set; } = 1024 * 1024 * 500;

        /// <summary>
        /// Cообщения выше порога FramingThreshold будут попадать в FrameHandler. Очень сильно экономит память.
        /// </summary>
        public bool DataStreaming { get; set; } = false;

        /// <summary>
        /// Максимальное количество пинг-пакетов от клиента в секунду. При выходе за порог соединение закрывается.
        /// </summary>
        public byte MaxPingPacketsPerSecond { get; set; } = 5;

        /// <summary>
        /// Разрешает/запрещает клиентам без публичного ключа для подписи подключаться. Такие клиенты уязвимы к MitM атакам.
        /// </summary>
        public bool AllowInsecureClients { get; set; } = false;

    }



    /// <summary>
    /// Класс, содержащий ответ от сервера.
    /// </summary>
    public class OSPServerAnswer
    {
        /// <summary>
        /// Данные. (Полезная нагрузка)
        /// </summary>
        public OSPData? Data { get; set; } = null;

        /// <summary>
        /// Статус-код.
        /// </summary>
        public OSPStatusCode Code { get; set; } = OSPStatusCode.Error;

        /// <summary>
        /// Данные внутри заголовка.
        /// </summary>
        public byte[]? HeaderDescription { get; set; } = default;

        
    }


    /// <summary>
    /// 
    /// </summary>
    public class OSPBaseHeader
    {
        public uint NumericID { get; set; }

        internal OSPBaseHeader()
        {

        }
    }

    internal class OSPSystemHeader : OSPBaseHeader
    {
        public byte Command { get; set; }
        public ReadOnlyMemory<byte>? Data { get; set; } = null;

        internal OSPSystemHeader() { }
    }

    /// <summary>
    /// 
    /// </summary>
    public class OSPHeader : OSPBaseHeader
    {
        internal OSPMessageType MessageType { get; set; }
        internal bool IsFramed { get; set; } = false;
        public uint UniID { get; set; }
        internal OSPHeader()
        {

        }
    }
    /// <summary>
    /// 
    /// </summary>
    public class OSPHeaderRequest : OSPHeader
    {
        public OSPStatusCode MessageStatus { get; set; }
        public byte[] Description { get; set; } = null!;
        public IPEndPoint IPEndPoint { get; set; } = null!;
        public long DataLength { get; set; }
        internal OSPHeaderRequest()
        {
            
        } 

    }
    internal class OSPHeaderFrame : OSPHeader
    {
        internal int CurrentFrame { get; set; }

        internal int MaxFrame { get; set; }

        internal OSPHeaderFrame()
        {

        }
    }

    /// <summary>
    /// 
    /// </summary>
    public class OSPMessageEventArgs
    {
        public required OSPHeaderRequest Header { get; set; }

        public NativeBytes? Data { get; set; }

        internal OSPMessageEventArgs() { }

    }
    /// <summary>
    /// Представляет класс, в котором лежит ответ от сервера. Иногда сервер может вернуть статус-код без данных.   
    /// </summary>
    public class OSPResponse
    {

        /// <summary>
        /// true, если сервер не прислал никаких данных, кроме статус-кода. Иначе false.
        /// </summary>
        public bool OnlyStatusCode { get; set; }

        /// <summary>
        /// Статус-код.
        /// </summary>
        public OSPStatusCode StatusCode { get; set; }

        /// <summary>
        /// Заголовок запроса.
        /// </summary>
        public required OSPHeaderRequest Header { get; set; }

        /// <summary>
        /// Полезная нагрузка.
        /// </summary>
        public NativeBytes? Data { get; set; }

        internal OSPResponse() { }
    }

    internal enum OSPPriority
    {
        Low,
        Medium,
        High
    }

    internal static class OSPConsts
    {
        public const byte PingCommand = 0x00;
        public const byte PingAnswerCommand = 0x01;
        public const byte CancelPacketCommand = 0x02;
        public const byte HandshakeSettings = 0x03;


        public static byte[] Info = Encoding.UTF8.GetBytes("Handshake-ECDH-MLKem-OSP-V1");

        public static byte[] NullableData = new byte[] { 0x6E };
    }


}


