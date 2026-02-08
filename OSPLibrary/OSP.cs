
using System.Text;

using System.Security.Cryptography;

using System.Collections.Concurrent;

namespace System.Net.Sockets.OSP
{
#pragma warning disable CS1591 // Отсутствует комментарий XML для открытого видимого типа или члена
#pragma warning disable CS8625 // Литерал, равный NULL, не может быть преобразован в ссылочный тип, не допускающий значение NULL.
#pragma warning disable CS8602 // Разыменование вероятной пустой ссылки.
    public enum OSPStatusCode
    {
        None,
        OK,
        Error,
        Forbidden,
        NotFound
    }

    public class OSPSettings
    {
        public int RSA_Size { get; private set; }


        public int AES_Size { get; private set; }


        public void SetRSAKeySise(int size)
        {
            if (size % 64 == 0)
            {
                if (size % 8 == 0)
                {
                    RSA_Size = size;
                    AES_Size = size / 8;
                }
            }
        }
        public void SetAESKeySize(int size)
        {
            if (size % 8 == 0)
            {
                int del = RSA_Size / size;
                if (del >= 8)
                {
                    AES_Size = del;
                }
            }
        }


        // public bool StatusCodeSupport = true;
    }
#pragma warning disable CS8600 // Преобразование литерала, допускающего значение NULL или возможного значения NULL в тип, не допускающий значение NULL.
#pragma warning disable CS8604 // Возможно, аргумент-ссылка, допускающий значение NULL.

    /// <summary>
    /// Это клиент. Подключается к серверу и обменивается с ним данными по вашему запросу. Обеспечивает автоматическое шифрование.
    /// </summary>
    public class OSPClient : IDisposable
    {
        /// <summary>
        /// Подключен ли клиент к серверу на текущий момент?
        /// </summary>
        public bool IsConnected { get; private set; } = false;
        OSPSettings Settings = new OSPSettings();
        Tools Tools = new Tools();

        NetworkStream? stream;

        TcpClient tcp_client;

        RSA rsa_provider;
      

        string _ip = string.Empty;
        int _port = 0;

        /// <summary>
        /// Запускаем клиент, присоединяясь к серверу.
        /// </summary>
        /// <returns></returns>
        public Task Start()
        {
            
            Tools.aes.GenerateIV();
            Tools.aes.GenerateKey();



            tcp_client.Connect(IPAddress.Parse(_ip), _port);
            stream = tcp_client.GetStream();

            List<byte> data = new List<byte>();
            int byteRead;
            while ((byteRead = stream.ReadByte()) != -1)
            {
                data.Add((byte)byteRead);
                if (data.Count >= 4)
                {
                    if (data[data.Count - 1] == 0x1F && data[data.Count - 2] == 0x1E && data[data.Count - 3] == 0x1F && data[data.Count - 4] == 0x1E)
                    {
                        data.RemoveAt(data.Count - 1);
                        data.RemoveAt(data.Count - 1);
                        data.RemoveAt(data.Count - 1);
                        data.RemoveAt(data.Count - 1);
                        break;
                    }
                }

            }
            byte[] terminator = { 0x1A, 0x2B, 0x3C, 0x4D };
            rsa_provider.ImportRSAPublicKey(data.ToArray(), out int count);
            byte[] ecnryptedKey = rsa_provider.Encrypt(Tools.aes.Key, RSAEncryptionPadding.Pkcs1);
            List<byte> sendData = new List<byte>();
            sendData.AddRange(ecnryptedKey);
            sendData.AddRange(terminator);
            sendData.AddRange(Tools.aes.IV);
            sendData.Add(0x1E);
            sendData.Add(0x1F);
            sendData.Add(0x1E);
            sendData.Add(0x1F);
            stream.Write(sendData.ToArray());
            stream.Flush();
            Task.Run(() => ReadData());
            return Task.CompletedTask;
        }

        SemaphoreSlim _writeLock = new SemaphoreSlim(1, 1);

        async Task ReadData()
        {

            IsConnected = true;
            List<byte> data = new List<byte>();

            //   header;


            while (true)
            {
                try
                {
                    byte[] headerBuffer = new byte[4];


                    await stream.ReadExactlyAsync(headerBuffer, 0, headerBuffer.Length);


                    int headerLength = BitConverter.ToInt32(headerBuffer, 0);


                    byte[] HedBuffer = new byte[headerLength];
                    await stream.ReadExactlyAsync(HedBuffer, 0, HedBuffer.Length);
                    byte[] decoded = Tools.Decrypt(HedBuffer);
                    HeaderMessage header = MakeHeaderFromResponse(decoded, IPEndPoint.Parse($"{_ip}:{_port}"));


                    TaskCompletionSource<OSPResponse>? response = null;

                    if (!_allRequests.TryRemove(header.UniID, out response))
                    {

                        NewMessageSent(header);
                    }



                    if (header.DataLength == 0)
                    {

                        if (response != null) _ = Task.Run(() => response.SetResult(new OSPResponse() { Data = null, Header = header, StatusCode = header.MessageStatus, OnlyStatusCode = true }));
                        data.Clear();
                    }
                    else
                    {
                        float beforeProgress = -666;
                        long bufferCount = 0;
                        if (header.DataLength < 262144) bufferCount = header.DataLength;
                        else bufferCount = 262144;
                        byte[] dataBuffer = new byte[bufferCount];

                        while (data.Count < header.DataLength)
                        {

                            int readTo = dataBuffer.Length;
                            if (header.DataLength - data.Count < 262144) readTo = (int)(header.DataLength - data.Count);
                            int bytesCount = await stream.ReadAsync(dataBuffer, 0, readTo);

                            if (bytesCount == 0) break;
                            for (int i = 0; i < bytesCount; i++)
                            {
                                data.Add(dataBuffer[i]);
                            }
                            float progress = 0.00f;
                            progress = (float)data.Count / (float)header.DataLength;
                            progress = (float)Math.Round(progress, 2, MidpointRounding.ToZero);
                            if (beforeProgress == -666) beforeProgress = progress;
                            else if (beforeProgress < progress)
                            {
                                if (response == null)
                                {
                                    MessageProgressRead(progress, header.UniID);
                                    beforeProgress = progress;
                                }
                                else { ResponseProgressRead(progress); beforeProgress = progress; }
                            }
                            if (progress == 1)
                            {
                                if (response == null)
                                {

                                    MessageEventArgs args = new MessageEventArgs()
                                    {
                                        Data = Tools.Decrypt(data.ToArray()),
                                        Header = header,

                                    };
                                    MessageFullyReaded(args);
                                    data.Clear();

                                }
                                else
                                {
                                    byte[] buffer = Tools.Decrypt(data.ToArray());
                                    _ = Task.Run(() => response.SetResult(new OSPResponse() { Data = buffer, Header = header, StatusCode = header.MessageStatus, OnlyStatusCode = false }));
                                    data.Clear();

                                }
                                break;
                            }
                        }
                    }
                }
                catch
                {

                    IsConnected = false;
                    return;
                }


            }
        }
        public OSPClient(string ip, int port)
        {
            tcp_client = new TcpClient();
            tcp_client.NoDelay = true;
            tcp_client.ReceiveBufferSize = 262144;
            tcp_client.SendBufferSize = 262144;
            Settings.SetRSAKeySise(2048);
            rsa_provider = RSA.Create();
            rsa_provider.KeySize = Settings.RSA_Size;
            Tools.aes.KeySize = Settings.AES_Size;

            _ip = ip;
            _port = port;
        }

        ConcurrentDictionary<uint, TaskCompletionSource<OSPResponse>> _allRequests = new ConcurrentDictionary<uint, TaskCompletionSource<OSPResponse>>();

        /// <summary>
        /// Используйте эту функцию для отправки данных удалённому серверу.
        /// </summary>
        /// <param name="data">Те данные, что Вы хотите отправить</param>
        /// <param name="description">Эта переменная универсальна, используете её на своё усмотрение. Она находится в заголовке запроса. Нельзя использовать пробелы.</param>

        /// <returns>Дешифрованный ответ от сервера.</returns>
        public async Task<OSPResponse> Send(byte[] data, string? description = null)
        {

            if (data == null || data.Length == 0) throw new Exception("Данные отсутствуют или их количество равно нулю!");
            byte[] endData = Tools.Encrypt(data);


            var tcs = new TaskCompletionSource<OSPResponse>();
            uint uniID = Random();
            _allRequests[uniID] = tcs;

            await _writeLock.WaitAsync();
            await stream.WriteAsync(MakeRequest(description, OSPStatusCode.None, endData, uniID));
            await stream.FlushAsync();
            _writeLock.Release();

            return await tcs.Task;



        }




        uint Random()
        {
            System.Random rnd = new System.Random();
            int key = rnd.Next(100, 1000);
            if (_allRequests.ContainsKey((uint)key))
            {
                return Random();
            }
            else return (uint)key;
        }




        HeaderMessage MakeHeaderFromResponse(byte[] data, IPEndPoint ip)
        {
            string header = Encoding.UTF8.GetString(data);
            string[] args = header.Split(' ');
            HeaderMessage msg = new HeaderMessage()
            {
                UniID = Convert.ToUInt32(args[0]),
                DataLength = Convert.ToInt32(args[1]),
                Description = args[2],
                MessageStatus = (OSPStatusCode)Convert.ToInt32(args[3]),
                IPEndPoint = ip,
            };

            return msg;
        }

        byte[] MakeRequest(string description, OSPStatusCode code, byte[] body, uint ID)
        {

            int bodyLength = body.Length;
            if (String.IsNullOrEmpty(description)) description = "n";
            else
            {
                if (description.Contains(' '))
                {
                    throw new ArgumentException("description содержит пробел!");
                }
            }
            string header = $"{ID} {bodyLength} {description} {(int)code}";

            byte[] headerbytes = Tools.Encrypt(Encoding.UTF8.GetBytes(header));

            List<byte> requestBytes = new List<byte>();
            requestBytes.AddRange(BitConverter.GetBytes(headerbytes.Length));
            requestBytes.AddRange(headerbytes);

            requestBytes.AddRange(body);

            return requestBytes.ToArray();
        }

        



        ~OSPClient()
        {
            Dispose(false);
        }
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }


        bool _disposed = false;
        protected virtual void Dispose(bool disposing)
        {
            if (_disposed) return;

            if (disposing)
            {
                tcp_client.Close();
                stream.Close();
                rsa_provider.Dispose();
                Tools.aes.Dispose();
                _allRequests.Clear();



            }

            if (Settings != null)
            {

                Settings = null;

                _ip = null;

            }
            _disposed = true;
        }


        // New Message Event

        protected virtual void NewMessageSent(HeaderMessage eventArgs)

        {
            NewMessageEvent? msg = OnNewMessage;
            if (msg != null)
            {
                msg(new MessageEventArgs() { Header = eventArgs, Data = null });
            }
        }
        public delegate void NewMessageEvent(MessageEventArgs args);
        /// <summary>
        /// Это событие происходит, когда заголовок полностью прочитывается. Не содержит тело запроса. (Только для неожиданных сообщений от сервера.)
        /// </summary>
        public event NewMessageEvent? OnNewMessage;


        // Message FullyReaded
        protected virtual void MessageFullyReaded(MessageEventArgs args)
        {

            MessageFullyReadedEvent? msg = OnMessageFullyReaded;
            if (msg != null)
            {
                msg(args);
            }
        }
        public delegate void MessageFullyReadedEvent(MessageEventArgs args);
        /// <summary>
        /// Это событие происходит, когда заголовок и тело полностью прочитаны. (Только для неожиданных сообщений от сервера.)
        /// </summary>
        public event MessageFullyReadedEvent? OnMessageFullyReaded;


        // Message Reading Progress



        protected virtual void MessageProgressRead(float progress, uint ID)
        {
            MessageProgressReadEvent? msg = OnMessageProgressRead;
            if (msg != null)
            {
                msg(progress, ID);
            }
        }
        public delegate void MessageProgressReadEvent(float progress, uint ID);
        /// <summary>
        /// Это событие происходит при обновлении прогресса. (Только для неожиданных сообщений от сервера.)
        /// </summary>

        public event MessageProgressReadEvent? OnMessageProgressRead;


        protected virtual void ResponseProgressRead(float progress)
        {
            ResponseProgressReadEvent? msg = OnResponseProgressRead;
            if (msg != null)
            {
                msg(progress);
            }
        }
        public delegate void ResponseProgressReadEvent(float progress);

        /// <summary>
        /// Это событие происходит, когда прогресс запроса обновляется. 
        /// </summary>
        public event ResponseProgressReadEvent? OnResponseProgressRead;
    }

    public class OSPServerAnswer
    {
        public byte[]? Data { get; set; } = null;

        public OSPStatusCode Code { get; set; } = OSPStatusCode.OK;
    }

    /// <summary>
    /// Это сервер. Принимает подключения и данные, обеспечивая шифрование.
    /// </summary>
    public class OSPServer : IDisposable
    {
        public delegate Task<OSPServerAnswer> GetAnswerOnMessage(MessageEventArgs args);
        static GetAnswerOnMessage? messageHandler;
        static Tools Tools = new Tools();


        class OSPListener : IDisposable
        {
            NetworkStream? stream;
            RSA rsa_provider;

        
            OSPServer _server;
            SemaphoreSlim _writeLock = new SemaphoreSlim(1, 1);


            IPEndPoint _ip;

            public OSPListener(OSPServer server, TcpClient client)
            {


                _server = server;





                rsa_provider = RSA.Create();
                rsa_provider.KeySize = 2048;

                client.NoDelay = true;
                client.SendBufferSize = 262144;     // 256KB ←
                client.ReceiveBufferSize = 262144;  // 256KB ←

                stream = client.GetStream();


                Tools.aes.Mode = CipherMode.CBC;
                Tools.aes.Padding = PaddingMode.PKCS7;
                _ = Task.Run(() => ClientConnection(client));
            }




            async Task ClientConnection(TcpClient client)
            {

                try
                {
                    _ip = (IPEndPoint)client.Client.RemoteEndPoint;



                    List<byte> data = new List<byte>();
                    int bytesRead = 0;


                    data.AddRange(rsa_provider.ExportRSAPublicKey());
                    data.Add(0x1E);
                    data.Add(0x1F);
                    data.Add(0x1E);
                    data.Add(0x1F);

                    await stream.WriteAsync(data.ToArray(), 0, data.Count);
                    await stream.FlushAsync();
                    data.Clear();


                    while ((bytesRead = stream.ReadByte()) != -1)
                    {

                        data.Add((byte)bytesRead);
                        if (data.Count >= 4)
                        {

                            if (data[data.Count - 1] == 0x4D && data[data.Count - 2] == 0x3C && data[data.Count - 3] == 0x2B && data[data.Count - 4] == 0x1A)
                            {
                                data.RemoveAt(data.Count - 1);
                                data.RemoveAt(data.Count - 1);
                                data.RemoveAt(data.Count - 1);
                                data.RemoveAt(data.Count - 1);

                                Tools.aes.Key = rsa_provider.Decrypt(data.ToArray(), RSAEncryptionPadding.Pkcs1);


                                data.Clear();
                                continue;

                            }
                            else if (data[data.Count - 1] == 0x1F && data[data.Count - 2] == 0x1E && data[data.Count - 3] == 0x1F && data[data.Count - 4] == 0x1E)
                            {
                                data.RemoveAt(data.Count - 1);
                                data.RemoveAt(data.Count - 1);
                                data.RemoveAt(data.Count - 1);
                                data.RemoveAt(data.Count - 1);
                                break;
                            }
                        }


                    }

                    Tools.aes.IV = data.ToArray();



                    data.Clear();

                    _server.NewClientConnected((IPEndPoint)client.Client.RemoteEndPoint);
                }
                catch
                {

                }










                try
                {
                    while (true)
                    {

                        HeaderMessage header;
                        byte[] headerBuffer = new byte[4];

                        await stream.ReadExactlyAsync(headerBuffer, 0, headerBuffer.Length);
                        int headerLength = BitConverter.ToInt32(headerBuffer, 0);

                        byte[] HedBuffer = new byte[headerLength];
                        await stream.ReadExactlyAsync(HedBuffer, 0, HedBuffer.Length);

                        byte[] decoded = Tools.Decrypt(HedBuffer);
                        header = _server.MakeHeaderFromResponse(decoded, (IPEndPoint)client.Client.RemoteEndPoint);


                        _server.NewMessageSent(header);


                        byte[] dataBuffer = new byte[header.DataLength];

                        await stream.ReadExactlyAsync(dataBuffer, 0, dataBuffer.Length);







                        MessageEventArgs args = new MessageEventArgs()
                        {
                            Data = Tools.Decrypt(dataBuffer),
                            Header = header,

                        };

                        _server.MessageFullyReaded(args);
                        OSPServerAnswer dataAnswer = await messageHandler.Invoke(args);

                        _ = Task.Run(async () => await Answer(args.Header.UniID, dataAnswer.Code, dataAnswer.Data is null ? null : dataAnswer.Data));











                    }
                }
                catch
                {
                    _server.ClientDisconnected((IPEndPoint)client.Client.RemoteEndPoint);

                }






            }

            async void Send(byte[] data)
            {

                await _writeLock.WaitAsync();
                try
                {
                    await stream.WriteAsync(data, 0, data.Length);
                }
                catch
                {
                    _server.ClientDisconnected(_ip);
                }

                await stream.FlushAsync();
                _writeLock.Release();

            }

            public Task SendMessage(byte[] data, string? description = null)
            {
                if (String.IsNullOrEmpty(description)) description = "n";


                byte[] encrypted = Tools.Encrypt(data);

                Send(MakeRequest(description, OSPStatusCode.None, Random(), encrypted));

                return Task.CompletedTask;
            }

            ~OSPListener()
            {
                Dispose(false);
            }
            public void Dispose()
            {
                Dispose(true);
                GC.SuppressFinalize(this);
            }


            bool _disposed = false;
            protected virtual void Dispose(bool disposing)
            {
                if (_disposed) return;

                if (disposing)
                {
                    _writeLock.Dispose();
                    stream.Close();
                    rsa_provider.Dispose();
                    Tools.aes.Dispose();



                }
                else
                {
                    _server = null;
                }

                _disposed = true;
            }

            uint Random()
            {
                System.Random rnd = new System.Random();
                int key = rnd.Next(100, 1000);

                return (uint)key;
            }
            
            byte[] MakeRequest(string description, OSPStatusCode code, uint ID, byte[]? body = null)
            {
                int bodyLength = 0;
                if (body != null) bodyLength = body.Length;

                if (String.IsNullOrEmpty(description)) description = "n";
                else
                {
                    if (description.Contains(' '))
                    {
                        throw new ArgumentException("description содержит пробел!");
                    }
                }
                string header = $"{ID} {bodyLength} {description} {(int)code}";

                byte[] headerbytes = Tools.Encrypt(Encoding.UTF8.GetBytes(header));

                List<byte> requestBytes = new List<byte>();
                requestBytes.AddRange(BitConverter.GetBytes(headerbytes.Length));
                requestBytes.AddRange(headerbytes);

                if (body != null) requestBytes.AddRange(body);

                return requestBytes.ToArray();
            }


            public Task Answer(uint ID, OSPStatusCode statusCode, byte[]? data = null)
            {
                if (data != null)
                {
                    byte[] encrypted = Tools.Encrypt(data);
                    byte[] toSend = MakeRequest(string.Empty, statusCode, ID, encrypted);

                    Send(toSend);
                }
                else
                {
                    byte[] toSend = MakeRequest(string.Empty, statusCode, ID, null);
                    Send(toSend);
                }

                return Task.CompletedTask;
            }
        }

        TcpListener _listener;



        ~OSPServer()
        {
            Dispose(false);
        }
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }


        bool _disposed = false;
        protected virtual void Dispose(bool disposing)
        {
            if (_disposed) return;

            if (disposing)
            {


                _listener.Dispose();



            }

            if (Settings != null)
            {

                Settings = null;
                messageHandler = null;
                _ip = null;

            }
            _disposed = true;
        }

        OSPSettings Settings = new OSPSettings();



        string _ip = string.Empty;
        int _port = 0;

        /// <summary>
        /// С этого всё начинается. Запустите сервер!
        /// </summary>
        /// <param name="messageAnswerHandler">Составьте свою логику ответов.</param>
        public void Start(GetAnswerOnMessage messageAnswerHandler)
        {
            messageHandler = messageAnswerHandler;
            _listener.Start();

            Task.Run(() => _start());

        }
        Dictionary<string, uint> all_requests = new Dictionary<string, uint>();
        Dictionary<string, OSPListener> all_clients = new Dictionary<string, OSPListener>();
        async Task _start()
        {
            while (true)
            {
                try
                {
                    TcpClient client = await _listener.AcceptTcpClientAsync();


                    IPEndPoint ip = (IPEndPoint)client.Client.RemoteEndPoint;

                    all_clients[ip.ToString()] = new OSPListener(this, client);
                }
                catch
                {

                }


            }
        }

        /// <summary>
        /// Используйте эту функцию, чтобы ответить клиенту на его запрос.
        /// </summary>
        /// <param name="requestHeader">Заголовок, который отправлял Вам клиент.</param>
        /// <param name="statusCode">Статус-код</param>
        /// <param name="data">Ваши данные. (Необязательно)</param>
        /// <returns></returns>
        [Obsolete("С появлением нового аргумента в старте сервера, данная функция становится устаревшей. Может быть использована исключительно для своей сложной логики.")]
        public Task Answer(HeaderMessage requestHeader, OSPStatusCode statusCode, byte[]? data = null)
        {

            if (all_requests.ContainsKey(requestHeader.IPEndPoint.ToString()))
            {

                all_clients[requestHeader.IPEndPoint.ToString()].Answer(requestHeader.UniID, statusCode, data);
                all_requests.Remove(requestHeader.IPEndPoint.ToString());
            }



            return Task.CompletedTask;
        }

        /// <summary>
        /// Отправьте данные клиенту без его запроса. (Данные можно отправлять только подключенным клиентам)
        /// </summary>
        /// <param name="data">Данные для отправки.</param>
        /// <param name="ip">IP клиента, которому Вы хотите отправить данные.</param>
        /// <param name="description">Универсальное значение для вас.</param>


        public async Task Send(byte[] data, IPEndPoint ip, string? description = null)
        {
            if (all_clients.ContainsKey(ip.ToString()))
            {
                await all_clients[ip.ToString()].SendMessage(data, description);

            }
            else throw new Exception($"{ip} не существует.");

        }


        public OSPServer(string ip, int port)
        {
            _listener = new TcpListener(IPAddress.Parse(ip), port);

            _listener.Server.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.NoDelay, true);
            _listener.Server.SendBufferSize = 262144;    // 256KB ←
            _listener.Server.ReceiveBufferSize = 262144; // 256KB ←
            _listener.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveBuffer, 262144);
            _listener.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.SendBuffer, 262144);
            _ip = ip;
            _port = port;
        }

        HeaderMessage MakeHeaderFromResponse(byte[] data, IPEndPoint ip)
        {
            string header = Encoding.UTF8.GetString(data);
            string[] args = header.Split(' ');
            HeaderMessage msg = new HeaderMessage()
            {
                UniID = Convert.ToUInt32(args[0]),
                DataLength = Convert.ToInt32(args[1]),
                Description = args[2],
                MessageStatus = (OSPStatusCode)Convert.ToInt32(args[3]),
                IPEndPoint = ip
            };

            return msg;
        }


        // New Message Event
        protected virtual void NewMessageSent(HeaderMessage eventArgs)
        {
            all_requests.Add(eventArgs.IPEndPoint.ToString(), eventArgs.UniID);
            NewMessageEvent? msg = OnNewMessage;
            if (msg != null)
            {
                msg(new MessageEventArgs() { Header = eventArgs, Data = null });
            }
        }
        public delegate void NewMessageEvent(MessageEventArgs args);
        /// <summary>
        /// Это событие происходит, когда заголовок полностью прочитывается. Не содержит тело запроса.
        /// </summary>
        public event NewMessageEvent? OnNewMessage;


        // Message FullyReaded
        protected virtual void MessageFullyReaded(MessageEventArgs args)
        {

            all_requests.Remove(args.Header.IPEndPoint.ToString());
            MessageFullyReadedEvent? msg = OnMessageFullyReaded;

            if (msg != null)
            {
                msg(args);
            }
        }
        public delegate void MessageFullyReadedEvent(MessageEventArgs args);
        /// <summary>
        /// Это событие происходит, когда заголовок и тело полностью прочитаны.
        /// </summary>
        public event MessageFullyReadedEvent? OnMessageFullyReaded;




        // New Client Event
        protected virtual void NewClientConnected(IPEndPoint remotePoint)
        {
            all_requests.Remove(remotePoint.ToString());
            NewClientConnectedEvent? msg = OnNewClientConnected;
            if (msg != null)
            {
                msg(remotePoint);
            }
        }
        public delegate void NewClientConnectedEvent(IPEndPoint remotePoint);
        /// <summary>
        /// Это событие происходит, когда новый клиент подключился к серверу, и они произвели успешный обмен ключами шифрования.
        /// </summary>
        public event NewClientConnectedEvent? OnNewClientConnected;

        // Client Disconnected 
        protected virtual void ClientDisconnected(IPEndPoint remotePoint)
        {
            OSPListener listener = all_clients[remotePoint.ToString()];
            all_clients.Remove(remotePoint.ToString());
            listener.Dispose();
            ClientDisconnectedEvent? msg = OnClientDisconnected;
            if (msg != null)
            {
                msg(remotePoint);
            }
        }
        public delegate void ClientDisconnectedEvent(IPEndPoint remotePoint);
        /// <summary>
        /// Это событие происходит, когда клиент отключается от сервера.
        /// </summary>
        public event ClientDisconnectedEvent? OnClientDisconnected;

    }

    public class HeaderMessage
    {
        public uint UniID { get; set; }
        public OSPStatusCode MessageStatus { get; set; }
        public long DataLength { get; set; }
        public required string Description { get; set; }
        public required IPEndPoint IPEndPoint { get; set; }
    }
    public class MessageEventArgs
    {





        public required HeaderMessage Header { get; set; }

        public byte[]? Data { get; set; }
    }
#pragma warning restore CS8604 // Возможно, аргумент-ссылка, допускающий значение NULL.
#pragma warning restore CS8600 // Преобразование литерала, допускающего значение NULL или возможного значения NULL в тип, не допускающий значение NULL.

    /// <summary>
    /// Представляет класс, в котором лежит ответ от сервера. Иногда сервер может вернуть статус-код без данных.   
    /// </summary>
    public class OSPResponse
    {
        public bool OnlyStatusCode { get; set; }
        public OSPStatusCode StatusCode { get; set; }

        public required HeaderMessage Header { get; set; }
        public byte[]? Data { get; set; }
    }
#pragma warning restore CS8625 // Литерал, равный NULL, не может быть преобразован в ссылочный тип, не допускающий значение NULL.
#pragma warning restore CS8602 // Разыменование вероятной пустой ссылки.
#pragma warning restore CS1591 // Отсутствует комментарий XML для открытого видимого типа или члена
}


