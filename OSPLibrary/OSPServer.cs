
using System.Security.Cryptography;
using System.Text;


namespace System.Net.Sockets.OSP
{
    /// <summary>
    /// Это сервер. Принимает подключения и данные, обеспечивая шифрование.
    /// </summary>
    public class OSPServer : IDisposable
    {
        public  OSPSettings Settings = new OSPSettings();

        public delegate Task<OSPServerAnswer> GetAnswerOnMessage(MessageEventArgs args);
          GetAnswerOnMessage? messageHandler;

        byte[]? masterKey = null;

        class OSPListener : IDisposable
        {


            NetworkStream stream;

            Tools Tools = new Tools();

            OSPServer _server;
            SemaphoreSlim _writeLock = new SemaphoreSlim(1, 1);


            IPEndPoint? _ip;


            uint DataNum = 0;

            uint SendDataNum = 0;
            public OSPListener(OSPServer server, TcpClient client)
            {


                _server = server;





                _server.Settings.SetRSAKeySise(2048);
                Tools.rsa_provider.KeySize = _server.Settings.RSA_Size;
                Tools.Master_RSA.ImportRSAPrivateKey(_server.masterKey, out _);
                client.NoDelay = true;
                client.SendBufferSize = _server.Settings.SendBufferSize;    
                client.ReceiveBufferSize = _server.Settings.ReceiveBufferSize;  

                stream = client.GetStream();
           

                Tools.aes.Mode = CipherMode.CBC;
                Tools.aes.Padding = PaddingMode.PKCS7;
                _ = Task.Run(() => ClientConnection(client));
            }




            async Task ClientConnection(TcpClient client)
            {

                try
                {
         
                  if (client.Client.RemoteEndPoint != null)  _ip = (IPEndPoint)client.Client.RemoteEndPoint;



                    List<byte> data = new List<byte>();
                    int bytesRead = 0;
                    byte[] publicKey = Tools.rsa_provider.ExportRSAPublicKey();
                    byte[] sign = Tools.Master_RSA.SignData(publicKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    data.AddRange(BitConverter.GetBytes(publicKey.Length));
                    data.AddRange(publicKey);
                    data.AddRange(sign);
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

                                Tools.aes.Key = Tools.rsa_provider.Decrypt(data.ToArray(), RSAEncryptionPadding.Pkcs1);


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

                    _server.NewClientConnected(client.Client.RemoteEndPoint is null ? IPEndPoint.Parse("0.0.0.0:1") : (IPEndPoint)client.Client.RemoteEndPoint);
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
                        header = GlobalTools.MakeHeaderFromResponse(decoded, client.Client.RemoteEndPoint is null ? IPEndPoint.Parse("0.0.0.0:1") : (IPEndPoint)client.Client.RemoteEndPoint);

                        if (header.MessageType != OSPMessageType.MessageFromClient) throw new Exception("Атака злоумышленника.");

                        if (header.UniID != DataNum) throw new Exception("Атака злоумышленника.");
                        else DataNum++;
                            _server.NewMessageSent(header);


                        byte[] dataBuffer = new byte[header.DataLength];

                        await stream.ReadExactlyAsync(dataBuffer, 0, dataBuffer.Length);







                        MessageEventArgs args = new MessageEventArgs()
                        {
                            Data = Tools.Decrypt(dataBuffer),
                            Header = header,

                        };

                        _server.MessageFullyReaded(args);
                        if (_server.messageHandler != null)
                        {
                            OSPServerAnswer dataAnswer = await _server.messageHandler.Invoke(args);

                            _ = Task.Run(async () => await Answer(args.Header.UniID, dataAnswer.Code, dataAnswer.Data is null ? null : dataAnswer.Data));
                        }
                  











                    }
                }
                catch
                {
                    _server.ClientDisconnected(client.Client.RemoteEndPoint is null ? IPEndPoint.Parse("0.0.0.0:1") : (IPEndPoint)client.Client.RemoteEndPoint);

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
                    _server.ClientDisconnected(_ip is null ? IPEndPoint.Parse("0.0.0.0:1") : _ip);
                }

                await stream.FlushAsync();
                _writeLock.Release();

            }

            public Task SendMessage(byte[] data, string? description = null)
            {
                if (String.IsNullOrEmpty(description)) description = "n";


                byte[] encrypted = Tools.Encrypt(data);

                Send(MakeRequest(description, OSPStatusCode.None, SendDataNum, OSPMessageType.MessageFromServer,encrypted));
                SendDataNum++;

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
                    Tools.rsa_provider.Dispose();
                    Tools.aes.Dispose();



                }
              

                _disposed = true;
            }

          

            byte[] MakeRequest(string description, OSPStatusCode code, uint ID, OSPMessageType type, byte[]? body = null)
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
                string header = $"{ID} {bodyLength} {description} {(int)code} {(int)type}";

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
                    byte[] toSend = MakeRequest(string.Empty, statusCode, ID, OSPMessageType.AnswerFromServer,encrypted);

                    Send(toSend);
                }
                else
                {
                    byte[] toSend = MakeRequest(string.Empty, statusCode, ID, OSPMessageType.AnswerFromServer, null);
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

              
                messageHandler = null;
              

            }
            _disposed = true;
        }

        



        string _ip = string.Empty;
        int _port = 0;

        /// <summary>
        /// С этого всё начинается. Запустите сервер!
        /// </summary>
        /// <param name="messageAnswerHandler">Составьте свою логику ответов.</param>
        ///  /// <param name="PrivateMasterKey">Поместите сюда приватный мастер-ключ для подписи.</param>
        public void Start(GetAnswerOnMessage messageAnswerHandler, string PrivateMasterKey)
        {

            messageHandler = messageAnswerHandler;
            masterKey = Convert.FromBase64String(PrivateMasterKey);
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


                    IPEndPoint ip = client.Client.RemoteEndPoint is null ? IPEndPoint.Parse("0.0.0.0:1") : (IPEndPoint)client.Client.RemoteEndPoint;

                    all_clients[ip.ToString()] = new OSPListener(this, client);
                }
                catch
                {

                }


            }
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
      
            _listener.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveBuffer, Settings.ReceiveBufferSize);
            _listener.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.SendBuffer, Settings.SendBufferSize);
            _ip = ip;
            _port = port;
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
}
