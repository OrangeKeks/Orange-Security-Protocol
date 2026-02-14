
using System.Collections.Concurrent;

using System.Security.Cryptography;
using System.Text;


namespace System.Net.Sockets.OSP
{
    /// <summary>
    /// Это клиент. Подключается к серверу и обменивается с ним данными по вашему запросу. Обеспечивает автоматическое шифрование.
    /// </summary>
    public class OSPClient : IDisposable
    {
        /// <summary>
        /// Подключен ли клиент к серверу на текущий момент?
        /// </summary>
        public bool IsConnected { get; private set; } = false;
       public OSPSettings Settings = new OSPSettings();
        Tools Tools = new Tools();

        NetworkStream? stream;

        TcpClient tcp_client;

       


        string _ip = string.Empty;
        int _port = 0;

        /// <summary>
        /// Запускаем клиент, присоединяясь к серверу.
        /// </summary>
        /// <param name="PublicMasterKey">Публичный ключ сервера для проверки подписи.</param>
        /// <returns></returns>
        public Task Start(string PublicMasterKey)
        {

            Tools.aes.GenerateIV();
            Tools.aes.GenerateKey();
            Tools.Master_RSA.ImportRSAPublicKey(Convert.FromBase64String(PublicMasterKey), out _);


            tcp_client.Connect(IPAddress.Parse(_ip), _port);
            stream = tcp_client.GetStream();

            byte[] publicKeyLength = new byte[4];

            stream.ReadExactly(publicKeyLength, 0, 4);
            byte[] publicKey = new byte[BitConverter.ToInt32(publicKeyLength)];
            stream.ReadExactly(publicKey);
            Tools.rsa_provider.ImportRSAPublicKey(publicKey, out _);
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

            bool isSecured = Tools.Master_RSA.VerifyData(publicKey, data.ToArray(), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            if (!isSecured) { stream.Close(); tcp_client.Close(); throw new Exception("Недостоверная подпись. Соединение разорвано."); }
     

            byte[] terminator = { 0x1A, 0x2B, 0x3C, 0x4D };
       
           

            byte[] ecnryptedKey = Tools.rsa_provider.Encrypt(Tools.aes.Key, RSAEncryptionPadding.Pkcs1);
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


        uint DataNum = 0;
        uint SendDataNum = 0;


        async Task ReadData()
        {

            IsConnected = true;
            List<byte> data = new List<byte>();

            //   header;


            while (true)
            {
                try
                {
                    if (stream == null) return;
                    byte[] headerBuffer = new byte[4];


                    await stream.ReadExactlyAsync(headerBuffer, 0, headerBuffer.Length);


                    int headerLength = BitConverter.ToInt32(headerBuffer, 0);


                    byte[] HedBuffer = new byte[headerLength];
                    await stream.ReadExactlyAsync(HedBuffer, 0, HedBuffer.Length);
                    byte[] decoded = Tools.Decrypt(HedBuffer);
                    HeaderMessage header = GlobalTools.MakeHeaderFromResponse(decoded, IPEndPoint.Parse($"{_ip}:{_port}"));

                    if (header.MessageType == OSPMessageType.AnswerFromServer)
                    {
                        if (header.UniID != SendDataNum) throw new Exception("Пакет отправлен злоумышленником.");
                        else SendDataNum++;
                    }
                    else if (header.MessageType == OSPMessageType.MessageFromServer)
                    {
                        if (header.UniID != DataNum) throw new Exception("Пакет отправлен злоумышленником.");
                        else DataNum++;
                    }


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
                        if (header.DataLength < Settings.ReceiveBufferSize) bufferCount = header.DataLength;
                        else bufferCount = Settings.ReceiveBufferSize;
                        byte[] dataBuffer = new byte[bufferCount];

                        while (data.Count < header.DataLength)
                        {

                            int readTo = dataBuffer.Length;
                            if (header.DataLength - data.Count < Settings.ReceiveBufferSize) readTo = (int)(header.DataLength - data.Count);
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
            tcp_client.ReceiveBufferSize = Settings.ReceiveBufferSize;
            tcp_client.SendBufferSize = Settings.SendBufferSize;
            Settings.SetRSAKeySise(2048);
            Tools.rsa_provider = RSA.Create();
            Tools.rsa_provider.KeySize = Settings.RSA_Size;
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
            var tcs = new TaskCompletionSource<OSPResponse>();
            if (stream == null) return await tcs.Task;
            if (data == null || data.Length == 0) throw new Exception("Данные отсутствуют или их количество равно нулю!");
            byte[] endData = Tools.Encrypt(data);


         
            
            _allRequests[SendDataNum] = tcs;

            await _writeLock.WaitAsync();
            await stream.WriteAsync(MakeRequest(description is null ? "" : description, OSPStatusCode.None, endData, SendDataNum, OSPMessageType.MessageFromClient));
            await stream.FlushAsync();
            _writeLock.Release();

            return await tcs.Task;



        }




       



      

        byte[] MakeRequest(string description, OSPStatusCode code, byte[] body, uint ID, OSPMessageType type)
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
            string header = $"{ID} {bodyLength} {description} {(int)code} {(int)type}";

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
               if (stream != null) stream.Close();
                Tools.rsa_provider.Dispose();
                Tools.aes.Dispose();
                _allRequests.Clear();



            }

            //if (Settings != null)
            //{

            //    Settings = null;

            //    _ip = null;

            //}
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
}
