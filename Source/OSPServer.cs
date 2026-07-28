using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace Orange.Security.Protocol
{
    /// <summary>
    /// Это сервер. Принимает подключения и данные. Автоматическое шифрование.
    /// </summary>
    public class OSPServer : IDisposable
    {
        /// <summary>
        /// Настройки сервера.
        /// </summary>
        public OSPServerSettings Settings = new OSPServerSettings();

        
        internal OSPMessageHandler messageHandler = null!;
        internal OSPFrameHandler? frameHandler;
        internal byte[]? masterKey = null!;

        /// <summary>
        /// 
        /// </summary>
        ~OSPServer()
        {
            Dispose(false);
        }

        /// <summary>
        /// Выключает сервер и отсоедияет всех клиентов.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }


        private bool _disposed = false;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="disposing"></param>
        protected virtual void Dispose(bool disposing)
        {
            if (_disposed) return;

            if (disposing)
            {

                
                lock (all_clients)
                {
                    foreach (var client in all_clients)
                    {
                        try
                        {
                            client.Value.Dispose();
                        }
                        catch { }
                        
                    }
                }
                all_clients.Clear();



            }

            if (Settings != null)
            {


                messageHandler = null!;


            }
            _disposed = true;
        }

        private IPEndPoint IPEndPoint = null!;

        private CancellationTokenSource _cts = new CancellationTokenSource();

        /// <summary>
        /// Запускает сервер и начинает ожидать подключения.
        /// </summary>
        /// <param name="MessageAnswerHandler">Составьте свою логику ответов.</param>
        /// <param name="PrivateMasterKey">Поместите сюда приватный мастер-ключ для подписи.</param>
        /// <param name="FrameHandler">Склеивайте сообщения по кусочкам. Очень сильно экономит память. Подходит для стриминга данных.</param>
        public void Start(OSPMessageHandler MessageAnswerHandler, string? PrivateMasterKey = null, OSPFrameHandler? FrameHandler = null)
        {
            

            messageHandler = MessageAnswerHandler;
            if (!String.IsNullOrWhiteSpace(PrivateMasterKey)) masterKey = Convert.FromBase64String(PrivateMasterKey);
            
            if (FrameHandler != null)
            {
                frameHandler = FrameHandler;
            }
            

            Task.Run(() => _start(_cts.Token));

        }

        /// <summary>
        /// Закрывает соединение с клиентом. (Событие ClientDisconnected сработает)
        /// </summary>
        /// <param name="clientIPEndPoint">Клиент, соединение с которым будет закрыто.</param>
        public void CloseConnectionWith(IPEndPoint clientIPEndPoint)
        {
            
            if (all_clients.TryRemove(clientIPEndPoint, out OSPListener? listener))
            {
                listener.Dispose();
                ClientDisconnectedEvent? msg = OnClientDisconnected;
                if (msg != null) msg(clientIPEndPoint);

            }
          
            
            
        }

        /// <summary>
        /// Обновляет скоростные лимиты с клиентом.
        /// </summary>
        /// <param name="clientIPEndPoint">IPEndPoint клиента, с которым лимиты поменяются</param>
        /// <param name="EgressBitrateMbps">Исходящая скорость в Мбит/с</param>
        /// <param name="IngressBitrateMbps">Входяшая скорость в Мбит/с</param>
        public void UpdateBitrateMbpsWith(IPEndPoint clientIPEndPoint, int EgressBitrateMbps, int IngressBitrateMbps)
        {
            if (all_clients.TryGetValue(clientIPEndPoint, out OSPListener? listener))
            {
                listener.UpdateBitrate(EgressBitrateMbps, IngressBitrateMbps);
            }
        }

        /// <summary>
        /// Отменить запрос, приходящий от клиента.
        /// </summary>
        /// <param name="clientIPEndPoint">IPEndPoint клиента</param>
        /// <param name="ID">ID запроса.</param>
        public void CancelPacketWith(IPEndPoint clientIPEndPoint, uint ID)
        {
            if (all_clients.TryGetValue(clientIPEndPoint, out OSPListener? listener))
            {
                listener.CancelPacket(ID);
            }
        }


        
        private ConcurrentDictionary<IPEndPoint, OSPListener> all_clients = new ConcurrentDictionary<IPEndPoint, OSPListener>();
        private async Task _start(CancellationToken ct)
        {
            using Socket listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            listener.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.NoDelay, true);
            listener.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveBuffer, Settings.ReceiveBufferSize);
            listener.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.SendBuffer, Settings.SendBufferSize);
            listener.Bind(IPEndPoint);
            listener.Listen();
            while (!ct.IsCancellationRequested)
            {
                
                try
                {
                    Socket clientSocket = await listener.AcceptAsync(ct);

                    bool isLimit = false;
                    if (Settings.MaxClients != 0) isLimit = all_clients.Count >= Settings.MaxClients; 

                    if (isLimit)
                    {
                        clientSocket.Shutdown(SocketShutdown.Both);
                        clientSocket.Close();
                        continue;
                    }
                    if (clientSocket.RemoteEndPoint is IPEndPoint ip)
                    {
                        OSPListener newClient = new OSPListener(this, clientSocket);
                        all_clients[ip] = newClient;
                    }
                    else
                    {
                        clientSocket.Close();
                    }
                    
                    
                    
                }
                finally { }
                


            }
        }





        /// <summary>
        /// Отправьте данные клиенту без его запроса. (Данные можно отправлять только подключенным клиентам)
        /// </summary>
        /// <param name="data">Данные для отправки.</param>
        /// <param name="ip">IP клиента, которому Вы хотите отправить данные.</param>
        /// <param name="description">Универсальное значение для вас.</param>
        public bool Send(NativeBytes data, IPEndPoint ip, byte[]? description)
        {
            if (all_clients.TryGetValue(ip, out OSPListener? _client))
            {
                _client.SendMessage(new OSPData(data), description);

                return true;
            }
            else return false;

        }
        /// <summary>
        /// Отправьте данные клиенту без его запроса. (Данные можно отправлять только подключенным клиентам)
        /// </summary>
        /// <param name="data">Данные для отправки.</param>
        /// <param name="ip">IP клиента, которому Вы хотите отправить данные.</param>
        /// <param name="description">Универсальное значение для вас.</param>
        public bool Send(Memory<byte> data, IPEndPoint ip, byte[]? description)
        {
            if (all_clients.TryGetValue(ip, out OSPListener? _client))
            {
                _client.SendMessage(new OSPData(data), description);

                return true;
            }
            else return false;

        }
        /// <summary>
        /// Отправьте данные клиенту без его запроса. (Данные можно отправлять только подключенным клиентам)
        /// </summary>
        /// <param name="data">Данные для отправки.</param>
        /// <param name="ip">IP клиента, которому Вы хотите отправить данные.</param>
        /// <param name="description">Универсальное значение для вас.</param>
        public bool Send(byte[] data, IPEndPoint ip, byte[]? description)
        {
            if (all_clients.TryGetValue(ip, out OSPListener? _client))
            {
                _client.SendMessage(new OSPData(data), description);

                return true;
            }
            else return false;

        }
        /// <summary>
        /// Отправьте данные клиенту без его запроса. (Данные можно отправлять только подключенным клиентам)
        /// </summary>
        /// <param name="data">Данные для отправки.</param>
        /// <param name="ip">IP клиента, которому Вы хотите отправить данные.</param>
        /// <param name="description">Универсальное значение для вас.</param>
        public bool Send(Stream data, IPEndPoint ip, byte[]? description)
        {
            if (all_clients.TryGetValue(ip, out OSPListener? _client))
            {
                _client.SendMessage(new OSPData(data), description);

                return true;
            }
            else return false;

        }

        /// <summary>
        /// Отправьте данные клиенту без его запроса. (Данные можно отправлять только подключенным клиентам)
        /// </summary>
        /// <param name="data">Данные для отправки.</param>
        /// <param name="ip">IP клиента, которому Вы хотите отправить данные.</param>
        /// <param name="description">Универсальное значение для вас.</param>
        public bool Send(OSPData data, IPEndPoint ip, byte[]? description)
        {
            if (all_clients.TryGetValue(ip, out OSPListener? _client))
            {
                _client.SendMessage(data, description);

                return true;
            }
            else return false;

        }



        /// <summary>
        /// Представляет класс сервера. 
        /// </summary>
        /// <param name="ip">String IP</param>
        /// <param name="port">Порт</param>
        public OSPServer(string ip, int port)
        {
            IPEndPoint = IPEndPoint.Parse(ip + ":" + port);
        }
        /// <summary>
        /// Представляет класс сервера. 
        /// </summary>
        public OSPServer(IPEndPoint ip)
        {
            IPEndPoint = ip;
            
        }
        /// <summary>
        /// Представляет класс сервера. 
        /// </summary>
        public OSPServer(IPAddress ip, int port)
        {
            IPEndPoint = new IPEndPoint(ip, port);
        }




        // New Message Event
        internal virtual void NewMessageSent(OSPHeaderRequest eventArgs)
        {

            NewMessageEvent? msg = OnNewMessage;
            if (msg != null)
            {
                msg(new OSPMessageEventArgs() { Header = eventArgs, Data = null });
            }
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="args"></param>
        public delegate void NewMessageEvent(OSPMessageEventArgs args);
        /// <summary>
        /// Это событие происходит, когда заголовок полностью прочитывается. Не содержит тело запроса.
        /// </summary>
        public event NewMessageEvent? OnNewMessage;







        // New Client Event
        internal virtual void NewClientConnected(IPEndPoint remotePoint)
        {

            NewClientConnectedEvent? msg = OnNewClientConnected;
            if (msg != null)
            {
                msg(remotePoint);
            }
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="remotePoint"></param>
        public delegate void NewClientConnectedEvent(IPEndPoint remotePoint);
        /// <summary>
        /// Это событие происходит, когда новый клиент подключился к серверу, завершив рукопожатие.
        /// </summary>
        public event NewClientConnectedEvent? OnNewClientConnected;

        // Client Disconnected 
        internal virtual void ClientDisconnected(IPEndPoint remotePoint)
        {
            if (all_clients.TryRemove(remotePoint, out OSPListener? listener))
            {
                listener.Dispose();
                ClientDisconnectedEvent? msg = OnClientDisconnected;
                if (msg != null)
                {
                    msg(remotePoint);
                }
            }       
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="remotePoint"></param>
        public delegate void ClientDisconnectedEvent(IPEndPoint remotePoint);
        /// <summary>
        /// Это событие происходит, когда клиент отключается от сервера.
        /// </summary>
        public event ClientDisconnectedEvent? OnClientDisconnected;



        internal virtual void ErrorOccured(IPEndPoint remotePoint, Exception ex)
        {
            ErrorOccuredEvent? msg = OnErrorOccured;
            if (msg != null) msg(remotePoint, ex);
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="remotePoint"></param>
        /// <param name="ex"></param>
        public delegate void ErrorOccuredEvent(IPEndPoint remotePoint, Exception ex);

        /// <summary>
        /// Это событие происходит, когда склиентом происходит ошибка внутри протокола.
        /// </summary>
        public event ErrorOccuredEvent? OnErrorOccured;
    }
}
