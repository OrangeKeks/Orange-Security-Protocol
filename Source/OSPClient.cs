using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace Orange.Security.Protocol
{
    /// <summary>
    /// Это клиент. Подключается к серверу и обменивается с ним данными по вашему запросу. Обеспечивает автоматическое шифрование.
    /// </summary>
    public class OSPClient : IDisposable
    {
        /// <summary>
        /// Подключен ли клиент к серверу на текущий момент? (Не гарантирует точность)
        /// </summary>
        public bool IsConnected { get; private set; } = false;

        /// <summary>
        /// Задержка между клиентом и сервером в миллисекундах.
        /// </summary>
        public uint Ping { get; private set; } = 0;

        public OSPClientSettings Settings = new OSPClientSettings();
        
        private Tools Tools = new Tools(true);

        private OSPStream _scheduler = null!;
        private Socket _socket;

        

        private ConcurrentDictionary<uint, byte> CancelledPackets = new ConcurrentDictionary<uint, byte>();


        private IPEndPoint IPEndPoint = null!;
       

        /// <summary>
        /// Запускаем клиент, присоединяясь к серверу.
        /// </summary>
        /// <param name="PublicMasterKey">Публичный ключ сервера для проверки подписи.</param>        
        public async Task Start(string PublicMasterKey)
        {


            _socket.NoDelay = true;
            _socket.ReceiveBufferSize = Settings.ReceiveBufferSize;
            _socket.SendBufferSize = Settings.SendBufferSize;
            Tools._ecndhe = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);


            await _socket.ConnectAsync(IPEndPoint);
            
            _scheduler = new OSPStream(_socket, Tools, Settings, true);
            _scheduler.OnError += (ex) => ErrorOccured(ex);
            bool isSuccess = await _scheduler.Handshake(true, Convert.FromBase64String(PublicMasterKey));

            if (!isSuccess) throw new OSPException("Не удалось установить безопасное соединение с сервером.");

            if (Settings.PingInvervalMilliseconds > 0)
            {
                pingTimer = new System.Timers.Timer(Settings.PingInvervalMilliseconds);
                pingTimer.AutoReset = true;
                pingTimer.Elapsed += PingTimer_Elapsed;
                pingTimer.Start();
            }

            var header = await _scheduler.ReadHeader(IPEndPoint);

            if (header is OSPSystemHeader headerSys)
            {
                if (headerSys.Command == OSPConsts.HandshakeSettings)
                {
                    if (headerSys.Data != null)
                    {
                        _scheduler.variables.SliceSize = BinaryPrimitives.ReadInt32LittleEndian(headerSys.Data.Value.Span.Slice(0, 4));
                        _scheduler.variables.FrameSizeThreshold = BinaryPrimitives.ReadInt32LittleEndian(headerSys.Data.Value.Span.Slice(4));
                        ushort maxPackets = BinaryPrimitives.ReadUInt16LittleEndian(headerSys.Data.Value.Span.Slice(8));
                        int recPing = 1000 / maxPackets + 50; // 50 - stable value
                     
                        if (Settings.PingInvervalMilliseconds < recPing && Settings.PingInvervalMilliseconds > 0) pingTimer.Interval = recPing;
                    }
                }
            }

            _background = Task.Run(() => ReadData(source.Token));
           
            IsConnected = true;
        }


        /// <summary>
        /// Запускаем клиент, присоединяясь к серверу. Уязвимо к MitM атаке. 
        /// </summary>
        public async Task Start()
        {


            _socket.NoDelay = true;
            _socket.ReceiveBufferSize = Settings.ReceiveBufferSize;
            _socket.SendBufferSize = Settings.SendBufferSize;
            Tools._ecndhe = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);


            await _socket.ConnectAsync(IPEndPoint);

            _scheduler = new OSPStream(_socket, Tools, Settings, true);
            _scheduler.OnError += (ex) => ErrorOccured(ex);
            bool isSuccess = await _scheduler.Handshake(true);

            if (!isSuccess) throw new OSPException("Не удалось установить безопасное соединение с сервером.");

            if (Settings.PingInvervalMilliseconds > 0)
            {
                pingTimer = new System.Timers.Timer(Settings.PingInvervalMilliseconds);
                pingTimer.AutoReset = true;
                pingTimer.Elapsed += PingTimer_Elapsed;
                pingTimer.Start();
            }

            var header = await _scheduler.ReadHeader(IPEndPoint);

            if (header is OSPSystemHeader headerSys)
            {
                if (headerSys.Command == OSPConsts.HandshakeSettings)
                {
                    if (headerSys.Data != null)
                    {
                        _scheduler.variables.SliceSize = BinaryPrimitives.ReadInt32LittleEndian(headerSys.Data.Value.Span.Slice(0, 4));
                        _scheduler.variables.FrameSizeThreshold = BinaryPrimitives.ReadInt32LittleEndian(headerSys.Data.Value.Span.Slice(4));
                        ushort maxPackets = BinaryPrimitives.ReadUInt16LittleEndian(headerSys.Data.Value.Span.Slice(8));
                        int recPing = 1000 / maxPackets + 50; // 50 - stable value

                        if (Settings.PingInvervalMilliseconds < recPing && Settings.PingInvervalMilliseconds > 0) pingTimer.Interval = recPing;
                    }
                }
            }

            _background = Task.Run(() => ReadData(source.Token));

            IsConnected = true;
        }

        private void PingTimer_Elapsed(object? sender, System.Timers.ElapsedEventArgs e)
        {
            
            _scheduler.SendHighPacketToQueue(OSPConsts.PingCommand, null);
         
            pingWatch.Restart();
        }

        private System.Timers.Timer pingTimer = null!;
        private Stopwatch pingWatch = new Stopwatch();



        private NativeBytes frameBuffer = null!;
        private async Task ReadData(CancellationToken token)
        {
            byte[] tag = new byte[16];
            
            SemaphoreSlim _networkLock = new SemaphoreSlim(1, 1);
            while (!token.IsCancellationRequested)
            {
                try
                {

                    if (_socket == null) return;

                    await _networkLock.WaitAsync();

                    OSPBaseHeader base_header = await _scheduler.ReadHeader(IPEndPoint);
                    
                    
                    lock (TimersList) TimersList.RemoveAll(x => !x.Enabled);
                    
                    foreach (var cancelled in CancelledPackets)
                    {
                        CancelledPackets[cancelled.Key] = (byte)(cancelled.Value + 1);
                        if (CancelledPackets[cancelled.Key] >= 255)
                        {
                            CancelledPackets.Remove(cancelled.Key, out _);
                        }
                        
                    }


                    if (base_header is OSPHeader header)
                    {
                        
                        
                        if (header.MessageType == OSPMessageType.FrameFromClient || header.MessageType == OSPMessageType.RequestFromClient) throw new OSPException("Неверный тип пакета.");
                        if (CancelledPackets.ContainsKey(header.UniID)) throw new OSPException("Отменённый пакет продолжает приходить.");

                        (TaskCompletionSource<OSPResponse> answer, bool isStreaming)? response = null;
                        bool contains = true;


                        if (_allRequests.ContainsKey(header.UniID)) response = _allRequests[header.UniID]; 
                        else contains = false;
                        
                        
                        if (header is OSPHeaderRequest request)
                        {
                            if (header.IsFramed)
                            {
                                
                                if (frameBuffer == null) frameBuffer = new NativeBytes(_scheduler.variables.SliceSize);
                                if (response != null && response!.Value.isStreaming)
                                {
                                    frames[request.UniID] = (request, null!, 0);
                                }
                                else
                                {
                                    frames[request.UniID] = (request, new NativeBytes((long)request.DataLength), 0);
                                }

                                continue;
                            }
                            

                        }

                        if (header is OSPHeaderRequest _request)
                        {

                            if (!contains) NewMessageSent(_request);

                            if (_request.DataLength == 0)
                            {

                                if (response != null) { _ = Task.Run(() => response.Value.answer.SetResult(new OSPResponse() { Data = null, Header = _request, StatusCode = _request.MessageStatus, OnlyStatusCode = true })); _allRequests.TryRemove(header.UniID, out _); }
                                
                                continue;
                            }

                            await _scheduler.ReceiveExactlyAsync(tag);

                            var sw = Stopwatch.StartNew();

                            var obj = await _scheduler.ReadBodyFragment((int)_request.DataLength);

                            sw.Stop();

                            await _scheduler.IngressThrottling(sw.Elapsed.TotalMilliseconds, (int)obj.Length);
                            
                            

                            Tools.Decrypt(obj.AsWritableSpan(), tag);

                            if (response != null) { _ = Task.Run(() => response.Value.answer.SetResult(new OSPResponse() { Data = obj, Header = _request, StatusCode = _request.MessageStatus, OnlyStatusCode = false })); }
                            else
                            {
                                OSPMessageEventArgs args = new OSPMessageEventArgs()
                                {
                                    Data = obj,
                                    Header = _request,

                                };
                                if (OnMessageFullyRead != null) await OnMessageFullyRead(args);
                            }


                        }
                        else if (header is OSPHeaderFrame _frame)
                        {
                           
                            await _scheduler.ReceiveExactlyAsync(tag);
                            var current = frames[_frame.UniID];


                            var sw = Stopwatch.StartNew();

                           

                            int bytesRead =  await _scheduler.ReadFrame((long)current.request.DataLength, _frame.CurrentFrame, frameBuffer);

                            await _scheduler.IngressThrottling(sw.Elapsed.TotalMilliseconds, bytesRead);


                            Tools.Decrypt(frameBuffer.AsWritableSpan(0, bytesRead), tag);
                            current.countBytes += bytesRead;


                            if (contains)
                            {

                                if (response!.Value.isStreaming)
                                {


                                    if (OnResponseProgressRead != null)
                                    {
                                        double progress = 0;
                                        if (current.countBytes == current.request.DataLength) progress = 1;
                                        else progress = (double)current.countBytes / current.request.DataLength;
                                        _ = Task.Run(async () => await OnResponseProgressRead(progress, _frame.UniID, frameBuffer.AsMemory(0, bytesRead)));
                                    } 
                                    if (_frame.CurrentFrame == 1) { _ = Task.Run(() => response!.Value.answer.SetResult(new OSPResponse() { Data = null, Header = current.request, StatusCode = current.request.MessageStatus, OnlyStatusCode = true })); }
                                }
                                else
                                {
                                    current.data.Write(frameBuffer.AsSpan(0, bytesRead));
                                }
                            }
                            else MessageProgressRead((double)current.countBytes / current.request.DataLength, _frame.UniID);


                            frames[_frame.UniID] = current;


                            if (_frame.CurrentFrame == _frame.MaxFrame)
                            {

                                
                                
                                if (contains)
                                {
                                    if (!response!.Value.isStreaming)
                                    {
                                        _ = Task.Run(() => response!.Value.answer.SetResult(new OSPResponse() { Data = current.data, Header = current.request, StatusCode = current.request.MessageStatus, OnlyStatusCode = false }));
                                        _allRequests.TryRemove(header.UniID, out _);
                                    }

                                }
                                else
                                {

                                    if (OnMessageFullyRead != null) await OnMessageFullyRead(new OSPMessageEventArgs() { Header = current.request, Data = current.data });
                                    current.data.Dispose();
                                }

                                frames.Remove(_frame.UniID);

                            }

                        }
                    }
                    else if (base_header is OSPSystemHeader systemHeader)
                    {
                        if (systemHeader.Command == OSPConsts.PingAnswerCommand)
                        {
                            pingWatch.Stop();
                            if (pingWatch.ElapsedMilliseconds < int.MaxValue)
                            {
                                Ping = (uint)pingWatch.ElapsedMilliseconds;
                                
                            }
                           
                        }     
                        else if (systemHeader.Command == OSPConsts.HandshakeSettings)
                        {
                     
                            if (systemHeader.Data != null)
                            {

                                _scheduler.variables.SliceSize = BinaryPrimitives.ReadInt32LittleEndian(systemHeader.Data.Value.Span.Slice(0, 4));
                                _scheduler.variables.FrameSizeThreshold = BinaryPrimitives.ReadInt32LittleEndian(systemHeader.Data.Value.Span.Slice(4, 4));
                                ushort maxPackets = BinaryPrimitives.ReadUInt16LittleEndian(systemHeader.Data.Value.Span.Slice(8));
                                int recPing =  1000 / maxPackets + 50; // 50 - stable value
                                if (Settings.PingInvervalMilliseconds < recPing) pingTimer.Interval = recPing;
                            }
                        }
                        else if (systemHeader.Command == OSPConsts.CancelPacketCommand)
                        {
                         
                            if (systemHeader.Data != null)
                            {
                                var d = BinaryPrimitives.ReadUInt32LittleEndian(systemHeader.Data.Value.Span);

                                _scheduler.CancelPacket(d);

                                CancelledPackets[d] = 0;
                            }

                        }
                       

                    }



                }
                catch (Exception ex)
                {
                    ErrorOccured(ex);
                    IsConnected = false;
                    this.Dispose();
                    return;
                }
                finally
                {
                    _networkLock.Release();
                }
            }

        }



        private CancellationTokenSource source = new CancellationTokenSource();
        private Task _background = null!;
        public OSPClient(string ip, int port)
        {
            _socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            IPEndPoint = IPEndPoint.Parse(ip + ":" + port);
        }
        public OSPClient(IPAddress ip, int port)
        {
            _socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            IPEndPoint = new IPEndPoint(ip, port);
            
        }
        public OSPClient(IPEndPoint ip)
        {
            _socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            IPEndPoint = ip;
        }

        Dictionary<uint, (OSPHeaderRequest request, NativeBytes data, long countBytes)> frames = new();
        ConcurrentDictionary<uint, (TaskCompletionSource<OSPResponse> answer, bool isStreaming)> _allRequests = new();

        /// <summary>
        /// Используйте эту функцию для отправки данных удалённому серверу.
        /// </summary>
        /// <param name="data">Данные (полезная нагрузка), которые вы хотите отправить</param>
        /// <param name="description">Эта переменная универсальна, используете её на своё усмотрение. Она находится в заголовке запроса.</param>
        /// <param name="isStreaming">Включает/выключает стриминг данных. Если включено - ответ вернётся сразу при получении заголовка, но без данных. Сами данные будут идти в событие OnResponseProgressRead.</param>
        /// <returns>Дешифрованный ответ от сервера.</returns>
        public async Task<OSPResponse> Send(NativeBytes data, byte[]? description, bool isStreaming = false)
        {
            var tcs = new TaskCompletionSource<OSPResponse>();
            if (_socket == null) throw new OSPException("Соединение отсутствует или было сброшено.");
            if (data == null || data.Length == 0) throw new OSPException("Данные отсутствуют или их количество равно нулю.");
            uint id = _scheduler.SendToQueue(new OSPData(data), description, OSPStatusCode.None, OSPMessageType.RequestFromClient);

            _allRequests[id] = (tcs, isStreaming);

            return await tcs.Task;

        }
        /// <summary>
        /// Используйте эту функцию для отправки данных удалённому серверу.
        /// </summary>
        /// <param name="data">Данные (полезная нагрузка), которые вы хотите отправить</param>
        /// <param name="description">Эта переменная универсальна, используете её на своё усмотрение. Она находится в заголовке запроса.</param>
        /// <param name="isStreaming">Включает/выключает стриминг данных. Если включено - ответ вернётся сразу при получении заголовка, но без данных. Сами данные будут идти в событие OnResponseProgressRead.</param>
        /// <returns>Дешифрованный ответ от сервера.</returns>
        public async Task<OSPResponse> Send(Stream data, byte[]? description, bool isStreaming = false)
        {
            var tcs = new TaskCompletionSource<OSPResponse>();
            if (_socket == null) throw new OSPException("Соединение отсутствует или было сброшено.");
            if (data == null || data.Length == 0) throw new OSPException("Данные отсутствуют или их количество равно нулю.");
            uint id = _scheduler.SendToQueue(new OSPData(data), description, OSPStatusCode.None, OSPMessageType.RequestFromClient);

            _allRequests[id] = (tcs, isStreaming);

            return await tcs.Task;

        }

        /// <summary>
        /// Используйте эту функцию для отправки данных удалённому серверу.
        /// </summary>
        /// <param name="data">Данные (полезная нагрузка), которые вы хотите отправить</param>
        /// <param name="description">Эта переменная универсальна, используете её на своё усмотрение. Она находится в заголовке запроса.</param>
        /// <param name="isStreaming">Включает/выключает стриминг данных. Если включено - ответ вернётся сразу при получении заголовка, но без данных. Сами данные будут идти в событие OnResponseProgressRead.</param>
        /// <returns>Дешифрованный ответ от сервера.</returns>
        public async Task<OSPResponse> Send(byte[] data, byte[]? description, bool isStreaming = false)
        {
            var tcs = new TaskCompletionSource<OSPResponse>();
            if (_socket == null) throw new OSPException("Соединение отсутствует или было сброшено.");
            if (data == null || data.Length == 0) throw new OSPException("Данные отсутствуют или их количество равно нулю.");
            uint id = _scheduler.SendToQueue(new OSPData(data), description, OSPStatusCode.None, OSPMessageType.RequestFromClient);

            _allRequests[id] = (tcs, isStreaming);

            return await tcs.Task;

        }

        /// <summary>
        /// Используйте эту функцию для отправки данных удалённому серверу.
        /// </summary>
        /// <param name="data">Данные (полезная нагрузка), которые вы хотите отправить</param>
        /// <param name="description">Эта переменная универсальна, используете её на своё усмотрение. Она находится в заголовке запроса.</param>
        /// <param name="isStreaming">Включает/выключает стриминг данных. Если включено - ответ вернётся сразу при получении заголовка, но без данных. Сами данные будут идти в событие OnResponseProgressRead.</param>
        /// <returns>Дешифрованный ответ от сервера.</returns>
        public async Task<OSPResponse> Send(Memory<byte> data, byte[]? description, bool isStreaming = false)
        {
            var tcs = new TaskCompletionSource<OSPResponse>();
            if (_socket == null) throw new OSPException("Соединение отсутствует или было сброшено.");
            if (data.Length == 0) throw new OSPException("Данные отсутствуют или их количество равно нулю.");
            uint id = _scheduler.SendToQueue(new OSPData(data), description, OSPStatusCode.None, OSPMessageType.RequestFromClient);

            _allRequests[id] = (tcs, isStreaming);

            return await tcs.Task;

        }
        /// <summary>
        /// Используйте эту функцию для отправки данных удалённому серверу.
        /// </summary>
        /// <param name="data">Данные (полезная нагрузка), которые вы хотите отправить</param>
        /// <param name="description">Эта переменная универсальна, используете её на своё усмотрение. Она находится в заголовке запроса.</param>
        /// <param name="isStreaming">Включает/выключает стриминг данных. Если включено - ответ вернётся сразу при получении заголовка, но без данных. Сами данные будут идти в событие OnResponseProgressRead.</param>
        /// <returns>Дешифрованный ответ от сервера.</returns>
        public async Task<OSPResponse> Send(OSPData data, byte[]? description, bool isStreaming = false)
        {
            var tcs = new TaskCompletionSource<OSPResponse>();
            if (_socket == null) throw new OSPException("Соединение отсутствует или было сброшено.");
            if (data == null || data.Length == 0) throw new OSPException("Данные отсутствуют или их количество равно нулю.");
            uint id = _scheduler.SendToQueue(data, description, OSPStatusCode.None, OSPMessageType.RequestFromClient);

            _allRequests[id] = (tcs, isStreaming);

            return await tcs.Task;

        }



        List<System.Timers.Timer> TimersList = new();
       
        public void CancelPacket(uint messageID)
        {
            NativeBytes NId = new NativeBytes(4);
            BinaryPrimitives.WriteUInt32LittleEndian(NId.AsWritableSpan(), messageID);
            _scheduler.SendHighPacketToQueue(OSPConsts.CancelPacketCommand, NId);
            var _timer = GlobalTools.StartTimer(Settings.CancellationPacketTimeout, () =>
            {
                CancelledPackets[messageID] = 0;
                
            });
            lock (TimersList) TimersList.Add(_timer);


        }
        
        public void UpdateBitrateMbps(int EgressMbps, int IngressMbps)
        {
            _scheduler.UpdateBitrateMbps(EgressMbps, IngressMbps);
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
                try
                {
                    
                    source.Cancel();
                    _background.Wait(TimeSpan.FromSeconds(3));

                }
                catch { }
                finally
                {
                    foreach (var item in frames)
                    {
                        if (item.Value.data != null) item.Value.data.Dispose();
                    }
                    frames.Clear();
                    if (frameBuffer != null) frameBuffer.Dispose();

                    source.Dispose();
                    _socket.Close();
                    if (_socket != null) _socket.Close();
                    _scheduler.Dispose();
                    _allRequests.Clear();
                }

                



            }


            _disposed = true;
        }


        // New Message Event

        protected virtual void NewMessageSent(OSPHeaderRequest eventArgs)

        {
            NewMessageEvent? msg = OnNewMessage;
            if (msg != null)
            {
                msg(new OSPMessageEventArgs() { Header = eventArgs, Data = null });
            }
        }
        public delegate void NewMessageEvent(OSPMessageEventArgs args);

        /// <summary>
        /// Это событие происходит, когда заголовок полностью прочитывается. Не содержит тело запроса. (Только для неожиданных сообщений от сервера.)
        /// </summary>
        public event NewMessageEvent? OnNewMessage;


        // Message FullyRead

        public Func<OSPMessageEventArgs, Task>? OnMessageFullyRead = null;




        // Message Reading Progress



        protected virtual void MessageProgressRead(double progress, uint ID)
        {
            MessageProgressReadEvent? msg = OnMessageProgressRead;
            if (msg != null)
            {
                msg(progress, ID);
            }
        }
        public delegate void MessageProgressReadEvent(double progress, uint ID);
        /// <summary>
        /// Это событие происходит при обновлении прогресса. (Только для неожиданных сообщений от сервера.)
        /// </summary>

        public event MessageProgressReadEvent? OnMessageProgressRead;


        /// <summary>
        /// Это событие происходит, когда прогресс запроса обновляется. Может содержать данные. 
        /// </summary>
        public Func<double, uint, ReadOnlyMemory<byte>?, Task>? OnResponseProgressRead = null;

        protected virtual void ErrorOccured(Exception ex)
        {
            ErrorOccuredEvent? msg = OnErrorOccured;
            if (msg != null)
            {
                msg(ex);
            }
        }

        public delegate void ErrorOccuredEvent(Exception ex);

        /// <summary>
        /// Это событие происходит при возникновении какой-либо ошибки. (Чаще всего соединение будет сброшено)
        /// </summary>

        public event ErrorOccuredEvent? OnErrorOccured;




    }
}
