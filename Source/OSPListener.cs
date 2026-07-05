using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;


namespace Orange.Security.Protocol
{
    internal class OSPListener : IDisposable
    {
        private readonly Socket client;

        private Tools Tools = new Tools(false);

        private OSPServer _server;

        private IPEndPoint _ip = null!;

        private OSPStream _scheduler;


        private CancellationTokenSource _token = new CancellationTokenSource();
        internal OSPListener(OSPServer server, Socket socket)
        {

            _server = server;
            client = socket;
            Tools._ecndhe = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            client.NoDelay = true;
            client.SendBufferSize = _server.Settings.SendBufferSize;
            client.ReceiveBufferSize = _server.Settings.ReceiveBufferSize;


            _scheduler = new OSPStream(socket, Tools, _server.Settings, false);
            _scheduler.OnError += (ex) => _server.ErrorOccured(_ip, ex);
            pingPacketsCounter.Elapsed += PingPacketsCounter_Elapsed;
            pingPacketsCounter.AutoReset = true;
            _ = Task.Run(() => ClientConnection(_token.Token));
        }

    

        private void PingPacketsCounter_Elapsed(object? sender, System.Timers.ElapsedEventArgs e)
        {
            currentPingPacketsSent = 0;
        }

        private ConcurrentDictionary<uint, (OSPHeaderRequest request, NativeBytes data, long read)> frames = new();





        private NativeBytes frameBuffer = null!;

        private System.Timers.Timer pingPacketsCounter = new System.Timers.Timer(1000);

        private int currentPingPacketsSent = 0;



        private ConcurrentDictionary<uint, byte> CancelledPackets = new ConcurrentDictionary<uint, byte>();


        private async Task ClientConnection(CancellationToken token)
        {
            try
            {
                
                if (client.RemoteEndPoint != null) _ip = (IPEndPoint)client.RemoteEndPoint;
                else _ip = IPEndPoint.Parse("0.0.0.0:1");

                bool success = false;
                if (_server.masterKey == null) success = await _scheduler.Handshake(false);
                else success = await _scheduler.Handshake(false, _server.masterKey);

                if (success) _server.NewClientConnected(_ip);
                else throw new OSPException("Неудача в установки безопасного соединения с клиентом.");

                _scheduler.HandshakeSettings();
            }
            catch (Exception ex)
            {
                _server.ErrorOccured(_ip, ex);
                this.Dispose();
            }
            try
            {
                while (!token.IsCancellationRequested)
                {
                    pingPacketsCounter.Start();





                    OSPBaseHeader base_header = await _scheduler.ReadHeader(_ip is null ? IPEndPoint.Parse("0.0.0.0:1") : _ip);

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
                        if (header.MessageType == OSPMessageType.AnswerFromServer || header.MessageType == OSPMessageType.RequestFromServer || header.MessageType == OSPMessageType.FrameFromServer) throw new OSPException("Неверный тип пакета.");

                        if (header is OSPHeaderRequest request)
                        {
                            if (request.IsFramed)
                            {
                                if (frameBuffer == null) frameBuffer = new NativeBytes(_scheduler.variables.SliceSize);


                                if (request.DataLength > _server.Settings.MaxReceiveDataLength) throw new OSPException("Превышена длина полезной нагрузки.");
                                _server.NewMessageSent(request);
                                if (_server.Settings.DataStreaming)
                                {
                                    frames[request.UniID] = (request, null!, 0);
                                    OSPMessageEventArgs args = new OSPMessageEventArgs()
                                    {
                                        Data = null,
                                        Header = request

                                    };


                                }
                                else frames[request.UniID] = (request, new NativeBytes((long)request.DataLength), 0);

                                continue;

                            }
                        }

                        NativeBytes nTag = new NativeBytes(16);
                        Memory<byte> tag = nTag.AsMemory();

                        await _scheduler.ReceiveExactlyAsync(tag);

                        if (header is OSPHeaderRequest requestHeader)
                        {



                            _server.NewMessageSent(requestHeader);



                            var sw = Stopwatch.StartNew();

                            NativeBytes obj = await _scheduler.ReadBodyFragment((int)requestHeader.DataLength);

                            sw.Stop();

                            await _scheduler.IngressThrottling(sw.Elapsed.Milliseconds, (int)obj.Length);


                            Tools.Decrypt(obj.AsWritableSpan(), tag.Span);

                            OSPMessageEventArgs args = new OSPMessageEventArgs()
                            {
                                Data = obj,
                                Header = requestHeader,

                            };

                            if (_server.messageHandler != null)
                            {
                                OSPServerAnswer dataAnswer = await _server.messageHandler.Invoke(args);



                                _scheduler.SendToQueue(dataAnswer.Data, dataAnswer.HeaderDescription, dataAnswer.Code, OSPMessageType.AnswerFromServer, args.Header.UniID);


                            }

                        }
                        else if (header is OSPHeaderFrame _frame)
                        {


                            var current = frames[_frame.UniID];

                            Stopwatch sw = Stopwatch.StartNew();
                            int bytesRead = await _scheduler.ReadFrame((long)current.request.DataLength, _frame.CurrentFrame, frameBuffer);

                            sw.Stop();

                            await _scheduler.IngressThrottling(sw.Elapsed.Milliseconds, bytesRead);





                            Tools.Decrypt(frameBuffer.AsWritableSpan(0, bytesRead), tag.Span);



                            if (!_server.Settings.DataStreaming) current.data.Write(frameBuffer.AsSpan(0, bytesRead));

                            current.read += bytesRead;

                            frames[_frame.UniID] = current;
                            if (_server.frameHandler != null)
                            {
                                try
                                {
                                    await _server.frameHandler.Invoke(frameBuffer.AsMemory(0, bytesRead), current.request, (double)current.read / current.request.DataLength);
                                }
                                catch (Exception ex)
                                {
                                    _server.ErrorOccured(_ip!, ex);
                                }


                            }
                            if (_frame.CurrentFrame == _frame.MaxFrame)
                            {
                                frameBuffer.Dispose();
                                frameBuffer = null!;

                                OSPMessageEventArgs args = new OSPMessageEventArgs()
                                {
                                    Data = current.data,
                                    Header = current.request

                                };

                                try
                                {

                                    OSPServerAnswer dataAnswer = await _server.messageHandler!.Invoke(args);
                                    _scheduler.SendToQueue(dataAnswer.Data, dataAnswer.HeaderDescription, dataAnswer.Code, OSPMessageType.AnswerFromServer, args.Header.UniID);

                                }
                                catch (Exception ex) { _server.ErrorOccured(_ip!, ex); }
                                finally
                                {

                                    if (current.data != null) current.data.Dispose();
                                    frames.TryRemove(_frame.UniID, out _);
                                }


                            }



                        }

                        nTag.Dispose();

                    }
                    else if (base_header is OSPSystemHeader systemHeader)
                    {
                       
                        if (systemHeader.Command == OSPConsts.PingCommand)
                        {
                            currentPingPacketsSent++;
                            if (currentPingPacketsSent > _server.Settings.MaxPingPacketsPerSecond) throw new OSPException("Количество пинг-пакетов превысило допустимый порог.");
                            else _scheduler.SendHighPacketToQueue(OSPConsts.PingAnswerCommand, null);
                        }
                        else if (systemHeader.Command == OSPConsts.CancelPacketCommand)
                        {
                         

                            if (systemHeader.Data != null)
                            {
                              
                                var packetID = BinaryPrimitives.ReadUInt32LittleEndian(systemHeader.Data.Value.Span);

                                _scheduler.CancelPacket(packetID);
                               
                            }

                        }
                    }



                }
            }
            catch (Exception ex)
            {
                _server.ErrorOccured(_ip, ex);
                _server.ClientDisconnected(_ip);
                this.Dispose();
            }







        }



        public void SendMessage(OSPData data, byte[]? description) => _scheduler.SendToQueue(data, description, OSPStatusCode.None, OSPMessageType.RequestFromServer);

        public void UpdateBitrate(int Egress, int Ingress) => _scheduler.UpdateBitrateMbps(Egress, Ingress);



        private List<System.Timers.Timer> TimersList = new();
        public void CancelPacket(uint id)
        {
            NativeBytes NId = new NativeBytes(4);
            BinaryPrimitives.WriteUInt32LittleEndian(NId.AsWritableSpan(), id);
            _scheduler.SendHighPacketToQueue(OSPConsts.CancelPacketCommand, NId);
            var _timer = GlobalTools.StartTimer(_server.Settings.CancellationPacketTimeout, () =>
            {
                CancelledPackets[id] = 0;

            });
            lock (TimersList) TimersList.Add(_timer);
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
        private bool _disposed = false;
        protected virtual void Dispose(bool disposing)
        {
            if (_disposed) return;
            if (disposing)
            {

                client.Dispose();
                _scheduler.Dispose();
                _token.Cancel();

            }
            _disposed = true;
        }








    }
}
