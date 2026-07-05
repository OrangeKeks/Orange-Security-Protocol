using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Timers;

namespace Orange.Security.Protocol
{

    internal struct OSPStreamVariables
    {
        internal OSPStreamVariables(OSPSegment sliceInterval, OSPSegment segmentInter)
        {
            sliceHandshakeInterval = sliceInterval;
            segmentInterval = segmentInter;
        }


        public int TimeoutSending = 5;

        public int TimeoutReceiving = 30;

        public int FrameSizeThreshold = (8192 * 4) * 2;

        public int SliceSize = 8192 * 4;

        public int MaxHeaderLength;

        public double EgressMbps = 0;

        public double IngressMbps = 0;

        public OSPSegment sliceHandshakeInterval;

        public OSPSegment segmentInterval;

        public short PacketsPerSecond = 1;
    }


    internal class OSPPacketContext
    {
        public OSPPriority Priority { get; set; }
        public OSPData? Data { get; set; }
        public OSPHeaderRequest Request { get; set; } = null!;
        public long CurrentChunkSize { get; set; }
        public bool RequestSend { get; set; }
    }


    internal class OSPStream : IDisposable
    {
        private Socket network;

        private Tools tools;

     
        private void Timer_Elapsed(object? sender, ElapsedEventArgs e)
        {
            Dispose(true);


            throw new OSPException("Превышено время ожидания. Соединение разорвано.");

        }

        internal uint OutgoingNum = 0;
        internal uint IncomingNum = 0;

        private readonly CancellationTokenSource _cts = new CancellationTokenSource();



        


        public void UpdateBitrateMbps(int EgressBitrateMbps, int IngressBitrateMbps)
        {
            variables.EgressMbps = EgressBitrateMbps;
            variables.IngressMbps = IngressBitrateMbps;
        }


        public event Action<Exception>? OnError;
        internal OSPStream(Socket ns, Tools _tools, OSPSettings _settings, bool isClient)
        {
            variables = new OSPStreamVariables(_settings.HandshakeSegmentSize, _settings.HandshakeSegmentInterval);


            if (!isClient)
            {
                var settings = (OSPServerSettings)_settings;
                
                variables.SliceSize = settings.FrameSize;
                variables.FrameSizeThreshold = settings.FramingThreshold;
                variables.PacketsPerSecond = settings.MaxPingPacketsPerSecond;
            }
            variables.TimeoutReceiving = _settings.InactiveReceiveTimeoutSeconds;
            variables.TimeoutSending = _settings.InactiveSendingTimeoutSeconds;
            variables.MaxHeaderLength = _settings.MaxReceiveHeaderLength;
            variables.EgressMbps = _settings.DefaultEgressBitrateMbps;
            variables.IngressMbps = _settings.DefaultIngressBitrateMbps;

            



            
            tools = _tools;
            network = ns;

            if (isClient)
            {
                maxValue = uint.MaxValue / 2;
                minValue = 0;
            }
            else
            {
                maxValue = uint.MaxValue;
                minValue = uint.MaxValue / 2;
            }

            _sender = Task.Run(async () => await Sender(_cts.Token));
        }




        public OSPStreamVariables variables; // settings


        public ConcurrentDictionary<uint, OSPPacketContext> Packets = new();
        private readonly ConcurrentQueue<uint> _rrQueue = new();


        private object highLocker = new object(); // locker for HighPriorityPackets
        public List<(byte command, NativeBytes? data)> HighPriorityPackets = new();



        private SemaphoreSlim _signal = new SemaphoreSlim(0);


        private Task _sender = null!;


        private NativeBytes frameDataBuffer = null!;

        private Stopwatch sw = new Stopwatch(); // speed throttling;
        private async Task Sender(CancellationToken _cts)
        {

            Memory<byte> dataTag = new Memory<byte>(new byte[16]);
             
            while (!_cts.IsCancellationRequested)
            {
            
                try
                {
                 
                    await _signal.WaitAsync();
                 
                    lock (ToCancel)
                    {
                        for (int i = ToCancel.Count - 1; i >= 0; i--)
                        {
                            uint id = ToCancel[i];
                            if (Packets.ContainsKey(id))
                            {
                                
                                var _poc = Packets[id];
                                _poc.Data?.ClearSource();
                                _poc.Data?.Dispose();

                                Packets.TryRemove(id, out _);

                                ToCancel.RemoveAt(i);

                            }
                        }
                       
                    }


                    (byte command, NativeBytes? data)? com = null;
                    lock (highLocker) if (HighPriorityPackets.Count > 0) com = HighPriorityPackets.FirstOrDefault();
                    if (com != null)
                    {


                        var data = GlobalTools.MakeSystemHeaderWith(OutgoingNum, com.Value.command, com.Value.data, tools);

                        await SendData(data.AsMemory());
                        data.Dispose();

                        com.Value.data?.Dispose();

                        lock (highLocker) HighPriorityPackets.Remove(com.Value);
                        OutgoingNum++;
                    }


                    if (!_rrQueue.TryDequeue(out uint targetKey))
                        continue;
                    if (!Packets.TryGetValue(targetKey, out var pocket))
                        continue;


                    if (pocket.Priority == OSPPriority.High)
                    {
                        
                        var header = GlobalTools.MakeHeaderRequestWithData(pocket.Request.Description, pocket.Request.MessageStatus, OutgoingNum, pocket.Request.MessageType, tools, null, false, targetKey);
                        await SendData(header.AsMemory());

                        header.Dispose();

                        OutgoingNum++;

                        Packets.TryRemove(targetKey, out _);


                        
                        
                    }
                    else if (pocket.Priority == OSPPriority.Medium)
                    {



                        var current = pocket.Data!.AsMemory();
                        var header = GlobalTools.MakeHeaderRequestWithData(pocket.Request.Description, pocket.Request.MessageStatus, OutgoingNum, pocket.Request.MessageType, tools, current, false, targetKey);

                 

                        await SendData(header.AsMemory(), false, (int)current.Length);
         
                        
                        header.Dispose();

                        pocket.Data.ClearSource();
                        pocket.Data.Dispose();


                        OutgoingNum++;

                        Packets.TryRemove(targetKey, out _);


                        _signal.Release();
                    }
                    else if (pocket.Priority == OSPPriority.Low)
                    {
                        if (frameDataBuffer == null) frameDataBuffer = new NativeBytes(variables.SliceSize + 54 + 16); // 54 - frame header, 16 - tag size

                        int toSend = (int)Math.Min(variables.SliceSize, pocket.Data!.Length - pocket.CurrentChunkSize);

                        if (toSend <= 0)
                        {
                            pocket.Data.ClearSource();
                            pocket.Data.Dispose();
                            Packets.TryRemove(targetKey, out _);
                            continue;
                        }


                        if (!pocket.RequestSend)
                        {

                            NativeBytes _header = GlobalTools.MakeHeaderRequestWithData(pocket.Request.Description, pocket.Request.MessageStatus, OutgoingNum, pocket.Request.MessageType, tools, null, true, targetKey, pocket.Data.Length);

                            await SendData(_header.AsMemory());

                            _header.Dispose();
                            OutgoingNum++;
                            pocket.RequestSend = true;
                        }


                        var chunk = pocket.Data.AsMemory(pocket.CurrentChunkSize, toSend);
                        int max = (int)((pocket.Data.Length + variables.SliceSize - 1) / variables.SliceSize);

                        int currentFrame = (int)(pocket.CurrentChunkSize / variables.SliceSize) + 1;

                        //using NativeBytes frameBuffer = new NativeBytes(chunk.Length + 54 + 16); 
                        GlobalTools.MakeHeaderFrame(OutgoingNum, TypeForFrame(pocket.Request.MessageType), tools, max, currentFrame, targetKey, frameDataBuffer);

                        tools.Encrypt(chunk.Span, dataTag.Span);




                      
                        
                        dataTag.Span.CopyTo(frameDataBuffer.AsWritableSpan().Slice(54));

                        
                        chunk.Span.CopyTo(frameDataBuffer.AsWritableSpan().Slice(54 + 16));


                      

                        await SendData(frameDataBuffer.AsMemory(0, chunk.Length + 54 + 16), false, chunk.Length);



                    


                        OutgoingNum++;



                        pocket.CurrentChunkSize += toSend;


                        

                        if (pocket.CurrentChunkSize >= pocket.Data.Length)
                        {
                            frameDataBuffer.Dispose();
                            frameDataBuffer = null!;
                            pocket.Data.ClearSource();
                            pocket.Data.Dispose();
                            Packets.TryRemove(targetKey, out _);
                        }
                        else
                        {


                            _rrQueue.Enqueue(targetKey);
                            _signal.Release();
                        }




                    }


                }
                catch (Exception ex)
                {
                    OnError?.Invoke(ex);
                    this.Dispose();
                    throw;
                }
            }
        }


        // Receiving

        public async ValueTask ReceiveExactlyAsync(Memory<byte> buffer)
        {
            int totalRead = 0;


            while (totalRead < buffer.Length)
            {

                using (var timeToken = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token))
                {
                    timeToken.CancelAfter(TimeSpan.FromSeconds(variables.TimeoutReceiving));
                    try
                    {
                        int received = await network.ReceiveAsync(buffer.Slice(totalRead), SocketFlags.None, timeToken.Token);

                        if (received == 0) throw new SocketException((int)SocketError.ConnectionReset);

                        totalRead += received;
                    }
                    catch (OperationCanceledException) when (timeToken.IsCancellationRequested)
                    {
                        OnError?.Invoke(new OSPException("Превышено время ожидания для получения данных."));
                        throw;
                    }
                    catch (Exception ex) { OnError?.Invoke(ex); throw; }
                    
                }
            }
        }

        public async ValueTask<NativeBytes> ReadBodyFragment(int bodyLength)
        {
            NativeBytes b = new NativeBytes(bodyLength);

            await ReceiveExactlyAsync(b.AsMemory());


            return b;

        }

        public async ValueTask<NativeBytes> ReadFrame(long allBodyLength, int currentFrame)
        {
            long offset = (long)(currentFrame - 1) * variables.SliceSize;

            int toRead = (int)Math.Min(variables.SliceSize, allBodyLength - offset);

            NativeBytes b = new NativeBytes(toRead);
            await ReceiveExactlyAsync(b.AsMemory());

            return b;


        }

        public async ValueTask<int> ReadFrame(long allBodyLength, int currentFrame, NativeBytes frameBuffer)
        {
            long offset = (long)(currentFrame - 1) * variables.SliceSize;

            int toRead = (int)Math.Min(variables.SliceSize, allBodyLength - offset);


            await ReceiveExactlyAsync(frameBuffer.AsMemory().Slice(0, toRead));

            return toRead;



        }

        public async ValueTask<OSPBaseHeader> ReadHeader(IPEndPoint ip)
        {
            OSPBaseHeader _base = null!;


        

            using NativeBytes first = new NativeBytes(16 + 5);

            Memory<byte> lengthAndType = first.AsMemory();
            await ReceiveExactlyAsync(lengthAndType);
            tools.Decrypt(lengthAndType.Span.Slice(16, 5), lengthAndType.Span.Slice(0, 16));
            byte type = lengthAndType.Span[20];

            uint len = BitConverter.ToUInt32(lengthAndType.Slice(16, 4).Span);
            if (len > variables.MaxHeaderLength)
            {
                this.Dispose();
                throw new OSPException("Длина заголовка превысила порог.");
            }

           
            first.Dispose();

            using NativeBytes header = new NativeBytes(len + 16);
            Memory<byte> headerMem = header.AsMemory();

            await ReceiveExactlyAsync(headerMem);






            tools.Decrypt(headerMem.Span.Slice(16), headerMem.Span.Slice(0, 16));

            Span<byte> enHeader = headerMem.Span.Slice(16);
            switch (type)
            {
                case 0x00: // Frame Header
                    {

                        OSPHeaderFrame frame = GlobalTools.MakeFrameFromResponse(enHeader);

                        if (frame.NumericID < IncomingNum) throw new OSPException("Повтор пакета.");
                        else IncomingNum++;

                        _base = frame;

                        break;
                    }
                case 0x01: // Request Header
                    {

                        OSPHeaderRequest request = GlobalTools.MakeRequestFromResponse(headerMem.Slice(16), ip);

                        if (request.NumericID < IncomingNum) throw new OSPException("Повтор пакета.");
                        else IncomingNum++;

                        _base = request;

                        break;

                    }
                case 0x02: // System Header
                    {


                        OSPSystemHeader system = GlobalTools.MakeSystemHeader(headerMem.Slice(16));

                        if (system.NumericID < IncomingNum) throw new OSPException("Повтор пакета.");
                        else IncomingNum++;

                        _base = system;

                        break;
                    }
                default: // ???
                    {
                        this.Dispose();
                        throw new NotImplementedException();
                    }
            }



            header.Dispose();
            return _base;






        }


        public OSPMessageType TypeForFrame(OSPMessageType type)
        {

            if (type == OSPMessageType.AnswerFromServer || type == OSPMessageType.RequestFromServer) return OSPMessageType.FrameFromServer;
            else if (type == OSPMessageType.RequestFromClient) return OSPMessageType.RequestFromClient;
            else return type;
        }

       


        // Sending

        public async ValueTask SendData(Memory<byte> Data, bool IgnoreEgress = true, int EgressLength = 0)
        {
            
            using (var linked = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token))
            {
                linked.CancelAfter(TimeSpan.FromSeconds(variables.TimeoutSending));
                try
                {
                    if (!IgnoreEgress) sw.Restart();

                    await network.SendAsync(Data, linked.Token);

                    if (!IgnoreEgress)
                    {
                        sw.Stop();
                        await EgressThrottling(sw.Elapsed.TotalMilliseconds, EgressLength);
                    } 

                    
                }
                catch (OperationCanceledException) when (linked.IsCancellationRequested)
                {
                   
                    OnError?.Invoke(new OSPException("Превышено время ожидания для отправки."));
                    throw;
                }
                catch (Exception ex)
                {
                    OnError?.Invoke(ex);
                    throw;
                }
                
            }
        }

        public async ValueTask SendViaSegments(Memory<byte> data)
        {
            int sentCount = 0;
            while (sentCount != data.Length)
            {

                int sliceSize = Random.Shared.Next(variables.sliceHandshakeInterval.Min, variables.sliceHandshakeInterval.Max + 1);

                int finalSize = Math.Min(sliceSize, data.Length - sentCount);


                int delayMS = Random.Shared.Next(variables.segmentInterval.Min, variables.segmentInterval.Max + 1);

                await SendData(data.Slice(sentCount, finalSize));

                await Task.Delay(delayMS);

                sentCount += finalSize;
            }
        }



        private (HashAlgorithmName hash, int lengthKey, int signLength) GetCorrect(int size)
        {
            switch (size)
            {
                case 256:
                    {
                        return (HashAlgorithmName.SHA256, 91, 64);
                    }
                case 384:
                    {
                        return (HashAlgorithmName.SHA384, 120, 96);
                    }
                case 521:
                    {
                        return (HashAlgorithmName.SHA512, 158, 132);
                    }
                default:
                    {
                        return (HashAlgorithmName.SHA256, 91, 64);
                    }
            }
        }



        private static readonly MLKemParameters MlKemParams = MLKemParameters.ml_kem_768;

        private static readonly int MlKemPubKeyLen = 1184;
        private static readonly int MlKemCipherTextLen = 1088;


        // mlkem-768, ecdh
        public async ValueTask<bool> Handshake(bool isClient, byte[] keyB)
        {
            var classicKeyLen = GetCorrect(tools._ecndhe.KeySize).lengthKey;

            if (isClient)
            {
                byte padding = (byte)Random.Shared.Next(16, 256);
                using NativeBytes rndNonce = new NativeBytes(1 + 16);
                rndNonce.AsWritableSpan()[0] = padding;
                RandomNumberGenerator.Fill(rndNonce.AsWritableSpan().Slice(1));
                await SendViaSegments(rndNonce.AsMemory());
              

                using ECDsa ecdServer = ECDsa.Create();
                ecdServer.ImportSubjectPublicKeyInfo(keyB, out _);
                var obj = GetCorrect(ecdServer.KeySize);

              


                int serverPacketLen = classicKeyLen + MlKemPubKeyLen + obj.signLength + padding;
                using NativeBytes result = new NativeBytes(serverPacketLen);
                await ReceiveExactlyAsync(result.AsMemory());


                var serverEcdhSpan = result.AsSpan(0, classicKeyLen);
                var serverMlKemSpan = result.AsSpan(classicKeyLen, MlKemPubKeyLen);

                using NativeBytes signData = new NativeBytes(classicKeyLen + MlKemPubKeyLen + 16);
                serverEcdhSpan.CopyTo(signData.AsWritableSpan());
                serverMlKemSpan.CopyTo(signData.AsWritableSpan().Slice(classicKeyLen));
                rndNonce.AsSpan(1, 16).CopyTo(signData.AsWritableSpan().Slice(classicKeyLen + MlKemPubKeyLen));

                int signOffset = classicKeyLen + MlKemPubKeyLen;
                if (!ecdServer.VerifyData(signData.AsSpan(), result.AsSpan(signOffset, obj.signLength), obj.hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
                    return false;


                Span<byte> ecdhSecret = stackalloc byte[obj.lengthKey];
                using (var otherEcdh = ECDiffieHellman.Create())
                {
                    otherEcdh.ImportSubjectPublicKeyInfo(serverEcdhSpan, out _);
                    ecdhSecret = tools._ecndhe.DeriveRawSecretAgreement(otherEcdh.PublicKey);
                }


                var peerMlKemPub = MLKemPublicKeyParameters.FromEncoding(MlKemParams, serverMlKemSpan.ToArray());
                var encapsulator = new MLKemEncapsulator(MlKemParams);
                encapsulator.Init(peerMlKemPub);

                Span<byte> mlKemCipherText = stackalloc byte[MlKemCipherTextLen];
                Span<byte> mlKemSecret = stackalloc byte[encapsulator.SecretLength];

                encapsulator.Encapsulate(mlKemCipherText, mlKemSecret);

                tools.Key = DeriveHybridKey(ecdhSecret, mlKemSecret, rndNonce.AsSpan().Slice(1));


                int clientPacketLen = classicKeyLen + MlKemCipherTextLen + padding;
                using NativeBytes clientKeyPkg = new NativeBytes(clientPacketLen);
                var clientPkgSpan = clientKeyPkg.AsWritableSpan();

                tools._ecndhe.TryExportSubjectPublicKeyInfo(clientPkgSpan.Slice(0, classicKeyLen), out _);
                mlKemCipherText.CopyTo(clientPkgSpan.Slice(classicKeyLen, MlKemCipherTextLen));
                RandomNumberGenerator.Fill(clientPkgSpan.Slice(classicKeyLen + MlKemCipherTextLen));


                // cleaning
                CryptographicOperations.ZeroMemory(ecdhSecret);
                CryptographicOperations.ZeroMemory(mlKemSecret);

                await SendViaSegments(clientKeyPkg.AsMemory());

             


                


          


                return true;
            }
            else
            {
                using ECDsa ecdsaSigner = ECDsa.Create();
                ecdsaSigner.ImportPkcs8PrivateKey(keyB, out _);
                var obj = GetCorrect(ecdsaSigner.KeySize);

                using NativeBytes rndNonce = new NativeBytes(1 + 16);

                await ReceiveExactlyAsync(rndNonce.AsMemory());
                byte padding = rndNonce.AsSpan()[0];

                


                var mlKemKeyGen = new MLKemKeyPairGenerator();
                mlKemKeyGen.Init(new MLKemKeyGenerationParameters(new SecureRandom(), MlKemParams));
                var mlKemPair = mlKemKeyGen.GenerateKeyPair();
                var mlKemPrivKey = (MLKemPrivateKeyParameters)mlKemPair.Private;
                var mlKemPubKey = (MLKemPublicKeyParameters)mlKemPair.Public;
                Span<byte> localMlKemPubKeyBytes = stackalloc byte[MlKemPubKeyLen];
                localMlKemPubKeyBytes = mlKemPubKey.GetEncoded();


                int serverPacketLen = classicKeyLen + MlKemPubKeyLen + obj.signLength + padding;
                using NativeBytes result = new NativeBytes(serverPacketLen);
                var resSpan = result.AsWritableSpan();


                tools._ecndhe.TryExportSubjectPublicKeyInfo(resSpan.Slice(0, classicKeyLen), out _);
                localMlKemPubKeyBytes.CopyTo(resSpan.Slice(classicKeyLen, MlKemPubKeyLen));


                using NativeBytes dataToSignNative = new NativeBytes(classicKeyLen + MlKemPubKeyLen + 16);
                Span<byte> dataToSign = dataToSignNative.AsWritableSpan();
                resSpan.Slice(0, classicKeyLen).CopyTo(dataToSign);
                resSpan.Slice(classicKeyLen, MlKemPubKeyLen).CopyTo(dataToSign.Slice(classicKeyLen));
                rndNonce.AsSpan(1, 16).CopyTo(dataToSign.Slice(classicKeyLen + MlKemPubKeyLen));

                int signOffset = classicKeyLen + MlKemPubKeyLen;
                var signSpan = resSpan.Slice(signOffset, obj.signLength);
                ecdsaSigner.TrySignData(dataToSign, signSpan, obj.hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation, out _);


                RandomNumberGenerator.Fill(resSpan.Slice(signOffset + obj.signLength));

                //await network.SendAsync(result.AsMemory());
                await SendViaSegments(result.AsMemory());

                int clientPacketLen = classicKeyLen + MlKemCipherTextLen + padding;
                using NativeBytes clientKeyPkg = new NativeBytes(clientPacketLen);
                await ReceiveExactlyAsync(clientKeyPkg.AsMemory());

                var clientEcdhSpan = clientKeyPkg.AsSpan(0, classicKeyLen);
                var clientMlKemCipherSpan = clientKeyPkg.AsSpan(classicKeyLen, MlKemCipherTextLen);


                Span<byte> ecdhSecret = stackalloc byte[obj.lengthKey];
                using (var otherEcdh = ECDiffieHellman.Create())
                {
                    otherEcdh.ImportSubjectPublicKeyInfo(clientEcdhSpan, out _);
                    ecdhSecret = tools._ecndhe.DeriveRawSecretAgreement(otherEcdh.PublicKey);
                }


                var decapsulator = new MLKemDecapsulator(MlKemParams);
                decapsulator.Init(mlKemPrivKey);
                Span<byte> mlKemSecret = stackalloc byte[decapsulator.SecretLength];

                decapsulator.Decapsulate(clientMlKemCipherSpan, mlKemSecret);

                tools.Key = DeriveHybridKey(ecdhSecret, mlKemSecret, rndNonce.AsSpan().Slice(1));


                // cleaning
                CryptographicOperations.ZeroMemory(ecdhSecret);
                CryptographicOperations.ZeroMemory(mlKemSecret);

                return true;
            }
        }


        // without sign
        public async ValueTask<bool> Handshake(bool isClient)
        {
            var classicKeyLen = GetCorrect(tools._ecndhe.KeySize).lengthKey;

            if (isClient)
            {

                byte padding = (byte)Random.Shared.Next(16, 256);
                using NativeBytes rndNonce = new NativeBytes(1 + 16);
                rndNonce.AsWritableSpan()[0] = padding;
                
                RandomNumberGenerator.Fill(rndNonce.AsWritableSpan().Slice(1));
                
                //await network.SendAsync(rndNonce.AsMemory());

                await SendViaSegments(rndNonce.AsMemory());
               


                int serverPacketLen = classicKeyLen + MlKemPubKeyLen + padding;

                using NativeBytes result = new NativeBytes(serverPacketLen);
                await ReceiveExactlyAsync(result.AsMemory());

                var serverEcdhSpan = result.AsSpan(0, classicKeyLen);
                var serverMlKemSpan = result.AsSpan(classicKeyLen, MlKemPubKeyLen);


                Span<byte> ecdhSecret = stackalloc byte[classicKeyLen];
                using (var otherEcdh = ECDiffieHellman.Create())
                {
                    otherEcdh.ImportSubjectPublicKeyInfo(serverEcdhSpan, out _);
                    ecdhSecret = tools._ecndhe.DeriveRawSecretAgreement(otherEcdh.PublicKey);
                }

                var peerMlKemPub = MLKemPublicKeyParameters.FromEncoding(MlKemParams, serverMlKemSpan.ToArray());
                var encapsulator = new MLKemEncapsulator(MlKemParams);
                encapsulator.Init(peerMlKemPub);

                Span<byte> mlKemCipherText = stackalloc byte[MlKemCipherTextLen];
                Span<byte> mlKemSecret = stackalloc byte[encapsulator.SecretLength];
                encapsulator.Encapsulate(mlKemCipherText, mlKemSecret);


                tools.Key = DeriveHybridKey(ecdhSecret, mlKemSecret, rndNonce.AsSpan().Slice(1));


                int clientPacketLen = classicKeyLen + MlKemCipherTextLen + padding;
                using NativeBytes clientKeyPkg = new NativeBytes(clientPacketLen);
                var clientPkgSpan = clientKeyPkg.AsWritableSpan();

                tools._ecndhe.TryExportSubjectPublicKeyInfo(clientPkgSpan.Slice(0, classicKeyLen), out _);
                mlKemCipherText.CopyTo(clientPkgSpan.Slice(classicKeyLen, MlKemCipherTextLen));
                RandomNumberGenerator.Fill(clientPkgSpan.Slice(classicKeyLen + MlKemCipherTextLen));


                CryptographicOperations.ZeroMemory(ecdhSecret);
                CryptographicOperations.ZeroMemory(mlKemSecret);

                //await network.SendAsync(clientKeyPkg.AsMemory());
                await SendViaSegments(clientKeyPkg.AsMemory());
            

                return true;
            }
            else
            {

                using NativeBytes rndNonce = new NativeBytes(1 + 16);
                await ReceiveExactlyAsync(rndNonce.AsMemory());
                byte padding = rndNonce.AsSpan()[0];

                
            
                
                var mlKemKeyGen = new MLKemKeyPairGenerator();
                mlKemKeyGen.Init(new MLKemKeyGenerationParameters(new SecureRandom(), MlKemParams));
                var mlKemPair = mlKemKeyGen.GenerateKeyPair();
                var mlKemPrivKey = (MLKemPrivateKeyParameters)mlKemPair.Private;
                var mlKemPubKey = (MLKemPublicKeyParameters)mlKemPair.Public;

                Span<byte> localMlKemPubKeyBytes = stackalloc byte[MlKemPubKeyLen];
                localMlKemPubKeyBytes = mlKemPubKey.GetEncoded();


                int serverPacketLen = classicKeyLen + MlKemPubKeyLen + padding;
                using NativeBytes result = new NativeBytes(serverPacketLen);
                var resSpan = result.AsWritableSpan();

                tools._ecndhe.TryExportSubjectPublicKeyInfo(resSpan.Slice(0, classicKeyLen), out _);
                localMlKemPubKeyBytes.CopyTo(resSpan.Slice(classicKeyLen, MlKemPubKeyLen));


                RandomNumberGenerator.Fill(resSpan.Slice(classicKeyLen + MlKemPubKeyLen));

               // await network.SendAsync(result.AsMemory());

                await SendViaSegments(result.AsMemory());
                int clientPacketLen = classicKeyLen + MlKemCipherTextLen + padding;
                using NativeBytes clientKeyPkg = new NativeBytes(clientPacketLen);
                await ReceiveExactlyAsync(clientKeyPkg.AsMemory());

                var clientEcdhSpan = clientKeyPkg.AsSpan(0, classicKeyLen);
                var clientMlKemCipherSpan = clientKeyPkg.AsSpan(classicKeyLen, MlKemCipherTextLen);

                Span<byte> ecdhSecret = stackalloc byte[classicKeyLen];
                using (var otherEcdh = ECDiffieHellman.Create())
                {
                    otherEcdh.ImportSubjectPublicKeyInfo(clientEcdhSpan, out _);
                    ecdhSecret = tools._ecndhe.DeriveRawSecretAgreement(otherEcdh.PublicKey);
                }


                var decapsulator = new MLKemDecapsulator(MlKemParams);
                decapsulator.Init(mlKemPrivKey);
                Span<byte> mlKemSecret = stackalloc byte[decapsulator.SecretLength];
                decapsulator.Decapsulate(clientMlKemCipherSpan, mlKemSecret);


                tools.Key = DeriveHybridKey(ecdhSecret, mlKemSecret, rndNonce.AsSpan().Slice(1));

                


                CryptographicOperations.ZeroMemory(ecdhSecret);
                CryptographicOperations.ZeroMemory(mlKemSecret);

                return true;
            }
        }


        private byte[] DeriveHybridKey(Span<byte> ecdhSecret, Span<byte> mlKemSecret, ReadOnlySpan<byte> salt)
        {

            Span<byte> combined = stackalloc byte[ecdhSecret.Length + mlKemSecret.Length];


            ecdhSecret.CopyTo(combined);
            mlKemSecret.CopyTo(combined.Slice(ecdhSecret.Length));


            byte[] finalKey = new byte[32]; // aes-gcm key
            HKDF.DeriveKey(HashAlgorithmName.SHA256, combined, finalKey, salt ,OSPConsts.Info );
            return finalKey;
        }




        public void HandshakeSettings()
        {
            NativeBytes bytes = new NativeBytes(10);

            BinaryPrimitives.WriteInt32LittleEndian(bytes.AsWritableSpan().Slice(0, 4), variables.SliceSize);
            BinaryPrimitives.WriteInt32LittleEndian(bytes.AsWritableSpan().Slice(4, 4), variables.FrameSizeThreshold);
            BinaryPrimitives.WriteInt16LittleEndian(bytes.AsWritableSpan().Slice(8), variables.PacketsPerSecond);
            SendHighPacketToQueue(OSPConsts.HandshakeSettings, bytes);
        }


        

        private uint maxValue = 0;
        private uint minValue = 0;
        private uint RandomNumber(List<uint>? blocked = null)
        {
            uint rnd = (uint)Random.Shared.NextInt64(minValue, maxValue);
            if (blocked != null) lock (blocked) if (blocked.Contains(rnd)) return RandomNumber();
            if (Packets.ContainsKey(rnd)) return RandomNumber();
            else return rnd;

        }



        private OSPPriority GetPriority(long dataLength, int threshold)
        {
            if (dataLength == 0) return OSPPriority.High;
            if (dataLength > threshold)
            {
                return OSPPriority.Low;
            }
            else
            {
                return OSPPriority.Medium;
            }
        }



       
        public uint SendToQueue(OSPData? data, byte[]? description, OSPStatusCode status, OSPMessageType type, List<uint>? blocked = null)
        {
            //if (data == null) data = new OSPData(new byte[] { 0x6E });
            if (description == null) description = OSPConsts.NullableData;


            uint id = RandomNumber(blocked);
            Packets[id] = new OSPPacketContext() { Priority = GetPriority(data is null ? 0 : data.Length, variables.FrameSizeThreshold), Data = data, Request = new OSPHeaderRequest() { MessageStatus = status, MessageType = type, Description = description }, CurrentChunkSize = 0, RequestSend = false };
            _rrQueue.Enqueue(id);
            _signal.Release();
            return id;
        }
        public void SendToQueue(OSPData? data, byte[]? description, OSPStatusCode status, OSPMessageType type, uint id)
        {
            //if (data == null) data = new OSPData(new byte[] { 0x6E });
            if (description == null) description = OSPConsts.NullableData;


           
            Packets[id] = new OSPPacketContext() { Priority = GetPriority(data is null ? 0 : data.Length, variables.FrameSizeThreshold), Data = data, Request = new OSPHeaderRequest() { MessageStatus = status, MessageType = type, Description = description }, CurrentChunkSize = 0, RequestSend = false };
            _rrQueue.Enqueue(id);
            _signal.Release();
        }


        public void SendHighPacketToQueue(byte command, NativeBytes? data)
        {
            lock (highLocker) HighPriorityPackets.Add((command, data));

            _signal.Release();
        }


        

        private double _ingressDelayDebtMs = 0;
        private readonly Stopwatch _shaperClock = new(); 

        public async ValueTask IngressThrottling(double elapsedMS, int bytesRead)
        {
            if (variables.IngressMbps <= 0 || bytesRead <= 0 || variables.IngressMbps >= 5000) return;

            long bytesPerSecond = (long)((variables.IngressMbps * 1_000_000) / 8);
            double targetMS = ((double)bytesRead / bytesPerSecond) * 1000;

            if (elapsedMS < targetMS)
            {
               
                _ingressDelayDebtMs += (targetMS - elapsedMS);

              
                if (_ingressDelayDebtMs >= 15.6)
                {
                    int delay = (int)_ingressDelayDebtMs;

                    
                    _shaperClock.Restart();
                    await Task.Delay(delay);
                    _shaperClock.Stop();

                 
                    _ingressDelayDebtMs -= _shaperClock.Elapsed.TotalMilliseconds;
                }
            }
            else
            {
                
                _ingressDelayDebtMs -= (elapsedMS - targetMS);
            }

            
            if (_ingressDelayDebtMs < -100) _ingressDelayDebtMs = -100;
        }


        private double _egressDelayDebtMs = 0;
        private readonly Stopwatch _egressShaperClock = new();
        public async ValueTask EgressThrottling(double elapsedMS, int bytesWritten)
        {
            
            if (variables.EgressMbps <= 0 || bytesWritten <= 0) return;

            long bytesPerSecond = (long)((variables.EgressMbps * 1_000_000) / 8);
            double targetMS = ((double)bytesWritten / bytesPerSecond) * 1000;

            if (elapsedMS < targetMS)
            {
                _egressDelayDebtMs += (targetMS - elapsedMS);

                if (_egressDelayDebtMs >= 15.6)
                {
                    int delay = (int)_egressDelayDebtMs;

                    _egressShaperClock.Restart();
                    await Task.Delay(delay);
                    _egressShaperClock.Stop();

                    _egressDelayDebtMs -= _egressShaperClock.Elapsed.TotalMilliseconds;
                }
            }
            else
            {
                _egressDelayDebtMs -= (elapsedMS - targetMS);
            }

            if (_egressDelayDebtMs < -100) _egressDelayDebtMs = -100;
        }



        
        private List<uint> ToCancel = new();
        
        public async void CancelPacket(uint id)
        {

            lock (ToCancel)
            {
                if (Packets.ContainsKey(id))
                {
                    ToCancel.Add(id);
                    _signal.Release();
                }
            }
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
                
                try
                {
                    
                    _cts.Cancel();
                   
                  
                }
                catch { }
                finally
                {

                
                    foreach (var item in Packets.Values)
                    {
                        
                        item.Data?.ClearSource();
                        item.Data?.Dispose();
                    }
                    lock (HighPriorityPackets)
                    {
                        foreach (var item in HighPriorityPackets)
                        {
                            if (item.data != null) item.data.Dispose();
                        }
                    }
                    HighPriorityPackets.Clear();
                    Packets.Clear();

                    network.Close();


                    tools.Dispose();


                    _cts.Dispose();

                    _disposed = true;

                }
            }





        }
        ~OSPStream() => Dispose(false);
    }
}
