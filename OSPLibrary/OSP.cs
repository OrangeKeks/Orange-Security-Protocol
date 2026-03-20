


using System.Security.Cryptography;



namespace System.Net.Sockets.OSP
{

    public enum OSPStatusCode
    {
        None,
        OK,
        Error,
        Forbidden,
        NotFound
    }


    public static class OSPSecurity
    {
        /// <summary>
        /// Генерирует пару RSA-ключей. Эти ключи можно использовать для подписи.
        /// </summary>
        /// <param name="keySize">Размер RSA-ключа.</param>
        /// <returns></returns>
        public static (string Public, string Private) GenerateRSAMasterKeys(int keySize)
        {
            using var rsa = RSA.Create(keySize);
          
            return (
                Convert.ToBase64String(rsa.ExportRSAPublicKey()),
                Convert.ToBase64String(rsa.ExportRSAPrivateKey())
            );
        }

    }
    internal enum OSPMessageType
    {
        AnswerFromServer,
        MessageFromServer,
        MessageFromClient
    }

    public class OSPSettings
    {
      


      


        public int SendBufferSize { get; set; } = 262144;

        public int ReceiveBufferSize { get; set; } = 262144;

        public ECCurve Curve { get; set; } = ECCurve.NamedCurves.nistP256;


        /// <summary>
        /// Задаёт указанный размер RSA-ключу. Одновременно влияет на AES-ключ, поправляя его под RSA.
        /// </summary>
        /// <param name="size">Размер ключа</param>
        /// <exception cref="ArgumentException">Ошибка при создании ключа.</exception>
       

       
    }



    public class OSPServerAnswer
    {
        public byte[]? Data { get; set; } = null;

        public OSPStatusCode Code { get; set; } = OSPStatusCode.OK;
    }

    internal class DataHeader
    {
        public byte[]? Nonce { get; set; } = new byte[12];
        public byte[]? Tag { get; set; } = new byte[16];
        public byte[]? Value { get; set; } 
    }
    public class OSPHeaderMessage
    {
        public uint UniID { get; set; }
        public OSPStatusCode MessageStatus { get; set; }
        public long DataLength { get; set; }
        public required string Description { get; set; }
        public required IPEndPoint IPEndPoint { get; set; }
        internal OSPMessageType MessageType { get; set; }
        internal byte[]? DataNonce { get; set; }
        internal byte[]? DataTag {  get; set; }
    }

    public class OSPMessageEventArgs
    {
        public required OSPHeaderMessage Header { get; set; }

        public byte[]? Data { get; set; }
    }
    /// <summary>
    /// Представляет класс, в котором лежит ответ от сервера. Иногда сервер может вернуть статус-код без данных.   
    /// </summary>
    public class OSPResponse
    {
        public bool OnlyStatusCode { get; set; }
        public OSPStatusCode StatusCode { get; set; }

        public required OSPHeaderMessage Header { get; set; }
        public byte[]? Data { get; set; }
    }





    }


