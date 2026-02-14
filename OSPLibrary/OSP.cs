


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
        public int RSA_Size { get; private set; } 


        public int AES_Size { get; private set; }


        public int SendBufferSize { get; set; } = 262144;

        public int ReceiveBufferSize { get; set; } = 262144;



        /// <summary>
        /// Задаёт указанный размер RSA-ключу. Одновременно влияет на AES-ключ, поправляя его под RSA.
        /// </summary>
        /// <param name="size">Размер ключа</param>
        /// <exception cref="ArgumentException">Ошибка при создании ключа.</exception>
        public void SetRSAKeySise(int size)
        {
            if (size > 16384) throw new ArgumentException("Чересчур большой размер ключа RSA.");
            if (size % 64 == 0)
            {
                if (size % 8 == 0)
                {
                    RSA_Size = size;
                    AES_Size = size / 8;
                    if (AES_Size > 256) AES_Size = 256;
                }
            }
            else throw new ArgumentException("Неправильный размер ключа.");
        }
        public void SetAESKeySize(int size)
        {
            if (size > 256) throw new ArgumentException("AES не поддерживает размеры больше 256 бит.");
            if (size % 8 == 0)
            {
                int del = RSA_Size / size;
                if (del >= 8)
                {
                    AES_Size = del;
                }
                else throw new ArgumentException("Слишком большой размер ключа для RSA.");
            }
            else throw new ArgumentException("Неправильный размер ключа.");
        }


       
    }



    public class OSPServerAnswer
    {
        public byte[]? Data { get; set; } = null;

        public OSPStatusCode Code { get; set; } = OSPStatusCode.OK;
    }
    public class HeaderMessage
    {
        public uint UniID { get; set; }
        public OSPStatusCode MessageStatus { get; set; }
        public long DataLength { get; set; }
        public required string Description { get; set; }
        public required IPEndPoint IPEndPoint { get; set; }
        internal OSPMessageType MessageType { get; set; }
    }
    public class MessageEventArgs
    {
        public required HeaderMessage Header { get; set; }

        public byte[]? Data { get; set; }
    }
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





    }


