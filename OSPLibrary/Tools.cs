using System.Security.Cryptography;
using System.Text;


namespace System.Net.Sockets.OSP
{
   static internal class GlobalTools
    {
       public static HeaderMessage MakeHeaderFromResponse(byte[] data, IPEndPoint ip)
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
                MessageType = (OSPMessageType)Convert.ToInt32(args[4]),
            };

            return msg;
        }



    }
    internal class Tools
    {
        public RSA Master_RSA = RSA.Create();

        public RSA rsa_provider =  RSA.Create();
        public Aes aes = Aes.Create();
        public byte[] Encrypt(byte[] data)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(data, 0, data.Length);
                    cs.FlushFinalBlock();

                }
                return ms.ToArray();
            }

        }
        public byte[] Decrypt(byte[] data)
        {

           
                using var msDecrypt = new MemoryStream(data);
                using var csDecrypt = new CryptoStream(msDecrypt, aes.CreateDecryptor(), CryptoStreamMode.Read);
                using (var srDecrypt = new MemoryStream())
                {


                    try
                    {
                        csDecrypt.CopyTo(srDecrypt);


                        return srDecrypt.ToArray();


                    

                    }
                    catch (CryptographicException ex)
                    {

                        throw new CryptographicException("Ошибка во время дешифровки:", ex);
                    }

                }
        }

        
    }
}
    

