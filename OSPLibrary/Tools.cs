using System.Security.Cryptography;
using System.Text;


namespace System.Net.Sockets.OSP
{
   static internal class GlobalTools
    {
       public static OSPHeaderMessage MakeHeaderFromResponse(byte[] data, IPEndPoint ip)
        {
            ReadOnlySpan<byte> packetSpan = data.AsSpan();
            ReadOnlySpan<byte> _nonce = packetSpan.Slice(0, 12) ;
            ReadOnlySpan<byte> _tag = packetSpan.Slice(12, 16);
            string header = Encoding.UTF8.GetString(packetSpan.Slice(12 + 16));
         
            string[] args = header.Split(' ');
            OSPHeaderMessage msg = new OSPHeaderMessage()
            {
                UniID = Convert.ToUInt32(args[0]),
                DataLength = Convert.ToInt32(args[1]),
                Description = args[2],
                MessageStatus = (OSPStatusCode)Convert.ToInt32(args[3]),
                IPEndPoint = ip,
                MessageType = (OSPMessageType)Convert.ToInt32(args[4]),
                DataNonce = _nonce.ToArray(),
                DataTag = _tag.ToArray()
            };

            return msg;
        }



    }
    internal class Tools
    {
        public RSA Master_RSA = RSA.Create();

        public RSA rsa_provider =  RSA.Create();
        public static byte[] Key = null!;

        public ECDiffieHellman _ecndhe = null!;



        



        public static (byte[] ciphertext, byte[] nonce, byte[] tag) Encrypt(byte[] data)
        {
            using var aesGcm = new AesGcm(Key, 16);

       
            byte[] ciphertext = new byte[data.Length];
            byte[] nonce = new byte[12]; 
            byte[] tag = new byte[16]; 

            RandomNumberGenerator.Fill(nonce);

            aesGcm.Encrypt(nonce, data, ciphertext, tag);

            return (ciphertext, nonce, tag);
        }
       

        public static byte[] Decrypt(byte[] data, byte[] nonce, byte[] tag)
        {
            
               
                using var aesGcm = new AesGcm(Key, 16);
                byte[] decryptedBytes = new byte[data.Length];


                aesGcm.Decrypt(nonce, data, tag, decryptedBytes);
                return decryptedBytes;
          

          
        }


    }
}
    

