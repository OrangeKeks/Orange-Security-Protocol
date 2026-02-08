using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace System.Net.Sockets.OSP
{
    internal class Tools
    {
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

            try
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
            finally
            {

            }




        }
    }
}
    

