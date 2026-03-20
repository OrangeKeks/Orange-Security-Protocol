# Orange-Security-Protocol
— это интернет-протокол прикладного уровня над TCP, который обеспечивающий автоматическое шифрование и упрощает взаимодействие между двумя узлами.


# Быстрое начало
### Сервер
  

    public static class DoWork
    {
       public static void Main()
       {
          OSPServer server = new OSPServer("192.168.1.1", 1111);
          server.Start(MessageHandler, AnyPrivateRSAKey);
          Console.ReadKey();
       }

       public static async Task<OSPServerAnswer> MessageHandler(OSPMessageEventArgs args)
      {
        OSPServerAnswer answer = new OSPServerAnswer();
        if (args.Data != null)
        {
            string text = ToText(args.Data);

            if (text == "Hello!")
            {
                answer.Code = OSPStatusCode.OK;
                answer.Data = FromText("Hello too!");
                return answer;
            }
        }

        answer.Code = OSPStatusCode.Error;
        
        return answer;
       }

       public static string ToText(byte[] data) => Encoding.UTF8.GetString(data);
       public static byte[] FromText(string text) => Encoding.UTF8.GetBytes(text);
    }
### Клиент
    public static class DoWork
    {
        public static async Task Main()
        {
            OSPClient client = new OSPClient("192.168.1.1", 1111);
            await client.Start(PublicRSAKey);
          OSPResponse response =  await client.Send(FromText("Hello!"));
    
            if (response.Data != null) Console.WriteLine(ToText(response.Data));
    
            Console.WriteLine("STATUS: {0}", response.StatusCode);
    
        }
    
    
        public static byte[] FromText(string input) => Encoding.UTF8.GetBytes(input);
        public static string ToText(byte[] data) => Encoding.UTF8.GetString(data);
    }


## Основные возможности

- Быстрая генерация пары RSA-ключей для подписи:
  
    `var keys = OSPSecurity.GenerateRSAMasterKeys(RSAKeySize);`

- Описание сообщения:
  
    `OSPResponse response = await client.Send(FromText("Hello!"), "AnyDescription");`

- Внезапная отправка данных клиенту:

    `await server.Send(FromText("Hello too!"), ConnectedIP, "AnyDescription");`

- Отслеживание прогресса ответа сервера на клиенте:

    Подписываемся на событие:
  
    `client.OnResponseProgressRead += Client_OnResponseProgressRead;`

    Выводим прогресс:

       private static void Client_OnResponseProgressRead(float progress)
       {
           Console.WriteLine("Download Progress: {0}%", progress * 100);
       }


## Безопасность

- Использование ECDH и AES-GCM для шифрования.
- Использование RSA-подписи.
- Нумерация для предотвращения использования старых пакетов.
