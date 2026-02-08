# Orange-Security-Protocol
— это интернет-протокол, надстройка над TCP, которая обеспечивает автоматическое шифрование и удобство в использовании.


# Быстрое начало
### Сервер
  

    public static class DoWork
    {
       public static void Main()
       {
          OSPServer server = new OSPServer("192.168.1.1", 1111);
          server.Start(MessageHandler);
          Console.ReadKey();
       }

       public static async Task<OSPServerAnswer> MessageHandler(MessageEventArgs args)
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
            await client.Start();
          OSPResponse response =  await client.Send(FromText("Hello!"));
    
            if (response.Data != null) Console.WriteLine(ToText(response.Data));
    
            Console.WriteLine("STATUS: {0}", response.StatusCode);
    
        }
    
    
        public static byte[] FromText(string input) => Encoding.UTF8.GetBytes(input);
        public static string ToText(byte[] data) => Encoding.UTF8.GetString(data);
    }



## Основные возможности

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

