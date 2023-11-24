using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.IO;

namespace isaklm_cryptography
{
    internal class Program
    {
        static byte[] HashPassword(string password, int iterations)
        {
            RNGCryptoServiceProvider provider = new RNGCryptoServiceProvider();

            byte[] salt = new byte[32];
            provider.GetBytes(salt);

            Rfc2898DeriveBytes hash = new Rfc2898DeriveBytes(password, salt, iterations);

            return hash.GetBytes(16);
        }
        static string EncryptString(string text, byte[] keys, byte[] initialization_vector)
        {
            byte[] encrypted_text;
            using (Aes aes = Aes.Create())
            {
                ICryptoTransform encryptor = aes.CreateEncryptor(keys, initialization_vector);
                using (MemoryStream memory_stream = new MemoryStream())
                {
                    using (CryptoStream crypto_stream = new CryptoStream(memory_stream, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter stream_writer = new StreamWriter(crypto_stream))
                        {
                            stream_writer.Write(text);
                        }

                        encrypted_text = memory_stream.ToArray();
                    }
                }
            }
            return Convert.ToBase64String(encrypted_text);
        }

        static string DecryptString(string encrypted_text, byte[] key, byte[] iv)
        {
            string text = String.Empty;
            using (Aes aes = Aes.Create())
            {
                ICryptoTransform decryptor = aes.CreateDecryptor(key, iv);
                using (MemoryStream memory_stream = new MemoryStream(Convert.FromBase64String(encrypted_text)))
                {
                    using (CryptoStream crypto_stream = new CryptoStream(memory_stream, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader streamReader = new StreamReader(crypto_stream))
                        {
                            text = streamReader.ReadToEnd();
                        }
                    }
                }
            }
            return text;
        }
        async static void Server()
        {
            Dictionary<byte, string> files = new Dictionary<byte, string>();
            byte open_file = 0;

            IPHostEntry ip_host_info = await Dns.GetHostEntryAsync(Dns.GetHostName());
            IPAddress ip_address = ip_host_info.AddressList[0];
            IPEndPoint ip_end_point = new IPEndPoint(ip_address, 11000);

            Socket listener = new Socket(ip_end_point.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

            listener.Bind(ip_end_point);
            listener.Listen(100);

            var server = await listener.AcceptAsync();

            while (true)
            {
                var recieved_message = await GetMessage(server);

                char message_type = recieved_message[0];

                string message_content = "";

                for(int i = 1; i < recieved_message.Length; ++i)
                {
                    message_content += recieved_message[i];
                }


                if(message_type == 'W')
                {
                    byte file_id = 0;
                    byte.TryParse(message_content, out file_id);

                    if(!files.ContainsKey(file_id))
                    {
                        files.Add(file_id, "");
                    }

                    open_file = file_id;


                    _ = await SendMessage(server, "A");
                }
                else if(message_type == 'R')
                {
                    byte file_id = 0;
                    byte.TryParse(message_content, out file_id);

                    if (files.ContainsKey(file_id))
                    {
                        _ = await SendMessage(server, "A" + files[file_id]);
                    }
                    else
                    {
                        _ = await SendMessage(server, "D");
                    }
                }
                else
                {
                    files[open_file] = message_content;
                }
            }
        }

        async static Task<string> GetMessage(Socket socket)
        {
            var buffer = new byte[8192];
            var recieved_bytes = new ArraySegment<byte>(buffer, 0, buffer.Length);
            _ = await socket.ReceiveAsync(recieved_bytes, SocketFlags.None);
            var recieved_message = Encoding.UTF8.GetString(recieved_bytes.Array);

            return recieved_message;
        }

        async static Task<bool> SendMessage(Socket socket, string message)
        {
            var message_bytes = Encoding.UTF8.GetBytes(message);
            var message_segment = new ArraySegment<byte>(message_bytes, 0, message_bytes.Length);

            _ = await socket.SendAsync(message_segment, SocketFlags.None);

            return true;
        }

        async static Task<bool> SendReadRequest(Socket client, byte file_id)
        {
            _ = await SendMessage(client, "R" + file_id);

            return true;
        }

        async static Task<bool> SendWriteRequest(Socket client, byte file_id)
        {
            _ = await SendMessage(client, "W" + file_id);

            string recieved_message = await GetMessage(client);

            if (recieved_message[0] == 'A')
            {
                return true;
            }

            return false;
        }

        static byte GetFileId()
        {
            byte file_id = 0;

            while (true)
            {
                Console.Write("Enter file id: ");

                if (byte.TryParse(Console.ReadLine(), out file_id))
                {
                    break;
                }
                else
                {
                    Console.WriteLine("Invalid id.");
                }
            }

            return file_id;
        }

        async static void Client()
        {
            RandomNumberGenerator random = RandomNumberGenerator.Create();

            string password = "";

            while(true)
            {
                Console.Write("Input password here: ");
                password = Console.ReadLine();

                if(password.Length >= 8)
                {
                    break;
                }
                else
                {
                    Console.WriteLine("Password needs to be atleast 8 characters.");
                }
            }


            byte[] keys = HashPassword(password, 10000);

            Dictionary<byte, byte[]> initialization_vectors = new Dictionary<byte, byte[]>();


            IPHostEntry ip_host_info = await Dns.GetHostEntryAsync(Dns.GetHostName());
            IPAddress ip_address = ip_host_info.AddressList[0];
            IPEndPoint ip_end_point = new IPEndPoint(ip_address, 11000);

            Socket client = new Socket(ip_end_point.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

            await client.ConnectAsync(ip_end_point);

            while (true)
            {
                Console.Write("Do you want to read or write to a file? (read/write/exit): ");
                var request = Console.ReadLine().ToLower();

                if (request == "read" || request == "r")
                {
                    byte file_id = GetFileId();

                    _ = await SendReadRequest(client, file_id);
                    
                    string message = await GetMessage(client);

                    if (message[0] == 'A')
                    {
                        string content = "";

                        for(int i = 1; i < message.Length; ++i)
                        {
                            if (message[i] == '\0')
                            {
                                break;
                            }

                            content += message[i];
                        }

                        Console.WriteLine("File recieved from server:");
                        Console.WriteLine(DecryptString(content, keys, initialization_vectors[file_id]));
                    }
                    else
                    {
                        Console.WriteLine("Server denied permission to read.");
                    }
                }
                else if (request == "write" || request == "w")
                {
                    byte file_id = GetFileId();

                    if(await SendWriteRequest(client, file_id))
                    {
                        if(!initialization_vectors.ContainsKey(file_id))
                        {
                            initialization_vectors.Add(file_id, new byte[16]);
                        }

                        random.GetBytes(initialization_vectors[file_id]);

                        Console.Write("Enter message: ");
                        string message = EncryptString(Console.ReadLine(), keys, initialization_vectors[file_id]);
                        Console.WriteLine("message: " + message);

                        _ = await SendMessage(client, "M" + message);
                    }
                    else
                    {
                        Console.WriteLine("Server denied permission to write.");
                    }
                }
                else if (request == "exit" || request == "e")
                {
                    break;
                }
                else
                {
                    Console.WriteLine("Invalid request.");
                }
            }

            client.Shutdown(SocketShutdown.Both);
        }

        static void Main(string[] args)
        {
            while(true)
            {
                Console.Write("Start server or client: ");
                var program = Console.ReadLine().ToLower();

                if(program == "server" || program == "s")
                {
                    Server();

                    break;
                }
                else if(program == "client" || program == "c")
                {
                    Client();

                    break;
                }
                else
                {
                    Console.WriteLine("Invalid response.");
                }
            }

            while (true) ;
        }
    }
}
