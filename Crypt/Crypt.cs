using System;
using System.IO;
using System.Resources;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Crypt
{
    public static class Crypt
    {
        [DllExport(ExportName = "RSADecrypt", CallingConvention = System.Runtime.InteropServices.CallingConvention.Cdecl)]
        public static string RSADecrypt(string dataToDecrypt, string hashAlg, string password = "")
        {
            if (!int.TryParse(hashAlg.Substring(3), out int hashSize))
                throw new Exception("Unknown hash algorithm!");

            using X509Certificate2? cert = new((byte[])new ResourceManager("Crypt.app", typeof(Crypt).Assembly)?.GetObject("cert"), string.IsNullOrWhiteSpace(password) ? null : password);

            if (!cert.HasPrivateKey)
                throw new Exception("Specified certificate has no private key!");

            using RSA? rsa = cert.GetRSAPrivateKey();
            if (rsa == null)
                throw new Exception("No RSA private key found!");
            if (rsa.KeySize < 2048 && hashAlg == "SHA512")
                throw new Exception("OAEP SHA512 padding is not applicable when key size is less than 2048!");

            int blockSize = rsa.KeySize / 8 - 2 * hashSize / 8 - 2;
            byte[] data = new byte[rsa.KeySize / 8];

            using MemoryStream fs = new(Convert.FromBase64String(dataToDecrypt));
            using MemoryStream ms = new();

            while (fs.Read(data, 0, data.Length) > 0)
                ms.Write(rsa.Decrypt(data, RSAEncryptionPadding.CreateOaep(new HashAlgorithmName(hashAlg))), 0, blockSize);

            fs.Close();
            string ret = Encoding.UTF8.GetString(ms.ToArray());
            ms.Close();

            return ret;
        }
    }
}
