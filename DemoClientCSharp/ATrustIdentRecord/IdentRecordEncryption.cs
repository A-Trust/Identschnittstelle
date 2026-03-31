using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.X509;
using System;
using System.Security.Cryptography;
using System.Text;

namespace ATrustIdentRecord
{
    public static class IdentRecordEncryption
    {
        private static RandomNumberGenerator rng = RandomNumberGenerator.Create();


        private static readonly byte[] IV = new byte[16]
        {
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
        };



        public static byte[] Encrypt(string identRecord, byte[] certData)
        {
            byte[] identRecordData = Encoding.UTF8.GetBytes(identRecord);

            byte[] key = new byte[32];
            rng.GetBytes(key);


            byte[] outputAes = AesGcm(identRecordData, key);


            //RSA OAEP key encryption
            byte[] outputRSA = RsaOaep(certData, key, outputAes);

            var result = new byte[outputAes.Length + outputRSA.Length];
            Buffer.BlockCopy(outputAes, 0, result, 0, outputAes.Length);
            Buffer.BlockCopy(outputRSA, 0, result, outputAes.Length, outputRSA.Length);
            return result;
        }

        private static byte[] RsaOaep(byte[] certData, byte[] key, byte[] outputAes)
        {
            if(certData is null)
            {
                return null;
            }

            var certParser = new X509CertificateParser();
            var cert = certParser.ReadCertificate(certData);
            if(cert is null)
            {
                return null;
            }
            AsymmetricKeyParameter publicKey = cert.GetPublicKey();

            var rsa = new OaepEncoding(new RsaEngine());
            rsa.Init(true, publicKey);
            return rsa.ProcessBlock(key, 0, key.Length);
        }

        private static byte[] AesGcm(byte[] identRecordData, byte[] key)
        {
            var cipher = new GcmBlockCipher(new AesEngine());

            var parameters = new AeadParameters(
                new KeyParameter(key),
                128,      // Tag length (bits)
                IV,
                null      // AAD (none)
            );


            cipher.Init(true, parameters);
            byte[] outputAes = new byte[cipher.GetOutputSize(identRecordData.Length)];
            int len = cipher.ProcessBytes(identRecordData, 0, identRecordData.Length, outputAes, 0);
            cipher.DoFinal(outputAes, len);
            return outputAes;
        }
    }
}
