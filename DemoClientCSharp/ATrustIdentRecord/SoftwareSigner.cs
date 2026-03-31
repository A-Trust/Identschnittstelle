using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using System.IO;
using System.Security.Cryptography;

namespace ATrustIdentRecord
{
    public class SoftwareSigner : IIdentRecordSigner
    {

        AsymmetricKeyEntry key = null;
        Org.BouncyCastle.X509.X509Certificate cert = null;

        public SoftwareSigner()
        {
        }


        public bool LoadFromFile(string filename, string password)
        {
            using (var fs = new FileStream(filename, FileMode.Open, FileAccess.Read))
            {
                return LoadFromStream(fs, password);
            }
        }



        public bool LoadFromData(byte[] data, string password)
        {
            using (var ms = new MemoryStream(data))
            {
                return LoadFromStream(ms, password);
            }
        }


        public bool LoadFromStream(Stream stream, string password)
        {
            Pkcs12Store store = new Pkcs12StoreBuilder().Build();
            store.Load(stream, password.ToCharArray());

            foreach (string n in store.Aliases)
            {
                if (store.IsKeyEntry(n))
                {
                    key = store.GetKey(n);
                    cert = store.GetCertificate(n).Certificate;
                    return true; 
                }
            }

            return false; 
        }


        byte[] IIdentRecordSigner.GetCertificate()
        {
            return cert?.GetEncoded();
        }

        byte[] IIdentRecordSigner.Sign(byte[] toBeSigned, HashAlgorithmName algorithm)
        {
            if(toBeSigned == null || toBeSigned.Length == 0)
            {
                return null;
            }

            if (null == cert)
            {
                return null;
            }

            if (null == key)
            {
                return null;
            }

            AsymmetricKeyParameter privateKey = key.Key;
            if (privateKey == null || !privateKey.IsPrivate)
            {
                return null;
            }


            var publicKey = cert.GetPublicKey();
            string signerAlgorithm = ResolveSignerAlgorithm(publicKey, algorithm);
            if(string.IsNullOrWhiteSpace(signerAlgorithm))
            {
                return null;
            }

            ISigner signer = SignerUtilities.GetSigner(signerAlgorithm);
            signer.Init(true, privateKey);
            signer.BlockUpdate(toBeSigned, 0, toBeSigned.Length);
            return signer.GenerateSignature();
        }


        private static string ResolveSignerAlgorithm(
            AsymmetricKeyParameter publicKey,
            HashAlgorithmName hashAlgorithm)
        {
            string hash = hashAlgorithm.Name ?? "SHA256";

            if (publicKey is RsaKeyParameters)
                return $"{hash}withRSA";

            if (publicKey is ECPublicKeyParameters)
                return $"{hash}withECDSA";

            return null;
        }
    }
}
