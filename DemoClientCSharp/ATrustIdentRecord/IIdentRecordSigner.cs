using System.Security.Cryptography;

namespace ATrustIdentRecord
{
    public interface IIdentRecordSigner
    {
        byte[] GetCertificate();

        byte[] Sign(byte[] toBeSigned, HashAlgorithmName algorithm);
    }
}
