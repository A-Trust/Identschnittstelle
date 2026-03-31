using ATrustIdentRecord.Type;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace ATrustIdentRecord
{
    public sealed class IdentRecord
    {
        private static readonly string IDR_PREFIX = "idr";
        private static readonly string IDR_NAMESPACE = "http://www.a-trust.at/namespace/idconfirmation#";
        private static readonly string DSIG_PREFIX = "dsig";
        private static readonly string DSIG_NAMESPACE = "http://www.w3.org/2000/09/xmldsig#";
        private const string SignatureId = "signedinfo-1";
        private static readonly string ETSI_PREFIX = "etsi";
        private static readonly string ETSI_NAMESPACE = "http://uri.etsi.org/01903/v1.1.1#";
        private const string etsi_xpath = "//*[@Id='etsi-signed-1-1']/etsi:QualifyingProperties/etsi:SignedProperties";


        // person data
        public string GivenName { get; set; } = null;
        public string FamilyName { get; set; } = null;
        public eSexCode SexCode { get; set; } = eSexCode.NotStated;
        public int DateOfBirthYear { get; set; }
        public int DateOfBirthMonth { get; set; }
        public int DateOfBirthDay { get; set; }
        public string Titel { get; set; } // TODO: !!!

        public DateTime DateOfBirth
        {
            get
            {
                return new DateTime(DateOfBirthYear, DateOfBirthMonth, DateOfBirthDay);
            }
            set
            {
                DateOfBirthYear = value.Year;
                DateOfBirthMonth = value.Month;
                DateOfBirthDay = value.Day;
            }
        }

        public string PlaceOfBirth { get; set; }
        public string PhoneNumber { get; set; }
        public string EMailAddress { get; set; }

        // person data / Address
        public string AddressLine1 { get; set; }
        public string AddressLine2 { get; set; }
        public string AddressLine3 { get; set; }
        public string AddressLine4 { get; set; }
        public string CountryCode { get; set; }
        public string PostalCode { get; set; }

        //  identification
        public eIdMethod IdMethod { get; set; }
        public string IdType { get; set; }
        public string IdNumber { get; set; }
        public DateTime? IdIssueDate { get; set; }
        public DateTime? IdValidToDate { get; set; }
        public string IdAuthority { get; set; }
        public string IdNation { get; set; }

        // process data
        public eProcess Process { get; set; }
        public string Tag { get; set; }
        public string CustomerName { get; set; }
        public string Design { get; set; }
        public string Language { get; set; }
        public DateTime? IdentValidTo { get; set; }
        public string HashValue { get; set; }
        public string Binding { get; set; }
        public eBindingType BindingType { get; set; }
        public string ResponseSuccessUrl { get; set; }
        public string ResponseErrorUrl { get; set; }

        // Custom
        public List<(string, string)> Custom { get; set; } = new List<(string, string)>();

        public XmlDocument BuildIdentRecord()
        {
            XmlDocument doc = new XmlDocument()
            {
                PreserveWhitespace = true
            };

            XmlElement root = doc.CreateElement(IDR_PREFIX, "Confirmation", IDR_NAMESPACE);
            doc.AppendChild(root);

            var attrVersion = doc.CreateAttribute("Version");
            attrVersion.Value = "4";
            root.Attributes.Append(attrVersion);

            AppendPersonData(doc);
            AppendIdentification(doc);
            AppendProcessData(doc);
            AppendCustom(doc);
            return doc;
        }


        public string GetIdentRecordXml()
        {
            var doc = BuildIdentRecord();
            if (null == doc)
            {
                return null;
            }
            return doc.OuterXml;
        }

        private void AppendCustom(XmlDocument doc)
        {
            if (!Custom.Any())
            {
                return;
            }

            var custom = doc.CreateElement(IDR_PREFIX, "Custom", IDR_NAMESPACE);
            doc.DocumentElement.AppendChild(custom);

            foreach ((string key, string value) in Custom)
            {
                AppendIdrNode(custom, key, value);
            }
        }

        private void AppendProcessData(XmlDocument doc)
        {
            var processData = doc.CreateElement(IDR_PREFIX, "ProcessData", IDR_NAMESPACE);
            doc.DocumentElement.AppendChild(processData);
            AppendIdrNode(processData, "Name", ProcessNameAsString());
            AppendIdrNode(processData, "Tag", Tag);
            AppendIdrNode(processData, "CustomerName", CustomerName);
            AppendIdrNode(processData, "Design", Design);
            AppendIdrNode(processData, "Language", Language);
            AppendResponse(processData);
            AppendIdrNodeWithTime(processData, "IdentValidTo", IdentValidTo);
            var binding = AppendIdrNode(processData, "Binding", Binding);
            if (null != binding)
            {
                var attr = doc.CreateAttribute("type");
                attr.Value = BindingTypeAsString();
                binding.Attributes.Append(attr);
            }
            AppendIdrNode(processData, "HashValue", HashValue);
        }

        private string BindingTypeAsString()
        {
            if (eBindingType.MobilePhoneNumber == BindingType)
            {
                return "MobilePhoneNumber";
            }
            else if (eBindingType.CINCSN == BindingType)
            {
                return "CINCSN";
            }
            else if (eBindingType.ExtCardNumber == BindingType)
            {
                return "ExtCardNumber";
            }
            else if (eBindingType.EMail == BindingType)
            {
                return "EMail";
            }
            else if (eBindingType.ActivationCode == BindingType)
            {
                return "ActivationCode";
            }
            else
            {
                return "unknown";
            }
        }

        private string ProcessNameAsString()
        {
            if (eProcess.ATrustQES == Process)
            {
                return "A-TrustQES";
            }
            else if (eProcess.Acos == Process)
            {
                return "ACOS";
            }
            else if (eProcess.EuIdentity == Process)
            {
                return "EuIdentity";
            }
            else if (eProcess.WebId == Process)
            {
                return "WebId";
            }
            else if (eProcess.Seal == Process)
            {
                return "Seal";
            }
            else if (eProcess.TestCaQES == Process)
            {
                return "TestCaQES";
            }
            else if (eProcess.ShortLived == Process)
            {
                return "ShortLived";
            }
            else if (eProcess.TestShortLived == Process)
            {
                return "TestShortLived";
            }
            else
            {
                return "unknown";
            }
        }

        private void AppendResponse(XmlElement ele)
        {
            if (string.IsNullOrWhiteSpace(ResponseSuccessUrl))
            {
                return;
            }

            var doc = ele.OwnerDocument;
            var response = doc.CreateElement(IDR_PREFIX, "Response", IDR_NAMESPACE);
            ele.AppendChild(response);
            AppendIdrNode(response, "Success", ResponseSuccessUrl);
            AppendIdrNode(response, "Error", ResponseErrorUrl);
        }

        private void AppendIdentification(XmlDocument doc)
        {
            var identification = doc.CreateElement(IDR_PREFIX, "Identification", IDR_NAMESPACE);
            doc.DocumentElement.AppendChild(identification);
            AppendIdrNode(identification, "IdMethod", IdMethodAsString());
            AppendIdrNode(identification, "IdType", IdType);
            AppendIdrNode(identification, "IdNumber", IdNumber);
            AppendIdrNode(identification, "IdIssueDate", IdIssueDate);
            AppendIdrNode(identification, "IdValidToDate", IdValidToDate);
            AppendIdrNode(identification, "IdAuthority", IdAuthority);
            AppendIdrNode(identification, "IdNation", IdNation);
        }

        private string IdMethodAsString()
        {
            if (eIdMethod.IdCard == IdMethod)
            {
                return "IdCard";
            }
            else if (eIdMethod.VideoIdent == IdMethod)
            {
                return "VideoIdent";
            }
            else if (eIdMethod.AutoIdent == IdMethod)
            {
                return "AutoIdent";
            }
            else if (eIdMethod.QES == IdMethod)
            {
                return "QES";
            }
            else if (eIdMethod.EID == IdMethod)
            {
                return "EID";
            }
            else if (eIdMethod.BankIdent == IdMethod)
            {
                return "BankIdent";
            }
            else if (eIdMethod.TrustedDatabase == IdMethod)
            {
                return "TrustedDatabase";
            }
            else
            {
                return "unknown";
            }
        }

        private void AppendPersonData(XmlDocument doc)
        {
            var personData = doc.CreateElement(IDR_PREFIX,"PersonData", IDR_NAMESPACE);
            doc.DocumentElement.AppendChild(personData);
            AppendIdrNode(personData, "GivenName", GivenName);
            AppendIdrNode(personData, "FamilyName", FamilyName);
            AppendIdrNode(personData, "Titel", Titel);
            AppendIdrNode(personData, "SexCode", SexCodeAsString());
            AppendIdrNode(personData, "DateOfBirth", $"{DateOfBirthYear:D4}-{DateOfBirthMonth:D2}-{DateOfBirthDay:D2}");
            AppendIdrNode(personData, "PlaceOfBirth", PlaceOfBirth);
            AppendIdrNode(personData, "PhoneNumber", PhoneNumber);
            AppendIdrNode(personData, "EMailAddress", EMailAddress);

            AppendPostalAddress(personData);
        }

        private void AppendPostalAddress(XmlElement personData)
        {
            if (string.IsNullOrWhiteSpace(AddressLine3) ||
                string.IsNullOrWhiteSpace(AddressLine4) ||
                string.IsNullOrWhiteSpace(CountryCode) ||
                string.IsNullOrWhiteSpace(PostalCode))
            {
                return;
            }

            var doc = personData.OwnerDocument;
            var postalAddress = doc.CreateElement(IDR_PREFIX, "PostalAddress", IDR_NAMESPACE);
            personData.AppendChild(postalAddress);


            AppendIdrNode(postalAddress, "AddressLine1", AddressLine1);
            AppendIdrNode(postalAddress, "AddressLine2", AddressLine2);
            AppendIdrNode(postalAddress, "AddressLine3", AddressLine3);
            AppendIdrNode(postalAddress, "AddressLine4", AddressLine4);
            AppendIdrNode(postalAddress, "CountryCode", CountryCode);
            AppendIdrNode(postalAddress, "PostalCode", PostalCode);
        }

        private string SexCodeAsString()
        {
            if (eSexCode.Male == SexCode)
            {
                return "male";
            }
            else if (eSexCode.Female == SexCode)
            {
                return "female";
            }
            else if (eSexCode.Company == SexCode)
            {
                return "company";
            }
            else if (eSexCode.Diverse == SexCode)
            {
                return "diverse";
            }
            else if (eSexCode.Intersex == SexCode)
            {
                return "intersex";
            }
            else if (eSexCode.Open == SexCode)
            {
                return "open";
            }
            else if (eSexCode.Unknown == SexCode)
            {
                return "unknown";
            }
            else
            {
                return "not stated";
            }
        }

        private XmlElement AppendIdrNodeWithTime(XmlElement node, string name, DateTime? value)
            => AppendIdrNode(node, name, value?.ToString("yyyy-MM-ddTHH:mm:sszzz"));

        private XmlElement AppendIdrNode(XmlElement node, string name, DateTime? value)
            => AppendIdrNode(node, name, value?.ToString("yyyy-MM-dd"));

        private XmlElement AppendIdrNode(XmlElement node, string name, string value)
            => AppendNode(node, name, value, IDR_PREFIX, IDR_NAMESPACE);
        private XmlElement AppendDSigNode(XmlElement node, string name, string value)
            => AppendNode(node, name, value, DSIG_PREFIX, DSIG_NAMESPACE);


        private XmlElement AppendNode(XmlElement node, string name, string value, string prefix, string namespaceUri)
        {
            if (null == value)
            {
                return null;
            }

            var temp = node.OwnerDocument.CreateElement(prefix, name, namespaceUri);
            temp.AppendChild(node.OwnerDocument.CreateTextNode(value));
            node.AppendChild(temp);
            return temp;
        }



        public string Sign(IIdentRecordSigner signer)
        {
            var doc = BuildIdentRecord();
            if (null == doc)
            {
                return null;
            }

            return Sign(doc, signer);
        }


        public string SignFile(string filename, IIdentRecordSigner signer)
        {
            XmlDocument doc = new XmlDocument()
            {
                PreserveWhitespace = true
            };
            doc.Load(filename);

            return Sign(doc, signer);
        }

        private string Sign(XmlDocument doc, IIdentRecordSigner signer)
        {

            byte[] sigObj1 = DoC14N(doc);
            var hashSigObj1 = "";
            using (var hash = SHA256.Create())
            {
                hashSigObj1 = Convert.ToBase64String(hash.ComputeHash(sigObj1));
            }

            var sigNode = doc.CreateElement(DSIG_PREFIX, "Signature", DSIG_NAMESPACE);
            sigNode.SetAttribute("Id", "signature-1");
            doc.DocumentElement.AppendChild(sigNode);

            var signdInfo = doc.CreateElement(DSIG_PREFIX, "SignedInfo", DSIG_NAMESPACE);
            signdInfo.SetAttribute("Id", SignatureId);
            sigNode.AppendChild(signdInfo);


            var cMethod = doc.CreateElement(DSIG_PREFIX, "CanonicalizationMethod", DSIG_NAMESPACE);
            cMethod.SetAttribute("Algorithm", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
            signdInfo.AppendChild(cMethod);

            var sMethod = doc.CreateElement(DSIG_PREFIX, "SignatureMethod", DSIG_NAMESPACE);
            sMethod.SetAttribute("Algorithm", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
            signdInfo.AppendChild(sMethod);

            var ref1 = CreateReference1(doc, hashSigObj1, signdInfo);
            var ref2 = CreateEtsiReference(doc, signdInfo);


            var sigValue = doc.CreateElement(DSIG_PREFIX, "SignatureValue", DSIG_NAMESPACE);
            sigNode.AppendChild(sigValue);

            var keyInfo = doc.CreateElement(DSIG_PREFIX, "KeyInfo", DSIG_NAMESPACE);
            sigNode.AppendChild(keyInfo);

            var x509Data = doc.CreateElement(DSIG_PREFIX, "X509Data", DSIG_NAMESPACE);
            keyInfo.AppendChild(x509Data);

            var certB64 = signer.GetCertificate();
            AppendDSigNode(x509Data, "X509Certificate", Convert.ToBase64String(certB64));


            X509Certificate2 cert = new X509Certificate2(certB64);
            if (null == cert)
            {
                return null;
            }
            var sigProperties = CreateEtisObject(doc, sigNode, cert);

            // hashes
            byte[] sigObj2 = DoC14N(doc, string.Format("{0}/descendant-or-self::node()|{0}//@*", etsi_xpath));
            string sigObj2UTF8 = System.Text.Encoding.UTF8.GetString(sigObj2);
            string hashSigObj2 = "";
            using (var hash = SHA256.Create())
            {
                hashSigObj2 = Convert.ToBase64String(hash.ComputeHash(sigObj2));
            }
            AppendDSigNode(ref2, "DigestValue", hashSigObj2);


            var toBeSigned = DoC14N(doc, "//*[@Id='" + SignatureId + "'] /descendant-or-self::node()|//*[@Id='" + SignatureId + "']//@*");


            var signature = signer.Sign(toBeSigned, HashAlgorithmName.SHA256);
            if (null == signature)
            {
                return null;
            }


            string SigB64 = Convert.ToBase64String(signature, Base64FormattingOptions.InsertLineBreaks);
            SigB64 = SigB64.Replace("\r\n", "\n");
            sigValue.AppendChild(doc.CreateTextNode(SigB64));

            return doc.OuterXml;
        }



        private XmlElement AppendDsigTransform(XmlElement parent, string algorithm)
        {
            XmlElement transform = parent.OwnerDocument.CreateElement(DSIG_PREFIX, "Transform", DSIG_NAMESPACE);
            parent.AppendChild(transform);
            transform.SetAttribute("Algorithm", algorithm);
            return transform;
        }

        private void AppendDigestMethod(XmlElement parent, string method)
        {
            XmlElement dMethod = parent.OwnerDocument.CreateElement(DSIG_PREFIX, "DigestMethod", DSIG_NAMESPACE);
            parent.AppendChild(dMethod);
            dMethod.SetAttribute("Algorithm", method);
        }


        private XmlElement CreateEtsiReference(XmlDocument doc, XmlElement sigInfo)
        {
            XmlElement reference = doc.CreateElement(DSIG_PREFIX, "Reference", DSIG_NAMESPACE);
            sigInfo.AppendChild(reference);

            reference.SetAttribute("Id", "etsi-data-reference-1-1");
            reference.SetAttribute("Type", ETSI_NAMESPACE + "SignedProperties");
            reference.SetAttribute("URI", "");

            XmlElement transforms = doc.CreateElement(DSIG_PREFIX, "Transforms", DSIG_NAMESPACE);
            reference.AppendChild(transforms);

            var transform = AppendDsigTransform(transforms, "http://www.w3.org/2002/06/xmldsig-filter2");
            XmlElement xmlXPath = doc.CreateElement("xpf", "XPath", "http://www.w3.org/2002/06/xmldsig-filter2");

            xmlXPath.AppendChild(doc.CreateTextNode(etsi_xpath));
            transform.AppendChild(xmlXPath);

            xmlXPath.SetAttribute("Filter", "intersect");
            xmlXPath.SetAttribute("xmlns:" + ETSI_PREFIX, ETSI_NAMESPACE);
            xmlXPath.SetAttribute("xmlns:xpf", "http://www.w3.org/2002/06/xmldsig-filter2");

            AppendDigestMethod(reference, "http://www.w3.org/2001/04/xmlenc#sha256");
            return reference;
        }

        private XmlElement CreateReference1(XmlDocument doc, string hashSigObj1, XmlElement sigInfo)
        {
            XmlElement reference = doc.CreateElement(DSIG_PREFIX, "Reference", DSIG_NAMESPACE);
            sigInfo.AppendChild(reference);
            reference.SetAttribute("URI", "");

            XmlElement transforms = doc.CreateElement(DSIG_PREFIX, "Transforms", DSIG_NAMESPACE);
            reference.AppendChild(transforms);

            var transform1 = AppendDsigTransform(transforms, "http://www.w3.org/2000/09/xmldsig#enveloped-signature");
            var transform2 = AppendDsigTransform(transforms, "http://www.w3.org/TR/2001/REC-xml-c14n-20010315");

            AppendDigestMethod(reference, "http://www.w3.org/2001/04/xmlenc#sha256");
            AppendDSigNode(reference, "DigestValue", hashSigObj1);
            return reference;
        }

        private XmlElement CreateEtisObject(XmlDocument doc, XmlElement XmlDsigSignature, X509Certificate2 certificate)
        {

            var _object = doc.CreateElement(DSIG_PREFIX, "Object", DSIG_NAMESPACE);
            XmlDsigSignature.AppendChild(_object);
            _object.SetAttribute("Id", "etsi-signed-1-1");

            var qualifyingProperties = doc.CreateElement(ETSI_PREFIX, "QualifyingProperties", ETSI_NAMESPACE);
            _object.AppendChild(qualifyingProperties);
            qualifyingProperties.SetAttribute("Target", "#reference-1-1");
            qualifyingProperties.SetAttribute("xmlns:" + ETSI_PREFIX, ETSI_NAMESPACE);

            var signedProperties = doc.CreateElement(ETSI_PREFIX, "SignedProperties", ETSI_NAMESPACE);
            qualifyingProperties.AppendChild(signedProperties);
            var signedSignatureProperties = doc.CreateElement(ETSI_PREFIX, "SignedSignatureProperties", ETSI_NAMESPACE);
            signedProperties.AppendChild(signedSignatureProperties);
            var signingTime = doc.CreateElement(ETSI_PREFIX, "SigningTime", ETSI_NAMESPACE);
            signedSignatureProperties.AppendChild(signingTime);
            signingTime.AppendChild(doc.CreateTextNode(DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss") + "Z"));
            var signingCertificate = doc.CreateElement(ETSI_PREFIX, "SigningCertificate", ETSI_NAMESPACE);
            signedSignatureProperties.AppendChild(signingCertificate);
            var cert = doc.CreateElement(ETSI_PREFIX, "Cert", ETSI_NAMESPACE);
            signingCertificate.AppendChild(cert);

            var certDigest = doc.CreateElement(ETSI_PREFIX, "CertDigest", ETSI_NAMESPACE);
            cert.AppendChild(certDigest);
            var digestMethod = doc.CreateElement(ETSI_PREFIX, "DigestMethod", ETSI_NAMESPACE);
            certDigest.AppendChild(digestMethod);

            digestMethod.SetAttribute("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256");
            var digestValue = doc.CreateElement(ETSI_PREFIX, "DigestValue", ETSI_NAMESPACE);
            certDigest.AppendChild(digestValue);

            using (var hash = SHA256.Create())
            {
                string Thumbprint = Convert.ToBase64String(hash.ComputeHash(certificate.RawData));
                digestValue.AppendChild(doc.CreateTextNode(Thumbprint));
            }

            var issuerSerial = doc.CreateElement(ETSI_PREFIX, "IssuerSerial", ETSI_NAMESPACE);
            cert.AppendChild(issuerSerial);
            var x509IssuerName = doc.CreateElement(DSIG_PREFIX, "X509IssuerName", DSIG_NAMESPACE);
            issuerSerial.AppendChild(x509IssuerName);
            x509IssuerName.AppendChild(doc.CreateTextNode(certificate.Issuer));
            var x509SerialNumber = doc.CreateElement(DSIG_PREFIX, "X509SerialNumber", DSIG_NAMESPACE);
            issuerSerial.AppendChild(x509SerialNumber);

            if (Int64.TryParse(certificate.SerialNumber,
                NumberStyles.HexNumber,
                CultureInfo.InvariantCulture,
                out var iSerialNumber))
            {
                x509SerialNumber.AppendChild(doc.CreateTextNode(iSerialNumber.ToString()));
            }

            var signaturePolicyIdentifier = doc.CreateElement(ETSI_PREFIX, "SignaturePolicyIdentifier", ETSI_NAMESPACE);
            signedSignatureProperties.AppendChild(signaturePolicyIdentifier);
            var signaturePolicyImplied = doc.CreateElement(ETSI_PREFIX, "SignaturePolicyImplied", ETSI_NAMESPACE);
            signaturePolicyIdentifier.AppendChild(signaturePolicyImplied);

            var signedDataObjectProperties = doc.CreateElement(ETSI_PREFIX, "SignedDataObjectProperties", ETSI_NAMESPACE);
            signedProperties.AppendChild(signedDataObjectProperties);

            var dataObjectFormat = doc.CreateElement(ETSI_PREFIX, "DataObjectFormat", ETSI_NAMESPACE);
            signedDataObjectProperties.AppendChild(dataObjectFormat);
            var objectReference = doc.CreateAttribute("ObjectReference");
            dataObjectFormat.Attributes.Append(objectReference);

            var mimeType = doc.CreateElement(ETSI_PREFIX, "MimeType", ETSI_NAMESPACE);
            dataObjectFormat.AppendChild(mimeType);
            mimeType.AppendChild(doc.CreateTextNode("application/xhtml+xml"));


            return signedProperties;
        }


        private byte[] DoC14N(XmlDocument doc, string xpath)
        {
            XmlNamespaceManager nsmgr = new XmlNamespaceManager(doc.NameTable);
            nsmgr.AddNamespace(ETSI_PREFIX, ETSI_NAMESPACE);
            nsmgr.AddNamespace(DSIG_PREFIX, DSIG_NAMESPACE);

            var c14n = new System.Security.Cryptography.Xml.XmlDsigC14NTransform(false);
            XmlNodeList c14nNodes = doc.SelectNodes(xpath, nsmgr);
            c14n.LoadInput(c14nNodes);
            return DoC14N(c14n);
        }



        private byte[] DoC14N(XmlDocument doc)
        {
            var c14n = new System.Security.Cryptography.Xml.XmlDsigC14NTransform(false);
            c14n.LoadInput(doc);
            return DoC14N(c14n);
        }

        private byte[] DoC14N(System.Security.Cryptography.Xml.XmlDsigC14NTransform c14n)
        {
            byte[] toBeSigned = null;
            try
            {
                using (var s1 = (Stream)c14n.GetOutput())
                {
                    long len = s1.Length;
                    toBeSigned = new byte[len];
                    s1.Read(toBeSigned, 0, (int)len);
                }
            }
            catch (Exception)
            {
                return null;
            }
            return toBeSigned;
        }

    }
}
