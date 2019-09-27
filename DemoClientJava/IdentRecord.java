import java.security.cert.CertificateFactory;
import java.io.ByteArrayInputStream; 
import java.security.cert.Certificate; 
import java.security.PublicKey; 
import javax.crypto.Cipher;
import java.net.URL; 
import java.io.InputStream; 
import javax.crypto.KeyGenerator; 
import javax.crypto.SecretKey;
import java.util.Base64;
import javax.xml.parsers.DocumentBuilderFactory; 
import javax.xml.parsers.DocumentBuilder; 
import java.io.ByteArrayInputStream; 
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;
import java.security.KeyPairGenerator; 
import java.security.KeyPair; 
import javax.xml.crypto.dsig.dom.DOMSignContext; 
import java.util.Scanner;
import java.util.ArrayList;
import java.util.List;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import java.nio.charset.StandardCharsets; 
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.XPathFilterParameterSpec;
import java.util.Collections; 
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.XMLSignature;
import java.io.ByteArrayOutputStream;
import javax.xml.transform.TransformerFactory; 
import javax.xml.transform.dom.DOMSource; 
import javax.xml.transform.Transformer; 
import javax.xml.transform.stream.StreamResult; 
import java.security.KeyStore;
import java.io.FileInputStream;
import java.util.Enumeration;
import java.security.cert.X509Certificate; 
import java.security.Principal; 
import java.security.PrivateKey;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dom.DOMStructure;
import org.w3c.dom.Attr;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import java.time.OffsetDateTime; 
import java.time.format.DateTimeFormatter;
import java.security.MessageDigest; 
import java.util.Arrays;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec; 
import java.security.spec.MGF1ParameterSpec;
import javax.crypto.spec.PSource; 
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.NodeSetData;
import org.w3c.dom.NodeList;
import java.util.stream.IntStream;
import org.w3c.dom.Node;
import java.util.stream.Stream;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.entity.ContentType;
import org.apache.http.util.EntityUtils;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.entity.ByteArrayEntity;
import javax.xml.crypto.XMLStructure;

import static javax.xml.xpath.XPathConstants.NODESET;

public class IdentRecord { 


	private static String baseURL = "https://hs-abnahme.a-trust.at/aktivierung/v3";  
	private static String signCert = "PATH_TO_P12_OR_PFX_FILE";  
	private static String signCertPwd = "PDF_PASSWORD";
	private static String sampleInputXml = "<idr:Confirmation Version=\"3\" xmlns:idr=\"http://reference.e-government.gv.at/namespace/idconfirmation#\" xmlns:pd=\"http://reference.e-government.gv.at/namespace/persondata/20020228#\">  <pd:CompactPhysicalPerson>    <pd:CompactName>      <pd:GivenName>Max</pd:GivenName>      <pd:FamilyName>Mustermann</pd:FamilyName>    </pd:CompactName>    <pd:Sex>male</pd:Sex>    <pd:DateOfBirth>1940-01-01</pd:DateOfBirth>  </pd:CompactPhysicalPerson>  <idr:SignatoryData/>  <idr:Binding>    <pd:Mobile>      <pd:FormattedNumber>10301998745646456</pd:FormattedNumber>    </pd:Mobile>  </idr:Binding>  <idr:Hash>    <idr:HashValue>XGllnlZACyu73Wm1sEa+49u47UQ=</idr:HashValue>  </idr:Hash></idr:Confirmation>";
	
	
	private static String etsi_prefix = "etsi";
	private static String etsi_ns = "http://uri.etsi.org/01903/v1.1.1#";
	private static String dsig_prefix = "dsig";
	private static String dsig_ns = "http://www.w3.org/2000/09/xmldsig#";

	private static String signatureId = "signature-1";
	private static String signedPropertiesId =  signatureId + "_SignedProperties";

	public static void main(String[] args) throws Exception {

		
		byte[] xmlSignature = createXmlDocumentAndSign();
		//String temp = new String(xmlSignature);
		//System.out.println("XML signature: " + temp);
		
		// load public key from A-Trust server
		String sCertificate = readStringFromURL(baseURL + "/Certificate/Pem");	
		
		byte[] binaryBlob = encryptXmlSignature(xmlSignature, sCertificate);

		//String sCombined = Base64.getEncoder().encodeToString(binaryBlob);	
		//System.out.println(sCombined);
		
		int result = uploadIdentrecord(binaryBlob);

		if(200 == result) {
			System.out.println("add identrecord success!!!");
		}
		else {
			System.out.println("error add identrecord: " + Integer.toString(result));
		}
	}
	

	private static int uploadIdentrecord(byte[] postData) throws Exception
	{
		String postUrl = baseURL + "/Identification";
		CloseableHttpClient httpClient = HttpClients.createDefault();
		HttpPost httpPost = new HttpPost(postUrl);	
		httpPost.setEntity(new ByteArrayEntity(postData));
	
		CloseableHttpResponse httpResponse = httpClient.execute(httpPost);
		int statusCode = httpResponse.getStatusLine().getStatusCode();		
		httpClient.close();
		return statusCode;
	}
  
	private static String readStringFromURL(String requestURL) throws Exception {
		try (Scanner scanner = new Scanner(new URL(requestURL).openStream(), StandardCharsets.UTF_8.toString())) {
			scanner.useDelimiter("\\A");
			return scanner.hasNext() ? scanner.next() : "";
		}
	}

	private static byte[] encryptXmlSignature(byte[] xmlSignature, String certificate) throws Exception {

		// AES Key Generation
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(256); // for example
		SecretKey aeskey = keyGen.generateKey();	
		byte[] aeskeyBytes = aeskey.getEncoded();  	

			
		//System.out.println("A-Trust certificate: " + sCertificate);
		certificate = certificate.replaceAll("-----BEGIN CERTIFICATE-----", "");
		certificate = certificate.replaceAll("-----END CERTIFICATE-----", "");
		certificate = certificate.replaceAll("\r", "");
		certificate = certificate.replaceAll("\n", "");

		CertificateFactory cf = CertificateFactory.getInstance("X.509");		
		byte[] bCert = Base64.getDecoder().decode(certificate);
		ByteArrayInputStream is = new ByteArrayInputStream(bCert);
		Certificate atrustCert = cf.generateCertificate(is);
		PublicKey atrustPubKey = atrustCert.getPublicKey();

		// encrypt aes key with A-Trust public key
		Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
		rsaCipher.init(Cipher.ENCRYPT_MODE, atrustPubKey);
		byte[] keyBlob = rsaCipher.doFinal(aeskeyBytes);    
		//String sCipherData = Base64.getEncoder().encodeToString(keyBlob);	
		//System.out.println(sCipherData);
		
		// encrypt signed xml with aes gcm		
        byte[] iv = new byte[16];
		Arrays.fill( iv, (byte) 0x00 );
		
		Cipher aesGcmCipher = Cipher.getInstance("AES/GCM/NoPadding", "SunJCE");
		GCMParameterSpec spec = new GCMParameterSpec(16 * 8, iv);
        aesGcmCipher.init(Cipher.ENCRYPT_MODE, aeskey, spec);
		byte[] encXmlSignature = aesGcmCipher.doFinal(xmlSignature);
		
		//combine		
		byte[] combined = new byte[encXmlSignature.length + keyBlob.length];
		System.arraycopy(encXmlSignature,0,combined,0,encXmlSignature.length);
		System.arraycopy(keyBlob,0,combined,encXmlSignature.length,keyBlob.length);
		return combined;		
	}


	private static byte[] createXmlDocumentAndSign() throws Exception {
		
		// load p12
		KeyStore keystore = KeyStore.getInstance("pkcs12");
        keystore.load(new FileInputStream(signCert), signCertPwd.toCharArray());
		
		String keyAlias = ""; 
		for (Enumeration en = keystore.aliases(); en.hasMoreElements();) {
			String alias = (String)en.nextElement();
			if(keystore.isKeyEntry(alias)) {
				keyAlias = alias;
				break;
			}
		}

		PrivateKey privKey = (PrivateKey) keystore.getKey(keyAlias, signCertPwd.toCharArray());
		X509Certificate cert = (X509Certificate) keystore.getCertificate(keyAlias);

		// sign 
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance(); 
		dbf.setNamespaceAware(true);
		DocumentBuilder builder = dbf.newDocumentBuilder();  
		Document doc = builder.parse(new ByteArrayInputStream(sampleInputXml.getBytes())); 		
		XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM"); 
		
		// sign -- reference 1
		List<Transform> transforms1 = new ArrayList<Transform>();
		transforms1.add(fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null));
		transforms1.add(fac.newTransform(CanonicalizationMethod.INCLUSIVE, (TransformParameterSpec) null));
		
		Reference ref1 = fac.newReference("", 
			fac.newDigestMethod(DigestMethod.SHA256, null),
			transforms1, 
			null, 
			null); 
		
		
		// sign -- reference 2	
		List<Transform> transforms2 = new ArrayList<Transform>();
		transforms2.add(fac.newTransform(CanonicalizationMethod.INCLUSIVE, (TransformParameterSpec) null));
				
		Reference ref2 = fac.newReference("#object-1", //"#xpointer(id('object-1')/*/*)", //"#" + signedPropertiesId, // "#object-1"
			fac.newDigestMethod(DigestMethod.SHA256, null),
			transforms2, 
			"http://uri.etsi.org/01903/v1.1.1#SignedProperties",
			null); // "object-1_Reference"
		
		//Element qualifyingProperties = buildEtsiObject(builder, cert);		
		Element qualifyingProperties = buildEtsiObject(doc, cert);		
		DOMStructure qualifyingPropertiesStructure = new DOMStructure(qualifyingProperties);
		List<XMLStructure> xmlStructureList = new ArrayList<XMLStructure>();
		xmlStructureList.add(qualifyingPropertiesStructure);

		XMLObject obj = fac.newXMLObject(
			xmlStructureList, 
			"object-1", 
			null, 
			null);
			
		
		
		List<Reference> references = new ArrayList<Reference>();		
		references.add(ref1);
		references.add(ref2);

		List<XMLObject> objectList = new ArrayList<XMLObject>();
		objectList.add(obj);
		
		// sign -- signed info
		SignedInfo si = fac.newSignedInfo(fac.newCanonicalizationMethod
			(CanonicalizationMethod.INCLUSIVE,(C14NMethodParameterSpec) null),
			fac.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", null),
			references); 
		
		KeyInfoFactory kif = fac.getKeyInfoFactory(); 
		X509Data x509Data = kif.newX509Data(Collections.singletonList(cert));
		KeyInfo ki = kif.newKeyInfo(Collections.singletonList(x509Data)); 
		XMLSignature signature = fac.newXMLSignature(si, ki, objectList, signatureId, null); 
		
		// sign -- sign
		DOMSignContext dsc = new DOMSignContext(privKey, doc.getDocumentElement()); 
		dsc.setDefaultNamespacePrefix(dsig_prefix);
		//dsc.putNamespacePrefix(etsi_ns, etsi_prefix);
		signature.sign(dsc); 
		
		// sign -- output
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer trans = tf.newTransformer();
		trans.transform(new DOMSource(doc), new StreamResult(os)); 
		byte[] xmlSignature = os.toByteArray();
		return xmlSignature;
	}

	//private static Element buildEtsiObject(DocumentBuilder builder, X509Certificate cert) throws Exception {
		//Document doc = builder.newDocument();

	private static Element buildEtsiObject(Document doc, X509Certificate cert) throws Exception {

		OffsetDateTime now = OffsetDateTime.now();
		DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssZ");
		String signingTime = dtf.format(now); 
		
		String certDigestValue = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-1").digest(cert.getEncoded()));
		
		Principal principal = cert.getIssuerDN();
        String issuerDn = principal.getName();
		issuerDn = issuerDn.replaceAll(", ",",");
		
		String certSerial = cert.getSerialNumber().toString(10);

		Element qualifyingProperties = doc.createElementNS(etsi_ns, etsi_prefix + ":QualifyingProperties");		
		qualifyingProperties.setAttributeNS(null, "Target", "#"+signatureId);
		qualifyingProperties.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:" + dsig_prefix, dsig_ns);
		qualifyingProperties.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:" + etsi_prefix, etsi_ns);
		//qualifyingProperties.setAttributeNS(xmlns_ns, "xmlns:"+etsi_prefix, etsi_ns);
		//qualifyingProperties.setAttribute("xmlns:" + dsig_prefix, dsig_ns);		
		Element signedProperties = doc.createElementNS(etsi_ns, etsi_prefix + ":SignedProperties");
		signedProperties.setAttribute("Id", signedPropertiesId);
		qualifyingProperties.appendChild(signedProperties);	
	
		Element signedSignatureProperties = doc.createElementNS(etsi_ns, etsi_prefix + ":SignedSignatureProperties");
		signedProperties.appendChild(signedSignatureProperties);
		Element xmlSigningTime = doc.createElementNS(etsi_ns, etsi_prefix + ":SigningTime");
		signedSignatureProperties.appendChild(xmlSigningTime);	
		Text signingTime_txt = doc.createTextNode(signingTime);
		xmlSigningTime.appendChild(signingTime_txt);			
		Element signingCertificate = doc.createElementNS(etsi_ns, etsi_prefix + ":SigningCertificate");
		signedSignatureProperties.appendChild(signingCertificate);					
		Element xmlCert = doc.createElementNS(etsi_ns, etsi_prefix + ":Cert");
		signingCertificate.appendChild(xmlCert);			
		
		Element xmlCertDigest = doc.createElementNS(etsi_ns, etsi_prefix + ":CertDigest");
		xmlCert.appendChild(xmlCertDigest);			
		Element xmlDigestMethod = doc.createElementNS(etsi_ns, etsi_prefix + ":DigestMethod");		
		xmlCertDigest.appendChild(xmlDigestMethod);	
		xmlDigestMethod.setAttributeNS(null,"Algorithm","http://www.w3.org/2000/09/xmldsig#sha1");				
		Element xmlDigestValue = doc.createElementNS(etsi_ns, etsi_prefix + ":DigestValue");
		xmlCertDigest.appendChild(xmlDigestValue);	
		Text xmlDigestValue_txt = doc.createTextNode(certDigestValue);
		xmlDigestValue.appendChild(xmlDigestValue_txt);			
		
		
		Element xmlIssuerSerial = doc.createElementNS(etsi_ns, etsi_prefix + ":IssuerSerial");
		xmlCert.appendChild(xmlIssuerSerial);	

		Element xmlX509IssuerName = doc.createElementNS(dsig_ns, dsig_prefix + ":X509IssuerName");
		xmlIssuerSerial.appendChild(xmlX509IssuerName);	
		Text xmlX509IssuerName_txt = doc.createTextNode(issuerDn);
		xmlX509IssuerName.appendChild(xmlX509IssuerName_txt);	

		Element xmlX509SerialNumber = doc.createElementNS(dsig_ns, dsig_prefix + ":X509SerialNumber");
		xmlIssuerSerial.appendChild(xmlX509SerialNumber);	
		Text xmlX509SerialNumber_txt = doc.createTextNode(certSerial);
		xmlX509SerialNumber.appendChild(xmlX509SerialNumber_txt);

		return qualifyingProperties;
	}
}