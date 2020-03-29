package com.sanjay.acme.v2;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.sanjay.acme.v2.exceptions.AIAFieldNotFoundException;
import com.sanjay.acme.v2.exceptions.AccountCreationException;
import com.sanjay.acme.v2.exceptions.InvalidOrderException;
import com.sanjay.acme.v2.exceptions.OrderCreationException;
import com.sanjay.acme.v2.exceptions.OrderNameExistsException;
import com.sanjay.acme.v2.exceptions.OrderNotFoundException;

public class PlaceOrder {
	private static final String NEW_ORDER_DIRECTORY_KEY = "newOrder";
	static final String ORDERS_FOLDER = LEClient.PROJECT_FOLDER + "orders/";
	private static final String IDENTIFIERS_PAYLOAD_KEY = "identifiers";
	private static final String AUTHORIZATIONS_JSON_KEY = "authorizations";
	static final String IDENTIFIER_TYPE_KEY = "type";
	private static final String DNS_TYPE_IDENTIFIER = "dns";
	static final String IDENTIFIER_VALUE_KEY = "value";
	private static final int ORDER_CREATED_RESPONSE_CODE = 201;
	private static final int HTTP_OK = 200;
	private static final String FINALIZE_PURCHASE_JSON_KEY = "finalize";
	private static final String CERTS_FOLDER_NAME = "/certs/";
	private static final String KEYS_FOLDER_NAME = "/keys/";
	private static final String CSR_PAYLOAD_KEY = "csr";
	private static final String STATUS_JSON_KEY = "status";
	private static final String VALID_STATUS = "valid";
	private static final String READY_STATUS = "ready";
	private static final String PENDING_STATUS = "pending";
	private static final String INVALID_STATUS = "invalid";
	private static final String PROCESSING_STATUS = "processing";
	private static final String CERTIFICATE_JSON_KEY = "certificate";
	private static final ASN1ObjectIdentifier OCSP_ISSUER_CERT_URI_OID = X509ObjectIdentifiers.id_ad_caIssuers;
	private static final int MAX_TRIES = 5;

	static void processOrder(String orderName) throws OrderNotFoundException, FileNotFoundException, JSONException,
			IOException, InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException, SignatureException,
			ParseException, OperatorCreationException, AccountCreationException, OrderCreationException,
			InvalidOrderException, CertificateException, AIAFieldNotFoundException, InterruptedException,
			InvalidAlgorithmParameterException, NoSuchProviderException {
		processOrder(orderName, 0);
	}

	static void processOrder(String orderName, int tries) throws OrderNotFoundException, FileNotFoundException,
			JSONException, IOException, InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException,
			SignatureException, ParseException, OperatorCreationException, AccountCreationException,
			OrderCreationException, InvalidOrderException, CertificateException, AIAFieldNotFoundException,
			InterruptedException, InvalidAlgorithmParameterException, NoSuchProviderException {
		File order = new File(ORDERS_FOLDER + orderName + "/order");
		String orderFolder = ORDERS_FOLDER + orderName;
		if (!order.exists()) {
			throw new OrderNotFoundException("Order not found");
		}
		JSONObject orderJson = new JSONObject(FileUtil.readFromFile(order));
		String status = orderJson.getString(STATUS_JSON_KEY);
		if (INVALID_STATUS.equals(status)) {
			throw new InvalidOrderException("Invalid order");
		} else if (PENDING_STATUS.equals(status) || READY_STATUS.equals(status)) {
			JSONArray authorizations = orderJson.getJSONArray(AUTHORIZATIONS_JSON_KEY);
			for (int i = 0; i < authorizations.length(); i++) {
				String authzUrl = authorizations.getString(i);
				AuthzUtil.storeAuthz(authzUrl, orderName, orderFolder);
			}
			boolean valid = AuthzUtil.validateAllAuthz(orderFolder);
			if (valid) {
				System.out.println("All authorizations validated. Proceed to certificate purchase.");
				String orderUrl = orderJson.getString("location");
				String passPhrase = orderJson.getString("passphrase");
				storeOrder(orderUrl, orderName, passPhrase);
				purchaseCertificate(orderJson, orderName, orderFolder);
			}
		} else if (VALID_STATUS.equals(status)) {
			getCertificate(orderJson, orderName, orderFolder);
		} else if (PROCESSING_STATUS.equals(status)) {
			if (tries == MAX_TRIES) {
				System.out.println("Max tries " + MAX_TRIES + " hit. Stopping.");
				return;
			}
			System.out.println("Status Processing. Wait for 5 seconds");
			tries++;
			Thread.sleep(5000);
			String orderUrl = orderJson.getString("location");
			String passPhrase = orderJson.getString("passphrase");
			storeOrder(orderUrl, orderName, passPhrase);
			processOrder(orderName, tries);
		} else {
			throw new InvalidOrderException("Status: " + status);
		}
	}

	private static X509Certificate convertBytesToCertificate(byte[] certBytes) throws CertificateException {
		return (X509Certificate) CertificateFactory.getInstance("X509")
				.generateCertificate(new ByteArrayInputStream(certBytes));
	}

	private static String getIssuerCertURI(X509Certificate certificate) throws AIAFieldNotFoundException, IOException {
		return getAIAField(certificate, OCSP_ISSUER_CERT_URI_OID);
	}

	private static String getAIAField(X509Certificate certificate, ASN1ObjectIdentifier oid)
			throws IOException, AIAFieldNotFoundException {
		byte[] octetBytes = certificate.getExtensionValue(Extension.authorityInfoAccess.getId());
		if (octetBytes == null) {
			throw new AIAFieldNotFoundException("Certificate does not contain Authority Information Access field");
		}
		byte[] encoded = X509ExtensionUtil.fromExtensionValue(octetBytes).getEncoded();
		ASN1Sequence seq = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(encoded));
		AuthorityInformationAccess access = AuthorityInformationAccess.getInstance(seq);
		for (AccessDescription accessDescription : access.getAccessDescriptions()) {
			if (accessDescription.getAccessMethod().equals(oid)) {
				return accessDescription.getAccessLocation().getName().toString();
			}
		}
		return null;
	}

	private static String convertToPem(X509Certificate certificate) throws IOException {
		StringWriter stringWriter = new StringWriter();
		JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter);
		pemWriter.writeObject(certificate);
		pemWriter.close();
		stringWriter.close();
		return stringWriter.toString();
	}

	private static void getCertificate(JSONObject orderJson, String orderName, String orderFolder)
			throws JSONException, MalformedURLException, IOException, CertificateException, AIAFieldNotFoundException {
		File certificateFile = new File(orderFolder + CERTS_FOLDER_NAME + orderName + ".pem");
		String certificateUrl = orderJson.getString(CERTIFICATE_JSON_KEY);
		HttpURLConnection connection = HttpUtil.getConnection(certificateUrl);
		byte[] pemCertificate = IOUtils.toByteArray(connection.getInputStream());
		StringBuilder certificateContent = new StringBuilder(new String(pemCertificate)).append(System.lineSeparator());
		// Getting leaf certificate - might not be necessary soon when LE sends full
		// chain in the first place
		X509Certificate leafCertificate = convertBytesToCertificate(pemCertificate);
		String issuerCertUrl = getIssuerCertURI(leafCertificate);
		connection = HttpUtil.getConnection(issuerCertUrl);
		byte[] issuerCertificatePem = IOUtils.toByteArray(connection.getInputStream());
		certificateContent.append(convertToPem(convertBytesToCertificate(issuerCertificatePem)));
		FileUtil.writeToFile(certificateFile, certificateContent.toString(), true);
	}

	private static void purchaseCertificate(JSONObject orderJson, String orderName, String orderFolder)
			throws OrderNotFoundException, JSONException, NoSuchAlgorithmException, IOException,
			OperatorCreationException, InvalidKeySpecException, InvalidKeyException, SignatureException,
			AccountCreationException, OrderCreationException, InvalidAlgorithmParameterException,
			NoSuchProviderException {
		JSONArray identifiers = orderJson.getJSONArray(IDENTIFIERS_PAYLOAD_KEY);
		Set<String> domains = new HashSet<>();
		for (int i = 0; i < identifiers.length(); i++) {
			JSONObject identifier = identifiers.getJSONObject(i);
			String domainName = identifier.getString(IDENTIFIER_VALUE_KEY);
			domains.add(domainName);
		}
		String resourceUrl = orderJson.getString(FINALIZE_PURCHASE_JSON_KEY);
		KeyPair certKeyPair = KeyUtil.generateEcdsaKey();
//		KeyPair certKeyPair = KeyUtil.generateKey();
		KeyUtil.writeEncryptedPrivateKey(certKeyPair.getPrivate(), orderFolder + KEYS_FOLDER_NAME, orderName,
				orderJson.getString("passphrase"));
		CSRUtil csrUtil = new CSRUtil(domains, certKeyPair);
		PKCS10CertificationRequest csr = csrUtil.generateCSR();
		JSONObject payload = new JSONObject();
		payload.put(CSR_PAYLOAD_KEY, JWSUtil.base64UrlEncode(csr.getEncoded()));
		String nonce = NonceUtil.fetchNonce();
		KeyPair keyPair = KeyUtil.readKeys();
		String accountUrl = AcmeAccount.readAccountUrl();
		String requestBody = JWSUtil.fetchJWS(keyPair, payload.toString(), nonce, resourceUrl, new URL(accountUrl));
		HttpURLConnection connection = HttpUtil.postData(resourceUrl, requestBody);
		int httpResponseCode = connection.getResponseCode();
		if (HTTP_OK != httpResponseCode) {
			String error = "Non standard repsonse code received: " + httpResponseCode;
			InputStream errorStream = connection.getErrorStream();
			if (errorStream != null) {
				error = StreamReader.readStream(errorStream);
			}
			throw new OrderCreationException(error);
		}
		String location = orderJson.getString("location");
		String passphrase = orderJson.getString("passphrase");
		connection = HttpUtil.getConnection(location);
		String content = StreamReader.readStream(connection.getInputStream());
		orderJson = new JSONObject(content);
		orderJson.put("location", location);
		orderJson.put("passphrase", passphrase);
		FileUtil.writeToFile(new File(orderFolder + "/" + orderName), orderJson.toString());
	}

	static String placeOrder(String orderName, List<String> domains, String passPhrase)
			throws JSONException, InvalidKeyException, MalformedURLException, FileNotFoundException,
			InvalidKeySpecException, NoSuchAlgorithmException, SignatureException, IOException,
			AccountCreationException, OrderNameExistsException, OrderCreationException {
		File orderFile = new File(ORDERS_FOLDER + orderName + "/order");
		if (orderFile.exists()) {
			throw new OrderNameExistsException("Order with name already exists");
		}
		KeyPair keyPair = KeyUtil.readKeys();
		String nonce = NonceUtil.fetchNonce();
		JSONObject directoryInfo = new JSONObject(LEClient.readDirectoryInfo());
		String newOrderUrl = directoryInfo.getString(NEW_ORDER_DIRECTORY_KEY);
		URL accountUrl = new URL(AcmeAccount.readAccountUrl());
		String payload = generatePayload(domains);
		String requestBody = JWSUtil.fetchJWS(keyPair, payload, nonce, newOrderUrl, accountUrl);
		HttpURLConnection connection = HttpUtil.postData(newOrderUrl, requestBody);
		int httpResponseCode = connection.getResponseCode();
		if (httpResponseCode == ORDER_CREATED_RESPONSE_CODE) {
			String content = StreamReader.readStream(connection.getInputStream());
			String orderUrl = connection.getHeaderField("Location");
			System.out.println("Order created - " + orderUrl);
			JSONObject json = new JSONObject(content);
			json.put("location", orderUrl);
			json.put("passphrase", passPhrase);
			FileUtil.writeToFile(orderFile, json.toString());
			return orderUrl;
		}
		String error = "Non standard http response code received: " + httpResponseCode;
		InputStream errorStream = connection.getErrorStream();
		if (errorStream != null) {
			error = StreamReader.readStream(errorStream);
		}
		throw new OrderCreationException(error);
	}

	static void storeOrder(String orderUrl, String orderName, String passPhrase) throws IOException, JSONException {
		HttpURLConnection connection = HttpUtil.getConnection(orderUrl);
		String content = StreamReader.readStream(connection.getInputStream());
		JSONObject json = new JSONObject(content);
		json.put("location", orderUrl);
		json.put("passphrase", passPhrase);
		File orderFile = new File(ORDERS_FOLDER + orderName + "/order");
		FileUtil.writeToFile(orderFile, json.toString());
	}

	private static String generatePayload(List<String> domains) throws JSONException {
		JSONObject payload = new JSONObject();
		JSONArray identifiers = new JSONArray();
		for (String domain : domains) {
			JSONObject identifier = new JSONObject();
			identifier.put(IDENTIFIER_TYPE_KEY, DNS_TYPE_IDENTIFIER);
			identifier.put(IDENTIFIER_VALUE_KEY, domain);
			identifiers.put(identifier);
		}
		payload.put(IDENTIFIERS_PAYLOAD_KEY, identifiers);
		return payload.toString();
	}
}
