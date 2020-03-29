package com.sanjay.acme.v2;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.List;

public class LEClient {
	public static final String PROJECT_FOLDER = "/Users/sanjaykumar/Docs/LetsEncrypt/CSCI5409/";
//	private static final String ACME_V2_STAGING_DIRECTORY_URL = "https://acme-staging-v02.api.letsencrypt.org/directory";
	private static final String ACME_V2_PRODUCTION_DIRECTORY_URL = "https://acme-v02.api.letsencrypt.org/directory";
//	private static final String BUY_PASS_DIRECTORY_URL = "https://api.buypass.com/acme/directory";
	private static final String DIRECTORY_INFO_FILE = "directory.txt";
	
	static String readDirectoryInfo() throws FileNotFoundException, IOException {
		File file = new File(PROJECT_FOLDER+DIRECTORY_INFO_FILE);
		if (file.exists()) {
			return FileUtil.readFromFile(file);
		}
		return fetchDirectoryInfo();
	}
	
	private static String fetchDirectoryInfo() throws MalformedURLException, IOException {
		HttpURLConnection connection = HttpUtil.getConnection(ACME_V2_PRODUCTION_DIRECTORY_URL);
		String output = StreamReader.readStream(connection.getInputStream());
		File directoryFile = new File(PROJECT_FOLDER+DIRECTORY_INFO_FILE);
		FileUtil.writeToFile(directoryFile, output);
		return output;
	}
	
	public static void main(String[] args) {
		System.out.println("Start");
		try {
//			fetchDirectoryInfo();
//			1. Account Creation
//			AcmeAccount.createAccount();
//			2. Order Creation 
//			2.1 Wildcard domain
			List<String> domains = new ArrayList<>();
			domains.add("*.travelsca.com");
			domains.add("travelsca.com");
//			String orderName = "csci5409-project";
			String orderName = "csci5409-project-final";
//			2.2 FQDN
//			List<String> domains = new ArrayList<>();
//			domains.add("webtier.thandora.com");
//			String orderName = "le-fqdn-rsa-may-19";
//			String passPhrase = "bmserv";
//			PlaceOrder.placeOrder(orderName, domains, passPhrase);
//			3. Process order
//			String orderName = "le-fqdn-may-19";
			PlaceOrder.processOrder(orderName);
//			String token = "UQTKqxvrieD7YjE1mJSg5bgzE41OsfWvOF3PxiVwP08";
//			KeyPair keyPair = KeyUtil.readKeys();
//			String keyAuthorization = AuthzUtil.generateKeyAuthorization(token, keyPair.getPublic());
//			String recordValue = JWSUtil.base64UrlEncode(AuthzUtil.SHA256(keyAuthorization));
//			System.out.println(recordValue);
		} catch (Exception e) {
			e.printStackTrace();
		}
		System.out.println("Done");
	}
}
