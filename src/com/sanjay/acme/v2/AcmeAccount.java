package com.sanjay.acme.v2;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.sanjay.acme.v2.exceptions.AccountCreationException;

public class AcmeAccount {
	private static final String NEW_ACCOUNT_DIRECTORY_KEY = "newAccount";
	private static final String CONTACT_ADDRESS = "mailto:m.sanjay94@gmail.com";
	private static final boolean TERMS_OF_SERVICE_AGREED = true;
	private static final String CONTACT_JSON_KEY = "contact";
	private static final String TERMS_OF_SERVICE_JSON_KEY = "termsOfServiceAgreed";
	private static final int ACCOUNT_CREATED_RESPONSE_CODE = 201;
	private static final int ACCOUNT_ALREADY_EXISTS_RESPONSE_CODE = 200;
	private static final String ACCOUNT_URL_FILE = LEClient.PROJECT_FOLDER + "accountUrl.txt";

	static String readAccountUrl() throws InvalidKeyException, FileNotFoundException, InvalidKeySpecException,
			NoSuchAlgorithmException, SignatureException, IOException, JSONException, AccountCreationException {
		File file = new File(ACCOUNT_URL_FILE);
		if (file.exists()) {
			String content = FileUtil.readFromFile(file);
			if (!content.isEmpty()) {
				return content;
			}
		}
		return createAccount();
	}

	static String createAccount() throws FileNotFoundException, IOException, JSONException, InvalidKeySpecException,
			NoSuchAlgorithmException, InvalidKeyException, SignatureException, AccountCreationException {
		String directoryInfo = LEClient.readDirectoryInfo();
		JSONObject directoryInfoJson = new JSONObject(directoryInfo);
		String urlString = directoryInfoJson.getString(NEW_ACCOUNT_DIRECTORY_KEY);
		String nonce = NonceUtil.fetchNonce();
		KeyPair accountKey = KeyUtil.readKeys();
		JSONArray contacts = new JSONArray();
		contacts.put(CONTACT_ADDRESS);
		JSONObject payload = new JSONObject();
		payload.put(CONTACT_JSON_KEY, contacts);
		payload.put(TERMS_OF_SERVICE_JSON_KEY, TERMS_OF_SERVICE_AGREED);
		String requestBody = JWSUtil.fetchJWS(accountKey, payload.toString(), nonce, urlString);
		HttpURLConnection connection = HttpUtil.postData(urlString, requestBody);
		int httpResponseCode = connection.getResponseCode();
		HttpUtil.printHeaders(connection);
		if (httpResponseCode == ACCOUNT_CREATED_RESPONSE_CODE) {
			System.out.println("Account created");
			String accountUrl = connection.getHeaderField("Location");
			FileUtil.writeToFile(new File(ACCOUNT_URL_FILE), accountUrl);
			return accountUrl;
		} else if (httpResponseCode == ACCOUNT_ALREADY_EXISTS_RESPONSE_CODE) {
			System.out.println("Account already exists with this key");
			String accountUrl = connection.getHeaderField("Location");
			FileUtil.writeToFile(new File(ACCOUNT_URL_FILE), accountUrl);
			return accountUrl;
		} else {
			InputStream errorStream = connection.getErrorStream();
			String error = "Non standard http response code received: " + httpResponseCode;
			if (errorStream != null) {
				error = StreamReader.readStream(errorStream);
			}
			throw new AccountCreationException(error);
		}
	}
}
