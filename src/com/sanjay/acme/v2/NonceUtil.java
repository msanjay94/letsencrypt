package com.sanjay.acme.v2;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.HttpURLConnection;

import org.json.JSONException;
import org.json.JSONObject;

public class NonceUtil {
	private static final String NEW_NONCE_DIRECTORY_KEY = "newNonce";
	private static final String NONCE_VALUE_HEADER_NAME = "Replay-Nonce";
	
	static String fetchNonce() throws FileNotFoundException, IOException, JSONException {
		String directoryInfo = LEClient.readDirectoryInfo();
		JSONObject directoryInfoJson = new JSONObject(directoryInfo);
		String newNonceUrlString = directoryInfoJson.getString(NEW_NONCE_DIRECTORY_KEY);
		HttpURLConnection connection = HttpUtil.getConnection(newNonceUrlString);
		connection.setRequestMethod("HEAD");
		return fetchNonce(connection);
	}
	
	private static String fetchNonce(HttpURLConnection connection) {
		return connection.getHeaderField(NONCE_VALUE_HEADER_NAME);
	}
}