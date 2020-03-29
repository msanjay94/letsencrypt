package com.sanjay.acme.v2;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

import org.json.JSONException;
import org.json.JSONObject;

import com.sanjay.acme.v2.exceptions.AccountCreationException;
import com.sanjay.acme.v2.exceptions.ChallengeFailedException;
import com.sanjay.acme.v2.exceptions.FailedLocalValidationException;

public class HttpChallenge {

	private static final int HTTP_OK = 200;
	private static final int HTTP_REDIRECT = 301;
	private static final String CHALLENGE_URL_JSON_KEY = "url";
	private static final String ACME_HTTP_CHALLENGE_URL_PREFIX = "/.well-known/acme-challenge/";

	static void processHttpChallenge(JSONObject http01Challenge, String domainName, String authzUrl,
			String orderName) throws JSONException, InvalidKeySpecException, NoSuchAlgorithmException,
			FileNotFoundException, IOException, InvalidKeyException, SignatureException, ChallengeFailedException,
			FailedLocalValidationException, AccountCreationException {
		String token = http01Challenge.getString(AuthzUtil.TOKEN_JSON_KEY);
		KeyPair keyPair = KeyUtil.readKeys();
		String keyAuthorization = AuthzUtil.generateKeyAuthorization(token, keyPair.getPublic());
		String challengedUri = "http://" + domainName + ACME_HTTP_CHALLENGE_URL_PREFIX + token;
		validateChallengeLocal(challengedUri, token, keyAuthorization);
		JSONObject payload = new JSONObject();
		payload.put(AuthzUtil.KEY_AUTHORIZATION_JSON_KEY, keyAuthorization);
		URL accountUrl = new URL(AcmeAccount.readAccountUrl());
		String resourceUrl = http01Challenge.getString(CHALLENGE_URL_JSON_KEY);
		String nonce = NonceUtil.fetchNonce();
		String requestBody = JWSUtil.fetchJWS(keyPair, payload.toString(), nonce, resourceUrl, accountUrl);
		HttpURLConnection connection = HttpUtil.postData(resourceUrl, requestBody);
		int httpRepsonseCode = connection.getResponseCode();
		AuthzUtil.storeAuthz(authzUrl, orderName, PlaceOrder.ORDERS_FOLDER+orderName);
		if (httpRepsonseCode != HTTP_OK) {
			String error = "Non standard response code received: " + httpRepsonseCode;
			InputStream errorStream = connection.getErrorStream();
			if (errorStream != null) {
				error = StreamReader.readStream(errorStream);
			}
			throw new ChallengeFailedException(error);
		}
		System.out.println("Domain validated");
	}

	private static void validateChallengeLocal(final String challengedUri, final String token, final String keyAuthorization)
			throws MalformedURLException, IOException, FailedLocalValidationException {
		HttpURLConnection connection = HttpUtil
				.getConnection(challengedUri);
		int httpResponseCode = connection.getResponseCode();
		if (HTTP_REDIRECT == httpResponseCode) {
			String newUrl = connection.getHeaderField("Location");
			validateChallengeLocal(newUrl, token, keyAuthorization);
			return;
		}
		if (HTTP_OK != httpResponseCode) {
			throw new FailedLocalValidationException("Non standard response code received: " + httpResponseCode+". Expected: "+keyAuthorization);
		}
		String content = StreamReader.readStream(connection.getInputStream());
		if (!keyAuthorization.equals(content.trim())) {
			throw new FailedLocalValidationException("Expected : '" + keyAuthorization + "'. Got '" + content + "'");
		}
	}
}
