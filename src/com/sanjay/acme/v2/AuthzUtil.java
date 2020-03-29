package com.sanjay.acme.v2;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.sanjay.acme.v2.exceptions.AccountCreationException;
import com.sanjay.acme.v2.exceptions.AuthorizationNotFoundException;
import com.sanjay.acme.v2.exceptions.ChallengeFailedException;
import com.sanjay.acme.v2.exceptions.ChallengeNotFoundException;
import com.sanjay.acme.v2.exceptions.CustomException;
import com.sanjay.acme.v2.exceptions.ExpiredAuthorizationException;
import com.sanjay.acme.v2.exceptions.FailedLocalValidationException;
import com.sanjay.acme.v2.exceptions.InvalidAuthorizationException;

public class AuthzUtil {
	private static final String WILDCARD_JSON_KEY = "wildcard";
	private static final String IDENTIFIER_JSON_KEY = "identifier";
	static final String TOKEN_JSON_KEY = "token";
	static final String AUTHZ_FOLDER_NAME = "/authz/";
	static final String KEY_AUTHORIZATION_JSON_KEY = "keyAuthorization";
	private static final String CHALLENGES_JSON_KEY = "challenges";
	private static final String STATUS_JSON_KEY = "status";
	private static final String VALID_AUTHZ = "valid";
	private static final String INVALID_AUTHZ = "invalid";
	private static final String EXPIRES_JSON_KEY = "expires";
	private static final String HTTP_CHALLENGE_KEY = "http-01";
	private static final String DNS_CHALLENGE_KEY = "dns-01";
	private static final SimpleDateFormat STANDARD_DATE_TIME_FORMAT = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");

	static void storeAuthz(String authzUrl, String orderName, String orderFolder) throws IOException, JSONException {
		HttpURLConnection connection = HttpUtil.getConnection(authzUrl);
		String content = StreamReader.readStream(connection.getInputStream());
		JSONObject authzContent = new JSONObject(content);
		authzContent.put("location", authzUrl);
		authzContent.put("orderName", orderName);
		boolean isWildcardDomain = false;
		if (authzContent.has(WILDCARD_JSON_KEY)) {
			isWildcardDomain = authzContent.getBoolean(WILDCARD_JSON_KEY);
		}
		String fileName = authzContent.getJSONObject(IDENTIFIER_JSON_KEY).getString(PlaceOrder.IDENTIFIER_VALUE_KEY)
				+ isWildcardDomain;
		FileUtil.writeToFile(new File(orderFolder + "/" + AUTHZ_FOLDER_NAME + fileName), authzContent.toString());
	}

	static boolean validateAllAuthz(String ordersFolder)
			throws InvalidKeyException, FileNotFoundException, InvalidKeySpecException, NoSuchAlgorithmException,
			SignatureException, IOException, JSONException, ParseException {
		File authzFolder = new File(ordersFolder+AUTHZ_FOLDER_NAME);
		File[] authz = authzFolder.listFiles();
		boolean valid = true;
		for (File file : authz) {
			try {
				validateAuthz(file);
			} catch (CustomException e) {
				System.out.println("Error: "+e.getMessage());
				valid = false;
			}
		}
		return valid;
	}

	private static void validateAuthz(File authzFile)
			throws FileNotFoundException, IOException, AuthorizationNotFoundException, JSONException,
			InvalidAuthorizationException, ParseException, ExpiredAuthorizationException, ChallengeNotFoundException,
			InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException, SignatureException,
			ChallengeFailedException, FailedLocalValidationException, AccountCreationException {
		if (!authzFile.exists()) {
			throw new AuthorizationNotFoundException("Authz not found");
		}
		String authzContent = FileUtil.readFromFile(authzFile);
		JSONObject authzJson = new JSONObject(authzContent);
		String domainName = authzJson.getJSONObject(IDENTIFIER_JSON_KEY).getString(PlaceOrder.IDENTIFIER_VALUE_KEY);
		String authzUrl = authzJson.getString("location");
		String orderName = authzJson.getString("orderName");
		String status = authzJson.getString(STATUS_JSON_KEY);
		if (INVALID_AUTHZ.equals(status)) {
			throw new InvalidAuthorizationException("Invalid");
		}
		String expires = authzJson.getString(EXPIRES_JSON_KEY);
		STANDARD_DATE_TIME_FORMAT.setTimeZone(TimeZone.getTimeZone("UTC"));
		Date date = STANDARD_DATE_TIME_FORMAT.parse(expires);
		if (date.getTime() < System.currentTimeMillis()) {
			throw new ExpiredAuthorizationException("Expired");
		}
		if (VALID_AUTHZ.equals(authzJson.getString(STATUS_JSON_KEY))) {
			System.out.println("Domain already valid");
			return;
		}
		JSONArray challenges = authzJson.getJSONArray(CHALLENGES_JSON_KEY);
		for (int i = 0; i < challenges.length(); i++) {
			JSONObject challenge = challenges.getJSONObject(i);
			String type = challenge.getString(PlaceOrder.IDENTIFIER_TYPE_KEY);
			if (HTTP_CHALLENGE_KEY.equals(type)) {
				System.out.println("Validating domain - " + domainName + " using HTTP Challenge method");
				try {
					HttpChallenge.processHttpChallenge(challenge, domainName, authzUrl, orderName);
				} catch(CustomException e) {
					System.out.println("HTTP Validation failed: "+e.getMessage());
					continue;
				}
				return;
			} else if (DNS_CHALLENGE_KEY.equals(type)) {
				System.out.println("Validating domain - " + domainName + " using DNS Challenge method");
				try {
					DNSChallenge.processDNSChallenge(challenge, domainName, authzUrl, orderName);
				} catch(CustomException e) {
					System.out.println("DNS Validation failed: "+e.getMessage());
					continue;
				}
				return;
			}
		}
		throw new ChallengeNotFoundException("None of the known challenge types succeeded.");
	}

	static String generateKeyAuthorization(String token, PublicKey publicKey)
			throws NoSuchAlgorithmException, UnsupportedEncodingException, JSONException {
		StringBuilder keyAuthorization = new StringBuilder();
		keyAuthorization.append(token);
		String jwk = fetchBase64JwkThumbprint(publicKey);
		keyAuthorization.append(".").append(jwk);
		return keyAuthorization.toString();
	}

	private static String fetchBase64JwkThumbprint(PublicKey pubKey)
			throws NoSuchAlgorithmException, UnsupportedEncodingException, JSONException {
		JSONObject webKey = JWSUtil.fetchJSONWebKey(pubKey);
		StringBuilder jwk = new StringBuilder();
		jwk.append("{\"e\":\"" + webKey.get("e") + "\",");
		jwk.append("\"kty\":\"" + webKey.get("kty") + "\",");
		jwk.append("\"n\":\"" + webKey.get("n") + "\"}");
		return JWSUtil.base64UrlEncode(SHA256(jwk.toString()));
	}

	static byte[] SHA256(String text) throws NoSuchAlgorithmException, UnsupportedEncodingException {
		MessageDigest md;
		md = MessageDigest.getInstance("SHA-256");
		md.update(text.getBytes("UTF-8"), 0, text.length()); // No I18n
		return md.digest();
	}
}
