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
import java.util.List;

import org.json.JSONException;
import org.json.JSONObject;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Record;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.Type;

import com.sanjay.acme.v2.exceptions.AccountCreationException;
import com.sanjay.acme.v2.exceptions.ChallengeFailedException;
import com.sanjay.acme.v2.exceptions.FailedLocalValidationException;

public class DNSChallenge {
	private static final int DNS_LOOKUP_SUCCESSFUL = 0;
	private static final String TXT_RECORD_NAME_PREFIX = "_acme-challenge.";
	private static final String CHALLENGE_URL_JSON_KEY = "url";
	private static final int HTTP_OK = 200;
	
	static void processDNSChallenge(JSONObject dns01Challenge, String domainName, String authzUrl,
			String orderName) throws JSONException, InvalidKeySpecException, NoSuchAlgorithmException,
			FileNotFoundException, IOException, InvalidKeyException, SignatureException, ChallengeFailedException,
			FailedLocalValidationException, AccountCreationException {
		String token = dns01Challenge.getString(AuthzUtil.TOKEN_JSON_KEY);
		KeyPair keyPair = KeyUtil.readKeys();
		String keyAuthorization = AuthzUtil.generateKeyAuthorization(token, keyPair.getPublic());
		String recordName = TXT_RECORD_NAME_PREFIX+domainName+".";
		String recordValue = JWSUtil.base64UrlEncode(AuthzUtil.SHA256(keyAuthorization));
		validateChallengeLocal(recordName, recordValue);
		JSONObject payload = new JSONObject();
		payload.put(AuthzUtil.KEY_AUTHORIZATION_JSON_KEY, keyAuthorization);
		URL accountUrl = new URL(AcmeAccount.readAccountUrl());
		String resourceUrl = dns01Challenge.getString(CHALLENGE_URL_JSON_KEY);
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

	private static void validateChallengeLocal(final String recordName, final String recordValue)
			throws MalformedURLException, IOException, FailedLocalValidationException {
		final Lookup dnsQuery = new Lookup(recordName, Type.TXT);
		final Record[] records = dnsQuery.run();
		final int result = dnsQuery.getResult();
		if (result != DNS_LOOKUP_SUCCESSFUL) {
			throw new FailedLocalValidationException("DNS Lookup for "+recordName+" failed. Expected TXT record: "+recordValue);
		}
		for (Record record : records) {
			final TXTRecord txtRecord = (TXTRecord) record;
			@SuppressWarnings("unchecked")
			final List<String> iterator = txtRecord.getStrings();
			for (String value : iterator) {
				if (recordValue.equals(value)) {
					return;
				}
			}
		}
		throw new FailedLocalValidationException("Expected record '"+recordName+" 300 IN TXT \""+recordValue+"\"'");
	}

}
