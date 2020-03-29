package com.sanjay.acme.v2;

import java.math.BigInteger;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

import org.json.JSONException;
import org.json.JSONObject;

public class JWSUtil {
	private static final String PROTECTED_JWS_FIELD_KEY = "protected";
	private static final String PAYLOAD_JWS_FIELD_KEY = "payload";
	private static final String SIGNATURE_JWS_FIELD_KEY = "signature";
	
	static String fetchJWS(KeyPair keyPair, String payload, String nonce, String resourceUrl)
			throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, JSONException {
		String header = fetchJWSHeader(keyPair.getPublic(), nonce, resourceUrl);
		System.out.println(header);
		String signingInput = base64UrlEncode(header.getBytes()) + "." + base64UrlEncode(payload.getBytes());
		byte[] signature = fetchSignedContent(keyPair.getPrivate(), signingInput);
		JSONObject jws = new JSONObject();
		jws.put(PROTECTED_JWS_FIELD_KEY, base64UrlEncode(header.getBytes()));
		jws.put(PAYLOAD_JWS_FIELD_KEY, base64UrlEncode(payload.getBytes()));
		jws.put(SIGNATURE_JWS_FIELD_KEY, base64UrlEncode(signature));
		return jws.toString();
	}

	static String fetchJWS(KeyPair keyPair, String payload, String nonce, String resourceUrl, URL accountUrl)
			throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, JSONException {
		// JWS is header.payload.signature
		String header = fetchJWSHeader(accountUrl.toString(), nonce, resourceUrl);
		String signingInput = base64UrlEncode(header.getBytes()) + "." + base64UrlEncode(payload.getBytes());
		byte[] signature = fetchSignedContent(keyPair.getPrivate(), signingInput);
		JSONObject jws = new JSONObject();
		jws.put(PROTECTED_JWS_FIELD_KEY, base64UrlEncode(header.getBytes()));
		jws.put(PAYLOAD_JWS_FIELD_KEY, base64UrlEncode(payload.getBytes()));
		jws.put(SIGNATURE_JWS_FIELD_KEY, base64UrlEncode(signature));
		return jws.toString();
	}

	static String base64UrlEncode(byte[] bytes) {
		return new String(Base64.getUrlEncoder().encode(bytes)).replaceAll("=", "");
	}

	private static byte[] fetchSignedContent(PrivateKey privKey, String payload)
			throws InvalidKeyException, SignatureException, NoSuchAlgorithmException {
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initSign(privKey);
		signature.update(payload.getBytes());
		return signature.sign();
	}

	private static String fetchJWSHeader(PublicKey pubKey, String nonce, String resourceUrl) throws JSONException {
		JSONObject header = new JSONObject();
		header.put("alg", "RS256");
		header.put("nonce", nonce);
		header.put("jwk", fetchJSONWebKey(pubKey));
		header.put("url", resourceUrl);
		return header.toString();
	}

	private static String fetchJWSHeader(String accountUrl, String nonce, String resourceUrl) throws JSONException {
		JSONObject header = new JSONObject();
		header.put("alg", "RS256");
		header.put("nonce", nonce);
		header.put("kid", accountUrl);
		header.put("url", resourceUrl);
		return header.toString();
	}

	static JSONObject fetchJSONWebKey(PublicKey pubKey) throws JSONException {
		JSONObject jwk = new JSONObject();
		jwk.put("e", base64UrlEncode(toIntegerBytes(((RSAPublicKey) pubKey).getPublicExponent())));
		jwk.put("kty", "RSA");
		jwk.put("n", base64UrlEncode(toIntegerBytes(((RSAPublicKey) pubKey).getModulus())));
		return new JSONObject(jwk.toString());
	}

	private static byte[] toIntegerBytes(final BigInteger bigInt) {
		int bitlen = bigInt.bitLength();
		// round bitlen
		bitlen = ((bitlen + 7) >> 3) << 3;
		final byte[] bigBytes = bigInt.toByteArray();
		if (((bigInt.bitLength() % 8) != 0) && (((bigInt.bitLength() / 8) + 1) == (bitlen / 8))) {
			return bigBytes;
		}
		// set up params for copying everything but sign bit
		int startSrc = 0;
		int len = bigBytes.length;
		// if bigInt is exactly byte-aligned, just skip signbit in copy
		if ((bigInt.bitLength() % 8) == 0) {
			startSrc = 1;
			len--;
		}
		final int startDst = bitlen / 8 - len; // to pad w/ nulls as per spec
		final byte[] resizedBytes = new byte[bitlen / 8];
		System.arraycopy(bigBytes, startSrc, resizedBytes, startDst, len);
		return resizedBytes;
	}
}
