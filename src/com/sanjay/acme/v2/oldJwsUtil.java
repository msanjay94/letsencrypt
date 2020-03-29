package com.sanjay.acme.v2;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

import org.json.JSONObject;

public class oldJwsUtil {
	static String fetchJWS(KeyPair keyPair, String payload, String nonce) throws Exception {
		// JWS is header.payload.signature
		String header = fetchJWSHeader(keyPair.getPublic(), nonce);
		System.out.println(header);
		String signingInput = base64UrlEncode(header.getBytes()) + "." + base64UrlEncode(payload.getBytes());
		byte[] signature = fetchSignedContent(keyPair.getPrivate(), signingInput);
		return signingInput + "." + base64UrlEncode(signature);
	}

	static String fetchBase64JwkThumbprint(PublicKey pubKey) throws Exception {
		JSONObject webKey = fetchJSONWebKey(pubKey);
		StringBuilder jwk = new StringBuilder();
		jwk.append("{\"e\":\"" + webKey.get("e") + "\",");
		jwk.append("\"kty\":\"" + webKey.get("kty") + "\",");
		jwk.append("\"n\":\"" + webKey.get("n") + "\"}");
		return base64UrlEncode(SHA256(jwk.toString()));
	}

	static byte[] SHA256(String text) throws Exception {
		MessageDigest md;
		md = MessageDigest.getInstance("SHA-256");
		md.update(text.getBytes("UTF-8"), 0, text.length()); // No I18n
		return md.digest();
	}

	static String base64UrlEncode(byte[] bytes) throws Exception {
		return new String(Base64.getUrlEncoder().encode(bytes)).replaceAll("=", "");
	}

	private static byte[] fetchSignedContent(PrivateKey privKey, String payload) throws Exception {
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initSign(privKey);
		signature.update(payload.getBytes());
		return signature.sign();
	}

	private static String fetchJWSHeader(PublicKey pubKey, String nonce) throws Exception {
		JSONObject header = new JSONObject();
		header.put("alg", "RS256");
		header.put("nonce", nonce);
		header.put("jwk", fetchJSONWebKey(pubKey));
		return header.toString();
	}

	private static JSONObject fetchJSONWebKey(PublicKey pubKey) throws Exception {
		JSONObject jwk = new JSONObject();
		jwk.put("e", base64UrlEncode(toIntegerBytes(((RSAPublicKey) pubKey).getPublicExponent())));
		jwk.put("kty", "RSA");
		jwk.put("n", base64UrlEncode(toIntegerBytes(((RSAPublicKey) pubKey).getModulus())));
		return new JSONObject(jwk.toString());
	}

	private static byte[] toIntegerBytes(final BigInteger bigInt) throws Exception {
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