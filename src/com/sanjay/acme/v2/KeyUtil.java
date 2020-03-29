package com.sanjay.acme.v2;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

public class KeyUtil {
	private static final int DEFAULT_KEY_SIZE = 4096;
	private static final int ECDSA_KEY_SIZE = 256;
	private static final String DEFAULT_ALGORITHM = "RSA";
	private static final String ECDSA_ALGORITHM = "EC";
	private static final String KEYS_FOLDER = LEClient.PROJECT_FOLDER + "keys/";
	private static final String PUB_KEY_FILE = "pub.key";
	private static final String PRIV_KEY_FILE = "priv.key";

	static KeyPair readKeys()
			throws InvalidKeySpecException, NoSuchAlgorithmException, FileNotFoundException, IOException {
		if (!isKeyAvailable()) {
			return generateKey(true);
		}
		KeyPair keyPair = null;
		byte[] publicKey = readPublicKey();
		byte[] privateKey = readPrivateKey();
		KeyFactory keyFactory = KeyFactory.getInstance(DEFAULT_ALGORITHM);
		PublicKey pubKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKey));
		PrivateKey privKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKey));
		keyPair = new KeyPair(pubKey, privKey);
		return keyPair;
	}

	// will be used to write certificate's private key into file
	static void writeEncryptedPrivateKey(PrivateKey privKey, String folderName, String orderName, String passPhrase)
			throws IOException, OperatorCreationException {
		JceOpenSSLPKCS8EncryptorBuilder encryptorBuilder = new JceOpenSSLPKCS8EncryptorBuilder(
				PKCS8Generator.PBE_SHA1_3DES);
		encryptorBuilder.setPasssword(passPhrase.toCharArray());
		OutputEncryptor oe = encryptorBuilder.build();
		JcaPKCS8Generator gen = new JcaPKCS8Generator(privKey, oe);
		PemObject pem = gen.generate();
		File privateKeyFile = new File(folderName + orderName + ".key");
		privateKeyFile.getParentFile().mkdirs();
		if (privateKeyFile.exists()) {
			FileUtils.copyFile(privateKeyFile,
					new File(privateKeyFile.getAbsolutePath() + "-" + System.currentTimeMillis()));
		}
		PemWriter pemWrt = new PemWriter(new FileWriter(privateKeyFile));
		pemWrt.writeObject(pem);
		pemWrt.close();
	}

	private static boolean isKeyAvailable() {
		return new File(KEYS_FOLDER + PUB_KEY_FILE).exists() && new File(KEYS_FOLDER + PRIV_KEY_FILE).exists();
	}

	private static byte[] readPublicKey() throws FileNotFoundException, IOException {
		File pubKeyFile = new File(KEYS_FOLDER + PUB_KEY_FILE);
		return IOUtils.toByteArray(new FileInputStream(pubKeyFile));
	}

	private static byte[] readPrivateKey() throws FileNotFoundException, IOException {
		File privKeyFile = new File(KEYS_FOLDER + PRIV_KEY_FILE);
		return IOUtils.toByteArray(new FileInputStream(privKeyFile));
	}

	// generate keypair for certificate ( cert and account keys shouldn't be same )
	static KeyPair generateKey() throws NoSuchAlgorithmException, IOException {
		return generateKey(false);
	}

	static KeyPair generateEcdsaKey()
			throws NoSuchAlgorithmException, IOException, InvalidAlgorithmParameterException, NoSuchProviderException {
		return generateEcdsaKey(false);
	}

	private static KeyPair generateKey(boolean writeToFile) throws NoSuchAlgorithmException, IOException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(DEFAULT_ALGORITHM);
		keyGen.initialize(DEFAULT_KEY_SIZE);
		KeyPair keyPair = keyGen.genKeyPair();
		if (writeToFile) {
			writeKeys(keyPair);
		}
		return keyPair;
	}

	private static KeyPair generateEcdsaKey(boolean writeToFile)
			throws NoSuchAlgorithmException, IOException, InvalidAlgorithmParameterException, NoSuchProviderException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ECDSA_ALGORITHM, new BouncyCastleProvider());
		keyGen.initialize(ECDSA_KEY_SIZE);
		keyGen.initialize(new ECGenParameterSpec("prime256v1"), new SecureRandom());
		KeyPair keyPair = keyGen.generateKeyPair();
		return keyPair;
	}

	// write keys
	private static void writeKeys(KeyPair keyPair) throws IOException {
		writePublicKey(keyPair);
		writePrivateKey(keyPair);
	}

	// write public key
	private static void writePublicKey(KeyPair keyPair) throws IOException {
		File pubKeyFile = new File(KEYS_FOLDER + PUB_KEY_FILE);
		FileOutputStream fos = null;
		try {
			if (pubKeyFile.exists()) {
				pubKeyFile.delete();
			}
			pubKeyFile.getParentFile().mkdirs();
			pubKeyFile.createNewFile();
			fos = new FileOutputStream(pubKeyFile);
			fos.write(keyPair.getPublic().getEncoded());
		} finally {
			fos.close();
		}
	}

	// write private key
	private static void writePrivateKey(KeyPair keyPair) throws IOException {
		File pubKeyFile = new File(KEYS_FOLDER + PRIV_KEY_FILE);
		FileOutputStream fos = null;
		try {
			if (pubKeyFile.exists()) {
				pubKeyFile.delete();
			}
			pubKeyFile.getParentFile().mkdirs();
			pubKeyFile.createNewFile();
			fos = new FileOutputStream(pubKeyFile);
			fos.write(keyPair.getPrivate().getEncoded());
		} finally {
			fos.close();
		}
	}
}