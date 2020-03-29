package com.sanjay.acme.v2;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

public class CSRUtil {
	private String country;
	private String state;
	private String city;
	private String organisation;
	private String organisationUnit;
	private String emailId;
	private Set<String> domains;
	private KeyPair keyPair;
	private String signatureAlgorithm;
	
	CSRUtil(Set<String> domains, KeyPair keyPair) {
//		signatureAlgorithm = "SHA256withRSA";
		signatureAlgorithm = "SHA256withECDSA";
		country = "IN";
		state = "TN";
		city = "CH";
		organisation = "Sanjay";
		organisationUnit = "Sanjay";
		emailId = "m.sanjay94@gmail.com";
		this.domains = domains;
		this.keyPair = keyPair;
	}
	
	PKCS10CertificationRequest generateCSR() throws IOException, OperatorCreationException {
		Security.addProvider(new BouncyCastleProvider());
		PrivateKey privKey = keyPair.getPrivate();
		PublicKey pubKey = keyPair.getPublic();
		String commonName = "";
		for (String domain : domains) {
			commonName = domain;
			break;
		}
		X500Name subject = new X500Name("C="+country+", ST="+state+", L="+city+", O="+organisation+", OU="+organisationUnit+", CN="+commonName+", EMAILADDRESS="+emailId);
        PKCS10CertificationRequestBuilder builder = 
                new JcaPKCS10CertificationRequestBuilder(subject, pubKey);
		
		List<ASN1Encodable> subjectAlternativeNames = new ArrayList<ASN1Encodable>();
		if(domains!=null && !domains.isEmpty()) {
			for (String domain : domains) {
				GeneralName generalName = new GeneralName(GeneralName.dNSName, domain.trim());
				subjectAlternativeNames.add(generalName);
			}
			GeneralNames subjectAltNames = new GeneralNames(subjectAlternativeNames.toArray(new GeneralName [] {}));
			ExtensionsGenerator extGen = new ExtensionsGenerator();
			extGen.addExtension(Extension.subjectAlternativeName, false, subjectAltNames);
			builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());
		}
        
        ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(privKey);
        PKCS10CertificationRequest request = builder.build(contentSigner);
        return request;
	}
}
