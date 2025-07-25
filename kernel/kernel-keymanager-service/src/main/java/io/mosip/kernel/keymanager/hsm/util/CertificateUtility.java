package io.mosip.kernel.keymanager.hsm.util;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;

import javax.security.auth.x500.X500Principal;

import io.mosip.kernel.keymanagerservice.constant.KeymanagerConstant;
import io.mosip.kernel.keymanagerservice.dto.ExtendedCertificateParameters;
import io.mosip.kernel.keymanagerservice.dto.SubjectAlternativeNamesDto;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import io.mosip.kernel.core.keymanager.exception.KeystoreProcessingException;
import io.mosip.kernel.core.keymanager.model.CertificateParameters;
import io.mosip.kernel.keymanager.hsm.constant.KeymanagerErrorCode;

/**
 * Certificate utility to generate and sign X509 Certificate
 * 
 * @author Dharmesh Khandelwal
 * @since 1.0.0
 *
 */
public class CertificateUtility {

	
	/**
	 * Private constructor for CertificateUtility
	 */
	private CertificateUtility() {
	}

	/**
	 * Generate and sign X509 Certificate
	 * 
	 * @param keyPair            the keypair
	 * @param commonName         commonName
	 * @param organizationalUnit organizationalUnit
	 * @param organization       organization
	 * @param country            country
	 * @param validityFrom       validityFrom
	 * @param validityTo         validityTo
	 * @return The certificate
	 */
	public static X509Certificate generateX509Certificate(PrivateKey signPrivateKey, PublicKey publicKey, String commonName, String organizationalUnit,
			String organization, String country, LocalDateTime validityFrom, LocalDateTime validityTo, String signAlgorithm, String providerName) { 

		X500Name rootCertIssuer = new X500Name(getCertificateAttributes(commonName, organizationalUnit, organization, country));
		X500Name rootCertSubject = rootCertIssuer;
		KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign);
		BasicConstraints basicConstraints = new BasicConstraints(1);
		if (rootCertSubject.equals(rootCertIssuer)) {
			basicConstraints = new BasicConstraints(2);
		}
		return generateX509Certificate(signPrivateKey, publicKey, rootCertIssuer, rootCertSubject, signAlgorithm, providerName,
				 validityFrom, validityTo, keyUsage, basicConstraints);
	}

	/**
	 * Generate and sign X509 Certificate
	 * 
	 * @param signPrivateKey  the private key for signing certificate
	 * @param publicKey  the public key for generating certificate
	 * @param certParams   the certificate parameters
	 * 
	 * @return The certificate
	 */
	public static X509Certificate generateX509Certificate(PrivateKey signPrivateKey, PublicKey publicKey, CertificateParameters certParams,
						X500Principal signerPrincipal, String signAlgorithm, String providerName) { 
		// Using RFC4519Style instance to preserve the RDN sequence because in certificate creation the RDN sequence is getting reversed.
		X500Name certSubject = getCertificateAttributes(certParams); //new X500Name(RFC4519Style.INSTANCE, getCertificateAttributes(certParams));
		X500Name certIssuer = Objects.nonNull(signerPrincipal)? new X500Name(RFC4519Style.INSTANCE, signerPrincipal.getName()) : certSubject;
		KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign);
		BasicConstraints basicConstraints = new BasicConstraints(1);
		if (certSubject.equals(certIssuer)) {
			basicConstraints = new BasicConstraints(2);
		}

		if (certParams instanceof ExtendedCertificateParameters) {
			ExtendedCertificateParameters extendedCertParams = (ExtendedCertificateParameters) certParams;
			List<SubjectAlternativeNamesDto> sanDtoList = extendedCertParams.getSubjectAlternativeNames();
			GeneralName[] sanArray = getCertificateSAN(sanDtoList, publicKey);
			return generateX509Certificate(signPrivateKey, publicKey, certIssuer, certSubject, signAlgorithm, providerName,
					certParams.getNotBefore(), certParams.getNotAfter(), keyUsage, basicConstraints, sanArray);
		}else {
			return generateX509Certificate(signPrivateKey, publicKey, certIssuer, certSubject, signAlgorithm, providerName,
					certParams.getNotBefore(), certParams.getNotAfter(), keyUsage, basicConstraints);
		}
	}

	private static X509Certificate generateX509Certificate(PrivateKey signPrivateKey, PublicKey publicKey, X500Name certIssuer, X500Name certSubject,
						String signAlgorithm, String providerName, LocalDateTime notBefore, LocalDateTime notAfter, KeyUsage keyUsage,
						BasicConstraints basicConstraints) {
		try {
			BigInteger certSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));

			ContentSigner certContentSigner = new JcaContentSignerBuilder(signAlgorithm).setProvider(providerName).build(signPrivateKey);
			X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(certIssuer, certSerialNum, getDateFromLocalDateTime(notBefore),
													getDateFromLocalDateTime(notAfter), certSubject, publicKey);
			JcaX509ExtensionUtils certExtUtils = new JcaX509ExtensionUtils();
			certBuilder.addExtension(Extension.basicConstraints, true, basicConstraints);
			certBuilder.addExtension(Extension.subjectKeyIdentifier, false, certExtUtils.createSubjectKeyIdentifier(publicKey));
			certBuilder.addExtension(Extension.keyUsage, true, keyUsage);
			X509CertificateHolder certHolder = certBuilder.build(certContentSigner);
			return new JcaX509CertificateConverter().getCertificate(certHolder);
		} catch (OperatorCreationException | NoSuchAlgorithmException | CertificateException | IOException e) {
			throw new KeystoreProcessingException(KeymanagerErrorCode.CERTIFICATE_PROCESSING_ERROR.getErrorCode(),
					KeymanagerErrorCode.CERTIFICATE_PROCESSING_ERROR.getErrorMessage() + e.getMessage(), e);
		}
	}

	private static X509Certificate generateX509Certificate(PrivateKey signPrivateKey, PublicKey publicKey, X500Name certIssuer, X500Name certSubject,
														   String signAlgorithm, String providerName, LocalDateTime notBefore, LocalDateTime notAfter, KeyUsage keyUsage,
														   BasicConstraints basicConstraints, GeneralName[] altNames) {
		try {
			BigInteger certSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));

			ContentSigner certContentSigner = new JcaContentSignerBuilder(signAlgorithm).setProvider(providerName).build(signPrivateKey);
			X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(certIssuer, certSerialNum, getDateFromLocalDateTime(notBefore),
					getDateFromLocalDateTime(notAfter), certSubject, publicKey);
			JcaX509ExtensionUtils certExtUtils = new JcaX509ExtensionUtils();
			certBuilder.addExtension(Extension.basicConstraints, true, basicConstraints);
			certBuilder.addExtension(Extension.subjectKeyIdentifier, false, certExtUtils.createSubjectKeyIdentifier(publicKey));
			certBuilder.addExtension(Extension.keyUsage, true, keyUsage);
			if (altNames != null && altNames.length > 0) {
				certBuilder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(altNames));
			}
			X509CertificateHolder certHolder = certBuilder.build(certContentSigner);
			return new JcaX509CertificateConverter().getCertificate(certHolder);
		} catch (OperatorCreationException | NoSuchAlgorithmException | CertificateException | IOException e) {
			throw new KeystoreProcessingException(KeymanagerErrorCode.CERTIFICATE_PROCESSING_ERROR.getErrorCode(),
					KeymanagerErrorCode.CERTIFICATE_PROCESSING_ERROR.getErrorMessage() + e.getMessage(), e);
		}
	}

	public static X509Certificate generateX509Certificate(PrivateKey signPrivateKey, PublicKey publicKey, CertificateParameters certParams, 
						X500Principal signerPrincipal, String signAlgorithm, String providerName, boolean encKeyUsage) { 
		
		X500Name certSubject = getCertificateAttributes(certParams); 
		X500Name certIssuer = Objects.nonNull(signerPrincipal)? new X500Name(RFC4519Style.INSTANCE, signerPrincipal.getName()) : certSubject;
		KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign);
		if (encKeyUsage) {
			keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.keyEncipherment);
		}
		BasicConstraints basicConstraints = new BasicConstraints(true);
		return generateX509Certificate(signPrivateKey, publicKey, certIssuer, certSubject, signAlgorithm, providerName, 
									certParams.getNotBefore(), certParams.getNotAfter(), keyUsage, basicConstraints);
	}

	public static X509Certificate generateX509Certificate(PrivateKey signPrivateKey, PublicKey publicKey, CertificateParameters certParams, 
						X500Principal signerPrincipal, String signAlgorithm, String providerName, String encryptionKey) { 
		
		X500Name certSubject = getCertificateAttributes(certParams); 
		X500Name certIssuer = Objects.nonNull(signerPrincipal)? new X500Name(RFC4519Style.INSTANCE, signerPrincipal.getName()) : certSubject;
		KeyUsage keyUsage = new KeyUsage(KeyUsage.keyEncipherment);
		BasicConstraints basicConstraints = new BasicConstraints(false);
		if (certParams instanceof ExtendedCertificateParameters) {
			ExtendedCertificateParameters extendedCertParams = (ExtendedCertificateParameters) certParams;
			List<SubjectAlternativeNamesDto> sanDtoList = extendedCertParams.getSubjectAlternativeNames();
			GeneralName[] sanArray = getCertificateSAN(sanDtoList, publicKey);
			return generateX509Certificate(signPrivateKey, publicKey, certIssuer, certSubject, signAlgorithm, providerName,
					certParams.getNotBefore(), certParams.getNotAfter(), keyUsage, basicConstraints, sanArray);
		} else {
			return generateX509Certificate(signPrivateKey, publicKey, certIssuer, certSubject, signAlgorithm, providerName,
					certParams.getNotBefore(), certParams.getNotAfter(), keyUsage, basicConstraints);
		}
	}

	/**
	 * Converts the local date time to Date
	 * @param localDateTime
	 * @return
	 */
    private static Date getDateFromLocalDateTime(LocalDateTime localDateTime) {    	
    	return Date.from(localDateTime.atZone(ZoneId.systemDefault()).toInstant());
    }
    
    /**
     * Concatenates the cert attributes
     * @param commonName
     * @param organizationalUnit
     * @param organization
     * @param country
     * @return
     */
    private static String getCertificateAttributes(String commonName, String organizationalUnit,
			String organization, String country ) {
    	return "CN=" + commonName + ", OU =" + organizationalUnit + ",O=" + organization + ", C=" + country;
	}
	
	
	private static X500Name getCertificateAttributes(CertificateParameters certParams) {

		/* return "CN=" + certParams.getCommonName() + ", OU =" + certParams.getOrganizationUnit() + ",O=" + certParams.getOrganization()
					+ ", L=" + certParams.getLocation() + ", ST=" + certParams.getState() + ", C=" + certParams.getCountry(); */
		X500NameBuilder builder = new X500NameBuilder(RFC4519Style.INSTANCE);
		addRDN(certParams.getCountry(), builder, BCStyle.C);
		addRDN(certParams.getState(), builder, BCStyle.ST);
		addRDN(certParams.getLocation(), builder, BCStyle.L);
		addRDN(certParams.getOrganization(), builder, BCStyle.O);
		addRDN(certParams.getOrganizationUnit(), builder, BCStyle.OU);
		addRDN(certParams.getCommonName(), builder, BCStyle.CN);
		return builder.build();
	}
	
	private static void addRDN(String dnValue, X500NameBuilder builder, ASN1ObjectIdentifier identifier) {
		if (dnValue != null && !dnValue.isEmpty())
			builder.addRDN(identifier, dnValue);
	}

	private static GeneralName[] getCertificateSAN(List<SubjectAlternativeNamesDto> sanDtoList, PublicKey publicKey) {
		if (sanDtoList == null || sanDtoList.isEmpty()) {
			return new GeneralName[0];
		}
		try {
			SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
			ASN1ObjectIdentifier oid = subjectPublicKeyInfo.getAlgorithm().getAlgorithm();
			List<GeneralName> sanList = new ArrayList<>();

			for (SubjectAlternativeNamesDto san : sanDtoList) {
				String type = san.getType();
				String value = san.getValue();
				if (type == null || value == null) continue;

				switch (type) {
					case KeymanagerConstant.OTHER_NAME:
						sanList.add(new GeneralName(GeneralName.otherName,
								new org.bouncycastle.asn1.x509.OtherName(oid, new DERUTF8String(value.trim()))
						));
						break;
					case KeymanagerConstant.EMAIL_Address:
						sanList.add(new GeneralName(GeneralName.rfc822Name, value.trim()));
						break;
					case KeymanagerConstant.DNS_NAME:
						sanList.add(new GeneralName(GeneralName.dNSName, value.trim()));
						break;
					case KeymanagerConstant.X400_ADDRESS:
						DERUTF8String derValue = new DERUTF8String(value.trim());
						ASN1EncodableVector vector = new ASN1EncodableVector();
						vector.add(derValue);
						DERSequence sequence = new DERSequence(vector);
						sanList.add(new GeneralName(GeneralName.x400Address, sequence));
						break;
					case KeymanagerConstant.DIRECTORY_NAME:
						sanList.add(new GeneralName(GeneralName.directoryName, value.trim()));
						break;
					case KeymanagerConstant.URI:
						sanList.add(new GeneralName(GeneralName.uniformResourceIdentifier, value.trim()));
						break;
					case KeymanagerConstant.IP_ADDRESS:
						sanList.add(new GeneralName(GeneralName.iPAddress, value.trim()));
						break;
					case KeymanagerConstant.REGISTERED_ID:
						sanList.add(new GeneralName(GeneralName.registeredID, value.trim()));
						break;
					default:
						// Unknown type, skip or log if needed
						break;
				}
			}

			return sanList.toArray(new GeneralName[0]);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
}
