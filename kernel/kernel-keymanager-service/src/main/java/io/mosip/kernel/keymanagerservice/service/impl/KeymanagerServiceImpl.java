package io.mosip.kernel.keymanagerservice.service.impl;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import io.mosip.kernel.core.crypto.exception.InvalidDataException;
import io.mosip.kernel.core.crypto.exception.InvalidKeyException;
import io.mosip.kernel.core.crypto.exception.NullDataException;
import io.mosip.kernel.core.crypto.exception.NullKeyException;
import io.mosip.kernel.core.crypto.exception.NullMethodException;
import io.mosip.kernel.core.exception.BaseUncheckedException;
import io.mosip.kernel.core.keymanager.exception.KeystoreProcessingException;
import io.mosip.kernel.core.keymanager.exception.NoSuchSecurityProviderException;
import io.mosip.kernel.core.keymanager.model.CertificateEntry;
import io.mosip.kernel.core.keymanager.model.CertificateParameters;
import io.mosip.kernel.core.keymanager.spi.ECKeyStore;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.kernel.core.util.DateUtils;
import io.mosip.kernel.cryptomanager.util.CryptomanagerUtils;
import io.mosip.kernel.keygenerator.bouncycastle.KeyGenerator;
import io.mosip.kernel.keymanager.hsm.util.CertificateUtility;
import io.mosip.kernel.keymanagerservice.constant.ECCurves;
import io.mosip.kernel.keymanagerservice.constant.KeyReferenceIdConsts;
import io.mosip.kernel.keymanagerservice.constant.KeymanagerConstant;
import io.mosip.kernel.keymanagerservice.constant.KeymanagerErrorConstant;
import io.mosip.kernel.keymanagerservice.dto.AllCertificatesDataResponseDto;
import io.mosip.kernel.keymanagerservice.dto.CSRGenerateRequestDto;
import io.mosip.kernel.keymanagerservice.dto.CertificateDataResponseDto;
import io.mosip.kernel.keymanagerservice.dto.CertificateInfo;
import io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateRequestDto;
import io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateResponseDto;
import io.mosip.kernel.keymanagerservice.dto.PublicKeyResponse;
import io.mosip.kernel.keymanagerservice.dto.RevokeKeyRequestDto;
import io.mosip.kernel.keymanagerservice.dto.RevokeKeyResponseDto;
import io.mosip.kernel.keymanagerservice.dto.SignatureCertificate;
import io.mosip.kernel.keymanagerservice.dto.SymmetricKeyGenerateRequestDto;
import io.mosip.kernel.keymanagerservice.dto.SymmetricKeyGenerateResponseDto;
import io.mosip.kernel.keymanagerservice.dto.SymmetricKeyRequestDto;
import io.mosip.kernel.keymanagerservice.dto.SymmetricKeyResponseDto;
import io.mosip.kernel.keymanagerservice.dto.UploadCertificateRequestDto;
import io.mosip.kernel.keymanagerservice.dto.UploadCertificateResponseDto;
import io.mosip.kernel.keymanagerservice.entity.KeyAlias;
import io.mosip.kernel.keymanagerservice.entity.KeyPolicy;
import io.mosip.kernel.keymanagerservice.exception.CryptoException;
import io.mosip.kernel.keymanagerservice.exception.InvalidResponseObjectTypeException;
import io.mosip.kernel.keymanagerservice.exception.KeymanagerServiceException;
import io.mosip.kernel.keymanagerservice.exception.NoUniqueAliasException;
import io.mosip.kernel.keymanagerservice.helper.KeymanagerDBHelper;
import io.mosip.kernel.keymanagerservice.helper.SessionKeyDecrytorHelper;
import io.mosip.kernel.keymanagerservice.logger.KeymanagerLogger;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import io.mosip.kernel.keymanagerservice.util.KeymanagerUtil;
import io.mosip.kernel.keymanagerservice.validator.ECKeyPairGenRequestValidator;
import io.mosip.kernel.signature.util.SignatureUtil;

/**
 * This class provides the implementation for the methods of KeymanagerService
 * interface.
 *
 * @author Dharmesh Khandelwal
 * @author Urvil Joshi
 * @author Srinivasan
 * @since 1.0.0
 *
 */
@Service
@Transactional
public class KeymanagerServiceImpl implements KeymanagerService {

	private static final String VALID_REFERENCE_ID_GETTING_KEY_ALIAS_WITH_REFERENCE_ID = "Valid reference Id. Getting key alias with referenceId";

	private static final String NOT_A_VALID_REFERENCE_ID_GETTING_KEY_ALIAS_WITHOUT_REFERENCE_ID = "Not a valid reference Id. Getting key alias without referenceId";

	private static final Logger LOGGER = KeymanagerLogger.getLogger(KeymanagerServiceImpl.class);

	@Value("${mosip.root.key.applicationid:ROOT}")
	private String rootKeyApplicationId;

	@Value("${mosip.sign-certificate-refid:SIGN}")
	private String certificateSignRefID;

	/** The sign applicationid. */
	@Value("${mosip.sign.applicationid:KERNEL}")
	private String signApplicationid;

	@Value("${mosip.kernel.certificate.sign.algorithm:SHA256withRSA}")
	private String signAlgorithm;

	/** The 1.1.3 no thumbprint support flag. */
	@Value("${mosip.kernel.keymanager.113nothumbprint.support:false}")
	private boolean noThumbprint;

	/** Flag to generate and store Ed25519 key in real HSM. */
	@Value("${mosip.kernel.keymanager.ed25519.hsm.support.enabled:false}")
	private boolean ed25519SupportFlag;


	/**
	 * Keystore instance to handles and store cryptographic keys.
	 */
	@Autowired
	private ECKeyStore keyStore;

	/**
	 * KeyGenerator instance to generate asymmetric key pairs
	 */
	@Autowired
	private KeyGenerator keyGenerator;

	/**
	 * Utility to generate Metadata
	 */
	@Autowired
	KeymanagerUtil keymanagerUtil;

	/**
	 * KeymanagerDBHelper instance to handle all DB operations
	 */
	@Autowired
	private KeymanagerDBHelper dbHelper;

	/**
	 * {@link CryptomanagerUtils} instance
	 */
	@Autowired
	CryptomanagerUtils cryptomanagerUtil;

	@Autowired
	SessionKeyDecrytorHelper keyDecryptorHelper;

	@Autowired
	private ECKeyPairGenRequestValidator ecKeyPairGenRequestValidator;

	private static Map<String, String> ecRefIdsAlgoNamesMap = new HashMap<>();

	static {
		ecRefIdsAlgoNamesMap.put(KeyReferenceIdConsts.EC_SECP256K1_SIGN.name(), ECCurves.SECP256K1.name());
		ecRefIdsAlgoNamesMap.put(KeyReferenceIdConsts.EC_SECP256R1_SIGN.name(), ECCurves.SECP256R1.name());
		ecRefIdsAlgoNamesMap.put(KeyReferenceIdConsts.ED25519_SIGN.name(), ECCurves.ED25519.name());
	}

	/**
	 * Function to get Certificate from HSM. On first request for an applicationId
	 * and duration, will create a new keypair.
	 * 
	 * @param applicationId applicationId
	 * @param timeStamp     timeStamp
	 * @return {@link CertificateInfo} instance
	 */
	@SuppressWarnings("unused")
	private CertificateInfo<X509Certificate> getCertificateFromHSM(String applicationId, LocalDateTime timeStamp, String referenceId) {
		LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.APPLICATIONID, applicationId,
				KeymanagerConstant.GETPUBLICKEYHSM);
		LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.TIMESTAMP, timeStamp.toString(),
				KeymanagerConstant.GETPUBLICKEYHSM);

		String alias = null;
		Optional<KeyPolicy> keyPolicy = dbHelper.getKeyPolicy(applicationId);
		Map<String, List<KeyAlias>> keyAliasMap = dbHelper.getKeyAliases(applicationId, referenceId, timeStamp);
		List<KeyAlias> currentKeyAlias = keyAliasMap.get(KeymanagerConstant.CURRENTKEYALIAS);
		List<KeyAlias> keyAlias = keyAliasMap.get(KeymanagerConstant.KEYALIAS);

		if (keyAlias.isEmpty()) {
			LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.KEYALIAS, String.valueOf(keyAlias.size()),
					"Initial Key generation process not completed.");
			throw new KeymanagerServiceException(KeymanagerErrorConstant.KEY_GENERATION_NOT_DONE.getErrorCode(),
					KeymanagerErrorConstant.KEY_GENERATION_NOT_DONE.getErrorMessage());
		}
		X509Certificate x509Cert = null;
		if (currentKeyAlias.size() > 1) {
			LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.CURRENTKEYALIAS,
					String.valueOf(currentKeyAlias.size()), "CurrentKeyAlias size more than one Throwing exception");
			throw new NoUniqueAliasException(KeymanagerErrorConstant.NO_UNIQUE_ALIAS.getErrorCode(),
					KeymanagerErrorConstant.NO_UNIQUE_ALIAS.getErrorMessage());
		} else if (currentKeyAlias.size() == 1) {
			LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.CURRENTKEYALIAS,
					currentKeyAlias.get(0).getAlias(), "CurrentKeyAlias size is one fetching keypair using this alias");
			KeyAlias fetchedKeyAlias = currentKeyAlias.get(0);
			alias = fetchedKeyAlias.getAlias();
			x509Cert = (X509Certificate) keyStore.getCertificate(alias);
		} else if (currentKeyAlias.isEmpty()) {
			LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.CURRENTKEYALIAS,
					String.valueOf(currentKeyAlias.size()),
					"CurrentKeyAlias size is zero. Will create new Keypair for this applicationId and timestamp");
			alias = UUID.randomUUID().toString();
			ImmutablePair<String, X509Certificate> immPair = generateKeyPairInHSM(alias, applicationId, referenceId, timeStamp, keyAlias);
			x509Cert = immPair.getRight();
		}
		return new CertificateInfo<>(alias, x509Cert);
	}

	private ImmutablePair<String, X509Certificate> generateKeyPairInHSM(String alias, String applicationId, String referenceId, 
							LocalDateTime timeStamp, List<KeyAlias> keyAlias) {
		LocalDateTime generationDateTime = timeStamp;
		LocalDateTime expiryDateTime = dbHelper.getExpiryPolicy(applicationId, generationDateTime, keyAlias);
		String rootKeyAlias = getRootKeyAlias(applicationId, timeStamp);
		X500Principal latestCertPrincipal = getLatestCertPrincipal(keyAlias);
		CertificateParameters certParams = keymanagerUtil.getCertificateParameters(latestCertPrincipal,
				generationDateTime, expiryDateTime);
		keyStore.generateAndStoreAsymmetricKey(alias, rootKeyAlias, certParams);
		X509Certificate x509Cert = (X509Certificate) keyStore.getCertificate(alias);
		String certThumbprint = cryptomanagerUtil.getCertificateThumbprintInHex(x509Cert);
		String uniqueValue = applicationId + KeymanagerConstant.UNDER_SCORE + referenceId + KeymanagerConstant.UNDER_SCORE +
								timeStamp.format(KeymanagerConstant.DATE_FORMATTER);
		LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY,
								"Unique Value formatter: " + uniqueValue);
		String uniqueIdentifier = keymanagerUtil.getUniqueIdentifier(uniqueValue);
		dbHelper.storeKeyInAlias(applicationId, generationDateTime, referenceId, alias, expiryDateTime, certThumbprint, uniqueIdentifier);
		ImmutablePair<String, X509Certificate> immPair = ImmutablePair.of(uniqueIdentifier, x509Cert);
		return immPair;
	}


	private X500Principal getLatestCertPrincipal(List<KeyAlias> keyAlias) {
		KeyAlias latestKeyAlias = keyAlias.get(0);
		String alias = latestKeyAlias.getAlias();
		X509Certificate signCert = (X509Certificate) keyStore.getCertificate(alias);
		return signCert.getSubjectX500Principal();
	}

	/**
	 * Function to get public key from DB store. On first request for an
	 * applicationId, referenceId and duration, will create a new keypair.
	 * 
	 * @param applicationId applicationId
	 * @param timeStamp     timeStamp
	 * @param referenceId   referenceId
	 * @return {@link PublicKeyResponse} instance
	 */
	@SuppressWarnings("unused")
	private CertificateInfo<X509Certificate> getCertificateFromDBStore(String applicationId, LocalDateTime timeStamp,
			String referenceId, boolean isSignKey) {
		LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.APPLICATIONID, applicationId,
				KeymanagerConstant.GETPUBLICKEYDB);
		LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.TIMESTAMP, timeStamp.toString(),
				KeymanagerConstant.GETPUBLICKEYDB);
		LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.REFERENCEID, referenceId,
				KeymanagerConstant.GETPUBLICKEYDB);

		String alias = null;
		X509Certificate x509Cert = null;
		
		Map<String, List<KeyAlias>> keyAliasMap = dbHelper.getKeyAliases(applicationId, referenceId, timeStamp);
		List<KeyAlias> currentKeyAlias = keyAliasMap.get(KeymanagerConstant.CURRENTKEYALIAS);

		if (currentKeyAlias.size() > 1) {
			LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.CURRENTKEYALIAS,
					String.valueOf(currentKeyAlias.size()), "CurrentKeyAlias size more than one. Throwing exception");
			throw new NoUniqueAliasException(KeymanagerErrorConstant.NO_UNIQUE_ALIAS.getErrorCode(),
					KeymanagerErrorConstant.NO_UNIQUE_ALIAS.getErrorMessage());
		} else if (currentKeyAlias.size() == 1) {
			LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.CURRENTKEYALIAS,
					currentKeyAlias.get(0).getAlias(),
					"CurrentKeyAlias size is one. Will fetch keypair using this alias");
			Optional<io.mosip.kernel.keymanagerservice.entity.KeyStore> keyFromDBStore = dbHelper
					.getKeyStoreFromDB(currentKeyAlias.get(0).getAlias());
			if (!keyFromDBStore.isPresent()) {
				LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.KEYFROMDB, keyFromDBStore.toString(),
						"Key in DBStore does not exist for this alias. Throwing exception");
				throw new NoUniqueAliasException(KeymanagerErrorConstant.NO_UNIQUE_ALIAS.getErrorCode(),
						KeymanagerErrorConstant.NO_UNIQUE_ALIAS.getErrorMessage());
			} else {
				LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.KEYFROMDB,
						currentKeyAlias.get(0).getAlias(),
						"Key in DBStore exists for this alias. Fetching Certificate.");
				KeyAlias fetchedKeyAlias = currentKeyAlias.get(0);
				alias = fetchedKeyAlias.getAlias();
				String certificateData = keyFromDBStore.get().getCertificateData();
				x509Cert = (X509Certificate) keymanagerUtil.convertToCertificate(certificateData);
			}
		} else if (currentKeyAlias.isEmpty()) {
			LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.CURRENTKEYALIAS,
					String.valueOf(currentKeyAlias.size()),
					"CurrentKeyAlias size is zero. Will create new Keypair for this applicationId, referenceId and timestamp");
			List<KeyAlias> keyAlias = keyAliasMap.get(KeymanagerConstant.KEYALIAS);
			if (!keyAlias.isEmpty()) {
				keyAlias.forEach(innerAlias -> {
					String ksAlias = innerAlias.getAlias();
					Optional<io.mosip.kernel.keymanagerservice.entity.KeyStore> keyFromDBStore = dbHelper.getKeyStoreFromDB(ksAlias);
					String masterKeyAlias = keyFromDBStore.get().getMasterAlias();
					String privateKeyObj = keyFromDBStore.get().getPrivateKey();

					if (ksAlias.equals(masterKeyAlias) || privateKeyObj.equals(KeymanagerConstant.KS_PK_NA)) {
						LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.APPLICATIONID, null,
								"Not Allowed to generate New Key Pair for other domains (Partner Certificate might have expired).");
						throw new KeymanagerServiceException(KeymanagerErrorConstant.GENERATION_NOT_ALLOWED.getErrorCode(),
								String.format(KeymanagerErrorConstant.GENERATION_NOT_ALLOWED.getErrorMessage(), "other domains, partner Certificate expired"));
					}
				});
			}
			if (applicationId.equalsIgnoreCase(KeymanagerConstant.ROOT)){
				LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.APPLICATIONID, null,
								"Not Allowed to generate Base Key for Root Key.");
				throw new KeymanagerServiceException(KeymanagerErrorConstant.GENERATION_NOT_ALLOWED.getErrorCode(),
								String.format(KeymanagerErrorConstant.GENERATION_NOT_ALLOWED.getErrorMessage(), "Root Key"));
			}
			if (applicationId.equalsIgnoreCase(KeymanagerConstant.KERNEL_APP_ID)){
				LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.KERNEL_APP_ID, null,
								"Not Allowed to generate Base Key for Kernel App Id.");
				throw new KeymanagerServiceException(KeymanagerErrorConstant.GENERATION_NOT_ALLOWED.getErrorCode(),
					String.format(KeymanagerErrorConstant.GENERATION_NOT_ALLOWED.getErrorMessage(), "Kernel App Id"));
			}
			if (applicationId.equalsIgnoreCase(KeymanagerConstant.PARTNER_APP_ID)){
				LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.KERNEL_APP_ID, null,
								"Not Allowed to generate Keys for PARTNER App Id.");
				throw new KeymanagerServiceException(KeymanagerErrorConstant.GENERATION_NOT_ALLOWED.getErrorCode(),
					String.format(KeymanagerErrorConstant.GENERATION_NOT_ALLOWED.getErrorMessage(), "Partner App Id"));
			}
			if (referenceId.equals(KeyReferenceIdConsts.ED25519_SIGN.name()) && !isSignKey) {
				LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.KERNEL_APP_ID, null,
								"Not Allowed to generate Keys for Signature key Ed25519 Algorithm.");
				throw new KeymanagerServiceException(KeymanagerErrorConstant.GENERATION_NOT_ALLOWED.getErrorCode(),
					String.format(KeymanagerErrorConstant.GENERATION_NOT_ALLOWED.getErrorMessage(), "Ed25519 Signature Key"));
			}
			Optional<KeyPolicy> keyPolicy = dbHelper.getKeyPolicy(applicationId);
			String encryptedPrivateKey;
			alias = UUID.randomUUID().toString();
			KeyPair keypair = null;
			if (referenceId.equals(KeyReferenceIdConsts.ED25519_SIGN.name()) && isSignKey) {
				keypair = keyGenerator.getEd25519KeyPair();
			} else {
				keypair = keyGenerator.getAsymmetricKey();
			}
			PrivateKey privateKey = keypair.getPrivate();
			/**
			 * Will get application's master key information from HSM. On first request for
			 * an applicationId and duration, will create a new keypair.
			 */
			CertificateInfo<X509Certificate> certInfo = getCertificateFromHSM(applicationId, timeStamp, KeymanagerConstant.EMPTY);
			X509Certificate hsmX509Cert = certInfo.getCertificate();
			PublicKey masterPublicKey = hsmX509Cert.getPublicKey();

			String masterAlias = certInfo.getAlias();
			LocalDateTime generationDateTime = timeStamp;
			LocalDateTime expiryDateTime = dbHelper.getExpiryPolicy(KeymanagerConstant.BASE_KEY_POLICY_CONST,
					generationDateTime, keyAliasMap.get(KeymanagerConstant.KEYALIAS));
			/**
			 * Before storing a keypair in db, will first encrypt its private key with
			 * application's master public key from softhsm's/HSM's keystore
			 */
			try {
				encryptedPrivateKey = CryptoUtil.encodeToURLSafeBase64(keymanagerUtil.encryptKey(privateKey, masterPublicKey));
			} catch (InvalidDataException | InvalidKeyException | NullDataException | NullKeyException
					| NullMethodException e) {
				throw new CryptoException(KeymanagerErrorConstant.CRYPTO_EXCEPTION.getErrorCode(),
						KeymanagerErrorConstant.CRYPTO_EXCEPTION.getErrorMessage() + e.getErrorText());
			}
			PrivateKeyEntry signKeyEntry = keyStore.getAsymmetricKey(masterAlias);
			PrivateKey signPrivateKey = signKeyEntry.getPrivateKey();
			X509Certificate signCert = (X509Certificate) signKeyEntry.getCertificate();
			X500Principal signerPrincipal = signCert.getSubjectX500Principal();

			CertificateParameters certParams = keymanagerUtil.getCertificateParameters(signerPrincipal,
													generationDateTime, expiryDateTime);
			certParams.setCommonName(applicationId + "-" + referenceId);
			x509Cert = (X509Certificate) CertificateUtility.generateX509Certificate(signPrivateKey, keypair.getPublic(), 
						certParams, signerPrincipal, signAlgorithm, keyStore.getKeystoreProviderName(), KeymanagerConstant.ENCRYPTION_KEY);
			String certificateData = keymanagerUtil.getPEMFormatedData(x509Cert);
			dbHelper.storeKeyInDBStore(alias, masterAlias, certificateData, encryptedPrivateKey);
			String certThumbprint = cryptomanagerUtil.getCertificateThumbprintInHex(x509Cert);
			String uniqueValue = applicationId + KeymanagerConstant.UNDER_SCORE + referenceId + KeymanagerConstant.UNDER_SCORE +
								timeStamp.format(KeymanagerConstant.DATE_FORMATTER);
			LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY,
									"Unique Value formatter: " + uniqueValue);
			String uniqueIdentifier = keymanagerUtil.getUniqueIdentifier(uniqueValue);
			dbHelper.storeKeyInAlias(applicationId, generationDateTime, referenceId, alias, expiryDateTime, certThumbprint, uniqueIdentifier);
			keymanagerUtil.destoryKey(privateKey);
		}
		return new CertificateInfo<>(alias, x509Cert);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * io.mosip.kernel.keymanager.service.KeymanagerService#decryptSymmetricKey(java
	 * .lang.String, java.time.LocalDateTime, java.util.Optional, byte[])
	 */
	@Override
	public SymmetricKeyResponseDto decryptSymmetricKey(SymmetricKeyRequestDto symmetricKeyRequestDto) {
		return keyDecryptorHelper.decryptSessionKey(symmetricKeyRequestDto);
	}

	@Override
	public SignatureCertificate getSignatureCertificate(String applicationId, Optional<String> referenceId,
													String timestamp){
		return getSigningCertificate(applicationId, referenceId, timestamp, true);
	}

	private SignatureCertificate getSigningCertificate(String applicationId, Optional<String> referenceId,
			String timestamp, boolean isPrivateRequired) {
		String alias = null;
		List<KeyAlias> currentKeyAlias = null;
		Map<String, List<KeyAlias>> keyAliasMap = null;
		LocalDateTime generationDateTime = null;
		LocalDateTime expiryDateTime = null;
		CertificateEntry<X509Certificate, PrivateKey> certificateEntry = null;
		LocalDateTime localDateTimeStamp = DateUtils.getUTCCurrentDateTime();
		String refId = null;
		String uniqueIdentifier = null;
		if (!referenceId.isPresent() || referenceId.get().trim().isEmpty()) {
			LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY,
					NOT_A_VALID_REFERENCE_ID_GETTING_KEY_ALIAS_WITHOUT_REFERENCE_ID);
			keyAliasMap = dbHelper.getKeyAliases(applicationId, KeymanagerConstant.EMPTY, localDateTimeStamp);
			refId = KeymanagerConstant.EMPTY;
		} else if (applicationId.equalsIgnoreCase(signApplicationid) && referenceId.isPresent()
							&& referenceId.get().equals(certificateSignRefID)){
			LOGGER.info(KeymanagerConstant.SESSIONID, applicationId, referenceId.get(),
					VALID_REFERENCE_ID_GETTING_KEY_ALIAS_WITH_REFERENCE_ID);
			keyAliasMap = dbHelper.getKeyAliases(applicationId, referenceId.get(), localDateTimeStamp);
			refId = referenceId.get();
		} else if (referenceId.isPresent() &&
				  (Arrays.stream(KeyReferenceIdConsts.values()).anyMatch((rId) -> rId.name().equals(referenceId.get())))){
			LOGGER.info(KeymanagerConstant.SESSIONID, applicationId, referenceId.get(),
					VALID_REFERENCE_ID_GETTING_KEY_ALIAS_WITH_REFERENCE_ID);
			keyAliasMap = dbHelper.getKeyAliases(applicationId, referenceId.get(), localDateTimeStamp);
			refId = referenceId.get();
		} else {
			LOGGER.error(KeymanagerConstant.SESSIONID, applicationId, referenceId.get(),
									"Signing operation not allowed for the provided application Id & reference Id.");
			throw new KeymanagerServiceException(KeymanagerErrorConstant.NOT_VALID_SIGNATURE_KEY.getErrorCode(),
					KeymanagerErrorConstant.NOT_VALID_SIGNATURE_KEY.getErrorMessage());
		}
		List<KeyAlias> keyAlias = keyAliasMap.get(KeymanagerConstant.KEYALIAS);
		currentKeyAlias = keyAliasMap.get(KeymanagerConstant.CURRENTKEYALIAS);
		
		if (currentKeyAlias.size() > 1) {
			LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.CURRENTKEYALIAS,
					String.valueOf(currentKeyAlias.size()), "CurrentKeyAlias size more than one. Throwing exception");
			throw new NoUniqueAliasException(KeymanagerErrorConstant.NO_UNIQUE_ALIAS.getErrorCode(),
					KeymanagerErrorConstant.NO_UNIQUE_ALIAS.getErrorMessage());
		} else if (currentKeyAlias.size() == 1) {
			LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.CURRENTKEYALIAS,
					currentKeyAlias.get(0).getAlias(),
					"CurrentKeyAlias size is one. Will fetch keypair using this alias");
			KeyAlias fetchedKeyAlias = currentKeyAlias.get(0);
			alias = fetchedKeyAlias.getAlias();
			// @TODO Not Sure why always check the existing HSM only. We need to get more details from team. 
			// Expecting the signature key to be always in HSM.
			if (!refId.equals("ED25519_SIGN")){
				certificateEntry = getCertificateEntry(alias, isPrivateRequired);
			} else {
				Optional<io.mosip.kernel.keymanagerservice.entity.KeyStore> keyFromDBStore = dbHelper.getKeyStoreFromDB(alias);
				Object[] keyDetailsArr = getKeyDetails(keyFromDBStore, alias);
				certificateEntry = new CertificateEntry<X509Certificate, PrivateKey>(new X509Certificate[] 
										{(X509Certificate) keyDetailsArr[1]}, (PrivateKey) keyDetailsArr[0]);
			}
			generationDateTime = fetchedKeyAlias.getKeyGenerationTime();
			expiryDateTime = fetchedKeyAlias.getKeyExpiryTime();
			uniqueIdentifier = fetchedKeyAlias.getUniqueIdentifier();
		} else if (currentKeyAlias.isEmpty() && keyAlias.size() > 0) {
			LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.KEYALIAS,
						keyAlias.get(0).getAlias(),
					"CurrentKeyAlias size is zero. Key got expired, generating new keypair using this App Id & Ref Id");
			// This will generate the new key in HSM.
			alias = UUID.randomUUID().toString();
			ImmutablePair<String, X509Certificate> immPair = generateKeyPairInHSM(alias, applicationId, refId, localDateTimeStamp, keyAlias);
			certificateEntry = getCertificateEntry(alias, isPrivateRequired);
			generationDateTime = localDateTimeStamp;
			expiryDateTime = dbHelper.getExpiryPolicy(applicationId, generationDateTime, keyAlias);
			uniqueIdentifier = immPair.getLeft();
		} else {
			LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.KEYALIAS, String.valueOf(keyAlias.size()),
					"Initial Key generation process not completed.");
			throw new KeymanagerServiceException(KeymanagerErrorConstant.KEY_GENERATION_NOT_DONE.getErrorCode(),
					KeymanagerErrorConstant.KEY_GENERATION_NOT_DONE.getErrorMessage());
		}
		String providerName = keyStore.getKeystoreProviderName();
		return new SignatureCertificate(alias, certificateEntry, generationDateTime, expiryDateTime, providerName, uniqueIdentifier);
	}

	private CertificateEntry<X509Certificate, PrivateKey> getCertificateEntry(String alias, boolean isPrivateRequired) {
		BaseUncheckedException exception = null;
		try {
			PrivateKeyEntry privateKeyEntry = keyStore.getAsymmetricKey(alias);
			return new CertificateEntry<>((X509Certificate[]) privateKeyEntry.getCertificateChain(),
					privateKeyEntry.getPrivateKey());
		} catch(KeystoreProcessingException | NoSuchSecurityProviderException kpe) {
			LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.CURRENTKEYALIAS, "Error", 
							"Key Not found in HSM, keystore might have loaded as offline." + kpe.getMessage());
			exception = kpe;
		}
		if (!isPrivateRequired) {
			Optional<io.mosip.kernel.keymanagerservice.entity.KeyStore> keyFromDBStore = dbHelper.getKeyStoreFromDB(alias);
			if (!keyFromDBStore.isPresent()) {
				LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.CURRENTKEYALIAS, KeymanagerConstant.EMPTY,
									"Certificate Not found in keystore table.");
				throw new KeymanagerServiceException(KeymanagerErrorConstant.CERTIFICATE_NOT_FOUND.getErrorCode(),
									KeymanagerErrorConstant.CERTIFICATE_NOT_FOUND.getErrorMessage());
			}
			String certificateData = keyFromDBStore.get().getCertificateData();
			X509Certificate reqX509Cert = (X509Certificate) keymanagerUtil.convertToCertificate(certificateData);
			return new CertificateEntry<>( new X509Certificate[] {reqX509Cert}, null);
		}
		throw exception;
	}

	@Override
	public PublicKeyResponse<String> getSignPublicKey(String applicationId, String timestamp,
			Optional<String> referenceId) {
		// Ignoring the input timestamp and considering current system time to check the key expiry.
		String localDateTimeStamp = DateUtils.getUTCCurrentDateTimeString(); //keymanagerUtil.parseToLocalDateTime(timeStamp);

		SignatureCertificate certificateResponse = getSigningCertificate(applicationId, referenceId, localDateTimeStamp, false);
		return new PublicKeyResponse<>(certificateResponse.getAlias(),
				CryptoUtil.encodeToURLSafeBase64(certificateResponse.getCertificateEntry().getChain()[0].getPublicKey().getEncoded()),
				certificateResponse.getIssuedAt(), certificateResponse.getExpiryAt());
	}

	@Override
	public KeyPairGenerateResponseDto generateMasterKey(String responseObjectType, KeyPairGenerateRequestDto request) {

		String applicationId = request.getApplicationId();
		String refId = request.getReferenceId() == null ? KeymanagerConstant.EMPTY : request.getReferenceId();
		Boolean forceFlag = request.getForce() == null ? Boolean.FALSE : request.getForce();
		
		Optional<KeyPolicy> keyPolicy = dbHelper.getKeyPolicy(applicationId);
		// Need to check with Team whether we need to check this condition..
		if (keymanagerUtil.isValidReferenceId(refId) && 
					((refId.equals(certificateSignRefID) && !applicationId.equals(signApplicationid)) || 
					 (!refId.equals(certificateSignRefID)))) {
			LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.KEYPOLICY, keyPolicy.toString(),
									"Reference Id not supported for the provided application Id.");
			throw new KeymanagerServiceException(KeymanagerErrorConstant.REFERENCE_ID_NOT_SUPPORTED.getErrorCode(),
					KeymanagerErrorConstant.REFERENCE_ID_NOT_SUPPORTED.getErrorMessage());
		}

		if (!keymanagerUtil.isValidResponseType(responseObjectType)) {
			LOGGER.error(KeymanagerConstant.SESSIONID, "Response Object Type", null,
					"Invalid Response Object type provided for the key generation request.");
			throw new KeymanagerServiceException(KeymanagerErrorConstant.INVALID_REQUEST.getErrorCode(),
					KeymanagerErrorConstant.INVALID_REQUEST.getErrorMessage());
		}
		
		LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.APPLICATIONID, KeymanagerConstant.EMPTY,
					KeymanagerConstant.REQUEST_FOR_MASTER_KEY_GENERATION);
		return generateKey(responseObjectType, applicationId, refId, forceFlag, request);
	}

	private KeyPairGenerateResponseDto generateKey(String responseObjectType, String appId, String refId,
			Boolean forceFlag, KeyPairGenerateRequestDto request) {

		LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.APPLICATIONID, appId,
				"Generate Key for application ID: " + appId + ", RefId: " + refId + ", force flag: " + forceFlag.toString());
		LocalDateTime timestamp = DateUtils.getUTCCurrentDateTime();
		Map<String, List<KeyAlias>> keyAliasMap = dbHelper.getKeyAliases(appId, refId, timestamp);
		List<KeyAlias> currentKeyAlias = keyAliasMap.get(KeymanagerConstant.CURRENTKEYALIAS);
		if (forceFlag) {
			LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.APPLICATIONID, appId, 
					"Force Flag is True, invalidating all the existing keys and generating new key pair.");
			LocalDateTime expireTime = timestamp.minusMinutes(1L);
			currentKeyAlias.forEach(alias -> {
				dbHelper.storeKeyInAlias(appId, alias.getKeyGenerationTime(), refId, alias.getAlias(), 
								expireTime, alias.getCertThumbprint(), alias.getUniqueIdentifier());
			});
			return generateAndBuildResponse(responseObjectType, appId, refId, timestamp, keyAliasMap, request);
		}
				
		if (currentKeyAlias.size() > 1) {
			LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.CURRENTKEYALIAS,
					String.valueOf(currentKeyAlias.size()), "CurrentKeyAlias size more than one");
			throw new NoUniqueAliasException(KeymanagerErrorConstant.NO_UNIQUE_ALIAS.getErrorCode(),
					KeymanagerErrorConstant.NO_UNIQUE_ALIAS.getErrorMessage());
		} else if (currentKeyAlias.isEmpty()) {
			LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.CURRENTKEYALIAS,
					String.valueOf(currentKeyAlias.size()),
					"CurrentKeyAlias size is zero. Will create new Keypair for this applicationId and timestamp");
			return generateAndBuildResponse(responseObjectType, appId, refId, timestamp, keyAliasMap, request);
		} 
		LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.CURRENTKEYALIAS,
					String.valueOf(currentKeyAlias.size()),
					"key details present in DB" + currentKeyAlias.get(0));
		KeyAlias fetchedKeyAlias = currentKeyAlias.get(0);
		//X509Certificate x509Cert = (X509Certificate) keyStore.getCertificate(fetchedKeyAlias.getAlias());
		return buildResponseObject(responseObjectType, appId, refId, timestamp, fetchedKeyAlias.getAlias(), 
					fetchedKeyAlias.getKeyGenerationTime(), fetchedKeyAlias.getKeyExpiryTime(), request, null);
	}

	private KeyPairGenerateResponseDto generateAndBuildResponse(String responseObjectType, String appId, String refId, 
									LocalDateTime timestamp, Map<String, List<KeyAlias>> keyAliasMap, KeyPairGenerateRequestDto request) {

		String alias = UUID.randomUUID().toString();
		LocalDateTime generationDateTime = timestamp;
		LocalDateTime expiryDateTime = dbHelper.getExpiryPolicy(appId, generationDateTime, keyAliasMap.get(KeymanagerConstant.KEYALIAS));
		String rootKeyAlias = getRootKeyAlias(appId, timestamp);
		CertificateParameters certParams = keymanagerUtil.getCertificateParameters(request, generationDateTime, expiryDateTime, appId);
		//keyStore.generateAndStoreAsymmetricKey(alias, rootKeyAlias, certParams);
		CertificateInfo<X509Certificate> certificateInfo = generateAndStoreAsymmetricKey(alias, rootKeyAlias, certParams, request, generationDateTime, expiryDateTime, keyAliasMap);
 		return buildResponseObject(responseObjectType, appId, refId, timestamp, certificateInfo.getAlias(), generationDateTime, 
					expiryDateTime, request, certificateInfo.getCertificate());
	}

	private String getRootKeyAlias(String appId, LocalDateTime timestamp) {
		Map<String, List<KeyAlias>> rootKeyAliasMap = dbHelper.getKeyAliases(rootKeyApplicationId, KeymanagerConstant.EMPTY, timestamp);
		List<KeyAlias> rootCurrentKeyAlias = rootKeyAliasMap.get(KeymanagerConstant.CURRENTKEYALIAS);
		String rootKeyAlias = null;
		if (rootCurrentKeyAlias.size() > 1) {
			LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.CURRENTKEYALIAS,
					String.valueOf(rootCurrentKeyAlias.size()), "CurrentKeyAlias size more than one for ROOT Key");
			throw new NoUniqueAliasException(KeymanagerErrorConstant.NO_UNIQUE_ALIAS.getErrorCode(),
					KeymanagerErrorConstant.NO_UNIQUE_ALIAS.getErrorMessage());
		} else if (rootCurrentKeyAlias.size() == 1) {
			LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.CURRENTKEYALIAS,
					String.valueOf(rootCurrentKeyAlias.size()),
					"CurrentKeyAlias size is one. Use the current root key alias as key to sign the key.");
			rootKeyAlias = rootCurrentKeyAlias.get(0).getAlias();
		}
		LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.ROOT_KEY, "Found Root Key.", 
						"Root Key for signing the new generated key: " + rootKeyAlias);
		if (Objects.isNull(rootKeyAlias) && !appId.equals(rootKeyApplicationId)) {
			LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.ROOT_KEY,
					"Root Key Error", "ROOT Key not available to sign the new generated key.");
			throw new KeymanagerServiceException(KeymanagerErrorConstant.ROOT_KEY_NOT_FOUND.getErrorCode(), 
					KeymanagerErrorConstant.ROOT_KEY_NOT_FOUND.getErrorMessage());
		}
		return rootKeyAlias;
	}

	private CertificateInfo<X509Certificate> generateAndStoreAsymmetricKey(String alias, String rootKeyAlias, 
				CertificateParameters certParams, KeyPairGenerateRequestDto request, LocalDateTime generationDateTime, 
				LocalDateTime expiryDateTime, Map<String, List<KeyAlias>> keyAliasMap) {
		
		X509Certificate x509Cert = null;
		String applicationId = request.getApplicationId();
		String refId = request.getReferenceId();
		String genAlias = alias;
		if (keymanagerUtil.isValidReferenceId(refId) && 
					(Arrays.stream(KeyReferenceIdConsts.values()).anyMatch((rId) -> rId.name().equals(refId)))) {
			if (refId.equals(KeyReferenceIdConsts.EC_SECP256K1_SIGN.name()) || 
					refId.equals(KeyReferenceIdConsts.EC_SECP256R1_SIGN.name()) || 
					(refId.equals(KeyReferenceIdConsts.ED25519_SIGN.name()) && ed25519SupportFlag)) {
				keyStore.generateAndStoreAsymmetricKey(alias, rootKeyAlias, certParams, 
								ecRefIdsAlgoNamesMap.get(refId).toLowerCase());
				x509Cert = (X509Certificate) keyStore.getCertificate(alias);
				storeAsymmetricKey(alias, applicationId, refId, keyAliasMap, x509Cert, generationDateTime, expiryDateTime);
			} else if (refId.equals(KeyReferenceIdConsts.ED25519_SIGN.name())) {
				// ed25519SupportFlag enabled, this code will not get executed.
				// Generate KeyPair outside HSM and wrap the private key using component master key.
				// store the encrypted private key & certificate in DB (KeyStore) 
				LocalDateTime localDateTimeStamp = DateUtils.getUTCCurrentDateTime();
				CertificateInfo<X509Certificate> certificateInfo = getCertificateFromDBStore(request.getApplicationId(), 
									localDateTimeStamp, request.getReferenceId(), true);
				x509Cert = certificateInfo.getCertificate();
				genAlias = certificateInfo.getAlias();
			}
			return new CertificateInfo<>(genAlias, x509Cert);
		} 
		keyStore.generateAndStoreAsymmetricKey(alias, rootKeyAlias, certParams);
		x509Cert = (X509Certificate) keyStore.getCertificate(alias);
		storeAsymmetricKey(alias, applicationId, refId, keyAliasMap, x509Cert, generationDateTime, expiryDateTime);
		return new CertificateInfo<>(genAlias, x509Cert);
	}

	private void storeAsymmetricKey(String alias, String appId, String refId, Map<String, List<KeyAlias>> keyAliasMap, 
				X509Certificate x509Cert, LocalDateTime generationDateTime, LocalDateTime expiryDateTime ) {
		
		String certThumbprint = cryptomanagerUtil.getCertificateThumbprintInHex(x509Cert);
		String uniqueValue = appId + KeymanagerConstant.UNDER_SCORE + refId + KeymanagerConstant.UNDER_SCORE +
								generationDateTime.format(KeymanagerConstant.DATE_FORMATTER);
		LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY,
									"Unique Value formatter: " + uniqueValue);
		String uniqueIdentifier = keymanagerUtil.getUniqueIdentifier(uniqueValue);
		dbHelper.storeKeyInAlias(appId, generationDateTime, refId, alias, expiryDateTime, certThumbprint, uniqueIdentifier);
	}

	private KeyPairGenerateResponseDto buildResponseObject(String responseObjectType, String appId, String refId,
			LocalDateTime timestamp, String keyAlias, LocalDateTime generationDateTime, LocalDateTime expiryDateTime, 
			KeyPairGenerateRequestDto request, X509Certificate x509Cert) {

		if (responseObjectType.toUpperCase().equals(KeymanagerConstant.REQUEST_TYPE_CERTIFICATE)) {
			LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.APPLICATIONID, appId,
				"Getting Key Certificate for application ID: " + appId + ", RefId: " + refId);
			// for already generated key, fetching certificate.
			if (Objects.isNull(x509Cert)) {
				Optional<io.mosip.kernel.keymanagerservice.entity.KeyStore> keyFromDBStore = dbHelper.getKeyStoreFromDB(keyAlias);
				Object[] keyDetailsArr = getKeyDetails(keyFromDBStore, keyAlias);
				x509Cert = (X509Certificate) keyDetailsArr[1];
			}

			KeyPairGenerateResponseDto responseDto = new KeyPairGenerateResponseDto();
			responseDto.setCertificate(keymanagerUtil.getPEMFormatedData(x509Cert));
			responseDto.setExpiryAt(DateUtils.parseDateToLocalDateTime(x509Cert.getNotAfter()));
			responseDto.setIssuedAt(DateUtils.parseDateToLocalDateTime(x509Cert.getNotBefore()));
			responseDto.setTimestamp(timestamp);
			return responseDto;
		}

		if (responseObjectType.toUpperCase().equals(KeymanagerConstant.REQUEST_TYPE_CSR)) {
			LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.APPLICATIONID, appId,
				"Getting Key CSR for application ID: " + appId + ", RefId: " + refId);
			
			//PublicKey publicKey = ((X509Certificate) keyStore.getCertificate(keyAlias)).getPublicKey();
			Optional<io.mosip.kernel.keymanagerservice.entity.KeyStore> keyFromDBStore = dbHelper.getKeyStoreFromDB(keyAlias);
			Object[] keyDetailsArr = getKeyDetails(keyFromDBStore, keyAlias);
			if (Objects.isNull(x509Cert)){
				x509Cert = (X509Certificate) keyDetailsArr[1];
			}
			PublicKey publicKey = x509Cert.getPublicKey();
			//PrivateKey privateKey = keyStore.getPrivateKey(keyAlias);
			PrivateKey privateKey =  (PrivateKey) keyDetailsArr[0];
			KeyPairGenerateResponseDto responseDto = new KeyPairGenerateResponseDto();
			CertificateParameters certParams = keymanagerUtil.getCertificateParameters(request, generationDateTime, expiryDateTime, appId);
			responseDto.setCertSignRequest(keymanagerUtil.getCSR(privateKey, publicKey, certParams, publicKey.getAlgorithm()));
			responseDto.setExpiryAt(expiryDateTime);
			responseDto.setIssuedAt(generationDateTime);
			responseDto.setTimestamp(timestamp);
			return responseDto;
		}
		LOGGER.error(KeymanagerConstant.SESSIONID, "Response Object Type", null,
							"Invalid Response Object type provided for the key pair");
		throw new InvalidResponseObjectTypeException(KeymanagerErrorConstant.INVALID_RESPONSE_TYPE.getErrorCode(),
						KeymanagerErrorConstant.INVALID_RESPONSE_TYPE.getErrorMessage());
	}

	

	@Override
	public KeyPairGenerateResponseDto getCertificate(String appId, Optional<String> refId) {
		LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.APPLICATIONID, appId,
				KeymanagerConstant.GET_CERTIFICATE);
		LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.REFERENCEID, refId.toString(),
				KeymanagerConstant.GET_CERTIFICATE);
		
		LocalDateTime localDateTimeStamp = DateUtils.getUTCCurrentDateTime();
		CertificateInfo<X509Certificate> certificateData = null;
		if (!refId.isPresent() || refId.get().trim().isEmpty()) {
			LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY,
					"Reference Id is not present. Will get Certificate from HSM");
			certificateData = getCertificateFromHSM(appId, localDateTimeStamp, KeymanagerConstant.EMPTY);
		} else if ((appId.equalsIgnoreCase(signApplicationid) && refId.isPresent()
						&& refId.get().equals(certificateSignRefID)) || 
						(refId.isPresent() && refId.get().equals(KeyReferenceIdConsts.EC_SECP256K1_SIGN.name())) ||
						(refId.isPresent() && refId.get().equals(KeyReferenceIdConsts.EC_SECP256R1_SIGN.name())) ||
						(refId.isPresent() && refId.get().equals(KeyReferenceIdConsts.ED25519_SIGN.name())
						 && ed25519SupportFlag)) {
			LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY,
					"Reference Id is present and it is " + refId.get() + " reference. Will get Certificate from HSM");
			certificateData = getCertificateFromHSM(appId, localDateTimeStamp, refId.get());
		} else {
			LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY,
					"Reference Id is present. Will get Certificate from DB store");
			certificateData = getCertificateFromDBStore(appId, localDateTimeStamp, refId.get(), false);
		}
		
		X509Certificate x509Cert = certificateData.getCertificate();
		KeyPairGenerateResponseDto responseDto = new KeyPairGenerateResponseDto();
		responseDto.setCertificate(keymanagerUtil.getPEMFormatedData(x509Cert));
		responseDto.setExpiryAt(DateUtils.parseDateToLocalDateTime(x509Cert.getNotAfter()));
		responseDto.setIssuedAt(DateUtils.parseDateToLocalDateTime(x509Cert.getNotBefore()));
		responseDto.setTimestamp(localDateTimeStamp);
		return responseDto;
	}

	@SuppressWarnings("java:S3655") // added suppress for sonarcloud, because handling the optional object properly in other if conditions.
	@Override
	public KeyPairGenerateResponseDto generateCSR(CSRGenerateRequestDto csrGenRequestDto) {
		
		String appId = csrGenRequestDto.getApplicationId();
		Optional<String> refId = Optional.ofNullable(csrGenRequestDto.getReferenceId());
		LocalDateTime localDateTimeStamp = DateUtils.getUTCCurrentDateTime();
		
		dbHelper.getKeyPolicy(appId);
		CertificateInfo<X509Certificate> certificateData = null;
		if (!refId.isPresent() || refId.get().trim().isEmpty()) {
			LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY,
					"Reference Id is not present. Will get Certificate from HSM");
			certificateData = getCertificateFromHSM(appId, localDateTimeStamp, KeymanagerConstant.EMPTY);
		} else if (appId.equalsIgnoreCase(KeymanagerConstant.KERNEL_APP_ID) && refId.isPresent()
							&& refId.get().equalsIgnoreCase(KeymanagerConstant.KERNEL_IDENTIFY_CACHE)) {
			LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.KERNEL_APP_ID, KeymanagerConstant.EMPTY,
								"Reference Id is present and it is IDENTITY_CACHE reference id. CSR generation not possible.");
			throw new KeymanagerServiceException(KeymanagerErrorConstant.GENERATION_CSR_ALLOWED.getErrorCode(),
								KeymanagerErrorConstant.GENERATION_CSR_ALLOWED.getErrorMessage());
		} else if ((appId.equalsIgnoreCase(signApplicationid) && refId.isPresent()
							&& refId.get().equals(certificateSignRefID))|| 
						(refId.isPresent() && refId.get().equals(KeyReferenceIdConsts.EC_SECP256K1_SIGN.name())) ||
						(refId.isPresent() && refId.get().equals(KeyReferenceIdConsts.EC_SECP256R1_SIGN.name())) ||
						(refId.isPresent() && refId.get().equals(KeyReferenceIdConsts.ED25519_SIGN.name())
						 && ed25519SupportFlag)) {
			LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY,
								"Reference Id is present and it is " + refId.get() + " reference. Will get Certificate from HSM");
			certificateData = getCertificateFromHSM(appId, localDateTimeStamp, refId.get());
		} else {
			LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY,
					"Reference Id is present. Will get Certificate from DB store");
			certificateData = getCertificateFromDBStore(appId, localDateTimeStamp, refId.get(), false);
		}
		
		String keyAlias = certificateData.getAlias();
		Optional<io.mosip.kernel.keymanagerservice.entity.KeyStore> keyFromDBStore = dbHelper.getKeyStoreFromDB(keyAlias);
		
		Object[] keyDetailsArr = getKeyDetails(keyFromDBStore, keyAlias);
		PrivateKey signPrivateKey = (PrivateKey) keyDetailsArr[0];
		X509Certificate x509Cert = (X509Certificate) keyDetailsArr[1];
		
		LocalDateTime generationDateTime = DateUtils.parseDateToLocalDateTime(x509Cert.getNotBefore());
		LocalDateTime expiryDateTime = DateUtils.parseDateToLocalDateTime(x509Cert.getNotAfter());
		CertificateParameters certParams = keymanagerUtil.getCertificateParameters(csrGenRequestDto, generationDateTime, expiryDateTime);
		KeyPairGenerateResponseDto responseDto = new KeyPairGenerateResponseDto();
		responseDto.setCertSignRequest(keymanagerUtil.getCSR(signPrivateKey, x509Cert.getPublicKey(), certParams, signPrivateKey.getAlgorithm()));
		responseDto.setExpiryAt(expiryDateTime);
		responseDto.setIssuedAt(generationDateTime);
		responseDto.setTimestamp(localDateTimeStamp);
		if ((refId.isPresent() || !refId.get().trim().isEmpty()) && (!appId.equalsIgnoreCase(signApplicationid) && 
					!refId.get().equals(certificateSignRefID))) {
			keymanagerUtil.destoryKey(signPrivateKey);
		}
		return responseDto;
	}

	@SuppressWarnings("unused")
	private KeyAlias getKeyAlias(String appId, String refId){

		if (!keymanagerUtil.isValidApplicationId(appId)) {
			LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.APPLICATIONID, null,
					"Invalid application ID provided to get Object details.");
			throw new KeymanagerServiceException(KeymanagerErrorConstant.INVALID_REQUEST.getErrorCode(),
					KeymanagerErrorConstant.INVALID_REQUEST.getErrorMessage());
		}

		LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.APPLICATIONID, appId,
				"to get KeyInfo for application ID: " + appId + ", RefId: " + refId);
		Optional<KeyPolicy> keyPolicy = dbHelper.getKeyPolicy(appId);
		LocalDateTime timestamp = DateUtils.getUTCCurrentDateTime();
		Map<String, List<KeyAlias>> keyAliasMap = dbHelper.getKeyAliases(appId, refId, timestamp);
		List<KeyAlias> currentKeyAlias = keyAliasMap.get(KeymanagerConstant.CURRENTKEYALIAS);

		if (currentKeyAlias.size() > 1) {
			LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.CURRENTKEYALIAS,
					String.valueOf(currentKeyAlias.size()), "CurrentKeyAlias size more than one");
			throw new NoUniqueAliasException(KeymanagerErrorConstant.NO_UNIQUE_ALIAS.getErrorCode(),
					KeymanagerErrorConstant.NO_UNIQUE_ALIAS.getErrorMessage());
		} else if (currentKeyAlias.isEmpty()) {
			// checking empty because after certificate expiry new CSR request should be called to generate new key pair. 
			LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.CURRENTKEYALIAS,
					String.valueOf(currentKeyAlias.size()),
					"CurrentKeyAlias size is zero for this applicationId and timestamp");
			throw new NoUniqueAliasException(KeymanagerErrorConstant.NO_UNIQUE_ALIAS.getErrorCode(),
					KeymanagerErrorConstant.NO_UNIQUE_ALIAS.getErrorMessage());
		} 
		LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.CURRENTKEYALIAS,
					String.valueOf(currentKeyAlias.size()),
					"key details present in DB: " + currentKeyAlias.get(0));
		KeyAlias fetchedKeyAlias = currentKeyAlias.get(0);
		return fetchedKeyAlias;
	}

	private Object[] getKeyDetails(Optional<io.mosip.kernel.keymanagerservice.entity.KeyStore> keyFromDBStore, String keyAlias) {
		
		if (!keyFromDBStore.isPresent()) {
			LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.KEYFROMDB, keyFromDBStore.toString(),
					"Key in DBStore does not exist for this alias. So fetching the certificate from HSM.");
			PrivateKeyEntry signKeyEntry = keyStore.getAsymmetricKey(keyAlias);
			PrivateKey signPrivateKey = signKeyEntry.getPrivateKey();
			X509Certificate x509Cert = (X509Certificate) signKeyEntry.getCertificate();
			return new Object[] {signPrivateKey, x509Cert};
		} 
		PrivateKeyEntry masterKeyEntry = keyStore.getAsymmetricKey(keyFromDBStore.get().getMasterAlias());
		PrivateKey masterPrivateKey = masterKeyEntry.getPrivateKey();
		PublicKey masterPublicKey = masterKeyEntry.getCertificate().getPublicKey();
		try {
			byte[] decryptedPrivateKey = keymanagerUtil.decryptKey(CryptoUtil.decodeURLSafeBase64(keyFromDBStore.get().getPrivateKey()), 
													masterPrivateKey, masterPublicKey, keyStore.getKeystoreProviderName());
			X509Certificate x509Cert = (X509Certificate) keymanagerUtil.convertToCertificate(keyFromDBStore.get().getCertificateData());
			String keyAlgorithm = x509Cert.getPublicKey().getAlgorithm();
			PrivateKey signPrivateKey = null;
			if (keyAlgorithm.equals(KeymanagerConstant.ED25519_KEY_TYPE) || 
					keyAlgorithm.equals(KeymanagerConstant.ED25519_ALG_OID) || 
					keyAlgorithm.equals(KeymanagerConstant.EDDSA_KEY_TYPE)) {
				signPrivateKey = keyGenerator.buildPrivateKey(decryptedPrivateKey);
			} else {
				signPrivateKey = KeyFactory.getInstance(KeymanagerConstant.RSA).generatePrivate(new PKCS8EncodedKeySpec(decryptedPrivateKey));
			}
			
			return new Object[] {signPrivateKey, x509Cert};
		} catch (InvalidDataException | InvalidKeyException | NullDataException | NullKeyException
				| NullMethodException | InvalidKeySpecException | NoSuchAlgorithmException e) {
			throw new CryptoException(KeymanagerErrorConstant.CRYPTO_EXCEPTION.getErrorCode(),
					KeymanagerErrorConstant.CRYPTO_EXCEPTION.getErrorMessage() + e.getMessage(), e);
		}
	}

	@Override
	public UploadCertificateResponseDto uploadCertificate(UploadCertificateRequestDto uploadCertRequestDto){
		String appId = uploadCertRequestDto.getApplicationId();
		String refId = uploadCertRequestDto.getReferenceId();
		String certificateData = uploadCertRequestDto.getCertificateData();

		if (!keymanagerUtil.isValidCertificateData(certificateData)) {
			LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.APPLICATIONID, null,
					"Invalid Certificate Data provided to upload the certificate.");
			throw new KeymanagerServiceException(KeymanagerErrorConstant.INVALID_REQUEST.getErrorCode(),
					KeymanagerErrorConstant.INVALID_REQUEST.getErrorMessage());
		}

		LocalDateTime timestamp = DateUtils.getUTCCurrentDateTime();
		KeyAlias currentKeyAlias = getKeyAlias(appId, refId);
		String keyAlias = currentKeyAlias.getAlias();
		Optional<io.mosip.kernel.keymanagerservice.entity.KeyStore> keyFromDBStore = dbHelper.getKeyStoreFromDB(keyAlias);
		
		Object[] keyDetailsArr = getKeyDetails(keyFromDBStore, keyAlias);
		PrivateKey privateKey = (PrivateKey) keyDetailsArr[0];
		X509Certificate x509Cert = (X509Certificate) keyDetailsArr[1];

		X509Certificate reqX509Cert = (X509Certificate) keymanagerUtil.convertToCertificate(certificateData);
		if (!Arrays.equals(x509Cert.getPublicKey().getEncoded(), reqX509Cert.getPublicKey().getEncoded())) {
			LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.APPLICATIONID, null,
					"Certificate Key is not matching with the available key.");
			throw new KeymanagerServiceException(KeymanagerErrorConstant.KEY_NOT_MATCHING.getErrorCode(),
					KeymanagerErrorConstant.KEY_NOT_MATCHING.getErrorMessage());
		}
		LocalDateTime notBeforeDate = keymanagerUtil.convertToUTC(reqX509Cert.getNotBefore());
		LocalDateTime notAfterDate = keymanagerUtil.convertToUTC(reqX509Cert.getNotAfter());
		if (!keyFromDBStore.isPresent()){
			keyStore.storeCertificate(keyAlias, privateKey, reqX509Cert);
		} else {
			dbHelper.storeKeyInDBStore(keyAlias, keyFromDBStore.get().getMasterAlias(), keymanagerUtil.getPEMFormatedData(reqX509Cert), 
									keyFromDBStore.get().getPrivateKey());
		}
		// Need to be check if any data got encrypted with the existing certificate and thumbprint is prepended to the encrypted data.
		// Need to add in documentation about this limitation.
		String certThumbprint = cryptomanagerUtil.getCertificateThumbprintInHex(reqX509Cert);
		String uniqueValue = appId + KeymanagerConstant.UNDER_SCORE + refId + KeymanagerConstant.UNDER_SCORE +
								timestamp.format(KeymanagerConstant.DATE_FORMATTER);
		LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY,
									"Unique Value formatter: " + uniqueValue);
		String uniqueIdentifier = keymanagerUtil.getUniqueIdentifier(uniqueValue);
		dbHelper.storeKeyInAlias(appId, notBeforeDate, refId, keyAlias, notAfterDate, certThumbprint, uniqueIdentifier);
		UploadCertificateResponseDto responseDto = new UploadCertificateResponseDto();
		responseDto.setStatus(KeymanagerConstant.UPLOAD_SUCCESS);
		responseDto.setTimestamp(timestamp);
		return responseDto;
	}

	@SuppressWarnings("java:S3655") // added suppress for sonarcloud, because handling the optional object properly in other if conditions.
	@Override
	public UploadCertificateResponseDto uploadOtherDomainCertificate(UploadCertificateRequestDto uploadCertRequestDto) {

		String appId = uploadCertRequestDto.getApplicationId();
		String refId = uploadCertRequestDto.getReferenceId();
		String certificateData = uploadCertRequestDto.getCertificateData();

		if (!keymanagerUtil.isValidCertificateData(certificateData) || !keymanagerUtil.isValidReferenceId(refId) ||
						!keymanagerUtil.isValidApplicationId(appId)) {
			LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.APPLICATIONID, null,
					"Invalid Data provided to upload other domain certificate.");
			throw new KeymanagerServiceException(KeymanagerErrorConstant.INVALID_REQUEST.getErrorCode(),
					KeymanagerErrorConstant.INVALID_REQUEST.getErrorMessage());
		}

		if (appId.equalsIgnoreCase(signApplicationid) && refId.equalsIgnoreCase(certificateSignRefID)) {
			LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.APPLICATIONID, appId,
					"Not allowed to upload other domain certificate with AppId: " + signApplicationid + " & RefId: SIGN.");
			throw new KeymanagerServiceException(KeymanagerErrorConstant.UPLOAD_NOT_ALLOWED.getErrorCode(),
					KeymanagerErrorConstant.UPLOAD_NOT_ALLOWED.getErrorMessage());
		}
		if (keymanagerUtil.isValidReferenceId(refId) && 
					(Arrays.stream(KeyReferenceIdConsts.values()).anyMatch((rId) -> rId.name().equals(refId)))) {
			LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.APPLICATIONID, appId,
						"Not allowed to upload other domain certificate with RefId: " + refId 
						+ ", This refId is reserve for ECC algorithms.");
			throw new KeymanagerServiceException(KeymanagerErrorConstant.UPLOAD_NOT_ALLOWED.getErrorCode(),
						KeymanagerErrorConstant.UPLOAD_NOT_ALLOWED.getErrorMessage());
		}

		LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.APPLICATIONID, appId,
				"to get KeyInfo for application ID: " + appId + ", RefId: " + refId);
		LocalDateTime timestamp = DateUtils.getUTCCurrentDateTime();
		Map<String, List<KeyAlias>> keyAliasMap = dbHelper.getKeyAliases(appId, refId, timestamp);
		List<KeyAlias> currentKeyAlias = keyAliasMap.get(KeymanagerConstant.CURRENTKEYALIAS);

		if (currentKeyAlias.size() > 1) {
			LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.CURRENTKEYALIAS,
					String.valueOf(currentKeyAlias.size()), "CurrentKeyAlias size more than one");
			throw new NoUniqueAliasException(KeymanagerErrorConstant.NO_UNIQUE_ALIAS.getErrorCode(),
					KeymanagerErrorConstant.NO_UNIQUE_ALIAS.getErrorMessage());
		}


		List<KeyAlias> keyAliasList = keyAliasMap.get(KeymanagerConstant.KEYALIAS);
		X509Certificate reqX509Cert = (X509Certificate) keymanagerUtil.convertToCertificate(certificateData);
		String certThumbprint = cryptomanagerUtil.getCertificateThumbprintInHex(reqX509Cert);
		LocalDateTime notBeforeDate = keymanagerUtil.convertToUTC(reqX509Cert.getNotBefore());
		LocalDateTime notAfterDate = keymanagerUtil.convertToUTC(reqX509Cert.getNotAfter());
		if (currentKeyAlias.isEmpty() && keyAliasList.isEmpty()) {
			return storeAndBuildResponse(appId, refId, reqX509Cert, notBeforeDate, notAfterDate, certThumbprint);
		}

		// Current valid key is not available and expired key is available in key_alias, but certificate not available in key_store 
		if (currentKeyAlias.isEmpty() && keyAliasList.size() > 0) {
			String keyAlias = keyAliasList.get(0).getAlias();
			Optional<io.mosip.kernel.keymanagerservice.entity.KeyStore> keyFromDBStore = dbHelper.getKeyStoreFromDB(keyAlias);
			if (!keyFromDBStore.isPresent()) {
				LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY,
									"Other valid key is available, so not allowed to upload certificate.");
				throw new KeymanagerServiceException(KeymanagerErrorConstant.UPLOAD_NOT_ALLOWED.getErrorCode(),
									KeymanagerErrorConstant.UPLOAD_NOT_ALLOWED.getErrorMessage());
			}
			return storeAndBuildResponse(appId, refId, reqX509Cert, notBeforeDate, notAfterDate, certThumbprint);
		}
		
		// Current valid key is available in key_alias, but not certificate available in key_store
		String keyAlias = currentKeyAlias.get(0).getAlias();
		Optional<io.mosip.kernel.keymanagerservice.entity.KeyStore> keyFromDBStore = dbHelper.getKeyStoreFromDB(keyAlias);
		if (!keyFromDBStore.isPresent() && currentKeyAlias.size() == 1) {
			LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY,
								"Other domain valid key is not available in key store, so not allowed to upload certificate.");
			throw new KeymanagerServiceException(KeymanagerErrorConstant.UPLOAD_NOT_ALLOWED.getErrorCode(),
								KeymanagerErrorConstant.UPLOAD_NOT_ALLOWED.getErrorMessage());
		} 

		// master key alias & key alias should be same & private key should not available for other domain certificates.
		String masterKeyAlias = keyFromDBStore.get().getMasterAlias();
		String privateKeyObj = keyFromDBStore.get().getPrivateKey();
		if (!keyAlias.equals(masterKeyAlias) || !privateKeyObj.equals(KeymanagerConstant.KS_PK_NA)) {
			LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.APPLICATIONID, null,
					"Not Allowed to update certificate for other domains if private key available.");
			throw new KeymanagerServiceException(KeymanagerErrorConstant.UPLOAD_NOT_ALLOWED.getErrorCode(),
					KeymanagerErrorConstant.UPLOAD_NOT_ALLOWED.getErrorMessage());
		}
		
		// 
		if (currentKeyAlias.get(0).getCertThumbprint().equals(certThumbprint)) {
			LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.APPLICATIONID, appId,
					"Not Allowed to upload same certificate for other domains. " +
							"Current available certificate thumbprint matching with input certificate thumbprint.");
			throw new KeymanagerServiceException(KeymanagerErrorConstant.UPLOAD_NOT_ALLOWED.getErrorCode(),
					KeymanagerErrorConstant.UPLOAD_NOT_ALLOWED.getErrorMessage());
		}
		
		LocalDateTime expireTime = timestamp.minusMinutes(1L);
		dbHelper.storeKeyInAlias(appId, currentKeyAlias.get(0).getKeyGenerationTime(), refId, keyAlias, expireTime, 
				currentKeyAlias.get(0).getCertThumbprint(), currentKeyAlias.get(0).getUniqueIdentifier());
		return storeAndBuildResponse(appId, refId, reqX509Cert, notBeforeDate, notAfterDate, certThumbprint);
	}

	private UploadCertificateResponseDto storeAndBuildResponse(String appId, String refId, X509Certificate reqX509Cert, 
															   LocalDateTime notBeforeDate, LocalDateTime notAfterDate, 
															   String certThumbprint) {
		String alias = UUID.randomUUID().toString();
		dbHelper.storeKeyInDBStore(alias, alias, keymanagerUtil.getPEMFormatedData(reqX509Cert), KeymanagerConstant.KS_PK_NA);
		
		//String certThumbprint = cryptomanagerUtil.getCertificateThumbprintInHex(reqX509Cert);
		// Using certThumbprint to allow same date certificate to upload because existing has moved expired.
		String uniqueValue = appId + KeymanagerConstant.UNDER_SCORE + refId + KeymanagerConstant.UNDER_SCORE +
									certThumbprint;
		LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY,
									"Unique Value formatter: " + uniqueValue);
		String uniqueIdentifier = keymanagerUtil.getUniqueIdentifier(uniqueValue);
		dbHelper.storeKeyInAlias(appId, notBeforeDate, refId, alias, notAfterDate, certThumbprint, uniqueIdentifier);
		UploadCertificateResponseDto responseDto = new UploadCertificateResponseDto();
		responseDto.setStatus(KeymanagerConstant.UPLOAD_SUCCESS);
		responseDto.setTimestamp(DateUtils.getUTCCurrentDateTime());
		return responseDto;
	}

	@Override
	public SymmetricKeyGenerateResponseDto generateSymmetricKey(SymmetricKeyGenerateRequestDto symGenRequestDto) {
		
		String appId = symGenRequestDto.getApplicationId();
		String refId = symGenRequestDto.getReferenceId();
		LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.APPLICATIONID, appId,
						KeymanagerConstant.REQ_SYM_KEY_GEN);

		if (!keymanagerUtil.isValidReferenceId(refId) ||
						!keymanagerUtil.isValidApplicationId(appId)) {
			LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.APPLICATIONID, null,
					"Invalid Data provided to generate symmetric key.");
			throw new KeymanagerServiceException(KeymanagerErrorConstant.INVALID_REQUEST.getErrorCode(),
					KeymanagerErrorConstant.INVALID_REQUEST.getErrorMessage());
		}
		
		LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.APPLICATIONID, appId,
				"to get KeyInfo for application ID: " + appId + ", RefId: " + refId);
		LocalDateTime timestamp = DateUtils.getUTCCurrentDateTime();
		Map<String, List<KeyAlias>> keyAliasMap = dbHelper.getKeyAliases(appId, refId, timestamp);
		List<KeyAlias> currentKeyAlias = keyAliasMap.get(KeymanagerConstant.CURRENTKEYALIAS);

		if (currentKeyAlias.size() > 1) {
			LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.CURRENTKEYALIAS,
					String.valueOf(currentKeyAlias.size()), "CurrentKeyAlias size more than one");
			throw new NoUniqueAliasException(KeymanagerErrorConstant.NO_UNIQUE_ALIAS.getErrorCode(),
					KeymanagerErrorConstant.NO_UNIQUE_ALIAS.getErrorMessage());
		}

		Boolean forceFlag = symGenRequestDto.getForce();
		if (forceFlag) {
			LOGGER.debug(KeymanagerConstant.SESSIONID, KeymanagerConstant.APPLICATIONID, appId, 
					"Force Flag is True, Invalidating the existing key and generating new key.");
			LocalDateTime expireTime = timestamp.minusMinutes(1L);
			currentKeyAlias.forEach(alias -> {
				dbHelper.storeKeyInAlias(appId, alias.getKeyGenerationTime(), refId, alias.getAlias(), expireTime, null, null);
			});
			return generateAndBuildResponse(appId, refId, timestamp);
		}
		
		if (currentKeyAlias.size() == 1){
			return buildSymGenKeyRespObject(timestamp, KeymanagerConstant.SYMM_KEY_EXISTS);
		}

		return generateAndBuildResponse(appId, refId, timestamp);
	}

	private SymmetricKeyGenerateResponseDto generateAndBuildResponse(String appId, String refId, LocalDateTime timestamp) {
		
		String alias = UUID.randomUUID().toString();
		LocalDateTime expiryDateTime = timestamp.plusDays(KeymanagerConstant.SYMMETRIC_KEY_VALIDITY);
		keyStore.generateAndStoreSymmetricKey(alias);
		dbHelper.storeKeyInAlias(appId, timestamp, refId, alias, expiryDateTime, null, null);
		return buildSymGenKeyRespObject(timestamp, KeymanagerConstant.GENERATE_SUCCESS);
	}

	private SymmetricKeyGenerateResponseDto buildSymGenKeyRespObject(LocalDateTime timestamp, String status){
		SymmetricKeyGenerateResponseDto responseDto = new SymmetricKeyGenerateResponseDto();
		responseDto.setStatus(status);
		responseDto.setTimestamp(timestamp);
		return responseDto;
	}

	@Override
	public RevokeKeyResponseDto revokeKey(RevokeKeyRequestDto revokeKeyRequest) {

		String appId = revokeKeyRequest.getApplicationId();
		String refId = revokeKeyRequest.getReferenceId();
		// Disable Auto Generation of functionality not implemented yet.
		Boolean disableAutoGen = revokeKeyRequest.getDisableAutoGen() == null ? Boolean.FALSE : revokeKeyRequest.getDisableAutoGen();

		LOGGER.info(KeymanagerConstant.SESSIONID, appId, refId,	KeymanagerConstant.REQ_REV_KEY);
		LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.APPLICATIONID, appId,
						KeymanagerConstant.REQ_REV_KEY + disableAutoGen);

		if (!keymanagerUtil.isValidReferenceId(refId) ||
						!keymanagerUtil.isValidApplicationId(appId)) {
			LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.APPLICATIONID, null,
					"Invalid Data provided to revoke key.");
			throw new KeymanagerServiceException(KeymanagerErrorConstant.INVALID_REQUEST.getErrorCode(),
					KeymanagerErrorConstant.INVALID_REQUEST.getErrorMessage());
		}

		if (appId.equalsIgnoreCase(signApplicationid) && refId.equalsIgnoreCase(certificateSignRefID)) {
			LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.APPLICATIONID, null,
					"Not allowed to revoke key. AppId: KERNEL & RefId: SIGN.");
			throw new KeymanagerServiceException(KeymanagerErrorConstant.REVOKE_NOT_ALLOWED.getErrorCode(),
					KeymanagerErrorConstant.REVOKE_NOT_ALLOWED.getErrorMessage());
		}

		LocalDateTime timestamp = DateUtils.getUTCCurrentDateTime();
		Map<String, List<KeyAlias>> keyAliasMap = dbHelper.getKeyAliases(appId, refId, timestamp);
		List<KeyAlias> currentKeyAlias = keyAliasMap.get(KeymanagerConstant.CURRENTKEYALIAS);

		if (currentKeyAlias.isEmpty() || currentKeyAlias.size() > 1) {
			LOGGER.error(KeymanagerConstant.SESSIONID, KeymanagerConstant.CURRENTKEYALIAS,
					String.valueOf(currentKeyAlias.size()), "CurrentKeyAlias size more than one");
			throw new NoUniqueAliasException(KeymanagerErrorConstant.NO_UNIQUE_ALIAS.getErrorCode(),
					KeymanagerErrorConstant.NO_UNIQUE_ALIAS.getErrorMessage());
		}

		LOGGER.debug(KeymanagerConstant.SESSIONID, appId, refId, "Invalidating the current valid key.");
		
		LocalDateTime expireTime = timestamp.minusMinutes(1L);
		KeyAlias currentAlias = currentKeyAlias.get(0);
		dbHelper.storeKeyInAlias(appId, currentAlias.getKeyGenerationTime(), refId, currentAlias.getAlias(), expireTime, 
					currentAlias.getCertThumbprint(), currentAlias.getUniqueIdentifier());
		RevokeKeyResponseDto responseDto = new RevokeKeyResponseDto();
		responseDto.setStatus(KeymanagerConstant.KEY_REVOKED);
		responseDto.setTimestamp(timestamp);
		return responseDto;
	}

	@Override
	public AllCertificatesDataResponseDto getAllCertificates(String appId, Optional<String> refId) {

		LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.APPLICATIONID, appId,
				KeymanagerConstant.ALL_GET_CERTIFICATES);
		LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.REFERENCEID, refId.toString(),
				KeymanagerConstant.ALL_GET_CERTIFICATES);
		
		LocalDateTime localDateTimeStamp = DateUtils.getUTCCurrentDateTime();
		CertificateDataResponseDto[] certificateDataList = null;
		if (!refId.isPresent() || refId.get().trim().isEmpty()) {
			LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY,
					"Reference Id is not present. Will get All Certificates from HSM");
			certificateDataList = getAllCertificatesFromHSM(appId, localDateTimeStamp, KeymanagerConstant.EMPTY);
		} else if ((appId.equalsIgnoreCase(signApplicationid) && refId.isPresent()
											&& refId.get().equals(certificateSignRefID)) || 
						(refId.isPresent() && refId.get().equals(KeyReferenceIdConsts.EC_SECP256K1_SIGN.name())) ||
						(refId.isPresent() && refId.get().equals(KeyReferenceIdConsts.EC_SECP256R1_SIGN.name())) ||
						(refId.isPresent() && refId.get().equals(KeyReferenceIdConsts.ED25519_SIGN.name())
						 && ed25519SupportFlag)) {
			LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY,
					"Reference Id is present and it is " + refId.get() + " reference. Will get all certificates from HSM");
			certificateDataList = getAllCertificatesFromHSM(appId, localDateTimeStamp, refId.get());
		} else {
			LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY,
					"Reference Id is present. Will get Certificate from DB store");
			certificateDataList = getAllCertificatesFromDBStore(appId, localDateTimeStamp, refId.get());
		}
		LOGGER.info(KeymanagerConstant.SESSIONID, KeymanagerConstant.EMPTY, KeymanagerConstant.EMPTY,
					"Total Number of certificates found:" + certificateDataList.length);
		AllCertificatesDataResponseDto allCertificatesDataResponseDto = new AllCertificatesDataResponseDto();
		allCertificatesDataResponseDto.setAllCertificates(certificateDataList);
		return allCertificatesDataResponseDto;
	}

	private CertificateDataResponseDto[] getAllCertificatesFromHSM(String applicationId, LocalDateTime timeStamp, 
			String referenceId) {
		Map<String, List<KeyAlias>> keyAliasMap = dbHelper.getKeyAliases(applicationId, referenceId, timeStamp);
		List<KeyAlias> keyAliases = keyAliasMap.get(KeymanagerConstant.KEYALIAS);
		List<CertificateDataResponseDto> certDataRespList = new ArrayList<>(); 

		for (KeyAlias keyAlias: keyAliases) {
			X509Certificate x509Cert = (X509Certificate) keyStore.getCertificate(keyAlias.getAlias());
			String pemFormatCert = keymanagerUtil.getPEMFormatedData(x509Cert);
			LocalDateTime issuedAt = keyAlias.getKeyGenerationTime();
			LocalDateTime expiryAt = keyAlias.getKeyExpiryTime();
			String keyId = SignatureUtil.convertHexToBase64(keyAlias.getUniqueIdentifier());
			certDataRespList.add(new CertificateDataResponseDto(pemFormatCert, issuedAt, expiryAt, keyId));
		}
		return certDataRespList.toArray(new CertificateDataResponseDto[0]);
	}

	private CertificateDataResponseDto[] getAllCertificatesFromDBStore (String applicationId, LocalDateTime timeStamp, 
				String referenceId){
		Map<String, List<KeyAlias>> keyAliasMap = dbHelper.getKeyAliases(applicationId, referenceId, timeStamp);
		List<KeyAlias> keyAliases = keyAliasMap.get(KeymanagerConstant.KEYALIAS);
		List<CertificateDataResponseDto> certDataRespList = new ArrayList<>(); 
		for (KeyAlias keyAlias: keyAliases) {
			Optional<io.mosip.kernel.keymanagerservice.entity.KeyStore> keyFromDBStore = dbHelper
					.getKeyStoreFromDB(keyAlias.getAlias());
			if (keyFromDBStore.isPresent()) {
				String certificateData = keyFromDBStore.get().getCertificateData();
				X509Certificate x509Cert = (X509Certificate) keymanagerUtil.convertToCertificate(certificateData);
				String pemFormatCert = keymanagerUtil.getPEMFormatedData(x509Cert);
				LocalDateTime issuedAt = keyAlias.getKeyGenerationTime();
				LocalDateTime expiryAt = keyAlias.getKeyExpiryTime();
				String keyId = SignatureUtil.convertHexToBase64(keyAlias.getUniqueIdentifier());
				certDataRespList.add(new CertificateDataResponseDto(pemFormatCert, issuedAt, expiryAt, keyId));
			} 
		}
		return certDataRespList.toArray(new CertificateDataResponseDto[0]);
	}

	@Override
	public KeyPairGenerateResponseDto generateECSignKey(String objectType, KeyPairGenerateRequestDto request) {
		LOGGER.info(KeymanagerConstant.SESSIONID, this.getClass().getSimpleName(), KeymanagerConstant.EMPTY,
				KeymanagerConstant.GENERATE_ECC_MASTER_KEY);

		String applicationId = request.getApplicationId();
		String refId = request.getReferenceId() == null ? KeymanagerConstant.EMPTY : request.getReferenceId();
		Boolean forceFlag = request.getForce() == null ? Boolean.FALSE : request.getForce();

		LOGGER.info(KeymanagerConstant.SESSIONID, this.getClass().getSimpleName(), KeymanagerConstant.EMPTY, 
					KeymanagerConstant.APPLICATIONID + ": " + applicationId);
		LOGGER.info(KeymanagerConstant.SESSIONID, this.getClass().getSimpleName(), KeymanagerConstant.EMPTY, 
				KeymanagerConstant.REFERENCEID + ":" + refId.toString());
		
		ecKeyPairGenRequestValidator.validate(objectType, request);
		return generateKey(objectType, applicationId, refId, forceFlag, request);
	}
}
