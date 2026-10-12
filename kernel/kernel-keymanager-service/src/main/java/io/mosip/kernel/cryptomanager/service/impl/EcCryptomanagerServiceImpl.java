package io.mosip.kernel.cryptomanager.service.impl;

import io.mosip.kernel.core.exception.NoSuchAlgorithmException;
import io.mosip.kernel.core.keymanager.spi.KeyStore;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.kernel.crypto.jce.constant.SecurityExceptionCodeConstant;
import io.mosip.kernel.crypto.jce.util.CryptoUtils;
import io.mosip.kernel.cryptomanager.constant.CryptomanagerConstant;
import io.mosip.kernel.cryptomanager.service.EcCryptomanagerService;
import io.mosip.kernel.keymanager.hsm.impl.KeyStoreImpl;
import io.mosip.kernel.keymanagerservice.constant.KeymanagerConstant;
import io.mosip.kernel.keymanagerservice.logger.KeymanagerLogger;
import io.mosip.kernel.core.crypto.exception.InvalidKeyException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Objects;

@Service
public class EcCryptomanagerServiceImpl implements EcCryptomanagerService {

    @Autowired
    private KeyStore keyStore;

    private static final String AES = "AES";

    @Value("${mosip.kernel.data-key-splitter}")
    private String keySplitter;

    @Value("${mosip.kernel.crypto.gcm-tag-length:128}")
    private int tagLength;

    @Value("${mosip.kernel.crypto.symmetric-algorithm-name:AES/GCM/NoPadding}")
    private String symmetricAlgorithmName;

    private static final Logger LOGGER = KeymanagerLogger.getLogger(EcCryptomanagerServiceImpl.class);

    private static final String reason = "CryptoManager";

    private static final int AES_KEY_LENGTH = 32; // AES-256

    private static final String HMAC_SHA_256 = "HmacSHA256";

    private static final String EC_ALGORITHM = "EC";

    private static final String ECDH = "ECDH";

    private static final String BC_PROVIDER = "BC";

    @Override
    public byte[] asymmetricEcEncrypt(PublicKey key, byte[] data, String curveName) {
        Objects.requireNonNull(key, SecurityExceptionCodeConstant.MOSIP_INVALID_KEY_EXCEPTION.getErrorMessage());
        CryptoUtils.verifyData(data);
        return asymmetricEcEncrypt(key, data, null, null, curveName);
    }

    @Override
    public byte[] asymmetricEcEncrypt(PublicKey key, byte[] data, byte[] randomIV, byte[] aad, String curveName) {
        byte[] output;
        Cipher cipher;
        SecretKey aesKey = null;
        byte[] ephemeralPublicKey = null;
        KeyPair ephemeralKeyPair = null;

        try {
            String provider = keyStore.getKeystoreProviderName();
            ephemeralKeyPair = generateAlgorithmBasedEphemeralKeyPair(curveName, provider);
            KeyAgreement keyAgreement = getKeyAgreementAlorithmBased(key, ephemeralKeyPair.getPrivate(), curveName, provider);
            byte[] sharedSecret = keyAgreement.generateSecret();

            if (randomIV == null || randomIV.length == 0) {
                randomIV = generateIV(CryptomanagerConstant.GCM_NONCE_LENGTH); // Default IV length for AES
            }

            byte[] aesKeyBytes = getHkdfKeyBytes(sharedSecret, randomIV, reason.getBytes(), AES_KEY_LENGTH);
            aesKey = new SecretKeySpec(aesKeyBytes, 0, AES_KEY_LENGTH, AES);

            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(tagLength, randomIV);
            cipher = Cipher.getInstance(symmetricAlgorithmName);
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmParameterSpec);
            if (aad != null && aad.length != 0) {
                cipher.updateAAD(aad);
            }

            byte[] encryptedData = cipher.doFinal(data);

            byte[] encryptedDataWithIv = new byte[encryptedData.length + randomIV.length];
            ephemeralPublicKey = ephemeralKeyPair.getPublic().getEncoded();

            System.arraycopy(encryptedData, 0, encryptedDataWithIv, 0, encryptedData.length);
            System.arraycopy(randomIV, 0, encryptedDataWithIv, encryptedData.length, randomIV.length);

            byte[] keySplitterBytes = keySplitter.getBytes();
            output = new byte[encryptedDataWithIv.length + keySplitterBytes.length + ephemeralPublicKey.length];

            System.arraycopy(encryptedDataWithIv, 0, output, 0, encryptedDataWithIv.length);
            System.arraycopy(keySplitterBytes, 0, output, encryptedDataWithIv.length, keySplitterBytes.length);
            System.arraycopy(ephemeralPublicKey, 0, output, encryptedDataWithIv.length + keySplitterBytes.length, ephemeralPublicKey.length);

        } catch (java.security.NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException e) {
            throw new NoSuchAlgorithmException(
                    SecurityExceptionCodeConstant.MOSIP_NO_SUCH_ALGORITHM_EXCEPTION.getErrorCode(),
                    SecurityExceptionCodeConstant.MOSIP_NO_SUCH_ALGORITHM_EXCEPTION.getErrorMessage(), e);
        } catch (java.security.InvalidKeyException | IllegalBlockSizeException e) {
            throw new InvalidKeyException(
                    SecurityExceptionCodeConstant.MOSIP_INVALID_KEY_EXCEPTION.getErrorCode(),
                    SecurityExceptionCodeConstant.MOSIP_INVALID_KEY_EXCEPTION.getErrorMessage(), e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidKeyException(
                    SecurityExceptionCodeConstant.MOSIP_INVALID_PARAM_SPEC_EXCEPTION.getErrorCode(),
                    SecurityExceptionCodeConstant.MOSIP_INVALID_PARAM_SPEC_EXCEPTION.getErrorMessage(), e);
        } finally {
            if (aesKey != null) {
                destroyKey(aesKey.getEncoded());
            }
            if (ephemeralPublicKey != null) {
                destroyKey(ephemeralPublicKey);
            }
            if (ephemeralKeyPair != null) {
                destroyKey(ephemeralKeyPair.getPrivate().getEncoded());
                destroyKey(ephemeralKeyPair.getPublic().getEncoded());
            }
        }
        return output;
    }

    @Override
    public byte[] asymmetricEcDecrypt(PrivateKey privateKey, byte[] data, byte[] aad, String algorithmName) {
        Objects.requireNonNull(privateKey, SecurityExceptionCodeConstant.MOSIP_INVALID_KEY_EXCEPTION.getErrorMessage());
        CryptoUtils.verifyData(data);
        byte[] decryptedData;
        byte[] aesKeyBytes = null;
        byte[] sharedSecret = null;

        try {
            byte[] keySplitterBytes = keySplitter.getBytes();

            int splitterIndex = 0;
            splitterIndex = CryptoUtil.getSplitterIndex(data, splitterIndex, keySplitter);

            // Extract encrypted data and ephemeral public key bytes
            byte[] encryptedData = Arrays.copyOfRange(data, 0, splitterIndex);
            byte[] ephemeralPublicKeyBytes = Arrays.copyOfRange(data, splitterIndex + keySplitterBytes.length, data.length);

            // Extract IV from the end of encryptedData
            int ivLength = CryptomanagerConstant.GCM_NONCE_LENGTH;
            byte[] iv = Arrays.copyOfRange(encryptedData, encryptedData.length - ivLength, encryptedData.length);
            byte[] cipherText = Arrays.copyOfRange(encryptedData, 0, encryptedData.length - ivLength);

            String provider = keyStore.getKeystoreProviderName();
            PublicKey ephemeralPublicKey = getAlgorithmBasedEphemeralPublicKey(ephemeralPublicKeyBytes, privateKey.getAlgorithm(), provider);
            KeyAgreement keyAgreement = getKeyAgreementAlorithmBased(ephemeralPublicKey, privateKey, privateKey.getAlgorithm(), provider);
            sharedSecret = keyAgreement.generateSecret();

            aesKeyBytes = getHkdfKeyBytes(sharedSecret, iv, reason.getBytes(), AES_KEY_LENGTH);
            SecretKey aesKey = new SecretKeySpec(aesKeyBytes, 0, AES_KEY_LENGTH, AES);

            Cipher aesCipher = Cipher.getInstance(symmetricAlgorithmName);
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(tagLength, iv);
            aesCipher.init(Cipher.DECRYPT_MODE, aesKey, gcmParameterSpec);
            if (aad != null && aad.length != 0) {
                aesCipher.updateAAD(aad);
            }
            decryptedData = aesCipher.doFinal(cipherText);
        } catch (java.security.NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException e) {
            throw new NoSuchAlgorithmException(
                    SecurityExceptionCodeConstant.MOSIP_NO_SUCH_ALGORITHM_EXCEPTION.getErrorCode(),
                    SecurityExceptionCodeConstant.MOSIP_NO_SUCH_ALGORITHM_EXCEPTION.getErrorMessage(), e);
        } catch (java.security.InvalidKeyException | IllegalBlockSizeException e) {
            throw new InvalidKeyException(
                    SecurityExceptionCodeConstant.MOSIP_INVALID_KEY_EXCEPTION.getErrorCode(),
                    SecurityExceptionCodeConstant.MOSIP_INVALID_KEY_EXCEPTION.getErrorMessage(), e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidKeyException(
                    SecurityExceptionCodeConstant.MOSIP_INVALID_PARAM_SPEC_EXCEPTION.getErrorCode(),
                    SecurityExceptionCodeConstant.MOSIP_INVALID_PARAM_SPEC_EXCEPTION.getErrorMessage(), e);
        } finally {
            if (aesKeyBytes != null)
                destroyKey(aesKeyBytes);

            if (sharedSecret != null)
                destroyKey(sharedSecret);
        }
        return decryptedData;
    }

    /**
     * Generator for IV (Initialization Vector)
     *
     * @param blockSize blocksize of current cipher
     * @return generated IV
     */
    private byte[] generateIV(int blockSize) {
        byte[] byteIV = new byte[blockSize];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(byteIV);
        return byteIV;
    }

    /**
     * Destroys the key by filling it with zeros.
     *
     * @param key The key to be destroyed.
     */
    private void destroyKey(byte[] key) {
        if (Objects.nonNull(key)) {
            Arrays.fill(key, (byte) 0);
        }
    }

    /**
     * Generates HKDF key bytes using the provided secret, salt, reason, and key length.
     *
     * @param ikm       The Input Key Material (IKM) to derive the key from.
     * @param salt      The salt to use in the HKDF process.
     * @param reason    The reason for generating the key, used as additional data.
     * @param keyLength The desired length of the generated key in bytes.
     * @return The derived key bytes.
     */
    private byte[] getHkdfKeyBytes(byte[] ikm, byte[] salt, byte[] reason, int keyLength) {
        LOGGER.info(CryptomanagerConstant.SESSIONID, CryptomanagerConstant.WHITESPACE, CryptomanagerConstant.WHITESPACE,
                "Generating HKDF key bytes.");

        try {
            Mac mac = Mac.getInstance(HMAC_SHA_256);
            SecretKeySpec secretKeySpec = new SecretKeySpec(salt, HMAC_SHA_256);
            mac.init(secretKeySpec);
            byte[] prk = mac.doFinal(ikm);

            byte[] result = new byte[keyLength];
            byte[] previousBlock = new byte[0];
            int bytegenerated = 0;
            int iteration = (int) Math.ceil((double) keyLength / mac.getMacLength());

            for (int i = 0; i < iteration; i++) {
                mac.init(new SecretKeySpec(prk, HMAC_SHA_256));
                mac.update(previousBlock);
                mac.update(reason);
                mac.update((byte) (i + 1));
                byte[] block = mac.doFinal();

                int bytesToCopy = Math.min(block.length, keyLength - bytegenerated);
                System.arraycopy(block, 0, result, bytegenerated, bytesToCopy);
                bytegenerated += bytesToCopy;

                previousBlock = block;
                LOGGER.info(CryptomanagerConstant.SESSIONID, CryptomanagerConstant.WHITESPACE, CryptomanagerConstant.WHITESPACE,
                        "Number of iterations: " + (i + 1) + ", Bytes generated so far: " + bytegenerated);
            }
            return result;
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new NoSuchAlgorithmException(
                    SecurityExceptionCodeConstant.MOSIP_NO_SUCH_ALGORITHM_EXCEPTION.getErrorCode(),
                    SecurityExceptionCodeConstant.MOSIP_NO_SUCH_ALGORITHM_EXCEPTION.getErrorMessage(), e);
        } catch (java.security.InvalidKeyException e) {
            throw new InvalidKeyException(
                    SecurityExceptionCodeConstant.MOSIP_INVALID_KEY_EXCEPTION.getErrorCode(),
                    SecurityExceptionCodeConstant.MOSIP_INVALID_KEY_EXCEPTION.getErrorMessage(), e);
        }
    }

    private KeyPair generateAlgorithmBasedEphemeralKeyPair(String curveName, String provider) {
        KeyPairGenerator ephemeralKeyPairGen;
        try {
            if (curveName.equals(KeymanagerConstant.X25519_KEY_TYPE) || curveName.equals(KeymanagerConstant.XDH_ALGORITHM)) {
                ephemeralKeyPairGen = KeyPairGenerator.getInstance(KeymanagerConstant.X25519_KEY_TYPE, provider);
                NamedParameterSpec x25519GenParameterSpec = new NamedParameterSpec(KeymanagerConstant.X25519_KEY_TYPE);
                ephemeralKeyPairGen.initialize(x25519GenParameterSpec);
                return ephemeralKeyPairGen.generateKeyPair();
            } else {
                ephemeralKeyPairGen = KeyPairGenerator.getInstance(EC_ALGORITHM, provider);
                ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec(curveName);
                ephemeralKeyPairGen.initialize(ecGenParameterSpec);
                return ephemeralKeyPairGen.generateKeyPair();
            }
        } catch (InvalidAlgorithmParameterException | java.security.NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new NoSuchAlgorithmException(
                    SecurityExceptionCodeConstant.MOSIP_NO_SUCH_ALGORITHM_EXCEPTION.getErrorCode(),
                    SecurityExceptionCodeConstant.MOSIP_NO_SUCH_ALGORITHM_EXCEPTION.getErrorMessage(), e);
        }
    }

    public KeyAgreement getKeyAgreementAlorithmBased(PublicKey key, PrivateKey privateKey, String curveName, String provider) {
        if (curveName.equals(KeymanagerConstant.X25519_KEY_TYPE) || curveName.equals(KeymanagerConstant.XDH_ALGORITHM))
            return getKeyAgreement(key, privateKey, KeymanagerConstant.X25519_KEY_TYPE, provider);
        else
            return getKeyAgreement(key, privateKey, ECDH, provider);
    }

    private KeyAgreement getKeyAgreement(PublicKey publicKey, PrivateKey privateKey, String algorithm, String provider) {
        KeyAgreement keyAgreement;
        try {
            keyAgreement = KeyAgreement.getInstance(algorithm, provider);
            keyAgreement.init(privateKey);
            keyAgreement.doPhase(publicKey, true);
        } catch (java.security.NoSuchAlgorithmException | java.security.InvalidKeyException | NoSuchProviderException e) {
            throw new InvalidKeyException(
                    SecurityExceptionCodeConstant.MOSIP_INVALID_KEY_EXCEPTION.getErrorCode(),
                    SecurityExceptionCodeConstant.MOSIP_INVALID_KEY_EXCEPTION.getErrorMessage(), e);
        }
        return keyAgreement;
    }

    public PublicKey getAlgorithmBasedEphemeralPublicKey(byte[] ephemeralPublicKeyBytes, String curveName, String provider) {
        if (curveName.equals(KeymanagerConstant.X25519_KEY_TYPE) || curveName.equals(KeymanagerConstant.XDH_ALGORITHM))
            return getEphemeralPublicKey(ephemeralPublicKeyBytes, KeymanagerConstant.X25519_KEY_TYPE, provider);
        else
            return getEphemeralPublicKey(ephemeralPublicKeyBytes, EC_ALGORITHM, provider);
    }

    private PublicKey getEphemeralPublicKey(byte[] ephemeralPublicKeyBytes, String algo, String provider) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(algo, BC_PROVIDER);
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(ephemeralPublicKeyBytes);
            return keyFactory.generatePublic(publicKeySpec);
        } catch (java.security.NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException e) {
            throw new InvalidKeyException(
                    SecurityExceptionCodeConstant.MOSIP_INVALID_KEY_EXCEPTION.getErrorCode(),
                    SecurityExceptionCodeConstant.MOSIP_INVALID_KEY_EXCEPTION.getErrorMessage(), e);
        }
    }
}