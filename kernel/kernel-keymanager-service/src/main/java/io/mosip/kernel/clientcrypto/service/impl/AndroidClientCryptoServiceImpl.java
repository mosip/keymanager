package io.mosip.kernel.clientcrypto.service.impl;

import io.mosip.kernel.clientcrypto.constant.ClientCryptoErrorConstants;
import io.mosip.kernel.clientcrypto.constant.ClientCryptoManagerConstant;
import io.mosip.kernel.clientcrypto.exception.ClientCryptoException;
import io.mosip.kernel.clientcrypto.service.spi.ClientCryptoService;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.keymanagerservice.logger.KeymanagerLogger;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import jakarta.validation.constraints.NotNull;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;

public class AndroidClientCryptoServiceImpl implements ClientCryptoService {

    private static final Logger LOGGER = KeymanagerLogger.getLogger(AndroidClientCryptoServiceImpl.class);
    private static final String ALGORITHM = "RSA";
    private static final String SIGN_ALGORITHM = "SHA256withRSA";
    private static final String ASYMMETRIC_ALGORITHM = "RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING";
    private static final String ASYMMETRIC_ALGO_MD = "SHA-256";
    private static final String ASYMMETRIC_ALGO_MGF = "MGF1";

    @Override
    public byte[] signData(@NotNull byte[] dataToSign) throws ClientCryptoException {
        return new byte[0];
    }

    @Override
    public boolean validateSignature(@NotNull byte[] signature, @NotNull byte[] actualData) throws ClientCryptoException {
        return validateSignature(getSigningPublicPart(), signature, actualData);
    }

    @Override
    public byte[] asymmetricEncrypt(@NotNull byte[] plainData) throws ClientCryptoException {
        return new byte[0];
    }

    @Override
    public byte[] asymmetricDecrypt(@NotNull byte[] cipher) throws ClientCryptoException {
        return asymmetricEncrypt(getEncryptionPublicPart(), cipher);
    }

    @Override
    public byte[] getSigningPublicPart() {
        return new byte[0];
    }

    @Override
    public void closeSecurityInstance() throws ClientCryptoException {
        //Do nothing
    }

    @Override
    public boolean isTPMInstance() {
        return false;
    }

    @Override
    public byte[] getEncryptionPublicPart() {
        return new byte[0];
    }

    public static boolean validateSignature(byte[] public_key, byte[] signature, byte[] actualData)
            throws ClientCryptoException {
        LOGGER.debug("AndroidClientSecurity validate signature invoked");
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(public_key);
            KeyFactory kf = KeyFactory.getInstance(ALGORITHM);
            PublicKey publicKey = kf.generatePublic(keySpec);

            Signature sign = Signature.getInstance(SIGN_ALGORITHM);
            sign.initVerify(publicKey);
            sign.update(actualData);
            return sign.verify(signature);
        } catch (Exception ex) {
            throw new ClientCryptoException(ClientCryptoErrorConstants.CRYPTO_FAILED.getErrorCode(),
                    ClientCryptoErrorConstants.CRYPTO_FAILED.getErrorMessage(), ex);
        }
    }


    public static byte[] asymmetricEncrypt(byte[] public_key, byte[] dataToEncrypt) throws ClientCryptoException {
        LOGGER.debug("AndroidClientSecurity asymmetricEncrypt invoked");
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(public_key);
            KeyFactory kf = KeyFactory.getInstance(ALGORITHM);
            PublicKey publicKey = kf.generatePublic(keySpec);

            //Only SHA-1 is the supported MGF digest currently
            final Cipher cipher_asymmetric = Cipher.getInstance(ASYMMETRIC_ALGORITHM);
            cipher_asymmetric.init(Cipher.ENCRYPT_MODE, publicKey, new OAEPParameterSpec(
                    ASYMMETRIC_ALGO_MD, ASYMMETRIC_ALGO_MGF, MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT));
            return cipher_asymmetric.doFinal(dataToEncrypt);
        } catch (Exception ex) {
            throw new ClientCryptoException(ClientCryptoErrorConstants.CRYPTO_FAILED.getErrorCode(),
                    ClientCryptoErrorConstants.CRYPTO_FAILED.getErrorMessage(), ex);
        }
    }
}
