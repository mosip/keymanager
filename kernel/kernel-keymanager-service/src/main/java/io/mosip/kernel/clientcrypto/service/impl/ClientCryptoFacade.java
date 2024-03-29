package io.mosip.kernel.clientcrypto.service.impl;

import io.mosip.kernel.clientcrypto.constant.ClientCryptoErrorConstants;
import io.mosip.kernel.clientcrypto.constant.ClientCryptoManagerConstant;
import io.mosip.kernel.clientcrypto.constant.ClientType;
import io.mosip.kernel.clientcrypto.exception.ClientCryptoException;
import io.mosip.kernel.clientcrypto.service.spi.ClientCryptoService;
import io.mosip.kernel.core.crypto.spi.CryptoCoreSpec;
import io.mosip.kernel.core.exception.ExceptionUtils;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.keymanagerservice.logger.KeymanagerLogger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;
import tss.tpm.TPMT_PUBLIC;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

@Component
public class ClientCryptoFacade {

    private static final Logger LOGGER = KeymanagerLogger.getLogger(ClientCryptoFacade.class);
    private static SecureRandom secureRandom = null;
    private static ClientCryptoService clientCryptoService = null;

    @Autowired
    private CryptoCoreSpec<byte[], byte[], SecretKey, PublicKey, PrivateKey, String> cryptoCore;

    @Autowired
    private Environment environment;

    @Autowired
    private ApplicationContext applicationContext;

    @Value("${mosip.kernel.client.crypto.use-resident-service-module-key:false}")
    private Boolean useResidentServiceModuleKey;

    @Value("${mosip.kernel.client.crypto.resident-service-app-id:RESIDENT}")
    private String residentServiceAppId;

    @Value("${mosip.kernel.client.crypto.iv-length:12}")
    private int ivLength;

    @Value("${mosip.kernel.client.crypto.aad-length:32}")
    private int aadLength;

    //we are using 2048 bit RSA key
    @Value("${mosip.kernel.client.crypto.sym-key-length:256}")
    private int symmetricKeyLength;

    @Deprecated
    public static void setIsTPMRequired(boolean flag) {
        //nothing to do @since 1.1.4
    }

    private void initializeClientSecurity() {
        LOGGER.debug(ClientCryptoManagerConstant.SESSIONID, ClientCryptoManagerConstant.INITIALIZATION,
                ClientCryptoManagerConstant.EMPTY, "initializeClientSecurity >>> started");

        try {
            clientCryptoService = new TPMClientCryptoServiceImpl();
        } catch(Throwable e) {
            LOGGER.debug(ClientCryptoManagerConstant.SESSIONID, ClientCryptoManagerConstant.INITIALIZATION,
                    ClientCryptoManagerConstant.EMPTY, ExceptionUtils.getStackTrace(e));
        }

        if(clientCryptoService == null) {
            try {
                LOGGER.warn(ClientCryptoManagerConstant.SESSIONID, ClientCryptoManagerConstant.INITIALIZATION, ClientCryptoManagerConstant.EMPTY,
                        "USING LOCAL CLIENT SECURITY INITIALIZED, IGNORE IF THIS IS NON-PROD ENV");
                clientCryptoService = new LocalClientCryptoServiceImpl(cryptoCore, applicationContext,
                    useResidentServiceModuleKey, residentServiceAppId);
            } catch (Throwable ex) {
                LOGGER.error(ClientCryptoManagerConstant.SESSIONID, ClientCryptoManagerConstant.INITIALIZATION,
                        ClientCryptoManagerConstant.EMPTY, ExceptionUtils.getStackTrace(ex));
            }
        }

        if(clientCryptoService == null) {
            LOGGER.error(ClientCryptoManagerConstant.SESSIONID, ClientCryptoManagerConstant.INITIALIZATION,
                    ClientCryptoManagerConstant.EMPTY, "Failed to get client security instance.");
            throw new ClientCryptoException(ClientCryptoErrorConstants.INITIALIZATION_ERROR.getErrorCode(),
                    ClientCryptoErrorConstants.INITIALIZATION_ERROR.getErrorMessage());
        }

        LOGGER.debug(ClientCryptoManagerConstant.SESSIONID, ClientCryptoManagerConstant.INITIALIZATION,
                ClientCryptoManagerConstant.EMPTY, "initializeClientSecurity >>> Completed");
    }

    public ClientCryptoService getClientSecurity() {
        if(clientCryptoService == null) {
            initializeClientSecurity();
        }
        return clientCryptoService;
    }

    public boolean validateSignature(byte[] publicKey, byte[] signature, byte[] actualData) {
       return validateSignature(ClientType.LOCAL, publicKey, signature, actualData);
    }

    public byte[] encrypt(byte[] publicKey, byte[] dataToEncrypt) {
        return encrypt(ClientType.LOCAL, publicKey, dataToEncrypt);
    }

    public boolean validateSignature(ClientType clientType, byte[] publicKey, byte[] signature, byte[] actualData) {
        clientType = isTPMKey(publicKey) ? ClientType.TPM : clientType;

        switch (clientType == null ? clientType.LOCAL : clientType) {
            case TPM:
                return TPMClientCryptoServiceImpl.validateSignature(publicKey, signature, actualData);
            case ANDROID:
                return AndroidClientCryptoServiceImpl.validateSignature(publicKey, signature, actualData);
        }
        LOGGER.warn("USING LOCAL CLIENT SECURITY USED TO SIGN DATA, IGNORE IF THIS IS NON-PROD ENV");
        return LocalClientCryptoServiceImpl.validateSignature(publicKey, signature, actualData);
    }

    public byte[] encrypt(ClientType clientType, byte[] publicKey, byte[] dataToEncrypt) {
        clientType = isTPMKey(publicKey) ? ClientType.TPM : clientType;

        SecretKey secretKey = getSecretKey();
        byte[] iv = generateRandomBytes(ivLength);
        byte[] aad = generateRandomBytes(aadLength);
        byte[] cipher = cryptoCore.symmetricEncrypt(secretKey, dataToEncrypt, iv, aad);

        byte[] encryptedSecretKey = null;
        switch (clientType == null ? clientType.LOCAL : clientType)  {
            case TPM:
                encryptedSecretKey = TPMClientCryptoServiceImpl.asymmetricEncrypt(publicKey, secretKey.getEncoded());
                break;
            case ANDROID:
                encryptedSecretKey = AndroidClientCryptoServiceImpl.asymmetricEncrypt(publicKey, secretKey.getEncoded());
                break;
            default:
                LOGGER.warn("USING LOCAL CLIENT SECURITY USED TO ENCRYPT DATA, IGNORE IF THIS IS NON-PROD ENV");
                LocalClientCryptoServiceImpl.cryptoCore = this.cryptoCore;
                encryptedSecretKey = LocalClientCryptoServiceImpl.asymmetricEncrypt(publicKey, secretKey.getEncoded());
                break;
        }
        Objects.requireNonNull(encryptedSecretKey);
        byte[] processedData = new byte[cipher.length+encryptedSecretKey.length+iv.length+aad.length];
        System.arraycopy(encryptedSecretKey,0,processedData, 0, encryptedSecretKey.length);
        System.arraycopy(iv, 0, processedData, encryptedSecretKey.length, iv.length);
        System.arraycopy(aad, 0, processedData, encryptedSecretKey.length + iv.length, aad.length);
        System.arraycopy(cipher, 0, processedData, encryptedSecretKey.length + iv.length + aad.length, cipher.length);
        return processedData;
    }

    public byte[] decrypt(byte[] dataToDecrypt) {
        byte[] encryptedSecretKey = Arrays.copyOfRange(dataToDecrypt, 0, symmetricKeyLength);
        byte[] secretKeyBytes =  Objects.requireNonNull(getClientSecurity()).asymmetricDecrypt(encryptedSecretKey);
        SecretKey secretKey = new SecretKeySpec(secretKeyBytes, "AES");

        try {
            byte[] iv = Arrays.copyOfRange(dataToDecrypt, symmetricKeyLength, symmetricKeyLength + ivLength);
            byte[] aad = Arrays.copyOfRange(dataToDecrypt, symmetricKeyLength + ivLength, symmetricKeyLength + ivLength + aadLength);
            byte[] cipher = Arrays.copyOfRange(dataToDecrypt, symmetricKeyLength + ivLength + aadLength,
                    dataToDecrypt.length);
            return cryptoCore.symmetricDecrypt(secretKey, cipher, iv, aad);
        } catch (Throwable t) {
            LOGGER.error("Failed to decrypt the data due to : ", t.getMessage());
            //1.1.4.4 backward compatibility code, for IV_LENGTH = 16 and AAD_LENGTH = 12;
            byte[] iv = Arrays.copyOfRange(dataToDecrypt, symmetricKeyLength, symmetricKeyLength + 16);
            byte[] aad = Arrays.copyOfRange(dataToDecrypt, symmetricKeyLength + 16, symmetricKeyLength + 16 + 12);
            byte[] cipher = Arrays.copyOfRange(dataToDecrypt, symmetricKeyLength + 16 + 12,
                    dataToDecrypt.length);
            return cryptoCore.symmetricDecrypt(secretKey, cipher, iv, aad);
        }
    }

    public static byte[] generateRandomBytes(int length) {
        if(secureRandom == null)
            secureRandom = new SecureRandom();

        byte[] bytes = new byte[length];
        secureRandom.nextBytes(bytes);
        return bytes;
    }

    private static SecretKey getSecretKey() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256);
            return keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            LOGGER.info(ClientCryptoManagerConstant.SESSIONID, "Client Security FACADE",
                    ClientCryptoManagerConstant.EMPTY, "Failed to generate secret key " + ExceptionUtils.getStackTrace(e));
        }
        // Removed returning null, instead throwing exception to understand that key generation has failed. Otherwise it is possible for null pointer exception.
        throw new ClientCryptoException(ClientCryptoErrorConstants.NOT_ABLE_GENERATE_KEY.getErrorCode(),
                    ClientCryptoErrorConstants.NOT_ABLE_GENERATE_KEY.getErrorMessage());
    }

    private boolean isTPMKey(byte[] publicKey) {
        try {
            TPMT_PUBLIC tpmPublic = TPMT_PUBLIC.fromTpm(publicKey);
            Objects.requireNonNull(tpmPublic);
            return true;
        } catch (Throwable t) {
            //*** INVALID TPM KEY **** As its noisy, its logged at debug level
            LOGGER.debug("*** INVALID TPM KEY **** " , t);
        }
        return false;
    }
}
