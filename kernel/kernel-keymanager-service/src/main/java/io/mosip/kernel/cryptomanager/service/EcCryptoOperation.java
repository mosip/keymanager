package io.mosip.kernel.cryptomanager.service;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface EcCryptoOperation {

    /**
     *
     * Encrypts data using an asymmetric EC public key.
     *
     * @param publicKey the public key to use for encryption
     * @param data the data to encrypt
     * @param iv the initialization vector (IV) for encryption
     * @param aad additional authenticated data (AAD)
     * @return the encrypted data
     */
    public byte[] asymmetricEcEncrypt(PublicKey publicKey, byte[] data, byte[] iv, byte[] aad, String algorithmName);

    /**
     *
     * Encrypts data using an asymmetric EC public key with a specified curve name.
     *
     * @param publicKey the public key to use for encryption
     * @param data the data to encrypt
     * @param curveName the name of the elliptic curve used
     * @return the encrypted data
     */
    public byte[] asymmetricEcEncrypt(PublicKey publicKey, byte[] data, String curveName);

    /**
     *
     * Decrypts data using an asymmetric EC private key.
     *
     * @param privateKey the private key to use for decryption
     * @param data the data to decrypt
     * @param aad additional authenticated data (AAD)
     * @param curveName the name of the elliptic curve used
     * @return the decrypted data
     */
    public byte[] asymmetricEcDecrypt(PrivateKey privateKey, byte[] data, byte[] aad, String curveName);
}
