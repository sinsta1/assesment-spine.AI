package com.bist.backendmodule.helpers;

import com.bist.backendmodule.exceptions.AlgorithmNotFoundException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

/**
 * Utility class for generating and providing a secret key for JWT signing.
 */
public class KeyGenUtil {
    private static final SecretKey GENERATED_SECRET_KEY;
    private static final String SIGNING_ALGORITHM = "HmacSHA256";

    // Key generating bench
    static {
        try {
            KeyGenerator generator = KeyGenerator.getInstance(SIGNING_ALGORITHM);
            generator.init(256);
            GENERATED_SECRET_KEY = generator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new AlgorithmNotFoundException("Failed to generate key using " + SIGNING_ALGORITHM, e, KeyGenUtil.class);
        }
    }

    /**
     * Returns the generated secret key.
     *
     * @return The secret key
     */
    public static SecretKey fetchGeneratedKey() {
        return GENERATED_SECRET_KEY;
    }
}
