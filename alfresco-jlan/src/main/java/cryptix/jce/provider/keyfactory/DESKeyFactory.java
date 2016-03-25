/* $Id: DESKeyFactory.java,v 1.1 2000/06/09 21:37:31 pw Exp $
 *
 * Copyright (C) 1995-2000 The Cryptix Foundation Limited.
 * All rights reserved.
 *
 * Use, modification, copying and distribution of this software is subject
 * the terms and conditions of the Cryptix General Licence. You should have
 * received a copy of the Cryptix General License along with this library;
 * if not, you can download a copy from http://www.cryptix.org/ .
 */
package cryptix.jce.provider.keyfactory;


import cryptix.jce.provider.key.RawSecretKey;

import java.security.InvalidKeyException;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;

import javax.crypto.spec.DESKeySpec;


/**
 * This is the KeyFactory for DES.
 * It translates key specs and secret keys into DESKeys.
 *
 * @author: Josef Hartmann (jhartmann@bigfoot.com)
 * @version: $Revision: 1.1 $
 */
public final class DESKeyFactory extends SecretKeyFactorySpi
{
    private DESKeySpec desKeySpec = null;

    /**
     * This method generates a secret key based
     * on the given KeySpec.
     * Either decode data of the key or regenerate the key based
     * on the keyspec.
     *
     * @param keySpec KeySpec Instance of DESKeySpec
     * @returns: SecretKey based on KeySpec.
     * @exception: InvalidKeySpecException if something goes wrong.
     */
    protected SecretKey engineGenerateSecret(KeySpec keySpec)
    throws InvalidKeySpecException
    {
        // Check if parameter is valid.
        if ((keySpec==null) || !(keySpec instanceof DESKeySpec))
        {
            // FIXME: Anything else to do here?
            // We could do keySpec.getEncoded()
            throw new InvalidKeySpecException(
                "Cannot generate SecretKey using given KeySpec.");
        }
        else
        {
            //FIXME: what to do here?
            // We could get not a DESKeySpec which could be converted!!
        }

        // keySpec is valid -> cast keySpec
        desKeySpec = (DESKeySpec) keySpec;

        // create DES key using the keySpec.
        RawSecretKey key = null;

        key = new RawSecretKey("DES",desKeySpec.getKey());

        return key;

    }


    /**
     * This method returns a key specification of the given secret key
     * using the provided key spec class as the output format.
     *
     *
     * @param key SecretKey The key to use for creating the key specification.
     * @param keySpec Class The key format of the returning KeySpec value.
     * @returns The key specification in the requested format.
     * @exception InvalidKeySpecException If something goes wrong.
     */
    protected KeySpec engineGetKeySpec(SecretKey key, Class keySpec)
    throws InvalidKeySpecException
    {
        // FIXME: add code.
        return (KeySpec)null;
    }


    /**
     * This method translates a secret key of an untrusted or
     * unknown provider into a "valid" secret key.
     *
     * status: pending, not tested.
     *
     * @param key SecretKey Key to translate.
     * @returns A secret key.
     * @exception InvalidKeyException
     */
    protected SecretKey engineTranslateKey(SecretKey key)
    throws InvalidKeyException
    {
        // FIXME: add code.
        return (SecretKey)null;
    }
}
