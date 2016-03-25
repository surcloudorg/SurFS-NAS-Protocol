/* $Id: PBEKeyFactory.java,v 1.1 2000/06/09 21:37:31 pw Exp $
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

import java.lang.reflect.Constructor;
import java.lang.reflect.Array;
import java.lang.reflect.InvocationTargetException;

import java.security.InvalidKeyException;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.spec.PBEKeySpec;


/**
 * This is a KeyFactory for PBE.
 * It converts key specs and secret keys into PBEKeys.
 * It is based (as any cipher) on a service provider interface.
 * This is SecretKeyFactorySpi as PBE ciphers are using
 * secret key ciphers.
 *
 * @author: Josef Hartmann (jhartmann@bigfoot.com)
 * @version: $Revision: 1.1 $
 */

public final class PBEKeyFactory extends SecretKeyFactorySpi
{

    /** Internal storage for the PBEKeySpec. */
    private PBEKeySpec pbeKeySpec = null;

    /**
     * This method generates a secret key based
     * on the given KeySpec.
     * Either decode data of the key or regenerate the key based
     * on the keyspec.
     *
     * @param keySpec KeySpec Instance of PBEKeySpec
     * @returns: SecretKey based on KeySpec.
     * @exception: InvalidKeySpecException if something goes wrong.
     */
    protected SecretKey engineGenerateSecret(KeySpec keySpec)
    throws InvalidKeySpecException
    {
        // Check if parameter is valid.
        if ((keySpec==null) || !(keySpec instanceof PBEKeySpec))
        {
            // FIXME: Anything else to do here?
            // We could do keySpec.getEncoded()
            throw new InvalidKeySpecException(
                "Cannot generate SecretKey using given KeySpec.");
        }
        else
        {
            // FIXME: We could get a KeySpec which is not a PBEKeySpec
            // so it should be possible to convert it!
        }

        // keySpec is valid -> cast keySpec
        pbeKeySpec = (PBEKeySpec) keySpec;

        // create RawSecretKey using the keySpec.
        RawSecretKey key = new RawSecretKey("PBE",new String(pbeKeySpec.getPassword()).getBytes());

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
        if ((key==null)||(keySpec == null))
        {
            throw new InvalidKeySpecException("Null parameter provided.");
        }

        Class specClass = null;
        try
        {
            specClass = Class.forName("javax.crypto.spec.PBEKeySpec");
        }
        catch (ClassNotFoundException cnfe)
        {
            throw new InvalidKeySpecException("Cannot create"
                                    +" KeySpec class not found!");
        }

        // Check if keySpec is the same as or a super class (interface) of
        // PBEKeySpec.

        if (keySpec.isAssignableFrom(specClass))
        {

            byte [] keyData = key.getEncoded();
            char [] rawKeyData = new char[keyData.length];

            // use System.arraycopy?
            for (int i=0; i<keyData.length; i++)
            {
                rawKeyData[i] = (char)(keyData[i]);
            }

            // Use reflection to detect constructor of keySpec and create it.
            // FIXME: MAYBE JUST DO WHAT (PW) does in BlockParameters.java
            // (jh)

            Object [] initArgs = new Object[] {rawKeyData};

            // This is the parameter type the constructor should take.
            Class [] constructorArgs = {char[].class};

            KeySpec pks = null;

            // Get constructors.
            try
            {
                Constructor specConstructor =
                        keySpec.getConstructor(constructorArgs);

                pks = (KeySpec) specConstructor.newInstance(initArgs);

            }
            catch (InstantiationException e)
            {
                throw new InvalidKeySpecException("InvalidKeySpec.");
            }
            catch (IllegalAccessException e)
            {
                throw new InvalidKeySpecException("IllegalAccess.");
            }
            catch (IllegalArgumentException e)
            {
                throw new InvalidKeySpecException("Illegal constr. argument.");
            }
            catch (InvocationTargetException e)
            {
                throw new InvalidKeySpecException("InvocationTargetException.");
            }
            catch (NoSuchMethodException e)
            {
                throw new InvalidKeySpecException("Method not found.");
            }

            return pks;
        }
        else
        {
            throw new InvalidKeySpecException("Cannot assign to KeySpec.");
        }

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
        if (key == null)
        {
            throw new InvalidKeyException();
        }
        else
        {
            if ((key instanceof RawSecretKey)&&(key.getAlgorithm()=="PBE"))
            {
                // Nothing to do key is fine.
                return key;
            }
            else
            {
                // create a key using PBEKeySpec
                try
                {
                    KeySpec tmpKs = this.engineGetKeySpec(key, null);
                    return engineGenerateSecret(tmpKs);
                }
                catch (InvalidKeySpecException ikse)
                {
                    throw new InvalidKeyException("Translation not possible.");
                }

            }

        }

        // throw new InvalidKeyException();

    }

}
