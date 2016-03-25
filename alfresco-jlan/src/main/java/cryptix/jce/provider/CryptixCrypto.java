/* $Id: CryptixCrypto.java,v 1.8 2003/02/07 15:16:01 gelderen Exp $
 *
 * Copyright (C) 1995-2000 The Cryptix Foundation Limited.
 * All rights reserved.
 *
 * Use, modification, copying and distribution of this software is subject
 * the terms and conditions of the Cryptix General Licence. You should have
 * received a copy of the Cryptix General Licence along with this library;
 * if not, you can download a copy from http://www.cryptix.org/ .
 */
package cryptix.jce.provider;


import java.security.Provider;


// FIXME: Use doPrivilegedAction. See JDK 1.2 doco/tutorial.. ??
// TODO:  Report list of algorithms in INFO string?
// TODO:  Create automatic version number, based on CVS Revision.
//        How does one map 1.1.2.96 to a double in a sensible way?


/**
 * The Cryptix JCE Strong Crypto Provider.
 *
 * @version $Revision: 1.8 $
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
public final class CryptixCrypto extends Provider
{

// Static variables and constants
//...........................................................................

    private static final String
        NAME    = "CryptixCrypto",
        INFO    = "Cryptix JCE Strong Crypto Provider";
    private static final double
        VERSION = 1.3;  //FIXME: set our VERSION later?? (pw)


// Constructor
//...........................................................................

    public CryptixCrypto() 
    {
        super(NAME, VERSION, INFO);

        //
        // Symmetric Ciphers + KeyGenerators
        //

        // Blowfish
        put("Cipher.Blowfish", "cryptix.jce.provider.cipher.Blowfish");
        put("KeyGenerator.Blowfish", 
                            "cryptix.jce.provider.key.BlowfishKeyGenerator");

        // CAST5
        put("Cipher.CAST5", "cryptix.jce.provider.cipher.CAST5");
        put("KeyGenerator.CAST5", 
                            "cryptix.jce.provider.key.CAST5KeyGenerator");

        // DES
        put("Cipher.DES", "cryptix.jce.provider.cipher.DES");
        put("KeyGenerator.DES", "cryptix.jce.provider.key.DESKeyGenerator");
        put("SecretKeyFactory.DES",
                    "cryptix.jce.provider.keyfactory.DESKeyFactory");
        
        // IDEA
        put("Cipher.IDEA", "cryptix.jce.provider.cipher.IDEA");
        put("KeyGenerator.IDEA", "cryptix.jce.provider.key.IDEAKeyGenerator");

        // MARS
        put("Cipher.MARS", "cryptix.jce.provider.cipher.MARS");
        put("KeyGenerator.MARS", "cryptix.jce.provider.key.MARSKeyGenerator");

        // Null
        put("Cipher.Null", "cryptix.jce.provider.cipher.Null");
        
        // RC2
        put("Cipher.RC2", "cryptix.jce.provider.cipher.RC2");
        put("KeyGenerator.RC2", "cryptix.jce.provider.key.RC2KeyGenerator");

        // RC4
        put("Cipher.RC4", "cryptix.jce.provider.cipher.RC4");
        put("KeyGenerator.RC4", "cryptix.jce.provider.key.RC4KeyGenerator");

        // RC6
        put("Cipher.RC6", "cryptix.jce.provider.cipher.RC6");
        put("KeyGenerator.RC6", "cryptix.jce.provider.key.RC6KeyGenerator");

        // Rijndael
        put("Cipher.Rijndael", "cryptix.jce.provider.cipher.Rijndael");
        put("KeyGenerator.Rijndael", 
                            "cryptix.jce.provider.key.RijndaelKeyGenerator");

        // Serpent
        put("Cipher.Serpent", "cryptix.jce.provider.cipher.Serpent");
        put("KeyGenerator.Serpent", 
                            "cryptix.jce.provider.key.SerpentKeyGenerator");

        // SKIPJACK
        put("Cipher.SKIPJACK", "cryptix.jce.provider.cipher.SKIPJACK");
        put("KeyGenerator.SKIPJACK", 
                            "cryptix.jce.provider.key.SKIPJACKKeyGenerator");

        // Square
        put("Cipher.Square", "cryptix.jce.provider.cipher.Square");
        put("KeyGenerator.Square", 
                            "cryptix.jce.provider.key.SquareKeyGenerator");

        // TripleDES
        put("Cipher.TripleDES", "cryptix.jce.provider.cipher.TripleDES");
        put("Alg.Alias.Cipher.DESede", "TripleDES");
        put("KeyGenerator.TripleDES", 
                            "cryptix.jce.provider.key.TripleDESKeyGenerator");
        put("Alg.Alias.KeyGenerator.DESede", "TripleDES");
        
        // Twofish
        put("Cipher.Twofish", "cryptix.jce.provider.cipher.Twofish");
        put("KeyGenerator.Twofish", 
                            "cryptix.jce.provider.key.TwofishKeyGenerator");


        //
        // Macs
        //
        put("Mac.HMAC-MD5", "cryptix.jce.provider.mac.HMAC_MD5");
		put("Alg.Alias.Mac.HmacMD5", "HMAC-MD5");
		
        put("Mac.HMAC-RIPEMD", "cryptix.jce.provider.mac.HMAC_RIPEMD");
        put("Alg.Alias.Mac.HmacRIPEMD", "HMAC-RIPEMD");

        put("Mac.HMAC-RIPEMD128", "cryptix.jce.provider.mac.HMAC_RIPEMD128");
        put("Alg.Alias.Mac.HmacRIPEMD128", "HMAC-RIPEMD128");
        
        put("Mac.HMAC-RIPEMD160", "cryptix.jce.provider.mac.HMAC_RIPEMD160");
        put("Alg.Alias.Mac.HmacRIPEMD160", "HMAC-RIPEMD160");
        
        put("Mac.HMAC-SHA0", "cryptix.jce.provider.mac.HMAC_SHA0");
        put("Alg.Alias.Mac.HMAC-SHA-0", "HMAC-SHA0");
        put("Alg.Alias.Mac.HmacSHA0", "HMAC-SHA0");
        put("Alg.Alias.Mac.HmacSHA-0", "HMAC-SHA0");
        
        put("Mac.HMAC-SHA", "cryptix.jce.provider.mac.HMAC_SHA1");
        put("Alg.Alias.Mac.HMAC-SHA-1", "HMAC-SHA");
        put("Alg.Alias.Mac.HMAC-SHA1", "HMAC-SHA");
        put("Alg.Alias.Mac.HmacSHA", "HMAC-SHA");
        put("Alg.Alias.Mac.HmacSHA-1", "HMAC-SHA");
        
        put("Mac.HMAC-Tiger", "cryptix.jce.provider.mac.HMAC_Tiger");
        
        put("Mac.Null", "cryptix.jce.provider.mac.Null");
        
        put("KeyGenerator.HMAC","cryptix.jce.provider.key.HMACKeyGenerator");


        //
        // MessageDigests
        //

        put("MessageDigest.MD2", "cryptix.jce.provider.md.MD2");
        put("MessageDigest.MD4", "cryptix.jce.provider.md.MD4");
        put("MessageDigest.MD5", "cryptix.jce.provider.md.MD5");
        put("MessageDigest.RIPEMD", "cryptix.jce.provider.md.RIPEMD");
        put("MessageDigest.RIPEMD128", "cryptix.jce.provider.md.RIPEMD128");
        put("Alg.Alias.MessageDigest.RIPEMD-128", "RIPEMD128");
        put("MessageDigest.RIPEMD160", "cryptix.jce.provider.md.RIPEMD160");
        put("Alg.Alias.MessageDigest.RIPEMD-160", "RIPEMD160");


        // SHA (SHA-1)
        // don't change this! this works around a bug in JDK 1.1.8 where it
        // barfs on multiple aliases to the same algorithm - gelderen
        put("MessageDigest.SHA1",  "cryptix.jce.provider.md.SHA1");
        put("MessageDigest.SHA-1",  "cryptix.jce.provider.md.SHA1");
        put("Alg.Alias.MessageDigest.SHA", "SHA1");


        // SHA-0
        put("MessageDigest.SHA0", "cryptix.jce.provider.md.SHA0");
        put("Alg.Alias.MessageDigest.SHA-0", "SHA0");

        // SHA-256
        put("MessageDigest.SHA-256", "cryptix.jce.provider.md.SHA256");

        // SHA-384
        put("MessageDigest.SHA-384", "cryptix.jce.provider.md.SHA384");

        // SHA-512
        put("MessageDigest.SHA-512", "cryptix.jce.provider.md.SHA512");

        // Tiger
        put("MessageDigest.Tiger", "cryptix.jce.provider.md.Tiger");

        //
        // Signatures
        //

	// RSASSA-PSS
        put("Signature.RSASSA-PSS/SHA-1",
                "cryptix.jce.provider.rsa.RSASignature_PSS_SHA1");

        put("Signature.RSASSA-PSS/SHA-256",
                "cryptix.jce.provider.rsa.RSASignature_PSS_SHA256");

        put("Signature.RSASSA-PSS/SHA-384",
                "cryptix.jce.provider.rsa.RSASignature_PSS_SHA384");

        put("Signature.RSASSA-PSS/SHA-512",
                "cryptix.jce.provider.rsa.RSASignature_PSS_SHA512");


        // RSA/PKCS#1
        put("Signature.MD2withRSA", 
                    "cryptix.jce.provider.rsa.RSASignature_PKCS1_MD2");
        put("Alg.Alias.Signature.MD2/RSA/PKCS#1", "MD2withRSA");

        put("Signature.MD4withRSA", 
                    "cryptix.jce.provider.rsa.RSASignature_PKCS1_MD4");
        put("Alg.Alias.Signature.MD4/RSA/PKCS#1", "MD4withRSA");

        put("Signature.MD5withRSA", 
                    "cryptix.jce.provider.rsa.RSASignature_PKCS1_MD5");
        put("Alg.Alias.Signature.MD5/RSA/PKCS#1", "MD5withRSA");

        put("Signature.RIPEMD128withRSA", 
                    "cryptix.jce.provider.rsa.RSASignature_PKCS1_RIPEMD128");
        put("Alg.Alias.Signature.RIPEMD-128/RSA/PKCS#1", "RIPEMD128withRSA");

        put("Signature.RIPEMD160withRSA", 
                    "cryptix.jce.provider.rsa.RSASignature_PKCS1_RIPEMD160");
        put("Alg.Alias.Signature.RIPEMD-160/RSA/PKCS#1", "RIPEMD160withRSA");

        put("Signature.SHA1withRSA", 
                    "cryptix.jce.provider.rsa.RSASignature_PKCS1_SHA1");
        put("Alg.Alias.Signature.SHA-1/RSA/PKCS#1", "SHA1withRSA");

        put("Signature.SHA-256/RSA/PKCS#1",
                    "cryptix.jce.provider.rsa.RSASignature_PKCS1_SHA256");

        put("Signature.SHA-384/RSA/PKCS#1",
                    "cryptix.jce.provider.rsa.RSASignature_PKCS1_SHA384");

        put("Signature.SHA-512/RSA/PKCS#1",
                    "cryptix.jce.provider.rsa.RSASignature_PKCS1_SHA512");


        // Can't name the algorithm 'DSA' because the JDK translates this
        // to SHA/DSA which is then not found
        put("Signature.SHA/DSA", "cryptix.jce.provider.dsa.DSASignature");

        put("Signature.RawDSA", "cryptix.jce.provider.dsa.RawDSASignature");


        // Parameters
        put("AlgorithmParameters.DES", 
                        "cryptix.jce.provider.parameters.BlockParameters");

        // RSA
        put("KeyFactory.RSA",
                    "cryptix.jce.provider.rsa.RSAKeyFactory");
        put("KeyPairGenerator.RSA", 
                    "cryptix.jce.provider.rsa.RSAKeyPairGenerator");

        put("Cipher.RSAES-OAEP-MD2",
                "cryptix.jce.provider.rsa.RSACipher_OAEP_MD2");
        put("Cipher.RSAES-OAEP-MD4",
                "cryptix.jce.provider.rsa.RSACipher_OAEP_MD4");
        put("Cipher.RSAES-OAEP-MD5",
                "cryptix.jce.provider.rsa.RSACipher_OAEP_MD5");
        put("Cipher.RSAES-OAEP-RIPEMD128",
                "cryptix.jce.provider.rsa.RSACipher_OAEP_RIPEMD128");
        put("Cipher.RSAES-OAEP-RIPEMD160",
                "cryptix.jce.provider.rsa.RSACipher_OAEP_RIPEMD160");
        put("Cipher.RSAES-OAEP-SHA1",
                "cryptix.jce.provider.rsa.RSACipher_OAEP_SHA1");
        put("Cipher.RSAES-OAEP-SHA256",
                "cryptix.jce.provider.rsa.RSACipher_OAEP_SHA256");
        put("Cipher.RSAES-OAEP-SHA384",
                "cryptix.jce.provider.rsa.RSACipher_OAEP_SHA384");
        put("Cipher.RSAES-OAEP-SHA512",
                "cryptix.jce.provider.rsa.RSACipher_OAEP_SHA512");
        put("Cipher.RSAES-OAEP-Tiger",
                "cryptix.jce.provider.rsa.RSACipher_OAEP_Tiger");
        put("Cipher.RSA/ECB/PKCS#1",
                    "cryptix.jce.provider.rsa.RSACipher_ECB_PKCS1");            
 
        // ElGamal       
        put("KeyPairGenerator.ElGamal", 
                    "cryptix.jce.provider.elgamal.ElGamalKeyPairGenerator");
                    
        put("Cipher.ElGamal/ECB/PKCS#1", 
                    "cryptix.jce.provider.elgamal.ElGamalCipher");


        put("KeyAgreement.DH", 
                        "cryptix.jce.provider.dh.DHKeyAgreement");
        put("KeyPairGenerator.DH", 
                        "cryptix.jce.provider.dh.DHKeyPairGenerator");

    }
}
