/* $Id: ModeOpenpgpCFB.java,v 1.2 2001/07/04 19:16:54 edwin Exp $
 *
 * Copyright (C) 1995-2000 The Cryptix Foundation Limited.
 * All rights reserved.
 *
 * Use, modification, copying and distribution of this software is subject
 * the terms and conditions of the Cryptix General Licence. You should have
 * received a copy of the Cryptix General Licence along with this library;
 * if not, you can download a copy from http://www.cryptix.org/ .
 */
package cryptix.jce.provider.cipher;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.spec.IvParameterSpec;


/**
 * This mode implements the special CFB mode used by the OpenPGP standard 
 * (RFC 2440)
 *
 * <p>
 * Due to the design of the JCE, it is not completely the OpenPGP CFB mode 
 * though. OpenPGP specifies that blocksize+2 bytes need to be prefixed to 
 * the encrypted data, consisting of blocksize bytes of random data and then
 * repeating the last two bytes of this random data to make it possible to
 * check whether we're decrypting with the right key.
 * </p><p>
 * Now the question is, where should this data be added and thus also where
 * should this check be done. Inside this mode object would be the obvious 
 * choice, such that applications need not to bother themselves with this quirk.
 * However there's no way to throw an Exception if the check fails. The only 
 * possibility is a RuntimeException and that's not really how it should work.
 * </p><p>
 * So the application needs to do the check, which means the application has to
 * pass in this random data on encryption and it needs to retrieve it back on
 * decryption. For passing it in on encryption, JCE has so called 
 * AlgorithmParameterSpec objects which would be perfect for this job. However,
 * there is no way for the application to retrieve it again at decryption time
 * and therefore no way to check it.
 * </p><p>
 * So the only way to do this is if the application handles the prefix. This
 * mode then only takes care of the resynchronization at blocksize+2 bytes.
 * It's not ideal and not how is should work, but it's the only thing possible
 * within the JCE. 
 * </p>
 *
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 * @version $Revision: 1.2 $
 */
/*package*/ class ModeOpenpgpCFB extends ModeCFB {

    /** 
     * Holds byteCount where the OpenPGP CFB extra crank is required.
     *
     * OpenPGP CFB mode specifies that an extra shift register encryption
     * (crank) occurs at CIPHER_BLOCK_SIZE+2 bytes. 
     */
    private final long extraCrankCount;


    ModeOpenpgpCFB(BlockCipher cipher) {
        super(cipher);
        this.extraCrankCount = CIPHER_BLOCK_SIZE+2;
    }

    protected boolean needCrank() {
        if(this.byteCount > extraCrankCount)
            return (this.byteCount-2)%CIPHER_BLOCK_SIZE == 0;
        else
            return super.needCrank() || (this.byteCount == extraCrankCount);
    }
}
