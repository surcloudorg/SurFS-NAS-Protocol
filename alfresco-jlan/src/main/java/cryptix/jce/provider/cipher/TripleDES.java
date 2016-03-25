/* $Id: TripleDES.java,v 1.7 2001/08/06 21:22:55 edwin Exp $
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


import cryptix.jce.provider.key.RawSecretKey;
import java.security.InvalidKeyException;
import java.security.Key;


/**
 * This class implements Triple DES EDE encryption with three independent
 * keys. DES-EDE3 acts as a block cipher with an 8 byte block size.
 * <p>
 * The encoded form of the Triple DES key should be a 24-byte array,
 * consisting of three 8-byte single DES keys in order - K1, K2 and K3.
 * Encryption and decryption are done as follows:
 * <ul>
 *   <li> C = E<sub>K3</sub>(D<sub>K2</sub>(E<sub>K1</sub>(P)))
 *   <li> P = D<sub>K1</sub>(E<sub>K2</sub>(D<sub>K3</sub>(C)))
 * </ul>
 * <p>
 * The alternating encryption and decryption was designed by IBM to
 * enable compatibility with single DES, when all three keys are equal
 * (although it is now rare for Triple DES to be used in that way).
 * <p>
 * When DES-EDE3 is used with the CBC mode class (algorithm name
 * "DES-EDE3/CBC"), the result is Outer-CBC, and only one IV is used.
 * <p>
 * DES was written by IBM and first released in 1976. The algorithm is
 * freely usable for both single and triple encryption.
 *
 * @version $Revision: 1.7 $
 * @author Systemics Ltd
 * @author David Hopwood
 * @author Eric Young
 * @author Geoffrey Keating
 * @author Jeroen C. van Gelderen (gelderen@cryptix.org)
 * @author John F. Dumas          (jdumas@zgs.com)
 * @author Raif S. Naffah         (raif@cryptix.org)
 */
public final class TripleDES
extends BlockCipher
{

// DES-EDE3 constants and variables
//............................................................................

    private static final int
        BLOCK_SIZE     =  8,
        KEY_LENGTH     = 24,
        ALT_KEY_LENGTH = 21,
        DES_KEY_LENGTH =  8;

    private DES
        des1,
        des2,
        des3;
        
       
// Constructor, ...
// ...................................................................

    public TripleDES() {
        super(BLOCK_SIZE);
        des1 = new DES();
        des2 = new DES();
        des3 = new DES();
    }
    


// BPI methods
// ...................................................................

    protected void coreInit(Key key, boolean decrypt)
    throws InvalidKeyException
    {
        byte[] userkey = key.getEncoded();
        if (userkey == null)
            throw new InvalidKeyException("Null user key");

        int len = 0;
                
        if (userkey.length == KEY_LENGTH) {
            len = 8;
        } else if (userkey.length == ALT_KEY_LENGTH) {
            len = 7;
        } else {
            throw new InvalidKeyException("Invalid user key length");
        }
        
        byte[] k = new byte[len];
        System.arraycopy(userkey, 0, k, 0, len);
        RawSecretKey sk = new RawSecretKey("DES", k);
        des1.coreInit(sk, decrypt);
        
        System.arraycopy(userkey, len, k, 0, len);
        sk = new RawSecretKey("DES", k);
        des2.coreInit(sk, !decrypt);

        System.arraycopy(userkey, len+len, k, 0, len);
        sk = new RawSecretKey("DES", k);
        des3.coreInit(sk, decrypt);
        
        if(decrypt) {
            DES des = des1;
            des1 = des3;
            des3 = des;
        }
    }
    
    

    /** 
     * Perform a DES encryption or decryption operation (depends on subkey).
     */
    protected void coreCrypt(byte[] in, int inOffset, byte[] out, int outOffset) {
        des1.coreCrypt(in,  inOffset,  out, outOffset);
        des2.coreCrypt(out, outOffset, out, outOffset);
        des3.coreCrypt(out, outOffset, out, outOffset);
    }   
}
