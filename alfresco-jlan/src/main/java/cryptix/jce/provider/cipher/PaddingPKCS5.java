/* $Id: PaddingPKCS5.java,v 1.9 2000/07/31 13:21:33 pw Exp $
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


import javax.crypto.IllegalBlockSizeException;


/**
 * This class implements generalized PKCS#5 padding.
 * <p>
 * PKCS#5 padding is described in RSA Labs' PKCS#5 document. Their version
 * is defined for 8 byte (64 bit) blocksizes only. This implementation handles 
 * blocksizes up to 255 bytes, hence 'Generalized PKCS#5'. This generalization
 * is completely compatible with the original 8-byte-only PKCS#5.
 * <p>
 * <a href="http://www.rsasecurity.com/rsalabs/pkcs/pkcs-5/index.html">
 * http://www.rsasecurity.com/rsalabs/pkcs/pkcs-5/index.html</a>
 *
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 * @author  Paul Waserbrot (pw@cryptix.org)
 * @version $Revision: 1.9 $
 */
final class PaddingPKCS5 extends Padding
{
    PaddingPKCS5(Mode mode) {
        super(mode);
    }


   final byte [] corePad(byte [] input, int inputLen) 
      throws IllegalBlockSizeException {
        if (input == null) input = new byte[0];
        int pad = getPadSize(inputLen);
        byte [] b = new byte[pad + inputLen];
        System.arraycopy(input, 0, b, 0, inputLen);
        for (int i = 0; i<pad; i++)
           b[inputLen + i] = (byte) pad;
         
        return b;        
   }
 
   final int coreUnPad(byte [] input, int inputLen) {
       return inputLen - ((int) input[inputLen - 1]);
   }        

   final int getPadSize(int inputLen) {
        int bs = getBlockSize();
        return bs - (inputLen + getBufSize())%bs;
   }
}
