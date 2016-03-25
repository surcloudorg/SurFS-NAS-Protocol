/* $Id: PaddingNone.java,v 1.7 2001/08/06 18:06:50 edwin Exp $
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


final class PaddingNone extends Padding
{
    private final boolean needsPadding;

    PaddingNone(Mode mode) {
        super(mode);
        needsPadding = mode.needsPadding();
    }

   final byte [] corePad(byte [] input, int inputLen) 
     throws IllegalBlockSizeException {
        if (input == null) input = new byte[0];
        if ((getBufSize() != 0 || inputLen % getBlockSize() != 0) 
           && needsPadding) 
        {
           throw new IllegalBlockSizeException(
            "Input buffer not a multiple of BlockSize");
        }
        byte [] t = new byte[inputLen];
        System.arraycopy(input,0,t,0,inputLen);
        return t;       
   }

   final int coreUnPad(byte [] input, int inputLen) {
        return inputLen;
   }

   final int getPadSize(int inputLen) {
        return 0;
   }
}
