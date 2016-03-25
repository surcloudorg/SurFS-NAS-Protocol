/* $Id: HMAC_RIPEMD128.java,v 1.6 2000/02/09 20:32:33 gelderen Exp $
 *
 * Copyright (C) 1995-2000 The Cryptix Foundation Limited.
 * All rights reserved.
 *
 * Use, modification, copying and distribution of this software is subject
 * the terms and conditions of the Cryptix General Licence. You should have
 * received a copy of the Cryptix General Licence along with this library;
 * if not, you can download a copy from http://www.cryptix.org/ .
 */
package cryptix.jce.provider.mac;


/**
 * HMAC-RIPEMD128
 *
 * @author Jeroen C. van Gelderen (gelderen@cryptix.org)
 * @version $Revision: 1.6 $
 */
public final class HMAC_RIPEMD128 extends HMAC
{
    private static final int
        BLOCK_SIZE = 64,
        DIGEST_LEN = 16;

    public HMAC_RIPEMD128()
    {
        super("RIPEMD128", BLOCK_SIZE, DIGEST_LEN);
    }
}