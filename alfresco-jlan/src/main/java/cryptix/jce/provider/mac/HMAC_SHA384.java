/* $Id: HMAC_SHA384.java,v 1.1 2001/06/25 16:03:45 gelderen Exp $
 *
 * Copyright (C) 2000 The Cryptix Foundation Limited.
 * All rights reserved.
 *
 * Use, modification, copying and distribution of this software is subject
 * the terms and conditions of the Cryptix General Licence. You should have
 * received a copy of the Cryptix General Licence along with this library;
 * if not, you can download a copy from http://www.cryptix.org/ .
 */
package cryptix.jce.provider.mac;


/**
 * @author Jeroen C. van Gelderen (gelderen@cryptix.org)
 * @version $Revision: 1.1 $
 */
public final class HMAC_SHA384 extends HMAC {

    private static final int
        BLOCK_SIZE = 128,
        DIGEST_LEN =  48;

    public HMAC_SHA384() {
        super("SHA-384", BLOCK_SIZE, DIGEST_LEN);
    }
}