/* $Id: HMAC_Tiger.java,v 1.1 2000/02/09 20:33:17 gelderen Exp $
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
public final class HMAC_Tiger extends HMAC
{
    private static final int
        BLOCK_SIZE = 64,
        DIGEST_LEN = 24;
    
    public HMAC_Tiger() 
    {
        super("Tiger", BLOCK_SIZE, DIGEST_LEN);
    }
}