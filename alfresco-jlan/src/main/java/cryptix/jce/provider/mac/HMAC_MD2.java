/* $Id: HMAC_MD2.java,v 1.7 2001/10/10 02:56:55 gelderen Exp $
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
 * HMAC-MD2
 *
 * @author Jeroen C. van Gelderen (gelderen@cryptix.org)
 * @version $Revision: 1.7 $
 */
public final class HMAC_MD2 extends HMAC
{
    private static final int
        BLOCK_SIZE = 16,
        DIGEST_LEN = 16;

    public HMAC_MD2()
    {
        super("MD2", BLOCK_SIZE, DIGEST_LEN);
    }
}
