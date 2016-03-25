/* $Id: AsnException.java,v 1.1 2000/08/17 01:55:25 gelderen Exp $
 *
 * Copyright (c) 2000 The Cryptix Foundation Limited. All rights reserved.
 */

package cryptix.jce.provider.asn;


import java.io.IOException;


/**
 * Superclass for all ASN encoding and decoding errors. Extends from
 * IOException for programmer convenience.
 *
 * @version $Revision: 1.1 $
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
public final class AsnException extends IOException {

    public AsnException(String msg) {
        super(msg);
    }
}
