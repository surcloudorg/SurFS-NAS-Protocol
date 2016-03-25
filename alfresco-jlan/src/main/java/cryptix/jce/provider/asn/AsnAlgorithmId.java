/* $Id: AsnAlgorithmId.java,v 1.1 2000/08/25 01:11:43 gelderen Exp $
 *
 * Copyright (c) 2000 The Cryptix Development Team. All rights reserved.
 */

package cryptix.jce.provider.asn;


import java.io.IOException;


/**
 * Immutable object representing an ASN.1 AlgorithmId.
 *
 * XXX: sortof a quick hack, AsnInputStream needs some tweaks...
 *
 * @version $Revision: 1.1 $
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
public final class AsnAlgorithmId extends AsnObject
{
    private final AsnSequence val;


    public AsnAlgorithmId(AsnObjectId oid) {
        super(AsnObject.TAG_SEQUENCE);
        this.val = new AsnSequence(oid, new AsnNull());
    }


    /** Write out payload. */
    protected void encodePayload(AsnOutputStream os) throws IOException {
        this.val.encodePayload(os);
    }


    protected int getEncodedLengthOfPayload(AsnOutputStream os) {
        return this.val.getEncodedLengthOfPayload(os);
    }


    public String toString(String indent) {
        return indent + "AlgorithmId";
    }
}
