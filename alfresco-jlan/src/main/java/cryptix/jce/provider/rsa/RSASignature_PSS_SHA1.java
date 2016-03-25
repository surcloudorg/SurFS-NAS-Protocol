/* $Id: RSASignature_PSS_SHA1.java,v 1.1 2001/05/18 03:00:15 gelderen Exp $
 *
 * Copyright (C) 2001 The Cryptix Foundation Limited.
 * All rights reserved.
 *
 * Use, modification, copying and distribution of this software is subject
 * the terms and conditions of the Cryptix General Licence. You should have
 * received a copy of the Cryptix General Licence along with this library;
 * if not, you can download a copy from http://www.cryptix.org/ .
 */
package cryptix.jce.provider.rsa;


/**
 * @version $Revision: 1.1 $
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
public class RSASignature_PSS_SHA1 extends RSASignature_PSS {
    public RSASignature_PSS_SHA1 () { super("SHA-1"); }
}
