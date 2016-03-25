/* $Id: RSASignature_PSS_MD4.java,v 1.1 2001/06/20 17:50:37 gelderen Exp $
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
public class RSASignature_PSS_MD4 extends RSASignature_PSS {
    public RSASignature_PSS_MD4 () { super("MD4"); }
}
