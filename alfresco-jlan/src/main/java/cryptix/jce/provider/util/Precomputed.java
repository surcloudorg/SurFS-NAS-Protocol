/* $Id: Precomputed.java,v 1.1 2003/02/15 13:41:21 gelderen Exp $
 *
 * Copyright (C) 2000 The Cryptix Foundation Limited.
 * All rights reserved.
 *
 * Use, modification, copying and distribution of this software is subject
 * the terms and conditions of the Cryptix General Licence. You should have
 * received a copy of the Cryptix General Licence along with this library;
 * if not, you can download a copy from http://www.cryptix.org/ .
 */
package cryptix.jce.provider.util;


import java.math.BigInteger;


/**
 * @version $Revision: 1.1 $
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 */
public final class Precomputed
{
    /**
     * Precomputed OAKLEY groups.
     *
     * P_00768: OAKLEY Well-Known Group 1, a 768 bit prime.
     * P_01024: OAKLEY Well-Known Group 2, a 1024 bit prime.
     * P_01536: OAKLEY Well-Known Group 5, a 1536 bit prime.
     *
     * See: RFC 2412
     */
    private static final Group
        OAKLEY_0768 = new Group(
            new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B" +
                           "80DC1CD129024E088A67CC74020BBEA63B139B22514A087" +
                           "98E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE135" +
                           "6D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFF" +
                           "FFFFFFFFFFF", 16),
            new BigInteger("7FFFFFFFFFFFFFFFE487ED5110B4611A62633145" +
                           "C06E0E68948127044533E63A0105DF531D89CD9128A5043" +
                           "CC71A026EF7CA8CD9E69D218D98158536F92F8A1BA7F09A" +
                           "B6B6A8E122F242DABB312F3F637A262174D31D1B107FFFF" +
                           "FFFFFFFFFFF", 16),
            new BigInteger("2", 16) ),

        OAKLEY_1024 = new Group(
            new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B" +
                          "80DC1CD129024E088A67CC74020BBEA63B139B22514A0879" +
                          "8E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D" +
                          "6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6" +
                          "F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651" +
                          "ECE65381FFFFFFFFFFFFFFFF", 16),
            new BigInteger("7FFFFFFFFFFFFFFFE487ED5110B4611A62633145" +
                          "C06E0E68948127044533E63A0105DF531D89CD9128A5043C" +
                          "C71A026EF7CA8CD9E69D218D98158536F92F8A1BA7F09AB6" +
                          "B6A8E122F242DABB312F3F637A262174D31BF6B585FFAE5B" +
                          "7A035BF6F71C35FDAD44CFD2D74F9208BE258FF324943328" +
                          "F67329C0FFFFFFFFFFFFFFFF", 16),
            new BigInteger("2", 16) ),

        OAKLEY_1536 = new Group(
            new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B" +
                          "80DC1CD129024E088A67CC74020BBEA63B139B22514A0879" +
                          "8E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D" +
                          "6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6" +
                          "F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651" +
                          "ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8" +
                          "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED52907" +
                          "7096966D670C354E4ABC9804F1746C08CA237327FFFFFFFF" +
                          "FFFFFFFF", 16),
            new BigInteger("7FFFFFFFFFFFFFFFE487ED5110B4611A62633145" +
                          "C06E0E68948127044533E63A0105DF531D89CD9128A5043C" +
                          "C71A026EF7CA8CD9E69D218D98158536F92F8A1BA7F09AB6" +
                          "B6A8E122F242DABB312F3F637A262174D31BF6B585FFAE5B" +
                          "7A035BF6F71C35FDAD44CFD2D74F9208BE258FF324943328" +
                          "F6722D9EE1003E5C50B1DF82CC6D241B0E2AE9CD348B1FD4" +
                          "7E9267AFC1B2AE91EE51D6CB0E3179AB1042A95DCF6A9483" +
                          "B84B4B36B3861AA7255E4C0278BA36046511B993FFFFFFFF" +
                          "FFFFFFFF", 16),
            new BigInteger("2", 16) );


    /**
     * Precomputed SKIP groups.
     *
     * See: http://skip.incog.com/spec/numbers.html
     */
    private static final Group
        SKIP_0512 = new Group(
            new BigInteger("F52AFF3CE1B1294018118D7C84A70A72D686C40319C80729" +
                           "7ACA950CD9969FABD00A509B0246D3083D66A45D419F9C7C" +
                           "BD894B221926BAABA25EC355E92A055F", 16),
            null,
            new BigInteger("2", 16) ),

        SKIP_1024 = new Group(
            new BigInteger("F488FD584E49DBCD20B49DE49107366B336C380D451D0F7C" +
                           "88B31C7C5B2D8EF6F3C923C043F0A55B188D8EBB558CB85D" +
                           "38D334FD7C175743A31D186CDE33212CB52AFF3CE1B12940" +
                           "18118D7C84A70A72D686C40319C807297ACA950CD9969FAB" +
                           "D00A509B0246D3083D66A45D419F9C7CBD894B221926BAAB" +
                           "A25EC355E92F78C7", 16),
            null,
            new BigInteger("2", 16) ),

        SKIP_2048 = new Group(
            new BigInteger("F64257B7087F081772A2BAD6A942F305E8F95311394FB6F1" +
                           "6EB94B3820DA01A756A314E98F4055F3D007C6CB43A994AD" +
                           "F74C648649F80C83BD65E917D4A1D350F8F5595FDC76524F" +
                           "3D3D8DDBCE99E1579259CDFDB8AE744FC5FC76BC83C54730" +
                           "61CE7CC966FF15F9BBFD915EC701AAD35B9E8DA0A5723AD4" +
                           "1AF0BF4600582BE5F488FD584E49DBCD20B49DE49107366B" +
                           "336C380D451D0F7C88B31C7C5B2D8EF6F3C923C043F0A55B" +
                           "188D8EBB558CB85D38D334FD7C175743A31D186CDE33212C" +
                           "B52AFF3CE1B1294018118D7C84A70A72D686C40319C80729" +
                           "7ACA950CD9969FABD00A509B0246D3083D66A45D419F9C7C" +
                           "BD894B221926BAABA25EC355E9320B3B", 16),
            null,
            new BigInteger("2", 16) ),

        SKIP_4096 = new Group(
            new BigInteger("FA147252C14DE15A49D4EF092DC0A8FD55ABD7D937042809" +
                           "E2E93E77E2A17A18DD46A34337239097F30EC903507D65CF" +
                           "7862A63A622283A12FFE79BA35FF59D81D61DD1E211317FE" +
                           "CD38879EF54F7910618DD422F35AED5DEA21E9336B48120A" +
                           "2077D4256061DEF6B44F1C63408B3A21938B7953512CCAB3" +
                           "7B2956A8C7F8F47B085EA6DCA2451256DD4192F2DD5B8F23" +
                           "F0F3EFE43B0A44DDED9684F1A83246A3DB4ABE3D45BA4EF8" +
                           "03E5DD6B590D841ECA165A8CC8DF7C5444C427A73B2A97CE" +
                           "A37D269CADF4C2AC374BC3AD68847F99A617EF6B463A7A36" +
                           "7A114392ADE99CFB446C3D8249CC5C6A5242F842FB44F939" +
                           "73FB60793BC29E0BDCD4A667F7663FFC423B1BDB4F66DCA5" +
                           "8F66F9EAC1ED31FB48A1827DF8E0CCB1C703E4F8B3FEB7A3" +
                           "1373A67BC10E39C7944826008579FC6F7AAFC5523575D775" +
                           "A440FA14746116F2EB67116F04433D11144CA7942A39A1C9" +
                           "90CF83C6FF028FA32AAC26DF0B8BBE644AF1A1DCEEBAC803" +
                           "82F6622C5DB6BB13196E86C55B2B5E3AF3B3286B70713A8E" +
                           "FF5C15E602A4CEED5956CC155107791A0F25262730A915B2" +
                           "C8D45CCC30E81BD8D50F19A880A4C701AA8BBA53BB47C21F" +
                           "6B54B01760ED792195B6058437C803A4DDD106698F4C39E0" +
                           "C85D831DBE6A9A99F39F0B4529D4CB2966EE1E7E3DD7134E" +
                           "DB909058CB5E9BCD2E2B0FA94E78AC05117FE39E27D499E1" +
                           "B9BD78E18441A0DF", 16),
            null,
            new BigInteger("2", 16) );


    public static Group getElGamalGroup(int keysize)
    {
        return getStrongGroup(keysize);
    }


    public static Group getStrongGroup(int keysize)
    {
        switch(keysize)
        {
        case 512:
            return SKIP_0512;
        case 768:
            return OAKLEY_0768;
        case 1024:
            return OAKLEY_1024;
        case 1536:
            return OAKLEY_1536;
        case 2048:
            return SKIP_2048;
        case 4096:
            return SKIP_4096;
        default:
            return null; // we don't have any
        }
    }
}
