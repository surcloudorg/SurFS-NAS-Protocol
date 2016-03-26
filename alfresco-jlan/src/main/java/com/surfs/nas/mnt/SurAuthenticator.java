/*
 * Copyright (C) 2016 SurCloud.
 *
 * This file is part of JLAN for SurFS
 *
 * JLAN for SurFS is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * JLAN for SurFS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with JLAN for SurFS. If not, see <http://www.gnu.org/licenses/>.
 */

package com.surfs.nas.mnt;

import com.autumn.core.log.LogFactory;
import com.autumn.core.log.Logger;
import org.alfresco.jlan.server.SrvSession;
import org.alfresco.jlan.server.auth.ClientInfo;
import org.alfresco.jlan.server.auth.EnterpriseCifsAuthenticator;
import org.alfresco.jlan.server.auth.UserAccount;
import org.alfresco.jlan.server.config.InvalidConfigurationException;
import org.alfresco.jlan.server.core.ShareType;
import org.alfresco.jlan.server.core.SharedDevice;

public class SurAuthenticator extends EnterpriseCifsAuthenticator {

    private static final Logger log = LogFactory.getLogger(SurAuthenticator.class);

    public SurAuthenticator() throws InvalidConfigurationException {
        super();
    }

    @Override
    public int authenticateShareConnect(ClientInfo client, SharedDevice share, String pwd, SrvSession sess) {
        if (this.getAccessMode() == SHARE_MODE) {
            return Writeable;
        }
        if (share.getType() == ShareType.ADMINPIPE) {
            return Writeable;
        }
        UserAccount user = null;
        if (client != null) {
            user = getUserDetails(client.getUserName());
        }
        if (user == null) {
            return allowGuest() ? Writeable : NoAccess;
        } else {
            SurDeviceContext sdc = (SurDeviceContext) share.getContext();
            String permission = sdc.getSurDevicePermission().getPermission(user.getUserName());
            if (permission == null) {
                 
                return NoAccess;
            } else {
                if (permission.startsWith("rw")) {
                    return Writeable;
                }
                if (permission.startsWith("r")) {
                    
                    return ReadOnly;
                }
                 
                return NoAccess;
            }
        }
    }
}
