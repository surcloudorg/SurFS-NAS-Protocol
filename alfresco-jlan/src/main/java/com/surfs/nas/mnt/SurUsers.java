/*
 * Copyright (C) 2016 SurCloud.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * http://www.gnu.org/licenses/licenses.html
 */ 

package com.surfs.nas.mnt;

import com.surfs.nas.StoragePool;
import com.surfs.nas.StorageSources;
import com.surfs.nas.error.PoolNotFoundException;
import com.surfs.nas.log.LogFactory;
import com.surfs.nas.log.Logger;
import java.io.IOException;
import org.alfresco.config.ConfigElement;
import org.alfresco.jlan.server.auth.UserAccount;
import org.alfresco.jlan.server.auth.UsersInterface;
import org.alfresco.jlan.server.config.InvalidConfigurationException;
import org.alfresco.jlan.server.config.ServerConfiguration;

public class SurUsers implements UsersInterface {
    
    private static final Logger log = LogFactory.getLogger(SurAuthenticator.class);
    private StoragePool pool;
    
    @Override
    public void initializeUsers(ServerConfiguration config, ConfigElement params) throws InvalidConfigurationException {
        try {
            pool = StorageSources.getStoragePool(SurNasDriver.poolname);
        } catch (PoolNotFoundException ex) {
            throw new InvalidConfigurationException("");
        }
    }
    
    @Override
    public UserAccount getUserAccount(String userName) {
        try {
            com.surfs.nas.UserAccount userAcc = pool.getDatasource().getNasMetaAccessor().getUserAccount(userName);
            UserAccount account = new UserAccount();
            account.setUserName(userAcc.getUserName());
            account.setPassword(userAcc.getPassword());
            account.setComment(userAcc.getComment());
            account.setRealName(userAcc.getRealName());
            return account;
        } catch (IOException ex) {
            return null;
        }
    }
}
