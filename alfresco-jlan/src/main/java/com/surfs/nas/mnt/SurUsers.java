package com.surfs.nas.mnt;

import com.autumn.core.log.LogFactory;
import com.autumn.core.log.Logger;
import com.surfs.nas.StoragePool;
import com.surfs.nas.StorageSources;
import com.surfs.nas.error.PoolNotFoundException;
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
