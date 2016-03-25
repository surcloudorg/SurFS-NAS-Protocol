package com.surfs.nas.mnt;

import com.surfs.nas.StoragePool;
import com.surfs.nas.StorageSources;
import java.io.IOException;
import java.util.Map;

public class SurDevicePermission extends Thread {

    private String name = null;
    private Map<String, String> map;

    public SurDevicePermission(String name) throws IOException {
        this.name = name;
        load();
    }

    private synchronized void load() throws IOException {
        StoragePool pool = StorageSources.getStoragePool(SurNasDriver.poolname);
        map = pool.getDatasource().getNasMetaAccessor().getPermission(name);
    }

    @Override
    public void run() {
        while (!this.isInterrupted()) {
            try {
                sleep(1000 * 60 * 10);
                load();
            } catch (IOException ex) {
            } catch (InterruptedException ex) {
                break;
            }
        }
    }

    /**
     *
     * @param username
     * @return
     */
    public String getPermission(String username) {
        String per = map.get(username);
        if (per == null) {
            try {
                load();
            } catch (IOException ex) {
            }
            return map.get(username);
        } else {
            return per;
        }
    }
}
