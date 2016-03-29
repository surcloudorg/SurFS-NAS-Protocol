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

import com.surfs.nas.StoragePool;
import com.surfs.nas.StorageSources;
import com.surfs.nas.client.SurFile;
import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.List;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.alfresco.config.ConfigElement;
import org.alfresco.jlan.app.XMLServerConfiguration;
import org.alfresco.jlan.oncrpc.nfs.NFSInfo;
import org.alfresco.jlan.server.SrvSession;
import org.alfresco.jlan.server.config.ConfigId;
import org.alfresco.jlan.server.config.ConfigurationListener;
import org.alfresco.jlan.server.config.InvalidConfigurationException;
import org.alfresco.jlan.server.config.ServerConfiguration;
import org.alfresco.jlan.server.core.ShareMapper;
import org.alfresco.jlan.server.core.SharedDevice;
import org.alfresco.jlan.server.core.SharedDeviceList;
import org.alfresco.jlan.server.filesys.DiskDeviceContext;
import org.alfresco.jlan.server.filesys.DiskSharedDevice;
import org.alfresco.jlan.server.filesys.FilesystemsConfigSection;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

public class SurShareMapper implements ShareMapper, ConfigurationListener {

    private XMLServerConfiguration m_config;
    private FilesystemsConfigSection m_filesysConfig;
    private StoragePool pool;

    @Override
    public void initializeMapper(ServerConfiguration config, ConfigElement params) throws InvalidConfigurationException {
        m_config = (XMLServerConfiguration) config;
        m_filesysConfig = (FilesystemsConfigSection) m_config.getConfigSection(FilesystemsConfigSection.SectionName);
        if (m_filesysConfig == null) {
            m_config.addListener(this);
        }
        try {
            pool = StorageSources.getStoragePool(SurNasDriver.poolname);
        } catch (IOException ex) {
            throw new InvalidConfigurationException("");
        }
        NFSInfo info = new NFSInfo() {

            @Override
            public int getBlockSize() {
                try {
                    return pool.getClientSourceMgr().getGlobleProperties().getBlocksize()*1024;
                } catch (IOException ex) {
                    return 1024 * 128;
                }
            }

        };
        NFSInfo.setNFSInfo(info);
    }

    /**
     * 初始化共享
     *
     * @param shares
     */
    private void initShare() throws IOException, InvalidConfigurationException {
        List<String> shares = pool.getDatasource().getNasMetaAccessor().getMountList();
        for (String path : shares) {
            String p = path.toLowerCase();
            if (m_filesysConfig.getShares().findShare(p) == null) {
                Element e = getShareElement(p);
              
                m_config.addDiskShare(e, m_filesysConfig);
            }
        }
    }

    /**
     * 生成xml
     *
     * @param name
     * @return
     */
    private Element getShareElement(String name) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            InputStream in = SurShareMapper.class.getResourceAsStream("SurShare.xml");
            InputSource xmlSource = new InputSource(in);
            Document doc = builder.parse(xmlSource);
            Element shareElement = doc.getDocumentElement();
            if (name.startsWith("/")) {
                shareElement.setAttribute("name", name.substring(1));
            } else {
                shareElement.setAttribute("name", name);
            }
            return shareElement;
        } catch (ParserConfigurationException | SAXException | IOException | DOMException r) {
            return null;
        }
    }

    @Override
    public SharedDeviceList getShareList(String host, SrvSession sess, boolean allShares) {
        if (m_filesysConfig == null) {
            return null;
        }
        //清理删除的共享
        SharedDeviceList shrList = new SharedDeviceList(m_filesysConfig.getShares());
        Enumeration<SharedDevice> list = shrList.enumerateShares();
        while (list.hasMoreElements()) {
            SharedDevice sd = list.nextElement();
            if (sd instanceof DiskSharedDevice) {
                DiskSharedDevice dsd = (DiskSharedDevice) sd;
                DiskDeviceContext dc = dsd.getDiskContext();
                if (dc instanceof SurDeviceContext) {
                    SurDeviceContext sdc = (SurDeviceContext) dc;
                    if (!sdc.isUseable()) {//移除
                        m_filesysConfig.getShares().deleteShare(sd.getName());
                        sdc.CloseContext();
                       
                    }
                }
            }
        }
        if (sess != null && sess.hasDynamicShares()) {
            shrList.addShares(sess.getDynamicShareList());
        }
        if (allShares == false) {
            shrList.removeUnavailableShares();
        }
        return shrList;
    }

    @Override
    public SharedDevice findShare(String tohost, String name, int typ, SrvSession sess, boolean create) throws Exception {
        SharedDevice share;
        if (name.equalsIgnoreCase("IPC$")) {
            share = m_filesysConfig.getShares().findShare(name, typ, false);
            if (share == null) {
                share = m_filesysConfig.getShares().findShare(name, typ, true);
            }
        } else {
            String path = SurFile.checkPath(name).toLowerCase();
            share = m_filesysConfig.getShares().findShare(path.substring(1), typ, false);
            if (share == null) { //创建
                try {//查找数据库
                    pool.getDatasource().getNasMetaAccessor().getQuata(path);
                } catch (Exception r) {//无此挂载点
                  
                    return null;
                }
                Element e = getShareElement(path);
                
                m_config.addDiskShare(e, m_filesysConfig);
                share = m_filesysConfig.getShares().findShare(path.substring(1), typ, false);
            }
        }
        if (share != null && share.getContext() != null && share.getContext().isAvailable() == false) {
            share = null;
        }
        return share;
    }

    @Override
    public void deleteShares(SrvSession sess) {
        if (sess.hasDynamicShares() == false) {
            return;
        }
        SharedDeviceList shares = sess.getDynamicShareList();
        Enumeration<SharedDevice> enm = shares.enumerateShares();
        while (enm.hasMoreElements()) {
            SharedDevice shr = enm.nextElement();
            shr.getContext().CloseContext();
          
        }
    }

    @Override
    public void closeMapper() {
       
        m_config.closeConfiguration();
    }

    @Override
    public int configurationChanged(int id, ServerConfiguration config, Object newVal) throws InvalidConfigurationException {
        if (id == ConfigId.ConfigSection) {
            if (newVal instanceof FilesystemsConfigSection) {
                m_filesysConfig = (FilesystemsConfigSection) newVal;
                //AdminSharedDevice admShare = new AdminSharedDevice();
                //m_filesysConfig.addShare(admShare);
                try {
                    initShare();
                } catch (IOException | InvalidConfigurationException ex) {
                }
            }
            return ConfigurationListener.StsAccepted;
        }
        return ConfigurationListener.StsIgnored;
    }
}
