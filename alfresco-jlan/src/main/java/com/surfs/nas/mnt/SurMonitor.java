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
import com.autumn.util.ConsoleCommand;
import java.io.File;
import java.util.Properties;
import org.alfresco.jlan.app.Monitor;

public class SurMonitor extends Monitor {

    private final static Logger log = LogFactory.getLogger(SurMonitor.class);

    private final String os;

    public SurMonitor(Properties properties) {
        super(properties);
        String s = System.getProperty("os.name").toLowerCase();
        if (s.contains("windows")) {
            os = "windows";
        } else {
            os = "linux";
        }
    }

    private void monitorWin(String id) throws Exception {
        String type = this.properties.getProperty(id + ".type");
        String option = this.properties.getProperty(id + ".option");
        String path = this.properties.getProperty(id + ".path");
        String point = this.properties.getProperty(id + ".point");
        File f = new File(point);
        if (f.exists()) {
            return;
        }
        if (type.equalsIgnoreCase("vhd")) {
            String cmd = "diskpart";
            String[] args = new String[3];
            args[0] = "select vdisk file=" + path;
            args[1] = "attach vdisk";
            args[2] = "exit";
            ConsoleCommand command = new ConsoleCommand(cmd, args);
            command.setLog(log);
            command.call();
        } else if (type.equalsIgnoreCase("nfs")) {
            StringBuilder sb = new StringBuilder("mount ");
            if (!(option == null || option.trim().isEmpty())) {
                sb.append("-o ").append(option);
            }
            sb.append(" ").append(path);
            sb.append(" ").append(point);
            String[] args = new String[2];
            args[0] = sb.toString();
            args[1] = "exit";
            ConsoleCommand command = new ConsoleCommand("cmd", args);
            
            command.setLog(log);
            command.call();
        } else if (type.equalsIgnoreCase("cifs")) {
            StringBuilder sb = new StringBuilder("net use ");
            sb.append(point);
            sb.append(" ").append(path);
            if (!(option == null || option.trim().isEmpty())) {
                sb.append(" ").append(option);
            }
            String[] args = new String[2];
            args[0] = sb.toString();
            args[1] = "exit";
            ConsoleCommand command = new ConsoleCommand("cmd", args);
           
            command.setLog(log);
            command.call();
        }
    }

    private void monitorLinux(String id) throws Exception {
        String type = this.properties.getProperty(id + ".type");
        String option = this.properties.getProperty(id + ".option");
        String path = this.properties.getProperty(id + ".path");
        String point = this.properties.getProperty(id + ".point");
        String cmd = "mount |grep '" + path + " on " + point + "'";
        String[] args = new String[2];
        args[0] = cmd;
        args[1] = "exit";
        ConsoleCommand cc = new ConsoleCommand("/bin/sh", args);
        cc.call();
        String s = cc.getOutputText();
        if (!(s == null || s.isEmpty() || s.equalsIgnoreCase("null"))) {
            return;
        }
        if (type.equalsIgnoreCase("nfs")) {
            StringBuilder sb = new StringBuilder("mount -t nfs ");
            if (!(option == null || option.trim().isEmpty())) {
                sb.append("-o ").append(option);
            }
            sb.append(" ").append(path);
            sb.append(" ").append(point);
            ConsoleCommand command = new ConsoleCommand(sb.toString());
           
            command.setLog(log);
            command.call();
        } else if (type.equalsIgnoreCase("cifs")) {
            StringBuilder sb = new StringBuilder("mount -t cifs ");
            if (!(option == null || option.trim().isEmpty())) {
                sb.append("-o ").append(option);
            }
            sb.append(" ").append(path);
            sb.append(" ").append(point);
            ConsoleCommand command = new ConsoleCommand(sb.toString());
            
            command.setLog(log);
            command.call();
        }
    }

    @Override
    public void doTask() throws Throwable {
        String ss = this.properties.getProperty("mountid");
        if (ss == null || ss.trim().isEmpty()) {
            return;
        }
        String[] ids = ss.split(",");
        for (String id : ids) {
            id = id.trim();
            if (id.isEmpty()) {
                continue;
            }
            String type = this.properties.getProperty(id + ".type");
            if (type == null || type.trim().isEmpty()) {
                continue;
            }
            if (os.equals("windows")) {
                monitorWin(id);
            } else {
                monitorLinux(id);
            }
        }
    }

    @Override
    public void close() throws Throwable {
        String onexit = this.properties.getProperty("umountonexit");
        if (onexit != null && onexit.equalsIgnoreCase("true")) {
            String ss = this.properties.getProperty("mountid");
            if (ss == null || ss.trim().isEmpty()) {
                return;
            }
            String[] ids = ss.split(",");
            for (int ii = ids.length - 1; ii >= 0; ii--) {
                String id = ids[ii].trim();
                if (id.isEmpty()) {
                    continue;
                }
                String type = this.properties.getProperty(id + ".type");
                if (type == null || type.trim().isEmpty()) {
                    continue;
                }
                if (os.equals("windows")) {
                    umountWin(id);
                } else {
                    umountLinux(id);
                }
            }
        }
    }

    private void umountWin(String id) throws Exception {
        String type = this.properties.getProperty(id + ".type");
        String point = this.properties.getProperty(id + ".point");
        String path = this.properties.getProperty(id + ".path");
        File f = new File(point);
        if (!f.exists()) {
            return;
        }
        if (type.equalsIgnoreCase("vhd")) {
            String cmd = "diskpart";
            String[] args = new String[3];
            args[0] = "select vdisk file=" + path;
            args[1] = "detach vdisk";
            args[2] = "exit";
            ConsoleCommand command = new ConsoleCommand(cmd, args);
            command.setLog(log);
            command.call();
        } else if (type.equalsIgnoreCase("nfs")) {
            StringBuilder sb = new StringBuilder("umount");
            sb.append(" ").append(point);
            sb.append(" -f");
            ConsoleCommand command = new ConsoleCommand(sb.toString());
            
            command.setLog(log);
            command.call();
        } else if (type.equalsIgnoreCase("cifs")) {
            StringBuilder sb = new StringBuilder("net use ");
            sb.append(point);
            sb.append(" /delete");
            String[] args = new String[3];
            args[0] = sb.toString();
            args[1] = "yes";
            args[2] = "exit";
            ConsoleCommand command = new ConsoleCommand("cmd", args);
            
            command.setLog(log);
            command.call();
        }
    }

    private void umountLinux(String id) throws Exception {
        String path = this.properties.getProperty(id + ".path");
        String point = this.properties.getProperty(id + ".point");
        String cmd = "mount |grep '" + path + " on " + point + "'";
        String[] args = new String[2];
        args[0] = cmd;
        args[1] = "exit";
        ConsoleCommand cc = new ConsoleCommand("/bin/sh", args);
        cc.call();
        String s = cc.getOutputText();
        if (s == null || s.isEmpty() || s.equalsIgnoreCase("null")) {
            return;
        }
        StringBuilder sb = new StringBuilder("umount -l");
        sb.append(" ").append(point);
        ConsoleCommand command = new ConsoleCommand(sb.toString());
        
        command.setLog(log);
        command.call();
    }
}
