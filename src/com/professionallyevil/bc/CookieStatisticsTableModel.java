/*
 * Copyright (c) 2019 Jason Gillam
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.professionallyevil.bc;

import burp.IBurpExtenderCallbacks;

import javax.swing.table.AbstractTableModel;
import java.util.Map;
import java.util.TreeMap;

public class CookieStatisticsTableModel extends AbstractTableModel {

    String[] columnNames = {"Name", "Count", "HttpOnly Flag", "Secure Flag", "Type", "Domains", "Paths"};
    Class[] columnClasses = {String.class, Integer.class, String.class, String.class, String.class, String.class, String.class};

    Map<String, CookieStatistics> cookieStatistics = new TreeMap<>();

    public void setCookieStatistics(Map<String,CookieStatistics> cookieStatistics, IBurpExtenderCallbacks callbacks) {
        this.cookieStatistics.clear();
        this.cookieStatistics.putAll(cookieStatistics);
        fireTableDataChanged();
    }

    public void clear() {
        this.cookieStatistics.clear();
        fireTableDataChanged();
    }

    @Override
    public String getColumnName(int column) {
        return columnNames[column];
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return columnClasses[columnIndex];
    }

    @Override
    public int getRowCount() {
        return cookieStatistics.size();
    }

    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        String key = (String)cookieStatistics.keySet().toArray()[rowIndex];
        CookieStatistics cs = cookieStatistics.get(key);
        switch(columnIndex){
            case 0:
                return key;
            case 1:
                return cs.getCount();
            case 2:
                return cs.getHttpOnly();
            case 3:
                return cs.getSecure();
            case 4:
                return cs.getType();
            case 5:
                return cs.getDomains();
            case 6:
                return cs.getPaths();
            default:
                return "";

        }
    }
}
