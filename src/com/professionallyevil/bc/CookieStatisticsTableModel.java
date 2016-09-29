package com.professionallyevil.bc;

import burp.IBurpExtenderCallbacks;

import javax.swing.table.AbstractTableModel;
import java.util.Map;
import java.util.TreeMap;

public class CookieStatisticsTableModel extends AbstractTableModel {

    String[] columnNames = {"Name", "Count", "HttpOnly Flag", "Secure Flag"};

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
        return String.class;
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
            default:
                return "";

        }
    }
}
