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

package com.professionallyevil.paramalyzer;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ParametersTableModel extends AbstractTableModel {

    enum Column {
        NAME("Name"),
        TYPE("Type"),
        ORIGIN("Origin"),
        REQUESTS("Requests", Integer.class),
        UNIQUE_URLS("Unique URLs", Integer.class),
        UNIQUE_VALUES("Unique Values", Integer.class),
        FORMAT("Format"),
        REFLECT("Reflect %", Integer.class),
        SECRET("Secret", Boolean.class, true),
        DECODABLE("Decodable", Boolean.class),
        EXAMPLE("Example Value");

        private final String title;
        private final Class clazz;
        private final boolean isEditable;

        private Column(String title) {
            this.title = title;
            this.clazz = String.class;
            this.isEditable = false;
        }

        private Column(String title, Class clazz) {
            this.title = title;
            this.clazz = clazz;
            this.isEditable = false;
        }

        private Column(String title, Class clazz, boolean isEditable) {
            this.title = title;
            this.clazz = clazz;
            this.isEditable = isEditable;
        }

        public String getTitle(){
            return title;
        }

        public Class getClazz() { return clazz; }

        public boolean isEditable() {return this.isEditable; }

    }

    boolean showDecodedValues = true;
    List<CorrelatedParam> entries = new ArrayList<>();
    String[] columns = {"Name", "Type", "Requests", "Unique URLs", "Unique Values" , "Format", "Reflect %", "Interesting", "Decodeable", "Example Value"};
    Class[] columnClasses = {String.class, String.class, Integer.class, Integer.class, Integer.class, String.class, Integer.class, Boolean.class, Boolean.class, String.class};
    Map<CorrelatedParam, ParamInstance> samples = new HashMap<>();

    @Override
    public String getColumnName(int column) {
        return Column.values()[column].getTitle();
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return Column.values()[columnIndex].getClazz();
    }

    public void addParameters(Map<String, CorrelatedParam> parametersToAdd) {
        entries.addAll(parametersToAdd.values());
        fireTableDataChanged();
    }

    public CorrelatedParam getParameter(int row) {
        return entries.get(row);
    }

    public void clear() {
        entries.clear();
        samples.clear();
        fireTableDataChanged();
    }

    public List<CorrelatedParam> getEntries(){
        return entries;
    }

    @Override
    public int getRowCount() {
        return entries.size();
    }

    @Override
    public int getColumnCount() {
        return Column.values().length;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        CorrelatedParam param = entries.get(rowIndex);
        if (!samples.containsKey(param)) {
            ParamInstance sample = param.getSample();
            samples.put(param, sample);
        }

        ParamInstance sample = samples.get(param);

        Column col = Column.values()[columnIndex];

        switch (col){
            case NAME:
                return sample.getName();
            case TYPE:
                return sample.getTypeName();
            case ORIGIN:
                return param.getOrigin();
            case REQUESTS:
                return param.getParamInstances(true).size();
            case UNIQUE_URLS:
                return param.getUniqueURLs().size();
            case UNIQUE_VALUES:
                return param.getParamInstances(false).size();
            case FORMAT:
                return param.getFormatString();
            case REFLECT:
                int count = param.getReflectedCount();
                return count == 0?0:(100 * count / param.getParamInstances(true).size());
            case SECRET:
                return param.setSecret() ;
            case DECODABLE:
                return !(sample.getDecodedValue() == null) && !sample.getDecodedValue().equals(sample.getValue());
            case EXAMPLE:
                if(showDecodedValues) {
                    return sample.getDecodedValue();
                }  else {
                    return sample.getValue();
                }
            default:
                return "";
        }
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return Column.values()[columnIndex].isEditable();
    }

    @Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        if(columnIndex == Column.SECRET.ordinal()) {
            CorrelatedParam param = entries.get(rowIndex);
            param.setSecret(!param.setSecret());
        }
    }

    public void setShowDecodedValues(boolean decoded) {
        showDecodedValues = decoded;
    }


}
