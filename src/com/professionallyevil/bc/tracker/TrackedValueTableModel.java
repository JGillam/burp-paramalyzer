/*
 * Copyright (c) 2020 Jason Gillam
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

package com.professionallyevil.bc.tracker;

import com.professionallyevil.bc.ParamInstance;

import javax.swing.table.AbstractTableModel;

public class TrackedValueTableModel extends AbstractTableModel {
    enum Column {
        VALUE("Value"),
        DIRECTION("Direction"),
        ORIGIN("Origin"),
        PATH("Path"),
        IN_SCOPE("In Scope"),
        SOURCE_SECRETS("Source Secrets");

        private final String title;

        private Column(String title) {
            this.title = title;
        }

        public String getTitle(){
            return title;
        }

    }

    TrackedParameter trackedParameter;
    java.util.List<ParamInstance> instanceList = new java.util.ArrayList<>();

    public void setTrackedParameter(TrackedParameter trackedParameter) {
        if(trackedParameter != this.trackedParameter) {
            this.trackedParameter = trackedParameter;
            this.instanceList.clear();
            trackedParameter.paramInstanceIterator().forEachRemaining(this.instanceList::add);
            fireTableDataChanged();
        }
    }

    @Override
    public int getRowCount() {
        return this.instanceList.size();
    }

    @Override
    public int getColumnCount() {
        return Column.values().length;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        Column col = Column.values()[columnIndex];
        ParamInstance row = instanceList.get(rowIndex);
        switch(col){
            case VALUE:
                return row.getValue();
            case DIRECTION:
                return "Request";
            case ORIGIN:
                break;
            case PATH:
                break;
            case IN_SCOPE:
                break;
            case SOURCE_SECRETS:
                break;
            default:
                return "";
        }
        return "";
    }

    @Override
    public String getColumnName(int column) {
        return Column.values()[column].getTitle();
    }
}
