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

import javax.swing.table.AbstractTableModel;

public class TrackedValueTableModel extends AbstractTableModel {
    TrackedParameter trackedParameter;

    public void setTrackedParameter(TrackedParameter trackedParameter) {
        if (trackedParameter == null) {
            this.trackedParameter = trackedParameter;
            fireTableDataChanged();
        } else if(trackedParameter != this.trackedParameter) {
            this.trackedParameter = trackedParameter;
            fireTableDataChanged();
        }
    }

    @Override
    public int getRowCount() {
        return trackedParameter == null ? 0 : trackedParameter.getEdges().size();
    }

    @Override
    public int getColumnCount() {
        return ParamTrackerEdge.Column.values().length;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        if (trackedParameter == null) {
            return null;
        } else {
            ParamTrackerEdge.Column col = ParamTrackerEdge.Column.values()[columnIndex];
            return trackedParameter.getEdges().get(rowIndex).getValue(col);
        }
    }

    @Override
    public String getColumnName(int column) {
        return ParamTrackerEdge.Column.values()[column].getTitle();
    }
}