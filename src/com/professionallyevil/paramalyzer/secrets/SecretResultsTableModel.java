/*
 * Copyright (c) 2022 Jason Gillam
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

package com.professionallyevil.paramalyzer.secrets;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

public class SecretResultsTableModel extends AbstractTableModel {

    enum SecretResultsColumn {
        VALUE("Value"),
        SEVERITY("Severity"),
        ISSUE_NAME("Issue Name");

        String name;
        SecretResultsColumn(String name)
        {
            this.name = name;
        }
    }

    List<SecretResult> secretResults = new ArrayList<>();

    @Override
    public int getRowCount() {
        return secretResults.size();
    }

    @Override
    public int getColumnCount() {
        return SecretResultsColumn.values().length;
    }

    @Override
    public String getColumnName(int i) {
        return SecretResultsColumn.values()[i].name;
    }

    @Override
    public Class<?> getColumnClass(int i) {
        return String.class;
    }

    @Override
    public boolean isCellEditable(int row, int column) {
        return false;
    }

    @Override
    public Object getValueAt(int row, int column) {
        SecretResult secretResult = secretResults.get(row);
        if(SecretResultsColumn.VALUE.ordinal() == column) {
            return secretResult.getValue();
        } else if(SecretResultsColumn.SEVERITY.ordinal() == column) {
            return secretResult.getSeverity();
        } else if(SecretResultsColumn.ISSUE_NAME.ordinal() == column) {
            return secretResult.getIssueName();
        } else {
            return "?";
        }
    }

    public void setResults(List<SecretResult> results) {
        this.secretResults = results;
        fireTableDataChanged();
    }

}
