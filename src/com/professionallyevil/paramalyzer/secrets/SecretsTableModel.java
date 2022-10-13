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

package com.professionallyevil.paramalyzer.secrets;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class SecretsTableModel extends AbstractTableModel {

    enum SecretsColumn {
        NAME("Name"),
        TYPE("Type"),

        EXAMPLE("Example Value"),

        HUNT_HASHED("Hunt Hashed"),

        ISSUES("Issues");

        String name;
        SecretsColumn(String name){
            this.name = name;
        }
    }

    List<Secret> secrets = new ArrayList<>();

    @Override
    public int getRowCount() {
        return secrets.size();
    }

    @Override
    public int getColumnCount() {
        return SecretsColumn.values().length;
    }

    @Override
    public String getColumnName(int i) {
        return SecretsColumn.values()[i].name;
    }

    @Override
    public Class<?> getColumnClass(int i) {
        if(SecretsColumn.ISSUES.ordinal() == i) {
            return Integer.class;
        } else if (SecretsColumn.HUNT_HASHED.ordinal() == i){
            return Boolean.class;
        } else {
            return String.class;
        }
    }

    @Override
    public boolean isCellEditable(int row, int column) {
        return SecretsColumn.HUNT_HASHED.ordinal() == column;
    }

    @Override
    public Object getValueAt(int row, int column) {
        Secret secret = secrets.get(row);
        if(SecretsColumn.NAME.ordinal() == column) {
            return secret.getName();
        } else if(SecretsColumn.TYPE.ordinal() == column) {
            return secret.getType();
        } else if(SecretsColumn.ISSUES.ordinal() == column) {
            return secret.getResults().size();
        } else if(SecretsColumn.EXAMPLE.ordinal() == column) {
            return secret.getExampleValue();
        } else if(SecretsColumn.HUNT_HASHED.ordinal() == column) {
            return secret.huntHashedValues();
        } else {
          return "?";
        }
    }

    public void add(Secret secret){
        if(!secrets.contains(secret)) {
            secrets.add(secret);
            fireTableDataChanged();
        }
    }

    public void removeImported(){
        List<ParameterSecret> secretsToBeRemoved = new ArrayList<>();
        for (Secret s: secrets) {
            if (s instanceof ParameterSecret) {
                secretsToBeRemoved.add((ParameterSecret) s);
            }
        }
        if(secretsToBeRemoved.size() > 0) {
            secrets.removeAll(secretsToBeRemoved);
            fireTableDataChanged();
        }
    }

    public void removeRows(int[] rows) {
        List<ParameterSecret> secretsToBeRemoved = new ArrayList<>();
        for(int i=0;i<rows.length;i++) {
            secretsToBeRemoved.add((ParameterSecret) secrets.get(rows[i]));
        }

        if(secretsToBeRemoved.size() > 0) {
            secrets.removeAll(secretsToBeRemoved);
            fireTableDataChanged();
            fireTableStructureChanged();
        }
    }

    public List<Secret> getSecretsList() {
        return secrets;
    }

    public void updateSecret(Secret secret) {
        int row = secrets.indexOf(secret);
        fireTableRowsUpdated(row, row);
    }

    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        if(SecretsColumn.HUNT_HASHED.ordinal() == columnIndex) {
            Secret secret = secrets.get(rowIndex);
            secret.setHuntHashedValues(!secret.huntHashedValues());
        }
    }

    public void clearIssues() {
        for(Iterator<Secret> secretIterator = secrets.listIterator();secretIterator.hasNext();) {
            Secret nextSecret = secretIterator.next();
            nextSecret.clearResults();
        }
        fireTableDataChanged();
    }
}
