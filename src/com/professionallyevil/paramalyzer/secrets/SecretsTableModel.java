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
import java.util.List;

public class SecretsTableModel extends AbstractTableModel {



    enum SecretsColumn {
        NAME("Name"),
        TYPE("Type");

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
        return String.class;
    }

    @Override
    public boolean isCellEditable(int row, int column) {
        return false;
    }

    @Override
    public Object getValueAt(int row, int column) {
        Secret secret = secrets.get(row);
        if(SecretsColumn.NAME.ordinal() == column) {
            return secret.getName();
        } else if(SecretsColumn.TYPE.ordinal() == column) {
            return secret.getType();
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

    public Secret getSecret(int row) {
        return secrets.get(row);
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

    public void removeSecrets(List<Secret> toBeRemoved) {
        secrets.removeAll(toBeRemoved);
        fireTableDataChanged();
    }
}
