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

import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.TableModel;
import java.util.ArrayList;
import java.util.List;

public class SecretsTableModel implements TableModel {
    List<TableModelListener> listeners = new ArrayList<>();

    enum SecretsColumn {
        NAME("Name");

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
        } else {
          return "?";
        }
    }

    @Override
    public void setValueAt(Object o, int row, int column) {

    }

    @Override
    public void addTableModelListener(TableModelListener tableModelListener) {
        listeners.add(tableModelListener);
    }

    @Override
    public void removeTableModelListener(TableModelListener tableModelListener) {
        listeners.remove(tableModelListener);
    }

    public void add(Secret secret){
        if(!secrets.contains(secret)) {
            secrets.add(secret);
            for (TableModelListener l: listeners){
                l.tableChanged(new TableModelEvent(this));
            }
        }
    }
}
