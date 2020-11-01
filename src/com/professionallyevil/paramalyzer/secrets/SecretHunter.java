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

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import com.intellij.uiDesigner.core.GridConstraints;
import com.intellij.uiDesigner.core.GridLayoutManager;
import com.intellij.uiDesigner.core.Spacer;
import com.professionallyevil.paramalyzer.CorrelatedParam;
import com.professionallyevil.paramalyzer.ParametersTableModel;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;

public class SecretHunter implements IBurpExtender {
    private JPanel mainPanel;
    private JTable secretsTable;
    private JButton importSecrets;
    private JButton removeImportedButton;
    private JButton addSecretButton;
    private JButton editSelectedButton;
    private JButton removeSelectedButton;
    private JPanel topPanel;
    private JPanel bottomPanel;
    private JProgressBar secretHunterProgress;
    private JButton huntSecretsButton;
    private JTable resultsTabel;
    private final SecretsTableModel secretsTableModel = new SecretsTableModel();
    private IBurpExtenderCallbacks callbacks;

    public SecretHunter(ParametersTableModel parametersTableModel) {
        secretsTable.setModel(secretsTableModel);
        importSecrets.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                for (CorrelatedParam correlatedParam : parametersTableModel.getEntries()) {
                    if (correlatedParam.setSecret()) {
                        ParameterSecret secret = new ParameterSecret(correlatedParam);
                        secretsTableModel.add(secret);
                    }
                }
            }
        });
        removeImportedButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                secretsTableModel.removeImported();

            }
        });
        addSecretButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                AddModifySecret dialog = new AddModifySecret(null, new AddModifySecretListener() {
                    @Override
                    public void dialogAccepted(String name, boolean isRegex, String matchString) {
                        CustomSecret secret = new CustomSecret(name, isRegex, matchString);
                        secretsTableModel.add(secret);
                    }
                });
                dialog.pack();
                dialog.setLocationRelativeTo(mainPanel);
                dialog.setVisible(true);

            }
        });
        editSelectedButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                int selectedRow = secretsTable.getSelectedRow();
                Secret secret = secretsTableModel.getSecret(selectedRow);
                if (secret instanceof CustomSecret) {
                    CustomSecret customSecret = (CustomSecret) secret;
                    AddModifySecret dialog = new AddModifySecret(customSecret, new AddModifySecretListener() {
                        @Override
                        public void dialogAccepted(String name, boolean isRegex, String matchString) {
                            customSecret.setName(name);
                            if (isRegex) {
                                customSecret.setRegex(matchString);
                            } else {
                                customSecret.setExactMatch(matchString);
                            }
                            secretsTableModel.fireTableRowsUpdated(selectedRow, selectedRow);
                        }
                    });
                    dialog.pack();
                    dialog.setLocationRelativeTo(mainPanel);
                    dialog.setVisible(true);

                }

            }
        });
        removeSelectedButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                int[] selectedRows = secretsTable.getSelectedRows();
                java.util.List<Secret> toBeRemoved = new ArrayList<>();
                for (int selectedRow : selectedRows) {
                    toBeRemoved.add(secretsTableModel.getSecret(selectedRow));
                }
                secretsTableModel.removeSecrets(toBeRemoved);
            }
        });

        //  TODO: Investigate - why adding this logic in seems to cause glitchy table rendering.
//        secretsTable.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
//            @Override
//            public void valueChanged(ListSelectionEvent listSelectionEvent) {
//                if (secretsTable.getSelectedColumnCount() > 0) {
//                    editSelectedButton.setEnabled(secretsTableModel.getSecret(secretsTable.getSelectedRow()) instanceof CustomSecret);
//                }
//            }
//        });
        huntSecretsButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {

            }
        });
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

    public Component getMainPanel() {
        return mainPanel;
    }


    {
// GUI initializer generated by IntelliJ IDEA GUI Designer
// >>> IMPORTANT!! <<<
// DO NOT EDIT OR ADD ANY CODE HERE!
        $$$setupUI$$$();
    }

    /**
     * Method generated by IntelliJ IDEA GUI Designer
     * >>> IMPORTANT!! <<<
     * DO NOT edit this method OR call it in your code!
     *
     * @noinspection ALL
     */
    private void $$$setupUI$$$() {
        mainPanel = new JPanel();
        mainPanel.setLayout(new GridLayoutManager(3, 2, new Insets(0, 0, 0, 0), -1, -1));
        mainPanel.setBorder(BorderFactory.createTitledBorder(null, "Secrets", TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, null, null));
        topPanel = new JPanel();
        topPanel.setLayout(new GridLayoutManager(2, 2, new Insets(0, 0, 0, 0), -1, -1));
        mainPanel.add(topPanel, new GridConstraints(0, 0, 2, 2, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final Spacer spacer1 = new Spacer();
        topPanel.add(spacer1, new GridConstraints(1, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        final JScrollPane scrollPane1 = new JScrollPane();
        topPanel.add(scrollPane1, new GridConstraints(0, 0, 2, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        secretsTable = new JTable();
        scrollPane1.setViewportView(secretsTable);
        final JPanel panel1 = new JPanel();
        panel1.setLayout(new GridLayoutManager(8, 1, new Insets(0, 0, 0, 0), -1, -1));
        topPanel.add(panel1, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        importSecrets = new JButton();
        importSecrets.setText("Import Secrets");
        importSecrets.setToolTipText("Import the secrets that are selected in the main Paramaeters tab.");
        panel1.add(importSecrets, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final Spacer spacer2 = new Spacer();
        panel1.add(spacer2, new GridConstraints(6, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_VERTICAL, 1, GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        removeImportedButton = new JButton();
        removeImportedButton.setText("Remove Imported");
        removeImportedButton.setToolTipText("Remove imported secrets but leave custom secrets in the list.");
        panel1.add(removeImportedButton, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        addSecretButton = new JButton();
        addSecretButton.setText("Add Secret");
        addSecretButton.setToolTipText("Add a custom secret by regex or exact string match.");
        panel1.add(addSecretButton, new GridConstraints(2, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        editSelectedButton = new JButton();
        editSelectedButton.setText("Edit Selected");
        editSelectedButton.setToolTipText("Edit selected custom secret. Has no affect on imported secrets.");
        panel1.add(editSelectedButton, new GridConstraints(3, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        removeSelectedButton = new JButton();
        removeSelectedButton.setText("Remove Selected");
        removeSelectedButton.setToolTipText("Remove all selected secrets.");
        panel1.add(removeSelectedButton, new GridConstraints(4, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel2 = new JPanel();
        panel2.setLayout(new GridLayoutManager(1, 1, new Insets(0, 0, 0, 0), -1, -1));
        panel1.add(panel2, new GridConstraints(7, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        panel2.setBorder(BorderFactory.createTitledBorder(null, "Progress", TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, null, null));
        secretHunterProgress = new JProgressBar();
        panel2.add(secretHunterProgress, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        huntSecretsButton = new JButton();
        huntSecretsButton.setText("Hunt Secrets");
        panel1.add(huntSecretsButton, new GridConstraints(5, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        bottomPanel = new JPanel();
        bottomPanel.setLayout(new GridLayoutManager(1, 1, new Insets(0, 0, 0, 0), -1, -1));
        mainPanel.add(bottomPanel, new GridConstraints(2, 0, 1, 2, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        bottomPanel.setBorder(BorderFactory.createTitledBorder(null, "Results", TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, null, null));
        final JSplitPane splitPane1 = new JSplitPane();
        bottomPanel.add(splitPane1, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, new Dimension(200, 200), null, 0, false));
        final JScrollPane scrollPane2 = new JScrollPane();
        splitPane1.setLeftComponent(scrollPane2);
        resultsTabel = new JTable();
        scrollPane2.setViewportView(resultsTabel);
        final JPanel panel3 = new JPanel();
        panel3.setLayout(new GridLayoutManager(1, 1, new Insets(0, 0, 0, 0), -1, -1));
        splitPane1.setRightComponent(panel3);
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return mainPanel;
    }


}
