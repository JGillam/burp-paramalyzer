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

import burp.IBurpExtenderCallbacks;
import com.intellij.uiDesigner.core.GridConstraints;
import com.intellij.uiDesigner.core.GridLayoutManager;
import com.intellij.uiDesigner.core.Spacer;
import com.professionallyevil.paramalyzer.CorrelatedParam;
import com.professionallyevil.paramalyzer.ParametersTableModel;
import com.professionallyevil.paramalyzer.WorkerStatusListener;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultHighlighter;
import javax.swing.text.Highlighter;
import java.awt.*;
import java.awt.event.*;

public class SecretHunter implements WorkerStatusListener {
    public static boolean DEBUG_STATUS = true;
    private JPanel mainPanel;
    private JTable secretsTable;
    private JButton importSecrets;
    private JButton removeImportedButton;
    private JProgressBar hunterProgressBar;
    private JTable secretResultsTable;
    private JButton huntSecrets;
    private JLabel statusLabel;
    private JPanel editorPanel;
    private JTextArea requestTextArea;
    private JPanel controlPanel;
    private JPanel topPanel;
    private JPanel bottomPanel;
    private JButton removeSelectedButton;
    private JComboBox colorCombo;
    private JTextField commentText;
    private SecretsTableModel secretsTableModel = new SecretsTableModel();
    private SecretResultsTableModel secretResultsTableModel = new SecretResultsTableModel();

    private IBurpExtenderCallbacks callbacks;

    @Override
    public void setStatus(String statusText) {

        if (DEBUG_STATUS) {
            callbacks.printOutput("STATUS: " + statusText);
        }

        statusLabel.setText(statusText);
    }

    @Override
    public void setProgress(int percentDone) {
        hunterProgressBar.setValue(percentDone);
    }

    @Override
    public void done(Object result) {
        statusLabel.setText("Done.");
        setProgress(100);
    }

    public SecretHunter(final ParametersTableModel parametersTableModel) {
        secretsTable.setModel(secretsTableModel);
        secretsTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        secretResultsTable.setModel(secretResultsTableModel);
        secretResultsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        hunterProgressBar.setStringPainted(true);

        importSecrets.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                for (CorrelatedParam correlatedParam : parametersTableModel.getEntries()) {
                    if (correlatedParam.isSecret()) {
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
        huntSecrets.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                SecretHunterWorker worker = new SecretHunterWorker(callbacks, SecretHunter.this, secretsTableModel);
                worker.execute();
            }
        });

        secretsTable.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
            @Override
            public void valueChanged(ListSelectionEvent e) {
                SwingUtilities.invokeLater(new Runnable() {
                    @Override
                    public void run() {
                        Secret selectedSecret = secretsTableModel.getSecretsList().get(secretsTable.getSelectedRow());
                        secretResultsTableModel.setResults(selectedSecret.getResults());
                    }
                });
            }
        });

        secretResultsTable.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
            @Override
            public void valueChanged(ListSelectionEvent e) {
                SwingUtilities.invokeLater(new Runnable() {
                    @Override
                    public void run() {
                        Highlighter highlighter = requestTextArea.getHighlighter();

                        highlighter.removeAllHighlights();
                        SecretResult selectedResult = secretResultsTableModel.secretResults.get(secretResultsTable.getSelectedRow());
                        if (selectedResult != null) {
                            byte[] requestBytes = selectedResult.requestResponse.getRequest();
                            String requestString = callbacks.getHelpers().bytesToString(requestBytes);
                            requestTextArea.setText(requestString);
                            String highlightValue = selectedResult.getValue();
                            int index = requestString.indexOf(highlightValue);
                            try {
                                highlighter.addHighlight(index, index + highlightValue.length(), new DefaultHighlighter.DefaultHighlightPainter(Color.pink));
                                Rectangle viewRect = requestTextArea.modelToView(index);
                                // Scroll to make the rectangle visible
                                requestTextArea.scrollRectToVisible(viewRect);
                            } catch (BadLocationException ex) {
                                // do nothing
                            }
                            //messageEditor.setMessage(selectedResult.getRequestResponse().getRequest(), true);
                            commentText.setText(selectedResult.getRequestResponse().getComment());
                            String color = selectedResult.getRequestResponse().getHighlight();
                            if (color == null) {
                                color = "none";
                            }
                            colorCombo.setSelectedItem(color);

                        } else {
                            requestTextArea.setText("");
                        }
                    }
                });
            }
        });

        removeSelectedButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int[] selectedRows = secretsTable.getSelectedRows();
                secretsTableModel.removeRows(selectedRows);
            }
        });
        colorCombo.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent e) {
                SecretResult selectedResult = secretResultsTableModel.secretResults.get(secretResultsTable.getSelectedRow());
                if (selectedResult != null && e.getStateChange() == ItemEvent.SELECTED) {
                    String color = (String) colorCombo.getSelectedItem();
                    if ("none".equals(color)) {
                        selectedResult.getRequestResponse().setHighlight(null);
                    } else {
                        selectedResult.getRequestResponse().setHighlight(color);
                    }
                }
            }
        });

        commentText.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                SecretResult selectedResult = secretResultsTableModel.secretResults.get(secretResultsTable.getSelectedRow());
                if (selectedResult != null) {
                    selectedResult.getRequestResponse().setComment(commentText.getText());
                }
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                SecretResult selectedResult = secretResultsTableModel.secretResults.get(secretResultsTable.getSelectedRow());
                if (selectedResult != null) {
                    selectedResult.getRequestResponse().setComment(commentText.getText());
                }
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                SecretResult selectedResult = secretResultsTableModel.secretResults.get(secretResultsTable.getSelectedRow());
                if (selectedResult != null) {
                    selectedResult.getRequestResponse().setComment(commentText.getText());
                }
            }
        });

//        commentText.addFocusListener(new FocusAdapter() {
//            @Override
//            public void focusLost(FocusEvent e) {
//                SecretResult selectedResult = secretResultsTableModel.secretResults.get(secretResultsTable.getSelectedRow());
//                if (selectedResult != null) {
//                    selectedResult.getRequestResponse().setComment(commentText.getText());
//                }
//            }
//        });
    }

    public void registerCallbacks(IBurpExtenderCallbacks callbacks) {
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
        mainPanel.setLayout(new GridLayoutManager(2, 1, new Insets(0, 0, 0, 0), -1, -1));
        final JSplitPane splitPane1 = new JSplitPane();
        splitPane1.setOrientation(0);
        mainPanel.add(splitPane1, new GridConstraints(0, 0, 2, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, new Dimension(200, 200), null, 0, false));
        topPanel = new JPanel();
        topPanel.setLayout(new GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), -1, -1));
        splitPane1.setLeftComponent(topPanel);
        final JScrollPane scrollPane1 = new JScrollPane();
        topPanel.add(scrollPane1, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, null, new Dimension(453, 280), null, 0, false));
        secretsTable = new JTable();
        secretsTable.setAutoCreateRowSorter(true);
        scrollPane1.setViewportView(secretsTable);
        controlPanel = new JPanel();
        controlPanel.setLayout(new GridLayoutManager(8, 1, new Insets(0, 0, 0, 0), -1, -1));
        topPanel.add(controlPanel, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, new Dimension(150, 280), null, 0, false));
        final Spacer spacer1 = new Spacer();
        controlPanel.add(spacer1, new GridConstraints(4, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_VERTICAL, 1, GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        removeImportedButton = new JButton();
        removeImportedButton.setText("Clear");
        controlPanel.add(removeImportedButton, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        huntSecrets = new JButton();
        huntSecrets.setText("Hunt Secrets!");
        controlPanel.add(huntSecrets, new GridConstraints(3, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        hunterProgressBar = new JProgressBar();
        controlPanel.add(hunterProgressBar, new GridConstraints(5, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        statusLabel = new JLabel();
        statusLabel.setText("Idle...");
        controlPanel.add(statusLabel, new GridConstraints(6, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final Spacer spacer2 = new Spacer();
        controlPanel.add(spacer2, new GridConstraints(7, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        importSecrets = new JButton();
        importSecrets.setText("Import Secrets");
        importSecrets.setToolTipText("Copy secrets from the main parameter table.");
        controlPanel.add(importSecrets, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        removeSelectedButton = new JButton();
        removeSelectedButton.setText("Remove Selected");
        controlPanel.add(removeSelectedButton, new GridConstraints(2, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        bottomPanel = new JPanel();
        bottomPanel.setLayout(new GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), -1, -1));
        splitPane1.setRightComponent(bottomPanel);
        final JSplitPane splitPane2 = new JSplitPane();
        splitPane2.setDividerLocation(254);
        splitPane2.setResizeWeight(0.5);
        bottomPanel.add(splitPane2, new GridConstraints(0, 0, 1, 2, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, new Dimension(200, 200), null, 0, false));
        final JScrollPane scrollPane2 = new JScrollPane();
        splitPane2.setLeftComponent(scrollPane2);
        scrollPane2.setBorder(BorderFactory.createTitledBorder(null, "Results", TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, null, null));
        secretResultsTable = new JTable();
        scrollPane2.setViewportView(secretResultsTable);
        editorPanel = new JPanel();
        editorPanel.setLayout(new GridLayoutManager(2, 1, new Insets(0, 0, 0, 0), -1, -1));
        splitPane2.setRightComponent(editorPanel);
        editorPanel.setBorder(BorderFactory.createTitledBorder(null, "Selected Request", TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, null, null));
        final JScrollPane scrollPane3 = new JScrollPane();
        editorPanel.add(scrollPane3, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        requestTextArea = new JTextArea();
        scrollPane3.setViewportView(requestTextArea);
        final JPanel panel1 = new JPanel();
        panel1.setLayout(new GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), -1, -1));
        editorPanel.add(panel1, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        panel1.setBorder(BorderFactory.createTitledBorder(null, "Highlight / Comment", TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, null, null));
        colorCombo = new JComboBox();
        final DefaultComboBoxModel defaultComboBoxModel1 = new DefaultComboBoxModel();
        defaultComboBoxModel1.addElement("none");
        defaultComboBoxModel1.addElement("red");
        defaultComboBoxModel1.addElement("orange");
        defaultComboBoxModel1.addElement("yellow");
        defaultComboBoxModel1.addElement("green");
        defaultComboBoxModel1.addElement("cyan");
        defaultComboBoxModel1.addElement("blue");
        defaultComboBoxModel1.addElement("pink");
        defaultComboBoxModel1.addElement("magenta");
        defaultComboBoxModel1.addElement("gray");
        colorCombo.setModel(defaultComboBoxModel1);
        panel1.add(colorCombo, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        commentText = new JTextField();
        panel1.add(commentText, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return mainPanel;
    }

}
