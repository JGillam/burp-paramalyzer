/*
 * Copyright (c) 2015 Jason Gillam
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

package com.professionallyevil.bc;

import burp.*;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.text.Caret;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.ClipboardOwner;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Transferable;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.net.URL;

/**
 * Main class for the Correlator burp extension.
 */
public class Paramalyzer implements IBurpExtender, ITab, CorrelatorEngineListener, ClipboardOwner {
    private JPanel mainPanel;
    private JButton beginAnalysisButton;
    private JTextField textFieldStatus;
    private JProgressBar progressBar;
    private JTable parametersTable;
    private JButton clearButton;
    private JList<String> listValues;
    private JTextArea textAreaRequest;
    private JTextArea textAreaResponse;
    private JCheckBox ignoreEmptyCheckBox;
    private JCheckBox showDuplicatesCheckBox;
    private JTextArea analysisTextArea;
    private JButton highlightValueButton;
    private JTextArea ignore;
    private JCheckBox showDecodedValuesCheckBox;
    private IBurpExtenderCallbacks callbacks;
    private CorrelatorEngine engine = null;
    private ParametersTableModel paramsTableModel = new ParametersTableModel();
    private ParamListModel paramListModel = new ParamListModel();
    private int lastSelectedRow = -1;
    private IHttpRequestResponse displayedRequest = null;

    private static final String VERSION = "0.4.2";
    private static final String EXTENSION_NAME = "Paramalyzer";

    public Paramalyzer() {
        parametersTable.setModel(paramsTableModel);
        parametersTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        beginAnalysisButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                paramsTableModel.setShowDecodedValues(showDecodedValuesCheckBox.isSelected());
                paramsTableModel.clear();
                lastSelectedRow = -1;
                textFieldStatus.setText("Analyzing...");
                progressBar.setIndeterminate(false);
                progressBar.setValue(0);
                progressBar.setStringPainted(true);
                engine = new CorrelatorEngine(callbacks, Paramalyzer.this, ignoreEmptyCheckBox.isSelected(), ignore.getText());
                engine.execute();
            }
        });

        parametersTable.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
            @Override
            public void valueChanged(ListSelectionEvent e) {
                updateParamInstanceList();

            }
        });

        clearButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                textFieldStatus.setText("");
                progressBar.setValue(0);
                paramsTableModel.clear();
                lastSelectedRow = -1;
                paramListModel.clear();
                textAreaRequest.setText("");
                textAreaResponse.setText("");
                analysisTextArea.setText("");
            }
        });

        listValues.setModel(paramListModel);

        listValues.addListSelectionListener(new ListSelectionListener() {
            @Override
            public void valueChanged(ListSelectionEvent e) {
                IHttpRequestResponse message = paramListModel.getMessageForIndex(listValues.getSelectedIndex());
                if (message != null) {
                    textAreaRequest.setText(callbacks.getHelpers().bytesToString(message.getRequest()));
                    displayedRequest = message;

                    ParamInstance pi = paramListModel.getParamInstance(listValues.getSelectedIndex());

                    if (message.getResponse() != null && message.getResponse().length > 0) {
                        textAreaResponse.setText(callbacks.getHelpers().bytesToString(message.getResponse()));
                    } else {
                        textAreaResponse.setText("");
                    }

                    analysisTextArea.setText(ParamAnalyzer.analyze(pi, callbacks));
                } else {
                    callbacks.printOutput("Message was null for: " + listValues.getSelectedIndex());
                    textAreaResponse.setText("");
                    textAreaRequest.setText("");
                    analysisTextArea.setText("");
                    displayedRequest = null;

                }
                analysisTextArea.setCaretPosition(0);
                textAreaRequest.setCaretPosition(0);
                textAreaResponse.setCaretPosition(0);

            }
        });
        textAreaRequest.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                super.mousePressed(e);
                popup(e);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                super.mouseReleased(e);
                popup(e);
            }

            private void popup(MouseEvent e) {
                if (e.isPopupTrigger() && displayedRequest != null) { //if the event shows the menu
                    JPopupMenu menu = new JPopupMenu();
                    menu.add(new AbstractAction() {
                        @Override
                        public Object getValue(String key) {
                            if (Action.NAME.equals(key)) {
                                return "Send to Repeater";
                            } else {
                                return super.getValue(key);
                            }
                        }

                        @Override
                        public void actionPerformed(ActionEvent e) {
                            IRequestInfo info = callbacks.getHelpers().analyzeRequest(displayedRequest);
                            URL url = info.getUrl();
                            callbacks.sendToRepeater(url.getHost(), url.getPort(), url.getProtocol().toLowerCase().endsWith("s"), displayedRequest.getRequest(), null);
                        }
                    });

                    menu.add(new HighlighterAction("red"));
                    menu.add(new HighlighterAction("orange"));

                    menu.show(textAreaRequest, e.getX(), e.getY());
                }
            }
        });
        listValues.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                super.mousePressed(e);
                popup(e);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                super.mouseReleased(e);
                popup(e);
            }

            private void popup(MouseEvent e) {
                if (e.isPopupTrigger() && paramListModel.getSize() > 0 ) { //if the event shows the menu
                    JPopupMenu menu = new JPopupMenu();
                    menu.add(new AbstractAction() {
                        @Override
                        public Object getValue(String key) {
                            if (Action.NAME.equals(key)) {
                                return "Copy List To Clipboard";
                            } else {
                                return super.getValue(key);
                            }
                        }

                        @Override
                        public void actionPerformed(ActionEvent e) {
                            StringBuilder buf = new StringBuilder();
                            for (int i=0;i<paramListModel.getSize();i++) {
                                buf.append(paramListModel.getElementAt(i));
                                buf.append("\n");
                            }
                            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                            StringSelection contents = new StringSelection(buf.toString());
                            clipboard.setContents(contents, Paramalyzer.this);
                        }
                    });


                    menu.show(listValues, e.getX(), e.getY());
                }
            }
        });


        showDuplicatesCheckBox.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                lastSelectedRow = -1;
                updateParamInstanceList();
            }
        });
        highlightValueButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                ParamInstance pi = paramListModel.getParamInstance(listValues.getSelectedIndex());
                if(pi!=null) {
                    Caret caret = textAreaRequest.getCaret();
                    caret.setSelectionVisible(true);
                    caret.setDot(pi.getValueStart());
                    caret.moveDot(pi.getValueEnd());
                }
            }
        });
        showDecodedValuesCheckBox.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                    updateParamInstanceList();
                    int row = parametersTable.getSelectedRow();
                    paramsTableModel.setShowDecodedValues(showDecodedValuesCheckBox.isSelected());
                    paramsTableModel.fireTableDataChanged();
                    parametersTable.setRowSelectionInterval(row, row);
            }
        });
    }

    private void updateParamInstanceList() {
        int selectedRow = parametersTable.getSelectedRow();
        if (selectedRow != -1) {
            selectedRow = parametersTable.convertRowIndexToModel(selectedRow);
        }
        if (selectedRow != lastSelectedRow) {
            lastSelectedRow = selectedRow;
            //DetailsWorker worker = new DetailsWorker(paramsTableModel.getParameter(selectedRow), Correlator.this);
            //worker.execute();
            CorrelatedParam selectedParam = paramsTableModel.getParameter(selectedRow);
            textAreaRequest.setText("");
            textAreaResponse.setText("");
            analysisTextArea.setText("");
            paramListModel.setValues(selectedParam, showDuplicatesCheckBox.isSelected(), showDecodedValuesCheckBox.isSelected());
            listValues.clearSelection();
        }
    }

    @Override
    public void setStatus(String statusText) {
        textFieldStatus.setText(statusText);
    }

    @Override
    public void setProgress(int percentDone) {
        progressBar.setValue(percentDone);
    }


    @Override
    public void done() {
        textFieldStatus.setText("Analysis complete.");
        progressBar.setValue(100);
        paramsTableModel.addParameters(engine.getUrlParameters());
        paramsTableModel.addParameters(engine.getBodyParameters());
        paramsTableModel.addParameters(engine.getCookieParameters());
    }


    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        callbacks.addSuiteTab(this);
        callbacks.setExtensionName(EXTENSION_NAME);
        callbacks.printOutput("Started " + EXTENSION_NAME + " version " + VERSION);
    }

    @Override
    public String getTabCaption() {
        return EXTENSION_NAME;
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }

    class HighlighterAction extends AbstractAction {
        String color;

        HighlighterAction(String color) {
            this.color = color;
        }

        @Override
        public Object getValue(String key) {
            if (Action.NAME.equals(key)) {
                return "Proxy Highlight " + color;
            } else {
                return super.getValue(key);
            }
        }

        @Override
        public void actionPerformed(ActionEvent e) {
            displayedRequest.setHighlight(color);
        }
    }

    @Override
    public void lostOwnership(Clipboard clipboard, Transferable contents) {

    }
}
