/*
 * Copyright (c) 2018 Jason Gillam
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

import burp.IBurpExtenderCallbacks;
import burp.IHttpService;
import com.intellij.uiDesigner.core.GridConstraints;
import com.intellij.uiDesigner.core.GridLayoutManager;
import com.intellij.uiDesigner.core.Spacer;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;

public class SessionAnalysisTab implements WorkerStatusListener {

    private JPanel sessionTabPanel;
    private JPanel messageEditorPanel;
    private JCheckBox checkboxFollowRedirects;
    private JButton buttonVerifyBaseline;
    private JTextArea textAreaBaselineRequest;
    private JTextArea textAreaBaselineResponse;
    private JTable resultsTable;
    private JButton analyzeButton;
    private JSplitPane horizontalSplitPane;
    private IHttpService service;
    private byte[] requestBytes;
    private Paramalyzer parent;
    private IBurpExtenderCallbacks callbacks;
    private SessionAnalysisTableModel sessionTableModel;


    SessionAnalysisTab(Paramalyzer parent, IBurpExtenderCallbacks callbacks, byte[] request, IHttpService service) {
        this.parent = parent;
        this.callbacks = callbacks;
        if (this.service == null) {
            this.service = service;
            this.requestBytes = request;
            if (textAreaBaselineRequest == null) {
                callbacks.printError("The textAreaBaselineRequest is null");
            } else if (request == null) {
                callbacks.printError("The request bytes object is null");
            } else {
                textAreaBaselineRequest.setText(new String(this.requestBytes));
            }
        }
        sessionTableModel = new SessionAnalysisTableModel(callbacks, service, request);
        resultsTable.setModel(sessionTableModel);
        buttonVerifyBaseline.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                RequestFetcher fetcher = new RequestFetcher(callbacks, request, service, SessionAnalysisTab.this, textAreaBaselineResponse);
                fetcher.execute();
            }
        });
        analyzeButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                SessionAnalyzer analyzer = new SessionAnalyzer(sessionTableModel, callbacks, SessionAnalysisTab.this);
                analyzer.execute();
            }
        });
        resultsTable.addMouseListener(new MouseAdapter() {
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
                if (e.isPopupTrigger()) {
                    int selectedRow = resultsTable.getSelectedRow();
                    if (selectedRow > -1) {
                        SessionTestCase testCase = sessionTableModel.getSessionTestCase(selectedRow);

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
                                callbacks.sendToRepeater(service.getHost(), service.getPort(), "https".equals(service.getProtocol()), testCase.getTestRequest(), testCase.getName());
                                //IRequestInfo info = callbacks.getHelpers().analyzeRequest(displayedRequest);
                                //URL url = info.getUrl();
                                //callbacks.sendToRepeater(url.getHost(), url.getPort(), url.getProtocol().toLowerCase().endsWith("s"), displayedRequest.getRequest(), null);
                            }
                        });

                        menu.show(resultsTable, e.getX(), e.getY());
                    }
                }
            }
        });
    }

    void initializeTab() {
        horizontalSplitPane.setDividerLocation(0.35);
    }


    JPanel getSessionTabPanel() {
        return sessionTabPanel;
    }


    @Override
    public void setStatus(String statusText) {
        parent.setStatus(statusText);

    }

    @Override
    public void setProgress(int percentDone) {
        parent.setProgress(percentDone);
    }

    @Override
    public void done() {
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
        sessionTabPanel = new JPanel();
        sessionTabPanel.setLayout(new GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), -1, -1));
        horizontalSplitPane = new JSplitPane();
        horizontalSplitPane.setDividerLocation(150);
        horizontalSplitPane.setFocusCycleRoot(true);
        horizontalSplitPane.setResizeWeight(0.3);
        sessionTabPanel.add(horizontalSplitPane, new GridConstraints(0, 0, 1, 2, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, new Dimension(200, 200), null, 0, false));
        final JPanel panel1 = new JPanel();
        panel1.setLayout(new GridLayoutManager(2, 1, new Insets(0, 0, 0, 0), -1, -1));
        horizontalSplitPane.setLeftComponent(panel1);
        panel1.setBorder(BorderFactory.createTitledBorder("Baseline Verification"));
        messageEditorPanel = new JPanel();
        messageEditorPanel.setLayout(new GridLayoutManager(1, 1, new Insets(0, 0, 0, 0), -1, -1));
        panel1.add(messageEditorPanel, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JScrollPane scrollPane1 = new JScrollPane();
        messageEditorPanel.add(scrollPane1, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        scrollPane1.setBorder(BorderFactory.createTitledBorder("Request"));
        textAreaBaselineRequest = new JTextArea();
        textAreaBaselineRequest.setEditable(false);
        scrollPane1.setViewportView(textAreaBaselineRequest);
        final JPanel panel2 = new JPanel();
        panel2.setLayout(new GridLayoutManager(3, 2, new Insets(0, 0, 0, 0), -1, -1));
        panel1.add(panel2, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JPanel panel3 = new JPanel();
        panel3.setLayout(new GridLayoutManager(2, 2, new Insets(0, 0, 0, 0), -1, -1));
        panel2.add(panel3, new GridConstraints(0, 0, 2, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        checkboxFollowRedirects = new JCheckBox();
        checkboxFollowRedirects.setSelected(true);
        checkboxFollowRedirects.setText("Follow Redirects");
        checkboxFollowRedirects.setVisible(false);
        panel3.add(checkboxFollowRedirects, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        buttonVerifyBaseline = new JButton();
        buttonVerifyBaseline.setText("Verify Baseline");
        panel3.add(buttonVerifyBaseline, new GridConstraints(1, 0, 1, 2, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final Spacer spacer1 = new Spacer();
        panel2.add(spacer1, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        final JScrollPane scrollPane2 = new JScrollPane();
        panel2.add(scrollPane2, new GridConstraints(2, 0, 1, 2, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        scrollPane2.setBorder(BorderFactory.createTitledBorder("Response"));
        textAreaBaselineResponse = new JTextArea();
        scrollPane2.setViewportView(textAreaBaselineResponse);
        final JPanel panel4 = new JPanel();
        panel4.setLayout(new GridLayoutManager(2, 1, new Insets(0, 0, 0, 0), -1, -1));
        horizontalSplitPane.setRightComponent(panel4);
        panel4.setBorder(BorderFactory.createTitledBorder("Results Table"));
        final JPanel panel5 = new JPanel();
        panel5.setLayout(new GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), -1, -1));
        panel4.add(panel5, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final Spacer spacer2 = new Spacer();
        panel5.add(spacer2, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        analyzeButton = new JButton();
        analyzeButton.setText("Analyze");
        panel5.add(analyzeButton, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JScrollPane scrollPane3 = new JScrollPane();
        panel4.add(scrollPane3, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        resultsTable = new JTable();
        resultsTable.setAutoCreateRowSorter(true);
        resultsTable.setFillsViewportHeight(true);
        scrollPane3.setViewportView(resultsTable);
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return sessionTabPanel;
    }
}
