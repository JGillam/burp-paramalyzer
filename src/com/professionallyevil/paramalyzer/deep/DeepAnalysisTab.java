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

package com.professionallyevil.paramalyzer.deep;

import burp.IBurpExtenderCallbacks;
import burp.IRequestInfo;
import com.intellij.uiDesigner.core.GridConstraints;
import com.intellij.uiDesigner.core.GridLayoutManager;
import com.intellij.uiDesigner.core.Spacer;
import com.professionallyevil.paramalyzer.*;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.net.URL;

/**
 * Created by jgillam on 4/18/2017.
 */

public class DeepAnalysisTab implements WorkerStatusListener {
    private JLabel titleLabel;
    private JList listMatches;
    private JTextArea textDetails;
    private JButton closeButton;
    private JPanel mainPanel;
    private ParamInstanceListModel listModel = new ParamInstanceListModel();

    private final Paramalyzer parent;
    private DeepAnalyzer analyzer;
    IBurpExtenderCallbacks callbacks;
    private String title;

    public DeepAnalysisTab(ParamInstance pi, Paramalyzer parent, IBurpExtenderCallbacks callbacks) {
        this.parent = parent;
        this.callbacks = callbacks;
        titleLabel.setText("Deep Analysis: [" + pi.getTypeName() + "] " + pi.getName() + " = " + pi.getDecodedValue() + "\n (Inferred Format: " + pi.getFormat() + ")");
        closeButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                DeepAnalysisTab.this.parent.tabPane.remove(mainPanel);

            }
        });

        listMatches.setModel(listModel);

        textDetails.setText("Processing...");
        analyzer = new DeepAnalyzer(pi, ((ParametersTableModel) parent.getParametersTableModel()).getEntries(), callbacks, this);
        listMatches.addListSelectionListener(new ListSelectionListener() {
            @Override
            public void valueChanged(ListSelectionEvent e) {
                ParamInstance pi = (ParamInstance) listModel.getParamInstanceAt(listMatches.getSelectedIndex());
                textDetails.setText(analyzer.getResultsMap().get(pi));
            }
        });

        PopupMouseListener pml = new PopupMouseListener();
        listMatches.addMouseListener(pml);
        textDetails.addMouseListener(pml);
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public void begin() {
        analyzer.execute();
    }

    public JPanel getMainPanel() {
        return mainPanel;
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
    public void done(Object result) {
        listMatches.setModel(listModel);

        callbacks.printOutput("Deep analysis complete.  Results: " + analyzer.getResultsMap().size());

        if (analyzer.getResultsMap().size() == 0) {
            textDetails.setText("Sorry, no matches found for this parameter.");
        } else {
            listModel.setListData(analyzer.getResultsMap().keySet());
            listMatches.setSelectedIndex(0);
        }
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
        mainPanel.setLayout(new GridLayoutManager(4, 1, new Insets(0, 0, 0, 0), -1, -1));
        final JPanel panel1 = new JPanel();
        panel1.setLayout(new GridLayoutManager(2, 2, new Insets(0, 0, 0, 0), -1, -1));
        mainPanel.add(panel1, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        titleLabel = new JLabel();
        titleLabel.setText("Deep Analysis:");
        panel1.add(titleLabel, new GridConstraints(0, 0, 2, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final Spacer spacer1 = new Spacer();
        panel1.add(spacer1, new GridConstraints(0, 1, 2, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        final JPanel panel2 = new JPanel();
        panel2.setLayout(new GridLayoutManager(1, 1, new Insets(0, 0, 0, 0), -1, -1));
        mainPanel.add(panel2, new GridConstraints(2, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JSplitPane splitPane1 = new JSplitPane();
        panel2.add(splitPane1, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, new Dimension(200, 200), null, 0, false));
        final JScrollPane scrollPane1 = new JScrollPane();
        splitPane1.setLeftComponent(scrollPane1);
        scrollPane1.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(), "Matches", TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, null, null));
        listMatches = new JList();
        listMatches.setSelectionMode(0);
        scrollPane1.setViewportView(listMatches);
        final JScrollPane scrollPane2 = new JScrollPane();
        splitPane1.setRightComponent(scrollPane2);
        scrollPane2.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(), "Details", TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, null, null));
        textDetails = new JTextArea();
        scrollPane2.setViewportView(textDetails);
        final Spacer spacer2 = new Spacer();
        mainPanel.add(spacer2, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_VERTICAL, 1, GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        final JPanel panel3 = new JPanel();
        panel3.setLayout(new GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), -1, -1));
        mainPanel.add(panel3, new GridConstraints(3, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        closeButton = new JButton();
        closeButton.setText("Close");
        closeButton.setToolTipText("Close this tab");
        panel3.add(closeButton, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, new Dimension(-1, 40), null, null, 0, false));
        final Spacer spacer3 = new Spacer();
        panel3.add(spacer3, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return mainPanel;
    }

    class PopupMouseListener extends MouseAdapter {

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
            if (e.isPopupTrigger() && listMatches.getModel().getSize() > 0) { //if the event shows the menu
                JPopupMenu menu = new JPopupMenu();

                menu.add(new AbstractAction() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        try {
                            Object selected = listMatches.getSelectedValue();
                            if (selected != null && selected instanceof ParamInstance) {
                                IRequestInfo info = callbacks.getHelpers().analyzeRequest(((ParamInstance) selected).getMessage());
                                URL url = info.getUrl();
                                callbacks.sendToRepeater(url.getHost(), url.getPort(), url.getProtocol().toLowerCase().endsWith("s"),
                                        ((ParamInstance) selected).getMessage().getRequest(), title + "." + listMatches.getSelectedIndex());
                            }

                        } catch (Throwable t) {
                            callbacks.printError(t.getMessage());
                        }
                    }

                    @Override
                    public Object getValue(String key) {
                        if (Action.NAME.equals(key)) {
                            return "Send to Repeater";
                        } else {
                            return super.getValue(key);
                        }
                    }
                });

                menu.show(e.getComponent(), e.getX(), e.getY());
            }
        }

    }

}
