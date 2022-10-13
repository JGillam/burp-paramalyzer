/*
 * Copyright (c) 2019 Jason Gillam
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

package com.professionallyevil.paramalyzer;

import burp.*;

import javax.swing.*;
import java.awt.*;

public class PopupRequestResponseDialog implements IMessageEditorController {

    IHttpRequestResponse requestResponse;
    IMessageEditor requestEditor;
    IMessageEditor responseEditor;

    public PopupRequestResponseDialog(IHttpRequestResponse requestResponse, IBurpExtenderCallbacks callbacks, Container parent, String title) {
        this.requestResponse = requestResponse;
        Frame parentFrame = JOptionPane.getFrameForComponent(parent);
        JDialog dialog = new JDialog(parentFrame, title);
        requestEditor = callbacks.createMessageEditor(this, false);
        requestEditor.setMessage(requestResponse.getRequest(), true);

        responseEditor = callbacks.createMessageEditor(this, false);
        responseEditor.setMessage(requestResponse.getResponse(), false);

        JTabbedPane tabs = new JTabbedPane();
        tabs.add("Request", requestEditor.getComponent());
        tabs.add("Response", responseEditor.getComponent());

        dialog.getContentPane().add(tabs);
        dialog.setSize(Math.min(800,parentFrame.getWidth()/2),Math.min(600, parentFrame.getHeight()/2));
        //dialog.setLocationRelativeTo(parentFrame);
        dialog.setLocation(parentFrame.getWidth()/2 - dialog.getWidth()/2 + parentFrame.getX(), parentFrame.getHeight()/2 - dialog.getHeight()/2 + parentFrame.getY());
        dialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
        dialog.setVisible(true);
    }


    @Override
    public IHttpService getHttpService() {
        return requestResponse.getHttpService();
    }

    @Override
    public byte[] getRequest() {
        return requestResponse.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return requestResponse.getResponse();
    }
}
