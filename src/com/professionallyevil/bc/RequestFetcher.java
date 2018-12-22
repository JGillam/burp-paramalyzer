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
import burp.IHttpRequestResponse;
import burp.IHttpService;

import javax.swing.*;

public class RequestFetcher extends SwingWorker {
    WorkerStatusListener statusListener;
    IHttpService service;
    byte[] requestBytes;
    JTextArea responseBox;
    IBurpExtenderCallbacks callbacks;

    RequestFetcher(IBurpExtenderCallbacks callbacks, byte[] requestBytes, IHttpService service, WorkerStatusListener l, JTextArea responseBox) {
        this.requestBytes = requestBytes;
        this.service = service;
        this.statusListener = l;
        this.responseBox = responseBox;
        this.callbacks = callbacks;
    }

    @Override
    protected Object doInBackground() throws Exception {
        statusListener.setProgress(0);
        statusListener.setStatus("Making request...");
        IHttpRequestResponse message = callbacks.makeHttpRequest(service, requestBytes);
        byte[] responseBytes = message.getResponse();
        if (responseBytes != null) {
            statusListener.setStatus("Done.");
            responseBox.setText(new String(responseBytes));
        }else {
            statusListener.setStatus("Request failed to complete.");
        }
        statusListener.done();
        return null;
    }

}
