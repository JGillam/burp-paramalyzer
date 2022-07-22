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

package com.professionallyevil.paramalyzer.sessions;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IResponseInfo;
import com.professionallyevil.paramalyzer.WorkerStatusListener;

import javax.swing.*;
import javax.swing.event.TableModelEvent;
import java.util.List;

public class SessionAnalyzer extends SwingWorker {

    private final IBurpExtenderCallbacks callbacks;
    private final SessionAnalysisTableModel model;
    private final WorkerStatusListener l;

    SessionAnalyzer(SessionAnalysisTableModel model, IBurpExtenderCallbacks callbacks, WorkerStatusListener l) {
        this.model = model;
        this.callbacks = callbacks;
        this.l = l;
    }

    @Override
    protected Object doInBackground() throws Exception {
        byte[] baselineRequest = model.getBaselineRequest();

        List<SessionTestCase> testCases = model.getSessionTestCases();
        int row = 0;
        publish(0);
        for(SessionTestCase testCase:testCases){
            byte[] testRequest = testCase.generateTestRequest(baselineRequest, callbacks);
            publish("Testcase "+testCase.getName());
            long startTime = System.currentTimeMillis();
            IHttpRequestResponse message = callbacks.makeHttpRequest(model.getService(), testRequest);
            testCase.setResponseTime((int) (System.currentTimeMillis() - startTime));
            IResponseInfo responseInfo = callbacks.getHelpers().analyzeResponse(message.getResponse());
            testCase.analyzeResults(responseInfo, message.getResponse());
            TableModelEvent ev = new TableModelEvent(model, row);
            model.fireTableChanged(ev);
            row = row + 1;
            publish(100 * row / testCases.size());
        }
        publish("Done");

        return null;
    }

    @Override
    protected void process(List chunks) {
        super.process(chunks);
        String lastMessage = null;
        int lastPercent = -1;

        for (Object chunk : chunks) {
            if (chunk instanceof String) {
                lastMessage = (String) chunk;
                callbacks.printOutput(lastMessage);
            } else if (chunk instanceof Integer) {
                lastPercent = (Integer) chunk;
            }
        }

        if (lastMessage != null) {
            l.setStatus(lastMessage);
        }
        if (lastPercent > -1) {
            l.setProgress(lastPercent);
        }
    }
}
