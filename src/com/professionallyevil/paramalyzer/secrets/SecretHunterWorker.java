/*
 * Copyright (c) 2022 Jason Gillam
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
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import com.professionallyevil.paramalyzer.WorkerStatusListener;

import javax.swing.*;
import java.io.PrintStream;
import java.net.URL;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ExecutionException;

public class SecretHunterWorker extends SwingWorker<String, Object> {
    private IBurpExtenderCallbacks callbacks;
    private WorkerStatusListener listener;
    private SecretsTableModel tableModel;

    SecretHunterWorker(IBurpExtenderCallbacks callbacks, WorkerStatusListener l, SecretsTableModel tableModel) {
        this.callbacks = callbacks;
        this.listener = l;
        this.tableModel = tableModel;
    }

    @Override
    protected String doInBackground() throws Exception {
        listener.setProgress(0);
        List<Secret> secrets = tableModel.getSecretsList();
        List<String> processedValues = new ArrayList<>();

        IExtensionHelpers helpers = callbacks.getHelpers();
        for (Iterator<Secret> secretsIterator = secrets.listIterator(); secretsIterator.hasNext(); ) {
            Secret secret = secretsIterator.next();
            publish("Hunting "+secret.getName()+"...");
            List<SecretResult> results = new ArrayList<>();
            List<String> values = secret.getValues();
            callbacks.printOutput("Values length: "+values.size());
            List<String> newValues = new ArrayList<>();
            for (Iterator<String> valueIterator = values.iterator(); valueIterator.hasNext();) {
                String value = valueIterator.next();
                if (!processedValues.contains(value)) {
                    processedValues.add(value);
                    newValues.add(value);
                }
            }
            callbacks.printOutput("New values: " + newValues.size());
            if (newValues.size() > 0) {
                IHttpRequestResponse[] messages = callbacks.getProxyHistory();
                callbacks.printOutput("Retrieved messages: "+ messages.length);
                for (int j = 0; j < messages.length; j++) {
                    publish(100 * j / messages.length);
                    IRequestInfo requestInfo = helpers.analyzeRequest(messages[j]);
                    URL url = requestInfo.getUrl();
                    boolean isInScope = callbacks.isInScope(url);

                    for (Iterator<String> valueIterator = newValues.iterator(); valueIterator.hasNext(); ) {
                        String value = valueIterator.next();

                        if (!isInScope) {
                            String request = helpers.bytesToString(messages[j].getRequest());
                            int index = request.indexOf(value);
                            if (index > -1) {
                                results.add(new SecretResult(value, "secret in out of scope request", "High"));
                            }
                        } else {
                            int urlIndex = url.toString().indexOf(value);
                            if (urlIndex > -1) {
                                results.add(new SecretResult(value, "secret in URL", "Medium"));
                            }
                        }
                    }
                }
            }
            secret.setResults(results);
            tableModel.updateSecret(secret);
        }
        publish("Done.");

        return "";
    }

    @Override
    protected void process(List<Object> chunks) {

        super.process(chunks);
        String lastMessage = null;
        int lastPercent = -1;

        for (Object chunk : chunks) {
            if (chunk instanceof String) {
                lastMessage = (String) chunk;
            } else if (chunk instanceof Integer) {
                lastPercent = (Integer) chunk;
            }
        }

        if (lastMessage != null) {
            listener.setStatus(lastMessage);
        }
        if (lastPercent > -1) {
            listener.setProgress(lastPercent);
        }

    }

    @Override
    protected void done() {
        super.done();
        try {
            this.get();
            listener.done(null);
        } catch (InterruptedException e) {
            listener.setStatus("Interrupted Exception: " + e.getMessage());
            e.printStackTrace(new PrintStream(callbacks.getStderr()));
        } catch (ExecutionException e) {
            listener.setStatus("Execution Exception: " + e.getMessage());
            e.printStackTrace(new PrintStream(callbacks.getStderr()));
        } catch (Throwable e) {
            listener.setStatus(e.getMessage());
            e.printStackTrace(new PrintStream(callbacks.getStderr()));
        }
    }
}
