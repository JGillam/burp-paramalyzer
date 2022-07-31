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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.ExecutionException;

public class SecretHunterWorker extends SwingWorker<String, Object> {
    private IBurpExtenderCallbacks callbacks;
    private WorkerStatusListener listener;
    private SecretsTableModel tableModel;

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    SecretHunterWorker(IBurpExtenderCallbacks callbacks, WorkerStatusListener l, SecretsTableModel tableModel) {
        this.callbacks = callbacks;
        this.listener = l;
        this.tableModel = tableModel;
    }

    @Override
    protected String doInBackground() throws Exception {
        listener.setProgress(0);
        List<Secret> secrets = tableModel.getSecretsList();
        Set<String> processedValues = new HashSet<>();
        processedValues.add("");  // skip empty strings

        IExtensionHelpers helpers = callbacks.getHelpers();
        for (Iterator<Secret> secretsIterator = secrets.listIterator(); secretsIterator.hasNext(); ) {
            Secret secret = secretsIterator.next();
            publish("Hunting "+secret.getName()+"...");
            List<SecretResult> results = new ArrayList<>();
            List<String> newValues = generateSearchValues(processedValues, secret);
            if (newValues.size() > 0) {
                IHttpRequestResponse[] messages = callbacks.getProxyHistory();
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
                                results.add(new SecretResult(value, "Secret in out-of-scope request", "High", messages[j],url.getHost(), index));
                            }
                        } else {
                            int urlIndex = url.toString().indexOf(value);
                            if (urlIndex > -1) {
                                results.add(new SecretResult(value, "Secret in URL", "Medium", messages[j], url.getHost(), urlIndex));
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

    private List<String> generateSearchValues(Set<String> processedValues, Secret secret) {
        List<String> values = secret.getValues(20, true);

        if (secret.huntHashedValues()) {
            Set<String> hashedValues = new HashSet<>();

            for (Iterator<String> valueIterator = values.iterator(); valueIterator.hasNext(); ) {
                String nextValue = valueIterator.next();


                for (String algorithm : Arrays.asList("MD5", "SHA1", "SHA256")) {
                    try {
                        String hashedValue = generateHashedValue(nextValue, algorithm);
                        hashedValues.add(hashedValue);
                        hashedValues.add(hashedValue.toLowerCase());
                    } catch (NoSuchAlgorithmException e) {
                        throw new RuntimeException(e);
                    }
                }
            }

            values.addAll(hashedValues);
        }

        values.removeAll(processedValues);
        processedValues.addAll(values);
        return values;
    }

    private String generateHashedValue(String value, String algorithm) throws NoSuchAlgorithmException{
        MessageDigest md = MessageDigest.getInstance(algorithm);
        md.reset();
        byte[] digest = md.digest(value.getBytes());
        String hexDigest = bytesToHex(digest);
        return hexDigest;
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
