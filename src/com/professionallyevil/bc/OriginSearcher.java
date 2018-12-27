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
import burp.ICookie;
import burp.IHttpRequestResponse;
import burp.IParameter;

import javax.swing.*;
import java.util.List;
import java.util.concurrent.ExecutionException;

public class OriginSearcher extends SwingWorker<IHttpRequestResponse, Object> {

    IParameter param;
    WorkerStatusListener statusListener;
    IBurpExtenderCallbacks callbacks;

    OriginSearcher(IParameter param, IBurpExtenderCallbacks callbacks, WorkerStatusListener listener){
        this.param = param;
        this.statusListener = listener;
        this.callbacks = callbacks;
    }

    @Override
    protected IHttpRequestResponse doInBackground() throws Exception {
        publish(0);
        String cookieName = param.getName();
        publish("Looking for "+cookieName+"...");
        IHttpRequestResponse[] messages = callbacks.getProxyHistory();
        for (int i = 0; i < messages.length; i++) {
            publish(100 * i / messages.length);
            if(messages[i].getResponse() != null && messages[i].getResponse().length > 0) {
                List<ICookie> cookies = callbacks.getHelpers().analyzeResponse(messages[i].getResponse()).getCookies();
                for(ICookie cookie: cookies) {
                    if (cookie.getName().equals(cookieName) && cookie.getValue().equals(param.getValue())) {
                        return messages[i];
                    }
                }
            }

        }

        publish(100);
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
            statusListener.setStatus(lastMessage);
        }
        if (lastPercent > -1) {
            statusListener.setProgress(lastPercent);
        }
    }

    @Override
    protected void done() {
        try {
            IHttpRequestResponse origin = this.get();
            statusListener.setProgress(100);
            if (origin == null) {
                statusListener.setStatus("Done: could not find origin.");
            } else {
                statusListener.setStatus("Done: found origin response.");
                statusListener.done(origin);
            }
        } catch (InterruptedException e) {
            e.printStackTrace();
        } catch (ExecutionException e) {
            e.printStackTrace();
        }

    }
}
