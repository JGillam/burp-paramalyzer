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

package com.professionallyevil.bc.tracker;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import com.professionallyevil.bc.ParamInstance;
import com.professionallyevil.bc.WorkerStatusListener;

import javax.swing.*;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ExecutionException;

public class ParamTrackerInitializer extends SwingWorker<Object,Object> {
    java.util.Set<TrackedParameter> params;
    IBurpExtenderCallbacks callbacks;
    WorkerStatusListener listener;

    public ParamTrackerInitializer(IBurpExtenderCallbacks callbacks, java.util.Set<TrackedParameter> params, WorkerStatusListener l) {
        this.params = params;
        this.callbacks = callbacks;
        this.listener = l;
    }

    @Override
    protected Object doInBackground() throws Exception {
        int progress = 0;
        this.publish(progress);
        this.publish("Initializing...");
        for(TrackedParameter param: params) {
            param.initialize(callbacks);
            progress+=1;
            this.publish(progress*100 / params.size());
        }

        this.publish("Finding edges...");
        for(TrackedParameter param: params) {
            for(Iterator<ParamInstance> i = param.paramInstanceIterator(); i.hasNext();) {
                ParamInstance pi = i.next();
                IHttpRequestResponse message = pi.getMessage();
                if (message.getResponse() != null){
                    String response = callbacks.getHelpers().bytesToString(message.getResponse());
                    for(TrackedParameter refParam: params) {
                        refParam.identifyPresence(response, param, pi);
                    }
                }
            }
        }
        this.publish("Initialization done.");

        return null;
    }

    @Override
    protected void process(List<Object> chunks) {
        super.process(chunks);
        for(Object chunk: chunks) {
            if (chunk instanceof Integer) {
                listener.setProgress((int)chunk);
            } else if (chunk instanceof String) {
                listener.setStatus((String)chunk);
            }
        }
    }

    @Override
    protected void done() {
        super.done();
        try {
            listener.done(get());
        } catch (InterruptedException e) {
            e.printStackTrace();
        } catch (ExecutionException e) {
            e.printStackTrace();
        }
    }
}
