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

import javax.swing.*;
import java.util.List;

public class ParamTrackerInitializer extends SwingWorker<Object,Object> {
    JLabel label;
    JProgressBar progressBar;
    java.util.Set<TrackedParameter> params;
    IBurpExtenderCallbacks callbacks;

    public ParamTrackerInitializer(JLabel label, JProgressBar bar, IBurpExtenderCallbacks callbacks, java.util.Set<TrackedParameter> params) {
        this.label = label;
        this.progressBar = bar;
        this.params = params;
        this.callbacks = callbacks;
    }


    @Override
    protected Object doInBackground() throws Exception {
        progressBar.setMaximum(params.size());
        int progress = 0;
        this.publish(progress);
        for(TrackedParameter param: params) {
            this.publish("Initializing "+param.toString()+"...");
            param.initialize(callbacks);
            progress++;
            this.publish(progress);
        }

        return null;
    }

    @Override
    protected void process(List<Object> chunks) {
        for(Object chunk: chunks) {
            if(chunk instanceof Integer && progressBar != null) {
                progressBar.setValue((int)chunk);
            } else if (chunk instanceof String && label != null) {
                label.setText((String)chunk);
            }
        }
    }

    @Override
    protected void done() {
        super.done();
    }
}
