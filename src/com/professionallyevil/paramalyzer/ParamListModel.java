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

import burp.IHttpRequestResponse;

import javax.swing.*;

public class ParamListModel extends AbstractListModel<String> {
    ParamInstance[] params = new ParamInstance[0];
    CorrelatedParam correlatedParam;
    boolean showDecoded = true;
    boolean showFormat = false;

    ParamListModel() {

    }

    public void setValues(CorrelatedParam param, boolean withDuplicateValues, boolean showDecodedValues) {
        int originalLength = params.length;
        this.correlatedParam = param;
        this.showDecoded = showDecodedValues;
        this.params = correlatedParam.getParamInstances(withDuplicateValues).toArray(new ParamInstance[correlatedParam.getParamInstances(withDuplicateValues).size()]);
        fireContentsChanged(this, 0, Math.max(params.length, originalLength));
    }


    @Override
    public int getSize() {
        return params.length;
    }

    @Override
    public String getElementAt(int index) {
        ParamInstance param = params[index];
        String prefix = "";

        if (showFormat) {
            prefix = "["+param.getFormat()+"]: ";
        }

        if (showDecoded) {
            return prefix + param.getDecodedValue();
        } else {
            return prefix + param.getValue();
        }
    }

    public IHttpRequestResponse getMessageForIndex(int i) {
        return params[i].getMessage();
    }

    public ParamInstance getParamInstance(int i) {
        return params[i];
    }

    public void clear() {
        int originalLength = params.length;
        params = new ParamInstance[0];
        fireIntervalRemoved(this, 0, originalLength);

    }
}
