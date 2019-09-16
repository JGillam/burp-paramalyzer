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

package com.professionallyevil.bc;

import burp.IBurpExtenderCallbacks;

import javax.swing.*;
import java.util.Set;

public class ParamInstanceListModel extends AbstractListModel<String> {

    private ParamInstance[] paramInstanceList = new ParamInstance[0];

    void setListData(Set<ParamInstance> params){
        int originalLength = paramInstanceList.length;
        ParamInstance[] newInstanceList = new ParamInstance[params.size()];
        paramInstanceList = params.toArray(newInstanceList);
        fireContentsChanged(this, 0, Math.max(paramInstanceList.length, originalLength));
    }

    @Override
    public int getSize() {
        return paramInstanceList.length;
    }

    @Override
    public String getElementAt(int index) {
        return "[" + paramInstanceList[index].getTypeName() +"] " + paramInstanceList[index].getName();
    }

    ParamInstance getParamInstanceAt(int index) {
        return paramInstanceList[index];
    }
}
