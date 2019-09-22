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

import burp.IHttpRequestResponse;

public class JSONParamInstance extends ParamInstance {

    private String paramName;
    private String paramValue;
    private ParamInstance parent;
    static final byte TYPE = 64;

    public JSONParamInstance(String name, String value, ParamInstance parent) {
        super(null, parent.getMessage());
        this.paramName = name;
        String[] parts = value.split("\n\r");
        this.paramValue = String.join(" ", parts);
        this.parent = parent;
    }

    @Override
    public byte getType() {
        return TYPE;
    }

    public ParamInstance getParent() {
        return parent;
    }

    @Override
    public String getName() {
        return paramName;
    }

    @Override
    public String getValue() {
        return paramValue;
    }

    @Override
    public int getNameStart() {
        return parent.getNameStart();
    }

    @Override
    public int getNameEnd() {
        return parent.getNameEnd();
    }

    @Override
    public int getValueStart() {
        return parent.getValueStart();
    }

    @Override
    public int getValueEnd() {
        return parent.getValueEnd();
    }

    @Override
    public IHttpRequestResponse getMessage() {
        return parent.getMessage();
    }

}
