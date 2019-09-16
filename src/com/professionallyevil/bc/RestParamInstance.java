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

public class RestParamInstance extends ParamInstance {

    private String paramName;
    private String paramValue;
    private int nameStart;
    private int nameEnd = -1;
    private int valueStart;
    private int valueEnd = -1;
    static final byte TYPE = 32;

    public RestParamInstance(String name, String value, IHttpRequestResponse message) {
        super(null, message);
        this.paramName = name;
        this.paramValue = value;
        String requestString = new String(message.getRequest());
        nameStart = requestString.indexOf(name);
        if (nameStart > -1) {
            nameEnd = nameStart + name.length();
        }
        valueStart = requestString.indexOf(value);
        if (valueStart > -1) {
            valueEnd = valueStart + value.length();
        }
    }

    @Override
    public String getDecodedValue() {
        return super.getDecodedValue();
    }

    @Override
    public void setDecodedValue(String decodedValue) {
        super.setDecodedValue(decodedValue);
    }

    @Override
    public byte getType() {
        return TYPE;
    }

    @Override
    public String getName() {
        return this.paramName;
    }

    @Override
    public String getValue() {
        return this.paramValue;
    }

    @Override
    public int getNameStart() {
        return nameStart;
    }

    @Override
    public int getNameEnd() {
        return nameEnd;
    }

    @Override
    public int getValueStart() {
        return valueStart;
    }

    @Override
    public int getValueEnd() {
        return valueEnd;
    }

    @Override
    public IHttpRequestResponse getMessage() {
        return super.getMessage();
    }

    @Override
    public boolean equals(Object obj) {
        return super.equals(obj);
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }

    @Override
    public int compareTo(ParamInstance o) {
        return super.compareTo(o);
    }

    @Override
    public Format getFormat() {
        return super.getFormat();
    }

    @Override
    public void setFormat(Format f) {
        super.setFormat(f);
    }

    @Override
    public String describe() {
        return super.describe();
    }

    @Override
    public String summarize() {
        return super.summarize();
    }
}
