/*
 * Copyright (c) 2015 Jason Gillam
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
import burp.IParameter;

/**
 * Wrapper for IParam  so it can be used as a key in a Set properly
 **/
public class ParamInstance implements IParameter, Comparable<ParamInstance> {
    enum Format {
        UNKNOWN("Unknown"),
        NUMERIC("Numeric"),
        TEXT("Word"),
        PRINTABLE("Printable"),
        MD5("MD5"),
        SHA1("SHA-1"),
        SHA224("SHA-224"),
        SHA256("SHA-256"),
        SHA512("SHA-512"),
        BASE64BIN("B64 Bin"),
        URLPATH("URL/Path"),
        BIGIP("BigIP"),
        HEX("Hex String"),
        EMAIL("Email"),
        SSN("SSN"),
        CREDITCARD("CC"),
        HTMLFRAG("XML/HTML"),
        EMPTY("Empty"),
        JSON("JSON Object");

        private String title;

        private Format(String title) {
            this.title = title;
        }

        public String getTitle(){
            return title;
        }
    }

    IParameter wrappedParam;
    IHttpRequestResponse message;
    int hashCode = 0;
    Format format = Format.UNKNOWN;

    public String getDecodedValue() {
        return decodedValue;
    }

    public void setDecodedValue(String decodedValue) {
        this.decodedValue = decodedValue;
    }

    String decodedValue;


    public ParamInstance(IParameter param, IHttpRequestResponse message) {
        this.wrappedParam = param;
        this.message = message;
    }


    @Override
    public byte getType() {
        return wrappedParam.getType();
    }

    @Override
    public String getName() {
        return wrappedParam.getName();
    }

    @Override
    public String getValue() {
        String value = wrappedParam.getValue();
        return value.isEmpty()?"[EMPTY]":value;
    }

    @Override
    public int getNameStart() {
        return wrappedParam.getNameStart();
    }

    @Override
    public int getNameEnd() {
        return wrappedParam.getNameEnd();
    }

    @Override
    public int getValueStart() {
        return wrappedParam.getValueStart();
    }

    @Override
    public int getValueEnd() {
        return wrappedParam.getValueEnd();
    }

    public IHttpRequestResponse getMessage() {
        return message;
    }

    @Override
    public boolean equals(Object obj) {
        return obj instanceof ParamInstance &&
                this.message.equals(((ParamInstance) obj).getMessage()) &&
                this.getType() == ((ParamInstance) obj).getType() &&
                this.getName().equals(((ParamInstance) obj).getName()) &&
                this.getValue().equals(((ParamInstance) obj).getValue()) &&
                this.getValueStart() == ((ParamInstance) obj).getValueStart() &&
                this.getValueEnd() == ((ParamInstance) obj).getValueEnd() &&
                this.getNameStart() == ((ParamInstance) obj).getNameStart() &&
                this.getNameEnd() == ((ParamInstance) obj).getNameEnd();
    }

    @Override
    public int hashCode() {
        StringBuilder buf = new StringBuilder();
        if (this.hashCode == 0) {
            buf.append(ParamInstance.class)
                    .append(':')
                    .append(getMessage().toString())
                    .append(':')
                    .append(getType())
                    .append(':')
                    .append(getName())
                    .append(':')
                    .append(getValue())
                    .append(':')
                    .append(getValueStart())
                    .append(':')
                    .append(getValueEnd())
                    .append(':')
                    .append(getNameStart())
                    .append(':')
                    .append(getNameEnd());
            this.hashCode = buf.hashCode();
        }
        return hashCode;
    }


    @Override
    public int compareTo(ParamInstance o) {
        if(this.hashCode() == o.hashCode()) {
            return 0;
        } else {
            return (this.getName() + ':' + this.getValue()).compareTo(o.getName() + ':' + o.getValue())==-1?-1:1;
        }
    }

    public Format getFormat(){
        return format;
    }

    public void setFormat(Format f){
        format = f;
    }
}
