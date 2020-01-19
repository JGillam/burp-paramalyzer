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
        MD5("MD5", true),
        SHA1("SHA-1", true),
        SHA224("SHA-224"),
        SHA256("SHA-256", true),
        SHA512("SHA-512"),
        BASE64BIN("B64 Bin"),
        URLPATH("URL/Path"),
        BIGIP("BigIP"),
        HEX("Hex String"),
        EMAIL("Email"),
        SSN("SSN", true),
        CREDITCARD("CC", true),
        HTMLFRAG("XML/HTML"),
        EMPTY("Empty"),
        JSON("JSON Object"),
        PHP("PHP Serialized", true),
        JWT("JWT", true);

        private String title;
        private boolean interesting = false;

        private Format(String title) {
            this.title = title;
        }

        private Format(String title, boolean interesting) { this.title = title; this.interesting = interesting; }

        public String getTitle(){
            return title;
        }

        public boolean isInteresting() {return interesting; }


        @Override
        public String toString() {
            return this.title;
        }
    }

    IParameter wrappedParam;
    IHttpRequestResponse message;
    int hashCode = 0;
    Format format = Format.UNKNOWN;
    int msgIndex;

    public String getDecodedValue() {
        return decodedValue==null?getValue():decodedValue;
    }

    public void setDecodedValue(String decodedValue) {
        this.decodedValue = decodedValue;
    }

    String decodedValue;


    public ParamInstance(IParameter param, IHttpRequestResponse message, int msgIndex) {
        this.wrappedParam = param;
        this.message = message;
        this.msgIndex = msgIndex;
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
//            return (this.getName() + ':' + this.getValue()).compareTo(o.getName() + ':' + o.getValue())==-1?-1:1;
            return this.getMessageIndex() > o.getMessageIndex() ? -1:1;
        }
    }

    public Format getFormat(){
        return format;
    }

    public void setFormat(Format f){
        format = f;
    }

    public String describe() {
        StringBuilder buf = new StringBuilder();
        buf.append("Name: ").append(getName());
        buf.append("\nType: ");
        appendType(buf);
        buf.append("\nValue: ").append(getValue());
        if(!getValue().equals(decodedValue)){
            buf.append("\nDecoded Value: ").append(getDecodedValue());
        }
        buf.append("\nFormat: ").append(getFormat().getTitle());
        return buf.toString();
    }

    public String summarize() {
        StringBuilder buf = new StringBuilder();
        buf.append(getName()).append(" (");
        appendType(buf);
        buf.append(")");
        return buf.toString();
    }

    public String getTypeName() {
        switch (getType()){
            case IParameter.PARAM_BODY:
                return "Body";
            case IParameter.PARAM_COOKIE:
                return "Cookie";
            case IParameter.PARAM_URL:
                return "URL";
            case IParameter.PARAM_JSON:
                return "JSON";
            case IParameter.PARAM_MULTIPART_ATTR:
                return "Multi";
            case IParameter.PARAM_XML:
                return "XML";
            case RestParamInstance.TYPE:
                return "REST";
            case JSONParamInstance.TYPE:
                return "JSON Part";
            default:
                return "Unknown";
        }
    }

    public int getMessageIndex() {
        return msgIndex;
    }

    private void appendType(StringBuilder buf) {
        buf.append(getTypeName());
    }


}
