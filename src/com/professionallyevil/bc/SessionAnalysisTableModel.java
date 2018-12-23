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
import burp.IHttpService;
import burp.IParameter;
import burp.IRequestInfo;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

public class SessionAnalysisTableModel extends AbstractTableModel {

    private byte[] baselineRequestBytes;
    IBurpExtenderCallbacks callbacks;
    private IHttpService service;
    private List<SessionTestCase> tests = new ArrayList<>();
    private String[] columns = {"Name", "Type", "Test?", "Response Code", "Size", "Time (ms)"};
    private Class[] columnClasses = {String.class, String.class, Boolean.class, String.class, Integer.class, Integer.class};
    private static byte[] SUPPORTED_PARAM_TYPES = {IParameter.PARAM_COOKIE};


    SessionAnalysisTableModel(IBurpExtenderCallbacks callbacks, IHttpService service, byte[] request){
        this.service = service;
        this.callbacks = callbacks;
        setBaselineRequest(request);
    }

    boolean isSupportedType(IParameter param){
        byte type = param.getType();
        for (byte supported:SUPPORTED_PARAM_TYPES) {
            if (supported == type) {
                return true;
            }
        }
        return false;
    }

    void setBaselineRequest(byte[] request){
        this.baselineRequestBytes = request;
        IRequestInfo requestInfo = this.callbacks.getHelpers().analyzeRequest(request);
        List<IParameter> params = requestInfo.getParameters();
        tests.clear();
        tests.add(new SessionTestCase());  // add null entry for baseline.
        for (IParameter param:params){
            if(isSupportedType(param)) {
                tests.add(new SessionTestCase(param));
            }
        }
        List<String> headers = requestInfo.getHeaders();
        for(String header:headers) {
            if (header.toLowerCase().startsWith("authorization:")) {
                tests.add(new SessionTestCase(header));
            }
        }

        fireTableDataChanged();
    }

    byte[] getBaselineRequest() {
        return baselineRequestBytes;
    }

    List<SessionTestCase> getSessionTestCases(){
        return tests;
    }

    IHttpService getService(){
        return service;
    }

    @Override
    public String getColumnName(int column) {
        return columns[column];
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return columnClasses[columnIndex];
    }

    @Override
    public int getRowCount() {
        return tests.size();
    }

    @Override
    public int getColumnCount() {
        return columns.length;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        SessionTestCase test = tests.get(rowIndex);
        switch(columnIndex) {
            case 0:
                return test.getName();
            case 1:
                return test.getType();
            case 2:
                return true;
            case 3:
                return test.getResponseCode();
            case 4:
                return test.getResponseSize();
            case 5:
                return test.getResponseTime();
            default:
                return "?";
        }
    }

    public SessionTestCase getSessionTestCase(int i) {
        return tests.get(i);
    }

}
