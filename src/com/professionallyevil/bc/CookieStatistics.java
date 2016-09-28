package com.professionallyevil.bc;

public class CookieStatistics {
    private String name;
    private int count = 0;
    private int httpOnlyCount = 0;
    private int secureCount = 0;

    public CookieStatistics(String name) {
        this.name = name;
    }

    void addCookieValues(boolean httpOnly, boolean secure) {
        count+=1;
        if(httpOnly) {
            httpOnlyCount += 1;
        }
        if(secure) {
            secureCount += 1;
        }
    }

    public String getName(){
        return this.name;
    }

    public String getHttpOnly() {
        return httpOnlyCount==count?"Always":(httpOnlyCount==0?"Never":""+httpOnlyCount+"/"+"count");
    }

    public String getSecure() {
        return secureCount==count?"Always":(secureCount==0?"Never":""+secureCount+"/"+"count");
    }


}
