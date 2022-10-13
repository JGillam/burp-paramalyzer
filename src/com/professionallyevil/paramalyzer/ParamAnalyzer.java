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

import burp.IBurpExtenderCallbacks;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

/**
 * This class contains the analysis logic that identifies formats and decodes values.
 */
public class ParamAnalyzer {

    enum ValuePattern {
        URL_ENCODED("%[0-9a-zA-Z]{2}"),
        BASE64_ENCODED("^(?:[A-Za-z0-9+/]{4}(==)?)*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"),
        BASE62_ENCODED("^[A-Za-z0-9]{1,11}$"),
        PRINTABLE_CHARS("^\\p{Print}+$"),
        TEXT("^([\\w']+ ){1,15}[\\w']+[\\.?!]?$"),
        HEX_STRING("^([A-F0-9]{2}){2,}$", Pattern.CASE_INSENSITIVE),
        DECIMAL("^[-]?[0-9]+$"),
        BIG_IP("\"^[0-9]{4,}\\.[0-9]{4,}\\.[0-9]{4,}$\""),
        URL_PATH("^(/([\\p{Alnum}!$&'()*+,-.:;<=>?@_]|%[0-9]{2})+)+/?$"),
        URL_PATH2("^http[s]?://[a-zA-Z0-9]+"),
        EMAIL_ADDRESS("^[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,4}$", Pattern.CASE_INSENSITIVE),
        SSN("^[0-9]{3}-?[0-9]{2}-?[0-9]{4}$"),
        CREDIT_CARD_QUICK("^[0-9 -]{14,20}$", "DECIMAL", "HEX_STRING", "PRINTABLE_CHARS", "BASE64_ENCODED", "TEXT"),
        CREDIT_CARD("^[0-9]{14,16}$", "DECIMAL", "HEX_STRING", "PRINTABLE_CHARS", "BASE64_ENCODED", "CREDIT_CARD_QUICK"),
        HTML_FRAGMENT("</[a-z]+>"),
        JSON_VALUE_QUICK("^(\\s*((\\d+)|(\"[\\w ]*\")|true|false|null|\\[.*\\]|\\{.*\\})\\s*)$", "PRINTABLE_CHARS"),
        JSON_OBJECT(JSONParamParser.JSONValue.OBJECT.getRegex(), "PRINTABLE_CHARS", "JSON_VALUE_QUICK"),
        PHP_SERIALIZED_QUICK("^([si]:\\d+:\\w+?;)(N;)|[oa]:\\d+:.*\\{.*}$"),
        PHP_SERIALIZED("^((s:\\d+:\".*\";)|(i:\\d+;)|(N;)|(a:\\d+:\\{((s:\\d+:\".*?\";)|(i:\\d+;)|(N;)|(o:\\d+:\"[a-z0-9_]+\":\\d+:\\{((s:\\d+:\".*?\";)|(i:\\d+;)|(N;))*}))*})|(o:\\d+:\"[a-z0-9_]+\":\\d+:\\{((s:\\d+:\".*?\";)|(i:\\d+;)|(N;))*}))$"),
        JWT("^ey[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.?[A-Za-z0-9-_.+/=]*$", "PRINTABLE_CHARS");


        private Pattern pattern;
        private List<String> dependencies;

        private ValuePattern(String regex, String ...dependency) {
            this.pattern = Pattern.compile(regex);
            this.dependencies = Arrays.asList(dependency);
        }

        private ValuePattern(String regex, int flags, String ...dependency){
            this.pattern = Pattern.compile(regex, flags);
            this.dependencies = Arrays.asList(dependency);
        }

        public boolean matches(String input){
            return pattern.matcher(input).find();
        }

        public Pattern getPattern() {
            return pattern;
        }

        public boolean isDependency(String patternName) {
            return dependencies.contains(patternName);
        }

    }


    private static Base62 base62 = new Base62();

    public static boolean isBase62Encoded(String testValue) {
        return ValuePattern.BASE62_ENCODED.matches(testValue);
    }

    static String analyze(ParamInstance pi, IBurpExtenderCallbacks callbacks) {
        return analyze(pi, callbacks, "");
    }

    static String analyze(ParamInstance pi, IBurpExtenderCallbacks callbacks, String logPrefix) {
        try {
            String value = pi.getValue();
            if (value.isEmpty() || "[EMPTY]".equals(value)) {
                pi.setFormat(ParamInstance.Format.EMPTY);
                return "An empty string.";
            } else if (value.trim().isEmpty()) {
                return "A string of " + value.length() + " whitespace characters.";
            } else if (pi.getName().toLowerCase().contains("bigip") && ValuePattern.BIG_IP.matches(value)) {
                return "Appears to be a BigIP value: " + value + "\nDecodes to: " + decodeBigIP(pi, value);
            }

            StringBuilder smartDecodeLog = new StringBuilder(logPrefix);
            String currentValue = value;
            String lastValue = "";
            while (!lastValue.equals(currentValue)) {
                lastValue = currentValue;
                currentValue = smartDecode(pi, currentValue, callbacks, smartDecodeLog);
            }


            StringBuilder text = new StringBuilder();
            if (!currentValue.equals(value)) {
                text.append("Decoded value:\n");
                text.append(currentValue);
                text.append("\n\nDecoding sequence:\nStarting value: ");
                text.append(value);
                text.append(smartDecodeLog.toString());
                text.append("\n");
                pi.setDecodedValue(currentValue);
                text.append(identify(pi, currentValue));

            } else {
                text.append("Value: ");
                text.append(currentValue);
                text.append("\n");
                text.append(identify(pi, currentValue));
            }
            pi.setDecodedValue(currentValue);
            return text.toString();
        } catch(Throwable t) {
            callbacks.printError(t.getMessage());
            return "";
        }
    }

    private static String smartDecode(ParamInstance pi, String input, IBurpExtenderCallbacks callbacks, StringBuilder log) {
        if(input.length() > 2 && input.startsWith("\"") && input.endsWith("\"")) {
            String output = input.substring(1, input.length()-1);
            log.append("\nquoted value -> ");
            log.append(output);
            return output;
        }

        if (isCreditCard(input))  {
            return input;
        }
        if(isPHPSerialized(input, true)){
            return input;
        }
        if (ValuePattern.URL_ENCODED.matches(input)) {
            String output = callbacks.getHelpers().urlDecode(input);
            if (!output.equals(input)) {
                log.append("\nURL Decode -> ");
                log.append(output);
            }
            return output;
        } else if (ValuePattern.HEX_STRING.matches(input)) {
            log.append(identify(pi, input));
            String output = asciiHexDecode(input);
            if (ValuePattern.PRINTABLE_CHARS.matches(output)) {
                log.append("\nASCII Hex Decoded to printable string -> ");
                log.append(output);
                return output;
            } else {
                return input;
            }
        } else if(ValuePattern.URL_PATH.matches(input)) {    // This is a bit of a hack to exit out for things that might accidentally be interpreted as base64
            log.append("\n");
            log.append(identify(pi, input));
            return input;
        } else if(ValuePattern.JWT.matches(input)) {
            String[] parts = input.split("[\\.]");
            byte[] algorithmBytes = callbacks.getHelpers().base64Decode(parts[0]);
            String algorithm = callbacks.getHelpers().bytesToString(algorithmBytes);
            byte[] decodedBytes = callbacks.getHelpers().base64Decode(parts[1]);
            String decodedString = callbacks.getHelpers().bytesToString(decodedBytes);
            pi.setFormat(ParamInstance.Format.JWT);
            log.append("\nLooks to be a JWT: \n  The algorithm section is: \n").append(algorithm);
            log.append("\n  The body section is: \n").append(decodedString);
            return decodedString;
        } else if(ValuePattern.BASE64_ENCODED.matches(input)) {
            byte[] decodedBytes = callbacks.getHelpers().base64Decode(input);
            String decodedString = callbacks.getHelpers().bytesToString(decodedBytes);
            if(ValuePattern.PRINTABLE_CHARS.matches(decodedString)) {
                log.append("\nBase64 Decode -> ");
                log.append(decodedString).append(" ...");
            } else {
                log.append("\nBase64 Decode -> (Looks like a ");
                log.append(decodedBytes.length);
                log.append(" byte binary value)\nHash best guess is: ");
                log.append(guessHash(pi, decodedBytes.length));
                pi.setFormat(ParamInstance.Format.BASE64BIN);
                return input;
            }
            return decodedString;
        } else {
            log.append("\n");
//            log.append(identify(pi, input));
            return input;
        }
    }


    private static String identify(ParamInstance pi, String input) {
        StringBuilder log = new StringBuilder();
        if (isCreditCard(input)) {
            log.append("Looks like a credit card (passed Luhn).");
            pi.setFormat(ParamInstance.Format.CREDITCARD);
        } else if(isPHPSerialized(input, false)) {
            log.append("Looks like a PHP serialized data structure.");
            pi.setFormat(ParamInstance.Format.PHP);
        } else if(ValuePattern.DECIMAL.matches(input)) {
            log.append("A ");
            log.append(input.length());
            log.append(" digit numeric value.");
            pi.setFormat(ParamInstance.Format.NUMERIC);
        } else if(ValuePattern.HEX_STRING.matches(input)) {
            log.append("Looks like a hex string of length ");
            log.append(input.length());
            log.append(" (");
            log.append(input.length() * 4);
            log.append(" bits)");
            log.append(": ");
            pi.setFormat(ParamInstance.Format.HEX);
            log.append(guessHash(pi, input.length() * 4));
        } else if(ValuePattern.URL_PATH2.matches(input)) {
            log.append("Looks like a URL or path.");
            pi.setFormat(ParamInstance.Format.URLPATH);
        } else if(ValuePattern.EMAIL_ADDRESS.matches(input)) {
            log.append("Looks like an email address.");
            pi.setFormat(ParamInstance.Format.EMAIL);
        } else if (ValuePattern.SSN.matches(input)) {
            log.append("Looks like a SSN.");
            pi.setFormat(ParamInstance.Format.SSN);
        } else if (ValuePattern.BIG_IP.matches(input)) {
            log.append("Looks like a big IP cookie.");
            String decoded = decodeBigIP(pi, input);
            log.append("\nBigIP decoded value: ").append(decoded);
            pi.setFormat(ParamInstance.Format.BIGIP);
        } else if(ValuePattern.TEXT.matches(input)) {
            log.append("Looks like a word or sentence.");
            if (ValuePattern.BASE62_ENCODED.matches(input)) {
                try {
                    long result = Base62.decode(input);
                    log.append("\n\nThis may be a base62 encoded value (rare)." +
                            "\n  If it is, it decodes to: ").append(result);
                } catch (Exception e) {
                    // ignore - our regex isn't precise enough to catch everything.
                }
            }
            pi.setFormat(ParamInstance.Format.TEXT);
        } else if(ValuePattern.PRINTABLE_CHARS.matches(input)) {
            log.append("Looks like a ");
            log.append(input.length());
            log.append(" length string of printable characters.");
            if (ValuePattern.BASE62_ENCODED.matches(input)) {
                try {
                    long result = Base62.decode(input);
                    log.append("\n\nThis may be a base62 encoded value (rare)." +
                            "\n  If it is, it decodes to: ").append(result);
                } catch (Exception e) {
                    // ignore - our regex isn't precise enough to catch everything.
                }
            }

            if (ValuePattern.HTML_FRAGMENT.matches(input)) {
                log.append("\nThis may be XML or an HTML Fragment!");
                pi.setFormat(ParamInstance.Format.HTMLFRAG);
            } else if (ValuePattern.JSON_OBJECT.matches(input)) {
                log.append("\nThis may be a JSON-formatted String.");
                if (pi.getFormat() != ParamInstance.Format.JWT) {
                    pi.setFormat(ParamInstance.Format.JSON);
                }
            } else {
                pi.setFormat(ParamInstance.Format.PRINTABLE);
            }
        } else {
            log.append("Unidentified.");
        }

        return log.toString();
    }



    private static boolean isPHPSerialized(String input, boolean quick) {
        return quick?ValuePattern.PHP_SERIALIZED_QUICK.matches(input):ValuePattern.PHP_SERIALIZED.matches(input);
    }

    private static boolean isCreditCard(String input) {
        if (ValuePattern.CREDIT_CARD_QUICK.matches(input)) {
            String[] parts = input.split("[ -]");
            String squashedInput = String.join("", parts);
            return ValuePattern.CREDIT_CARD.matches(squashedInput) && applyLuhnAlgorithm(squashedInput);
        } else {
            return false;
        }
    }

    // Based on code from http://www.journaldev.com/1443/java-credit-card-validation-program-using-luhn-algorithm
    private static boolean applyLuhnAlgorithm(String str) {
        int[] ints = new int[str.length()];
        for(int i = 0;i < str.length(); i++){
            ints[i] = Integer.parseInt(str.substring(i, i+1));
        }
        for(int i = ints.length-2; i>=0; i=i-2){
            int j = ints[i];
            j = j*2;
            if(j>9){
                j = j%10 + 1;
            }
            ints[i]=j;
        }
        int sum=0;
        for (int anInt : ints) {
            sum += anInt;
        }
        return (sum%10 == 0);
    }

    public static String guessHash(ParamInstance pi, int bits) {
        switch (bits) {
            case 128:
                pi.setFormat(ParamInstance.Format.MD5);
                return("MD5?");
            case 160:
                pi.setFormat(ParamInstance.Format.SHA1);
                return("SHA-1?");
            case 224:
                pi.setFormat(ParamInstance.Format.SHA224);
                return("SHA-224?");
            case 256:
                pi.setFormat(ParamInstance.Format.SHA256);
                return("SHA-256?");
            case 512:
                pi.setFormat(ParamInstance.Format.SHA512);
                return("SHA-512?");
            default:
                return("? (uncommon hash length)");
        }

    }

    public static String decodeBigIP(ParamInstance pi, String input) {
        try {
            String[] segments = input.split("\\.");
            String hexIP = getHex(segments[0]);
            String hexPort = getHex(segments[1]);
            String decoded =  generateDecimal(hexIP, ".") + ":" + generateDecimal(hexPort, "");
            pi.setFormat(ParamInstance.Format.BIGIP);
            return decoded;
        } catch(Throwable t) {
            return "(could not decode)";
        }
    }

    private static String getHex(String segment) {
        long decIP = Long.parseLong(segment);
        String hexString = Long.toHexString(decIP);
        System.out.println("hexString: "+hexString);
        StringBuilder reversedHex = new StringBuilder();
        for(int i=hexString.length();i>0;i-=2){
            reversedHex.append(hexString.substring(i-2,i));
        }

        System.out.println("Reversed: "+reversedHex);
        return reversedHex.toString();
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    private static String generateDecimal(String hex, String separator) {
        StringBuilder buf = new StringBuilder();

        for(int i=0;i<hex.length();i+=2) {
            String octetHex = hex.substring(i, i+2);
            int octetInt = Integer.parseInt(octetHex, 16);
            buf.append(separator);
            buf.append(octetInt);
        }
        return buf.substring(separator.length());
    }

    private static String asciiHexDecode(String input) {
        int len = input.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(input.charAt(i), 16) << 4)
                    + Character.digit(input.charAt(i+1), 16));
        }
        String output = input;
        try {
            output = new String(data, "ASCII");
        } catch (UnsupportedEncodingException e) {
            return input;
        }

        return output;
    }

    public static void test(String name, String input, ValuePattern ...shouldMatch){
        for (ValuePattern testPattern: ValuePattern.values()) {
            boolean result = testPattern.matches(input);
            if(Arrays.asList(shouldMatch).contains(testPattern)) {
                System.out.println(name+":  "+(result?"pass":"FAIL" + " for " + input));
            } else {
                if (result) {
                    boolean dependencyMatch = false;
                    for (ValuePattern aMatch: shouldMatch) {
                        if (aMatch.isDependency(testPattern.name())){
                            dependencyMatch = true;
                        }
                    }

                    if (!dependencyMatch) {
                        System.out.println(name + ": FALSE POSITIVE.  Passed " + testPattern.name()+ " for " + input);
                    }
                }
            }
        }
    }

    public static void main(String[] args) {
        test("credit card", "4242424242424242", ValuePattern.CREDIT_CARD);
        test("credit card 2", "424242424242424", ValuePattern.CREDIT_CARD);
        System.out.println("credit card 3: "+(isCreditCard("4242 4242 4242 4242")?"pass":"FAIL"));
        System.out.println("credit card 4: "+(isCreditCard("4242-4242-4242-4242")?"pass":"FAIL"));
        test("JSON 1", "{\"foo\": \"bar\"}", ValuePattern.JSON_OBJECT);
        test("JSON 2", "{\"foo\": {\"foo1\": [1,2,3]}}", ValuePattern.JSON_OBJECT);
        test("JSON 3", "{\"foo\": \"bar\", \"foo2\": [42, 99], \"foo3\": {\"secret1\": \"4242-4242-4242-4242\", \"secret2\": false}}", ValuePattern.JSON_OBJECT);
        test("JSON 4", "{\"secret1\": \"4242-4242-4242-4242\", \"secret2\": false}", ValuePattern.JSON_OBJECT);
        test("JWT 1", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ikphc29uIEdpbGxhbSIsInNlY3JldCI6NDJ9.Yo-96trF4CAU_v-mrJLYuqigEGC3QBDul7C41RM2RL4", ValuePattern.JWT);
        test("JSON 5", "{\"sub\":\"1234567890\",\"name\":\"Jason Gillam\",\"secret\":42}", ValuePattern.JSON_OBJECT);



    }

}
