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

import burp.IBurpExtenderCallbacks;

import java.io.UnsupportedEncodingException;
import java.util.regex.Pattern;

/**
 * This class contains the analysis logic that identifies formats and decodes values.
 */
public class ParamAnalyzer {

    private static Pattern urlEncodedPattern = Pattern.compile("%[0-9a-zA-Z]{2}");
    private static Pattern base64EncodedPattern = Pattern.compile("^(?:[A-Za-z0-9+/]{4}(==)?)*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$");
    private static Pattern printableCharsPattern = Pattern.compile("^\\p{Print}+$");
    private static Pattern textPattern = Pattern.compile("^([\\w']+ )*[\\w']+[\\.?!]?$");
    private static Pattern hexStringPattern = Pattern.compile("^([A-F0-9]{2})+$", Pattern.CASE_INSENSITIVE);
    private static Pattern decimalPattern = Pattern.compile("^[-]?[0-9]+$");
    private static Pattern bigIPPattern = Pattern.compile("^[0-9]+\\.[0-9]+\\.[0-9]+$"); // close enough
    private static Pattern urlPathPattern = Pattern.compile("^(/([\\p{Alnum}!$&'()*+,-.:;<=>?@_]|%[0-9]{2})+)+/?$");
    private static Pattern urlPathPattern2 = Pattern.compile("^http[s]?://[a-zA-Z0-9]+");
    private static Pattern emailAddressPattern = Pattern.compile("^[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,4}$", Pattern.CASE_INSENSITIVE);
    private static Pattern ssnPattern = Pattern.compile("^[0-9]{3}-[0-9]{2}-[0-9]{4}$");
    private static Pattern creditcardPattern = Pattern.compile("^[0-9]{14,16}$");
    private static Pattern htmlFragment = Pattern.compile("</[a-z]+>");


    public static String analyze(ParamInstance pi, IBurpExtenderCallbacks callbacks) {
        try {
            String value = pi.getValue();
            if (value.isEmpty() || "[EMPTY]".equals(value)) {
                pi.setFormat(ParamInstance.Format.EMPTY);
                return "An empty string.";
            } else if (value.trim().isEmpty()) {
                return "A string of " + value.length() + " whitespace characters.";
            } else if (pi.getName().toLowerCase().contains("bigip") && bigIPPattern.matcher(value).find()) {
                return "Appears to be a BigIP value: " + value + "\nDecodes to: " + decodeBigIP(pi, value);
            }

            StringBuilder smartDecodeLog = new StringBuilder();
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

    public static String smartDecode(ParamInstance pi, String input, IBurpExtenderCallbacks callbacks, StringBuilder log) {
        if (isURLEncoded(input)) {
            String output = callbacks.getHelpers().urlDecode(input);
            if (!output.equals(input)) {
                log.append("\nURL Decode -> ");
                log.append(output);
            }
            return output;
        } else if (isHexString(input)) {
            log.append(identify(pi, input));
            String output = asciiHexDecode(input);
            if (isPrintableCharacters(output)) {
                log.append("\nASCII Hex Decoded to printable string -> ");
                log.append(output);
                return output;
            } else {
                return input;
            }
        } else if(isURLPathString(input)) {    // This is a bit of a hack to exit out for things that might accidentally be interpreted as base64
            log.append("\n");
            log.append(identify(pi, input));
            return input;
        }else if(isBase64Encoded(input)) {
            byte[] decodedBytes = callbacks.getHelpers().base64Decode(input);
            String decodedString = callbacks.getHelpers().bytesToString(decodedBytes);
            if(isPrintableCharacters(decodedString)) {
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
            log.append(identify(pi, input));
            return input;
        }
    }

    public static String identify(ParamInstance pi, String input) {
        StringBuilder log = new StringBuilder();
        if (isCreditCard(input)) {
            log.append("Looks like a credit card (passed Luhn).");
            pi.setFormat(ParamInstance.Format.CREDITCARD);
        } else if(isDecimalString(input)) {
            log.append("A ");
            log.append(input.length());
            log.append(" digit numeric value.");
            pi.setFormat(ParamInstance.Format.NUMERIC);
        } else if(isHexString(input)) {
            log.append("Looks like a hex string of length ");
            log.append(input.length());
            log.append(" (");
            log.append(input.length() * 4);
            log.append(" bits)");
            log.append(": ");
            pi.setFormat(ParamInstance.Format.HEX);
            log.append(guessHash(pi, input.length() * 4));
        } else if(isURLPathString(input)) {
            log.append("Looks like a URL or path.");
            pi.setFormat(ParamInstance.Format.URLPATH);
        } else if(isEmail(input)) {
            log.append("Looks like an email address.");
            pi.setFormat(ParamInstance.Format.EMAIL);
        } else if (isSSN(input)) {
            log.append("Looks like a SSN.");
            pi.setFormat(ParamInstance.Format.SSN);
        }  else if(isSentence(input)) {
            log.append("Looks like a word or sentence.");
            pi.setFormat(ParamInstance.Format.TEXT);
        } else if(isPrintableCharacters(input)) {
            log.append("Looks like a ");
            log.append(input.length());
            log.append(" length string of printable characters.");
            if (isHTMLFragment(input)) {
                log.append("\nThis may be XML or an HTML Fragment!");
                pi.setFormat(ParamInstance.Format.HTMLFRAG);
            } else {
                pi.setFormat(ParamInstance.Format.PRINTABLE);
            }
        } else {
            log.append("Unidentified");
        }

        return log.toString();
    }

    public static boolean isURLEncoded(String input) {
        return urlEncodedPattern.matcher(input).find();
    }

    public static boolean isBase64Encoded(String input) {
        return base64EncodedPattern.matcher(input).find();
    }

    public static boolean isPrintableCharacters(String input) {
        return printableCharsPattern.matcher(input).find();
    }

    public static boolean isHexString(String input) {
        return hexStringPattern.matcher(input).find();
    }

    public static boolean isDecimalString(String input) {
        return decimalPattern.matcher(input).find();
    }

    public static boolean isURLPathString(String input) { return urlPathPattern.matcher(input).find() ||
            urlPathPattern2.matcher(input).find();}

    public static boolean isSentence(String input) {return input.length() < 40 && textPattern.matcher(input).find();}

    public static boolean isEmail(String input) {return emailAddressPattern.matcher(input).find();}

    public static boolean isSSN(String input) {return ssnPattern.matcher(input).find();}

    public static boolean isHTMLFragment(String input) {return htmlFragment.matcher(input).find();}

    public static boolean isCreditCard(String input) {
        return creditcardPattern.matcher(input).find() && applyLuhnAlgorithm(input);
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

}
