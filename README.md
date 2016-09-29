# burp-paramalyzer

## Description
The purpose of this extension is to improve efficiency of manual parameter analysis for web penetration tests of either complex or numerous applications.  This can assist in tasks such as identifying sensitive data, identifying hash algorithms, decoding parameters, and determining which parameters are reflected in the response.

This extension performs an in-depth and intelligent parameter analysis of all in-scope Burp traffic.  Results are displayed in an interactive table and can be sent directly to other Burp tools such as Repeater.

## Usage
Burp Paramalyzer is an extension for the popular Burp Suite web penetration testing tool by Portswigger.  To use it, simply set your scope within Burp and map out the application by using it (clicking through links and filling out forms).  The goal of mapping should be to generate "normal" user traffic rather than attack payloads.  Once this is done click on the correlator tab and perform analysis.  The results will be displayed in an interactive table.

For a video demo see: https://www.youtube.com/watch?v=jn1hd-LkSuw

_Note: You must install Burp Suite (either the community or pro version) first.  Then download the latest burp-paramalyzer release (.jar file) and install it through the Burp Extender tab._
