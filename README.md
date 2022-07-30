# burp-paramalyzer

## Description
The purpose of this extension is to improve efficiency of manual parameter analysis for web penetration tests of either complex or numerous applications.  This can assist in tasks such as identifying sensitive data, identifying hash algorithms, decoding parameters, and determining which parameters are reflected in the response.

## Docs

[Read the docs](http://jgillam.github.io/burp-paramalyzer/)

## Issues and Enhancements
Use the Issues tab above to report any problems or enhancement requests.

_Note: You must install Burp Suite (either the community or pro version) first.  Then download the latest burp-paramalyzer release (.jar file) and install it through the Burp Extender tab._


## Development Notes
This project was built using IntelliJ IDEA and uses a Gradle build (as per Portswiggers requirements for BAppStore integration).

Assuming you are bringing this into IntelliJ to work on it, you should be able to build using the Gradle `burp-paramalyzer[fatJar]` target.

However, if you make significant changes through the UI designer, it may be necessary to run a build from the project menu (`Ctrl-F9`) to regenerate the UI component code. It may also be necessary to run this twice (you will know when you see errors about things it can't seem to find). Once the UI designer code is regenerated, you can go back to using the Gradle fatJar target.  