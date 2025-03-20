/*
 * Copyright (c) 2023 Jason Gillam
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

import javax.swing.*;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultHighlighter;
import javax.swing.text.Highlighter;
import javax.swing.text.JTextComponent;
import java.awt.*;

/**
 * Utility class providing common UI operations and theme-aware functionality.
 */
public class UIUtils {
    // Static fields
    private static boolean darkModeDetected;
    private static Color highlightColor;
    
    // Static initialization block - runs once when class is loaded
    static {        
        // Pre-detect dark mode at class load time
        darkModeDetected = UIManager.getLookAndFeel().getName().toLowerCase().contains("dark");
        
        // Pre-compute highlight color based on theme
        highlightColor = darkModeDetected ? new Color(128, 0, 128) : Color.pink;
        
        // Could also register listeners for theme changes here
        UIManager.addPropertyChangeListener(evt -> {
            if ("lookAndFeel".equals(evt.getPropertyName())) {
                // Update colors when theme changes
                darkModeDetected = UIManager.getLookAndFeel().getName().toLowerCase().contains("dark");
                highlightColor = darkModeDetected ? new Color(128, 0, 128) : Color.pink;
            }
        });
    }
    
    /**
     * Returns the appropriate highlight color based on the current UI theme
     * @return Color suitable for highlights in the current theme
     */
    public static Color getHighlightColor() {
        return highlightColor;
    }
    
    
    /**
     * Highlights all occurrences of text in a component and optionally scrolls to the first match
     * @param textComponent The text component to highlight in
     * @param textToHighlight The text to highlight
     * @param scrollToHighlight Whether to scroll to make the first highlight visible
     * @param maxOccurrences Maximum number of occurrences to highlight (0 or negative for all)
     * @return The number of occurrences highlighted
     */
    public static int highlightText(JTextComponent textComponent, String textToHighlight, 
                                   boolean scrollToHighlight, int maxOccurrences) {
        if (textComponent == null || textToHighlight == null || textToHighlight.isEmpty()) {
            return 0;
        }
        
        String text = textComponent.getText();
        Highlighter highlighter = textComponent.getHighlighter();
        highlighter.removeAllHighlights();
        
        int occurrencesFound = 0;
        int firstIndex = -1;
        int searchFrom = 0;
        int textToHighlightLength = textToHighlight.length();
        
        // The DefaultHighlightPainter for all occurrences
        DefaultHighlighter.DefaultHighlightPainter painter = 
            new DefaultHighlighter.DefaultHighlightPainter(getHighlightColor());
        
        try {
            while ((maxOccurrences <= 0 || occurrencesFound < maxOccurrences) && 
                   (searchFrom < text.length())) {
                int index = text.indexOf(textToHighlight, searchFrom);
                if (index == -1) {
                    break; // No more occurrences
                }
                
                // Add highlight for this occurrence
                highlighter.addHighlight(index, index + textToHighlightLength, painter);
                occurrencesFound++;
                
                // Remember position of first occurrence for scrolling
                if (firstIndex == -1) {
                    firstIndex = index;
                }
                
                // Move search position forward
                searchFrom = index + textToHighlightLength;
            }
            
            // Scroll to the first occurrence if requested and found
            if (scrollToHighlight && firstIndex != -1) {
                Rectangle viewRect = textComponent.modelToView(firstIndex);
                textComponent.scrollRectToVisible(viewRect);
            }
        } catch (BadLocationException ex) {
            // Ignore exceptions
        }
        
        return occurrencesFound;
    }

    /**
     * Highlights all occurrences of text in a component and optionally scrolls to the first match
     * Default to highlighting up to 10 occurrences
     */
    public static int highlightText(JTextComponent textComponent, String textToHighlight, 
                                   boolean scrollToHighlight) {
        return highlightText(textComponent, textToHighlight, scrollToHighlight, 10);
    }
    
    /**
     * Sets up a text area with common configurations (line wrapping, etc.)
     * @param textArea The text area to configure
     */
    public static void wrap(JTextArea textArea) {
        textArea.setLineWrap(true);
        textArea.setWrapStyleWord(true);        
    }        
}