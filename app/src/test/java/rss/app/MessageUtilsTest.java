/*
 * This Java source file was generated by the Gradle 'init' task.
 */
package rss.app;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class MessageUtilsTest {
    @Test
    public void testGetMessage() {
        assertEquals("Hello      World!", MessageUtils.getMessage());
    }
}
