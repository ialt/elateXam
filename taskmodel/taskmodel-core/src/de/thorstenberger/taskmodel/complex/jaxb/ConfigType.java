//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v1.0.6-01/24/2006 06:08 PM(kohsuke)-fcs 
// 	See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// 	Any modifications to this file will be lost upon recompilation of the source schema. 
// 	Generated on: 2009.01.14 um 02:56:20 CET 
//


package de.thorstenberger.taskmodel.complex.jaxb;


/**
 * Java content class for anonymous complex type.
 * 	<p>The following schema fragment specifies the expected 	content contained within this java content object. 	(defined at file:/D:/java_files/workspace/elatePortal/taskmodel-core/jaxb/complexTaskDef.xsd line 523)
 * <p>
 * <pre>
 * &lt;complexType>
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;attribute name="noOfSelectedTasks" use="required">
 *         &lt;simpleType>
 *           &lt;restriction base="{http://www.w3.org/2001/XMLSchema}int">
 *             &lt;minInclusive value="0"/>
 *           &lt;/restriction>
 *         &lt;/simpleType>
 *       &lt;/attribute>
 *       &lt;attribute name="pointsPerTask" use="required">
 *         &lt;simpleType>
 *           &lt;restriction base="{http://www.w3.org/2001/XMLSchema}float">
 *             &lt;minInclusive value="0"/>
 *           &lt;/restriction>
 *         &lt;/simpleType>
 *       &lt;/attribute>
 *       &lt;attribute name="preserveOrder" use="required" type="{http://www.w3.org/2001/XMLSchema}boolean" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 */
public interface ConfigType {


    /**
     * Gets the value of the preserveOrder property.
     * 
     */
    boolean isPreserveOrder();

    /**
     * Sets the value of the preserveOrder property.
     * 
     */
    void setPreserveOrder(boolean value);

    boolean isSetPreserveOrder();

    void unsetPreserveOrder();

    /**
     * Gets the value of the noOfSelectedTasks property.
     * 
     */
    int getNoOfSelectedTasks();

    /**
     * Sets the value of the noOfSelectedTasks property.
     * 
     */
    void setNoOfSelectedTasks(int value);

    boolean isSetNoOfSelectedTasks();

    void unsetNoOfSelectedTasks();

    /**
     * Gets the value of the pointsPerTask property.
     * 
     */
    float getPointsPerTask();

    /**
     * Sets the value of the pointsPerTask property.
     * 
     */
    void setPointsPerTask(float value);

    boolean isSetPointsPerTask();

    void unsetPointsPerTask();

}
