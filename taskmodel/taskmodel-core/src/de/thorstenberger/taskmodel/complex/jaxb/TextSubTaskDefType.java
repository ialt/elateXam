//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v1.0.6-01/24/2006 06:08 PM(kohsuke)-fcs 
// 	See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// 	Any modifications to this file will be lost upon recompilation of the source schema. 
// 	Generated on: 2009.01.14 um 02:56:20 CET 
//


package de.thorstenberger.taskmodel.complex.jaxb;


/**
 * Java content class for anonymous complex type.
 * 	<p>The following schema fragment specifies the expected 	content contained within this java content object. 	(defined at file:/D:/java_files/workspace/elatePortal/taskmodel-core/jaxb/complexTaskDef.xsd line 410)
 * <p>
 * <pre>
 * &lt;complexType>
 *   &lt;complexContent>
 *     &lt;extension base="{http://complex.taskmodel.thorstenberger.de/complexTaskDef}SubTaskDefType">
 *       &lt;sequence>
 *         &lt;element name="initialTextFieldValue" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *       &lt;/sequence>
 *       &lt;attribute name="textFieldHeight">
 *         &lt;simpleType>
 *           &lt;restriction base="{http://www.w3.org/2001/XMLSchema}int">
 *             &lt;minInclusive value="1"/>
 *           &lt;/restriction>
 *         &lt;/simpleType>
 *       &lt;/attribute>
 *       &lt;attribute name="textFieldWidth">
 *         &lt;simpleType>
 *           &lt;restriction base="{http://www.w3.org/2001/XMLSchema}int">
 *             &lt;minInclusive value="1"/>
 *           &lt;/restriction>
 *         &lt;/simpleType>
 *       &lt;/attribute>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 */
public interface TextSubTaskDefType
    extends de.thorstenberger.taskmodel.complex.jaxb.SubTaskDefType
{


    /**
     * Gets the value of the textFieldHeight property.
     * 
     */
    int getTextFieldHeight();

    /**
     * Sets the value of the textFieldHeight property.
     * 
     */
    void setTextFieldHeight(int value);

    boolean isSetTextFieldHeight();

    void unsetTextFieldHeight();

    /**
     * Gets the value of the textFieldWidth property.
     * 
     */
    int getTextFieldWidth();

    /**
     * Sets the value of the textFieldWidth property.
     * 
     */
    void setTextFieldWidth(int value);

    boolean isSetTextFieldWidth();

    void unsetTextFieldWidth();

    /**
     * Gets the value of the initialTextFieldValue property.
     * 
     * @return
     *     possible object is
     *     {@link java.lang.String}
     */
    java.lang.String getInitialTextFieldValue();

    /**
     * Sets the value of the initialTextFieldValue property.
     * 
     * @param value
     *     allowed object is
     *     {@link java.lang.String}
     */
    void setInitialTextFieldValue(java.lang.String value);

    boolean isSetInitialTextFieldValue();

    void unsetInitialTextFieldValue();

}
