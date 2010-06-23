<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<!-- per default copy everything -->
  <xsl:template match="@*|node()">
    <xsl:copy>
      <xsl:apply-templates select="@*|node()" />
    </xsl:copy>
  </xsl:template>
  
  <!--  strip all script tags -->
  <xsl:template match="script" />
  
  <!-- xhtmlrenderer doesn't know how to render input elements, so we replace them accordingly -->
  <!-- replace all comoboxes with a string that contains the selected element -->
  <xsl:template match="select">
    ausgew�hlt: 
    <b>"
      <xsl:value-of select="./option[@selected='selected']" />
    "</b>
  </xsl:template>
  
  <!-- replace checkboxes with an equivalent string -->
  <xsl:template match="input[@type='checkbox']">
    <b>
      <xsl:choose>
        <xsl:when test="@checked"><div>[X]</div></xsl:when>
        <xsl:otherwise>
          <div style="white-space:nowrap;">[ ]</div>
        </xsl:otherwise>
      </xsl:choose>
    </b>
  </xsl:template>
  <!-- replace radio buttons with an equivalent string -->
  <xsl:template match="input[@type='radio']">
    <b>
      <xsl:choose>
        <xsl:when test="@checked">[X]</xsl:when>
        <xsl:otherwise>[ ]</xsl:otherwise>
      </xsl:choose>
    </b>
  </xsl:template>
  
  <!-- use different columns for checkboxes and the added image to make sure,
       they are horizontally aligned. xhtmlrenderer likes to mess with the layout... -->
  <xsl:template match="td[./input/@type='checkbox']">
  <td>
     <xsl:apply-templates select="./input" />
  </td>
  <td> 
     <xsl:apply-templates select="img" />
  </td>     
  </xsl:template>
  
  <!-- try to avoid page breaks within a subtasklet -->
  <xsl:template match="fieldset[@class='complexTask']">
      <xsl:element name="fieldset">
        <xsl:attribute name="style">
          page-break-inside: avoid;
        </xsl:attribute> 
        <xsl:apply-templates select="@*|node()" />
      </xsl:element>
  </xsl:template>
  
  <!-- add page numbers to each page footer -->
  <!-- also make sure we use a font with at least some utf8 glyphs (cyrillic etc.) -->
  <xsl:template match="head">
    <xsl:element name="head">
      <xsl:apply-templates select="@*|node()" />
      <style type="text/css">
        @page { 
          @bottom-center { 
            content: "Seite " counter(page) " von " counter(pages); 
          } 
        }
             
        p,ul,ol,li,div,td,th,address,blockquote,nobr,i,b {
           font-family: "Lucida Sans Unicode";
        }
      </style>
      <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    </xsl:element>
  </xsl:template>
  
  <!-- Flying saucer seems to have trouble with thead and tbody, strip them from the html. -->
  <xsl:template match="thead">
    <xsl:apply-templates/>  
  </xsl:template>
  <xsl:template match="tbody">
    <xsl:apply-templates/>  
  </xsl:template>
</xsl:stylesheet>