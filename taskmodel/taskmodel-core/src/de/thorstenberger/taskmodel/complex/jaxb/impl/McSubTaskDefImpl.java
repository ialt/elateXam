//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v1.0.2-b15-fcs 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2006.07.09 at 10:15:46 CEST 
//


package de.thorstenberger.taskmodel.complex.jaxb.impl;

public class McSubTaskDefImpl
    extends de.thorstenberger.taskmodel.complex.jaxb.impl.McSubTaskDefTypeImpl
    implements de.thorstenberger.taskmodel.complex.jaxb.McSubTaskDef, java.io.Serializable, com.sun.xml.bind.RIElement, com.sun.xml.bind.JAXBObject, de.thorstenberger.taskmodel.complex.jaxb.impl.runtime.UnmarshallableObject, de.thorstenberger.taskmodel.complex.jaxb.impl.runtime.XMLSerializable, de.thorstenberger.taskmodel.complex.jaxb.impl.runtime.ValidatableObject
{

    private final static long serialVersionUID = 1L;
    public final static java.lang.Class version = (de.thorstenberger.taskmodel.complex.jaxb.impl.JAXBVersion.class);
    private static com.sun.msv.grammar.Grammar schemaFragment;

    private final static java.lang.Class PRIMARY_INTERFACE_CLASS() {
        return (de.thorstenberger.taskmodel.complex.jaxb.McSubTaskDef.class);
    }

    public java.lang.String ____jaxb_ri____getNamespaceURI() {
        return "http://complex.taskmodel.thorstenberger.de/complexTaskDef";
    }

    public java.lang.String ____jaxb_ri____getLocalName() {
        return "mcSubTaskDef";
    }

    public de.thorstenberger.taskmodel.complex.jaxb.impl.runtime.UnmarshallingEventHandler createUnmarshaller(de.thorstenberger.taskmodel.complex.jaxb.impl.runtime.UnmarshallingContext context) {
        return new de.thorstenberger.taskmodel.complex.jaxb.impl.McSubTaskDefImpl.Unmarshaller(context);
    }

    public void serializeBody(de.thorstenberger.taskmodel.complex.jaxb.impl.runtime.XMLSerializer context)
        throws org.xml.sax.SAXException
    {
        context.startElement("http://complex.taskmodel.thorstenberger.de/complexTaskDef", "mcSubTaskDef");
        super.serializeURIs(context);
        context.endNamespaceDecls();
        super.serializeAttributes(context);
        context.endAttributes();
        super.serializeBody(context);
        context.endElement();
    }

    public void serializeAttributes(de.thorstenberger.taskmodel.complex.jaxb.impl.runtime.XMLSerializer context)
        throws org.xml.sax.SAXException
    {
    }

    public void serializeURIs(de.thorstenberger.taskmodel.complex.jaxb.impl.runtime.XMLSerializer context)
        throws org.xml.sax.SAXException
    {
    }

    public java.lang.Class getPrimaryInterface() {
        return (de.thorstenberger.taskmodel.complex.jaxb.McSubTaskDef.class);
    }

    public com.sun.msv.verifier.DocumentDeclaration createRawValidator() {
        if (schemaFragment == null) {
            schemaFragment = com.sun.xml.bind.validator.SchemaDeserializer.deserialize((
 "\u00ac\u00ed\u0000\u0005sr\u0000\'com.sun.msv.grammar.trex.ElementPattern\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0001\u0002\u0000\u0001L\u0000"
+"\tnameClasst\u0000\u001fLcom/sun/msv/grammar/NameClass;xr\u0000\u001ecom.sun.msv."
+"grammar.ElementExp\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0001\u0002\u0000\u0002Z\u0000\u001aignoreUndeclaredAttributesL\u0000"
+"\fcontentModelt\u0000 Lcom/sun/msv/grammar/Expression;xr\u0000\u001ecom.sun."
+"msv.grammar.Expression\u00f8\u0018\u0082\u00e8N5~O\u0002\u0000\u0003I\u0000\u000ecachedHashCodeL\u0000\u0013epsilon"
+"Reducibilityt\u0000\u0013Ljava/lang/Boolean;L\u0000\u000bexpandedExpq\u0000~\u0000\u0003xp\u0013\u00a4S\u00b6p"
+"p\u0000sr\u0000\u001fcom.sun.msv.grammar.SequenceExp\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0001\u0002\u0000\u0000xr\u0000\u001dcom.sun."
+"msv.grammar.BinaryExp\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0001\u0002\u0000\u0002L\u0000\u0004exp1q\u0000~\u0000\u0003L\u0000\u0004exp2q\u0000~\u0000\u0003xq\u0000~"
+"\u0000\u0004\u0013\u00a4S\u00abppsq\u0000~\u0000\u0007\u0012v\u001c\u0096ppsq\u0000~\u0000\u0007\u0011\u0089N\u00eappsq\u0000~\u0000\u0007\u000f\u00b9\u0019\u009eppsq\u0000~\u0000\u0007\u000eZ\u00bb\u008fppsq\u0000~"
+"\u0000\u0007\fh5\u00cappsq\u0000~\u0000\u0007\tK\u00d9\u00d1ppsq\u0000~\u0000\u0007\u0007|\u008bBppsq\u0000~\u0000\u0007\u0005}\u00e8)ppsq\u0000~\u0000\u0000\u00035\u001f7pp\u0000sq\u0000"
+"~\u0000\u0007\u00035\u001f,ppsr\u0000\u001bcom.sun.msv.grammar.DataExp\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0001\u0002\u0000\u0003L\u0000\u0002dtt\u0000\u001fL"
+"org/relaxng/datatype/Datatype;L\u0000\u0006exceptq\u0000~\u0000\u0003L\u0000\u0004namet\u0000\u001dLcom/s"
+"un/msv/util/StringPair;xq\u0000~\u0000\u0004\u0000\u00ea\u00f4\u001cppsr\u0000#com.sun.msv.datatype."
+"xsd.StringType\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0001\u0002\u0000\u0001Z\u0000\risAlwaysValidxr\u0000*com.sun.msv.dat"
+"atype.xsd.BuiltinAtomicType\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0001\u0002\u0000\u0000xr\u0000%com.sun.msv.dataty"
+"pe.xsd.ConcreteType\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0001\u0002\u0000\u0000xr\u0000\'com.sun.msv.datatype.xsd.X"
+"SDatatypeImpl\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0001\u0002\u0000\u0003L\u0000\fnamespaceUrit\u0000\u0012Ljava/lang/String;"
+"L\u0000\btypeNameq\u0000~\u0000\u001cL\u0000\nwhiteSpacet\u0000.Lcom/sun/msv/datatype/xsd/Wh"
+"iteSpaceProcessor;xpt\u0000 http://www.w3.org/2001/XMLSchemat\u0000\u0006st"
+"ringsr\u00005com.sun.msv.datatype.xsd.WhiteSpaceProcessor$Preserv"
+"e\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0001\u0002\u0000\u0000xr\u0000,com.sun.msv.datatype.xsd.WhiteSpaceProcessor"
+"\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0001\u0002\u0000\u0000xp\u0001sr\u00000com.sun.msv.grammar.Expression$NullSetExpr"
+"ession\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0001\u0002\u0000\u0000xq\u0000~\u0000\u0004\u0000\u0000\u0000\nppsr\u0000\u001bcom.sun.msv.util.StringPair"
+"\u00d0t\u001ejB\u008f\u008d\u00a0\u0002\u0000\u0002L\u0000\tlocalNameq\u0000~\u0000\u001cL\u0000\fnamespaceURIq\u0000~\u0000\u001cxpq\u0000~\u0000 q\u0000~\u0000\u001f"
+"sr\u0000\u001dcom.sun.msv.grammar.ChoiceExp\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0001\u0002\u0000\u0000xq\u0000~\u0000\b\u0002J+\u000bppsr\u0000 "
+"com.sun.msv.grammar.AttributeExp\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0001\u0002\u0000\u0002L\u0000\u0003expq\u0000~\u0000\u0003L\u0000\tnam"
+"eClassq\u0000~\u0000\u0001xq\u0000~\u0000\u0004\u0002J+\u0000sr\u0000\u0011java.lang.Boolean\u00cd r\u0080\u00d5\u009c\u00fa\u00ee\u0002\u0000\u0001Z\u0000\u0005valu"
+"exp\u0000psq\u0000~\u0000\u0014\u0000\u00f3\u009bJppsr\u0000\"com.sun.msv.datatype.xsd.QnameType\u0000\u0000\u0000\u0000\u0000"
+"\u0000\u0000\u0001\u0002\u0000\u0000xq\u0000~\u0000\u0019q\u0000~\u0000\u001ft\u0000\u0005QNamesr\u00005com.sun.msv.datatype.xsd.WhiteS"
+"paceProcessor$Collapse\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0001\u0002\u0000\u0000xq\u0000~\u0000\"q\u0000~\u0000%sq\u0000~\u0000&q\u0000~\u00001q\u0000~\u0000\u001f"
+"sr\u0000#com.sun.msv.grammar.SimpleNameClass\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0001\u0002\u0000\u0002L\u0000\tlocalNa"
+"meq\u0000~\u0000\u001cL\u0000\fnamespaceURIq\u0000~\u0000\u001cxr\u0000\u001dcom.sun.msv.grammar.NameClass"
+"\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0001\u0002\u0000\u0000xpt\u0000\u0004typet\u0000)http://www.w3.org/2001/XMLSchema-inst"
+"ancesr\u00000com.sun.msv.grammar.Expression$EpsilonExpression\u0000\u0000\u0000\u0000"
+"\u0000\u0000\u0000\u0001\u0002\u0000\u0000xq\u0000~\u0000\u0004\u0000\u0000\u0000\tsq\u0000~\u0000,\u0001psq\u0000~\u00005t\u0000\u0007problemt\u00009http://complex.t"
+"askmodel.thorstenberger.de/complexTaskDefsq\u0000~\u0000(\u0002H\u00c8\u00edppsq\u0000~\u0000\u0000\u0002"
+"H\u00c8\u00e2q\u0000~\u0000-p\u0000sq\u0000~\u0000\u0007\u0002H\u00c8\u00d7ppq\u0000~\u0000\u0017sq\u0000~\u0000(\u0001]\u00d4\u00b6ppsq\u0000~\u0000*\u0001]\u00d4\u00abq\u0000~\u0000-pq\u0000~\u0000."
+"sq\u0000~\u00005q\u0000~\u00008q\u0000~\u00009q\u0000~\u0000;sq\u0000~\u00005t\u0000\u0004hintq\u0000~\u0000?q\u0000~\u0000;sq\u0000~\u0000\u0000\u0001\u00fe\u00a3\u0014pp\u0000sq\u0000"
+"~\u0000\u0007\u0001\u00fe\u00a3\tppsq\u0000~\u0000\u0014\u0000\u00f1\u0091\u007fppsr\u0000*com.sun.msv.datatype.xsd.MinInclusi"
+"veFacet\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0001\u0002\u0000\u0000xr\u0000#com.sun.msv.datatype.xsd.RangeFacet\u0000\u0000\u0000"
+"\u0000\u0000\u0000\u0000\u0001\u0002\u0000\u0001L\u0000\nlimitValuet\u0000\u0012Ljava/lang/Object;xr\u00009com.sun.msv.da"
+"tatype.xsd.DataTypeWithValueConstraintFacet\"\u00a7Ro\u00ca\u00c7\u008aT\u0002\u0000\u0000xr\u0000*co"
+"m.sun.msv.datatype.xsd.DataTypeWithFacet\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0001\u0002\u0000\u0005Z\u0000\fisFace"
+"tFixedZ\u0000\u0012needValueCheckFlagL\u0000\bbaseTypet\u0000)Lcom/sun/msv/dataty"
+"pe/xsd/XSDatatypeImpl;L\u0000\fconcreteTypet\u0000\'Lcom/sun/msv/datatyp"
+"e/xsd/ConcreteType;L\u0000\tfacetNameq\u0000~\u0000\u001cxq\u0000~\u0000\u001bq\u0000~\u0000?pq\u0000~\u00003\u0000\u0000sr\u0000 c"
+"om.sun.msv.datatype.xsd.IntType\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0001\u0002\u0000\u0000xr\u0000+com.sun.msv.da"
+"tatype.xsd.IntegerDerivedType\u0099\u00f1]\u0090&6k\u00be\u0002\u0000\u0001L\u0000\nbaseFacetsq\u0000~\u0000Pxq"
+"\u0000~\u0000\u0019q\u0000~\u0000\u001ft\u0000\u0003intq\u0000~\u00003sr\u0000*com.sun.msv.datatype.xsd.MaxInclusiv"
+"eFacet\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0001\u0002\u0000\u0000xq\u0000~\u0000Lppq\u0000~\u00003\u0000\u0001sq\u0000~\u0000Kppq\u0000~\u00003\u0000\u0000sr\u0000!com.sun.m"
+"sv.datatype.xsd.LongType\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0001\u0002\u0000\u0000xq\u0000~\u0000Tq\u0000~\u0000\u001ft\u0000\u0004longq\u0000~\u00003sq"
+"\u0000~\u0000Wppq\u0000~\u00003\u0000\u0001sq\u0000~\u0000Kppq\u0000~\u00003\u0000\u0000sr\u0000$com.sun.msv.datatype.xsd.Int"
+"egerType\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0001\u0002\u0000\u0000xq\u0000~\u0000Tq\u0000~\u0000\u001ft\u0000\u0007integerq\u0000~\u00003sr\u0000,com.sun.msv"
+".datatype.xsd.FractionDigitsFacet\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0001\u0002\u0000\u0001I\u0000\u0005scalexr\u0000;com."
+"sun.msv.datatype.xsd.DataTypeWithLexicalConstraintFacetT\u0090\u001c>\u001a"
+"zb\u00ea\u0002\u0000\u0000xq\u0000~\u0000Oppq\u0000~\u00003\u0001\u0000sr\u0000#com.sun.msv.datatype.xsd.NumberType"
+"\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0001\u0002\u0000\u0000xq\u0000~\u0000\u0019q\u0000~\u0000\u001ft\u0000\u0007decimalq\u0000~\u00003q\u0000~\u0000ft\u0000\u000efractionDigits\u0000"
+"\u0000\u0000\u0000q\u0000~\u0000`t\u0000\fminInclusivesr\u0000\u000ejava.lang.Long;\u008b\u00e4\u0090\u00cc\u008f#\u00df\u0002\u0000\u0001J\u0000\u0005value"
+"xr\u0000\u0010java.lang.Number\u0086\u00ac\u0095\u001d\u000b\u0094\u00e0\u008b\u0002\u0000\u0000xp\u0080\u0000\u0000\u0000\u0000\u0000\u0000\u0000q\u0000~\u0000`t\u0000\fmaxInclusiv"
+"esq\u0000~\u0000j\u007f\u00ff\u00ff\u00ff\u00ff\u00ff\u00ff\u00ffq\u0000~\u0000[q\u0000~\u0000isr\u0000\u0011java.lang.Integer\u0012\u00e2\u00a0\u00a4\u00f7\u0081\u00878\u0002\u0000\u0001I\u0000\u0005"
+"valuexq\u0000~\u0000k\u0080\u0000\u0000\u0000q\u0000~\u0000[q\u0000~\u0000msq\u0000~\u0000o\u007f\u00ff\u00ff\u00ffq\u0000~\u0000Uq\u0000~\u0000isq\u0000~\u0000o\u0000\u0000\u0000\u0001q\u0000~\u0000%"
+"sq\u0000~\u0000&t\u0000\u000bint-derivedq\u0000~\u0000?sq\u0000~\u0000(\u0001\r\u0011\u0085ppsq\u0000~\u0000*\u0001\r\u0011zq\u0000~\u0000-pq\u0000~\u0000.sq"
+"\u0000~\u00005q\u0000~\u00008q\u0000~\u00009q\u0000~\u0000;sq\u0000~\u00005t\u0000\u0010displayedAnswersq\u0000~\u0000?sr\u0000 com.sun"
+".msv.grammar.OneOrMoreExp\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0001\u0002\u0000\u0000xr\u0000\u001ccom.sun.msv.grammar."
+"UnaryExp\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0001\u0002\u0000\u0001L\u0000\u0003expq\u0000~\u0000\u0003xq\u0000~\u0000\u0004\u0001\u00cfN\u008appsq\u0000~\u0000\u0000\u0001\u00cfN\u0087pp\u0000sq\u0000~\u0000"
+"\u0007\u0001\u00cfN|ppsq\u0000~\u0000\u0000\u0000;\u00c2ypp\u0000sq\u0000~\u0000(\u0000;\u00c2nppsq\u0000~\u0000z\u0000;\u00c2cq\u0000~\u0000-psq\u0000~\u0000*\u0000;\u00c2`q\u0000"
+"~\u0000-psr\u00002com.sun.msv.grammar.Expression$AnyStringExpression\u0000\u0000"
+"\u0000\u0000\u0000\u0000\u0000\u0001\u0002\u0000\u0000xq\u0000~\u0000\u0004\u0000\u0000\u0000\bq\u0000~\u0000<q\u0000~\u0000\u0084sr\u0000 com.sun.msv.grammar.AnyName"
+"Class\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0001\u0002\u0000\u0000xq\u0000~\u00006q\u0000~\u0000;sq\u0000~\u00005t\u0000Ede.thorstenberger.taskmo"
+"del.complex.jaxb.McSubTaskDefType.CorrectTypet\u0000+http://java."
+"sun.com/jaxb/xjc/dummy-elementssq\u0000~\u0000(\u0001\u0093\u008b\u00feppsq\u0000~\u0000*\u0001\u0093\u008b\u00f3q\u0000~\u0000-pq"
+"\u0000~\u0000.sq\u0000~\u00005q\u0000~\u00008q\u0000~\u00009q\u0000~\u0000;sq\u0000~\u00005t\u0000\u0007correctq\u0000~\u0000?sq\u0000~\u0000(\u0003\u001c[\u00f4ppsq"
+"\u0000~\u0000z\u0003\u001c[\u00e9q\u0000~\u0000-psq\u0000~\u0000\u0000\u0003\u001c[\u00e6q\u0000~\u0000-p\u0000sq\u0000~\u0000\u0007\u0003\u001c[\u00dbppsq\u0000~\u0000\u0000\u0000;\u00c2ypp\u0000sq\u0000~"
+"\u0000(\u0000;\u00c2nppsq\u0000~\u0000z\u0000;\u00c2cq\u0000~\u0000-psq\u0000~\u0000*\u0000;\u00c2`q\u0000~\u0000-pq\u0000~\u0000\u0084q\u0000~\u0000\u0086q\u0000~\u0000;sq\u0000~\u0000"
+"5t\u0000Gde.thorstenberger.taskmodel.complex.jaxb.McSubTaskDefTyp"
+"e.IncorrectTypeq\u0000~\u0000\u0089sq\u0000~\u0000(\u0002\u00e0\u0099]ppsq\u0000~\u0000*\u0002\u00e0\u0099Rq\u0000~\u0000-pq\u0000~\u0000.sq\u0000~\u00005q"
+"\u0000~\u00008q\u0000~\u00009q\u0000~\u0000;sq\u0000~\u00005t\u0000\tincorrectq\u0000~\u0000?q\u0000~\u0000;sq\u0000~\u0000*\u0001\u00f2\u0085\u00c0ppsq\u0000~\u0000\u0014"
+"\u0001W\u00eaZppsr\u0000)com.sun.msv.datatype.xsd.EnumerationFacet\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0001\u0002"
+"\u0000\u0001L\u0000\u0006valuest\u0000\u000fLjava/util/Set;xq\u0000~\u0000Nq\u0000~\u0000?pq\u0000~\u0000#\u0000\u0000q\u0000~\u0000\u001eq\u0000~\u0000\u001et\u0000"
+"\u000benumerationsr\u0000\u0011java.util.HashSet\u00baD\u0085\u0095\u0096\u00b8\u00b74\u0003\u0000\u0000xpw\f\u0000\u0000\u0000\u0010?@\u0000\u0000\u0000\u0000\u0000\u0002"
+"t\u0000\fsingleSelectt\u0000\u000emultipleSelectxq\u0000~\u0000%sq\u0000~\u0000&t\u0000\u000estring-derive"
+"dq\u0000~\u0000?sq\u0000~\u00005t\u0000\bcategoryt\u0000\u0000sq\u0000~\u0000(\u0001^^\nppsq\u0000~\u0000*\u0001^]\u00ffq\u0000~\u0000-psq\u0000~\u0000\u0014"
+"\u0001\u000e5\u00e5ppsq\u0000~\u0000Kq\u0000~\u0000?pq\u0000~\u00003\u0000\u0000q\u0000~\u0000Uq\u0000~\u0000Uq\u0000~\u0000isq\u0000~\u0000o\u0000\u0000\u0000\u0001q\u0000~\u0000%sq\u0000~\u0000"
+"&t\u0000\u000bint-derivedq\u0000~\u0000?sq\u0000~\u00005t\u0000\u0011minCorrectAnswersq\u0000~\u0000\u00acq\u0000~\u0000;sq\u0000~"
+"\u0000(\u0001\u00d05Gppsq\u0000~\u0000*\u0001\u00d05<q\u0000~\u0000-psq\u0000~\u0000\u0014\u0001W\u008a\u00bbppq\u0000~\u0000Uq\u0000~\u0000%sq\u0000~\u0000&q\u0000~\u0000Vq\u0000~"
+"\u0000\u001fsq\u0000~\u00005t\u0000\u0011maxCorrectAnswersq\u0000~\u0000\u00acq\u0000~\u0000;sq\u0000~\u0000*\u0000\u00ec\u00cd\u00a7ppq\u0000~\u0000\u0017sq\u0000~\u0000"
+"5t\u0000\u0002idq\u0000~\u0000\u00acsq\u0000~\u0000(\u0001.7\u0010ppsq\u0000~\u0000*\u0001.7\u0005q\u0000~\u0000-pq\u0000~\u0000.sq\u0000~\u00005q\u0000~\u00008q\u0000~\u00009"
+"q\u0000~\u0000;sq\u0000~\u00005t\u0000\fmcSubTaskDefq\u0000~\u0000?sr\u0000\"com.sun.msv.grammar.Expre"
+"ssionPool\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0001\u0002\u0000\u0001L\u0000\bexpTablet\u0000/Lcom/sun/msv/grammar/Expre"
+"ssionPool$ClosedHash;xpsr\u0000-com.sun.msv.grammar.ExpressionPoo"
+"l$ClosedHash\u00d7j\u00d0N\u00ef\u00e8\u00ed\u001c\u0002\u0000\u0004I\u0000\u0005countI\u0000\tthresholdL\u0000\u0006parentq\u0000~\u0000\u00c5[\u0000\u0005"
+"tablet\u0000![Lcom/sun/msv/grammar/Expression;xp\u0000\u0000\u0000\u001e\u0000\u0000\u00009pur\u0000![Lco"
+"m.sun.msv.grammar.Expression;\u00d68D\u00c3]\u00ad\u00a7\n\u0002\u0000\u0000xp\u0000\u0000\u0000\u00bfppppq\u0000~\u0000|q\u0000~\u0000\f"
+"ppq\u0000~\u0000\u0090ppppppppppq\u0000~\u0000\u008fppppq\u0000~\u0000Cppppppq\u0000~\u0000\u008aq\u0000~\u0000\u00bfppq\u0000~\u0000\u0099q\u0000~\u0000\u00adp"
+"pppppppppppq\u0000~\u0000)ppppq\u0000~\u0000\u00b6ppppppppq\u0000~\u0000\u000bppppq\u0000~\u0000\u0011ppq\u0000~\u0000\u0010pppppp"
+"pq\u0000~\u0000\nq\u0000~\u0000\u000fpppppppppppppppppq\u0000~\u0000Bpppppq\u0000~\u0000\u000epppppppppppq\u0000~\u0000\tp"
+"ppq\u0000~\u0000@ppq\u0000~\u0000\u0013q\u0000~\u0000\u0081q\u0000~\u0000\u0095ppppppppq\u0000~\u0000\u0080q\u0000~\u0000\u0094pppppppppppppppppp"
+"q\u0000~\u0000\rppppppppppppq\u0000~\u0000uppppppppppq\u0000~\u0000Ippq\u0000~\u0000~pppq\u0000~\u0000\u0092ppppp"));
        }
        return new com.sun.msv.verifier.regexp.REDocumentDeclaration(schemaFragment);
    }

    public class Unmarshaller
        extends de.thorstenberger.taskmodel.complex.jaxb.impl.runtime.AbstractUnmarshallingEventHandlerImpl
    {


        public Unmarshaller(de.thorstenberger.taskmodel.complex.jaxb.impl.runtime.UnmarshallingContext context) {
            super(context, "----");
        }

        protected Unmarshaller(de.thorstenberger.taskmodel.complex.jaxb.impl.runtime.UnmarshallingContext context, int startState) {
            this(context);
            state = startState;
        }

        public java.lang.Object owner() {
            return de.thorstenberger.taskmodel.complex.jaxb.impl.McSubTaskDefImpl.this;
        }

        public void enterElement(java.lang.String ___uri, java.lang.String ___local, java.lang.String ___qname, org.xml.sax.Attributes __atts)
            throws org.xml.sax.SAXException
        {
            int attIdx;
            outer:
            while (true) {
                switch (state) {
                    case  3 :
                        revertToParentFromEnterElement(___uri, ___local, ___qname, __atts);
                        return ;
                    case  0 :
                        if (("mcSubTaskDef" == ___local)&&("http://complex.taskmodel.thorstenberger.de/complexTaskDef" == ___uri)) {
                            context.pushAttributes(__atts, false);
                            state = 1;
                            return ;
                        }
                        break;
                    case  1 :
                        attIdx = context.getAttribute("", "category");
                        if (attIdx >= 0) {
                            context.consumeAttribute(attIdx);
                            context.getCurrentHandler().enterElement(___uri, ___local, ___qname, __atts);
                            return ;
                        }
                        break;
                }
                super.enterElement(___uri, ___local, ___qname, __atts);
                break;
            }
        }

        public void leaveElement(java.lang.String ___uri, java.lang.String ___local, java.lang.String ___qname)
            throws org.xml.sax.SAXException
        {
            int attIdx;
            outer:
            while (true) {
                switch (state) {
                    case  3 :
                        revertToParentFromLeaveElement(___uri, ___local, ___qname);
                        return ;
                    case  2 :
                        if (("mcSubTaskDef" == ___local)&&("http://complex.taskmodel.thorstenberger.de/complexTaskDef" == ___uri)) {
                            context.popAttributes();
                            state = 3;
                            return ;
                        }
                        break;
                    case  1 :
                        attIdx = context.getAttribute("", "category");
                        if (attIdx >= 0) {
                            context.consumeAttribute(attIdx);
                            context.getCurrentHandler().leaveElement(___uri, ___local, ___qname);
                            return ;
                        }
                        break;
                }
                super.leaveElement(___uri, ___local, ___qname);
                break;
            }
        }

        public void enterAttribute(java.lang.String ___uri, java.lang.String ___local, java.lang.String ___qname)
            throws org.xml.sax.SAXException
        {
            int attIdx;
            outer:
            while (true) {
                switch (state) {
                    case  3 :
                        revertToParentFromEnterAttribute(___uri, ___local, ___qname);
                        return ;
                    case  1 :
                        if (("category" == ___local)&&("" == ___uri)) {
                            spawnHandlerFromEnterAttribute((((de.thorstenberger.taskmodel.complex.jaxb.impl.McSubTaskDefTypeImpl)de.thorstenberger.taskmodel.complex.jaxb.impl.McSubTaskDefImpl.this).new Unmarshaller(context)), 2, ___uri, ___local, ___qname);
                            return ;
                        }
                        break;
                }
                super.enterAttribute(___uri, ___local, ___qname);
                break;
            }
        }

        public void leaveAttribute(java.lang.String ___uri, java.lang.String ___local, java.lang.String ___qname)
            throws org.xml.sax.SAXException
        {
            int attIdx;
            outer:
            while (true) {
                switch (state) {
                    case  3 :
                        revertToParentFromLeaveAttribute(___uri, ___local, ___qname);
                        return ;
                    case  1 :
                        attIdx = context.getAttribute("", "category");
                        if (attIdx >= 0) {
                            context.consumeAttribute(attIdx);
                            context.getCurrentHandler().leaveAttribute(___uri, ___local, ___qname);
                            return ;
                        }
                        break;
                }
                super.leaveAttribute(___uri, ___local, ___qname);
                break;
            }
        }

        public void handleText(final java.lang.String value)
            throws org.xml.sax.SAXException
        {
            int attIdx;
            outer:
            while (true) {
                try {
                    switch (state) {
                        case  3 :
                            revertToParentFromText(value);
                            return ;
                        case  1 :
                            attIdx = context.getAttribute("", "category");
                            if (attIdx >= 0) {
                                context.consumeAttribute(attIdx);
                                context.getCurrentHandler().text(value);
                                return ;
                            }
                            break;
                    }
                } catch (java.lang.RuntimeException e) {
                    handleUnexpectedTextException(value, e);
                }
                break;
            }
        }

    }

}