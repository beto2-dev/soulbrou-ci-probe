package com.soulbrou.dex2c.model

/**
 * An encoded_value, used both by static field initial values and by
 * annotations. The runtime types are preserved so the writer can pick the
 * canonical smallest encoding.
 */
sealed class DexEncodedValue {
    data class ByteValue(val value: Byte) : DexEncodedValue()
    data class ShortValue(val value: Short) : DexEncodedValue()
    data class CharValue(val value: Char) : DexEncodedValue()
    data class IntValue(val value: Int) : DexEncodedValue()
    data class LongValue(val value: Long) : DexEncodedValue()
    data class FloatValue(val bits: Int) : DexEncodedValue()
    data class DoubleValue(val bits: Long) : DexEncodedValue()
    data class MethodTypeValue(val proto: DexProto) : DexEncodedValue()
    data class MethodHandleValue(val handle: DexMethodHandle) : DexEncodedValue()
    data class StringValue(val value: DexString) : DexEncodedValue()
    data class TypeValue(val value: DexType) : DexEncodedValue()
    data class FieldValue(val value: DexField) : DexEncodedValue()
    data class MethodValue(val value: DexMethod) : DexEncodedValue()
    data class EnumValue(val value: DexField) : DexEncodedValue()
    data class ArrayValue(val values: List<DexEncodedValue>) : DexEncodedValue()
    data class AnnotationValue(
        val type: DexType,
        val elements: List<Pair<DexString, DexEncodedValue>>,
    ) : DexEncodedValue()

    data object NullValue : DexEncodedValue()
    data class BooleanValue(val value: Boolean) : DexEncodedValue()
}

/** A method handle as defined by the DEX format. */
class DexMethodHandle(
    val handleType: Int,
    val field: DexField?,
    val method: DexMethod?,
)

/** A call site item. */
class DexCallSite(
    val methodHandle: DexMethodHandle,
    val methodName: DexString,
    val methodProto: DexProto,
    val linkerArgs: List<DexEncodedValue>,
)

/** An annotation instance with visibility. */
class DexAnnotation(
    val visibility: Int,
    val type: DexType,
    val elements: List<Pair<DexString, DexEncodedValue>>,
)

/** An annotation set: a list of annotation offsets. */
class DexAnnotationSet(
    val annotations: List<DexAnnotation>,
)

/** An annotation set reference list used for parameter annotations. */
class DexAnnotationSetRefList(
    val refs: List<DexAnnotationSet?>,
)

/** The annotations directory of one class. */
class DexAnnotationsDirectory(
    val classAnnotations: DexAnnotationSet?,
    val fieldAnnotations: List<Pair<DexField, DexAnnotationSet>>,
    val methodAnnotations: List<Pair<DexMethod, DexAnnotationSet>>,
    val parameterAnnotations: List<Pair<DexMethod, DexAnnotationSetRefList>>,
)

/** One entry of the map list. */
class DexMapEntry(
    val type: Int,
    val unused: Int,
    var offset: Int,
    var size: Int,
)

/** DEX map item type constants. */
object MapItemType {
    const val HEADER = 0x0000
    const val STRING_ID = 0x0001
    const val TYPE_ID = 0x0002
    const val PROTO_ID = 0x0003
    const val FIELD_ID = 0x0004
    const val METHOD_ID = 0x0005
    const val CLASS_DEF = 0x0006
    const val CALL_SITE_ID = 0x0007
    const val METHOD_HANDLE = 0x0008
    const val MAP_LIST = 0x1000
    const val TYPE_LIST = 0x1001
    const val ANNOTATION_SET_REF_LIST = 0x1002
    const val ANNOTATION_SET = 0x1003
    const val CLASS_DATA = 0x2000
    const val CODE = 0x2001
    const val STRING_DATA = 0x2002
    const val DEBUG_INFO = 0x2003
    const val ANNOTATION = 0x2004
    const val ENCODED_ARRAY = 0x2005
    const val ANNOTATIONS_DIRECTORY = 0x2006
}
