package com.soulbrou.dex2c.parser

import com.soulbrou.core.io.IoUtils
import com.soulbrou.dex2c.code.DexCatchHandler
import com.soulbrou.dex2c.code.DexCodeCodec
import com.soulbrou.dex2c.code.DexDebugInfo
import com.soulbrou.dex2c.code.DebugOp
import com.soulbrou.dex2c.code.TrySpec
import com.soulbrou.dex2c.io.Leb128Reader
import com.soulbrou.dex2c.io.Mutf8
import com.soulbrou.dex2c.model.DexAnnotation
import com.soulbrou.dex2c.model.DexAnnotationSet
import com.soulbrou.dex2c.model.DexAnnotationSetRefList
import com.soulbrou.dex2c.model.DexAnnotationsDirectory
import com.soulbrou.dex2c.model.DexClassData
import com.soulbrou.dex2c.model.DexClassDef
import com.soulbrou.dex2c.model.DexDocument
import com.soulbrou.dex2c.model.DexEncodedField
import com.soulbrou.dex2c.model.DexEncodedMethod
import com.soulbrou.dex2c.model.DexEncodedValue
import com.soulbrou.dex2c.model.DexField
import com.soulbrou.dex2c.model.DexMethod
import com.soulbrou.dex2c.model.DexProto
import com.soulbrou.dex2c.model.DexString
import com.soulbrou.dex2c.model.DexType
import com.soulbrou.dex2c.model.MapItemType

/**
 * Parses a DEX file into a [DexDocument].
 *
 * The parser is strict: any structural inconsistency aborts with a
 * [DexParseException] so the engine never produces a corrupted output.
 * Supported input covers DEX versions 035 to 039 without call sites or
 * method handles, which is what all mainstream Android toolchains emit.
 */
class DexParser(private val bytes: ByteArray) {

    class DexParseException(message: String) : Exception(message)

    companion object {
        const val HEADER_SIZE = 0x70
        const val ENDIAN_TAG = 0x12345678

        private const val DBG_END_SEQUENCE = 0x00
        private const val DBG_ADVANCE_PC = 0x01
        private const val DBG_ADVANCE_LINE = 0x02
        private const val DBG_START_LOCAL = 0x03
        private const val DBG_START_LOCAL_EXTENDED = 0x04
        private const val DBG_END_LOCAL = 0x05
        private const val DBG_RESTART_LOCAL = 0x06
        private const val DBG_SET_PROLOGUE_END = 0x07
        private const val DBG_SET_EPILOGUE_BEGIN = 0x08
        private const val DBG_SET_FILE = 0x09
        private const val DBG_FIRST_SPECIAL = 0x0A
        private const val DBG_LINE_BASE = -4
        private const val DBG_LINE_RANGE = 15

        const val NO_INDEX = 0xFFFFFFFF.toInt()
    }

    private val document = DexDocument()

    // Header fields cached for parse time helpers.
    private var stringIdsOff = 0
    private var typeIdsOff = 0

    fun parse(): DexDocument {
        require(bytes.size >= HEADER_SIZE) { "File too small for a DEX header" }

        if (bytes[0] != 'd'.code.toByte() || bytes[1] != 'e'.code.toByte() ||
            bytes[2] != 'x'.code.toByte() || bytes[3] != '\n'.code.toByte()
        ) {
            throw DexParseException("Missing dex magic")
        }
        val versionText = String(bytes, 4, 3, Charsets.US_ASCII)
        val version = versionText.toIntOrNull()
            ?: throw DexParseException("Bad dex version '$versionText'")
        if (version < 35 || version > 39) {
            throw DexParseException("Unsupported dex version 0$version")
        }
        document.dexVersion = version

        val endianTag = IoUtils.u32(bytes, 40).toInt()
        if (endianTag != ENDIAN_TAG) {
            throw DexParseException("Unsupported endian tag 0x" + endianTag.toString(16))
        }

        val stringIdsSize = IoUtils.u32(bytes, 56).toInt()
        stringIdsOff = IoUtils.u32(bytes, 60).toInt()
        val typeIdsSize = IoUtils.u32(bytes, 64).toInt()
        typeIdsOff = IoUtils.u32(bytes, 68).toInt()
        val protoIdsSize = IoUtils.u32(bytes, 72).toInt()
        val protoIdsOff = IoUtils.u32(bytes, 76).toInt()
        val fieldIdsSize = IoUtils.u32(bytes, 80).toInt()
        val fieldIdsOff = IoUtils.u32(bytes, 84).toInt()
        val methodIdsSize = IoUtils.u32(bytes, 88).toInt()
        val methodIdsOff = IoUtils.u32(bytes, 92).toInt()
        val classDefsSize = IoUtils.u32(bytes, 96).toInt()
        val classDefsOff = IoUtils.u32(bytes, 100).toInt()
        val dataSize = IoUtils.u32(bytes, 104).toInt()
        val dataOff = IoUtils.u32(bytes, 108).toInt()

        if (dataOff + dataSize > bytes.size) {
            throw DexParseException("Data section exceeds file bounds")
        }

        // Refuse unsupported 038+ structures so nothing is silently lost.
        val mapOff = IoUtils.u32(bytes, 52).toInt()
        if (mapOff != 0) {
            var mapIndex = mapOff
            val mapSize = IoUtils.u32(bytes, mapOff).toInt()
            repeat(mapSize) {
                val type = IoUtils.u16(bytes, mapIndex + 4)
                val size = IoUtils.u32(bytes, mapIndex + 12).toInt()
                if ((type == MapItemType.CALL_SITE_ID || type == MapItemType.METHOD_HANDLE) && size > 0) {
                    throw DexParseException(
                        "DEX file uses call sites or method handles (invoke-custom), " +
                            "not supported in this version",
                    )
                }
                mapIndex += 12
            }
        }

        // ---- String ids ----
        val strings = arrayOfNulls<DexString>(stringIdsSize)
        for (i in 0 until stringIdsSize) {
            strings[i] = internStringAt(i)
        }

        // ---- Type ids ----
        val types = arrayOfNulls<DexType>(typeIdsSize)
        for (i in 0 until typeIdsSize) {
            val descriptorIdx = IoUtils.u16(bytes, typeIdsOff + i * 4)
            types[i] = document.internType(strings[descriptorIdx]!!.value)
        }

        // ---- Proto ids ----
        val protos = arrayOfNulls<DexProto>(protoIdsSize)
        for (i in 0 until protoIdsSize) {
            val shortyIdx = IoUtils.u32(bytes, protoIdsOff + i * 12).toInt()
            val returnTypeIdx = IoUtils.u32(bytes, protoIdsOff + i * 12 + 4).toInt()
            val paramsOff = IoUtils.u32(bytes, protoIdsOff + i * 12 + 8).toInt()
            val parameters = readTypeList(paramsOff).map { types[it]!! }
            protos[i] = document.internProto(
                shorty = strings[shortyIdx]!!.value,
                returnType = types[returnTypeIdx]!!,
                parameters = parameters,
            )
        }

        // ---- Field ids ----
        val fields = arrayOfNulls<DexField>(fieldIdsSize)
        for (i in 0 until fieldIdsSize) {
            val classIdx = IoUtils.u16(bytes, fieldIdsOff + i * 8)
            val typeIdx = IoUtils.u16(bytes, fieldIdsOff + i * 8 + 2)
            val nameIdx = IoUtils.u32(bytes, fieldIdsOff + i * 8 + 4).toInt()
            fields[i] = document.internField(
                declaringClass = types[classIdx]!!,
                name = strings[nameIdx]!!.value,
                type = types[typeIdx]!!,
            )
        }

        // ---- Method ids ----
        val methods = arrayOfNulls<DexMethod>(methodIdsSize)
        for (i in 0 until methodIdsSize) {
            val classIdx = IoUtils.u16(bytes, methodIdsOff + i * 8)
            val protoIdx = IoUtils.u16(bytes, methodIdsOff + i * 8 + 2)
            val nameIdx = IoUtils.u32(bytes, methodIdsOff + i * 8 + 4).toInt()
            methods[i] = document.internMethod(
                declaringClass = types[classIdx]!!,
                name = strings[nameIdx]!!.value,
                proto = protos[protoIdx]!!,
            )
        }

        document.installParseIndexes(
            strings = strings.map { it!! },
            types = types.map { it!! },
            protos = protos.map { it!! },
            fields = fields.map { it!! },
            methods = methods.map { it!! },
        )

        val codec = DexCodeCodec(document)

        // ---- Class defs ----
        for (i in 0 until classDefsSize) {
            val base = classDefsOff + i * 32
            val classIdx = IoUtils.u32(bytes, base).toInt()
            val accessFlags = IoUtils.u32(bytes, base + 4).toInt()
            val superclassIdx = IoUtils.u32(bytes, base + 8).toInt()
            val interfacesOff = IoUtils.u32(bytes, base + 12).toInt()
            val sourceFileIdx = IoUtils.u32(bytes, base + 16).toInt()
            val annotationsOff = IoUtils.u32(bytes, base + 20).toInt()
            val classDataOff = IoUtils.u32(bytes, base + 24).toInt()
            val staticValuesOff = IoUtils.u32(bytes, base + 28).toInt()

            val classData = if (classDataOff != 0) {
                readClassData(classDataOff, fields, methods, codec)
            } else {
                null
            }

            val staticValues = if (staticValuesOff != 0) {
                val reader = Leb128Reader(bytes)
                reader.offset = staticValuesOff
                readEncodedArray(reader, strings, types, fields, protos, methods)
            } else {
                null
            }

            val annotationsDirectory = if (annotationsOff != 0) {
                readAnnotationsDirectory(annotationsOff, fields, methods, strings, types, protos)
            } else {
                null
            }

            val classDef = DexClassDef(
                type = types[classIdx]!!,
                accessFlags = accessFlags,
                superclass = if (superclassIdx != NO_INDEX) types[superclassIdx] else null,
                interfaces = readTypeList(interfacesOff).map { types[it]!! },
                sourceFile = if (sourceFileIdx != NO_INDEX) strings[sourceFileIdx] else null,
                annotationsDirectory = annotationsDirectory,
                staticValues = staticValues,
                classData = classData,
            )
            document.classes.intern(classDef)
        }

        document.clearParseIndexes()
        return document
    }

    private object NoIndex {
        const val VALUE = 0xFFFFFFFF.toInt()
    }

    /** Reads a type_list, returning the type indices. */
    private fun readTypeList(offset: Int): List<Int> {
        if (offset == 0) return emptyList()
        val size = IoUtils.u32(bytes, offset).toInt()
        return (0 until size).map { IoUtils.u16(bytes, offset + 4 + it * 2) }
    }

    /** Reads a class_data_item including decoding every method body. */
    private fun readClassData(
        offset: Int,
        fields: Array<DexField?>,
        methods: Array<DexMethod?>,
        codec: DexCodeCodec,
    ): DexClassData {
        val reader = Leb128Reader(bytes)
        reader.offset = offset

        fun readFields(count: Int): List<DexEncodedField> {
            var fieldIdx = 0
            val result = ArrayList<DexEncodedField>(count)
            repeat(count) {
                fieldIdx += reader.readUnsignedLeb128()
                val access = reader.readUnsignedLeb128()
                result.add(DexEncodedField(fields[fieldIdx]!!, access))
            }
            return result
        }

        fun readMethods(count: Int): MutableList<DexEncodedMethod> {
            var methodIdx = 0
            val result = ArrayList<DexEncodedMethod>(count)
            repeat(count) {
                methodIdx += reader.readUnsignedLeb128()
                val access = reader.readUnsignedLeb128()
                val codeOff = reader.readUnsignedLeb128()
                val code = if (codeOff != 0) readCodeItem(codeOff, codec) else null
                result.add(DexEncodedMethod(methods[methodIdx]!!, access, code))
            }
            return result
        }

        val staticFieldsCount = reader.readUnsignedLeb128()
        val instanceFieldsCount = reader.readUnsignedLeb128()
        val directMethodsCount = reader.readUnsignedLeb128()
        val virtualMethodsCount = reader.readUnsignedLeb128()

        return DexClassData(
            staticFields = readFields(staticFieldsCount),
            instanceFields = readFields(instanceFieldsCount),
            directMethods = readMethods(directMethodsCount),
            virtualMethods = readMethods(virtualMethodsCount),
        )
    }

    /** Reads a code_item and decodes its instruction stream. */
    private fun readCodeItem(offset: Int, codec: DexCodeCodec): com.soulbrou.dex2c.code.DexCode {
        val registersSize = IoUtils.u16(bytes, offset)
        val insSize = IoUtils.u16(bytes, offset + 2)
        val outsSize = IoUtils.u16(bytes, offset + 4)
        val triesSize = IoUtils.u16(bytes, offset + 6)
        val debugInfoOff = IoUtils.u32(bytes, offset + 8).toInt()
        val insnsSize = IoUtils.u32(bytes, offset + 12).toInt()

        val units = IntArray(insnsSize) { i -> IoUtils.u16(bytes, offset + 16 + i * 2) }
        val debugInfo = if (debugInfoOff != 0) readDebugInfo(debugInfoOff) else null

        val triesSpec = ArrayList<TrySpec>(triesSize)
        if (triesSize > 0) {
            var cursor = offset + 16 + insnsSize * 2
            if (insnsSize % 2 == 1) {
                cursor += 2 // padding unit between insns and tries
            }

            val handlersListOff = cursor + triesSize * 8

            // Parse the handler list first: offset (from list start) -> handler.
            val handlerByOffset = HashMap<Int, DexCatchHandler>()
            val handlerReader = Leb128Reader(bytes)
            handlerReader.offset = handlersListOff
            val handlerListSize = handlerReader.readUnsignedLeb128()
            repeat(handlerListSize) {
                val handlerOffset = handlerReader.offset - handlersListOff
                val sizeField = handlerReader.readSignedLeb128()
                val count = Math.abs(sizeField)
                val typedEntries = ArrayList<com.soulbrou.dex2c.code.DexCatchEntry>(count)
                repeat(count) {
                    val typeIdx = handlerReader.readUnsignedLeb128()
                    val addr = handlerReader.readUnsignedLeb128()
                    typedEntries.add(
                        com.soulbrou.dex2c.code.DexCatchEntry(
                            document.internType(descriptorOfType(typeIdx)),
                            addr,
                        ),
                    )
                }
                val catchAll = if (sizeField <= 0) handlerReader.readUnsignedLeb128() else null
                handlerByOffset[handlerOffset] = DexCatchHandler(typedEntries, catchAll)
            }

            for (i in 0 until triesSize) {
                val startAddr = IoUtils.u32(bytes, cursor + i * 8).toInt()
                val insnCount = IoUtils.u16(bytes, cursor + i * 8 + 4)
                val handlerOff = IoUtils.u16(bytes, cursor + i * 8 + 6)
                val handler = handlerByOffset[handlerOff]
                    ?: throw DexParseException("Try references unknown handler offset $handlerOff")
                triesSpec.add(TrySpec(startAddr, insnCount, handler))
            }
        }

        return codec.decode(
            registersSize = registersSize,
            insSize = insSize,
            outsSize = outsSize,
            debugInfo = debugInfo,
            units = units,
            triesSpec = triesSpec,
        )
    }

    /** Reads a debug_info_item. */
    private fun readDebugInfo(offset: Int): DexDebugInfo {
        val reader = Leb128Reader(bytes)
        reader.offset = offset
        val lineStart = reader.readUnsignedLeb128()
        val parameterCount = reader.readUnsignedLeb128()
        val parameterNames = ArrayList<DexString?>(parameterCount)
        repeat(parameterCount) {
            val nameIdx = reader.readUnsignedLeb128()
            parameterNames.add(if (nameIdx == 0) null else internStringAt(nameIdx))
        }

        val ops = ArrayList<DebugOp>(16)
        loop@ while (true) {
            val opcode = bytes[reader.offset++].toInt() and 0xFF
            when {
                opcode == DBG_END_SEQUENCE -> break@loop
                opcode == DBG_ADVANCE_PC -> ops.add(DebugOp.AdvancePc(reader.readUnsignedLeb128()))
                opcode == DBG_ADVANCE_LINE -> ops.add(DebugOp.AdvanceLine(reader.readSignedLeb128()))
                opcode == DBG_START_LOCAL -> {
                    val register = reader.readUnsignedLeb128()
                    val nameIdx = reader.readUnsignedLeb128()
                    val typeIdx = reader.readUnsignedLeb128()
                    ops.add(DebugOp.StartLocal(register, optionalString(nameIdx), optionalType(typeIdx)))
                }
                opcode == DBG_START_LOCAL_EXTENDED -> {
                    val register = reader.readUnsignedLeb128()
                    val nameIdx = reader.readUnsignedLeb128()
                    val typeIdx = reader.readUnsignedLeb128()
                    val sigIdx = reader.readUnsignedLeb128()
                    ops.add(
                        DebugOp.StartLocalExtended(
                            register,
                            optionalString(nameIdx),
                            optionalType(typeIdx),
                            optionalString(sigIdx),
                        ),
                    )
                }
                opcode == DBG_END_LOCAL -> ops.add(DebugOp.EndLocal(reader.readUnsignedLeb128()))
                opcode == DBG_RESTART_LOCAL -> ops.add(DebugOp.RestartLocal(reader.readUnsignedLeb128()))
                opcode == DBG_SET_PROLOGUE_END -> ops.add(DebugOp.SetPrologueEnd)
                opcode == DBG_SET_EPILOGUE_BEGIN -> ops.add(DebugOp.SetEpilogueBegin)
                opcode == DBG_SET_FILE -> ops.add(DebugOp.SetFile(optionalString(reader.readUnsignedLeb128())))
                else -> {
                    // Special opcode: decodes into explicit advance ops.
                    val adjusted = opcode - DBG_FIRST_SPECIAL
                    ops.add(DebugOp.AdvancePc(adjusted / DBG_LINE_RANGE))
                    ops.add(DebugOp.AdvanceLine(DBG_LINE_BASE + adjusted % DBG_LINE_RANGE))
                }
            }
        }
        return DexDebugInfo(lineStart, parameterNames, ops)
    }

    /** Interns the string located at the given string_id index. */
    private fun internStringAt(index: Int): DexString {
        val dataOffItem = IoUtils.u32(bytes, stringIdsOff + index * 4).toInt()
        val reader = Leb128Reader(bytes)
        reader.offset = dataOffItem
        val utf16Length = reader.readUnsignedLeb128()
        return document.internString(Mutf8.decode(bytes, reader.offset, utf16Length))
    }

    private fun descriptorOfType(typeIdx: Int): String {
        val descriptorStrIdx = IoUtils.u16(bytes, typeIdsOff + typeIdx * 4)
        val dataOffItem = IoUtils.u32(bytes, stringIdsOff + descriptorStrIdx * 4).toInt()
        val reader = Leb128Reader(bytes)
        reader.offset = dataOffItem
        val utf16Length = reader.readUnsignedLeb128()
        return Mutf8.decode(bytes, reader.offset, utf16Length)
    }

    private fun optionalString(index: Int): DexString? =
        if (index == 0) null else internStringAt(index)

    private fun optionalType(index: Int): DexType? =
        if (index == 0) null else document.internType(descriptorOfType(index))

    /** Reads an encoded_array (used for static values). */
    private fun readEncodedArray(
        reader: Leb128Reader,
        strings: Array<DexString?>,
        types: Array<DexType?>,
        fields: Array<DexField?>,
        protos: Array<DexProto?>,
        methods: Array<DexMethod?>,
    ): List<DexEncodedValue> {
        val size = reader.readUnsignedLeb128()
        return (0 until size).map { readEncodedValue(reader, strings, types, fields, protos, methods) }
    }

    /** Reads one encoded_value. */
    private fun readEncodedValue(
        reader: Leb128Reader,
        strings: Array<DexString?>,
        types: Array<DexType?>,
        fields: Array<DexField?>,
        protos: Array<DexProto?>,
        methods: Array<DexMethod?>,
    ): DexEncodedValue {
        val argAndType = bytes[reader.offset++].toInt() and 0xFF
        val type = argAndType and 0x1F
        val arg = (argAndType shr 5) and 0x07

        fun readUnsigned(size: Int): Long {
            var result = 0L
            for (i in 0 until size) {
                result = result or ((bytes[reader.offset + i].toLong() and 0xFF) shl (i * 8))
            }
            reader.offset += size
            return result
        }

        fun readSigned(size: Int): Long {
            var result = readUnsigned(size)
            val bits = size * 8
            if (bits < 64) {
                val shift = 64 - bits
                result = (result shl shift) shr shift
            }
            return result
        }

        return when (type) {
            0x00 -> DexEncodedValue.ByteValue(readSigned(arg + 1).toByte())
            0x02 -> DexEncodedValue.ShortValue(readSigned(arg + 1).toShort())
            0x03 -> DexEncodedValue.CharValue(readUnsigned(arg + 1).toInt().toChar())
            0x04 -> DexEncodedValue.IntValue(readSigned(arg + 1).toInt())
            0x06 -> DexEncodedValue.LongValue(readSigned(arg + 1))
            0x10 -> DexEncodedValue.FloatValue(readUnsigned(arg + 1).toInt())
            0x11 -> DexEncodedValue.DoubleValue(readUnsigned(arg + 1))
            0x15 -> DexEncodedValue.MethodTypeValue(protos[readUnsigned(arg + 1).toInt()]!!)
            0x16 -> throw DexParseException("Method handle encoded values are not supported")
            0x17 -> DexEncodedValue.StringValue(strings[readUnsigned(arg + 1).toInt()]!!)
            0x18 -> DexEncodedValue.TypeValue(types[readUnsigned(arg + 1).toInt()]!!)
            0x19 -> DexEncodedValue.FieldValue(fields[readUnsigned(arg + 1).toInt()]!!)
            0x1A -> DexEncodedValue.MethodValue(methods[readUnsigned(arg + 1).toInt()]!!)
            0x1B -> DexEncodedValue.EnumValue(fields[readUnsigned(arg + 1).toInt()]!!)
            0x1C -> DexEncodedValue.ArrayValue(
                (0 until reader.readUnsignedLeb128()).map {
                    readEncodedValue(reader, strings, types, fields, protos, methods)
                },
            )
            0x1D -> readEncodedAnnotation(reader, strings, types, fields, protos, methods)
            0x1E -> DexEncodedValue.NullValue
            0x1F -> DexEncodedValue.BooleanValue(arg != 0)
            else -> throw DexParseException("Unsupported encoded value type 0x" + type.toString(16))
        }
    }

    private fun readEncodedAnnotation(
        reader: Leb128Reader,
        strings: Array<DexString?>,
        types: Array<DexType?>,
        fields: Array<DexField?>,
        protos: Array<DexProto?>,
        methods: Array<DexMethod?>,
    ): DexEncodedValue.AnnotationValue {
        val typeIdx = reader.readUnsignedLeb128()
        val size = reader.readUnsignedLeb128()
        val elements = (0 until size).map {
            val nameIdx = reader.readUnsignedLeb128()
            strings[nameIdx]!! to readEncodedValue(reader, strings, types, fields, protos, methods)
        }
        return DexEncodedValue.AnnotationValue(types[typeIdx]!!, elements)
    }

    /** Reads the annotations directory of one class. */
    private fun readAnnotationsDirectory(
        offset: Int,
        fields: Array<DexField?>,
        methods: Array<DexMethod?>,
        strings: Array<DexString?>,
        types: Array<DexType?>,
        protos: Array<DexProto?>,
    ): DexAnnotationsDirectory {
        val classAnnotationsOff = IoUtils.u32(bytes, offset).toInt()
        val annotatedFields = IoUtils.u32(bytes, offset + 4).toInt()
        val annotatedMethods = IoUtils.u32(bytes, offset + 8).toInt()
        val annotatedParameters = IoUtils.u32(bytes, offset + 12).toInt()

        val classAnnotations = if (classAnnotationsOff != 0) {
            readAnnotationSet(classAnnotationsOff, strings, types, fields, protos, methods)
        } else {
            null
        }

        val fieldAnnotations = (0 until annotatedFields).map { i ->
            val base = offset + 16 + i * 8
            val fieldIdx = IoUtils.u32(bytes, base).toInt()
            val setOff = IoUtils.u32(bytes, base + 4).toInt()
            fields[fieldIdx]!! to readAnnotationSet(setOff, strings, types, fields, protos, methods)
        }

        val methodAnnotations = (0 until annotatedMethods).map { i ->
            val base = offset + 16 + annotatedFields * 8 + i * 8
            val methodIdx = IoUtils.u32(bytes, base).toInt()
            val setOff = IoUtils.u32(bytes, base + 4).toInt()
            methods[methodIdx]!! to readAnnotationSet(setOff, strings, types, fields, protos, methods)
        }

        val parameterAnnotations = (0 until annotatedParameters).map { i ->
            val base = offset + 16 + (annotatedFields + annotatedMethods) * 8 + i * 8
            val methodIdx = IoUtils.u32(bytes, base).toInt()
            val refListOff = IoUtils.u32(bytes, base + 4).toInt()
            methods[methodIdx]!! to readAnnotationSetRefList(refListOff, strings, types, fields, protos, methods)
        }

        return DexAnnotationsDirectory(classAnnotations, fieldAnnotations, methodAnnotations, parameterAnnotations)
    }

    private fun readAnnotationSet(
        offset: Int,
        strings: Array<DexString?>,
        types: Array<DexType?>,
        fields: Array<DexField?>,
        protos: Array<DexProto?>,
        methods: Array<DexMethod?>,
    ): DexAnnotationSet {
        val size = IoUtils.u32(bytes, offset).toInt()
        val annotations = (0 until size).map { i ->
            val itemOff = IoUtils.u32(bytes, offset + 4 + i * 4).toInt()
            val visibility = bytes[itemOff].toInt() and 0xFF
            val reader = Leb128Reader(bytes)
            reader.offset = itemOff + 1
            val annotation = readEncodedAnnotation(reader, strings, types, fields, protos, methods)
            DexAnnotation(visibility, annotation.type, annotation.elements)
        }
        return DexAnnotationSet(annotations)
    }

    private fun readAnnotationSetRefList(
        offset: Int,
        strings: Array<DexString?>,
        types: Array<DexType?>,
        fields: Array<DexField?>,
        protos: Array<DexProto?>,
        methods: Array<DexMethod?>,
    ): DexAnnotationSetRefList {
        val size = IoUtils.u32(bytes, offset).toInt()
        val refs = (0 until size).map { i ->
            val setOff = IoUtils.u32(bytes, offset + 4 + i * 4).toInt()
            if (setOff == 0) null else readAnnotationSet(setOff, strings, types, fields, protos, methods)
        }
        return DexAnnotationSetRefList(refs)
    }
}
