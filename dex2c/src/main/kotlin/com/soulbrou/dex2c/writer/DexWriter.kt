package com.soulbrou.dex2c.writer

import com.soulbrou.dex2c.code.DexCatchHandler
import com.soulbrou.dex2c.code.DexCode
import com.soulbrou.dex2c.code.DexCodeCodec
import com.soulbrou.dex2c.code.DexDebugInfo
import com.soulbrou.dex2c.code.DebugOp
import com.soulbrou.dex2c.io.Leb128Writer
import com.soulbrou.dex2c.io.Mutf8
import com.soulbrou.dex2c.model.DexAnnotation
import com.soulbrou.dex2c.model.DexAnnotationSet
import com.soulbrou.dex2c.model.DexAnnotationSetRefList
import com.soulbrou.dex2c.model.DexAnnotationsDirectory
import com.soulbrou.dex2c.model.DexClassDef
import com.soulbrou.dex2c.model.DexClassData
import com.soulbrou.dex2c.model.DexDocument
import com.soulbrou.dex2c.model.DexEncodedValue
import com.soulbrou.dex2c.model.DexMapEntry
import com.soulbrou.dex2c.model.DexType
import com.soulbrou.dex2c.model.MapItemType
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.util.zip.Adler32

/**
 * Re emits a [DexDocument] as a complete DEX file.
 *
 * The writer rebuilds every section from the document model: identifier
 * tables are sorted per the DEX specification, all offsets are recomputed and
 * the map list, SHA-1 signature and adler32 checksum are generated from
 * scratch. Because every index is resolved through the model, any mutation
 * performed before the write is reflected consistently in instruction
 * operands, debug information, annotations and class data alike.
 *
 * Data section phases (each map type is emitted contiguously):
 * string data, encoded arrays, type lists, annotation items, annotation
 * sets, annotation set ref lists, annotations directories, debug info, code
 * items, class data, map list.
 */
class DexWriter(private val document: DexDocument) {

    /** Growable little endian sink that tracks absolute offsets. */
    private class Sink {
        val buffer = ByteArrayOutputStream(1 shl 20)

        val length: Int get() = buffer.size()

        fun u1(v: Int) {
            buffer.write(v and 0xFF)
        }

        fun u2(v: Int) {
            buffer.write(v and 0xFF)
            buffer.write((v shr 8) and 0xFF)
        }

        fun u4(v: Long) {
            buffer.write((v and 0xFF).toInt())
            buffer.write(((v shr 8) and 0xFF).toInt())
            buffer.write(((v shr 16) and 0xFF).toInt())
            buffer.write(((v shr 24) and 0xFF).toInt())
        }

        fun u4(v: Int) = u4(v.toLong())

        fun write(chunk: ByteArray) {
            buffer.write(chunk)
        }

        fun padTo(size: Int) {
            while (buffer.size() < size) {
                buffer.write(0)
            }
        }

        fun toByteArray(): ByteArray = buffer.toByteArray()
    }

    private val data = Sink()
    private val mapEntries = ArrayList<DexMapEntry>(14)

    private var dataOff = 0

    fun write(): ByteArray {
        sortAndSeal()

        // Id section offsets follow the fixed size header directly.
        val stringIdsOff = 0x70
        val typeIdsOff = stringIdsOff + document.strings.size * 4
        val protoIdsOff = typeIdsOff + document.types.size * 4
        val fieldIdsOff = protoIdsOff + document.protos.size * 12
        val methodIdsOff = fieldIdsOff + document.fields.size * 8
        val classDefsOff = methodIdsOff + document.methods.size * 8
        dataOff = align(classDefsOff + document.classes.size * 32, 4)

        emitStringData()
        emitEncodedArrays()
        emitTypeLists()
        emitAnnotations()
        emitDebugInfos()
        emitCodeItems()
        emitClassData()
        val mapOffset = emitMapList()

        val headerAndIds = buildIdSections(
            stringIdsOff,
            typeIdsOff,
            protoIdsOff,
            fieldIdsOff,
            methodIdsOff,
            classDefsOff,
            mapOffset,
        )

        return assemble(headerAndIds)
    }

    private fun align(value: Int, alignment: Int): Int =
        (value + alignment - 1) / alignment * alignment

    private fun sortAndSeal() {
        document.unseal()
        document.strings.sortWith(compareBy { it.value })
        document.types.sortWith(compareBy { it.descriptor.value })
        document.protos.sortWith(
            compareBy(
                { it.returnType.descriptor.value },
                { it.parameters.joinToString(",") { p -> p.descriptor.value } },
            ),
        )
        document.fields.sortWith(
            compareBy(
                { it.declaringClass.descriptor.value },
                { it.name.value },
                { it.type.descriptor.value },
            ),
        )
        document.methods.sortWith(
            compareBy(
                { it.declaringClass.descriptor.value },
                { it.name.value },
                { it.proto.returnType.descriptor.value },
                { it.proto.parameters.joinToString(",") { p -> p.descriptor.value } },
            ),
        )
        document.strings.seal()
        document.types.seal()
        document.protos.seal()
        document.fields.seal()
        document.methods.seal()
        document.classes.seal()
    }

    private fun phase(type: Int, emit: () -> Int): Int {
        val entry = DexMapEntry(type, 0, dataOff + data.length, 0)
        val count = emit()
        if (count > 0) {
            entry.size = count
            mapEntries.add(entry)
        }
        return count
    }

    /** Aligns the sink to a 4 byte boundary, returning the aligned offset. */
    private fun align4(): Int {
        val current = dataOff + data.length
        val aligned = align(current, 4)
        data.padTo(aligned - dataOff)
        return aligned
    }

    // ------------------------------------------------------------------
    // Data section phases
    // ------------------------------------------------------------------

    private fun emitStringData() {
        phase(MapItemType.STRING_DATA) {
            for (item in document.strings) {
                item.dataOffset = (dataOff + data.length).toLong()
                data.write(Leb128Writer.writeUnsignedLeb128(item.value.length))
                data.write(Mutf8.encode(item.value))
            }
            document.strings.size
        }
    }

    private val encodedArrayOffsets = HashMap<DexClassDef, Int>()

    private fun emitEncodedArrays() {
        phase(MapItemType.ENCODED_ARRAY) {
            var count = 0
            for (classDef in document.classes) {
                val values = classDef.staticValues ?: continue
                if (values.isEmpty()) continue
                encodedArrayOffsets[classDef] = dataOff + data.length
                data.write(Leb128Writer.writeUnsignedLeb128(values.size))
                for (value in values) {
                    writeEncodedValue(value)
                }
                count++
            }
            count
        }
    }

    private val typeListOffsets = HashMap<String, Int>()

    private fun typeListKey(types: List<DexType>): String =
        types.joinToString(",") { it.descriptor.value }

    private fun emitTypeLists() {
        phase(MapItemType.TYPE_LIST) {
            val unique = LinkedHashMap<String, List<DexType>>()
            for (proto in document.protos) {
                if (proto.parameters.isEmpty()) continue
                unique[typeListKey(proto.parameters)] = proto.parameters
            }
            for (classDef in document.classes) {
                if (classDef.interfaces.isEmpty()) continue
                unique[typeListKey(classDef.interfaces)] = classDef.interfaces
            }
            for ((key, types) in unique) {
                align4()
                typeListOffsets[key] = dataOff + data.length
                // type_list.size is a plain u4 per the DEX specification.
                data.u4(types.size)
                for (type in types) {
                    data.u2(document.typeIndexOf(type))
                }
            }
            unique.size
        }
    }

    private fun typeListOffset(types: List<DexType>): Int {
        if (types.isEmpty()) return 0
        return typeListOffsets[typeListKey(types)] ?: error("Type list not emitted")
    }

    private val annotationItemOffsets = HashMap<DexAnnotation, Int>()
    private val annotationSetOffsets = HashMap<DexAnnotationSet, Int>()
    private val refListOffsets = HashMap<DexAnnotationSetRefList, Int>()
    private val directoryOffsets = HashMap<DexAnnotationsDirectory, Int>()

    private fun emitAnnotations() {
        // Collect the unique structures reachable from class definitions.
        val annotations = LinkedHashMap<DexAnnotation, DexAnnotation>()
        val sets = LinkedHashMap<DexAnnotationSet, DexAnnotationSet>()
        val refLists = LinkedHashMap<DexAnnotationSetRefList, DexAnnotationSetRefList>()
        val directories = LinkedHashMap<DexAnnotationsDirectory, DexAnnotationsDirectory>()
        for (classDef in document.classes) {
            val directory = classDef.annotationsDirectory ?: continue
            directories[directory] = directory
            directory.classAnnotations?.let { sets[it] = it }
            for ((_, set) in directory.fieldAnnotations) sets[set] = set
            for ((_, set) in directory.methodAnnotations) sets[set] = set
            for ((_, refs) in directory.parameterAnnotations) refLists[refs] = refs
            for (ref in refsOf(directory)) {
                ref?.let { sets[it] = it }
            }
        }
        for (set in sets.values) {
            for (annotation in set.annotations) annotations[annotation] = annotation
        }

        phase(MapItemType.ANNOTATION) {
            for (annotation in annotations.values) {
                annotationItemOffsets[annotation] = dataOff + data.length
                data.u1(annotation.visibility)
                data.write(Leb128Writer.writeUnsignedLeb128(document.typeIndexOf(annotation.type)))
                data.write(Leb128Writer.writeUnsignedLeb128(annotation.elements.size))
                for ((name, value) in annotation.elements) {
                    data.write(Leb128Writer.writeUnsignedLeb128(document.stringIndexOf(name)))
                    writeEncodedValue(value)
                }
            }
            annotations.size
        }

        phase(MapItemType.ANNOTATION_SET) {
            for (set in sets.values) {
                align4()
                annotationSetOffsets[set] = dataOff + data.length
                data.u4(set.annotations.size.toLong())
                for (annotation in set.annotations) {
                    data.u4(annotationItemOffsets[annotation]!!.toLong())
                }
            }
            sets.size
        }

        phase(MapItemType.ANNOTATION_SET_REF_LIST) {
            for (refList in refLists.values) {
                align4()
                refListOffsets[refList] = dataOff + data.length
                data.u4(refList.refs.size.toLong())
                for (ref in refList.refs) {
                    data.u4(ref?.let { annotationSetOffsets[it] ?: 0 }?.toLong() ?: 0L)
                }
            }
            refLists.size
        }

        phase(MapItemType.ANNOTATIONS_DIRECTORY) {
            for (directory in directories.values) {
                align4()
                directoryOffsets[directory] = dataOff + data.length
                data.u4(directory.classAnnotations?.let { annotationSetOffsets[it] ?: 0 }?.toLong() ?: 0L)
                data.write(Leb128Writer.writeUnsignedLeb128(directory.fieldAnnotations.size))
                data.write(Leb128Writer.writeUnsignedLeb128(directory.methodAnnotations.size))
                data.write(Leb128Writer.writeUnsignedLeb128(directory.parameterAnnotations.size))
                for ((field, set) in directory.fieldAnnotations.sortedBy { document.fieldIndexOf(it.first) }) {
                    data.write(Leb128Writer.writeUnsignedLeb128(document.fieldIndexOf(field)))
                    data.write(Leb128Writer.writeUnsignedLeb128(annotationSetOffsets[set] ?: 0))
                }
                for ((method, set) in directory.methodAnnotations.sortedBy { document.methodIndexOf(it.first) }) {
                    data.write(Leb128Writer.writeUnsignedLeb128(document.methodIndexOf(method)))
                    data.write(Leb128Writer.writeUnsignedLeb128(annotationSetOffsets[set] ?: 0))
                }
                for ((method, refs) in directory.parameterAnnotations.sortedBy { document.methodIndexOf(it.first) }) {
                    data.write(Leb128Writer.writeUnsignedLeb128(document.methodIndexOf(method)))
                    data.write(Leb128Writer.writeUnsignedLeb128(refListOffsets[refs] ?: 0))
                }
            }
            directories.size
        }
    }

    private fun refsOf(directory: DexAnnotationsDirectory): List<DexAnnotationSet?> =
        directory.parameterAnnotations.map { it.second.refs }.flatten()

    private val debugInfoOffsets = HashMap<DexDebugInfo, Int>()
    private val codeOffsets = HashMap<DexCode, Int>()

    private fun emitDebugInfos() {
        phase(MapItemType.DEBUG_INFO) {
            var count = 0
            for (classDef in document.classes) {
                val classData = classDef.classData ?: continue
                for (method in classData.directMethods + classData.virtualMethods) {
                    val info = method.code?.debugInfo ?: continue
                    debugInfoOffsets[info] = dataOff + data.length
                    data.write(Leb128Writer.writeUnsignedLeb128(info.lineStart))
                    data.write(Leb128Writer.writeUnsignedLeb128(info.parameterNames.size))
                    for (name in info.parameterNames) {
                        data.write(Leb128Writer.writeUnsignedLeb128(name?.let { document.stringIndexOf(it) } ?: 0))
                    }
                    for (op in info.ops) writeDebugOp(op)
                    data.write(byteArrayOf(0x00)) // DBG_END_SEQUENCE
                    count++
                }
            }
            count
        }
    }

    private fun writeDebugOp(op: DebugOp) {
        when (op) {
            is DebugOp.AdvancePc -> {
                data.u1(0x01)
                data.write(Leb128Writer.writeUnsignedLeb128(op.units))
            }
            is DebugOp.AdvanceLine -> {
                data.u1(0x02)
                data.write(Leb128Writer.writeSignedLeb128(op.line))
            }
            is DebugOp.StartLocal -> {
                data.u1(0x03)
                data.write(Leb128Writer.writeUnsignedLeb128(op.register))
                data.write(Leb128Writer.writeUnsignedLeb128(op.name?.let { document.stringIndexOf(it) } ?: 0))
                data.write(Leb128Writer.writeUnsignedLeb128(op.type?.let { document.typeIndexOf(it) } ?: 0))
            }
            is DebugOp.StartLocalExtended -> {
                data.u1(0x04)
                data.write(Leb128Writer.writeUnsignedLeb128(op.register))
                data.write(Leb128Writer.writeUnsignedLeb128(op.name?.let { document.stringIndexOf(it) } ?: 0))
                data.write(Leb128Writer.writeUnsignedLeb128(op.type?.let { document.typeIndexOf(it) } ?: 0))
                data.write(Leb128Writer.writeUnsignedLeb128(op.signature?.let { document.stringIndexOf(it) } ?: 0))
            }
            is DebugOp.EndLocal -> {
                data.u1(0x05)
                data.write(Leb128Writer.writeUnsignedLeb128(op.register))
            }
            is DebugOp.RestartLocal -> {
                data.u1(0x06)
                data.write(Leb128Writer.writeUnsignedLeb128(op.register))
            }
            is DebugOp.SetPrologueEnd -> data.u1(0x07)
            is DebugOp.SetEpilogueBegin -> data.u1(0x08)
            is DebugOp.SetFile -> {
                data.u1(0x09)
                data.write(Leb128Writer.writeUnsignedLeb128(op.name?.let { document.stringIndexOf(it) } ?: 0))
            }
        }
    }

    private fun emitCodeItems() {
        phase(MapItemType.CODE) {
            var count = 0
            val codec = DexCodeCodec(document)
            for (classDef in document.classes) {
                val classData = classDef.classData ?: continue
                for (method in classData.directMethods + classData.virtualMethods) {
                    val code = method.code ?: continue
                    if (codeOffsets.containsKey(code)) continue
                    align4()
                    codeOffsets[code] = dataOff + data.length
                    val encoded = codec.encode(code)
                    data.u2(encoded.registersSize)
                    data.u2(encoded.insSize)
                    data.u2(encoded.outsSize)
                    data.u2(encoded.tries.size)
                    data.u4((encoded.debugInfo?.let { debugInfoOffsets[it] ?: 0 } ?: 0).toLong())
                    data.u4(encoded.units.size.toLong())
                    for (unit in encoded.units) {
                        data.u2(unit)
                    }
                    if (encoded.tries.isNotEmpty() && encoded.units.size % 2 == 1) {
                        data.u2(0) // padding between insns and tries
                    }
                    if (encoded.tries.isNotEmpty()) {
                        // Stage the handler list first to learn its offsets.
                        val staged = ByteArrayOutputStream(64)
                        val handlerOffsets = HashMap<DexCatchHandler, Int>()
                        val unique = encoded.tries.map { it.handler }.distinct()
                        var cursor = 0
                        staged.write(Leb128Writer.writeUnsignedLeb128(unique.size))
                        for (handler in unique) {
                            handlerOffsets[handler] = cursor
                            val entries = handler.entries
                            val sizeField = if (handler.catchAllAddress != null) -entries.size else entries.size
                            val sleb = Leb128Writer.writeSignedLeb128(sizeField)
                            staged.write(sleb)
                            cursor += sleb.size
                            for (entry in entries) {
                                val typeIdx = Leb128Writer.writeUnsignedLeb128(document.typeIndexOf(entry.type))
                                val addr = Leb128Writer.writeUnsignedLeb128(entry.address)
                                staged.write(typeIdx)
                                staged.write(addr)
                                cursor += typeIdx.size + addr.size
                            }
                            if (handler.catchAllAddress != null) {
                                val addr = Leb128Writer.writeUnsignedLeb128(handler.catchAllAddress)
                                staged.write(addr)
                                cursor += addr.size
                            }
                        }
                        for (tryItem in encoded.tries) {
                            data.u4(tryItem.startAddress.toLong())
                            data.u2(tryItem.instructionCount)
                            data.u2(handlerOffsets[tryItem.handler] ?: 0)
                        }
                        data.write(staged.toByteArray())
                    }
                    count++
                }
            }
            count
        }
    }

    private val classDataOffsets = HashMap<DexClassData, Int>()

    private fun emitClassData() {
        phase(MapItemType.CLASS_DATA) {
            var count = 0
            for (classDef in document.classes) {
                val classData = classDef.classData ?: continue
                if (classData.staticFields.isEmpty() && classData.instanceFields.isEmpty() &&
                    classData.directMethods.isEmpty() && classData.virtualMethods.isEmpty()
                ) {
                    continue
                }
                classDataOffsets[classData] = dataOff + data.length

                val staticFields = classData.staticFields.sortedBy { document.fieldIndexOf(it.field) }
                val instanceFields = classData.instanceFields.sortedBy { document.fieldIndexOf(it.field) }
                val directMethods = classData.directMethods.sortedBy { document.methodIndexOf(it.method) }
                val virtualMethods = classData.virtualMethods.sortedBy { document.methodIndexOf(it.method) }

                data.write(Leb128Writer.writeUnsignedLeb128(staticFields.size))
                data.write(Leb128Writer.writeUnsignedLeb128(instanceFields.size))
                data.write(Leb128Writer.writeUnsignedLeb128(directMethods.size))
                data.write(Leb128Writer.writeUnsignedLeb128(virtualMethods.size))

                fun writeDelta(values: List<Int>) {
                    var previous = 0
                    for (value in values) {
                        data.write(Leb128Writer.writeUnsignedLeb128(value - previous))
                        previous = value
                    }
                }

                // encoded_field: field_idx_diff, access_flags (interleaved).
                var previousField = 0
                for (field in staticFields) {
                    data.write(Leb128Writer.writeUnsignedLeb128(document.fieldIndexOf(field.field) - previousField))
                    previousField = document.fieldIndexOf(field.field)
                    data.write(Leb128Writer.writeUnsignedLeb128(field.accessFlags))
                }
                previousField = 0
                for (field in instanceFields) {
                    data.write(Leb128Writer.writeUnsignedLeb128(document.fieldIndexOf(field.field) - previousField))
                    previousField = document.fieldIndexOf(field.field)
                    data.write(Leb128Writer.writeUnsignedLeb128(field.accessFlags))
                }

                // encoded_method: method_idx_diff, access_flags, code_off.
                var previousMethod = 0
                for (method in directMethods) {
                    val index = document.methodIndexOf(method.method)
                    data.write(Leb128Writer.writeUnsignedLeb128(index - previousMethod))
                    previousMethod = index
                    data.write(Leb128Writer.writeUnsignedLeb128(method.accessFlags))
                    data.write(Leb128Writer.writeUnsignedLeb128(method.code?.let { codeOffsets[it] ?: 0 } ?: 0))
                }
                previousMethod = 0
                for (method in virtualMethods) {
                    val index = document.methodIndexOf(method.method)
                    data.write(Leb128Writer.writeUnsignedLeb128(index - previousMethod))
                    previousMethod = index
                    data.write(Leb128Writer.writeUnsignedLeb128(method.accessFlags))
                    data.write(Leb128Writer.writeUnsignedLeb128(method.code?.let { codeOffsets[it] ?: 0 } ?: 0))
                }
                count++
            }
            count
        }
    }

    private fun emitMapList(): Int {
        align4()
        val mapOffset = dataOff + data.length
        val entries = ArrayList<DexMapEntry>()
        entries.add(DexMapEntry(MapItemType.HEADER, 0, 0, 1))
        entries.add(DexMapEntry(MapItemType.STRING_ID, 0, 0x70, document.strings.size))
        entries.add(DexMapEntry(MapItemType.TYPE_ID, 0, 0x70 + document.strings.size * 4, document.types.size))
        entries.add(
            DexMapEntry(
                MapItemType.PROTO_ID,
                0,
                (0x70 + document.strings.size * 4 + document.types.size * 4),
                document.protos.size,
            ),
        )
        entries.add(
            DexMapEntry(
                MapItemType.FIELD_ID,
                0,
                (0x70 + document.strings.size * 4 + document.types.size * 4 + document.protos.size * 12),
                document.fields.size,
            ),
        )
        entries.add(
            DexMapEntry(
                MapItemType.METHOD_ID,
                0,
                (
                    0x70 + document.strings.size * 4 + document.types.size * 4 +
                        document.protos.size * 12 + document.fields.size * 8
                    ),
                document.methods.size,
            ),
        )
        entries.add(
            DexMapEntry(
                MapItemType.CLASS_DEF,
                0,
                (
                    0x70 + document.strings.size * 4 + document.types.size * 4 +
                        document.protos.size * 12 + document.fields.size * 8 + document.methods.size * 8
                    ),
                document.classes.size,
            ),
        )
        entries.addAll(mapEntries)
        entries.add(DexMapEntry(MapItemType.MAP_LIST, 0, mapOffset, 1))

        // map_list.size is a plain u4 per the DEX specification.
        data.u4(entries.size)
        for (entry in entries) {
            data.u2(entry.type)
            data.u2(0)
            data.u4(entry.offset)
            data.u4(entry.size)
        }
        return mapOffset
    }

    // ------------------------------------------------------------------
    // Header and id sections
    // ------------------------------------------------------------------

    private fun buildIdSections(
        stringIdsOff: Int,
        typeIdsOff: Int,
        protoIdsOff: Int,
        fieldIdsOff: Int,
        methodIdsOff: Int,
        classDefsOff: Int,
        mapOffset: Int,
    ): ByteArray {
        val ids = Sink()
        val magic = "dex\n" + "0" + document.dexVersion + "\u0000"
        for (ch in magic) ids.u1(ch.code)
        repeat(20) { ids.u1(0) } // signature placeholder
        ids.u4(0) // checksum placeholder
        ids.u4(0) // file_size placeholder, patched by assemble
        ids.u4(0x70) // header_size
        ids.u4(0x12345678) // endian_tag
        ids.u4(0); ids.u4(0) // link size / offset
        ids.u4(mapOffset)
        ids.u4(document.strings.size)
        ids.u4(stringIdsOff)
        ids.u4(document.types.size)
        ids.u4(typeIdsOff)
        ids.u4(document.protos.size)
        ids.u4(protoIdsOff)
        ids.u4(document.fields.size)
        ids.u4(fieldIdsOff)
        ids.u4(document.methods.size)
        ids.u4(methodIdsOff)
        ids.u4(document.classes.size)
        ids.u4(classDefsOff)
        ids.u4(data.length)
        ids.u4(dataOff)

        for (item in document.strings) ids.u4(item.dataOffset)
        for (item in document.types) {
            ids.u2(document.stringIndexOf(item.descriptor))
            ids.u2(0)
        }
        for (item in document.protos) {
            ids.u4(document.stringIndexOf(item.shorty).toLong())
            ids.u4(document.typeIndexOf(item.returnType).toLong())
            ids.u4(typeListOffset(item.parameters).toLong())
        }
        for (item in document.fields) {
            ids.u2(document.typeIndexOf(item.declaringClass))
            ids.u2(document.typeIndexOf(item.type))
            ids.u4(document.stringIndexOf(item.name).toLong())
        }
        for (item in document.methods) {
            ids.u2(document.typeIndexOf(item.declaringClass))
            ids.u2(document.protoIndexOf(item.proto))
            ids.u4(document.stringIndexOf(item.name).toLong())
        }
        for (classDef in document.classes) {
            ids.u4(document.typeIndexOf(classDef.type).toLong())
            ids.u4(classDef.accessFlags)
            ids.u4(classDef.superclass?.let { document.typeIndexOf(it).toLong() } ?: 0xFFFFFFFFL)
            ids.u4(typeListOffset(classDef.interfaces))
            ids.u4(classDef.sourceFile?.let { document.stringIndexOf(it).toLong() } ?: 0xFFFFFFFFL)
            ids.u4(classDef.annotationsDirectory?.let { (directoryOffsets[it] ?: 0).toLong() } ?: 0L)
            ids.u4(classDef.classData?.let { (classDataOffsets[it] ?: 0).toLong() } ?: 0L)
            ids.u4(encodedArrayOffsets[classDef]?.toLong() ?: 0L)
        }
        return ids.toByteArray()
    }

    private fun assemble(headerAndIds: ByteArray): ByteArray {
        val dataBytes = data.toByteArray()
        val fileSize = headerAndIds.size + dataBytes.size
        val result = ByteArray(fileSize)
        System.arraycopy(headerAndIds, 0, result, 0, headerAndIds.size)
        System.arraycopy(dataBytes, 0, result, headerAndIds.size, dataBytes.size)

        writeI32(result, 32, fileSize)
        writeI32(result, 104, dataBytes.size)
        writeI32(result, 108, headerAndIds.size)

        val digest = MessageDigest.getInstance("SHA-1")
        digest.update(result, 32, result.size - 32)
        val signature = digest.digest()
        System.arraycopy(signature, 0, result, 12, 20)

        val adler = Adler32()
        adler.update(result, 12, result.size - 12)
        writeI32(result, 8, adler.value.toInt())
        return result
    }

    private fun writeI32(target: ByteArray, offset: Int, value: Int) {
        target[offset] = (value and 0xFF).toByte()
        target[offset + 1] = ((value shr 8) and 0xFF).toByte()
        target[offset + 2] = ((value shr 16) and 0xFF).toByte()
        target[offset + 3] = ((value shr 24) and 0xFF).toByte()
    }

    // ------------------------------------------------------------------
    // Encoded values
    // ------------------------------------------------------------------

    private fun writeEncodedValue(value: DexEncodedValue) {
        when (value) {
            is DexEncodedValue.ByteValue -> writeNumeric(0x00, value.value.toLong(), 1)
            is DexEncodedValue.ShortValue -> writeNumeric(0x02, value.value.toLong(), 2)
            is DexEncodedValue.CharValue -> writeNumeric(0x03, value.value.toLong(), 2)
            is DexEncodedValue.IntValue -> writeNumeric(0x04, value.value.toLong(), 4)
            is DexEncodedValue.LongValue -> writeNumeric(0x06, value.value, 8)
            is DexEncodedValue.FloatValue -> writeNumeric(0x10, value.bits.toLong() and 0xFFFFFFFFL, 4)
            is DexEncodedValue.DoubleValue -> writeNumeric(0x11, value.bits, 8)
            is DexEncodedValue.MethodTypeValue -> writeIndexValue(0x15, document.protoIndexOf(value.proto))
            is DexEncodedValue.MethodHandleValue -> throw UnsupportedOperationException()
            is DexEncodedValue.StringValue -> writeIndexValue(0x17, document.stringIndexOf(value.value))
            is DexEncodedValue.TypeValue -> writeIndexValue(0x18, document.typeIndexOf(value.value))
            is DexEncodedValue.FieldValue -> writeIndexValue(0x19, document.fieldIndexOf(value.value))
            is DexEncodedValue.MethodValue -> writeIndexValue(0x1A, document.methodIndexOf(value.value))
            is DexEncodedValue.EnumValue -> writeIndexValue(0x1B, document.fieldIndexOf(value.value))
            is DexEncodedValue.ArrayValue -> {
                data.u1((0x1C shl 5))
                data.write(Leb128Writer.writeUnsignedLeb128(value.values.size))
                for (item in value.values) writeEncodedValue(item)
            }
            is DexEncodedValue.AnnotationValue -> {
                data.u1((0x1D shl 5))
                data.write(Leb128Writer.writeUnsignedLeb128(document.typeIndexOf(value.type)))
                data.write(Leb128Writer.writeUnsignedLeb128(value.elements.size))
                for ((name, element) in value.elements) {
                    data.write(Leb128Writer.writeUnsignedLeb128(document.stringIndexOf(name)))
                    writeEncodedValue(element)
                }
            }
            is DexEncodedValue.NullValue -> data.u1((0x1E shl 5))
            is DexEncodedValue.BooleanValue -> data.u1((0x1F shl 5) or (if (value.value) 1 else 0))
        }
    }

    private fun writeNumeric(tag: Int, value: Long, maxSize: Int) {
        var size = 0
        for (i in 0 until maxSize) {
            if (((value shr (i * 8)) and 0xFF) != 0L) size = i + 1
        }
        if (size == 0) {
            data.u1((tag shl 5) or 0)
            data.u1(0)
            return
        }
        data.u1((tag shl 5) or (size - 1))
        for (i in 0 until size) {
            data.u1(((value shr (i * 8)) and 0xFF).toInt())
        }
    }

    private fun writeIndexValue(tag: Int, index: Int) {
        var size = 0
        for (i in 0 until 4) {
            if (((index shr (i * 8)) and 0xFF) != 0) size = i + 1
        }
        if (size == 0) {
            data.u1((tag shl 5) or 0)
            data.u1(0)
            return
        }
        data.u1((tag shl 5) or (size - 1))
        for (i in 0 until size) {
            data.u1((index shr (i * 8)) and 0xFF)
        }
    }
}
