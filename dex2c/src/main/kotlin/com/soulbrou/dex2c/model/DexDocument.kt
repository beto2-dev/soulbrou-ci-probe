package com.soulbrou.dex2c.model

import com.soulbrou.dex2c.code.DexCodeCodec
import com.soulbrou.dex2c.code.DexCode

/**
 * In memory representation of one classes.dex file. The document holds every
 * identifier table as an interned, mutable structure, so the mutator can add
 * strings, methods or classes and the writer can re emit the file with fresh
 * sorted tables.
 *
 * Supported input: DEX versions 035 to 039 without call sites or method
 * handles (the 038+ invoke-custom family), which covers the bytecode
 * produced by all mainstream Android toolchains.
 */
class DexDocument : DexCodeCodec.ReferenceResolver {

    var dexVersion: Int = 35

    val strings = RefList<DexString> { it.value }
    val types = RefList<DexType> { it.descriptor.value }
    val protos = RefList<DexProto> { "${it.shorty.value}|${it.returnType.descriptor.value}|${it.parameterDescriptors}" }
    val fields = RefList<DexField> { "${it.declaringClass.descriptor.value}->${it.name.value}:${it.type.descriptor.value}" }
    val methods = RefList<DexMethod> {
        "${it.declaringClass.descriptor.value}->${it.name.value}(${it.proto.parameterDescriptors})${it.proto.returnType.descriptor.value}"
    }
    val classes = RefList<DexClassDef> { it.type.descriptor.value }

    /** Interns a string, returning the existing instance when present. */
    fun internString(value: String): DexString = strings.intern(DexString(value))

    /** Interns a type from its descriptor. */
    fun internType(descriptor: String): DexType = types.intern(DexType(internString(descriptor)))

    /** Interns a prototype. */
    fun internProto(shorty: String, returnType: DexType, parameters: List<DexType>): DexProto =
        protos.intern(DexProto(internString(shorty), returnType, parameters))

    /** Interns a field reference. */
    fun internField(declaringClass: DexType, name: String, type: DexType): DexField =
        fields.intern(DexField(declaringClass, internString(name), type))

    /** Interns a method reference. */
    fun internMethod(declaringClass: DexType, name: String, proto: DexProto): DexMethod =
        methods.intern(DexMethod(declaringClass, internString(name), proto))

    /** Finds or creates the standard static initializer method of a class. */
    fun staticInitializerOf(type: DexType): DexMethod {
        val voidType = internType("V")
        val proto = internProto("V", voidType, emptyList())
        return internMethod(type, "<clinit>", proto)
    }

    /** Reference to java.lang.System.loadLibrary(String). */
    fun systemLoadLibraryMethod(): DexMethod {
        val systemType = internType("Ljava/lang/System;")
        val stringType = internType("Ljava/lang/String;")
        val voidType = internType("V")
        val proto = internProto("VL", voidType, listOf(stringType))
        return internMethod(systemType, "loadLibrary", proto)
    }

    /**
     * Unseals all identifier tables so new items can be interned before the
     * next write.
     */
    fun unseal() {
        strings.unseal()
        types.unseal()
        protos.unseal()
        fields.unseal()
        methods.unseal()
        classes.unseal()
    }

    /** True when the given code can be processed by the engine. */
    fun isCodeSupported(code: DexCode?): Boolean = code != null

    // ------------------------------------------------------------------
    // ReferenceResolver implementation used by the code codec
    // ------------------------------------------------------------------

    private var stringsByIndex: List<DexString> = emptyList()
    private var typesByIndex: List<DexType> = emptyList()
    private var protosByIndex: List<DexProto> = emptyList()
    private var fieldsByIndex: List<DexField> = emptyList()
    private var methodsByIndex: List<DexMethod> = emptyList()

    /** Registers index views produced by the parser for read resolution. */
    fun installParseIndexes(
        strings: List<DexString>,
        types: List<DexType>,
        protos: List<DexProto>,
        fields: List<DexField>,
        methods: List<DexMethod>,
    ) {
        stringsByIndex = strings
        typesByIndex = types
        protosByIndex = protos
        fieldsByIndex = fields
        methodsByIndex = methods
    }

    /** Clears index views once parsing is complete. */
    fun clearParseIndexes() {
        stringsByIndex = emptyList()
        typesByIndex = emptyList()
        protosByIndex = emptyList()
        fieldsByIndex = emptyList()
        methodsByIndex = emptyList()
    }

    override fun string(index: Int): DexString = stringsByIndex[index]
    override fun type(index: Int): DexType = typesByIndex[index]
    override fun proto(index: Int): DexProto = protosByIndex[index]
    override fun field(index: Int): DexField = fieldsByIndex[index]
    override fun method(index: Int): DexMethod = methodsByIndex[index]
    override fun methodHandle(index: Int): DexMethodHandle =
        throw UnsupportedOperationException("Method handles are not supported")
    override fun callSite(index: Int): DexCallSite =
        throw UnsupportedOperationException("Call sites are not supported")

    override fun stringIndexOf(value: DexString): Int = strings.indexOfItem(value)
    override fun typeIndexOf(value: DexType): Int = types.indexOfItem(value)
    override fun protoIndexOf(value: DexProto): Int = protos.indexOfItem(value)
    override fun fieldIndexOf(value: DexField): Int = fields.indexOfItem(value)
    override fun methodIndexOf(value: DexMethod): Int = methods.indexOfItem(value)
    override fun methodHandleIndexOf(value: DexMethodHandle): Int =
        throw UnsupportedOperationException("Method handles are not supported")
    override fun callSiteIndexOf(value: DexCallSite): Int =
        throw UnsupportedOperationException("Call sites are not supported")
}
