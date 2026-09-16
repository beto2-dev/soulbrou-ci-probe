package com.soulbrou.dex2c.model

import com.soulbrou.dex2c.code.DexCode
import java.util.IdentityHashMap

/**
 * Ordered, append friendly list that assigns a stable sequential index to
 * every distinct item after [seal] is invoked. Lookups while unsealed use
 * structural equality so that parsing and mutation can re use existing items
 * instead of creating duplicates.
 */
class RefList<T>(private val idOf: (T) -> Any) : AbstractMutableList<T>() {

    private val items = ArrayList<T>()
    private val byId = HashMap<Any, T>()
    private val indicesById = IdentityHashMap<T, Int>()
    private var sealed = false

    val sizeBeforeSeal: Int get() = items.size

    /** Returns the assigned index; only valid after [seal]. */
    fun indexOfItem(item: T): Int {
        require(sealed) { "RefList is not sealed" }
        return indicesById[item] ?: error("Item not present in this RefList")
    }

    fun find(id: Any): T? = byId[id]

    fun intern(item: T): T {
        check(!sealed) { "Cannot intern into a sealed list" }
        val id = idOf(item)
        val existing = byId[id]
        if (existing != null) return existing
        byId[id] = item
        items.add(item)
        return item
    }

    /** Sorts the underlying items while unsealed. */
    fun sortWith(comparator: Comparator<T>) {
        check(!sealed) { "Cannot sort a sealed list" }
        items.sortWith(comparator)
    }

    fun seal() {
        if (sealed) return
        indicesById.clear()
        items.forEachIndexed { index, item ->
            indicesById[item] = index
        }
        sealed = true
    }

    fun unseal() {
        sealed = false
        indicesById.clear()
    }

    override val size: Int get() = items.size

    override fun get(index: Int): T = items[index]

    override fun set(index: Int, element: T): T {
        check(!sealed) { "Cannot modify a sealed list" }
        val previous = items[index]
        val id = idOf(element)
        val existing = byId[id]
        if (existing != null && existing !== element) {
            // Replacing an item with a structurally equal one: keep canonical.
            items[index] = existing
            return previous
        }
        byId[id] = element
        items[index] = element
        return previous
    }

    override fun add(index: Int, element: T) {
        check(!sealed) { "Cannot modify a sealed list" }
        val id = idOf(element)
        val existing = byId[id]
        if (existing != null) {
            // Already present: adding is a no-op for interned semantics.
            if (existing === element) return
            return
        }
        byId[id] = element
        items.add(index, element)
    }

    override fun removeAt(index: Int): T {
        check(!sealed) { "Cannot modify a sealed list" }
        val item = items.removeAt(index)
        byId.remove(idOf(item))
        return item
    }
}

/**
 * A DEX string item.
 */
class DexString(val value: String) {
    var index: Int = -1
    var dataOffset: Long = 0
}

/** A DEX type reference; the descriptor must be a valid JNI descriptor. */
class DexType(val descriptor: DexString) {
    var index: Int = -1
    var idOffset: Long = 0
}

/** A method prototype: shorty plus full resolved types. */
class DexProto(
    val shorty: DexString,
    val returnType: DexType,
    val parameters: List<DexType>,
) {
    var index: Int = -1
    var idOffset: Long = 0

    val parameterDescriptors: String get() = parameters.joinToString("") { it.descriptor.value }
}

/** A field reference. */
class DexField(
    val declaringClass: DexType,
    val name: DexString,
    val type: DexType,
) {
    var index: Int = -1
    var idOffset: Long = 0
}

/** A method reference. */
class DexMethod(
    val declaringClass: DexType,
    val name: DexString,
    val proto: DexProto,
) {
    var index: Int = -1
    var idOffset: Long = 0

    val fullName: String get() = "${declaringClass.descriptor.value}#${name.value}(${proto.parameterDescriptors})${proto.returnType.descriptor.value}"
}

/** A field definition inside a class data block. */
class DexEncodedField(
    val field: DexField,
    var accessFlags: Int,
)

/** A method definition inside a class data block. */
class DexEncodedMethod(
    val method: DexMethod,
    var accessFlags: Int,
    var code: DexCode?,
) {
    val isStatic: Boolean get() = accessFlags and AccessFlags.ACC_STATIC != 0
    val isDirect: Boolean
        get() = accessFlags and (AccessFlags.ACC_STATIC or AccessFlags.ACC_PRIVATE) != 0 ||
            name0.value == "<init>"

    private val name0: DexString get() = method.name
}

/** A class definition. */
class DexClassDef(
    val type: DexType,
    var accessFlags: Int,
    var superclass: DexType?,
    var interfaces: List<DexType>,
    var sourceFile: DexString?,
    var annotationsDirectory: DexAnnotationsDirectory?,
    var staticValues: List<DexEncodedValue>?,
    var classData: DexClassData?,
) {
    var index: Int = -1

    /** Locates the direct method with the given name, or null. */
    fun findDirectMethod(name: String): DexEncodedMethod? =
        classData?.directMethods?.firstOrNull { it.method.name.value == name }

    fun findStaticInitializer(): DexEncodedMethod? = findDirectMethod("<clinit>")
}

/** The members of a class: fields and methods with their flags. */
class DexClassData(
    val staticFields: List<DexEncodedField>,
    val instanceFields: List<DexEncodedField>,
    val directMethods: MutableList<DexEncodedMethod>,
    val virtualMethods: MutableList<DexEncodedMethod>,
)

/** Alignment requirement helper for section emission. */
object DexAlignment {
    fun align(value: Int, alignment: Int): Int = (value + alignment - 1) and (alignment - 1).inv()
    fun align(value: Long, alignment: Long): Long = (value + alignment - 1) and (alignment - 1).inv()
}

/** DEX access flags. */
object AccessFlags {
    const val ACC_PUBLIC = 0x1
    const val ACC_PRIVATE = 0x2
    const val ACC_PROTECTED = 0x4
    const val ACC_STATIC = 0x8
    const val ACC_FINAL = 0x10
    const val ACC_SYNCHRONIZED = 0x20
    const val ACC_VOLATILE = 0x40
    const val ACC_BRIDGE = 0x40
    const val ACC_TRANSIENT = 0x80
    const val ACC_VARARGS = 0x80
    const val ACC_NATIVE = 0x100
    const val ACC_INTERFACE = 0x200
    const val ACC_ABSTRACT = 0x400
    const val ACC_STRICT = 0x800
    const val ACC_SYNTHETIC = 0x1000
    const val ACC_ANNOTATION = 0x2000
    const val ACC_ENUM = 0x4000
    const val ACC_CONSTRUCTOR = 0x10000
    const val ACC_DECLARED_SYNCHRONIZED = 0x20000
}
