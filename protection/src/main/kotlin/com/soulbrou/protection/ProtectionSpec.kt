package com.soulbrou.protection

import kotlinx.serialization.Serializable

/**
 * The catalogue of protections offered by the tool. The ordinal values map
 * directly to the SB_PROTECTION bits of the native runtime.
 */
enum class ProtectionType(val bit: Int, val key: String) {
    ANTI_ROOT(0x01, "anti_root"),
    ANTI_FRIDA(0x02, "anti_frida"),
    ANTI_DEXDUMP(0x04, "anti_dexdump"),
    ANTI_TAMPERING(0x08, "anti_tampering"),
    SIGNATURE_CHECK(0x10, "signature_check"),
    ANTI_DEBUG(0x20, "anti_debug"),
    ANTI_EMULATOR(0x40, "anti_emulator"),
    ;

    companion object {
        fun fromMask(mask: Int): List<ProtectionType> =
            entries.filter { mask and it.bit != 0 }

        fun maskOf(types: Collection<ProtectionType>): Int =
            types.fold(0) { acc, type -> acc or type.bit }
    }
}

/** Per protection advanced settings. */
@Serializable
data class ProtectionSettings(
    val failHard: Boolean = false,
    val customPaths: List<String> = emptyList(),
    val checkInterval: Int = 1,
)

/** The full protection configuration of a build. */
@Serializable
data class ProtectionSpec(
    val enabled: Map<String, Boolean> = defaultFlags(),
    val markUnpatchable: Boolean = true,
    val settings: Map<String, ProtectionSettings> = emptyMap(),
) {
    val mask: Int
        get() = ProtectionType.entries
            .filter { enabled[it.key] == true }
            .fold(0) { acc, type -> acc or type.bit }

    /** Human readable list of active protection keys. */
    val activeKeys: List<String>
        get() = ProtectionType.entries.filter { enabled[it.key] == true }.map { it.key }

    companion object {
        fun defaultFlags(): Map<String, Boolean> = linkedMapOf(
            ProtectionType.ANTI_ROOT.key to true,
            ProtectionType.ANTI_FRIDA.key to true,
            ProtectionType.ANTI_DEXDUMP.key to true,
            ProtectionType.ANTI_TAMPERING.key to true,
            ProtectionType.SIGNATURE_CHECK.key to true,
            ProtectionType.ANTI_DEBUG.key to true,
            ProtectionType.ANTI_EMULATOR.key to false,
        )
    }
}
