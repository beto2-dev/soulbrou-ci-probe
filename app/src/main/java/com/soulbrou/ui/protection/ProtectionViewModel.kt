package com.soulbrou.ui.protection

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import com.soulbrou.SoulbrouApplication
import com.soulbrou.protection.ProtectionSpec
import com.soulbrou.protection.ProtectionType
import kotlinx.coroutines.flow.StateFlow

/**
 * Edits the protection configuration kept in the build session: individual
 * countermeasure toggles and the unpatchable mode switch.
 */
class ProtectionViewModel(app: Application) : AndroidViewModel(app) {

    private val container = (app as SoulbrouApplication).container

    val spec: StateFlow<ProtectionSpec> = container.session.spec

    fun toggle(type: ProtectionType) {
        val current = spec.value
        val flags = current.enabled.toMutableMap()
        flags[type.key] = !(flags[type.key] ?: false)
        container.session.setSpec(current.copy(enabled = flags))
    }

    fun setUnpatchable(enabled: Boolean) {
        container.session.setSpec(spec.value.copy(markUnpatchable = enabled))
    }
}
