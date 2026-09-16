package com.soulbrou.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.platform.LocalContext
import com.soulbrou.SoulbrouApplication
import com.soulbrou.session.SelectedApk

/** Current session APK observed as composable state. */
@Composable
fun currentSessionApk(): SelectedApk? {
    val app = LocalContext.current.applicationContext as SoulbrouApplication
    val apk by app.container.session.apk.collectAsState()
    return apk
}
