import org.gradle.api.tasks.Copy

plugins {
    id("soulbrou.android.application")
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
}

android {
    namespace = "com.soulbrou"

    defaultConfig {
        applicationId = "com.soulbrou"
        versionCode = 1
        versionName = "1.0.0"

        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }

        externalNativeBuild {
            cmake {
                arguments += listOf("-DANDROID_STL=c++_static")
            }
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    buildFeatures {
        compose = true
    }

    signingConfigs {
        create("release") {
            val ksPath = System.getenv("SOULBROU_KEYSTORE")
            val ksPassword = System.getenv("SOULBROU_KEYSTORE_PASSWORD")
            val ksAlias = System.getenv("SOULBROU_KEY_ALIAS")
            val ksKeyPassword = System.getenv("SOULBROU_KEY_PASSWORD")
            if (ksPath != null && ksPassword != null && ksAlias != null && ksKeyPassword != null) {
                storeFile = file(ksPath)
                storePassword = ksPassword
                keyAlias = ksAlias
                keyPassword = ksKeyPassword
                enableV1Signing = true
                enableV2Signing = true
                enableV3Signing = true
            }
        }
    }

    buildTypes {
        release {
            signingConfig = if (signingConfigs.getByName("release").storeFile != null) {
                signingConfigs.getByName("release")
            } else {
                signingConfigs.getByName("debug")
            }
        }
    }

    testOptions {
        unitTests {
            isIncludeAndroidResources = false
        }
    }
}

dependencies {
    implementation(project(":core"))
    implementation(project(":dex2c"))
    implementation(project(":protection"))
    implementation(project(":signer"))

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.documentfile)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.navigation.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.datastore.preferences)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.kotlinx.serialization.json)

    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.ui.graphics)
    implementation(libs.compose.ui.tooling.preview)
    implementation(libs.compose.material3)
    implementation(libs.compose.material.icons.extended)
    debugImplementation(libs.compose.ui.tooling)
    debugImplementation(libs.compose.ui.test.manifest)

    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)

    androidTestImplementation(libs.androidx.test.core)
    androidTestImplementation(libs.androidx.test.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(platform(libs.compose.bom))
    androidTestImplementation(libs.compose.ui.test.junit4)
}

// Copies the testapp fixture APK into the androidTest asset folder so the
// instrumented end to end suite can exercise the full protection pipeline.
val copyTestAppFixture by tasks.registering(Copy::class) {
    dependsOn(":testapp:assembleDebug")
    from(project(":testapp").layout.buildDirectory.file("outputs/apk/debug/testapp-debug.apk"))
    into(layout.buildDirectory.dir("generated/androidTest-assets/testapp"))
    rename { "testapp.apk" }
}

tasks.matching { it.name == "mergeDebugAndroidTestAssets" }.configureEach {
    dependsOn(copyTestAppFixture)
}

android.sourceSets.getByName("androidTest") {
    assets.srcDir(layout.buildDirectory.dir("generated/androidTest-assets"))
}
