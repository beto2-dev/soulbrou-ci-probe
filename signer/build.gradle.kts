plugins {
    id("soulbrou.kotlin.jvm")
    alias(libs.plugins.kotlin.serialization)
}

dependencies {
    api(project(":core"))
    api(libs.apksig)

    testImplementation(libs.junit)
}
