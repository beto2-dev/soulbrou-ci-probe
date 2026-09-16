plugins {
    id("soulbrou.kotlin.jvm")
    alias(libs.plugins.kotlin.serialization)
}

dependencies {
    api(project(":core"))

    testImplementation(libs.junit)
}
