# Soulbrou

**Autor:** beto2-dev
**Licencia:** [Apache License 2.0](LICENSE)

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Soulbrou es una herramienta Android de proteccion de aplicaciones que permite a desarrolladores y equipos de seguridad proteger APKs de terceros mediante conversion de codigo a nativo, protecciones anti-analisis y re-firmado, todo desde el propio dispositivo, sin conexion y sin depender de servicios externos.

## Caracteristicas principales

- Conversion Dex2C: transforma metodos o clases completas del bytecode Dalvik en codigo nativo C/C++ compilado como librerias compartidas (.so)
- Verificacion de firma APK a nivel nativo dentro del codigo protegido
- Protecciones anti-analisis configurables: anti-root, anti-Frida, anti-dexdump, anti-tampering, anti-debugging y anti-emulator
- Sistema de verificacion en cadena no parcheable: comprobaciones distribuidas, dependientes entre si y ofuscadas a nivel de flujo de control
- Re-firmado del APK resultante con keystore personalizada (JKS, PKCS12, BKS) con esquemas v1, v2 y v3
- Analisis local de APKs: clases detectadas, metodos por clase, permisos y arquitecturas
- Selector visual en arbol con busqueda, filtros, seleccion multiple y vista previa del codigo smali
- Comparativa antes/despues: tamano, metodos en DEX, metodos nativos y protecciones aplicadas
- Interfaz Jetpack Compose con Material Design 3, tema oscuro por defecto
- Soporte multi-idioma (Espanol, Ingles) y tema claro/oscuro/sistema
- Funcionamiento completamente offline

## Requisitos de compilacion

- JDK 17 o superior
- Android SDK con Platform 34 y Build Tools 34.0.0
- Android NDK 27.0.12077973
- CMake 3.22.1 o superior

## Compilacion

Clonar el repositorio y ejecutar desde la raiz:

```bash
./gradlew :app:assembleDebug
```

Para generar un APK release firmado con la keystore configurada:

```bash
./gradlew :app:assembleRelease
```

La keystore de firma release se configura mediante las variables de entorno `SOULBROU_KEYSTORE`, `SOULBROU_KEYSTORE_PASSWORD`, `SOULBROU_KEY_ALIAS` y `SOULBROU_KEY_PASSWORD` (ver `app/build.gradle.kts`). Nunca se versionan credenciales en el repositorio; la integracion continua utiliza GitHub Secrets.

## Uso basico

1. Seleccionar el APK de entrada desde el selector de archivos (o arrastrar y soltar en dispositivos compatibles)
2. Revisar el arbol de clases y metodos y marcar los que se desean convertir a nativo
3. Activar y configurar las protecciones requeridas
4. Seleccionar o generar la keystore de firma
5. Ejecutar el proceso de build y seguir el progreso paso a paso
6. Instalar, guardar o compartir el APK resultante ya firmado

## Estructura del proyecto

```
soulbrou/
├── app/          Aplicacion Android (UI Compose, pipeline, JNI)
├── dex2c/        Motor de conversion: parser DEX, traductor smali a C, escritor DEX
├── protection/   Definicion y planificacion de protecciones
├── signer/       Firma de APKs y gestion de keystores
├── core/         Modelos, registro de logs y utilidades compartidas
├── testapp/      APK de prueba para tests end to end
└── build-logic/  Plugins Gradle convencionales del proyecto
```

## Changelog

Los cambios de cada version se documentan en [CHANGELOG.md](CHANGELOG.md).
