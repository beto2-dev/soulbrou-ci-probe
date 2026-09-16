# Changelog

Todos los cambios notables de este proyecto se documentaran en este archivo.

El formato esta basado en [Keep a Changelog](https://keepachangelog.com/es/1.1.0/),
y este proyecto se adhiere a [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-09-17

Primera version publica estable de Soulbrou.

### Added

- Motor de conversion Dex2C con parser propio de archivos DEX, analizador de bytecode Dalvik, generador de codigo C con mapeo de tipos JNI, escritor de DEX y reempaquetado del APK de entrada.
- Biblioteca nativa de ejecucion (libsoulbrou) con interprete de bytecode Dalvik, lector de archivos ZIP con soporte del APK Signing Block, primitivas criptograficas (XXTEA, SHA-256, CRC32) y puente JNI, para ABIs arm64-v8a, armeabi-v7a y x86_64.
- Blob nativo cifrado que almacena los cuerpos de los metodos convertidos; la clave de descifrado se deriva del certificado firmante, de forma que un APK re-firmado no puede ejecutar el codigo protegido.
- Sistema de protecciones nativas configurable: anti-root (su, Magisk, SuperSU, Xposed), anti-Frida (puerto 27042, hilos gum-js-loop, modulos frida-agent), anti-dexdump, anti-tampering (CRC32, huella de firma y validacion cruzada con ofuscacion de flujo), verificacion de firma, anti-debugging (ptrace) y anti-emulator.
- Modo no parcheable: la configuracion de protecciones queda fijada dentro del blob nativo cifrado y no puede desactivarse recompilando recursos.
- Modulo de firma con apksig: esquemas v1, v2 y v3, importacion de almacenes JKS y PKCS12, generacion de almacenes PKCS12 con certificado autofirmado y verificacion del resultado.
- Canalizacion de construccion en nueve etapas con progreso visual y registro en vivo cancelable: analisis, analisis dex, plan, generacion C, empaquetado nativo, inyeccion, reempaquetado, alineado y firma, y verificacion.
- Interfaz Jetpack Compose con Material Design 3, tema oscuro indigo por defecto, navegacion inferior de flujo de trabajo y pantallas de inicio, seleccion de APK, seleccion de metodos en arbol con vista previa smali, configuracion de protecciones, administracion de almacenes de firma, construccion y comparativa de resultados.
- Persistencia local con DataStore: tema, idioma (espanol e ingles), nivel de ofuscacion, ruta de la cadena de herramientas y retencion de copias firmadas; historial de construcciones en JSON.
- Suite de pruebas: pruebas unitarias JVM de los modulos core, dex2c, protection y signer; pruebas instrumentadas y E2E sobre un APK de prueba incluido, ejecutadas en emulador API 34 mediante GitHub Actions.
- Flujos de integracion continua y de publicacion: CI en cada push y pull request, publicacion firmada al etiquetar una version con creacion automatica de la GitHub Release y carga del APK.

### Security

- Las credenciales de firma solo se administran mediante GitHub Secrets o variables de entorno; ningun dato confidencial se versiona en el repositorio.

[Unreleased]: https://github.com/beto2-dev/soulbrou/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/beto2-dev/soulbrou/releases/tag/v1.0.0
