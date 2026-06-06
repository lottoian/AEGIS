plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = "com.example.logcat"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.example.logcat"
        minSdk = 34
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        javaCompileOptions {
            annotationProcessorOptions {
                arguments["room.schemaLocation"] = "$projectDir/schemas"
            }
        }
    }

    buildFeatures {
        buildConfig = true
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            val releaseBaseUrl = System.getenv("RELEASE_BASE_URL") ?: "https://220.149.236.152:52346"
            val releaseUseMtls = System.getenv("RELEASE_USE_MTLS")?.toBoolean() ?: true
            buildConfigField("String", "BASE_URL", "\"$releaseBaseUrl\"")
            buildConfigField("Boolean", "USE_MTLS", "$releaseUseMtls")
        }
        debug {
            isMinifyEnabled = false
            val debugBaseUrl = System.getenv("DEBUG_BASE_URL") ?: "http://10.0.2.2:8080"
            val debugUseMtls = System.getenv("DEBUG_USE_MTLS")?.toBoolean() ?: false
            buildConfigField("String", "BASE_URL", "\"$debugBaseUrl\"")
            buildConfigField("Boolean", "USE_MTLS", "$debugUseMtls")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
            excludes += "META-INF/DEPENDENCIES"
        }
    }
}

dependencies {
    implementation(libs.appcompat)
    implementation(libs.material)
    implementation("com.google.code.gson:gson:2.8.9")
    implementation(libs.firebase.crashlytics.buildtools)

    // OkHttp (mTLS + SPKI pinning)
    implementation("com.squareup.okhttp3:okhttp:4.12.0")

    // WorkManager (offline queue retry)
    implementation("androidx.work:work-runtime:2.9.0")

    // Room + SQLCipher (encrypted offline queue)
    implementation("androidx.room:room-runtime:2.6.1")
    annotationProcessor("androidx.room:room-compiler:2.6.1")
    implementation("net.zetetic:android-database-sqlcipher:4.5.4")
    implementation("androidx.sqlite:sqlite:2.4.0")

    // BouncyCastle (X25519 ECDH + HKDF on Android)
    implementation("org.bouncycastle:bcprov-jdk15on:1.70")

    testImplementation(libs.junit)
    androidTestImplementation(libs.ext.junit)
    androidTestImplementation(libs.espresso.core)
}