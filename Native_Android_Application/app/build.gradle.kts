plugins {
    id("com.android.application")
}

val releaseKeystorePath = System.getenv("CAR_KEY_KEYSTORE_PATH")

android {
    namespace = "dev.jshstadler.carkey"
    compileSdk = 36

    defaultConfig {
        applicationId = "dev.jshstadler.carkey"
        minSdk = 23
        targetSdk = 36
        versionCode = 21
        versionName = "2.5.1"
        manifestPlaceholders["appLabel"] = "BLE Key"
    }

    buildFeatures {
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    signingConfigs {
        create("release") {
            storeFile = file(releaseKeystorePath ?: "missing-release-keystore.jks")
            storePassword = System.getenv("CAR_KEY_STORE_PASSWORD")
            keyAlias = System.getenv("CAR_KEY_KEY_ALIAS")
            keyPassword = System.getenv("CAR_KEY_KEY_PASSWORD")
        }
    }

    buildTypes {
        debug {
            applicationIdSuffix = ".test"
            versionNameSuffix = "-test"
            manifestPlaceholders["appLabel"] = "BLE Key"
        }
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("release")
        }
    }
}

dependencies {
    implementation("androidx.activity:activity:1.12.4")
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.fragment:fragment:1.8.9")
    testImplementation("junit:junit:4.13.2")
}
