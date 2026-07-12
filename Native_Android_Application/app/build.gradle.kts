plugins {
    id("com.android.application")
}

android {
    namespace = "dev.jshstadler.carkey"
    compileSdk = 36

    defaultConfig {
        applicationId = "dev.jshstadler.carkey"
        minSdk = 23
        targetSdk = 36
        versionCode = 7
        versionName = "2.0.0"
    }

    buildFeatures {
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("debug")
        }
    }
}

dependencies {
    implementation("androidx.activity:activity:1.12.4")
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.fragment:fragment:1.8.9")
}
