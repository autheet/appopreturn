buildscript {
    ext.kotlin_version = "2.1.0"
    repositories {
        google()
        mavenCentral()
    }

    dependencies {
        // START: FlutterFire Configuration
        classpath("com.google.gms:google-services:4.4.1")
        // END: FlutterFire Configuration
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:$kotlin_version")
    }
}

allprojects {
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.buildDir = "../build"
subprojects {
    project.buildDir = "${rootProject.buildDir}/${project.name}"
}
subprojects {
    project.evaluationDependsOn(":app")
}

tasks.register("clean", Delete::class) {
    delete(rootProject.buildDir)
}
