# JavaCard Libraries

Local `*.jar` dependencies repository.

You can add here local dependencies if there are not available on the 
Maven central repository or you are not willing to use those.

If there is a `test.jar` file you can add it as a dependency
by adding the following line to the `dependencies {}` block.

```gradle
compile name: 'test'
```

This works only for JAR files placed right in the `/libs` directory (flat hierarchy).
The artifact group is ignored, artifact is searched just by the name.
 
For subdirectories you have to use the `files()` or `fileTree` as demonstrated below.

```gradle
dependencies {
    testCompile 'org.testng:testng:6.1.1'
    testCompile group: 'com.klinec', name: 'javacard-tools', version: '0.0.1', transitive: false
}

```


## `globalplatform-2_1_1`

Globalplatform libraries

```gradle
compile fileTree(dir: rootDir.absolutePath + '/libs/globalplatform-2_1_1', include: '*.jar')
```

Or if you use predefined gradle file with `libs` variable:

```gradle
compile fileTree(dir: libs + '/globalplatform-2_1_1', include: '*.jar')
```

License: no idea

## `visa_openplatform`

```gradle
compile fileTree(dir: rootDir.absolutePath + '/libs/visa_openplatform-2_0', include: '*.jar')
```

License: no idea

