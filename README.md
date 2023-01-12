# AES ENCRYPTION COMMAND LINE TOOL
Program to be used as a command line tool.
Encrypt/Decrypt files using AES standard.

# BUILD 
Simplest, on aes-tool base dir (same as CMakeList.txt) :

```
mkdir build
cd build
cmake ..
```

When cmake has finished on the same build folder run:

```
make
```

Now on aes-tool base dir you will have a new folder called bin where you will find aes-tool executable.

## INDICATE BUILD TYPE

```
cmake -S . -B build -D CMAKE_BUILD_TYPE=Debug
```

or

```
cmake -S . -B build -D CMAKE_BUILD_TYPE=Release
```

# INSTALL

Build the project as release, then on your build project just:

```
sudo make install
```
