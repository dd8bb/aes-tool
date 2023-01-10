# AES ENCRYPTION COMMAND LINE TOOL
Program to be used as a command line tool.
Encrypt/Decrypt files using AES standard.

# INSTALLATION
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

**DEBUG**
If wanna debug aes-tool when calling cmake add following options:
```cmake .. -DDEBUG```
