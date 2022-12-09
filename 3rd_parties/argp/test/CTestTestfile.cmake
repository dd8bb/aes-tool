# CMake generated Testfile for 
# Source directory: /Users/david/Documents/Utils/AES-Encryption/3rd_parties/argp/test
# Build directory: /Users/david/Documents/Utils/AES-Encryption/3rd_parties/argp/test
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(argp-test "/Users/david/Documents/Utils/AES-Encryption/3rd_parties/argp/test/argp-test")
set_tests_properties(argp-test PROPERTIES  _BACKTRACE_TRIPLES "/Users/david/Documents/Utils/AES-Encryption/3rd_parties/argp/test/CMakeLists.txt;35;add_test;/Users/david/Documents/Utils/AES-Encryption/3rd_parties/argp/test/CMakeLists.txt;0;")
add_test(tst-argp1 "/Users/david/Documents/Utils/AES-Encryption/3rd_parties/argp/test/tst-argp1")
set_tests_properties(tst-argp1 PROPERTIES  _BACKTRACE_TRIPLES "/Users/david/Documents/Utils/AES-Encryption/3rd_parties/argp/test/CMakeLists.txt;36;add_test;/Users/david/Documents/Utils/AES-Encryption/3rd_parties/argp/test/CMakeLists.txt;0;")
add_test(tst-argp2 "/Users/david/Documents/Utils/AES-Encryption/3rd_parties/argp/test/tst-argp2")
set_tests_properties(tst-argp2 PROPERTIES  _BACKTRACE_TRIPLES "/Users/david/Documents/Utils/AES-Encryption/3rd_parties/argp/test/CMakeLists.txt;37;add_test;/Users/david/Documents/Utils/AES-Encryption/3rd_parties/argp/test/CMakeLists.txt;0;")
add_test(bug-argp1 "/Users/david/Documents/Utils/AES-Encryption/3rd_parties/argp/test/bug-argp1" "--help")
set_tests_properties(bug-argp1 PROPERTIES  _BACKTRACE_TRIPLES "/Users/david/Documents/Utils/AES-Encryption/3rd_parties/argp/test/CMakeLists.txt;38;add_test;/Users/david/Documents/Utils/AES-Encryption/3rd_parties/argp/test/CMakeLists.txt;0;")
add_test(bug-argp2 "/Users/david/Documents/Utils/AES-Encryption/3rd_parties/argp/test/bug-argp2" "-d" "111" "--dstaddr" "222" "-p" "333" "--peer" "444")
set_tests_properties(bug-argp2 PROPERTIES  _BACKTRACE_TRIPLES "/Users/david/Documents/Utils/AES-Encryption/3rd_parties/argp/test/CMakeLists.txt;39;add_test;/Users/david/Documents/Utils/AES-Encryption/3rd_parties/argp/test/CMakeLists.txt;0;")
