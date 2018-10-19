# Development Instructions
## Testing
Execute tests by using following commands:
    - make test (all tests are executed)
    - make test_{testname} (executes test suite with the name supplied)

Valgrind - memory leak checking
    - make valgrind_test_{testname} (checks the tested resource for leaks)
    NOTE: More verbose information is shown if set(VALGRIND_ARGUMENTS "--leak-check=full") is added to CMakeLists.txt

Cppcheck4 - static code analysis
    - execute "cppcheck --enable=all --inconclusive ." on the commandline

TODO: describe your solution and design decisions here

For every assignment:
* If everything is working, you are done within one sentence saying so.
* If parts are missing/failing, list them here.
