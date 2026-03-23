#!/bin/bash
if [ -f "e2e_functional_test.py" ]; then
    python3 e2e_functional_test.py &
    TEST_PID=$!
    sleep 5
fi
wait $TEST_PID
if [ $? -eq 0 ]; then
    echo "CMD_SUCCESS: Tests Passed."
else
    echo "CMD_FAILED: An Error Occurred."
fi
