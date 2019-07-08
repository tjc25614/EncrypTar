#!/usr/bin/env bash
# Test suite for EncrypTar
################################################################################
NUM_TESTS=0
PASSED_TESTS=0

if [ -x ../EncrypTar.py ]; then
    echo "Starting test suite..."
else
    echo "EncrypTar.py not found"
    exit 1
fi

################################################################################
# TEST 1 - BASIC INDIVIDUAL FILE USAGE
NUM_TESTS=$(($NUM_TESTS+1))
echo -n "TEST 1 - "

# clean up
rm file.txt passphrase.txt file.tar.enc 2>/dev/null

# setup
S1="Hello, world!"
echo "$S1" > file.txt
echo "test" > passphrase.txt

# test
../EncrypTar.py -p passphrase.txt file.tar.enc file.txt
if [ -e file.tar.enc ]; then
    rm file.txt
    ../EncrypTar.py -x -p passphrase.txt file.tar.enc ./
    if [ -e file.txt ]; then
        FILE_CONTENTS=`cat file.txt`
        if [ "$FILE_CONTENTS" = "$S1" ]; then
            echo "PASSED"
            PASSED_TESTS=$(($PASSED_TESTS+1))
        else
            echo "contents of extracted file incorrect"
        fi
    else
        echo "extraction failed"
    fi
else
    echo "encrypted archive does not exist"
fi

# clean up
rm file.txt passphrase.txt file.tar.enc 2>/dev/null
################################################################################
# TEST 2 - PASSPHRASE FROM COMMANDLINE
NUM_TESTS=$(($NUM_TESTS+1))
echo -n "TEST 2 - "

# setup
S1="Hello, world!"
echo "$S1" > file.txt
echo "test" > passphrase.txt

# test
expect user_passphrase.exp >/dev/null
if [ -e file.tar.enc ]; then
    rm file.txt
    ../EncrypTar.py -x -p passphrase.txt file.tar.enc ./
    if [ -e file.txt ]; then
        FILE_CONTENTS=`cat file.txt`
        if [ "$FILE_CONTENTS" = "$S1" ]; then
            echo "PASSED"
            PASSED_TESTS=$(($PASSED_TESTS+1))
        else
            echo "contents of extracted file incorrect"
        fi
    else
        echo "extraction failed"
    fi
else
    echo "encrypted archive does not exist"
fi

# clean up
rm file.txt passphrase.txt file.tar.enc 2>/dev/null
################################################################################
# TEST 2 - INCORRECT PASSPHRASE
NUM_TESTS=$(($NUM_TESTS+1))
echo -n "TEST 3 - "

# setup
S1="Hello, world!"
echo "$S1" > file.txt
echo "test2" > passphrase.txt

# test
expect user_passphrase.exp >/dev/null
if [ -e file.tar.enc ]; then
    rm file.txt
    ../EncrypTar.py -x -p passphrase.txt file.tar.enc ./ >/dev/null
    if [ $? -eq 1 ]; then
        echo "PASSED"
        PASSED_TESTS=$(($PASSED_TESTS+1))
    else
        echo "password check failed"
    fi
else
    echo "encrypted archive does not exist"
fi

# clean up
rm file.txt passphrase.txt file.tar.enc 2>/dev/null
################################################################################
# TEST 4 - MULTIPLE FILES
NUM_TESTS=$(($NUM_TESTS+1))
echo -n "TEST 4 - "

# clean up
rm file2.text 2>/dev/null

# setup
S1="Hello, world!"
S2="Goodbye, world!"
echo "$S1" > file.txt
echo "$S2" > file2.txt
echo "test" > passphrase.txt

# test
../EncrypTar.py -p passphrase.txt files.tar.enc file.txt file2.txt
if [ -e files.tar.enc ]; then
    rm file.txt file2.txt
    ../EncrypTar.py -x -p passphrase.txt files.tar.enc ./
    if [ -e file.txt ]; then
        FILE_CONTENTS=`cat file.txt`
        if [ "$FILE_CONTENTS" = "$S1" ]; then
            if [ -e file2.txt ]; then
                FILE_CONTENTS=`cat file2.txt`
                if [ "$FILE_CONTENTS" = "$S2" ]; then
                    echo "PASSED"
                    PASSED_TESTS=$(($PASSED_TESTS+1))
                else
                    echo "contents of extracted file incorrect"
                fi
            else
                echo "extraction failed"
            fi
        else
            echo "contents of extracted file incorrect"
        fi
    else
        echo "extraction failed"
    fi
else
    echo "encrypted archive does not exist"
fi

# clean up
rm file.txt file2.txt passphrase.txt files.tar.enc 2>/dev/null
################################################################################

################################################################################
echo "TESTS PASSED: $PASSED_TESTS/$NUM_TESTS"
